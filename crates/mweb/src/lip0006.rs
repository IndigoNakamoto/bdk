//! LIP-0006 light-client UTXO sync into [`MwebCoinDatabase`].
//!
//! Sync order: **header → leafset → verify leafset → batched utxos → verify each
//! batch → scan → mark spent**.
//!
//! [`VerifyMode::Anchored`] is the default: it binds `mweb_header` to the requested
//! block through the HogEx commitment, so the PMMR roots everything else is checked
//! against are known to be the chain's. [`VerifyMode::HeaderAndPmmr`] does the same
//! root checks without that binding, which makes them self-consistency checks only.
//! [`VerifyMode::Trusted`] just requires parent hashes to be present when UTXOs are
//! returned.

// Sync inputs are peer-controlled; a reachable panic is a remote DoS.
#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use bitcoin::blockdata::block::{BlockHash, MwebBlockHeader};
use bitcoin::blockdata::mimblewimble::Output;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;

use crate::coin_db::{MwebCoin, MwebCoinDatabase};
use crate::error::Error;
use crate::keys::MasterKeys;
use crate::p2p::{GetMwebUtxos, MwebHeaderMsg, MwebLeafset, MwebUtxos, OUTPUT_FORMAT_FULL};
use crate::pmmr::{verify_leafset_at, verify_utxo_batch};
use crate::scan::{scan_utxo_entries_at, AddressBook};

/// Default batch size for `getmwebutxos` (peer returns up to this many unspent UTXOs).
///
/// Set to [`crate::limits::MAX_REQUESTED_MWEB_UTXOS`], the widest batch litecoind
/// will answer. Since 0.21.5.6 the peer rate-limits serving per *request* rather
/// than per UTXO, so request count is what a sync pays for: at mainnet scale this
/// is roughly 86 requests instead of the ~700 a 500-wide batch needed.
///
/// [`crate::mweb_sync::MwebSyncer`] still halves and retries on rare PMMR verify
/// failures, so a width that some segment cannot prove costs a retry, not a pass.
pub const DEFAULT_UTXO_BATCH: u16 = crate::limits::MAX_REQUESTED_MWEB_UTXOS;

/// How strictly to verify LIP-0006 payloads.
///
/// The modes form a ladder. Only [`VerifyMode::Anchored`] establishes that the roots
/// everything else is checked against actually belong to the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyMode {
    /// Require `parent_hashes` non-empty when UTXOs are present; skip root checks.
    Trusted,
    /// Fetch `mwebheader`, verify leafset root and each UTXO batch against PMMR roots.
    ///
    /// Self-consistency only: `leafset_root` and `output_root` come from the same
    /// peer as the data checked against them, so a peer serving an internally
    /// consistent but invented MWEB chain passes. Prefer [`Self::Anchored`].
    HeaderAndPmmr,
    /// [`Self::HeaderAndPmmr`] plus [`MwebHeaderMsg::verify_anchored`], which binds
    /// `mweb_header` to the requested block through the HogEx commitment.
    ///
    /// This is the only mode where the roots are known to be the chain's. It
    /// requires `block_hash` to come from a header chain the caller trusts
    /// independently of the MWEB peer.
    Anchored,
}

/// Environment variable that downgrades the default to [`VerifyMode::HeaderAndPmmr`].
///
/// A rollout escape hatch, nothing more. [`VerifyMode::Anchored`] is the default
/// on the strength of regtest evidence that litecoind's `mwebheader` carries a
/// verifiable anchor (`tests/mweb_anchoring.rs`), since confirmed against mainnet
/// (`probe_mainnet_anchor`, 2026-08-01 — see F-01f in `docs/SECURITY_PLAN.md`);
/// if some mainnet peer turns out to serve a proof this crate cannot check, a
/// user needs a way to keep syncing while it is diagnosed rather than being
/// stuck on an old build.
///
/// [`VerifyMode::Trusted`] is deliberately *not* reachable this way. An
/// environment variable that switched verification off entirely would be a
/// downgrade attack against anyone whose environment an attacker can influence.
pub const VERIFY_MODE_ENV: &str = "BDK_MWEB_VERIFY_MODE";

/// [`VerifyMode::Anchored`], unless [`VERIFY_MODE_ENV`] says otherwise.
///
/// Reading the environment from `Default` is unusual, and it is the point: every
/// caller that constructs with `..Default::default()` picks the escape hatch up
/// without needing to thread a flag through. Read once and cached, so behaviour
/// cannot change midway through a sync.
impl Default for VerifyMode {
    #[cfg(feature = "std")]
    fn default() -> Self {
        use std::sync::OnceLock;
        static MODE: OnceLock<VerifyMode> = OnceLock::new();
        *MODE.get_or_init(|| parse_verify_mode(std::env::var(VERIFY_MODE_ENV).ok().as_deref()))
    }

    #[cfg(not(feature = "std"))]
    fn default() -> Self {
        VerifyMode::Anchored
    }
}

/// Interpret a [`VERIFY_MODE_ENV`] value. `None` and anything unrecognised give
/// [`VerifyMode::Anchored`]; [`VerifyMode::Trusted`] is unreachable by design.
#[cfg(feature = "std")]
fn parse_verify_mode(raw: Option<&str>) -> VerifyMode {
    let Some(raw) = raw else {
        return VerifyMode::Anchored;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "anchored" => VerifyMode::Anchored,
        "header-and-pmmr" | "headerandpmmr" | "header_and_pmmr" => {
            eprintln!(
                "{VERIFY_MODE_ENV}=header-and-pmmr: MWEB roots will not be anchored to the \
                 block chain. This is a rollout escape hatch; remove it once the underlying \
                 issue is understood."
            );
            VerifyMode::HeaderAndPmmr
        }
        other => {
            eprintln!(
                "{VERIFY_MODE_ENV}={other:?} is not recognised; using anchored verification. \
                 Valid values: anchored, header-and-pmmr."
            );
            VerifyMode::Anchored
        }
    }
}

impl VerifyMode {
    /// Whether this mode needs the `mwebheader` message fetched.
    pub fn needs_header(&self) -> bool {
        matches!(self, VerifyMode::HeaderAndPmmr | VerifyMode::Anchored)
    }

    /// Whether this mode binds the header to the block via the HogEx commitment.
    pub fn is_anchored(&self) -> bool {
        matches!(self, VerifyMode::Anchored)
    }
}

/// Source of LIP-0006 messages (P2P peer, scripted test double, etc.).
pub trait MwebUtxoSource {
    /// Fetch `mwebheader` for `block_hash`.
    fn get_header(&mut self, block_hash: BlockHash) -> Result<MwebHeaderMsg, Error>;
    /// Fetch the leafset for `block_hash`.
    fn get_leafset(&mut self, block_hash: BlockHash) -> Result<MwebLeafset, Error>;
    /// Fetch a batch of FULL_UTXO entries.
    fn get_utxos(&mut self, req: GetMwebUtxos) -> Result<MwebUtxos, Error>;

    /// Fetch several UTXO batches, invoking `on_batch` for each response in request order.
    ///
    /// The default implementation is sequential. Transports that support request
    /// pipelining (e.g. [`crate::lip0006_tcp::TcpMwebPeer`]) should send all requests
    /// upfront and stream the responses, so the peer builds the next batch while the
    /// caller verifies and scans the previous one.
    ///
    /// On error, some batches may already have been delivered to `on_batch`; the caller
    /// is expected to resume from its own cursor. Implementations must leave the
    /// transport in a clean state (no queued responses) before returning an error.
    fn get_utxos_pipelined(
        &mut self,
        reqs: &[GetMwebUtxos],
        on_batch: &mut dyn FnMut(MwebUtxos) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for req in reqs {
            on_batch(self.get_utxos(req.clone())?)?;
        }
        Ok(())
    }
}

/// Result of a LIP-0006 sync pass.
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    /// Newly rewound / inserted coins.
    pub found: Vec<MwebCoin>,
    /// Local coins marked spent because their output id was absent from the UTXO set.
    pub spent: Vec<[u8; 32]>,
    /// Number of FULL_UTXO outputs downloaded.
    pub downloaded: usize,
    /// MWEB header used for verification (when fetched).
    pub mweb_header: Option<MwebBlockHeader>,
}

/// Largest number of outputs [`sync_mweb_utxos`] will hold in memory for one pass.
///
/// Unlike [`crate::mweb_sync::MwebSyncer::run_once`], this entry point scans once at
/// the end, so it buffers every downloaded output. Bound it so a peer cannot grow
/// the buffer without limit.
pub const MAX_BUFFERED_ENTRIES: usize = 2_000_000;

/// Reject a `mwebutxos` batch that cannot move the caller's leaf cursor forward.
///
/// A peer that answers `start_index` with leaves *below* it leaves the cursor where
/// it was, so the caller re-issues the same request forever while accumulating the
/// replayed outputs. The batch is otherwise well-formed and passes PMMR
/// verification (those leaves really are in the tree), so nothing downstream
/// catches it.
pub fn check_batch_advances(batch: &MwebUtxos, start_index: u64) -> Result<(), Error> {
    let Some(first) = batch.utxos.first() else {
        return Ok(());
    };
    if first.leaf_index < start_index {
        return Err(Error::protocol(alloc::format!(
            "peer protocol violation: mwebutxos leaf {} precedes requested start_index {start_index}",
            first.leaf_index
        )));
    }
    Ok(())
}

/// Soft verification: require `parent_hashes` non-empty when `utxos` is non-empty.
pub fn verify_parent_hashes_present(msg: &MwebUtxos) -> Result<(), Error> {
    if !msg.utxos.is_empty() && msg.parent_hashes.is_empty() {
        return Err(Error::protocol(
            "mwebutxos missing parent_hashes (use VerifyMode::Trusted only with care)",
        ));
    }
    Ok(())
}

/// Sync MWEB UTXOs at `block_hash` into `db` via `source`.
///
/// Tip height tags new coins for confirmation buckets.
pub fn sync_mweb_utxos<S: MwebUtxoSource>(
    source: &mut S,
    keys: &MasterKeys,
    book: &AddressBook,
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
    block_hash: BlockHash,
    tip_height: Option<u32>,
    batch_size: u16,
    verify: VerifyMode,
) -> Result<SyncResult, Error> {
    let header_msg = if verify.needs_header() {
        let msg = source.get_header(block_hash)?;
        if verify.is_anchored() {
            // Before anything is checked *against* this header, prove it is the
            // chain's header for `block_hash`.
            msg.verify_anchored(block_hash)?;
        }
        Some(msg)
    } else {
        None
    };
    let mweb_header = header_msg.as_ref().map(|h| h.mweb_header.clone());

    let leafset = source.get_leafset(block_hash)?;
    // Checked here as well as in `verify_leafset_at` so `VerifyMode::Trusted`
    // (no header) still rejects a leafset for the wrong block.
    if leafset.block_hash != block_hash {
        return Err(Error::protocol("leafset block_hash mismatch"));
    }

    if let Some(ref hdr) = mweb_header {
        verify_leafset_at(&leafset, block_hash, &hdr.leafset_root, hdr.output_mmr_size)?;
    }

    let indices = leafset.unspent_leaf_indices();
    let mut result = SyncResult {
        mweb_header: mweb_header.clone(),
        ..SyncResult::default()
    };
    let mut all_output_ids = BTreeSet::new();
    let mut entries: Vec<(u64, Output)> = Vec::new();

    let mut i = 0usize;
    while i < indices.len() {
        let start = indices[i];
        let req = GetMwebUtxos {
            block_hash,
            start_index: start,
            num_requested: batch_size,
            output_format: OUTPUT_FORMAT_FULL,
        };
        let batch = source.get_utxos(req)?;
        if batch.output_format != OUTPUT_FORMAT_FULL {
            return Err(Error::protocol("expected FULL_UTXO format"));
        }
        match mweb_header.as_ref() {
            Some(hdr) => verify_utxo_batch(&batch, &leafset, hdr)?,
            None => verify_parent_hashes_present(&batch)?,
        }
        if batch.utxos.is_empty() {
            break;
        }
        check_batch_advances(&batch, start)?;
        for entry in &batch.utxos {
            let oid = crate::scan::output_id(&entry.output);
            all_output_ids.insert(oid);
            entries.push((entry.leaf_index, entry.output.clone()));
        }
        if entries.len() > MAX_BUFFERED_ENTRIES {
            return Err(Error::protocol(alloc::format!(
                "mwebutxos: buffered more than {MAX_BUFFERED_ENTRIES} outputs in one sync"
            )));
        }
        result.downloaded = result.downloaded.saturating_add(batch.utxos.len());
        let last_leaf = batch.utxos.last().map(|e| e.leaf_index).unwrap_or(start);
        let before = i;
        while i < indices.len() && indices[i] <= last_leaf {
            i += 1;
        }
        // `check_batch_advances` already guarantees this, but the loop above is the
        // only thing standing between a malicious peer and an unbounded spin, so
        // make the guarantee explicit rather than emergent.
        if i == before {
            return Err(Error::protocol(
                "peer protocol violation: mwebutxos batch did not advance the leaf cursor",
            ));
        }
    }

    result.found = scan_utxo_entries_at(keys, book, &entries, db, secp, |_| tip_height)?;

    let local: Vec<[u8; 32]> = db.unspent().map(|c| c.output_id).collect();
    for id in local {
        if !all_output_ids.contains(&id) && db.mark_spent(&id) {
            result.spent.push(id);
        }
    }

    Ok(result)
}

/// Tip-driven sync: tag coins at `tip_height` and run [`sync_mweb_utxos`].
///
/// Electrum/Esplora/RPC stay outside this crate — pass the transparent tip seam.
pub fn sync_mweb_at_tip<S: MwebUtxoSource>(
    source: &mut S,
    keys: &MasterKeys,
    book: &AddressBook,
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
    tip_hash: BlockHash,
    tip_height: u32,
    verify: VerifyMode,
) -> Result<SyncResult, Error> {
    sync_mweb_utxos(
        source,
        keys,
        book,
        db,
        secp,
        tip_hash,
        Some(tip_height),
        DEFAULT_UTXO_BATCH,
        verify,
    )
}

/// Scripted peer for tests: serves a fixed header, leafset, and UTXO list.
#[derive(Clone, Debug)]
pub struct ScriptedMwebSource {
    /// Header returned by [`MwebUtxoSource::get_header`].
    pub header: MwebHeaderMsg,
    /// Leafset returned by [`MwebUtxoSource::get_leafset`].
    pub leafset: MwebLeafset,
    /// FULL_UTXO catalog (leaf_index, output).
    pub utxos: Vec<(u64, Output)>,
    /// Parent hashes returned with each batch.
    pub parent_hashes: Vec<[u8; 32]>,
}

impl MwebUtxoSource for ScriptedMwebSource {
    fn get_header(&mut self, block_hash: BlockHash) -> Result<MwebHeaderMsg, Error> {
        if self.leafset.block_hash != block_hash {
            return Err(Error::Crypto("scripted header hash mismatch".into()));
        }
        Ok(self.header.clone())
    }

    fn get_leafset(&mut self, block_hash: BlockHash) -> Result<MwebLeafset, Error> {
        if self.leafset.block_hash != block_hash {
            return Err(Error::Crypto("scripted leafset hash mismatch".into()));
        }
        Ok(self.leafset.clone())
    }

    fn get_utxos(&mut self, req: GetMwebUtxos) -> Result<MwebUtxos, Error> {
        let mut entries = Vec::new();
        for (idx, out) in &self.utxos {
            if *idx >= req.start_index && entries.len() < req.num_requested as usize {
                entries.push(crate::p2p::MwebUtxoEntry {
                    leaf_index: *idx,
                    output: out.clone(),
                });
            }
        }
        Ok(MwebUtxos {
            block_hash: req.block_hash,
            start_index: req.start_index,
            output_format: OUTPUT_FORMAT_FULL,
            utxos: entries,
            parent_hashes: self.parent_hashes.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::p2p::MwebUtxoEntry;
    use bitcoin::hashes::Hash;

    /// The default is the security posture every caller inherits through
    /// `..Default::default()`. Pinning it means a future refactor cannot quietly
    /// drop back to unanchored verification.
    ///
    /// Reads the real environment rather than setting it: `Default` caches its
    /// answer in a `OnceLock`, and `set_var` is unsound across threads, so a test
    /// that mutated the environment would be both racy and unrepresentative.
    #[test]
    fn default_is_anchored_unless_the_escape_hatch_is_set() {
        assert_eq!(parse_verify_mode(None), VerifyMode::Anchored);
        assert_eq!(
            VerifyMode::default(),
            parse_verify_mode(std::env::var(VERIFY_MODE_ENV).ok().as_deref())
        );
    }

    #[test]
    fn the_escape_hatch_accepts_the_spellings_it_documents() {
        for spelling in [
            "header-and-pmmr",
            "headerandpmmr",
            "header_and_pmmr",
            "  Header-And-PMMR  ",
        ] {
            assert_eq!(
                parse_verify_mode(Some(spelling)),
                VerifyMode::HeaderAndPmmr,
                "{spelling:?}"
            );
        }
        assert_eq!(parse_verify_mode(Some("anchored")), VerifyMode::Anchored);
    }

    /// The escape hatch must never reach `Trusted`: that would let anyone who can
    /// set an environment variable turn verification off entirely.
    #[test]
    fn the_escape_hatch_cannot_select_trusted() {
        for spelling in [
            "trusted",
            "Trusted",
            "TRUSTED",
            "none",
            "off",
            "",
            "0",
            "no-verify",
        ] {
            assert_ne!(
                parse_verify_mode(Some(spelling)),
                VerifyMode::Trusted,
                "{spelling:?} reached Trusted"
            );
        }
    }

    #[test]
    fn the_syncer_inherits_the_default_verify_mode() {
        use crate::mweb_sync::MwebSyncer;
        assert_eq!(MwebSyncer::new().verify, VerifyMode::default());
        assert_eq!(MwebSyncer::tip_only().verify, VerifyMode::default());
    }

    #[test]
    fn only_anchored_binds_the_header_to_the_chain() {
        assert!(VerifyMode::Anchored.is_anchored());
        assert!(!VerifyMode::HeaderAndPmmr.is_anchored());
        assert!(!VerifyMode::Trusted.is_anchored());
        assert!(VerifyMode::Anchored.needs_header());
        assert!(VerifyMode::HeaderAndPmmr.needs_header());
        assert!(!VerifyMode::Trusted.needs_header());
    }

    fn batch_at(start_index: u64, leaves: &[u64]) -> MwebUtxos {
        MwebUtxos {
            block_hash: BlockHash::from_byte_array([1u8; 32]),
            start_index,
            output_format: OUTPUT_FORMAT_FULL,
            utxos: leaves
                .iter()
                .map(|&leaf_index| MwebUtxoEntry {
                    leaf_index,
                    // The advance check only reads leaf indices, so a default output
                    // keeps this focused on the cursor logic.
                    output: bitcoin::blockdata::mimblewimble::Output {
                        commitment: [0u8; 33],
                        sender_public_key: dummy_pubkey(),
                        receiver_public_key: dummy_pubkey(),
                        message: bitcoin::blockdata::mimblewimble::OutputMessage {
                            features: 0,
                            standard_fields: None,
                            extra_data: Vec::new(),
                        },
                        range_proof: [0u8; 675],
                        signature: [0u8; 64],
                    },
                })
                .collect(),
            parent_hashes: Vec::new(),
        }
    }

    fn dummy_pubkey() -> bitcoin::secp256k1::PublicKey {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&bitcoin::key::Secp256k1::new(), &sk)
    }

    /// F-05: a peer replaying leaves below the requested start leaves the caller's
    /// cursor where it was, so the request repeats forever. The batch is otherwise
    /// valid and passes PMMR verification, so this is the only place to catch it.
    #[test]
    fn batch_below_start_index_is_rejected() {
        let err = check_batch_advances(&batch_at(100, &[10, 11]), 100).unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(msg.contains("precedes requested start_index"), "got {msg}");
        assert!(
            crate::mweb_sync::is_banworthy_peer_error(&err),
            "a replaying peer must be rotated away from, got {msg}"
        );
    }

    #[test]
    fn batch_at_or_after_start_index_is_accepted() {
        assert!(check_batch_advances(&batch_at(100, &[100, 101]), 100).is_ok());
        assert!(check_batch_advances(&batch_at(100, &[105]), 100).is_ok());
        // An empty batch is handled by the callers' own skip path.
        assert!(check_batch_advances(&batch_at(100, &[]), 100).is_ok());
    }
}
