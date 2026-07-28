//! LIP-0006 light-client UTXO sync into [`MwebCoinDatabase`].
//!
//! Sync order: **header → leafset → verify leafset → batched utxos → verify each
//! batch → scan → mark spent**.
//!
//! [`VerifyMode::HeaderAndPmmr`] checks `leafset_root` and segment `parent_hashes`
//! against [`MwebBlockHeader::output_root`]. [`VerifyMode::Trusted`] only requires
//! parent hashes to be present when UTXOs are returned.

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
use crate::pmmr::{verify_leafset, verify_utxo_batch};
use crate::scan::{scan_utxo_entries_at, AddressBook};

/// Default batch size for `getmwebutxos` (peer returns up to this many unspent UTXOs).
///
/// [`crate::mweb_sync::MwebSyncer`] still halves and retries on rare PMMR verify failures.
pub const DEFAULT_UTXO_BATCH: u16 = 500;

/// How strictly to verify LIP-0006 payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyMode {
    /// Require `parent_hashes` non-empty when UTXOs are present; skip root checks.
    Trusted,
    /// Fetch `mwebheader`, verify leafset root and each UTXO batch against PMMR roots.
    #[default]
    HeaderAndPmmr,
}

/// Source of LIP-0006 messages (P2P peer, scripted test double, etc.).
pub trait MwebUtxoSource {
    /// Fetch `mwebheader` for `block_hash`.
    fn get_header(&mut self, block_hash: BlockHash) -> Result<MwebHeaderMsg, Error>;
    /// Fetch the leafset for `block_hash`.
    fn get_leafset(&mut self, block_hash: BlockHash) -> Result<MwebLeafset, Error>;
    /// Fetch a batch of FULL_UTXO entries.
    fn get_utxos(&mut self, req: GetMwebUtxos) -> Result<MwebUtxos, Error>;
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

/// Soft verification: require `parent_hashes` non-empty when `utxos` is non-empty.
pub fn verify_parent_hashes_present(msg: &MwebUtxos) -> Result<(), Error> {
    if !msg.utxos.is_empty() && msg.parent_hashes.is_empty() {
        return Err(Error::Crypto(
            "mwebutxos missing parent_hashes (use VerifyMode::Trusted only with care)".into(),
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
    let header_msg = if matches!(verify, VerifyMode::HeaderAndPmmr) {
        Some(source.get_header(block_hash)?)
    } else {
        None
    };
    let mweb_header = header_msg.as_ref().map(|h| h.mweb_header.clone());

    let leafset = source.get_leafset(block_hash)?;
    if leafset.block_hash != block_hash {
        return Err(Error::Crypto("leafset block_hash mismatch".into()));
    }

    if let Some(ref hdr) = mweb_header {
        verify_leafset(&leafset, &hdr.leafset_root, hdr.output_mmr_size)?;
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
            return Err(Error::Crypto("expected FULL_UTXO format".into()));
        }
        match verify {
            VerifyMode::Trusted => verify_parent_hashes_present(&batch)?,
            VerifyMode::HeaderAndPmmr => {
                let hdr = mweb_header.as_ref().expect("header fetched");
                verify_utxo_batch(&batch, &leafset, hdr)?;
            }
        }
        if batch.utxos.is_empty() {
            break;
        }
        for entry in &batch.utxos {
            let oid = crate::scan::output_id(&entry.output);
            all_output_ids.insert(oid);
            entries.push((entry.leaf_index, entry.output.clone()));
        }
        result.downloaded = result.downloaded.saturating_add(batch.utxos.len());
        let last_leaf = batch.utxos.last().map(|e| e.leaf_index).unwrap_or(start);
        while i < indices.len() && indices[i] <= last_leaf {
            i += 1;
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
