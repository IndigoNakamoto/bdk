//! LIP-0006 light-client UTXO sync into [`MwebCoinDatabase`].
//!
//! MVP security model: **trusted peer + rewind**. Parent-hash / leafset-root
//! PMMR verification is available as [`verify_parent_hashes_present`] (presence
//! check) and can be tightened later without changing the sync seam.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use bitcoin::blockdata::block::BlockHash;
use bitcoin::blockdata::mimblewimble::Output;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;

use crate::coin_db::{MwebCoin, MwebCoinDatabase};
use crate::error::Error;
use crate::keys::MasterKeys;
use crate::p2p::{
    GetMwebUtxos, MwebLeafset, MwebUtxos, OUTPUT_FORMAT_FULL,
};
use crate::scan::{scan_outputs_at, AddressBook};

/// Default batch size for `getmwebutxos`.
pub const DEFAULT_UTXO_BATCH: u16 = 100;

/// Source of LIP-0006 messages (P2P peer, scripted test double, etc.).
pub trait MwebUtxoSource {
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
}

/// Soft verification: require `parent_hashes` non-empty when `utxos` is non-empty.
///
/// Full PMMR membership verification (LIP-0007) remains a follow-on.
pub fn verify_parent_hashes_present(msg: &MwebUtxos) -> Result<(), Error> {
    if !msg.utxos.is_empty() && msg.parent_hashes.is_empty() {
        return Err(Error::Crypto(
            "mwebutxos missing parent_hashes (enable trusted mode to skip)".into(),
        ));
    }
    Ok(())
}

/// Sync MWEB UTXOs at `block_hash` into `db` via `source`.
///
/// When `require_parent_hashes` is true, each batch must include parent hashes.
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
    require_parent_hashes: bool,
) -> Result<SyncResult, Error> {
    let leafset = source.get_leafset(block_hash)?;
    if leafset.block_hash != block_hash {
        return Err(Error::Crypto("leafset block_hash mismatch".into()));
    }
    let indices = leafset.unspent_leaf_indices();
    let mut result = SyncResult::default();
    let mut all_output_ids = BTreeSet::new();
    let mut outputs: Vec<Output> = Vec::new();

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
        if require_parent_hashes {
            verify_parent_hashes_present(&batch)?;
        }
        if batch.utxos.is_empty() {
            break;
        }
        for entry in &batch.utxos {
            let oid = crate::scan::output_id(&entry.output);
            all_output_ids.insert(oid);
            outputs.push(entry.output.clone());
        }
        result.downloaded = result.downloaded.saturating_add(batch.utxos.len());
        // Advance past the highest leaf returned (or by batch size).
        let last_leaf = batch.utxos.last().map(|e| e.leaf_index).unwrap_or(start);
        while i < indices.len() && indices[i] <= last_leaf {
            i += 1;
        }
    }

    result.found = scan_outputs_at(keys, book, &outputs, db, secp, tip_height)?;

    // Mark local unspent coins absent from the tip UTXO set as spent.
    let local: Vec<[u8; 32]> = db.unspent().map(|c| c.output_id).collect();
    for id in local {
        if !all_output_ids.contains(&id) {
            if db.mark_spent(&id) {
                result.spent.push(id);
            }
        }
    }

    Ok(result)
}

/// Scripted peer for tests: serves a fixed leafset + UTXO list.
#[derive(Clone, Debug)]
pub struct ScriptedMwebSource {
    /// Leafset returned by [`MwebUtxoSource::get_leafset`].
    pub leafset: MwebLeafset,
    /// FULL_UTXO catalog (leaf_index, output).
    pub utxos: Vec<(u64, Output)>,
    /// Parent hashes returned with each batch.
    pub parent_hashes: Vec<[u8; 32]>,
}

impl MwebUtxoSource for ScriptedMwebSource {
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
            output_format: OUTPUT_FORMAT_FULL,
            utxos: entries,
            parent_hashes: self.parent_hashes.clone(),
        })
    }
}
