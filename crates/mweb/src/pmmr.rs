//! Litecoin/Grin PMMR helpers for LIP-0006 / LIP-0007 verification.
//!
//! Leaf data in the output PMMR is the 32-byte [`crate::scan::output_id`]. Parent hashes are
//! untagged BLAKE3 over `uint64_le(position) || left || right`. Leaf hashes follow Core
//! `Leaf::CalcHash`: BLAKE3 over `uint64_le(position) || CompactSize(len) || leaf_data`
//! (Bitcoin `Serialize` of `vector<uint8_t>`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use bitcoin::blockdata::block::MwebBlockHeader;
use bitcoin::blockdata::mimblewimble::Output;

use crate::error::Error;
use crate::hash::blake3_hash;
use crate::p2p::{MwebLeafset, MwebUtxos};
use crate::scan::output_id;

/// Leaf index → MMR node position: `2 * i - popcount(i)`.
pub fn leaf_position(leaf_index: u64) -> u64 {
    2 * leaf_index - leaf_index.count_ones() as u64
}

/// Number of MMR nodes for `num_leaves` leaves (= position of the next leaf).
pub fn num_nodes_for_leaves(num_leaves: u64) -> u64 {
    leaf_position(num_leaves)
}

fn fill_ones_to_right(input: u64) -> u64 {
    let mut x = input;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x
}

fn count_rightmost_zeros(input: u64) -> u64 {
    if input == 0 {
        return 64;
    }
    input.trailing_zeros() as u64
}

fn index_height(position: u64) -> u64 {
    let mut height = position;
    let mut peak_size = fill_ones_to_right(position);
    while peak_size != 0 {
        if height >= peak_size {
            height -= peak_size;
        }
        peak_size >>= 1;
    }
    height
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Index {
    position: u64,
    height: u64,
}

impl Index {
    fn at(position: u64) -> Self {
        Self {
            position,
            height: index_height(position),
        }
    }

    fn is_leaf(self) -> bool {
        self.height == 0
    }

    fn sibling(self) -> Self {
        if index_height(self.position + 1) == self.height + 1 {
            Self {
                position: self.position + 1 - (1u64 << (self.height + 1)),
                height: self.height,
            }
        } else {
            Self {
                position: self.position + (1u64 << (self.height + 1)) - 1,
                height: self.height,
            }
        }
    }

    fn left_child(self) -> Self {
        Self {
            position: self.position - (1u64 << self.height),
            height: self.height - 1,
        }
    }

    fn right_child(self) -> Self {
        Self {
            position: self.position - 1,
            height: self.height - 1,
        }
    }

    fn next(self) -> Self {
        Self::at(self.position + 1)
    }
}

/// BLAKE3(position_le \|\| left \|\| right).
pub fn parent_hash(position: u64, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 8 + 32 + 32];
    payload[..8].copy_from_slice(&position.to_le_bytes());
    payload[8..40].copy_from_slice(left);
    payload[40..].copy_from_slice(right);
    blake3_hash(&payload)
}

/// BLAKE3(position_le \|\| CompactSize(32) \|\| output_id) for an output-ID leaf.
///
/// Matches Core `Leaf::CalcHash` / `Hasher().Append(uint64).Append(vector)`.
pub fn leaf_hash(leaf_index: u64, output_id: &[u8; 32]) -> [u8; 32] {
    let pos = leaf_position(leaf_index);
    let mut payload = [0u8; 8 + 1 + 32];
    payload[..8].copy_from_slice(&pos.to_le_bytes());
    // CompactSize for lengths < 253 is a single byte.
    payload[8] = 32;
    payload[9..].copy_from_slice(output_id);
    blake3_hash(&payload)
}

/// Memory-only MMR (hashes only; used for tests and full rebuilds).
#[derive(Clone, Debug, Default)]
pub struct MemMmr {
    hashes: Vec<[u8; 32]>,
    num_leaves: u64,
}

impl MemMmr {
    /// Empty MMR.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a leaf whose PMMR data is `output_id`.
    pub fn add_output_id(&mut self, output_id: [u8; 32]) -> u64 {
        let leaf_index = self.num_leaves;
        let hash = leaf_hash(leaf_index, &output_id);
        self.hashes.push(hash);
        self.num_leaves += 1;

        let mut next = Index::at(leaf_position(leaf_index)).next();
        while !next.is_leaf() {
            let left = self.hash_at(next.left_child().position);
            let right = *self.hashes.last().expect("parent has right child");
            self.hashes
                .push(parent_hash(next.position, &left, &right));
            next = next.next();
        }
        leaf_index
    }

    fn hash_at(&self, position: u64) -> [u8; 32] {
        self.hashes[position as usize]
    }

    /// Bag-the-peaks root (Core `IMMR::Root`).
    pub fn root(&self) -> [u8; 32] {
        let num_nodes = num_nodes_for_leaves(self.num_leaves);
        if num_nodes == 0 {
            return [0u8; 32];
        }
        bag_peaks(
            &peak_indices(num_nodes)
                .into_iter()
                .map(|idx| self.hash_at(idx.position))
                .collect::<Vec<_>>(),
            num_nodes,
        )
    }

    /// Number of leaves.
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }
}

fn peak_indices(num_nodes: u64) -> Vec<Index> {
    if num_nodes == 0 {
        return Vec::new();
    }
    let mut peak_indices = Vec::new();
    let mut peak_size = fill_ones_to_right(num_nodes);
    let mut num_left = num_nodes;
    let mut sum_prev = 0u64;
    while peak_size != 0 {
        if num_left >= peak_size {
            peak_indices.push(Index::at(sum_prev + peak_size - 1));
            sum_prev += peak_size;
            num_left -= peak_size;
        }
        peak_size >>= 1;
    }
    peak_indices
}

fn bag_peaks(peak_hashes_left_to_right: &[[u8; 32]], num_nodes: u64) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut have = false;
    for peak in peak_hashes_left_to_right.iter().rev() {
        if !have {
            hash = *peak;
            have = true;
        } else {
            hash = parent_hash(num_nodes, peak, &hash);
        }
    }
    hash
}

/// Verify leafset bytes against the header `leafset_root` (untagged BLAKE3).
///
/// Expects `leafset.leafset` to be the bitset blob of length `(output_mmr_size + 7) / 8`
/// (zero-padded). Extra trailing zero bytes are tolerated when longer; shorter is rejected.
pub fn verify_leafset(
    leafset: &MwebLeafset,
    leafset_root: &[u8; 32],
    output_mmr_size: u64,
) -> Result<(), Error> {
    let need = ((output_mmr_size + 7) / 8) as usize;
    if leafset.leafset.len() < need {
        return Err(Error::Crypto("leafset shorter than output_mmr_size".into()));
    }
    // Hash exactly `need` bytes (Core `ILeafSet::Root`).
    let digest = blake3_hash(&leafset.leafset[..need]);
    if &digest != leafset_root {
        return Err(Error::Crypto("leafset_root mismatch".into()));
    }
    Ok(())
}

fn bitset_test(leafset: &[u8], idx: u64) -> bool {
    let byte_i = (idx / 8) as usize;
    let bit = (idx % 8) as u8;
    leafset
        .get(byte_i)
        .map(|b| b & (1 << (7 - bit)) != 0)
        .unwrap_or(false)
}

fn calc_pruned_parents(unspent: &[u8], num_leaves: u64) -> BTreeSet<u64> {
    let mut ret: BTreeSet<u64> = BTreeSet::new();
    for i in 0..num_leaves {
        if !bitset_test(unspent, i) {
            ret.insert(leaf_position(i));
        }
    }
    if num_leaves == 0 || num_nodes_for_leaves(num_leaves) == 0 {
        return ret;
    }
    // Core `CalcPrunedParents`: `LeafIndex::At(num_leaves).GetNodeIndex()` (== next leaf pos).
    let last_node_pos = num_nodes_for_leaves(num_leaves);

    let mut height = 1u64;
    while (2u64 << height) - 2 <= last_node_pos {
        let mut sibling_num = 0u64;
        let base_inc = (2u64 << height) - 1;
        let mut next = Index {
            position: 0,
            height: 0,
        };
        loop {
            if sibling_num == 0 {
                next = Index {
                    position: base_inc - 1,
                    height,
                };
            } else {
                let increment = base_inc + count_rightmost_zeros(sibling_num);
                next = Index {
                    position: next.position + increment,
                    height,
                };
            }
            sibling_num += 1;
            if next.position > last_node_pos {
                break;
            }
            let right = next.right_child();
            if ret.contains(&right.position) {
                let left = next.left_child();
                if ret.contains(&left.position) {
                    ret.remove(&right.position);
                    ret.remove(&left.position);
                    ret.insert(next.position);
                }
            }
        }
        height += 1;
    }
    ret
}

fn calc_hash_indices(
    unspent: &[u8],
    num_leaves: u64,
    first_leaf: u64,
    last_leaf: u64,
) -> BTreeSet<u64> {
    let num_nodes = num_nodes_for_leaves(num_leaves);
    let peaks = peak_indices(num_nodes);
    let first_node = Index::at(leaf_position(first_leaf));
    let last_node = Index::at(leaf_position(last_leaf));

    let mut proof: BTreeSet<u64> = BTreeSet::new();

    // 1. Peaks left of first leaf
    let mut prev_peak: Option<Index> = None;
    for peak in &peaks {
        if peak.position < first_node.position {
            proof.insert(peak.position);
            prev_peak = Some(*peak);
        } else {
            break;
        }
    }

    // 2. Path to left edge of mountain
    let adjustment = prev_peak.map(|p| p.position + 1).unwrap_or(0);
    let on_left_edge = |idx: Index| (idx.position + 2 - adjustment) == (2u64 << idx.height);
    let mut idx = first_node;
    while !on_left_edge(idx) {
        let sib = idx.sibling();
        if sib.position < idx.position {
            proof.insert(sib.position);
            idx = Index {
                position: idx.position + 1,
                height: idx.height + 1,
            };
        } else {
            idx = Index {
                position: sib.position + 1,
                height: sib.height + 1,
            };
        }
    }

    // 3. Pruned parents between first and last
    let pruned = calc_pruned_parents(unspent, num_leaves);
    for pos in leaf_position(first_leaf)..leaf_position(last_leaf) {
        if pruned.contains(&pos) {
            proof.insert(pos);
        }
    }

    // 4. Path to right edge of mountain containing last leaf
    let peak = peaks
        .iter()
        .find(|p| p.position >= last_node.position)
        .copied()
        .unwrap_or(last_node);
    let on_right_edge = |idx: Index| idx.position >= peak.position - peak.height;
    idx = last_node;
    while !on_right_edge(idx) {
        let sib = idx.sibling();
        if sib.position > idx.position {
            proof.insert(sib.position);
            idx = Index {
                position: sib.position + 1,
                height: idx.height + 1,
            };
        } else {
            idx = Index {
                position: idx.position + 1,
                height: idx.height + 1,
            };
        }
    }

    proof
}

/// Verify a FULL_UTXO batch against `output_root` using segment `parent_hashes`.
///
/// `leafset` must be the bitset at the same tip as `header.output_mmr_size`.
///
/// Fast path: when the batch enumerates every leaf `0..output_mmr_size` (no spends),
/// rebuild a [`MemMmr`] from output ids and compare roots (parent hashes optional).
pub fn verify_utxo_batch(
    batch: &MwebUtxos,
    leafset: &MwebLeafset,
    header: &MwebBlockHeader,
) -> Result<(), Error> {
    if batch.utxos.is_empty() {
        return Ok(());
    }
    let num_leaves = header.output_mmr_size;
    if num_leaves == 0 {
        return Err(Error::Crypto("empty output MMR".into()));
    }
    let need = ((num_leaves + 7) / 8) as usize;
    if leafset.leafset.len() < need {
        return Err(Error::Crypto("leafset too short for PMMR verify".into()));
    }
    let bits = &leafset.leafset[..need];

    for entry in &batch.utxos {
        if !bitset_test(bits, entry.leaf_index) {
            return Err(Error::Crypto(
                "utxo leaf_index not set in leafset".into(),
            ));
        }
    }

    // Fast path: complete unspent MMR present in this batch (no spent leaves).
    // If the rebuild root mismatches (e.g. output_id wire quirks), fall through to
    // segment verification using Core's parent_hashes.
    let unspent = leafset.unspent_leaf_indices();
    let batch_indices: Vec<u64> = batch.utxos.iter().map(|e| e.leaf_index).collect();
    let complete_unspent = unspent.len() as u64 == num_leaves
        && unspent == (0..num_leaves).collect::<Vec<_>>()
        && batch_indices == unspent;
    if complete_unspent {
        let mut mmr = MemMmr::new();
        let mut sorted = batch.utxos.clone();
        sorted.sort_by_key(|e| e.leaf_index);
        for entry in &sorted {
            mmr.add_output_id(output_id(&entry.output));
        }
        if mmr.root() == header.output_root {
            return Ok(());
        }
    }

    let leaf_hashes: Vec<(u64, [u8; 32])> = batch
        .utxos
        .iter()
        .map(|e| (e.leaf_index, leaf_hash(e.leaf_index, &output_id(&e.output))))
        .collect();
    verify_segment_root(
        &leaf_hashes,
        &batch.parent_hashes,
        bits,
        num_leaves,
        &header.output_root,
    )
}

/// Core-style segment root check (leaf hashes + `parent_hashes` vs `output_root`).
fn verify_segment_root(
    leaf_hashes: &[(u64, [u8; 32])],
    parent_hashes: &[[u8; 32]],
    unspent_bits: &[u8],
    num_leaves: u64,
    output_root: &[u8; 32],
) -> Result<(), Error> {
    if leaf_hashes.is_empty() {
        return Ok(());
    }
    let first_leaf = leaf_hashes.first().unwrap().0;
    let last_leaf = leaf_hashes.last().unwrap().0;
    let hash_indices: Vec<u64> = calc_hash_indices(unspent_bits, num_leaves, first_leaf, last_leaf)
        .into_iter()
        .collect();

    // Core appends lower_peak after segment.hashes when present.
    let (proof_hashes, lower_peak) = if parent_hashes.len() == hash_indices.len() {
        (parent_hashes, None)
    } else if parent_hashes.len() == hash_indices.len() + 1 {
        let (proof, peak) = parent_hashes.split_at(hash_indices.len());
        (proof, Some(peak[0]))
    } else if hash_indices.is_empty() && parent_hashes.len() <= 1 {
        (&[][..], parent_hashes.first().copied())
    } else {
        return Err(Error::Crypto(alloc::format!(
            "parent_hashes len {} != hash_indices {} (or +1 lower_peak)",
            parent_hashes.len(),
            hash_indices.len()
        )));
    };

    let mut nodes: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    for &(leaf_idx, hash) in leaf_hashes {
        nodes.insert(leaf_position(leaf_idx), hash);
    }
    for (pos, hash) in hash_indices.iter().zip(proof_hashes.iter()) {
        nodes.insert(*pos, *hash);
    }

    let num_nodes = num_nodes_for_leaves(num_leaves);
    let mut changed = true;
    while changed {
        changed = false;
        for pos in 0..num_nodes {
            let idx = Index::at(pos);
            if idx.is_leaf() || nodes.contains_key(&pos) {
                continue;
            }
            let left = idx.left_child().position;
            let right = idx.right_child().position;
            if let (Some(l), Some(r)) = (nodes.get(&left).copied(), nodes.get(&right).copied()) {
                nodes.insert(pos, parent_hash(pos, &l, &r));
                changed = true;
            }
        }
    }

    let peaks = peak_indices(num_nodes);
    let last_node = Index::at(leaf_position(last_leaf));
    let mountain_peak_pos = peaks
        .iter()
        .find(|p| p.position >= last_node.position)
        .map(|p| p.position)
        .ok_or_else(|| Error::Crypto("missing mountain peak".into()))?;

    // Bag every peak from the left through the mountain that contains `last_leaf`.
    // Segments often span multiple mountains; skipping intermediate peaks (the old
    // "left-of-first + mountain only" approach) yields a false output_root mismatch.
    // Left peaks come from `parent_hashes`; in-range peaks are rebuilt from leaves.
    let mut left_and_mountain: Vec<[u8; 32]> = Vec::new();
    for peak in &peaks {
        if peak.position > mountain_peak_pos {
            break;
        }
        let h = nodes.get(&peak.position).ok_or_else(|| {
            Error::Crypto(alloc::format!(
                "missing peak hash at {} for segment verify (leaves {first_leaf}..{last_leaf})",
                peak.position
            ))
        })?;
        left_and_mountain.push(*h);
    }

    let root = match lower_peak {
        Some(lp) => {
            // lower_peak is the bag of all peaks to the right of the mountain.
            let mut hash = lp;
            for peak_h in left_and_mountain.iter().rev() {
                hash = parent_hash(num_nodes, peak_h, &hash);
            }
            hash
        }
        None => {
            // Segment must cover every peak (or only one mountain).
            let mut all = left_and_mountain;
            for peak in &peaks {
                if peak.position > mountain_peak_pos {
                    let h = nodes.get(&peak.position).ok_or_else(|| {
                        Error::Crypto("missing right peak (no lower_peak)".into())
                    })?;
                    all.push(*h);
                }
            }
            bag_peaks(&all, num_nodes)
        }
    };

    if root != *output_root {
        return Err(Error::Crypto(alloc::format!(
            "output_root mismatch (leaves {first_leaf}..{last_leaf}, utxos={}, parent_hashes={})",
            leaf_hashes.len(),
            parent_hashes.len()
        )));
    }
    Ok(())
}

/// Bag peaks from `peak_idx` through the rightmost peak (Core `CalcBaggedPeak`).
#[cfg(test)]
fn calc_bagged_peak(mmr: &MemMmr, peak_idx_pos: u64) -> Option<[u8; 32]> {
    let num_nodes = num_nodes_for_leaves(mmr.num_leaves());
    let peaks = peak_indices(num_nodes);
    let mut bagged: Option<[u8; 32]> = None;
    for peak in peaks.iter().rev() {
        let peak_hash = mmr.hash_at(peak.position);
        bagged = Some(match bagged {
            Some(b) => parent_hash(num_nodes, &peak_hash, &b),
            None => peak_hash,
        });
        if peak.position == peak_idx_pos {
            return bagged;
        }
    }
    None
}

/// Assemble Core-style segment parent hashes for tests.
#[cfg(test)]
fn assemble_parent_hashes(
    mmr: &MemMmr,
    unspent_bits: &[u8],
    first_leaf: u64,
    last_leaf: u64,
) -> Vec<[u8; 32]> {
    let num_leaves = mmr.num_leaves();
    let hash_indices = calc_hash_indices(unspent_bits, num_leaves, first_leaf, last_leaf);
    let mut hashes: Vec<[u8; 32]> = hash_indices
        .iter()
        .map(|pos| mmr.hash_at(*pos))
        .collect();
    let peaks = peak_indices(num_nodes_for_leaves(num_leaves));
    let last_node = Index::at(leaf_position(last_leaf));
    if let Some(mountain) = peaks.iter().find(|p| p.position >= last_node.position) {
        if let Some(next) = peaks.iter().find(|p| p.position > mountain.position) {
            if let Some(lp) = calc_bagged_peak(mmr, next.position) {
                hashes.push(lp);
            }
        }
    }
    hashes
}

/// Convenience: leaf hashes for a list of outputs (testing / scripting).
pub fn leaf_hashes_for_outputs(entries: &[(u64, Output)]) -> Vec<[u8; 32]> {
    entries
        .iter()
        .map(|(idx, out)| leaf_hash(*idx, &output_id(out)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;

    #[test]
    fn leaf_position_matches_core() {
        assert_eq!(leaf_position(0), 0);
        assert_eq!(leaf_position(1), 1);
        assert_eq!(leaf_position(2), 3);
        assert_eq!(leaf_position(3), 4);
        assert_eq!(leaf_position(4), 7);
    }

    #[test]
    fn mem_mmr_root_deterministic() {
        let mut mmr = MemMmr::new();
        for i in 0..15u64 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            mmr.add_output_id(id);
        }
        let root = mmr.root();
        // Recompute independently.
        let mut mmr2 = MemMmr::new();
        for i in 0..15u64 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            mmr2.add_output_id(id);
        }
        assert_eq!(root, mmr2.root());
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn verify_leafset_blake3() {
        let hash = BlockHash::from_byte_array([2u8; 32]);
        let ls = MwebLeafset::from_indices(hash, &[0, 2, 3]);
        // output_mmr_size must cover highest bit; use 4 leaves → 1 byte
        let root = blake3_hash(&ls.leafset);
        verify_leafset(&ls, &root, 4).unwrap();
        let mut bad = root;
        bad[0] ^= 1;
        assert!(verify_leafset(&ls, &bad, 4).is_err());
    }

    #[test]
    fn verify_utxo_batch_full_unspent_mmr() {
        // Build MMR of 4 output ids; all unspent; single batch = all leaves.
        let mut mmr = MemMmr::new();
        let mut outputs_meta = Vec::new();
        for i in 0..4u64 {
            let mut id = [0u8; 32];
            id[0] = (i + 10) as u8;
            mmr.add_output_id(id);
            outputs_meta.push((i, id));
        }
        let output_root = mmr.root();
        let leafset_bytes = {
            // bits 0..3 set
            let ls = MwebLeafset::from_indices(BlockHash::from_byte_array([1u8; 32]), &[0, 1, 2, 3]);
            ls.leafset
        };
        let leafset_root = blake3_hash(&leafset_bytes);
        let header = MwebBlockHeader {
            height: 1,
            output_root,
            kernel_root: [0; 32],
            leafset_root,
            kernel_offset: [0; 32],
            stealth_offset: [0; 32],
            output_mmr_size: 4,
            kernel_mmr_size: 1,
        };

        // Without real Output objects we can't use verify_utxo_batch end-to-end here;
        // instead check bag_peaks / leaf_hash wiring via MemMmr root equality.
        assert_eq!(mmr.num_leaves(), 4);
        let mut rebuilt = MemMmr::new();
        for (_, id) in &outputs_meta {
            rebuilt.add_output_id(*id);
        }
        assert_eq!(rebuilt.root(), output_root);
        let ls = MwebLeafset {
            block_hash: BlockHash::from_byte_array([1u8; 32]),
            leafset: leafset_bytes,
        };
        verify_leafset(&ls, &header.leafset_root, header.output_mmr_size).unwrap();
    }

    fn all_unspent_bits(num_leaves: u64) -> Vec<u8> {
        let indices: Vec<u64> = (0..num_leaves).collect();
        MwebLeafset::from_indices(BlockHash::from_byte_array([9u8; 32]), &indices).leafset
    }

    fn build_mmr(n: u64) -> MemMmr {
        let mut mmr = MemMmr::new();
        for i in 0..n {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            mmr.add_output_id(id);
        }
        mmr
    }

    /// Port of litecoind `Test_Segment/AssembleSegment` (15 leaves, request 4 from 0).
    #[test]
    fn core_assemble_segment_hash_indices_and_root() {
        let mmr = build_mmr(15);
        let bits = all_unspent_bits(15);
        let indices = calc_hash_indices(&bits, 15, 0, 3);
        assert_eq!(indices.iter().copied().collect::<Vec<_>>(), vec![13]);

        let parent_hashes = assemble_parent_hashes(&mmr, &bits, 0, 3);
        // one proof hash + lower_peak
        assert_eq!(parent_hashes.len(), 2);

        let leaf_hashes: Vec<(u64, [u8; 32])> = (0u64..=3)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&i.to_le_bytes());
                (i, leaf_hash(i, &id))
            })
            .collect();
        verify_segment_root(&leaf_hashes, &parent_hashes, &bits, 15, &mmr.root()).unwrap();
    }

    /// Segment spanning two mountains (leaves 6..=9 under peaks 14 and 21).
    #[test]
    fn multi_mountain_segment_verifies() {
        let mmr = build_mmr(15);
        let bits = all_unspent_bits(15);
        let first = 6u64;
        let last = 9u64;
        // Distinct mountain peaks for first vs last.
        let peaks = peak_indices(num_nodes_for_leaves(15));
        let first_peak = peaks
            .iter()
            .find(|p| p.position >= leaf_position(first))
            .unwrap()
            .position;
        let last_peak = peaks
            .iter()
            .find(|p| p.position >= leaf_position(last))
            .unwrap()
            .position;
        assert_ne!(first_peak, last_peak, "test requires a multi-mountain span");

        let parent_hashes = assemble_parent_hashes(&mmr, &bits, first, last);
        let leaf_hashes: Vec<(u64, [u8; 32])> = (first..=last)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&i.to_le_bytes());
                (i, leaf_hash(i, &id))
            })
            .collect();
        verify_segment_root(&leaf_hashes, &parent_hashes, &bits, 15, &mmr.root()).unwrap();
    }

    #[test]
    fn multi_mountain_with_spent_gap_verifies() {
        let mmr = build_mmr(15);
        // Spend leaf 8 (gap between 7 and 9).
        let bits = MwebLeafset::from_indices(
            BlockHash::from_byte_array([9u8; 32]),
            &[0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14],
        )
        .leafset;
        let first = 6u64;
        let last = 10u64;
        let parent_hashes = assemble_parent_hashes(&mmr, &bits, first, last);
        // Only unspent leaves in the requested window.
        let leaf_hashes: Vec<(u64, [u8; 32])> = [6u64, 7, 9, 10]
            .into_iter()
            .map(|i| {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&i.to_le_bytes());
                (i, leaf_hash(i, &id))
            })
            .collect();
        verify_segment_root(&leaf_hashes, &parent_hashes, &bits, 15, &mmr.root()).unwrap();
    }
}
