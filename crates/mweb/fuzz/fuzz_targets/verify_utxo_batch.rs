//! F-Z08: `verify_utxo_batch` acceptance and mutation rejection.
//!
//! Every MWEB output the wallet accepts during sync is admitted by this function.
//! Rangeproofs and output signatures are never checked, so PMMR inclusion is the
//! *only* thing binding an output to the chain — if a mutated output can be made to
//! verify, a peer can hand the wallet arbitrary coins.
//!
//! The target builds a genuinely valid batch (so the accept path is reached on
//! nearly every input), then asks the fuzzer to find a mutation that still passes.

use bdk_mweb::hash::blake3_hash;
use bdk_mweb::p2p::{MwebUtxoEntry, MwebUtxos, OUTPUT_FORMAT_FULL};
use bdk_mweb::pmmr::{verify_utxo_batch, MemMmr};
use bdk_mweb::scan::output_id;
use bdk_mweb_fuzz::Cursor;
use honggfuzz::fuzz;
use litecoin::blockdata::block::MwebBlockHeader;
use litecoin::blockdata::mimblewimble::{Output, OutputMessage};
use litecoin::hashes::Hash;
use litecoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use litecoin::BlockHash;

/// A valid but fixed point; `output_id` covers it, so varying the other fields is
/// enough to give each output a distinct leaf hash.
fn fixed_pubkey() -> PublicKey {
    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &sk)
}

fn output_from(c: &mut Cursor, pk: PublicKey) -> Output {
    let mut commitment = [0u8; 33];
    commitment[..32].copy_from_slice(&c.arr32());
    commitment[32] = c.u8();
    let mut range_proof = [0u8; 675];
    // Vary a few bytes rather than all 675: `output_id` hashes the whole proof, so
    // this still changes the leaf hash without burning the fuzzer's byte budget.
    range_proof[..32].copy_from_slice(&c.arr32());
    Output {
        commitment,
        sender_public_key: pk,
        receiver_public_key: pk,
        message: OutputMessage {
            features: c.u8(),
            standard_fields: None,
            extra_data: Vec::new(),
        },
        range_proof,
        signature: [0u8; 64],
    }
}

fn do_test(data: &[u8]) {
    let mut c = Cursor::new(data);
    let block_hash = BlockHash::from_byte_array([9u8; 32]);
    let pk = fixed_pubkey();

    // Build a contiguous, fully-unspent leaf range: that is the shape the fast path
    // in `verify_utxo_batch` accepts, and the one a fresh chain actually has.
    let mut outputs = Vec::new();
    while c.has_more() && outputs.len() < 64 {
        outputs.push(output_from(&mut c, pk));
    }
    if outputs.is_empty() {
        return;
    }
    let num_leaves = outputs.len() as u64;

    let mut mmr = MemMmr::new();
    for o in &outputs {
        mmr.add_output_id(output_id(o));
    }
    let output_root = mmr.root();

    // All leaves unspent: every bit set across `ceil(n/8)` bytes.
    let need = num_leaves.div_ceil(8) as usize;
    let mut bits = vec![0u8; need];
    for i in 0..num_leaves {
        bits[(i / 8) as usize] |= 1 << (7 - (i % 8));
    }
    let leafset = bdk_mweb::p2p::MwebLeafset {
        block_hash,
        leafset: bits.clone(),
    };

    let header = MwebBlockHeader {
        height: 1,
        output_root,
        kernel_root: [0u8; 32],
        leafset_root: blake3_hash(&bits),
        kernel_offset: [0u8; 32],
        stealth_offset: [0u8; 32],
        output_mmr_size: num_leaves,
        kernel_mmr_size: 0,
    };

    let entries: Vec<MwebUtxoEntry> = outputs
        .iter()
        .enumerate()
        .map(|(i, o)| MwebUtxoEntry {
            leaf_index: i as u64,
            output: o.clone(),
        })
        .collect();
    let batch = MwebUtxos {
        block_hash,
        start_index: 0,
        output_format: OUTPUT_FORMAT_FULL,
        utxos: entries.clone(),
        parent_hashes: Vec::new(),
    };

    verify_utxo_batch(&batch, &leafset, &header)
        .expect("a batch rebuilt from its own outputs must verify");

    // Swap in a different output at a fuzzer-chosen slot. The commitment changes, so
    // `output_id` changes, so the MMR root must change. If this ever verifies, an
    // attacker can substitute outputs the wallet will treat as spendable.
    let victim = (c.u32() as usize) % entries.len();
    let mut tampered = entries.clone();
    let replacement = output_from(&mut c, pk);
    if output_id(&replacement) != output_id(&tampered[victim].output) {
        tampered[victim].output = replacement;
        let tampered_batch = MwebUtxos {
            block_hash,
            start_index: 0,
            output_format: OUTPUT_FORMAT_FULL,
            utxos: tampered,
            parent_hashes: Vec::new(),
        };
        assert!(
            verify_utxo_batch(&tampered_batch, &leafset, &header).is_err(),
            "a substituted output verified against the original output_root"
        );
    }

    // Reordering must be rejected: leaf hashes are position-dependent, and the
    // segment walk reads the window from the first and last entries.
    if entries.len() >= 2 {
        let mut reordered = entries.clone();
        reordered.swap(0, entries.len() - 1);
        let reordered_batch = MwebUtxos {
            block_hash,
            start_index: 0,
            output_format: OUTPUT_FORMAT_FULL,
            utxos: reordered,
            parent_hashes: Vec::new(),
        };
        assert!(
            verify_utxo_batch(&reordered_batch, &leafset, &header).is_err(),
            "a reordered batch was accepted"
        );
    }

    // Dropping an entry must be rejected: a short batch cannot rebuild the root, and
    // the segment path has no parent_hashes to fill the gap.
    if entries.len() >= 2 {
        let mut dropped = entries.clone();
        dropped.pop();
        let dropped_batch = MwebUtxos {
            block_hash,
            start_index: 0,
            output_format: OUTPUT_FORMAT_FULL,
            utxos: dropped,
            parent_hashes: Vec::new(),
        };
        assert!(
            verify_utxo_batch(&dropped_batch, &leafset, &header).is_err(),
            "a truncated batch was accepted with no proof hashes"
        );
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    use bdk_mweb_fuzz::extend_vec_from_hex;

    /// Exercise the target's assertions over a deterministic pseudorandom corpus,
    /// so they are verified by `cargo test` even where honggfuzz is unavailable.
    #[test]
    fn sweep_pseudorandom_corpus() {
        bdk_mweb_fuzz::sweep(2000, super::do_test);
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
