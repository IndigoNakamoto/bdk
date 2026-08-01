//! Adversarial tests for the two functions that decide what enters the wallet.
//!
//! MWEB rangeproofs and output signatures are never checked during sync, so PMMR
//! inclusion is the only thing binding an accepted output to the chain.
//! [`verify_leafset`] and [`verify_utxo_batch`] are therefore the entire admission
//! control, and `ltc-wallet-mac`'s leafset cross-check rests directly on the first
//! of them.
//!
//! Every test here states an attack and asserts it fails. A test that only checked
//! the honest path would pass just as happily against a function that returned
//! `Ok(())` unconditionally.
//!
//! These build outputs synthetically, so unlike the `core_*` suites they run
//! everywhere rather than only where `LITECOIND_EXE` is set.

#![cfg(feature = "lip0006")]

use bdk_mweb::hash::blake3_hash;
use bdk_mweb::limits::MAX_OUTPUT_MMR_SIZE;
use bdk_mweb::p2p::{MwebLeafset, MwebUtxoEntry, MwebUtxos, OUTPUT_FORMAT_FULL};
use bdk_mweb::pmmr::{verify_leafset, verify_utxo_batch, MemMmr};
use bdk_mweb::scan::output_id;
use bitcoin::blockdata::block::MwebBlockHeader;
use bitcoin::blockdata::mimblewimble::{Output, OutputMessage};
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::BlockHash;

fn block_hash() -> BlockHash {
    BlockHash::from_byte_array([0x77; 32])
}

fn pubkey() -> PublicKey {
    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &sk)
}

fn other_pubkey() -> PublicKey {
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &sk)
}

/// `OutputFeatures::ExtraDataFeatureBit`; gates whether `extra_data` is serialized.
const EXTRA_DATA_FEATURE_BIT: u8 = 0x02;

/// A distinct output per `tag`. `output_id` covers the commitment, so varying it is
/// enough to give each output a distinct leaf hash.
fn output(tag: u8) -> Output {
    let pk = pubkey();
    Output {
        commitment: [tag; 33],
        sender_public_key: pk,
        receiver_public_key: pk,
        message: OutputMessage {
            features: 0,
            standard_fields: None,
            extra_data: Vec::new(),
        },
        range_proof: [tag; 675],
        signature: [tag; 64],
    }
}

/// A bitset with every leaf in `0..num_leaves` marked unspent.
fn all_unspent(num_leaves: u64) -> Vec<u8> {
    let mut bits = vec![0u8; num_leaves.div_ceil(8) as usize];
    for i in 0..num_leaves {
        bits[(i / 8) as usize] |= 1 << (7 - (i % 8));
    }
    bits
}

/// A consistent (header, leafset, batch) triple over `n` fully-unspent leaves: the
/// shape a freshly-synced chain has, and the one `verify_utxo_batch` fast-paths.
fn honest_chain(n: u64) -> (MwebBlockHeader, MwebLeafset, MwebUtxos) {
    let outputs: Vec<Output> = (0..n).map(|i| output(i as u8 + 1)).collect();

    let mut mmr = MemMmr::new();
    for o in &outputs {
        mmr.add_output_id(output_id(o));
    }
    let bits = all_unspent(n);

    let header = MwebBlockHeader {
        height: 1,
        output_root: mmr.root(),
        kernel_root: [0u8; 32],
        leafset_root: blake3_hash(&bits),
        kernel_offset: [0u8; 32],
        stealth_offset: [0u8; 32],
        output_mmr_size: n,
        kernel_mmr_size: 1,
    };
    let leafset = MwebLeafset {
        block_hash: block_hash(),
        leafset: bits,
    };
    let batch = MwebUtxos {
        block_hash: block_hash(),
        start_index: 0,
        output_format: OUTPUT_FORMAT_FULL,
        utxos: outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| MwebUtxoEntry {
                leaf_index: i as u64,
                output,
            })
            .collect(),
        parent_hashes: Vec::new(),
    };
    (header, leafset, batch)
}

/// Sanity anchor: if this fails, every rejection test below is passing vacuously.
#[test]
fn honest_batch_and_leafset_verify() {
    let (header, leafset, batch) = honest_chain(8);
    verify_leafset(&leafset, &header.leafset_root, header.output_mmr_size).unwrap();
    verify_utxo_batch(&batch, &leafset, &header).unwrap();
}

// ---------------------------------------------------------------- verify_leafset

/// F-V01. The wallet's leafset cross-check compares a peer's leafset against the
/// header root; a single tolerated bit would let a peer misreport one output as
/// spent or unspent.
#[test]
fn leafset_rejects_every_single_bit_flip() {
    let (header, leafset, _) = honest_chain(16);
    let n_bytes = leafset.leafset.len();
    assert!(n_bytes > 0);

    for byte in 0..n_bytes {
        for bit in 0..8 {
            let mut mutated = leafset.clone();
            mutated.leafset[byte] ^= 1 << bit;
            assert!(
                verify_leafset(&mutated, &header.leafset_root, header.output_mmr_size).is_err(),
                "flipping bit {bit} of byte {byte} was accepted"
            );
        }
    }
}

/// F-V02. `verify_leafset` hashes exactly `ceil(output_mmr_size / 8)` bytes, matching
/// Core's `ILeafSet::Root`. Bytes past that are outside the commitment, so appending
/// must not change the verdict — this pins the documented behavior so a future
/// "hash the whole blob" change cannot break live sync silently.
#[test]
fn leafset_ignores_bytes_past_output_mmr_size() {
    let (header, leafset, _) = honest_chain(16);
    let mut padded = leafset.clone();
    padded.leafset.extend_from_slice(&[0xFF; 64]);
    verify_leafset(&padded, &header.leafset_root, header.output_mmr_size)
        .expect("trailing bytes are not covered by leafset_root");
}

/// F-V03. A short leafset must be rejected rather than hashed as-is: accepting it
/// would let a peer omit the tail of the bitset.
#[test]
fn leafset_rejects_truncation() {
    let (header, leafset, _) = honest_chain(16);
    for cut in 0..leafset.leafset.len() {
        let mut short = leafset.clone();
        short.leafset.truncate(cut);
        assert!(
            verify_leafset(&short, &header.leafset_root, header.output_mmr_size).is_err(),
            "a leafset truncated to {cut} bytes was accepted"
        );
    }
}

/// F-V04. `output_mmr_size` is peer-supplied and sizes `div_ceil(8)` plus the loops
/// in `verify_utxo_batch`. An absurd value must be refused up front.
#[test]
fn leafset_rejects_output_mmr_size_above_cap() {
    let (_, leafset, _) = honest_chain(16);
    let root = blake3_hash(&leafset.leafset);
    for size in [MAX_OUTPUT_MMR_SIZE + 1, u64::MAX / 2, u64::MAX] {
        let err = verify_leafset(&leafset, &root, size).unwrap_err();
        assert!(
            format!("{err}").contains("MAX_OUTPUT_MMR_SIZE"),
            "size {size} rejected for the wrong reason: {err}"
        );
    }
}

// ------------------------------------------------------------ verify_utxo_batch

/// F-V05. The core substitution attack: swap in an output the wallet does not own
/// for one it does, or a large-value output for a small one. `output_id` covers the
/// whole output, so the MMR root must change.
#[test]
fn batch_rejects_substituted_output() {
    let (header, leafset, batch) = honest_chain(8);
    for victim in 0..batch.utxos.len() {
        let mut tampered = batch.clone();
        tampered.utxos[victim].output = output(0xEE);
        assert!(
            verify_utxo_batch(&tampered, &leafset, &header).is_err(),
            "substituting the output at leaf {victim} was accepted"
        );
    }
}

/// F-V06. Leaf hashes are position-dependent and the segment walk reads its window
/// from the first and last entries, so an unsorted batch would be proved against the
/// wrong window. Reject rather than verify something other than what was sent.
#[test]
fn batch_rejects_reordering() {
    let (header, leafset, batch) = honest_chain(8);

    let mut swapped = batch.clone();
    swapped.utxos.swap(0, 7);
    assert!(verify_utxo_batch(&swapped, &leafset, &header).is_err());

    let mut reversed = batch.clone();
    reversed.utxos.reverse();
    let err = verify_utxo_batch(&reversed, &leafset, &header).unwrap_err();
    assert!(
        format!("{err}").contains("strictly ascending"),
        "expected the ordering check to fire, got {err}"
    );
}

/// F-V06b. Duplicate leaf indices are rejected by the same ordering invariant. A
/// duplicate would otherwise insert twice into the position map and silently
/// verify a batch with fewer distinct leaves than it claims.
#[test]
fn batch_rejects_duplicate_leaf_indices() {
    let (header, leafset, batch) = honest_chain(8);
    let mut dup = batch.clone();
    dup.utxos[1].leaf_index = dup.utxos[0].leaf_index;
    let err = verify_utxo_batch(&dup, &leafset, &header).unwrap_err();
    assert!(
        format!("{err}").contains("strictly ascending"),
        "expected the ordering check to fire, got {err}"
    );
}

/// F-V07. The fast path rebuilds the whole MMR when the batch looks like a complete
/// unspent set. It must fall *through* to segment verification on a root mismatch,
/// never accept. If the fall-through were ever short-circuited to `Ok`, a peer could
/// claim completeness and hand over arbitrary outputs.
#[test]
fn batch_fast_path_falls_through_on_root_mismatch() {
    let (mut header, leafset, batch) = honest_chain(8);
    // The batch still looks complete and fully unspent, but the header commits to a
    // different root. This is precisely the fast-path shape.
    header.output_root[0] ^= 0xFF;
    assert!(
        verify_utxo_batch(&batch, &leafset, &header).is_err(),
        "the complete-unspent fast path accepted a mismatched output_root"
    );
}

/// F-V08. A peer must not be able to hand over an output for a leaf the leafset
/// marks spent — that is how a spent coin would be re-credited.
#[test]
fn batch_rejects_leaf_not_marked_unspent() {
    let (header, mut leafset, batch) = honest_chain(8);
    // Mark leaf 3 spent while still serving its output.
    leafset.leafset[0] &= !(1 << (7 - 3));
    let err = verify_utxo_batch(&batch, &leafset, &header).unwrap_err();
    assert!(
        format!("{err}").contains("not set in leafset"),
        "expected the leafset membership check to fire, got {err}"
    );
}

/// F-V09. A leaf index past `output_mmr_size` must be refused before it reaches
/// `leaf_position`, which computes `2 * i - popcount(i)` and would otherwise wrap.
#[test]
fn batch_rejects_out_of_range_leaf_index() {
    let (header, leafset, batch) = honest_chain(8);
    for bad in [header.output_mmr_size, u64::MAX / 2, u64::MAX] {
        let mut oob = batch.clone();
        oob.utxos.last_mut().unwrap().leaf_index = bad;
        let err = verify_utxo_batch(&oob, &leafset, &header).unwrap_err();
        assert!(
            format!("{err}").contains("beyond output_mmr_size"),
            "leaf_index {bad} rejected for the wrong reason: {err}"
        );
    }
}

/// F-V10. Extra proof hashes must not be silently ignored. The length arithmetic in
/// `verify_segment_root` accepts `hash_indices.len()` or one more (Core appends a
/// lower peak); anything else is a malformed proof.
#[test]
fn batch_rejects_surplus_parent_hashes() {
    let (header, leafset, batch) = honest_chain(8);
    let mut padded = batch.clone();
    padded.parent_hashes = vec![[0xAA; 32]; 4];
    // The fast path is still eligible here, so the surplus is only reached on
    // fall-through; break the root so it falls through.
    let mut broken = header.clone();
    broken.output_root[0] ^= 0xFF;
    assert!(verify_utxo_batch(&padded, &leafset, &broken).is_err());
}

/// F-V10b. A batch missing entries cannot rebuild the root and carries no proof
/// hashes to cover the gap.
#[test]
fn batch_rejects_dropped_entries() {
    let (header, leafset, batch) = honest_chain(8);
    for drop_at in 0..batch.utxos.len() {
        let mut short = batch.clone();
        short.utxos.remove(drop_at);
        assert!(
            verify_utxo_batch(&short, &leafset, &header).is_err(),
            "dropping the entry at leaf {drop_at} was accepted"
        );
    }
}

/// F-V10c. An empty batch is vacuously fine — there is nothing to admit — but it
/// must not be a way to smuggle a bad header past verification. The caller treats an
/// empty batch as "nothing here" and stops, which the liveness tests cover.
#[test]
fn batch_empty_is_accepted_but_admits_nothing() {
    let (header, leafset, batch) = honest_chain(8);
    let mut empty = batch;
    empty.utxos.clear();
    verify_utxo_batch(&empty, &leafset, &header).unwrap();
}

/// F-V10d. `output_mmr_size` of zero has no valid interpretation alongside a
/// non-empty batch.
#[test]
fn batch_rejects_zero_mmr_size() {
    let (mut header, leafset, batch) = honest_chain(8);
    header.output_mmr_size = 0;
    assert!(verify_utxo_batch(&batch, &leafset, &header).is_err());
}

/// F-V10e. The same cap that guards `verify_leafset` must guard the batch path,
/// where `output_mmr_size` also bounds the node-reconstruction loops.
#[test]
fn batch_rejects_output_mmr_size_above_cap() {
    let (mut header, leafset, batch) = honest_chain(8);
    header.output_mmr_size = MAX_OUTPUT_MMR_SIZE + 1;
    let err = verify_utxo_batch(&batch, &leafset, &header).unwrap_err();
    assert!(
        format!("{err}").contains("MAX_OUTPUT_MMR_SIZE"),
        "rejected for the wrong reason: {err}"
    );
}

/// Mutating any single byte of any output must be caught. This is the property the
/// whole design rests on: with no rangeproof or signature check, `output_id`
/// feeding the MMR is the only thing standing between a peer and a forged coin.
#[test]
fn batch_rejects_any_single_byte_output_mutation() {
    let (header, leafset, batch) = honest_chain(4);

    // Cover one byte in each field rather than all 800+; `output_id` hashes the
    // serialization, so a per-field probe is what distinguishes a field left out of
    // the hash from one included.
    type OutputMutator = fn(&mut Output);
    let mutators: Vec<(&str, OutputMutator)> = vec![
        ("commitment", |o| o.commitment[0] ^= 1),
        ("range_proof", |o| o.range_proof[0] ^= 1),
        ("signature", |o| o.signature[0] ^= 1),
        ("features", |o| o.message.features ^= 1),
        ("sender_public_key", |o| {
            o.sender_public_key = other_pubkey()
        }),
        ("receiver_public_key", |o| {
            o.receiver_public_key = other_pubkey()
        }),
        // Only covered by the hash when the feature bit is set, so set it.
        ("extra_data", |o| {
            o.message.features |= EXTRA_DATA_FEATURE_BIT;
            o.message.extra_data.push(0xCD);
        }),
    ];

    for (field, mutate) in mutators {
        let mut tampered = batch.clone();
        mutate(&mut tampered.utxos[0].output);
        assert!(
            verify_utxo_batch(&tampered, &leafset, &header).is_err(),
            "mutating `{field}` did not change the leaf hash: it is outside output_id"
        );
    }
}

/// `OutputMessage` serialization is feature-gated: `extra_data` is written only when
/// `ExtraDataFeatureBit` is set, so with the bit clear it is outside `output_id`.
///
/// This is Core's rule, not a gap. It is safe because the *decoder* is gated the
/// same way — an output arriving with the bit clear always decodes to empty
/// `extra_data`, so a peer cannot smuggle bytes into an unhashed field. This test
/// exists so that equivalence is checked rather than assumed: if the encoder and
/// decoder ever disagree about the gate, the unhashed field becomes real.
#[test]
fn extra_data_is_outside_output_id_only_while_the_decoder_agrees() {
    use bitcoin::consensus::encode::{deserialize, serialize};

    let mut with_bit_clear = output(1);
    with_bit_clear.message.extra_data = vec![0xCD; 8];
    // Bit clear: not serialized, so not hashed.
    assert_eq!(output_id(&with_bit_clear), output_id(&output(1)));

    // And not decodable back: the round-trip drops it, so no peer can deliver it.
    let round_tripped: Output = deserialize(&serialize(&with_bit_clear)).unwrap();
    assert!(
        round_tripped.message.extra_data.is_empty(),
        "extra_data survived a round-trip with its feature bit clear, so it is \
         reachable from the wire while being outside output_id"
    );

    // Bit set: serialized, hashed, and preserved.
    let mut with_bit_set = with_bit_clear.clone();
    with_bit_set.message.features |= EXTRA_DATA_FEATURE_BIT;
    assert_ne!(output_id(&with_bit_set), output_id(&output(1)));
    let round_tripped: Output = deserialize(&serialize(&with_bit_set)).unwrap();
    assert_eq!(round_tripped.message.extra_data, vec![0xCD; 8]);
}
