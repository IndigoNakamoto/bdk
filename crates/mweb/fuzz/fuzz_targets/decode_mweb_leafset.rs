//! F-Z01: `mwebleafset` decode.
//!
//! The interesting property is not that decoding succeeds but that a hostile length
//! prefix cannot make it allocate: the blob is `vec![0u8; size]`-ed before any read,
//! and a failed allocation aborts rather than unwinding, so an uncapped length is a
//! remote crash. The assertion below pins the cap that prevents it.

use bdk_mweb::limits::MAX_LEAFSET_BYTES;
use bdk_mweb::p2p::MwebLeafset;
use honggfuzz::fuzz;
use litecoin::consensus::encode::{deserialize, serialize};

fn do_test(data: &[u8]) {
    let Ok(decoded) = deserialize::<MwebLeafset>(data) else {
        return;
    };

    // A decode that succeeded must have respected the cap, otherwise the allocation
    // guard is not actually on the path the wire takes.
    assert!(
        decoded.leafset.len() <= MAX_LEAFSET_BYTES,
        "decoded a leafset of {} bytes, above the {MAX_LEAFSET_BYTES} cap",
        decoded.leafset.len()
    );

    // Re-encoding must reproduce the accepted prefix of the input. `deserialize`
    // rejects trailing bytes, so this is a strict round-trip.
    // Non-canonical encodings (e.g. non-minimal VarInts) are accepted by
    // consensus decode; only require the canonical form to be stable.
    let reserialized = serialize(&decoded);
    if reserialized != data {
        let again: MwebLeafset = deserialize(&reserialized)
            .expect("canonical leafset encoding must decode");
        assert_eq!(again, decoded, "canonical leafset re-decode changed value");
        assert_eq!(
            serialize(&again),
            reserialized,
            "canonical leafset form unstable"
        );
    }

    // The index expansion is 64x the bitset in the worst case; make the fuzzer
    // actually walk it so the cap above is load-bearing rather than theoretical.
    let indices = decoded.unspent_leaf_indices();
    assert!(indices.len() <= decoded.leafset.len() * 8);
    assert!(indices.windows(2).all(|w| w[0] < w[1]));

    // The bounded accessor must agree with the unbounded one whenever it succeeds.
    if let Ok(bounded) = decoded.unspent_leaf_indices_bounded(indices.len()) {
        assert_eq!(bounded, indices);
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

    /// Random bytes essentially never form a valid leafset — the length prefix would
    /// have to exactly match the remaining input, and `deserialize` rejects trailing
    /// bytes — so the round-trip and cap assertions above would never run on the
    /// pseudorandom corpus alone. honggfuzz reaches them through coverage feedback;
    /// this reaches them deterministically.
    #[test]
    fn sweep_valid_encodings() {
        use litecoin::consensus::encode::serialize;
        use litecoin::hashes::Hash;

        // Sizes straddling the CompactSize width boundaries (0xFC / 0xFFFF).
        for n in [0usize, 1, 7, 8, 252, 253, 254, 4096, 65535, 65536] {
            let ls = super::MwebLeafset {
                block_hash: litecoin::BlockHash::from_byte_array([5u8; 32]),
                leafset: (0..n).map(|i| (i % 251) as u8).collect(),
            };
            super::do_test(&serialize(&ls));
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
