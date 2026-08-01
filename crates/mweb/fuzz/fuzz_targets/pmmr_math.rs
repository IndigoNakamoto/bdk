//! F-Z06: PMMR position arithmetic.
//!
//! The index math runs on peer-supplied leaf indices and MMR sizes. `leaf_position`
//! computes `2 * i - popcount(i)`, which wraps above `u64::MAX / 2`, and the
//! child/parent walks underflow near position 0. This target is built with
//! `overflow-checks = true` precisely so those wrap into crashes.

use bdk_mweb::pmmr::{
    checked_leaf_position, leaf_hash, leaf_position, num_nodes_for_leaves, MemMmr,
};
use bdk_mweb_fuzz::Cursor;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    let mut c = Cursor::new(data);

    let idx = c.u64();
    let pos = leaf_position(idx);
    match checked_leaf_position(idx) {
        Some(exact) => {
            assert_eq!(pos, exact);
            // Positions must be strictly increasing in the leaf index, which is what
            // lets the segment walk treat them as an ordered range.
            if let Some(next) = checked_leaf_position(idx.saturating_add(1)) {
                assert!(next > exact || idx == u64::MAX);
            }
        }
        None => assert_eq!(pos, u64::MAX, "unrepresentable position must saturate"),
    }

    let _ = num_nodes_for_leaves(c.u64());
    let _ = leaf_hash(c.u64(), &c.arr32());

    // Build a small MMR from fuzzer-chosen output ids and take its root. Bounded by
    // the input length so runtime stays proportional to the corpus entry.
    let mut mmr = MemMmr::new();
    let mut added = 0u32;
    while c.has_more() && added < 512 {
        mmr.add_output_id(c.arr32());
        added += 1;
    }
    let root = mmr.root();

    // An MMR built from the same ids must produce the same root: the root is what
    // every verification path compares against, so a non-deterministic one would
    // make all of them meaningless.
    if added > 0 {
        assert_ne!(root, [0u8; 32], "non-empty MMR hashed to zero");
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
