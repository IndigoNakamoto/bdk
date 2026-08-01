//! F-Z07: `verify_leafset` acceptance and mutation rejection.
//!
//! Random bytes almost never hash to a random root, so a target that only fed noise
//! to `verify_leafset` would test the reject path forever and never the accept path.
//! This one computes the *correct* root for the fuzzer's leafset, confirms it is
//! accepted, then mutates and confirms rejection. That makes the fuzzer search for
//! a mutation the check tolerates, which is the property that actually matters: the
//! wallet's leafset cross-check is only as good as this rejecting every altered bit.

use bdk_mweb::hash::blake3_hash;
use bdk_mweb::limits::MAX_OUTPUT_MMR_SIZE;
use bdk_mweb::p2p::MwebLeafset;
use bdk_mweb::pmmr::verify_leafset;
use bdk_mweb_fuzz::Cursor;
use honggfuzz::fuzz;
use litecoin::hashes::Hash;
use litecoin::BlockHash;

/// Whether this input reached the accept-then-mutate assertions, for the coverage
/// check in the test below.
fn do_test_reports(data: &[u8]) -> bool {
    let mut c = Cursor::new(data);
    let block_hash = BlockHash::from_byte_array(c.arr32());
    let claimed_root = c.arr32();
    let size_sel = c.u64();
    let blob = c.rest().to_vec();

    // Derive the claimed MMR size from the blob most of the time. A raw `u64` is
    // essentially always above `MAX_OUTPUT_MMR_SIZE`, which would early-return on
    // every input and leave the mutation assertions below dead. Keep one path in
    // eight fully unconstrained so the bound check is still exercised.
    let mmr_size = if size_sel % 8 == 0 {
        size_sel
    } else {
        size_sel % (blob.len() as u64 * 8 + 1)
    };

    let leafset = MwebLeafset {
        block_hash,
        leafset: blob.clone(),
    };

    // Arbitrary root: essentially always rejected, but it exercises the length and
    // bound checks ahead of the comparison.
    if verify_leafset(&leafset, &claimed_root, mmr_size).is_ok() {
        assert!(mmr_size <= MAX_OUTPUT_MMR_SIZE);
    }

    // Now the honest case. Only meaningful when the blob is long enough to cover the
    // claimed size, which is the same condition `verify_leafset` enforces.
    let need = mmr_size.div_ceil(8);
    if mmr_size > MAX_OUTPUT_MMR_SIZE || need > blob.len() as u64 {
        return false;
    }
    let need = need as usize;
    let true_root = blake3_hash(&blob[..need]);
    verify_leafset(&leafset, &true_root, mmr_size)
        .expect("leafset must verify against its own root");

    // Trailing bytes beyond `need` are explicitly outside the commitment, so
    // appending must not change the verdict.
    let mut extended = blob.clone();
    extended.push(0xAB);
    let extended = MwebLeafset {
        block_hash,
        leafset: extended,
    };
    verify_leafset(&extended, &true_root, mmr_size)
        .expect("trailing bytes past output_mmr_size are not covered by the root");

    // Any change *inside* the committed prefix must be rejected.
    if need > 0 {
        let flip_byte = (c.u32() as usize) % need;
        let mut mutated = blob.clone();
        mutated[flip_byte] ^= 1 << (c.u8() % 8);
        if mutated[..need] != blob[..need] {
            let mutated = MwebLeafset {
                block_hash,
                leafset: mutated,
            };
            assert!(
                verify_leafset(&mutated, &true_root, mmr_size).is_err(),
                "a mutated leafset verified against the original root"
            );
        }
    }

    // Truncating below `need` must be rejected rather than hashing a short buffer.
    if need > 0 {
        let truncated = MwebLeafset {
            block_hash,
            leafset: blob[..need - 1].to_vec(),
        };
        assert!(
            verify_leafset(&truncated, &true_root, mmr_size).is_err(),
            "a truncated leafset was accepted"
        );
    }

    true
}

fn do_test(data: &[u8]) {
    do_test_reports(data);
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
    ///
    /// Also asserts the corpus actually reaches the accept-then-mutate path. Without
    /// that check, a change to how `mmr_size` is derived could make every input
    /// early-return and the target would keep passing while testing nothing.
    #[test]
    fn sweep_pseudorandom_corpus() {
        let reached = std::sync::atomic::AtomicU32::new(0);
        bdk_mweb_fuzz::sweep(2000, |data| {
            if super::do_test_reports(data) {
                reached.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        let reached = reached.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            reached > 200,
            "only {reached}/2000 inputs reached the mutation assertions"
        );
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
