//! F-Z03: `mwebheader` decode.
//!
//! `MwebHeaderMsg` embeds a `MerkleBlock` and a full `Transaction`, so this target
//! reaches deep into the litecoin consensus decoders with peer-controlled bytes.
//! Those two fields are also what `VerifyMode::Anchored` verification consumes, so
//! they must survive decode before they can be checked.

use bdk_mweb::p2p::MwebHeaderMsg;
use honggfuzz::fuzz;
use litecoin::consensus::encode::{deserialize, serialize};

fn do_test(data: &[u8]) {
    let Ok(decoded) = deserialize::<MwebHeaderMsg>(data) else {
        return;
    };

    assert_eq!(
        serialize(&decoded),
        data,
        "mwebheader round-trip changed bytes"
    );

    // `header_hash` is the commitment anchoring checks compare against, and it runs
    // on the decoded header before any of it has been validated.
    let _ = bdk_mweb::p2p::header_hash(&decoded.mweb_header);

    // Extracting matches from a hostile partial merkle tree must not panic; it is
    // the first thing anchored verification does.
    let mut txids = Vec::new();
    let mut indexes = Vec::new();
    let _ = decoded.merkle.extract_matches(&mut txids, &mut indexes);
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
