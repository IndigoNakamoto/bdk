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

    // Consensus decode accepts some non-canonical encodings (e.g. non-minimal
    // VarInts). Byte-identity against the original input is therefore not a
    // crash condition; require that the canonical form is stable instead.
    let reserialized = serialize(&decoded);
    if reserialized != data {
        let again: MwebHeaderMsg = deserialize(&reserialized)
            .expect("canonical mwebheader encoding must decode");
        assert_eq!(again, decoded, "canonical mwebheader re-decode changed value");
        assert_eq!(
            serialize(&again),
            reserialized,
            "canonical mwebheader form unstable"
        );
    }

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

    /// CI crash: non-minimal VarInt encoding that still consensus-decodes.
    /// Must not abort the harness (byte-identity against the input is not required).
    #[test]
    fn known_noncanonical_varint_roundtrip() {
        let mut a = Vec::new();
        extend_vec_from_hex("4021296f6f3eff64ffffffffff012b010101ffffffffffffffff01010101010101010160200000000001000000010101010101010101010101010101010101010100000000000000000000000000019cf8da9830000000007e000008000064cd1d58e70cf3fb2a0800000064fd404e62c7064b7a78d1ecf88eff013c0101010101010101010101fe0101010101000000000000000000000000ff00010000000000040000000060080000010101010101010101010101010101010101010101000000000000000000000000000001000000000004000000006008000001010101010101010101010101020101010101010100000000000000000000000000000100000000000400000000600800000101010101fe0101010101010101010101010101010100000000000000000000000000000100000000000400000000600800000101010101010101010101010101010101010101010000000000000000000000000000010000000000040000000060080000010101010101010101010101010101010101010101000000000000000000000000001900000001000000000100000000000400000000600800000101010101010101010101010000000100000001000000010000000100000001246026010000000100000000000000ffff7f01010101010101010101010101fe0000000008000cf3fb2a6794af1364fd40fd6490f74a7a78d1ecf88eff7f0000000800000101010101010101010101010101010101010101010000000000000000000000000100010000000000040000000060080000010101010101010101010101010101010101010101010101010101010101010101010101010000ef0000000000000000000000000000000000000000000000000b0000000000000058e70cf3fb2a6794af13e4fd40fd6490f74a7a78d1ecf88eff7f20012e2f2301000001010101010101010101000000002500000001010101010101010101010101010101010101", &mut a);
        super::do_test(&a);
    }
}
