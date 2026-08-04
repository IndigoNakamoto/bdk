//! F-Z02: `mwebutxos` decode.
//!
//! This is the largest attacker-controlled structure in the protocol: two length
//! prefixes plus a nested `Output` (which itself carries a 675-byte rangeproof and
//! variable-length extra data) per entry. Every field here reaches the decoder
//! before any verification runs.

use bdk_mweb::limits::{MAX_PARENT_HASHES, MAX_UTXOS_PER_BATCH};
use bdk_mweb::p2p::{MwebUtxos, OUTPUT_FORMAT_FULL};
use honggfuzz::fuzz;
use litecoin::consensus::encode::{deserialize, serialize};

fn do_test(data: &[u8]) {
    let Ok(decoded) = deserialize::<MwebUtxos>(data) else {
        return;
    };

    assert!(decoded.utxos.len() <= MAX_UTXOS_PER_BATCH);
    assert!(decoded.parent_hashes.len() <= MAX_PARENT_HASHES);
    // The format check moved ahead of the entry loop, so no accepted message can
    // carry a format we would not have parsed.
    assert_eq!(decoded.output_format, OUTPUT_FORMAT_FULL);

    // Non-canonical encodings (e.g. non-minimal VarInts) are accepted by
    // consensus decode; only require the canonical form to be stable.
    let reserialized = serialize(&decoded);
    if reserialized != data {
        let again: MwebUtxos = deserialize(&reserialized)
            .expect("canonical mwebutxos encoding must decode");
        assert_eq!(again, decoded, "canonical mwebutxos re-decode changed value");
        assert_eq!(
            serialize(&again),
            reserialized,
            "canonical mwebutxos form unstable"
        );
    }

    // `output_id` runs on every entry during sync, before anything has been
    // verified, so it must tolerate whatever the decoder let through.
    for entry in &decoded.utxos {
        let _ = bdk_mweb::scan::output_id(&entry.output);
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

    /// As with the leafset target, random bytes never decode into a valid
    /// `mwebutxos`, so the assertions above need real encodings to run against.
    #[test]
    fn sweep_valid_encodings() {
        use bdk_mweb::p2p::MwebUtxoEntry;
        use litecoin::blockdata::mimblewimble::{Output, OutputMessage};
        use litecoin::consensus::encode::serialize;
        use litecoin::hashes::Hash;
        use litecoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);

        for n in [0usize, 1, 2, 16] {
            for extra in [0usize, 1, 300] {
                let utxos = (0..n)
                    .map(|i| MwebUtxoEntry {
                        leaf_index: i as u64,
                        output: Output {
                            commitment: [i as u8; 33],
                            sender_public_key: pk,
                            receiver_public_key: pk,
                            message: OutputMessage {
                                features: 0,
                                standard_fields: None,
                                extra_data: vec![0xAB; extra],
                            },
                            range_proof: [i as u8; 675],
                            signature: [0u8; 64],
                        },
                    })
                    .collect();
                let msg = super::MwebUtxos {
                    block_hash: litecoin::BlockHash::from_byte_array([5u8; 32]),
                    start_index: 0,
                    output_format: super::OUTPUT_FORMAT_FULL,
                    utxos,
                    parent_hashes: (0..n).map(|i| [i as u8; 32]).collect(),
                };
                super::do_test(&serialize(&msg));
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
