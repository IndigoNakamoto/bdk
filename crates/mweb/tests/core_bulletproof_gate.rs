//! Crypto gate: verify a Core-authored 675-byte MWEB bulletproof via Grin/MW FFI.
//!
//! Requires `LITECOIND_EXE`. Skips when unset.

use bdk_mweb::crypto::bulletproof_verify;
use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_testenv::try_node_from_env;
use bitcoin::consensus::encode::serialize;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, Network, NetworkKind};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn core_mw_tx_bulletproof_verifies_under_ffi() {
    let Some(env) = try_node_from_env().expect("node harness") else {
        return;
    };

    let seed = <Vec<u8>>::from_hex(SEED_HEX).unwrap();
    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &seed,
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .unwrap();
    let addr = keys.address(2, NetworkKind::Test, &secp).unwrap();

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let amount = Amount::from_btc(1.0).unwrap();
    let tx = env
        .finalize_mweb_pegin(&addr, amount)
        .expect("Core sendtoaddress mweb");
    env.mine_mweb_activation(&mining).expect("activate");

    let mw = tx.mw_tx.as_ref().expect("mw_tx present");
    assert!(
        !mw.body.outputs.is_empty(),
        "peg-in mw_tx must include outputs"
    );

    let mut verified = 0usize;
    for output in &mw.body.outputs {
        let extra = serialize(&output.message);
        let ok = bulletproof_verify(&output.commitment, &output.range_proof, &extra)
            .expect("FFI verify");
        assert!(
            ok,
            "Core bulletproof must verify; commitment={:02x?}",
            &output.commitment[..4]
        );
        verified += 1;
    }
    assert!(verified > 0);
}
