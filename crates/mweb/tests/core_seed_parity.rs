//! Compare `bdk_mweb` Core-scheme addresses to litecoind after `sethdseed`.
//!
//! Requires `LITECOIND_EXE`. Skips when unset.
//!
//! Note: a *blank* wallet + `sethdseed` does not refill the MWEB keypool on Core 0.21;
//! use a normal HD wallet and replace the seed instead.

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_testenv::try_node_from_env;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, NetworkKind, PrivateKey};
use hex_conservative::FromHex;
use serde_json::json;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn core_mweb_addresses_match_bdk_after_sethdseed() {
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

    // Core `sethdseed` takes a WIF whose raw secret is the BIP32 seed material.
    let seed_sk = SecretKey::from_slice(&seed).expect("seed is valid secret");
    let wif = PrivateKey::new(seed_sk, Network::Regtest).to_wif();

    // Replace the harness wallet seed (non-blank: blank wallets do not top up MWEB keys).
    let _ = env.rpc.call("unloadwallet", json!(["bdk"]));
    env.rpc
        .call("createwallet", json!(["mwebkeys"]))
        .expect("createwallet");
    env.rpc
        .call("sethdseed", json!([true, wif]))
        .expect("sethdseed");

    // Core reserves MWEB indices 0 and 1 (change / peg-in); `getnewaddress` starts at 2.
    for index in 2u32..6 {
        let expected = keys
            .address(index, NetworkKind::Test, &secp)
            .unwrap()
            .to_string();
        let v = env
            .rpc
            .call("getnewaddress", json!(["", "mweb"]))
            .expect("getnewaddress mweb");
        let got = v.as_str().expect("address string");
        assert_eq!(
            got, expected,
            "Core getnewaddress mweb != bdk_mweb at index {index}"
        );
    }
}
