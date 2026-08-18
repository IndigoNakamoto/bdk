//! LIP-0007 / Core v24 PSBT probe.
//!
//! Requires `LITECOIND_EXE` (v24). Skips when unset.
//!
//! Core golden bytes (cite, do not fork a third map):
//! `src/test/util/psbt_vectors.h`, `test/functional/mweb_psbt.py` in the v24 tree.

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::psbt_fund::fund_mweb_spend;
#[allow(deprecated)]
use bdk_mweb::tx_builder::build_pegin;
use bdk_testenv::{try_node_from_env, MWEB_PEGIN_MATURITY};
use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use bitcoin::key::Secp256k1;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, Network, NetworkKind};
use serde_json::json;

/// Core v24.0 is `240000`. 0.21.x decodepsbt still requires `unsigned_tx`.
fn require_core_v24(env: &bdk_testenv::LitecoinNodeEnv) -> bool {
    let Ok(info) = env.rpc.call("getnetworkinfo", json!([])) else {
        return false;
    };
    let version = info["version"].as_u64().unwrap_or(0);
    if version < 240_000 {
        return false;
    }
    true
}

#[test]
fn core_walletcreatefundedpsbt_keeps_address_descriptor() {
    let Some(env) = try_node_from_env().expect("node harness") else {
        return;
    };
    if !require_core_v24(&env) {
        return;
    }

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let recv = env.rpc.get_new_mweb_address().expect("core mweb addr");
    let pegin = Amount::from_btc(1.0).unwrap();
    env.finalize_mweb_pegin(&recv, pegin)
        .expect("Core sendtoaddress mweb");
    env.mine_mweb_activation(&mining).expect("activate");
    env.mine_blocks(MWEB_PEGIN_MATURITY, &mining)
        .expect("maturity");

    let dest = env.rpc.get_new_mweb_address().expect("dest");
    let created = env
        .rpc
        .call(
            "walletcreatefundedpsbt",
            json!([[], { dest.to_string(): 0.1 }, 0, {}, true]),
        )
        .expect("walletcreatefundedpsbt");
    let b64 = created["psbt"]
        .as_str()
        .expect("walletcreatefundedpsbt.psbt");
    let raw = BASE64_STANDARD.decode(b64).expect("psbt base64");
    let psbt = Psbt::deserialize(&raw).expect("rust-litecoin parse Core PSBT");
    assert_eq!(psbt.version, 2, "LIP-0007 / Core v24 is PSBTv2");
    let desc = psbt
        .mweb_inputs
        .iter()
        .find_map(|i| i.address_descriptor.clone())
        .expect("Core 0x96 address_descriptor");
    assert!(
        desc.starts_with("mweb("),
        "descriptor must be ASCII mweb(...): {desc}"
    );
    assert!(
        psbt.mweb_inputs
            .iter()
            .all(|i| i.master_scan_key_origin.is_none() && i.master_spend_key_origin.is_none()),
        "0x9A/0x9B must stay reserved"
    );
}

#[test]
fn bdk_fund_decodepsbt_is_v2() {
    let Some(env) = try_node_from_env().expect("node harness") else {
        return;
    };
    if !require_core_v24(&env) {
        return;
    }

    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &[11u8; 32],
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .unwrap();
    #[allow(deprecated)]
    let pegin = build_pegin(&keys, 1, 1_000_000, 50_000, NetworkKind::Test, &secp).unwrap();
    let coin = pegin.outputs[0].clone();
    let recv = keys.address(2, NetworkKind::Test, &secp).unwrap();
    let funded = fund_mweb_spend(
        vec![coin.clone()],
        vec![(recv, coin.amount - 50_000)],
        vec![],
        50_000,
        &keys,
        0,
        NetworkKind::Test,
        &secp,
    )
    .unwrap();
    assert!(
        funded.psbt.mweb_inputs[0]
            .address_descriptor
            .as_deref()
            .is_some_and(|d| d.starts_with("mweb("))
    );

    let b64 = BASE64_STANDARD.encode(funded.psbt.serialize());
    let decoded = env
        .rpc
        .call("decodepsbt", json!([b64]))
        .expect("Core decodepsbt of BDK fund packet");
    let version = decoded
        .get("psbt_version")
        .or_else(|| decoded.get("version"))
        .and_then(|v| v.as_u64())
        .expect("decodepsbt version");
    assert_eq!(version, 2, "Core must see a PSBTv2 packet: {decoded}");
}
