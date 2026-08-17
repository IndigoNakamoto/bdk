//! Phase 5: BDK-authored peg-in → mature → peg-out, without Core `sendtoaddress` for the body.
//!
//! Requires `LITECOIND_EXE`. Skips when unset.

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
#[allow(deprecated)]
use bdk_mweb::tx_builder::{build_pegin, kernel_id, MwebTxBuilder, CHANGE_ADDRESS_INDEX};
use bdk_mweb::{scan_litecoin_tx, AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::{try_node_from_env, MWEB_PEGIN_MATURITY};
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, Network};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn bdk_pegin_then_pegout_roundtrip() {
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
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp).unwrap();

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");

    // --- Peg-in (BDK body) ---
    let pegin_amount = Amount::from_btc(1.0).unwrap();
    let mweb_fee = Amount::from_sat(50_000);
    #[allow(deprecated)]
    let pegin = build_pegin(
        &keys,
        2,
        pegin_amount.to_sat(),
        mweb_fee.to_sat(),
        Network::Regtest,
        &secp,
    )
    .expect("build_pegin");
    assert_eq!(
        kernel_id(pegin.mw_tx.body.kernels.first().unwrap()),
        pegin.kernel_id
    );

    let pegin_tx = env
        .broadcast_bdk_pegin(pegin.kernel_id, pegin_amount, pegin.mw_tx.clone())
        .expect("broadcast BDK peg-in");
    assert!(pegin_tx.mw_tx.is_some());

    env.mine_mweb_activation(&mining).expect("activate");
    env.mine_blocks(MWEB_PEGIN_MATURITY, &mining)
        .expect("maturity");

    let mut db = MwebCoinDatabase::new();
    let found = scan_litecoin_tx(&keys, &book, &pegin_tx, &mut db, &secp).expect("scan peg-in");
    let receive_amt = pegin_amount.to_sat() - mweb_fee.to_sat();
    assert_eq!(db.balance(), receive_amt);
    let coin = found
        .into_iter()
        .find(|c| c.address_index == 2 && c.amount == receive_amt)
        .expect("rewound peg-in coin");
    assert!(coin.spend_key.is_some());

    // --- Peg-out to Core-watched transparent address ---
    let pegout_addr = env.rpc.get_new_address().expect("pegout addr");
    let pegout_amt = Amount::from_btc(0.3).unwrap();
    let pegout_fee = Amount::from_sat(50_000);

    let finished = MwebTxBuilder::new()
        .add_input(coin.clone())
        .add_pegout(pegout_addr.script_pubkey(), pegout_amt.to_sat())
        .fee(pegout_fee.to_sat())
        .finish(&keys, CHANGE_ADDRESS_INDEX, Network::Regtest, &secp)
        .expect("peg-out finish");

    let (allowed, reason) = env
        .rpc
        .test_mempool_accept(&finished.tx)
        .expect("testmempoolaccept");
    assert!(
        allowed,
        "litecoind must accept BDK peg-out; reject-reason={reason:?}"
    );
    env.rpc
        .send_raw_transaction(&finished.tx)
        .expect("send peg-out");
    env.mine_blocks(1, &mining)
        .expect("confirm peg-out / HogEx");

    // HogEx pays the peg-out SPK. Core's listunspent may omit HogEx outs; credit via RPC + tip.
    let tip = env.rpc.get_block_count().expect("height");
    let tip_hash = env.rpc.get_block_hash(tip).expect("tip hash");
    let tip_block = env.rpc.get_block(&tip_hash).expect("tip block");
    let hogex = tip_block.txdata.last().expect("hogex");
    assert!(hogex.is_hog_ex, "tip must end with HogEx");
    assert!(
        hogex
            .output
            .iter()
            .any(|o| { o.value == pegout_amt && o.script_pubkey == pegout_addr.script_pubkey() }),
        "HogEx must contain peg-out {pegout_amt} to watched SPK; outputs={:?}",
        hogex
            .output
            .iter()
            .map(|o| (o.value, o.script_pubkey.clone()))
            .collect::<Vec<_>>(),
    );
    let received = env
        .rpc
        .call(
            "getreceivedbyaddress",
            serde_json::json!([pegout_addr.to_string(), 1]),
        )
        .expect("getreceivedbyaddress");
    let received_btc = received.as_f64().expect("getreceivedbyaddress amount");
    assert_eq!(
        Amount::from_btc(received_btc).expect("amount"),
        pegout_amt,
        "wallet must credit peg-out amount"
    );

    // Rescan MWEB: input spent, change present.
    let mut db2 = MwebCoinDatabase::new();
    db2.insert(coin);
    let _ = scan_litecoin_tx(&keys, &book, &finished.tx, &mut db2, &secp).expect("rescan");
    assert!(db2.get(&finished.spent_output_ids[0]).is_none());
    let change_amt = receive_amt - pegout_amt.to_sat() - pegout_fee.to_sat();
    assert_eq!(db2.balance(), change_amt);
}
