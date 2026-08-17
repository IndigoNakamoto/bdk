//! Regtest: matured Core peg-in → BDK `MwebTxBuilder` spend → litecoind accept + payee credit.
//!
//! Requires `LITECOIND_EXE`. Skips when unset.

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::tx_builder::{MwebTxBuilder, CHANGE_ADDRESS_INDEX};
use bdk_mweb::{scan_litecoin_tx, AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::{try_node_from_env, MWEB_PEGIN_MATURITY};
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, Network};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn bdk_mweb_spend_accepted_by_litecoind() {
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

    let addr = keys.address(2, Network::Regtest, &secp).unwrap();
    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let peg_in = Amount::from_btc(1.0).unwrap();
    let pegin_tx = env
        .finalize_mweb_pegin(&addr, peg_in)
        .expect("Core sendtoaddress mweb");
    env.mine_mweb_activation(&mining).expect("activate");
    env.mine_blocks(MWEB_PEGIN_MATURITY, &mining)
        .expect("maturity");

    let mut db = MwebCoinDatabase::new();
    let found = scan_litecoin_tx(&keys, &book, &pegin_tx, &mut db, &secp).expect("scan");
    assert_eq!(db.balance(), peg_in.to_sat());
    let coin = found
        .into_iter()
        .find(|c| c.address_index == 2 && c.amount == peg_in.to_sat())
        .expect("coin at index 2");
    assert!(
        coin.spend_key.is_some(),
        "spend key required for Input::Create"
    );

    let payee = env.rpc.get_new_mweb_address().expect("payee mweb addr");
    let pay_amount = Amount::from_btc(0.3).unwrap();
    // MWEB weight is dominated by 675-byte proofs; keep fee above minrelay.
    let fee = Amount::from_sat(50_000);

    let finished = MwebTxBuilder::new()
        .add_input(coin.clone())
        .add_recipient(payee.clone(), pay_amount.to_sat())
        .fee(fee.to_sat())
        .finish(&keys, CHANGE_ADDRESS_INDEX, Network::Regtest, &secp)
        .expect("MwebTxBuilder::finish");

    let (allowed, reason) = env
        .rpc
        .test_mempool_accept(&finished.tx)
        .expect("testmempoolaccept");
    assert!(
        allowed,
        "litecoind must accept BDK MWEB spend; reject-reason={reason:?}"
    );

    let _txid = env
        .rpc
        .send_raw_transaction(&finished.tx)
        .expect("sendrawtransaction");
    env.mine_blocks(1, &mining).expect("confirm spend");

    let credited = env
        .rpc
        .list_received_by_mweb_address(&payee, 1)
        .expect("listreceived");
    assert_eq!(
        credited, pay_amount,
        "Core payee must be credited after BDK spend"
    );

    // Rescan: input spent, change owned.
    let mut db2 = MwebCoinDatabase::new();
    db2.insert(coin);
    let _ = scan_litecoin_tx(&keys, &book, &finished.tx, &mut db2, &secp).expect("rescan");
    assert!(
        db2.get(&finished.spent_output_ids[0]).is_none(),
        "input must be marked spent"
    );
    let change_amt = peg_in.to_sat() - pay_amount.to_sat() - fee.to_sat();
    assert_eq!(db2.balance(), change_amt, "change should be rewound");
    if let Some(change) = finished.change {
        assert_eq!(change.amount, change_amt);
        assert_eq!(change.address_index, CHANGE_ADDRESS_INDEX);
    }
}
