//! Core → BDK MWEB receive: `sendtoaddress` then rewind `mw_tx` outputs.
//!
//! Requires `LITECOIND_EXE`. Skips when unset.

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::{scan_litecoin_tx, AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::try_node_from_env;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, Network, NetworkKind};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn core_send_to_bdk_address_is_rewound() {
    let Some(env) = try_node_from_env().expect("node harness") else {
        return;
    };

    let seed = <Vec<u8>>::from_hex(SEED_HEX).unwrap();
    let secp = Secp256k1::new();
    let keys =
        MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
            .unwrap();
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp).unwrap();

    // Index 2 is the first user receive index in Core's keypool convention.
    let addr = keys.address(2, NetworkKind::Test, &secp).unwrap();
    assert!(addr.to_string().starts_with("tmweb1"));

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let amount = Amount::from_btc(1.0).unwrap();
    let tx = env
        .finalize_mweb_pegin(&addr, amount)
        .expect("Core sendtoaddress mweb");
    assert!(tx.mw_tx.is_some(), "payment must carry mw_tx");

    env.mine_mweb_activation(&mining).expect("activate");

    let mut db = MwebCoinDatabase::new();
    let found = scan_litecoin_tx(&keys, &book, &tx, &mut db, &secp).expect("scan");
    assert!(
        !found.is_empty(),
        "expected at least one rewound output for BDK address"
    );

    // Core does not credit a foreign stealth address via listreceived; assert the send amount.
    assert_eq!(
        db.balance(),
        amount.to_sat(),
        "rewound MWEB value must equal sendtoaddress amount; found={found:?}"
    );
    assert_eq!(db.unspent_count(), found.len());
    assert!(
        found.iter().any(|c| c.address_index == 2 && c.amount == amount.to_sat()),
        "expected a coin at address index 2 for {amount}; got {:?}",
        found
            .iter()
            .map(|c| (c.address_index, c.amount))
            .collect::<Vec<_>>()
    );
}
