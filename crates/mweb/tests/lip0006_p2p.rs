//! Real litecoind P2P LIP-0006 sync with [`VerifyMode::HeaderAndPmmr`].
//!
//! Needs `LITECOIND_EXE` (skips when unset).

#![cfg(feature = "lip0006")]

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006::{sync_mweb_at_tip, VerifyMode};
use bdk_mweb::lip0006_tcp::TcpMwebPeer;
use bdk_mweb::{AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::try_node_from_env;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, Network, NetworkKind};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn tcp_p2p_header_and_pmmr_syncs_owned_balance() {
    let Some(env) = try_node_from_env().expect("harness") else {
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
    let addr = keys.address(2, NetworkKind::Test, &secp).unwrap();

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let amount = Amount::from_btc(1.0).unwrap();
    env.finalize_mweb_pegin(&addr, amount)
        .expect("Core sendtoaddress mweb");
    env.mine_mweb_activation(&mining).expect("activate");

    let tip_height = env.rpc.get_block_count().unwrap() as u32;
    let tip_hash = env.rpc.get_block_hash(tip_height).unwrap();

    let mut peer = TcpMwebPeer::connect(env.p2p_addr(), Network::Regtest).expect("p2p connect");
    let mut db = MwebCoinDatabase::new();
    let result = sync_mweb_at_tip(
        &mut peer,
        &keys,
        &book,
        &mut db,
        &secp,
        tip_hash,
        tip_height,
        VerifyMode::HeaderAndPmmr,
    )
    .expect("verified LIP sync");

    assert!(
        !result.found.is_empty(),
        "expected at least one owned output"
    );
    assert_eq!(
        db.balance(),
        amount.to_sat(),
        "owned MWEB balance after HeaderAndPmmr sync"
    );
}
