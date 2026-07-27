//! LIP-0006 sync via a scripted peer fed from a Core-authored MWEB receive.
//!
//! Needs `LITECOIND_EXE` (skips when unset).

#![cfg(feature = "lip0006")]

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006::{sync_mweb_utxos, ScriptedMwebSource};
use bdk_mweb::p2p::MwebLeafset;
use bdk_mweb::{AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::try_node_from_env;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, BlockHash, Network, NetworkKind};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn scripted_lip0006_sync_rewinds_core_output() {
    let Some(env) = try_node_from_env().expect("harness") else {
        return;
    };

    let seed = <Vec<u8>>::from_hex(SEED_HEX).unwrap();
    let secp = Secp256k1::new();
    let keys =
        MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
            .unwrap();
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp).unwrap();
    let addr = keys.address(2, NetworkKind::Test, &secp).unwrap();

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let amount = Amount::from_btc(1.0).unwrap();
    let tx = env
        .finalize_mweb_pegin(&addr, amount)
        .expect("Core sendtoaddress mweb");
    let mw = tx.mw_tx.as_ref().expect("mw_tx");
    env.mine_mweb_activation(&mining).expect("activate");

    let tip = env.rpc.get_block_count().unwrap();
    let tip_hash = env.rpc.get_block_hash(tip).unwrap();

    let outputs: Vec<_> = mw
        .body
        .outputs
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, o)| (i as u64, o))
        .collect();
    let indices: Vec<u64> = outputs.iter().map(|(i, _)| *i).collect();
    let mut source = ScriptedMwebSource {
        leafset: MwebLeafset::from_indices(tip_hash, &indices),
        utxos: outputs,
        parent_hashes: vec![[0xab; 32]],
    };

    let mut db = MwebCoinDatabase::new();
    let result = sync_mweb_utxos(
        &mut source,
        &keys,
        &book,
        &mut db,
        &secp,
        tip_hash,
        Some(tip),
        50,
        true,
    )
    .expect("sync");

    assert!(!result.found.is_empty(), "should rewind owned output");
    assert_eq!(db.balance(), amount.to_sat());
    assert!(result.found.iter().any(|c| c.address_index == 2));
    assert!(result.found.iter().all(|c| c.block_height == Some(tip)));
    let _ = BlockHash::from_byte_array(tip_hash.to_byte_array());
}
