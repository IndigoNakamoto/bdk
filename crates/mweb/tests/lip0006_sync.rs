//! LIP-0006 sync via a scripted peer fed from a Core-authored MWEB receive.
//!
//! Needs `LITECOIND_EXE` (skips when unset).

#![cfg(feature = "lip0006")]

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006::{sync_mweb_utxos, ScriptedMwebSource, VerifyMode};
use bdk_mweb::p2p::{MwebHeaderMsg, MwebLeafset};
use bdk_mweb::{AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::try_node_from_env;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::blockdata::block::MwebBlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::{
    Amount, BlockHash, CompactTarget, MerkleBlock, Network, NetworkKind, Transaction, TxMerkleNode,
};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn dummy_header_msg(tip: u32, mmr_size: u64) -> MwebHeaderMsg {
    // PartialMerkleTree::from_txids rejects an empty set; Trusted sync never encodes this.
    let dummy_txid = bitcoin::Txid::from_byte_array([1u8; 32]);
    MwebHeaderMsg {
        merkle: MerkleBlock {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txn: PartialMerkleTree::from_txids(&[dummy_txid], &[true]),
        },
        hogex: Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
            mw_tx: None,
            is_hog_ex: false,
        },
        mweb_header: MwebBlockHeader {
            height: tip,
            output_root: [0; 32],
            kernel_root: [0; 32],
            leafset_root: [0; 32],
            kernel_offset: [0; 32],
            stealth_offset: [0; 32],
            output_mmr_size: mmr_size,
            kernel_mmr_size: 1,
        },
    }
}

#[test]
fn scripted_lip0006_sync_rewinds_core_output() {
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
    let tx = env
        .finalize_mweb_pegin(&addr, amount)
        .expect("Core sendtoaddress mweb");
    let mw = tx.mw_tx.as_ref().expect("mw_tx");
    env.mine_mweb_activation(&mining).expect("activate");

    let tip = env.rpc.get_block_count().unwrap() as u32;
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
        header: dummy_header_msg(tip, indices.len() as u64),
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
        VerifyMode::Trusted,
    )
    .expect("sync");

    assert!(!result.found.is_empty(), "should rewind owned output");
    assert_eq!(db.balance(), amount.to_sat());
    assert!(result.found.iter().any(|c| c.address_index == 2));
    assert!(result.found.iter().all(|c| c.block_height == Some(tip)));
}

#[test]
fn verify_mode_rejects_tampered_leafset() {
    use bdk_mweb::hash::blake3_hash;
    use bdk_mweb::pmmr::verify_leafset;

    let hash = BlockHash::from_byte_array([9u8; 32]);
    let ls = MwebLeafset::from_indices(hash, &[0, 1, 2]);
    let root = blake3_hash(&ls.leafset);
    verify_leafset(&ls, &root, 3).unwrap();
    let mut bad = root;
    bad[0] ^= 0xff;
    assert!(verify_leafset(&ls, &bad, 3).is_err());
}
