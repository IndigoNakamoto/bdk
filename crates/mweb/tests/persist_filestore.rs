//! Parallel MWEB coin persistence via `bdk_file_store` (feature `persist`).

#![cfg(feature = "persist")]

use bdk_core::Merge;
use bdk_file_store::Store;
use bdk_mweb::{MwebCoin, MwebCoinDatabase};

const MAGIC: &[u8] = b"bdk_mweb_v1";

fn sample_coin(id: u8, amount: u64) -> MwebCoin {
    let mut output_id = [0u8; 32];
    output_id[0] = id;
    MwebCoin {
        output_id,
        commitment: [0x02; 33],
        amount,
        address_index: 2,
        blind: [0x0b; 32],
        shared_secret: [0x0c; 32],
        spend_key: Some([0x0d; 32]),
        block_height: Some(100),
    }
}

#[test]
fn insert_persist_reload_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mweb.db");

    let mut db = MwebCoinDatabase::new();
    let c1 = sample_coin(1, 50_000);
    let c2 = sample_coin(2, 75_000);
    db.insert(c1.clone());
    db.insert(c2.clone());
    assert_eq!(db.balance(), 125_000);

    let staged = db.take_staged();
    assert!(!staged.is_empty());
    {
        let mut store = Store::create(MAGIC, &path).unwrap();
        store.append(&staged).unwrap();
    }

    let (_store, aggregated) = Store::load(MAGIC, &path).unwrap();
    let cs = aggregated.expect("aggregated changeset");
    let loaded = MwebCoinDatabase::from_changeset(cs);
    assert_eq!(loaded.balance(), 125_000);
    assert_eq!(loaded.get(&c1.output_id), Some(&c1));
    assert_eq!(loaded.get(&c2.output_id).unwrap().blind, c2.blind);
    assert_eq!(
        loaded.get(&c2.output_id).unwrap().spend_key,
        c2.spend_key
    );
}

#[test]
fn mark_spent_persists_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mweb_spend.db");

    let mut db = MwebCoinDatabase::new();
    let c1 = sample_coin(1, 50_000);
    db.insert(c1.clone());
    {
        let mut store = Store::create(MAGIC, &path).unwrap();
        store.append(&db.take_staged()).unwrap();
    }

    // Session 2: spend and append.
    {
        let (mut store, aggregated) = Store::load(MAGIC, &path).unwrap();
        let mut db = MwebCoinDatabase::from_changeset(aggregated.unwrap());
        assert!(db.mark_spent(&c1.output_id));
        assert_eq!(db.balance(), 0);
        assert!(db.is_spent(&c1.output_id));
        store.append(&db.take_staged()).unwrap();
    }

    // Session 3: reload — unspent empty, spent retained.
    let (_store, aggregated) = Store::load(MAGIC, &path).unwrap();
    let db = MwebCoinDatabase::from_changeset(aggregated.unwrap());
    assert_eq!(db.balance(), 0);
    assert!(db.get(&c1.output_id).is_none());
    assert!(db.is_spent(&c1.output_id));
    assert_eq!(db.get_spent(&c1.output_id).unwrap().amount, 50_000);
}
