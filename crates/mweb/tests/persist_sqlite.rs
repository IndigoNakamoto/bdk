//! Parallel MWEB coin persistence via SQLite (feature `rusqlite`).

#![cfg(feature = "rusqlite")]

use bdk_mweb::{ChangeSet, MwebCoin, MwebCoinDatabase};
use rusqlite::Connection;

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
        block_height: Some(42),
        is_pegin: false,
    }
}

#[test]
fn insert_persist_reload_roundtrip() {
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    ChangeSet::init_sqlite_tables(&tx).unwrap();

    let mut db = MwebCoinDatabase::new();
    let c1 = sample_coin(1, 50_000);
    let c2 = sample_coin(2, 75_000);
    db.insert(c1.clone());
    db.insert(c2.clone());
    db.take_staged().persist_to_sqlite(&tx).unwrap();
    tx.commit().unwrap();

    let tx = conn.transaction().unwrap();
    let loaded = MwebCoinDatabase::from_changeset(ChangeSet::from_sqlite(&tx).unwrap());
    assert_eq!(loaded.balance(), 125_000);
    assert_eq!(loaded.get(&c1.output_id), Some(&c1));
    assert_eq!(loaded.get(&c2.output_id).unwrap().block_height, Some(42));
}

#[test]
fn mark_spent_persists_across_reload() {
    let mut conn = Connection::open_in_memory().unwrap();
    {
        let tx = conn.transaction().unwrap();
        let mut db = MwebCoinDatabase::new();
        let c1 = sample_coin(1, 50_000);
        db.insert(c1);
        db.take_staged().persist_to_sqlite(&tx).unwrap();
        tx.commit().unwrap();
    }
    {
        let tx = conn.transaction().unwrap();
        let mut db = MwebCoinDatabase::from_changeset(ChangeSet::from_sqlite(&tx).unwrap());
        let id = sample_coin(1, 50_000).output_id;
        assert!(db.mark_spent(&id));
        db.take_staged().persist_to_sqlite(&tx).unwrap();
        tx.commit().unwrap();
    }
    let tx = conn.transaction().unwrap();
    let db = MwebCoinDatabase::from_changeset(ChangeSet::from_sqlite(&tx).unwrap());
    let id = sample_coin(1, 50_000).output_id;
    assert_eq!(db.balance(), 0);
    assert!(db.is_spent(&id));
}
