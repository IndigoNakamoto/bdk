//! SQLite persistence for [`crate::ChangeSet`] (parallel to the wallet DB).
//!
//! Enabled with feature `rusqlite`. Tables live beside (not inside) wallet schema.

use alloc::vec::Vec;

use rusqlite::named_params;
use rusqlite::{OptionalExtension, Transaction};

use crate::changeset::ChangeSet;
use crate::coin_db::MwebCoin;

const SCHEMA_NAME: &str = "bdk_mweb";
const COINS_TABLE: &str = "bdk_mweb_coins";

const V0: &str = "
CREATE TABLE bdk_mweb_coins (
    output_id BLOB PRIMARY KEY NOT NULL,
    commitment BLOB NOT NULL,
    amount INTEGER NOT NULL,
    address_index INTEGER NOT NULL,
    blind BLOB NOT NULL,
    shared_secret BLOB NOT NULL,
    spend_key BLOB,
    block_height INTEGER,
    spent INTEGER NOT NULL DEFAULT 0
) STRICT;
";

const V1: &str = "
ALTER TABLE bdk_mweb_coins ADD COLUMN is_pegin INTEGER NOT NULL DEFAULT 0;
";

fn init_schemas_table(db_tx: &Transaction<'_>) -> rusqlite::Result<()> {
    db_tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS bdk_schemas (
            name TEXT PRIMARY KEY NOT NULL,
            version INTEGER NOT NULL
        ) STRICT;",
    )?;
    Ok(())
}

fn schema_version(db_tx: &Transaction<'_>, name: &str) -> rusqlite::Result<Option<u32>> {
    db_tx
        .query_row(
            "SELECT version FROM bdk_schemas WHERE name=:name",
            named_params! { ":name": name },
            |row| row.get::<_, u32>(0),
        )
        .optional()
}

fn set_schema_version(db_tx: &Transaction<'_>, name: &str, version: u32) -> rusqlite::Result<()> {
    db_tx.execute(
        "REPLACE INTO bdk_schemas(name, version) VALUES(:name, :version)",
        named_params! { ":name": name, ":version": version },
    )?;
    Ok(())
}

fn migrate_schema(
    db_tx: &Transaction<'_>,
    schema_name: &str,
    versioned_scripts: &[&str],
) -> rusqlite::Result<()> {
    init_schemas_table(db_tx)?;
    let current = schema_version(db_tx, schema_name)?;
    let exec_from = current.map_or(0_usize, |v| v as usize + 1);
    for (version, script) in versioned_scripts.iter().enumerate().skip(exec_from) {
        set_schema_version(db_tx, schema_name, version as u32)?;
        db_tx.execute_batch(script)?;
    }
    Ok(())
}

fn blob32(bytes: &[u8; 32]) -> Vec<u8> {
    bytes.to_vec()
}

fn blob33(bytes: &[u8; 33]) -> Vec<u8> {
    bytes.to_vec()
}

fn read_coin(row: &rusqlite::Row<'_>) -> rusqlite::Result<MwebCoin> {
    let output_id: Vec<u8> = row.get("output_id")?;
    let commitment: Vec<u8> = row.get("commitment")?;
    let blind: Vec<u8> = row.get("blind")?;
    let shared_secret: Vec<u8> = row.get("shared_secret")?;
    let spend_key: Option<Vec<u8>> = row.get("spend_key")?;
    let mut oid = [0u8; 32];
    let mut cmt = [0u8; 33];
    let mut bl = [0u8; 32];
    let mut ss = [0u8; 32];
    if output_id.len() != 32 || commitment.len() != 33 || blind.len() != 32 || shared_secret.len() != 32
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    oid.copy_from_slice(&output_id);
    cmt.copy_from_slice(&commitment);
    bl.copy_from_slice(&blind);
    ss.copy_from_slice(&shared_secret);
    let spend = match spend_key {
        Some(v) if v.len() == 32 => {
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&v);
            Some(sk)
        }
        Some(_) => return Err(rusqlite::Error::InvalidQuery),
        None => None,
    };
    Ok(MwebCoin {
        output_id: oid,
        commitment: cmt,
        amount: row.get::<_, i64>("amount")? as u64,
        address_index: row.get::<_, i64>("address_index")? as u32,
        blind: bl,
        shared_secret: ss,
        spend_key: spend,
        block_height: row
            .get::<_, Option<i64>>("block_height")?
            .map(|h| h as u32),
        is_pegin: row.get::<_, i64>("is_pegin").unwrap_or(0) != 0,
    })
}

fn upsert_coin(db_tx: &Transaction<'_>, coin: &MwebCoin, spent: bool) -> rusqlite::Result<()> {
    db_tx.execute(
        &format!(
            "REPLACE INTO {COINS_TABLE} (
                output_id, commitment, amount, address_index,
                blind, shared_secret, spend_key, block_height, spent, is_pegin
            ) VALUES (
                :output_id, :commitment, :amount, :address_index,
                :blind, :shared_secret, :spend_key, :block_height, :spent, :is_pegin
            )"
        ),
        named_params! {
            ":output_id": blob32(&coin.output_id),
            ":commitment": blob33(&coin.commitment),
            ":amount": coin.amount as i64,
            ":address_index": coin.address_index as i64,
            ":blind": blob32(&coin.blind),
            ":shared_secret": blob32(&coin.shared_secret),
            ":spend_key": coin.spend_key.as_ref().map(blob32),
            ":block_height": coin.block_height.map(|h| h as i64),
            ":spent": if spent { 1i64 } else { 0i64 },
            ":is_pegin": if coin.is_pegin { 1i64 } else { 0i64 },
        },
    )?;
    Ok(())
}

impl ChangeSet {
    /// Create / migrate MWEB SQLite tables.
    pub fn init_sqlite_tables(db_tx: &Transaction<'_>) -> rusqlite::Result<()> {
        migrate_schema(db_tx, SCHEMA_NAME, &[V0, V1])
    }

    /// Load the full coin table into a changeset.
    pub fn from_sqlite(db_tx: &Transaction<'_>) -> rusqlite::Result<Self> {
        let mut cs = ChangeSet::default();
        let mut stmt = db_tx.prepare(&format!(
            "SELECT output_id, commitment, amount, address_index, blind, shared_secret,
                    spend_key, block_height, spent, is_pegin FROM {COINS_TABLE}"
        ))?;
        let rows = stmt.query_map([], |row| {
            let spent: i64 = row.get("spent")?;
            let coin = read_coin(row)?;
            Ok((spent != 0, coin))
        })?;
        for row in rows {
            let (spent, coin) = row?;
            if spent {
                cs.spent.insert(coin.output_id, coin);
            } else {
                cs.coins.insert(coin.output_id, coin);
            }
        }
        Ok(cs)
    }

    /// Persist this changeset (upsert coins / mark spent).
    pub fn persist_to_sqlite(&self, db_tx: &Transaction<'_>) -> rusqlite::Result<()> {
        Self::init_sqlite_tables(db_tx)?;
        for coin in self.coins.values() {
            upsert_coin(db_tx, coin, false)?;
        }
        for coin in self.spent.values() {
            upsert_coin(db_tx, coin, true)?;
        }
        Ok(())
    }
}
