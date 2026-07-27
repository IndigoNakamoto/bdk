//! In-memory MWEB coin database (separate from transparent `IndexedTxGraph`).
//!
//! With feature `persist`, mutations stage a [`crate::changeset::ChangeSet`] for
//! parallel append-only storage (e.g. `bdk_file_store`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[cfg(feature = "persist")]
use crate::changeset::ChangeSet;

/// A rewound MWEB output owned by the wallet.
///
/// # Security
///
/// `blind`, `shared_secret`, and `spend_key` are spend-equivalent secrets. Persist
/// only in encrypted storage; never log them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MwebCoin {
    /// Core `Output::GetOutputID()` (BLAKE3 of selected output fields).
    pub output_id: [u8; 32],
    /// Pedersen / switch commitment (33 bytes).
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_util::bytes33"))]
    pub commitment: [u8; 33],
    /// Unmasked value in litoshis.
    pub amount: u64,
    /// Stealth address index that matched.
    pub address_index: u32,
    /// Pre-switch blinding factor (`Hashed(BLIND, t)`).
    pub blind: [u8; 32],
    /// Shared secret `t = Hashed(DERIVE, a·Ke)`.
    pub shared_secret: [u8; 32],
    /// One-time output spend key `k_o` when the spend secret is available.
    pub spend_key: Option<[u8; 32]>,
}

/// Unspent MWEB coins keyed by output id.
#[derive(Debug, Default, Clone)]
pub struct MwebCoinDatabase {
    coins: BTreeMap<[u8; 32], MwebCoin>,
    spent: BTreeMap<[u8; 32], MwebCoin>,
    #[cfg(feature = "persist")]
    staged: ChangeSet,
}

impl MwebCoinDatabase {
    /// Empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a coin as unspent.
    pub fn insert(&mut self, coin: MwebCoin) {
        self.spent.remove(&coin.output_id);
        #[cfg(feature = "persist")]
        {
            self.staged.spent.remove(&coin.output_id);
            self.staged.coins.insert(coin.output_id, coin.clone());
        }
        self.coins.insert(coin.output_id, coin);
    }

    /// Get an unspent coin by output id.
    pub fn get(&self, output_id: &[u8; 32]) -> Option<&MwebCoin> {
        self.coins.get(output_id)
    }

    /// Mark an output spent (moves from unspent to spent if present).
    pub fn mark_spent(&mut self, output_id: &[u8; 32]) -> bool {
        if let Some(coin) = self.coins.remove(output_id) {
            #[cfg(feature = "persist")]
            {
                self.staged.coins.remove(output_id);
                self.staged.spent.insert(*output_id, coin.clone());
            }
            self.spent.insert(*output_id, coin);
            true
        } else {
            false
        }
    }

    /// Sum of unspent amounts.
    pub fn balance(&self) -> u64 {
        self.coins.values().map(|c| c.amount).sum()
    }

    /// Iterator over unspent coins.
    pub fn unspent(&self) -> impl Iterator<Item = &MwebCoin> {
        self.coins.values()
    }

    /// Number of unspent coins.
    pub fn unspent_count(&self) -> usize {
        self.coins.len()
    }

    /// Snapshot of unspent coins.
    pub fn unspent_vec(&self) -> Vec<MwebCoin> {
        self.coins.values().cloned().collect()
    }

    /// Whether `output_id` is in the spent set.
    pub fn is_spent(&self, output_id: &[u8; 32]) -> bool {
        self.spent.contains_key(output_id)
    }

    /// Get a spent coin by output id (if retained).
    pub fn get_spent(&self, output_id: &[u8; 32]) -> Option<&MwebCoin> {
        self.spent.get(output_id)
    }
}

#[cfg(feature = "persist")]
impl MwebCoinDatabase {
    /// Build a database by applying an aggregated changeset (e.g. from `Store::dump`).
    pub fn from_changeset(cs: ChangeSet) -> Self {
        let mut db = Self::new();
        db.apply_changeset(cs);
        db
    }

    /// Apply a changeset without staging (used on load / replay).
    pub fn apply_changeset(&mut self, cs: ChangeSet) {
        for (id, coin) in cs.coins {
            if self.spent.contains_key(&id) {
                continue;
            }
            self.spent.remove(&id);
            self.coins.insert(id, coin);
        }
        for (id, coin) in cs.spent {
            self.coins.remove(&id);
            self.spent.insert(id, coin);
        }
    }

    /// Peek at the currently staged (not yet persisted) changeset.
    pub fn staged(&self) -> &ChangeSet {
        &self.staged
    }

    /// Mutable access to the staged changeset.
    pub fn staged_mut(&mut self) -> &mut ChangeSet {
        &mut self.staged
    }

    /// Take the staged changeset, leaving it empty.
    pub fn take_staged(&mut self) -> ChangeSet {
        core::mem::take(&mut self.staged)
    }
}
