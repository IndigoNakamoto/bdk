//! In-memory MWEB coin database (separate from transparent `IndexedTxGraph`).
//!
//! With feature `persist`, mutations stage a [`crate::changeset::ChangeSet`] for
//! parallel append-only storage (e.g. `bdk_file_store`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[cfg(feature = "persist")]
use crate::changeset::ChangeSet;

/// Bucketed unspent MWEB balance at a chain tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MwebBalance {
    /// Coins with a known `block_height` and at least one confirmation at the tip.
    pub confirmed: u64,
    /// Coins with unknown height, or not yet confirmed at the tip.
    pub untrusted_pending: u64,
}

impl MwebBalance {
    /// Confirmed + untrusted pending.
    pub fn total(&self) -> u64 {
        self.confirmed.saturating_add(self.untrusted_pending)
    }
}

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
    /// Inclusion height when known. `None` means unconfirmed / unknown.
    #[cfg_attr(feature = "serde", serde(default))]
    pub block_height: Option<u32>,
}

impl MwebCoin {
    /// Whether this coin has at least one confirmation at `tip_height`.
    pub fn is_confirmed(&self, tip_height: u32) -> bool {
        match self.block_height {
            Some(h) => tip_height >= h,
            None => false,
        }
    }

    /// Set inclusion height (builder-style).
    pub fn with_block_height(mut self, height: u32) -> Self {
        self.block_height = Some(height);
        self
    }
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

    /// Sum of all unspent amounts (confirmed and pending).
    pub fn balance(&self) -> u64 {
        self.coins.values().map(|c| c.amount).sum()
    }

    /// Bucketed unspent balance at `tip_height` (1+ confirmation ⇒ confirmed).
    pub fn balance_at(&self, tip_height: u32) -> MwebBalance {
        let mut bal = MwebBalance::default();
        for coin in self.coins.values() {
            if coin.is_confirmed(tip_height) {
                bal.confirmed = bal.confirmed.saturating_add(coin.amount);
            } else {
                bal.untrusted_pending = bal.untrusted_pending.saturating_add(coin.amount);
            }
        }
        bal
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

    /// Unspent coins with at least one confirmation at `tip_height`.
    pub fn unspent_confirmed(&self, tip_height: u32) -> Vec<MwebCoin> {
        self.coins
            .values()
            .filter(|c| c.is_confirmed(tip_height))
            .cloned()
            .collect()
    }

    /// Set `block_height` on an unspent coin (stages when `persist` is enabled).
    pub fn set_block_height(&mut self, output_id: &[u8; 32], height: u32) -> bool {
        let Some(coin) = self.coins.get_mut(output_id) else {
            return false;
        };
        coin.block_height = Some(height);
        #[cfg(feature = "persist")]
        {
            self.staged
                .coins
                .insert(*output_id, coin.clone());
        }
        true
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
