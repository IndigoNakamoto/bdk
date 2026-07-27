//! In-memory MWEB coin database (separate from transparent `IndexedTxGraph`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// A rewound MWEB output owned by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MwebCoin {
    /// Core `Output::GetOutputID()` (BLAKE3 of selected output fields).
    pub output_id: [u8; 32],
    /// Pedersen / switch commitment (33 bytes).
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
}

impl MwebCoinDatabase {
    /// Empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a coin as unspent.
    pub fn insert(&mut self, coin: MwebCoin) {
        self.spent.remove(&coin.output_id);
        self.coins.insert(coin.output_id, coin);
    }

    /// Get an unspent coin by output id.
    pub fn get(&self, output_id: &[u8; 32]) -> Option<&MwebCoin> {
        self.coins.get(output_id)
    }

    /// Mark an output spent (moves from unspent to spent if present).
    pub fn mark_spent(&mut self, output_id: &[u8; 32]) -> bool {
        if let Some(coin) = self.coins.remove(output_id) {
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
}
