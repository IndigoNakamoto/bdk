//! In-memory MWEB coin database (separate from transparent `IndexedTxGraph`).
//!
//! With feature `persist`, mutations stage a [`crate::changeset::ChangeSet`] for
//! parallel append-only storage (e.g. `bdk_file_store`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[cfg(feature = "persist")]
use crate::changeset::ChangeSet;

/// Peg-in maturity in blocks (matches Litecoin Core / testenv).
pub const MWEB_PEGIN_MATURITY: u32 = 6;

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
/// `blind`, `shared_secret`, and `spend_key` are spend-equivalent secrets.
/// Persist only in encrypted storage.
///
/// Three protections are structural rather than advisory: [`Drop`] wipes the
/// three secret fields, [`core::fmt::Debug`] redacts them so a stray `{:?}` in
/// a caller's log cannot leak them, and [`PartialEq`] compares them in constant
/// time. The fields stay `[u8; 32]` rather than [`crate::Secret32`] so that
/// struct-literal construction in downstream crates keeps compiling.
#[derive(Clone)]
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
    /// Whether this output was created by a peg-in kernel (needs [`MWEB_PEGIN_MATURITY`]).
    #[cfg_attr(feature = "serde", serde(default))]
    pub is_pegin: bool,
    /// Output PMMR leaf index when known (from LIP-0006 UTXO sync).
    #[cfg_attr(feature = "serde", serde(default))]
    pub leaf_index: Option<u64>,
}

impl core::fmt::Debug for MwebCoin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MwebCoin")
            .field("output_id", &self.output_id)
            .field("commitment", &self.commitment)
            .field("amount", &self.amount)
            .field("address_index", &self.address_index)
            .field("blind", &"<redacted>")
            .field("shared_secret", &"<redacted>")
            .field(
                "spend_key",
                &self.spend_key.map(|_| "<redacted>").unwrap_or("None"),
            )
            .field("block_height", &self.block_height)
            .field("is_pegin", &self.is_pegin)
            .field("leaf_index", &self.leaf_index)
            .finish()
    }
}

/// Hand-written to compare the three secret fields in constant time. Semantics
/// are otherwise identical to the previous derive: full field-by-field equality.
impl PartialEq for MwebCoin {
    fn eq(&self, other: &Self) -> bool {
        self.output_id == other.output_id
            && self.commitment == other.commitment
            && self.amount == other.amount
            && self.address_index == other.address_index
            && self.block_height == other.block_height
            && self.is_pegin == other.is_pegin
            && self.leaf_index == other.leaf_index
            && crate::secret::ct_eq32(&self.blind, &other.blind)
            && crate::secret::ct_eq32(&self.shared_secret, &other.shared_secret)
            && crate::secret::ct_eq32_opt(&self.spend_key, &other.spend_key)
    }
}

impl Eq for MwebCoin {}

/// Best-effort wipe of the spend-equivalent fields. `MwebCoin` is cloned on
/// nearly every database operation, so each clone wipes itself independently.
/// See [`crate::secret`] for what this does and does not guarantee.
impl Drop for MwebCoin {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl MwebCoin {
    /// Overwrite the spend-equivalent fields. Called from [`Drop`]; also
    /// callable directly to shorten a secret's lifetime.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.blind.zeroize();
        self.shared_secret.zeroize();
        if let Some(k) = self.spend_key.as_mut() {
            k.zeroize();
        }
        self.spend_key = None;
    }

    /// Whether this coin has at least one confirmation at `tip_height`.
    pub fn is_confirmed(&self, tip_height: u32) -> bool {
        match self.block_height {
            Some(h) => tip_height >= h,
            None => false,
        }
    }

    /// Whether the coin is confirmed and mature enough to spend at `tip_height`.
    ///
    /// Peg-ins require `tip + 1 - height >= maturity` (Core semantics). Non-pegins
    /// only need a confirmation.
    pub fn is_spendable(&self, tip_height: u32, maturity: u32) -> bool {
        let Some(h) = self.block_height else {
            return false;
        };
        if tip_height < h {
            return false;
        }
        if self.is_pegin {
            tip_height.saturating_add(1).saturating_sub(h) >= maturity
        } else {
            true
        }
    }

    /// Set inclusion height (builder-style).
    pub fn with_block_height(mut self, height: u32) -> Self {
        self.block_height = Some(height);
        self
    }

    /// Mark as peg-in (builder-style).
    pub fn with_pegin(mut self, is_pegin: bool) -> Self {
        self.is_pegin = is_pegin;
        self
    }

    /// Set PMMR leaf index (builder-style).
    pub fn with_leaf_index(mut self, leaf_index: u64) -> Self {
        self.leaf_index = Some(leaf_index);
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
    ///
    /// Saturates rather than wrapping: coin amounts can originate from a peer
    /// (via scan), so the sum must not be able to panic or wrap on fabricated
    /// values.
    pub fn balance(&self) -> u64 {
        self.coins
            .values()
            .fold(0u64, |acc, c| acc.saturating_add(c.amount))
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

    /// Unspent coins that are confirmed and mature at `tip_height`.
    pub fn unspent_spendable(&self, tip_height: u32, maturity: u32) -> Vec<MwebCoin> {
        self.coins
            .values()
            .filter(|c| c.is_spendable(tip_height, maturity))
            .cloned()
            .collect()
    }

    /// Clear inclusion heights for coins at or above `height` (reorg disconnect).
    ///
    /// Does not delete coins; the next verified sync re-tags live UTXOs.
    pub fn disconnect_from(&mut self, height: u32) {
        for coin in self.coins.values_mut() {
            if coin.block_height.is_some_and(|h| h >= height) {
                coin.block_height = None;
                #[cfg(feature = "persist")]
                {
                    self.staged.coins.insert(coin.output_id, coin.clone());
                }
            }
        }
        for coin in self.spent.values_mut() {
            if coin.block_height.is_some_and(|h| h >= height) {
                coin.block_height = None;
                #[cfg(feature = "persist")]
                {
                    self.staged.spent.insert(coin.output_id, coin.clone());
                }
            }
        }
    }

    /// Set `block_height` on an unspent coin (stages when `persist` is enabled).
    pub fn set_block_height(&mut self, output_id: &[u8; 32], height: u32) -> bool {
        let Some(coin) = self.coins.get_mut(output_id) else {
            return false;
        };
        coin.block_height = Some(height);
        #[cfg(feature = "persist")]
        {
            self.staged.coins.insert(*output_id, coin.clone());
        }
        true
    }

    /// Set `leaf_index` on an unspent coin (stages when `persist` is enabled).
    pub fn set_leaf_index(&mut self, output_id: &[u8; 32], leaf_index: u64) -> bool {
        let Some(coin) = self.coins.get_mut(output_id) else {
            return false;
        };
        coin.leaf_index = Some(leaf_index);
        #[cfg(feature = "persist")]
        {
            self.staged.coins.insert(*output_id, coin.clone());
        }
        true
    }

    /// Find an unspent coin by PMMR leaf index.
    pub fn find_by_leaf_index(&self, leaf_index: u64) -> Option<&MwebCoin> {
        self.coins
            .values()
            .find(|c| c.leaf_index == Some(leaf_index))
    }

    /// Mark spent the unspent coin with `leaf_index`, if any.
    pub fn mark_spent_by_leaf_index(&mut self, leaf_index: u64) -> Option<[u8; 32]> {
        let id = self.find_by_leaf_index(leaf_index)?.output_id;
        if self.mark_spent(&id) {
            Some(id)
        } else {
            None
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(id: u8, amount: u64, height: Option<u32>, is_pegin: bool) -> MwebCoin {
        MwebCoin {
            output_id: [id; 32],
            commitment: [0; 33],
            amount,
            address_index: 0,
            blind: [0; 32],
            shared_secret: [0; 32],
            spend_key: Some([1; 32]),
            block_height: height,
            is_pegin,
            leaf_index: None,
        }
    }

    #[test]
    fn balance_saturates_on_fabricated_amounts() {
        let mut db = MwebCoinDatabase::new();
        db.insert(coin(1, u64::MAX, Some(10), false));
        db.insert(coin(2, u64::MAX, Some(10), false));
        // Fabricated coins (a lying peer can choose any value) must not wrap
        // or panic the balance sum.
        assert_eq!(db.balance(), u64::MAX);
        assert_eq!(db.balance_at(20).confirmed, u64::MAX);
    }

    #[test]
    fn debug_redacts_spend_equivalent_fields() {
        let mut c = coin(1, 100, Some(10), false);
        c.blind = [0xaa; 32];
        c.shared_secret = [0xbb; 32];
        c.spend_key = Some([0xcc; 32]);
        let rendered = alloc::format!("{c:?}");
        assert!(!rendered.contains("170"), "blind leaked: {rendered}");
        assert!(
            !rendered.contains("187"),
            "shared_secret leaked: {rendered}"
        );
        assert!(!rendered.contains("204"), "spend_key leaked: {rendered}");
        assert_eq!(rendered.matches("<redacted>").count(), 3);
        // Non-secret fields stay visible so the type is still useful in logs.
        assert!(rendered.contains("amount: 100"));
    }

    #[test]
    fn debug_shows_absent_spend_key_as_none() {
        let mut c = coin(1, 100, None, false);
        c.spend_key = None;
        let rendered = alloc::format!("{c:?}");
        assert!(rendered.contains("spend_key: \"None\""), "{rendered}");
        assert_eq!(rendered.matches("<redacted>").count(), 2);
    }

    #[test]
    fn equality_still_compares_every_field() {
        let base = coin(1, 100, Some(10), false);
        assert_eq!(base, base.clone());

        let mutations: [fn(&mut MwebCoin); 10] = [
            |c| c.output_id[0] ^= 1,
            |c| c.commitment[0] ^= 1,
            |c| c.amount ^= 1,
            |c| c.address_index ^= 1,
            |c| c.blind[31] ^= 1,
            |c| c.shared_secret[31] ^= 1,
            |c| c.spend_key = Some([0xff; 32]),
            |c| c.block_height = Some(999),
            |c| c.is_pegin = !c.is_pegin,
            |c| c.leaf_index = Some(7),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut other = base.clone();
            mutate(&mut other);
            assert_ne!(base, other, "mutation {i} was not detected");
        }

        let mut no_key = base.clone();
        no_key.spend_key = None;
        assert_ne!(base, no_key);
    }

    #[test]
    fn drop_wipes_secrets_in_place() {
        let mut c = coin(1, 100, Some(10), false);
        c.blind = [0xaa; 32];
        c.shared_secret = [0xbb; 32];
        c.spend_key = Some([0xcc; 32]);
        c.wipe();
        assert_eq!(c.blind, [0u8; 32]);
        assert_eq!(c.shared_secret, [0u8; 32]);
        assert_eq!(c.spend_key, None);
    }

    #[test]
    fn immature_pegin_not_spendable_until_maturity() {
        let mut db = MwebCoinDatabase::new();
        db.insert(coin(1, 100, Some(10), true));
        assert!(db.unspent_spendable(14, MWEB_PEGIN_MATURITY).is_empty()); // 14+1-10=5
        assert_eq!(db.unspent_spendable(15, MWEB_PEGIN_MATURITY).len(), 1); // 15+1-10=6
    }

    #[test]
    fn non_pegin_spendable_when_confirmed() {
        let mut db = MwebCoinDatabase::new();
        db.insert(coin(2, 50, Some(10), false));
        assert_eq!(db.unspent_spendable(10, MWEB_PEGIN_MATURITY).len(), 1);
    }

    #[test]
    fn disconnect_from_clears_heights() {
        let mut db = MwebCoinDatabase::new();
        db.insert(coin(1, 10, Some(5), false));
        db.insert(coin(2, 20, Some(8), true));
        db.insert(coin(3, 30, Some(12), false));
        db.disconnect_from(8);
        assert_eq!(db.get(&[1; 32]).unwrap().block_height, Some(5));
        assert_eq!(db.get(&[2; 32]).unwrap().block_height, None);
        assert_eq!(db.get(&[3; 32]).unwrap().block_height, None);
        // Coins remain; re-tag restores spendability.
        db.set_block_height(&[2; 32], 8);
        assert_eq!(
            db.unspent_spendable(20, MWEB_PEGIN_MATURITY).len(),
            2 // coin1 + mature pegin coin2
        );
    }
}
