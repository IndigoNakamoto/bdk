//! Core `Keychain::RewindOutput` receive scan (LIP-0004 §7 as shipped).
//!
//! Wire input may be decoded `mw_tx` bodies (Core RPC) or FULL_UTXO batches from
//! [`crate::lip0006`] (feature `lip0006`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::blockdata::mimblewimble::{self as mweb};
use bitcoin::consensus::encode::serialize;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, PublicKey, Scalar};

use crate::coin_db::{MwebCoin, MwebCoinDatabase};
use crate::crypto::switch_commit;
use crate::error::Error;
use crate::hash::{
    blake3_hash, hashed, hashed_pubkey, nonce_mask, send_key_hash, value_mask, HashTag,
};
use crate::keys::MasterKeys;

/// Default gap limit for precomputed spend pubkeys `B_i`.
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// Gap-limited map of `B_i` (compressed) → address index for ownership lookup.
#[derive(Debug, Clone)]
pub struct AddressBook {
    by_spend_pk: BTreeMap<[u8; 33], u32>,
    gap_limit: u32,
}

impl AddressBook {
    /// Precompute `B_i` for indices `0..gap_limit`.
    pub fn from_keys(
        keys: &MasterKeys,
        gap_limit: u32,
        secp: &Secp256k1<All>,
    ) -> Result<Self, Error> {
        let mut by_spend_pk = BTreeMap::new();
        for i in 0..gap_limit {
            let (_, b_i) = keys.stealth_pubkeys(i, secp)?;
            by_spend_pk.insert(b_i.serialize(), i);
        }
        Ok(Self {
            by_spend_pk,
            gap_limit,
        })
    }

    /// Gap limit used to build this book.
    pub fn gap_limit(&self) -> u32 {
        self.gap_limit
    }

    /// Look up address index by spend pubkey `B_i`.
    pub fn index_of(&self, spend_pk: &PublicKey) -> Option<u32> {
        self.by_spend_pk.get(&spend_pk.serialize()).copied()
    }
}

/// Core `Output::GetOutputID()` / `ComputeHash`.
pub fn output_id(output: &mweb::Output) -> [u8; 32] {
    let msg_hash = blake3_hash(&serialize(&output.message));
    let proof_hash = blake3_hash(&output.range_proof);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&output.commitment);
    hasher.update(&output.sender_public_key.serialize());
    hasher.update(&output.receiver_public_key.serialize());
    hasher.update(&msg_hash);
    hasher.update(&proof_hash);
    hasher.update(&output.signature);
    *hasher.finalize().as_bytes()
}

/// Try to rewind a single MWEB output. Returns `None` if it is not ours.
pub fn rewind_output(
    keys: &MasterKeys,
    book: &AddressBook,
    output: &mweb::Output,
    secp: &Secp256k1<All>,
) -> Result<Option<MwebCoin>, Error> {
    let Some(fields) = output.message.standard_fields.as_ref() else {
        return Ok(None);
    };
    // OutputFeatures::StandardFieldsFeatureBit = 0x01
    if output.message.features & 0x01 == 0 {
        return Ok(None);
    }

    let ke = fields.key_exchange_pubkey;
    let ko = output.receiver_public_key;

    // shared_point = a · Ke
    let scan_scalar =
        Scalar::from_be_bytes(keys.scan.secret_bytes()).map_err(|_| Error::InvalidTweak)?;
    let shared_point = ke.mul_tweak(secp, &scan_scalar)?;

    let view_tag = hashed_pubkey(HashTag::Tag, &shared_point)[0];
    if view_tag != fields.view_tag {
        return Ok(None);
    }

    let t = hashed_pubkey(HashTag::Derive, &shared_point);
    let out_key = hashed(HashTag::OutKey, &t);
    let out_key_scalar = Scalar::from_be_bytes(out_key).map_err(|_| Error::InvalidTweak)?;

    // B_i such that Ko = B_i · H(OUT_KEY||t)  → try gap book via forward multiply
    let mut matched_index = None;
    let mut matched_b = None;
    for (ref_b, &idx) in &book.by_spend_pk {
        let b_i = PublicKey::from_slice(ref_b)?;
        let expected_ko = b_i.mul_tweak(secp, &out_key_scalar)?;
        if expected_ko == ko {
            matched_index = Some(idx);
            matched_b = Some(b_i);
            break;
        }
    }
    let (address_index, b_i) = match (matched_index, matched_b) {
        (Some(i), Some(b)) => (i, b),
        _ => return Ok(None),
    };

    let a_i = {
        let scan_s =
            Scalar::from_be_bytes(keys.scan.secret_bytes()).map_err(|_| Error::InvalidTweak)?;
        b_i.mul_tweak(secp, &scan_s)?
    };

    let vmask = value_mask(&t);
    let nmask = nonce_mask(&t);
    let value = fields.masked_value ^ vmask;
    let mut nonce = [0u8; 16];
    for i in 0..16 {
        nonce[i] = fields.masked_nonce[i] ^ nmask[i];
    }

    let pre_blind = hashed(HashTag::Blind, &t);
    let expected_commit = switch_commit(&pre_blind, value, secp)?;
    if expected_commit != output.commitment {
        return Ok(None);
    }

    let s = send_key_hash(&a_i, &b_i, value, &nonce);
    let s_scalar = Scalar::from_be_bytes(s).map_err(|_| Error::InvalidTweak)?;
    let expected_ke = b_i.mul_tweak(secp, &s_scalar)?;
    if expected_ke != ke {
        return Ok(None);
    }

    let spend_key = {
        let b_i_sk = keys.spend_key_at(address_index)?;
        let factor = Scalar::from_be_bytes(out_key).map_err(|_| Error::InvalidTweak)?;
        Some(b_i_sk.mul_tweak(&factor)?.secret_bytes())
    };

    Ok(Some(MwebCoin {
        output_id: output_id(output),
        commitment: output.commitment,
        amount: value,
        address_index,
        blind: pre_blind,
        shared_secret: t,
        spend_key,
        block_height: None,
        is_pegin: false,
        leaf_index: None,
    }))
}

/// Scan MWEB outputs and insert matches into `db` (unknown inclusion height).
pub fn scan_outputs(
    keys: &MasterKeys,
    book: &AddressBook,
    outputs: &[mweb::Output],
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
) -> Result<Vec<MwebCoin>, Error> {
    scan_outputs_at(keys, book, outputs, db, secp, None)
}

/// Scan MWEB outputs, tagging matches with `block_height` when known.
pub fn scan_outputs_at(
    keys: &MasterKeys,
    book: &AddressBook,
    outputs: &[mweb::Output],
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
    block_height: Option<u32>,
) -> Result<Vec<MwebCoin>, Error> {
    let mut found = Vec::new();
    for output in outputs {
        if let Some(mut coin) = rewind_output(keys, book, output, secp)? {
            coin.block_height = block_height;
            db.insert(coin.clone());
            found.push(coin);
        }
    }
    Ok(found)
}

/// Scan FULL_UTXO entries, tagging each match with leaf index and optional height.
pub fn scan_utxo_entries_at(
    keys: &MasterKeys,
    book: &AddressBook,
    entries: &[(u64, mweb::Output)],
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
    height_for_leaf: impl Fn(u64) -> Option<u32>,
) -> Result<Vec<MwebCoin>, Error> {
    let mut found = Vec::new();
    for (leaf_index, output) in entries {
        if let Some(mut coin) = rewind_output(keys, book, output, secp)? {
            coin.leaf_index = Some(*leaf_index);
            coin.block_height = height_for_leaf(*leaf_index);
            db.insert(coin.clone());
            found.push(coin);
        }
    }
    Ok(found)
}

/// Scan a full MWEB transaction body: mark spent inputs, insert owned outputs.
pub fn scan_mweb_tx(
    keys: &MasterKeys,
    book: &AddressBook,
    tx: &mweb::Transaction,
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
) -> Result<Vec<MwebCoin>, Error> {
    scan_mweb_tx_at(keys, book, tx, db, secp, None)
}

/// [`scan_mweb_tx`] with an optional inclusion height for new coins.
pub fn scan_mweb_tx_at(
    keys: &MasterKeys,
    book: &AddressBook,
    tx: &mweb::Transaction,
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
    block_height: Option<u32>,
) -> Result<Vec<MwebCoin>, Error> {
    for input in &tx.body.inputs {
        let _ = db.mark_spent(&input.output_id);
    }
    let is_pegin = tx.body.kernels.iter().any(|k| k.pegin.is_some());
    let mut found = scan_outputs_at(keys, book, &tx.body.outputs, db, secp, block_height)?;
    if is_pegin {
        for coin in &mut found {
            coin.is_pegin = true;
            if let Some(stored) = db.get(&coin.output_id).cloned() {
                let mut updated = stored;
                updated.is_pegin = true;
                db.insert(updated);
            }
        }
    }
    Ok(found)
}

/// Scan the optional `mw_tx` on a Litecoin transaction.
pub fn scan_litecoin_tx(
    keys: &MasterKeys,
    book: &AddressBook,
    tx: &bitcoin::Transaction,
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
) -> Result<Vec<MwebCoin>, Error> {
    scan_litecoin_tx_at(keys, book, tx, db, secp, None)
}

/// [`scan_litecoin_tx`] with an optional inclusion height for new coins.
pub fn scan_litecoin_tx_at(
    keys: &MasterKeys,
    book: &AddressBook,
    tx: &bitcoin::Transaction,
    db: &mut MwebCoinDatabase,
    secp: &Secp256k1<All>,
    block_height: Option<u32>,
) -> Result<Vec<MwebCoin>, Error> {
    let Some(mw) = tx.mw_tx.as_ref() else {
        return Ok(Vec::new());
    };
    scan_mweb_tx_at(keys, book, mw, db, secp, block_height)
}
