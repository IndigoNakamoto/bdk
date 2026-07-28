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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::schnorr_sign;
    use crate::hash::blake3_hash;
    use crate::keys::{MasterKeyScheme, MasterKeys};
    use crate::tx_builder::create_output;
    use bitcoin::bip32::{DerivationPath, Fingerprint};
    use bitcoin::{Network, NetworkKind};
    use hex_conservative::FromHex;

    fn ltcd_coin_output() -> mweb::Output {
        use bitcoin::secp256k1::PublicKey;
        // ltcd `coin_test.go` uses a stub range-proof (64 bytes), not a full 675-byte bulletproof.
        let raw = <Vec<u8>>::from_hex(
            "087c3e31a61d3d46bdb13729d3c4ac39da15fb13f3e1b1e0e1abdbbc52ca03f0\
             2d031a4777fdfcbb3594ac4f7b57a1ad4343d27601e8542cac591733098d41e4\
             9c5002e44d6d8cbdb20d58b39a3294ea6e94031ae09e4a489e4f484ceea0df6c\
             467a76010334bab2ce38ea861e61d92386b4bdbb916ce3b481ce996ad5e62c2f\
             6801fa8e4e51f84fd893a8c658fcca5b70966568af374bfb0e75f24830ca0000\
             000000000000000000000000000000000000000000000000000000000000c090\
             05a93313d9d9ea3805655f5474e3f39db5ae4d0bc29c6ab3f3aded78e46da942\
             a4ec525fbf41cbb3e9bf878bbe0c26dba6f44250cc55c82a7fd1eb90a51ceda0\
             89ee46105283bb99cf465eb1bc901c62e289e3e710ec8df7daeaab187b9e",
        )
        .unwrap();
        assert_eq!(raw.len(), 286);
        let mut off = 0usize;
        let mut commitment = [0u8; 33];
        commitment.copy_from_slice(&raw[off..off + 33]);
        off += 33;
        let sender_public_key = PublicKey::from_slice(&raw[off..off + 33]).unwrap();
        off += 33;
        let receiver_public_key = PublicKey::from_slice(&raw[off..off + 33]).unwrap();
        off += 33;
        let features = raw[off];
        off += 1;
        assert_eq!(features, 1);
        let ke = PublicKey::from_slice(&raw[off..off + 33]).unwrap();
        off += 33;
        let view_tag = raw[off];
        off += 1;
        let masked_value = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        let mut masked_nonce = [0u8; 16];
        masked_nonce.copy_from_slice(&raw[off..off + 16]);
        off += 16;
        let stub_proof = &raw[off..off + 64];
        off += 64;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[off..off + 64]);
        // Pad stub into rust-litecoin's fixed 675-byte proof slot.
        let mut range_proof = [0u8; 675];
        range_proof[..64].copy_from_slice(stub_proof);
        mweb::Output {
            commitment,
            sender_public_key,
            receiver_public_key,
            message: mweb::OutputMessage {
                features,
                standard_fields: Some(mweb::OutputMessageStandardFields {
                    key_exchange_pubkey: ke,
                    view_tag,
                    masked_value,
                    masked_nonce,
                }),
                extra_data: Vec::new(),
            },
            range_proof,
            signature,
        }
    }

    fn keys_from_secrets(scan_hex: &str, spend_hex: &str) -> MasterKeys {
        let scan =
            bitcoin::secp256k1::SecretKey::from_slice(&<[u8; 32]>::from_hex(scan_hex).unwrap())
                .unwrap();
        let spend =
            bitcoin::secp256k1::SecretKey::from_slice(&<[u8; 32]>::from_hex(spend_hex).unwrap())
                .unwrap();
        MasterKeys {
            scan,
            spend,
            scheme: MasterKeyScheme::LitecoinCore,
            master_fingerprint: Fingerprint::from([0u8; 4]),
            scan_path: DerivationPath::default(),
            spend_path: DerivationPath::default(),
        }
    }

    /// Port of ltcd `TestSignature` (`coin_test.go`).
    #[test]
    fn ltcd_output_signature_matches_sender() {
        let output = ltcd_coin_output();
        let sender = <[u8; 32]>::from_hex(
            "46ea6b248ba712462007aad44d06d8cb2f05c2ab737a8fc3e0ff328676fa40e7",
        )
        .unwrap();

        // Fixture wire after the message is `[32 zero][32 RangeProofHash][64 sig]` (stub proof,
        // not a full 675-byte bulletproof). Go signs over `RangeProofHash` directly.
        let msg_hash = blake3_hash(&serialize(&output.message));
        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&output.range_proof[32..64]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&output.commitment);
        hasher.update(&output.sender_public_key.serialize());
        hasher.update(&output.receiver_public_key.serialize());
        hasher.update(&msg_hash);
        hasher.update(&proof_hash);
        let msg32 = *hasher.finalize().as_bytes();

        let sig = schnorr_sign(&sender, &msg32).unwrap();
        assert_eq!(sig, output.signature);
    }

    /// Port of ltcd `TestRewindOutput` (`coin_test.go`).
    #[test]
    fn ltcd_rewind_output_vector() {
        let secp = Secp256k1::new();
        let output = ltcd_coin_output();
        let keys = keys_from_secrets(
            "164c6001b2623ed37be1c776567d12fe28c82664bd7497e63b0efcddb5b3ec48",
            "ef66d0e0f7d2c59b3d7f5837ac4831ed0805f8f48f8bfd574a7fafc065b5747f",
        );
        let book = AddressBook::from_keys(&keys, 20, &secp).unwrap();
        let coin = rewind_output(&keys, &book, &output, &secp)
            .unwrap()
            .expect("owned output");

        assert_eq!(coin.amount, 10_000_000); // 0.1 LTC
        assert_eq!(coin.address_index, 0);
        assert_eq!(
            keys.address(0, NetworkKind::Test, &secp).unwrap().to_string(),
            "tmweb1qqv0mlyyk7sl09jkcrgy059m5yplw567ypuj6lxpwkcw4tl8m59p7wq6jc\
             6prtph5kf45kdlql8fjppr32nmwng34fs6ess9fq72ck7lfyvmr6s0c"
        );
    }

    /// Port of ltcd `TestRewindWrongScanKey`.
    #[test]
    fn ltcd_rewind_wrong_scan_key_fails() {
        let secp = Secp256k1::new();
        let seed = [0x5Au8; 32];
        let keys =
            MasterKeys::from_seed(&seed, Network::Regtest, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let addr = keys.address(0, NetworkKind::Test, &secp).unwrap();
        let (_, _, output) = create_output(&addr, 500_000, &secp).unwrap();

        let mut wrong = keys.clone();
        wrong.scan = bitcoin::secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let book = AddressBook::from_keys(&wrong, 20, &secp).unwrap();
        assert!(rewind_output(&wrong, &book, &output, &secp)
            .unwrap()
            .is_none());
    }

    /// Port of ltcd `TestOutputRoundTrip` (index 0).
    #[test]
    fn ltcd_output_roundtrip_index_zero() {
        let secp = Secp256k1::new();
        let seed = <[u8; 32]>::from_hex(
            "2a64df085eefedd8bfdbb33176b5ba2e62e8be8b56c8837795598bb6c440c064",
        )
        .unwrap();
        let keys =
            MasterKeys::from_seed(&seed, Network::Bitcoin, MasterKeyScheme::LitecoinCore, &secp)
                .unwrap();
        let addr = keys.address(0, NetworkKind::Main, &secp).unwrap();
        let amount = 1_234_567u64;
        let (_, _, output) = create_output(&addr, amount, &secp).unwrap();

        let book = AddressBook::from_keys(&keys, 20, &secp).unwrap();
        let coin = rewind_output(&keys, &book, &output, &secp)
            .unwrap()
            .expect("rewind");
        assert_eq!(coin.amount, amount);
        assert_eq!(coin.address_index, 0);

        // Recovered spend key pubkey must match receiver pubkey.
        let spend = coin.spend_key.expect("spend key");
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&spend).unwrap();
        let got = PublicKey::from_secret_key(&secp, &sk);
        assert_eq!(got, output.receiver_public_key);
    }
}
