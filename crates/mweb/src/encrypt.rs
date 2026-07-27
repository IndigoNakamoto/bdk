//! Encrypt-at-rest helpers for MWEB coin secrets / changesets.
//!
//! BDK does **not** manage KDF or key storage. Apps supply a 32-byte key
//! (e.g. from OS keychain / Argon2) and must keep it safe.
//!
//! Sealed blobs are `nonce (12 bytes) || ciphertext+tag` using ChaCha20-Poly1305.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;

use crate::error::Error;

#[cfg(feature = "encrypt-changeset")]
use crate::changeset::ChangeSet;

const NONCE_LEN: usize = 12;

/// AEAD-seal `plaintext` with `key`. Returns `nonce || ciphertext`.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + 16);
    out.extend_from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::Crypto("chacha20poly1305 encrypt failed".into()))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`].
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(Error::Crypto("sealed blob too short".into()));
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| Error::Crypto("chacha20poly1305 decrypt failed".into()))
}

/// Wire form for JSON (BTreeMap keys of `[u8;32]` are not JSON-object keys).
#[cfg(feature = "encrypt-changeset")]
#[derive(serde::Serialize, serde::Deserialize)]
struct ChangeSetWire {
    coins: alloc::vec::Vec<crate::coin_db::MwebCoin>,
    spent: alloc::vec::Vec<crate::coin_db::MwebCoin>,
}

/// Serialize + seal a [`ChangeSet`] (JSON). Requires feature `encrypt-changeset`.
#[cfg(feature = "encrypt-changeset")]
pub fn seal_changeset(key: &[u8; 32], cs: &ChangeSet) -> Result<Vec<u8>, Error> {
    let wire = ChangeSetWire {
        coins: cs.coins.values().cloned().collect(),
        spent: cs.spent.values().cloned().collect(),
    };
    let plaintext = serde_json::to_vec(&wire)
        .map_err(|e| Error::Crypto(alloc::format!("changeset encode: {e}")))?;
    seal(key, &plaintext)
}

/// Open + deserialize a [`ChangeSet`] sealed by [`seal_changeset`].
#[cfg(feature = "encrypt-changeset")]
pub fn open_changeset(key: &[u8; 32], sealed: &[u8]) -> Result<ChangeSet, Error> {
    let plaintext = open(key, sealed)?;
    let wire: ChangeSetWire = serde_json::from_slice(&plaintext)
        .map_err(|e| Error::Crypto(alloc::format!("changeset decode: {e}")))?;
    let mut cs = ChangeSet::default();
    for coin in wire.coins {
        cs.coins.insert(coin.output_id, coin);
    }
    for coin in wire.spent {
        cs.coins.remove(&coin.output_id);
        cs.spent.insert(coin.output_id, coin);
    }
    Ok(cs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let msg = b"mweb secret payload";
        let sealed = seal(&key, msg).unwrap();
        assert_ne!(&sealed[NONCE_LEN..], msg.as_slice());
        let opened = open(&key, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&[1u8; 32], b"hello").unwrap();
        assert!(open(&[2u8; 32], &sealed).is_err());
    }

    #[cfg(feature = "encrypt-changeset")]
    #[test]
    fn seal_changeset_roundtrip() {
        use crate::coin_db::MwebCoin;
        let key = [7u8; 32];
        let mut cs = ChangeSet::default();
        cs.coins.insert(
            [1; 32],
            MwebCoin {
                output_id: [1; 32],
                commitment: [2; 33],
                amount: 99,
                address_index: 0,
                blind: [3; 32],
                shared_secret: [4; 32],
                spend_key: Some([5; 32]),
                block_height: Some(10),
                is_pegin: false,
                leaf_index: None,
            },
        );
        let sealed = seal_changeset(&key, &cs).unwrap();
        let opened = open_changeset(&key, &sealed).unwrap();
        assert_eq!(opened, cs);
    }
}
