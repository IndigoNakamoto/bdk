//! Litecoin Core MWEB tagged BLAKE3 helpers (`EHashTag` / `Hasher`).

use bitcoin::secp256k1::{PublicKey, SecretKey};

/// Core `EHashTag` single-byte prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashTag {
    /// `'A'` — address-index tweak.
    Address = b'A',
    /// `'B'` — pre-switch blinding factor.
    Blind = b'B',
    /// `'D'` — ECDH shared secret derive.
    Derive = b'D',
    /// `'O'` — one-time output / spend key factor.
    OutKey = b'O',
    /// `'S'` — send key.
    SendKey = b'S',
    /// `'T'` — view tag.
    Tag = b'T',
    /// `'X'` — nonce mask.
    NonceMask = b'X',
    /// `'Y'` — value mask.
    ValueMask = b'Y',
    /// `'N'` — sender nonce (`Hash128` of sender key).
    Nonce = b'N',
}

/// BLAKE3(`tag` || `payload`).
pub fn hashed(tag: HashTag, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[tag as u8]);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Untagged BLAKE3 of `payload` (Core `Hasher()` / `Hashed(serializable)` body).
pub fn blake3_hash(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

/// `Hashed(tag, pubkey)` using compressed serialization.
pub fn hashed_pubkey(tag: HashTag, pk: &PublicKey) -> [u8; 32] {
    hashed(tag, &pk.serialize())
}

/// `Hashed(tag, secret)` using the 32-byte secret.
pub fn hashed_secret(tag: HashTag, sk: &SecretKey) -> [u8; 32] {
    hashed(tag, &sk.secret_bytes())
}

/// Core `Hasher(SEND_KEY).Append(A).Append(B).Append(value).Append(nonce)`.
pub fn send_key_hash(a: &PublicKey, b: &PublicKey, value: u64, nonce: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[HashTag::SendKey as u8]);
    hasher.update(&a.serialize());
    hasher.update(&b.serialize());
    hasher.update(&value.to_le_bytes());
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// First 8 bytes of `VALUE_MASK` hash as a little-endian `u64` (Core `uint64_t` cast).
pub fn value_mask(shared_t: &[u8; 32]) -> u64 {
    let h = hashed(HashTag::ValueMask, shared_t);
    u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
}

/// First 16 bytes of `NONCE_MASK` hash.
pub fn nonce_mask(shared_t: &[u8; 32]) -> [u8; 16] {
    let h = hashed(HashTag::NonceMask, shared_t);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}
