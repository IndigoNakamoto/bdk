//! Encrypt-at-rest helpers for MWEB coin secrets / changesets.
//!
//! BDK does **not** manage KDF or key storage. Apps supply a 32-byte key
//! (e.g. from OS keychain / Argon2) and must keep it safe.
//!
//! # Two wire formats
//!
//! **Legacy (v1)** is `nonce (12) || ciphertext+tag`, with no associated data.
//! Every blob sealed under one key is interchangeable with every other, so an
//! attacker with write access to the wallet directory can rename
//! `mweb_history.enc` over `mweb_coins.enc` and authentication still passes.
//! Restoring an older copy of a file is likewise undetectable.
//!
//! **v2** fixes both by prefixing a header and binding it as AEAD associated
//! data:
//!
//! ```text
//! b"MWEBSEAL"  8 bytes   magic
//! version      1 byte    = 2
//! context      1 byte    SealContext tag
//! counter      8 bytes   little-endian, caller-supplied
//! nonce       12 bytes   random
//! ciphertext + 16-byte Poly1305 tag
//! ```
//!
//! The first 18 bytes are the AAD, so editing the context tag or the counter
//! makes the tag check fail. Opening with [`open_with_context`] under the wrong
//! [`SealContext`] is rejected before decryption, which is what kills the
//! cross-file swap.
//!
//! # Compatibility
//!
//! [`open`] reads both formats — it looks for the magic and falls back to the
//! legacy layout — so existing wallet files keep opening with no migration
//! step. [`seal`] keeps *writing* the legacy format, so a wallet directory can
//! be shared by old and new binaries during a rollout. Callers opt in to v2 by
//! switching to [`seal_with_context`].
//!
//! # Nonce uniqueness
//!
//! Nonces are 96 random bits per seal. Under a single key, the birthday bound
//! puts collision probability near 2^-32 at roughly 2^48 seals — far beyond any
//! plausible wallet, which reseals a handful of files per sync. We stay on
//! ChaCha20-Poly1305 rather than moving to XChaCha20's 192-bit nonce because
//! the RustCrypto ChaCha20-Poly1305 implementation is the one that has seen the
//! most review, and because a counter-based or fixed nonce would be a genuine
//! break — hence the test asserting two seals of identical plaintext differ.
//! Revisit if a caller ever seals in a hot loop.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
#[cfg(feature = "encrypt-changeset")]
use zeroize::Zeroize;

use crate::error::Error;

#[cfg(feature = "encrypt-changeset")]
use crate::changeset::ChangeSet;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Envelope magic. Chosen so a random legacy nonce collides with probability 2^-64.
const MAGIC: &[u8; 8] = b"MWEBSEAL";
/// Current envelope version.
const VERSION: u8 = 2;
/// magic (8) + version (1) + context (1) + counter (8). This is the AAD.
const AAD_LEN: usize = 18;
/// AAD + nonce.
const V2_HEADER_LEN: usize = AAD_LEN + NONCE_LEN;

/// What a sealed blob *is*, bound into the ciphertext so blobs cannot be swapped.
///
/// A wallet that seals its coin database, sync state, address index, and
/// history under one key should give each a distinct context. Opening with the
/// wrong one fails.
///
/// Equality compares the wire tag, so `Other(1)` and `Coins` are the same
/// context. Use [`SealContext::Other`] only with tags at or above
/// [`SealContext::FIRST_FREE_TAG`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SealContext {
    /// The MWEB coin database (spend-equivalent secrets).
    Coins,
    /// Sync progress: leafset cursor, verified tip.
    SyncState,
    /// Derived address index / gap-limit state.
    Index,
    /// Transaction history.
    History,
    /// An application-defined context.
    Other(u8),
}

impl SealContext {
    /// Tags below this are reserved for the named variants.
    pub const FIRST_FREE_TAG: u8 = 5;

    /// The byte written into the envelope and bound as AAD.
    pub fn tag(self) -> u8 {
        match self {
            Self::Coins => 1,
            Self::SyncState => 2,
            Self::Index => 3,
            Self::History => 4,
            Self::Other(n) => n,
        }
    }

    /// Inverse of [`SealContext::tag`]. Reserved tags map to their named variant.
    pub fn from_tag(tag: u8) -> Self {
        match tag {
            1 => Self::Coins,
            2 => Self::SyncState,
            3 => Self::Index,
            4 => Self::History,
            n => Self::Other(n),
        }
    }
}

impl PartialEq for SealContext {
    fn eq(&self, other: &Self) -> bool {
        self.tag() == other.tag()
    }
}

impl Eq for SealContext {}

/// AEAD-seal `plaintext` with `key`. Returns the legacy `nonce || ciphertext`.
///
/// Kept on the legacy format for rollout compatibility; prefer
/// [`seal_with_context`] for anything new.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::Crypto("chacha20poly1305 encrypt failed".into()))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`] or [`seal_with_context`].
///
/// v2 envelopes open regardless of their context tag — only
/// [`open_with_context`] enforces it.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    // Route on the magic rather than on the version, so a blob from a future
    // envelope revision reports that plainly instead of failing as a legacy
    // decrypt. A legacy blob whose random nonce starts with the magic (2^-64)
    // is the price; it errors either way.
    if has_magic(sealed) {
        return open_v2(key, sealed, None, None).map(|(pt, _)| pt);
    }
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Crypto("sealed blob too short".into()));
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| Error::Crypto("chacha20poly1305 decrypt failed".into()))
}

/// Seal `plaintext` into a v2 envelope bound to `context`, with counter 0.
pub fn seal_with_context(
    key: &[u8; 32],
    plaintext: &[u8],
    context: SealContext,
) -> Result<Vec<u8>, Error> {
    seal_with_context_and_counter(key, plaintext, context, 0)
}

/// Seal into a v2 envelope bound to `context` and a monotonic `counter`.
///
/// The counter is the wallet's rollback defence: bump it on every write and
/// keep the high-water mark somewhere the attacker cannot roll back with the
/// file (alongside the Argon2 parameters, for instance), then open with
/// [`open_with_context_at_least`]. `bdk_mweb` cannot solve rollback on its
/// own — it provides the binding; the caller supplies the trusted counter.
pub fn seal_with_context_and_counter(
    key: &[u8; 32],
    plaintext: &[u8],
    context: SealContext,
    counter: u64,
) -> Result<Vec<u8>, Error> {
    let aad = aad_bytes(context, counter);
    let nonce_bytes = random_nonce();
    let cipher = ChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto("chacha20poly1305 encrypt failed".into()))?;

    let mut out = Vec::with_capacity(V2_HEADER_LEN + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a v2 envelope, requiring it to have been sealed under `context`.
///
/// Legacy blobs are rejected: accepting them here would silently reintroduce
/// the cross-file swap this function exists to prevent.
pub fn open_with_context(
    key: &[u8; 32],
    sealed: &[u8],
    context: SealContext,
) -> Result<Vec<u8>, Error> {
    open_v2(key, sealed, Some(context), None).map(|(pt, _)| pt)
}

/// Like [`open_with_context`], but also rejects a counter below `min_counter`.
///
/// Returns the plaintext and the envelope's counter, so the caller can advance
/// its high-water mark.
pub fn open_with_context_at_least(
    key: &[u8; 32],
    sealed: &[u8],
    context: SealContext,
    min_counter: u64,
) -> Result<(Vec<u8>, u64), Error> {
    open_v2(key, sealed, Some(context), Some(min_counter))
}

/// Whether `sealed` looks like a v2 envelope.
///
/// Public so a caller can tell whether a file still needs rewriting under
/// [`seal_with_context`].
pub fn is_v2(sealed: &[u8]) -> bool {
    has_magic(sealed) && sealed.len() >= V2_HEADER_LEN + TAG_LEN && sealed[MAGIC.len()] == VERSION
}

fn has_magic(sealed: &[u8]) -> bool {
    sealed.len() >= MAGIC.len() && &sealed[..MAGIC.len()] == MAGIC.as_slice()
}

fn aad_bytes(context: SealContext, counter: u64) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..8].copy_from_slice(MAGIC.as_slice());
    aad[8] = VERSION;
    aad[9] = context.tag();
    aad[10..18].copy_from_slice(&counter.to_le_bytes());
    aad
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Shared v2 path. `expect_context` and `min_counter` are checked before the
/// AEAD, so a mismatched context is a cheap, unambiguous error rather than a
/// generic decrypt failure.
fn open_v2(
    key: &[u8; 32],
    sealed: &[u8],
    expect_context: Option<SealContext>,
    min_counter: Option<u64>,
) -> Result<(Vec<u8>, u64), Error> {
    if sealed.len() < V2_HEADER_LEN + TAG_LEN {
        return Err(Error::Crypto("sealed blob too short".into()));
    }
    if &sealed[..MAGIC.len()] != MAGIC.as_slice() {
        return Err(Error::Crypto("sealed blob is not a v2 envelope".into()));
    }
    let version = sealed[8];
    if version != VERSION {
        return Err(Error::Crypto(alloc::format!(
            "unsupported seal envelope version {version}"
        )));
    }
    let context = SealContext::from_tag(sealed[9]);
    if let Some(expected) = expect_context {
        if context != expected {
            return Err(Error::Crypto(alloc::format!(
                "sealed blob context {} does not match expected {}",
                context.tag(),
                expected.tag()
            )));
        }
    }
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&sealed[10..18]);
    let counter = u64::from_le_bytes(counter_bytes);
    if let Some(min) = min_counter {
        if counter < min {
            return Err(Error::Crypto(alloc::format!(
                "sealed blob counter {counter} is below the expected minimum {min}"
            )));
        }
    }

    let aad = &sealed[..AAD_LEN];
    let nonce = Nonce::from_slice(&sealed[AAD_LEN..V2_HEADER_LEN]);
    let ct = &sealed[V2_HEADER_LEN..];
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| Error::Crypto("chacha20poly1305 decrypt failed".into()))?;
    Ok((plaintext, counter))
}

/// Wire form for JSON (BTreeMap keys of `[u8;32]` are not JSON-object keys).
#[cfg(feature = "encrypt-changeset")]
#[derive(serde::Serialize, serde::Deserialize)]
struct ChangeSetWire {
    coins: alloc::vec::Vec<crate::coin_db::MwebCoin>,
    spent: alloc::vec::Vec<crate::coin_db::MwebCoin>,
}

#[cfg(feature = "encrypt-changeset")]
fn changeset_to_json(cs: &ChangeSet) -> Result<Vec<u8>, Error> {
    let wire = ChangeSetWire {
        coins: cs.coins.values().cloned().collect(),
        spent: cs.spent.values().cloned().collect(),
    };
    serde_json::to_vec(&wire).map_err(|e| Error::Crypto(alloc::format!("changeset encode: {e}")))
}

/// Decodes then wipes `plaintext`, which holds spend-equivalent secrets.
#[cfg(feature = "encrypt-changeset")]
fn changeset_from_json(plaintext: &mut Vec<u8>) -> Result<ChangeSet, Error> {
    let decoded: Result<ChangeSetWire, _> = serde_json::from_slice(plaintext);
    plaintext.zeroize();
    let wire = decoded.map_err(|e| Error::Crypto(alloc::format!("changeset decode: {e}")))?;

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

/// Serialize + seal a [`ChangeSet`] (JSON, legacy envelope).
///
/// Requires feature `encrypt-changeset`. Prefer
/// [`seal_changeset_with_context`] once every reader understands v2.
#[cfg(feature = "encrypt-changeset")]
pub fn seal_changeset(key: &[u8; 32], cs: &ChangeSet) -> Result<Vec<u8>, Error> {
    let mut plaintext = changeset_to_json(cs)?;
    let sealed = seal(key, &plaintext);
    plaintext.zeroize();
    sealed
}

/// Open a [`ChangeSet`] sealed by either changeset sealer.
#[cfg(feature = "encrypt-changeset")]
pub fn open_changeset(key: &[u8; 32], sealed: &[u8]) -> Result<ChangeSet, Error> {
    let mut plaintext = open(key, sealed)?;
    changeset_from_json(&mut plaintext)
}

/// Serialize + seal a [`ChangeSet`] into a v2 envelope bound to `context` and
/// `counter`.
#[cfg(feature = "encrypt-changeset")]
pub fn seal_changeset_with_context(
    key: &[u8; 32],
    cs: &ChangeSet,
    context: SealContext,
    counter: u64,
) -> Result<Vec<u8>, Error> {
    let mut plaintext = changeset_to_json(cs)?;
    let sealed = seal_with_context_and_counter(key, &plaintext, context, counter);
    plaintext.zeroize();
    sealed
}

/// Open a [`ChangeSet`] from a v2 envelope, enforcing `context` and
/// `min_counter`. Returns the changeset and the envelope's counter.
#[cfg(feature = "encrypt-changeset")]
pub fn open_changeset_with_context(
    key: &[u8; 32],
    sealed: &[u8],
    context: SealContext,
    min_counter: u64,
) -> Result<(ChangeSet, u64), Error> {
    let (mut plaintext, counter) = open_with_context_at_least(key, sealed, context, min_counter)?;
    let cs = changeset_from_json(&mut plaintext)?;
    Ok((cs, counter))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42u8; 32];

    #[test]
    fn seal_open_roundtrip() {
        let msg = b"mweb secret payload";
        let sealed = seal(&KEY, msg).unwrap();
        assert_ne!(&sealed[NONCE_LEN..], msg.as_slice());
        let opened = open(&KEY, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&[1u8; 32], b"hello").unwrap();
        assert!(open(&[2u8; 32], &sealed).is_err());
    }

    #[test]
    fn seal_still_writes_the_legacy_format() {
        // A rollout guarantee: an old binary must keep reading what we write.
        let sealed = seal(&KEY, b"payload").unwrap();
        assert!(!is_v2(&sealed));
        assert_eq!(sealed.len(), NONCE_LEN + b"payload".len() + TAG_LEN);
    }

    #[test]
    fn v2_roundtrip_under_every_context() {
        let contexts = [
            SealContext::Coins,
            SealContext::SyncState,
            SealContext::Index,
            SealContext::History,
            SealContext::Other(SealContext::FIRST_FREE_TAG),
            SealContext::Other(255),
        ];
        for ctx in contexts {
            let sealed = seal_with_context(&KEY, b"payload", ctx).unwrap();
            assert!(is_v2(&sealed));
            assert_eq!(open_with_context(&KEY, &sealed, ctx).unwrap(), b"payload");
        }
    }

    #[test]
    fn wrong_context_is_rejected() {
        let sealed = seal_with_context(&KEY, b"coins", SealContext::Coins).unwrap();
        let err = open_with_context(&KEY, &sealed, SealContext::History).unwrap_err();
        assert!(alloc::format!("{err:?}").contains("context"), "{err:?}");
        assert!(open_with_context(&KEY, &sealed, SealContext::Coins).is_ok());
    }

    #[test]
    fn cross_file_swap_no_longer_authenticates() {
        // The whole point of F-09: two files, one key, no longer interchangeable.
        let coins = seal_with_context(&KEY, b"coin secrets", SealContext::Coins).unwrap();
        let history = seal_with_context(&KEY, b"history", SealContext::History).unwrap();
        assert!(open_with_context(&KEY, &history, SealContext::Coins).is_err());
        assert!(open_with_context(&KEY, &coins, SealContext::History).is_err());
    }

    #[test]
    fn context_equality_is_by_wire_tag() {
        assert_eq!(SealContext::Other(1), SealContext::Coins);
        assert_ne!(SealContext::Coins, SealContext::History);
        for tag in 0..=255u8 {
            assert_eq!(SealContext::from_tag(tag).tag(), tag);
        }
    }

    #[test]
    fn counter_below_the_high_water_mark_is_rejected() {
        let sealed =
            seal_with_context_and_counter(&KEY, b"state", SealContext::SyncState, 7).unwrap();
        let (pt, counter) =
            open_with_context_at_least(&KEY, &sealed, SealContext::SyncState, 7).unwrap();
        assert_eq!(pt, b"state");
        assert_eq!(counter, 7);
        assert!(open_with_context_at_least(&KEY, &sealed, SealContext::SyncState, 8).is_err());
        // A rolled-back file is exactly this case: an old, lower counter.
        let old = seal_with_context_and_counter(&KEY, b"old", SealContext::SyncState, 3).unwrap();
        let err = open_with_context_at_least(&KEY, &old, SealContext::SyncState, 7).unwrap_err();
        assert!(alloc::format!("{err:?}").contains("counter"), "{err:?}");
    }

    #[test]
    fn open_reads_both_formats() {
        let legacy = seal(&KEY, b"legacy").unwrap();
        let v2 = seal_with_context(&KEY, b"modern", SealContext::Coins).unwrap();
        assert_eq!(open(&KEY, &legacy).unwrap(), b"legacy");
        assert_eq!(open(&KEY, &v2).unwrap(), b"modern");
    }

    #[test]
    fn open_with_context_rejects_a_legacy_blob() {
        let legacy = seal(&KEY, b"legacy").unwrap();
        assert!(open_with_context(&KEY, &legacy, SealContext::Coins).is_err());
    }

    #[test]
    fn a_legacy_only_reader_cannot_open_a_v2_blob() {
        // Simulates an old binary: legacy parse of a v2 envelope must fail, not
        // hand back garbage. The magic lands where the nonce used to be.
        let v2 = seal_with_context(&KEY, b"modern", SealContext::Coins).unwrap();
        let (nonce_bytes, ct) = v2.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new((&KEY).into());
        assert!(cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).is_err());
    }

    #[test]
    fn every_single_bit_flip_is_rejected() {
        for (label, sealed) in [
            ("legacy", seal(&KEY, b"the quick brown fox").unwrap()),
            (
                "v2",
                seal_with_context_and_counter(
                    &KEY,
                    b"the quick brown fox",
                    SealContext::Coins,
                    9_000,
                )
                .unwrap(),
            ),
        ] {
            for byte in 0..sealed.len() {
                for bit in 0..8 {
                    let mut bad = sealed.clone();
                    bad[byte] ^= 1 << bit;
                    // A flip in the magic just reroutes to the other parser;
                    // either way it must error, never panic and never succeed.
                    assert!(
                        open(&KEY, &bad).is_err(),
                        "{label}: flip at byte {byte} bit {bit} was accepted"
                    );
                }
            }
        }
    }

    #[test]
    fn v2_header_field_edits_are_rejected() {
        let sealed =
            seal_with_context_and_counter(&KEY, b"payload", SealContext::Coins, 5).unwrap();

        let mut wrong_context = sealed.clone();
        wrong_context[9] = SealContext::History.tag();
        assert!(open(&KEY, &wrong_context).is_err(), "context edit accepted");

        let mut inflated_counter = sealed.clone();
        inflated_counter[10] = 0xff;
        assert!(
            open(&KEY, &inflated_counter).is_err(),
            "counter edit accepted"
        );

        let mut bad_version = sealed.clone();
        bad_version[8] = 3;
        assert!(!is_v2(&bad_version));
        let err = open(&KEY, &bad_version).unwrap_err();
        assert!(
            alloc::format!("{err:?}").contains("unsupported seal envelope version 3"),
            "{err:?}"
        );

        let mut bad_magic = sealed.clone();
        bad_magic[0] ^= 1;
        assert!(open(&KEY, &bad_magic).is_err(), "magic edit accepted");
    }

    #[test]
    fn truncation_at_every_boundary_errors_without_panicking() {
        for sealed in [
            seal(&KEY, b"some plaintext here").unwrap(),
            seal_with_context(&KEY, b"some plaintext here", SealContext::Index).unwrap(),
        ] {
            for len in 0..sealed.len() {
                assert!(open(&KEY, &sealed[..len]).is_err(), "truncation to {len}");
                assert!(open_with_context(&KEY, &sealed[..len], SealContext::Index).is_err());
            }
        }
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let legacy = seal(&KEY, b"").unwrap();
        assert_eq!(open(&KEY, &legacy).unwrap(), b"");
        let v2 = seal_with_context(&KEY, b"", SealContext::Coins).unwrap();
        assert_eq!(
            open_with_context(&KEY, &v2, SealContext::Coins).unwrap(),
            b""
        );
    }

    #[test]
    fn identical_plaintext_seals_to_distinct_nonces() {
        // Guards against a future refactor to a fixed or counter-derived nonce,
        // which would be catastrophic for a stream cipher.
        let mut nonces = alloc::collections::BTreeSet::new();
        for _ in 0..64 {
            let legacy = seal(&KEY, b"same").unwrap();
            assert!(nonces.insert(legacy[..NONCE_LEN].to_vec()), "nonce reused");
            let v2 = seal_with_context(&KEY, b"same", SealContext::Coins).unwrap();
            assert!(
                nonces.insert(v2[AAD_LEN..V2_HEADER_LEN].to_vec()),
                "nonce reused"
            );
        }
    }

    #[test]
    fn arbitrary_garbage_never_panics() {
        for len in 0..80usize {
            for seed in 0..8u8 {
                let blob: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(31) ^ seed)
                    .collect();
                let _ = open(&KEY, &blob);
                let _ = open_with_context(&KEY, &blob, SealContext::Coins);
                let _ = open_with_context_at_least(&KEY, &blob, SealContext::Coins, 1);
            }
        }
        // Blobs that start with the magic take the v2 path with a nonsense body.
        for len in 0..80usize {
            let mut blob = MAGIC.to_vec();
            blob.extend((0..len).map(|i| i as u8));
            let _ = open(&KEY, &blob);
            let _ = open_with_context(&KEY, &blob, SealContext::Coins);
        }
    }

    #[cfg(feature = "encrypt-changeset")]
    fn sample_changeset() -> ChangeSet {
        use crate::coin_db::MwebCoin;
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
        cs
    }

    #[cfg(feature = "encrypt-changeset")]
    #[test]
    fn seal_changeset_roundtrip() {
        let key = [7u8; 32];
        let cs = sample_changeset();
        let sealed = seal_changeset(&key, &cs).unwrap();
        let opened = open_changeset(&key, &sealed).unwrap();
        assert_eq!(opened, cs);
    }

    #[cfg(feature = "encrypt-changeset")]
    #[test]
    fn seal_changeset_with_context_roundtrip() {
        let key = [7u8; 32];
        let cs = sample_changeset();
        let sealed = seal_changeset_with_context(&key, &cs, SealContext::Coins, 12).unwrap();
        let (opened, counter) =
            open_changeset_with_context(&key, &sealed, SealContext::Coins, 12).unwrap();
        assert_eq!(opened, cs);
        assert_eq!(counter, 12);
        assert!(open_changeset_with_context(&key, &sealed, SealContext::History, 0).is_err());
        assert!(open_changeset_with_context(&key, &sealed, SealContext::Coins, 13).is_err());
        // The context-free reader still works, so a mixed-version wallet is fine.
        assert_eq!(open_changeset(&key, &sealed).unwrap(), cs);
    }
}
