//! Consensus-crypto helpers: switch commitments + MW bulletproof / schnorr FFI.
//!
//! Switch commitments match Litecoin Core `Pedersen::BlindSwitch` / `Commitment::Switch`:
//! `r' = r + SHA256(ser_commit(v·H+r·G) || ser_compressed(r·J))`, then `C = v·H + r'·G`.
//!
//! Bulletproofs and Schnorr use Grin’s vendored `secp256k1-zkp` (same modules Litecoin Core’s
//! `Bulletproofs.cpp` / `Schnorr.cpp` call). Elements CT `rangeproof_sign` is the wrong proof
//! system (not the fixed 675-byte MWEB bulletproof).
//!
//! # FFI safety
//!
//! The `mw` module declares `extern "C"` prototypes by hand against a vendored C
//! library with no ABI versioning. Nothing in the build verifies those declarations
//! still match the C definitions, and a mismatch compiles cleanly while producing
//! wrong output — which here means unspendable coins or commitments that do not
//! balance. The `abi_vectors` test module pins concrete outputs so a mismatch fails
//! a test instead of a transaction.
//!
//! To regenerate those vectors after a deliberate dependency bump, temporarily
//! change each `assert_eq!(hex(&…), "…")` to print its computed value, run
//! `cargo test -p bdk_mweb --all-features --lib abi_vectors -- --nocapture`, and
//! paste the results back. Do this only when the change is understood: a vector
//! that moved unexpectedly is the failure this module exists to catch.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, PublicKey, Scalar, SecretKey};

use crate::error::Error;

/// Length of an MWEB bulletproof, in bytes.
///
/// MWEB fixes this at 675; it is not a maximum. `Output::range_proof` is a
/// `[u8; BULLETPROOF_LEN]` on the wire, and `output_id` hashes exactly that, so a proof of any
/// other length cannot be represented at all.
pub const BULLETPROOF_LEN: usize = 675;

// The FFI writes into a `[u8; BULLETPROOF_LEN]` after checking `plen`. If the wire
// type and this constant ever disagree, that copy is a buffer overflow, so tie them
// together at compile time rather than trusting two `675` literals to stay in sync.
const _: () = {
    assert!(BULLETPROOF_LEN == 675);
    assert!(core::mem::size_of::<[u8; BULLETPROOF_LEN]>() == 675);
};

/// Compressed J from Litecoin `GENERATOR_J_PUB` (see `libmw/.../secp256k1-zkp.h`).
const GENERATOR_J: [u8; 33] = [
    0x02, 0xb8, 0x60, 0xf5, 0x67, 0x95, 0xfc, 0x03, 0xf3, 0xc2, 0x16, 0x85, 0x38, 0x3d, 0x1b, 0x5a,
    0x2f, 0x29, 0x54, 0xf4, 0x9b, 0x7e, 0x39, 0x8b, 0x8d, 0x2a, 0x01, 0x93, 0x93, 0x36, 0x21, 0x15,
    0x5f,
];

/// Pedersen commitment `C = v·H + r·G` in Core wire format (33 bytes).
pub fn pedersen_commit(
    value: u64,
    blind: &[u8; 32],
    _secp: &Secp256k1<All>,
) -> Result<[u8; 33], Error> {
    #[cfg(feature = "zkp")]
    {
        mw::pedersen_commit(value, blind)
    }
    #[cfg(not(feature = "zkp"))]
    {
        let _ = (value, blind);
        Err(Error::ZkpDisabled)
    }
}

/// Modular inverse of a nonzero scalar mod the secp256k1 group order.
#[cfg(feature = "zkp")]
pub fn scalar_inverse(scalar: &[u8; 32]) -> Result<[u8; 32], Error> {
    mw::scalar_inverse(scalar)
}

/// Core `Pedersen::BlindSwitch`.
pub fn blind_switch(
    blind: &[u8; 32],
    value: u64,
    secp: &Secp256k1<All>,
) -> Result<[u8; 32], Error> {
    let commit = pedersen_commit(value, blind, secp)?;
    let j = PublicKey::from_slice(&GENERATOR_J)?;
    let blind_scalar = Scalar::from_be_bytes(*blind).map_err(|_| Error::InvalidTweak)?;
    let r_j = j.mul_tweak(secp, &blind_scalar)?;

    let mut engine = sha256::Hash::engine();
    engine.input(&commit);
    engine.input(&r_j.serialize());
    let hash = sha256::Hash::from_engine(engine);

    let r = SecretKey::from_slice(blind)?;
    let tweak = Scalar::from_be_bytes(hash.to_byte_array()).map_err(|_| Error::InvalidTweak)?;
    Ok(r.add_tweak(&tweak)?.secret_bytes())
}

/// Core `Commitment::Switch(blind, value)`.
pub fn switch_commit(
    pre_blind: &[u8; 32],
    value: u64,
    secp: &Secp256k1<All>,
) -> Result<[u8; 33], Error> {
    let switched = blind_switch(pre_blind, value, secp)?;
    pedersen_commit(value, &switched, secp)
}

/// Convert a Pedersen commitment to a compressed public key (Core `PublicKeys::Convert`).
pub fn commitment_to_pubkey(commitment: &[u8; 33]) -> Result<PublicKey, Error> {
    #[cfg(feature = "zkp")]
    {
        mw::commitment_to_pubkey(commitment)
    }
    #[cfg(not(feature = "zkp"))]
    {
        let _ = commitment;
        Err(Error::ZkpDisabled)
    }
}

/// Prove a 675-byte MWEB bulletproof (Core `Bulletproofs::Generate`).
pub fn bulletproof_prove(
    value: u64,
    switched_blind: &[u8; 32],
    extra_data: &[u8],
) -> Result<[u8; BULLETPROOF_LEN], Error> {
    #[cfg(feature = "zkp")]
    {
        mw::bulletproof_prove(value, switched_blind, extra_data)
    }
    #[cfg(not(feature = "zkp"))]
    {
        let _ = (value, switched_blind, extra_data);
        Err(Error::ZkpDisabled)
    }
}

/// Verify a 675-byte MWEB bulletproof (Core `Bulletproofs::Verify`).
pub fn bulletproof_verify(
    commitment: &[u8; 33],
    proof: &[u8; BULLETPROOF_LEN],
    extra_data: &[u8],
) -> Result<bool, Error> {
    #[cfg(feature = "zkp")]
    {
        mw::bulletproof_verify(commitment, proof, extra_data)
    }
    #[cfg(not(feature = "zkp"))]
    {
        let _ = (commitment, proof, extra_data);
        Err(Error::ZkpDisabled)
    }
}

/// Schnorr-sign a 32-byte message (Core `Schnorr::Sign` → `secp256k1_schnorrsig_sign`).
pub fn schnorr_sign(secret: &[u8; 32], msg32: &[u8; 32]) -> Result<[u8; 64], Error> {
    #[cfg(feature = "zkp")]
    {
        mw::schnorr_sign(secret, msg32)
    }
    #[cfg(not(feature = "zkp"))]
    {
        let _ = (secret, msg32);
        Err(Error::ZkpDisabled)
    }
}

/// Verify a Schnorr signature (Core `Schnorr::Verify` → `secp256k1_aggsig_verify_single`).
pub fn schnorr_verify(
    signature: &[u8; 64],
    pubkey: &PublicKey,
    msg32: &[u8; 32],
) -> Result<bool, Error> {
    #[cfg(feature = "zkp")]
    {
        mw::schnorr_verify(signature, &pubkey.serialize(), msg32)
    }
    #[cfg(not(feature = "zkp"))]
    {
        let _ = (signature, pubkey, msg32);
        Err(Error::ZkpDisabled)
    }
}

/// Random 32-byte secret key bytes (valid curve scalar).
///
/// The `secp` argument is unused; it is kept because callers pass one and removing
/// it would be a public API break for no benefit.
pub fn random_secret(_secp: &Secp256k1<All>) -> [u8; 32] {
    // Avoid `SecretKey::new` so this works without `bitcoin/rand-std` (no-default-features CI).
    random_scalar()
}

/// A random valid curve scalar, without requiring a curve context.
#[cfg_attr(not(feature = "zkp"), allow(dead_code))]
fn random_nonce() -> [u8; 32] {
    random_scalar()
}

/// Rejection-sample until the 32 bytes are a valid scalar, wiping every
/// rejected candidate so discarded key-adjacent material does not linger.
fn random_scalar() -> [u8; 32] {
    use zeroize::Zeroize;
    loop {
        let mut bytes = random_seed32();
        let sk = SecretKey::from_slice(&bytes);
        bytes.zeroize();
        if let Ok(sk) = sk {
            return sk.secret_bytes();
        }
    }
}

/// 32 random bytes, without requiring a curve context or validating as a scalar.
fn random_seed32() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Sum positive blinds minus negative blinds (allows a zero running total).
pub fn blind_sum(positive: &[[u8; 32]], negative: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    #[cfg(feature = "zkp")]
    {
        mw::blind_sum(positive, negative)
    }
    #[cfg(not(feature = "zkp"))]
    {
        let _ = (positive, negative);
        Err(Error::ZkpDisabled)
    }
}

/// `a + b` mod n as 32-byte secrets.
pub fn secret_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
    blind_sum(&[*a, *b], &[])
}

/// `a - b` mod n.
pub fn secret_sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
    blind_sum(&[*a], &[*b])
}

/// `a * b` mod n.
pub fn secret_mul(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
    let a = SecretKey::from_slice(a)?;
    let t = Scalar::from_be_bytes(*b).map_err(|_| Error::InvalidTweak)?;
    Ok(a.mul_tweak(&t)?.secret_bytes())
}

/// Grin / Litecoin MW secp256k1-zkp façade.
#[cfg(feature = "zkp")]
pub mod mw {
    use super::{Error, BULLETPROOF_LEN};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use once_cell::race::OnceBox;
    use secp256k1zkp::pedersen::{Commitment, RangeProof};
    use secp256k1zkp::{
        aggsig, ffi, ContextFlag, Message, PublicKey as GrinPk, Secp256k1, SecretKey as GrinSk,
        Signature,
    };

    fn secp() -> &'static Secp256k1 {
        static SECP: OnceBox<Secp256k1> = OnceBox::new();
        SECP.get_or_init(|| Box::new(Secp256k1::with_caps(ContextFlag::Commit)))
    }

    /// Signing context for the raw `schnorrsig` FFI, created once and randomized.
    ///
    /// Randomization re-blinds the context's internal scalar arithmetic. It does not
    /// change any output — signatures stay deterministic — but it means a
    /// side-channel observer cannot correlate measurements across runs against a
    /// fixed blinding. libsecp256k1 recommends it for every signing context; the
    /// previous version of this function skipped it.
    fn sign_ctx() -> *mut ffi::Context {
        static CTX: OnceBox<usize> = OnceBox::new();
        let p = *CTX.get_or_init(|| {
            let ctx = unsafe {
                ffi::secp256k1_context_create(
                    ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY,
                )
            };
            assert!(!ctx.is_null(), "secp256k1_context_create returned null");
            let seed = super::random_seed32();
            let ok = unsafe { secp256k1_context_randomize(ctx, seed.as_ptr()) };
            assert_eq!(ok, 1, "secp256k1_context_randomize failed");
            Box::new(ctx as usize)
        });
        p as *mut ffi::Context
    }

    extern "C" {
        fn secp256k1_schnorrsig_sign(
            ctx: *const ffi::Context,
            sig: *mut [u8; 64],
            nonce_is_negated: *mut core::ffi::c_int,
            msg32: *const u8,
            seckey: *const u8,
            noncefp: *const core::ffi::c_void,
            ndata: *const core::ffi::c_void,
        ) -> core::ffi::c_int;

        fn secp256k1_schnorrsig_serialize(
            ctx: *const ffi::Context,
            out64: *mut u8,
            sig: *const [u8; 64],
        ) -> core::ffi::c_int;

        fn secp256k1_context_randomize(
            ctx: *mut ffi::Context,
            seed32: *const u8,
        ) -> core::ffi::c_int;
    }

    pub(super) fn blind_sum(
        positive: &[[u8; 32]],
        negative: &[[u8; 32]],
    ) -> Result<[u8; 32], Error> {
        let secp = secp();
        let pos: Result<Vec<_>, _> = positive
            .iter()
            .map(|b| GrinSk::from_slice(secp, b).map_err(|_| Error::InvalidTweak))
            .collect();
        let neg: Result<Vec<_>, _> = negative
            .iter()
            .map(|b| GrinSk::from_slice(secp, b).map_err(|_| Error::InvalidTweak))
            .collect();
        let sum = secp
            .blind_sum(pos?, neg?)
            .map_err(|_| Error::Crypto("blind_sum failed".into()))?;
        Ok(sum.0)
    }

    pub(super) fn scalar_inverse(scalar: &[u8; 32]) -> Result<[u8; 32], Error> {
        let secp = secp();
        let mut sk = GrinSk::from_slice(secp, scalar).map_err(|_| Error::InvalidTweak)?;
        sk.inv_assign(secp)
            .map_err(|_| Error::Crypto("scalar inversion failed".into()))?;
        Ok(sk.0)
    }

    pub(super) fn pedersen_commit(value: u64, blind: &[u8; 32]) -> Result<[u8; 33], Error> {
        let secp = secp();
        let blind = GrinSk::from_slice(secp, blind).map_err(|_| Error::InvalidTweak)?;
        let commit = secp
            .commit(value, blind)
            .map_err(|_| Error::Crypto("pedersen commit failed".into()))?;
        let mut out = [0u8; 33];
        out.copy_from_slice(&commit.0);
        Ok(out)
    }

    pub(super) fn commitment_to_pubkey(
        commitment: &[u8; 33],
    ) -> Result<bitcoin::secp256k1::PublicKey, Error> {
        let secp = secp();
        let commit = Commitment::from_vec(commitment.to_vec());
        let pk = commit
            .to_pubkey(secp)
            .map_err(|_| Error::Crypto("commitment_to_pubkey failed".into()))?;
        let bytes = pk.serialize_vec(secp, true);
        bitcoin::secp256k1::PublicKey::from_slice(&bytes).map_err(Into::into)
    }

    pub(super) fn bulletproof_prove(
        value: u64,
        switched_blind: &[u8; 32],
        extra_data: &[u8],
    ) -> Result<[u8; BULLETPROOF_LEN], Error> {
        let secp = secp();
        let blind = GrinSk::from_slice(secp, switched_blind).map_err(|_| Error::InvalidTweak)?;
        // Nonces come from the bitcoin RNG because the grin crate pins rand 0.5.
        // These used to build a fresh `Secp256k1` each — two full context creations
        // per proof — for an argument the generator ignores.
        let rewind =
            GrinSk::from_slice(secp, &super::random_nonce()).map_err(|_| Error::InvalidTweak)?;
        let private =
            GrinSk::from_slice(secp, &super::random_nonce()).map_err(|_| Error::InvalidTweak)?;
        let proof = secp.bullet_proof(
            value,
            blind,
            rewind,
            private,
            Some(extra_data.to_vec()),
            None,
        );
        if proof.plen != BULLETPROOF_LEN {
            return Err(Error::Crypto(format!(
                "unexpected bulletproof length {}",
                proof.plen
            )));
        }
        let mut out = [0u8; BULLETPROOF_LEN];
        out.copy_from_slice(&proof.proof[..BULLETPROOF_LEN]);
        Ok(out)
    }

    pub(super) fn bulletproof_verify(
        commitment: &[u8; 33],
        proof: &[u8; BULLETPROOF_LEN],
        extra_data: &[u8],
    ) -> Result<bool, Error> {
        let secp = secp();
        let mut proof_bytes = [0u8; BULLETPROOF_LEN];
        proof_bytes.copy_from_slice(proof);
        let rp = RangeProof {
            proof: proof_bytes,
            plen: BULLETPROOF_LEN,
        };
        let commit = Commitment::from_vec(commitment.to_vec());
        match secp.verify_bullet_proof(commit, rp, Some(extra_data.to_vec())) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub(super) fn schnorr_sign(secret: &[u8; 32], msg32: &[u8; 32]) -> Result<[u8; 64], Error> {
        let ctx = sign_ctx();
        // Opaque schnorrsig is 64 bytes; serialize to wire R||s.
        let mut opaque = [0u8; 64];
        let ok = unsafe {
            secp256k1_schnorrsig_sign(
                ctx,
                &mut opaque,
                core::ptr::null_mut(),
                msg32.as_ptr(),
                secret.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        if ok != 1 {
            return Err(Error::Crypto("schnorrsig_sign failed".into()));
        }
        let mut out = [0u8; 64];
        let ser_ok = unsafe { secp256k1_schnorrsig_serialize(ctx, out.as_mut_ptr(), &opaque) };
        if ser_ok != 1 {
            // Previously this fell back to emitting `opaque` directly, on the
            // assumption that the opaque struct happens to be laid out as wire
            // `R || s`. That is not guaranteed by the library's API — the whole point
            // of an opaque type is that its layout may change — and a signature built
            // from a misread struct is silently invalid rather than obviously broken.
            // The layouts do coincide in this build (see
            // `opaque_signature_layout_matches_wire_form_in_this_build`), so the
            // fallback was harmless by luck; failing loudly is what keeps it that way
            // if the layout ever moves.
            return Err(Error::Crypto("schnorrsig_serialize failed".into()));
        }
        Ok(out)
    }

    pub(super) fn schnorr_verify(
        signature: &[u8; 64],
        pubkey33: &[u8; 33],
        msg32: &[u8; 32],
    ) -> Result<bool, Error> {
        let secp = secp();
        let msg = Message::from_slice(msg32).map_err(|_| Error::InvalidTweak)?;
        let sig = Signature::from_raw_data(signature).map_err(|_| Error::InvalidTweak)?;
        let pk = GrinPk::from_slice(secp, pubkey33).map_err(|_| Error::InvalidTweak)?;
        Ok(aggsig::verify_single(
            secp,
            &sig,
            &msg,
            None,
            &pk,
            Some(&pk),
            None,
            false,
        ))
    }

    /// The raw opaque signature struct, before serialization.
    ///
    /// Exists so `schnorr_serialize_is_not_a_no_op` can show the serializer actually
    /// transforms the value, rather than the removed fallback having been harmless.
    #[cfg(test)]
    pub(super) fn schnorr_sign_opaque_for_test(
        secret: &[u8; 32],
        msg32: &[u8; 32],
    ) -> Result<[u8; 64], Error> {
        let ctx = sign_ctx();
        let mut opaque = [0u8; 64];
        let ok = unsafe {
            secp256k1_schnorrsig_sign(
                ctx,
                &mut opaque,
                core::ptr::null_mut(),
                msg32.as_ptr(),
                secret.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        if ok != 1 {
            return Err(Error::Crypto("schnorrsig_sign failed".into()));
        }
        Ok(opaque)
    }

    /// Round-trip smoke: prove and verify a bulletproof.
    pub fn bulletproof_roundtrip(value: u64) -> Result<(), Error> {
        let secp_btc = bitcoin::secp256k1::Secp256k1::new();
        let blind = super::random_secret(&secp_btc);
        let switched = super::blind_switch(&blind, value, &secp_btc)?;
        let commit = super::pedersen_commit(value, &switched, &secp_btc)?;
        let proof = bulletproof_prove(value, &switched, &[])?;
        if !bulletproof_verify(&commit, &proof, &[])? {
            return Err(Error::Crypto("bulletproof roundtrip verify failed".into()));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "zkp"))]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn bulletproof_roundtrip_smoke() {
        mw::bulletproof_roundtrip(42).expect("bulletproof FFI smoke");
    }

    #[test]
    fn schnorr_sign_verify_roundtrip() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let msg = [0x11u8; 32];
        let sig = schnorr_sign(&sk.secret_bytes(), &msg).unwrap();
        assert!(schnorr_verify(&sig, &pk, &msg).unwrap());
    }

    /// F-15: known-answer vectors pinning the `grin_secp256k1zkp` FFI.
    ///
    /// Every function here crosses an `extern "C"` boundary into a vendored,
    /// unversioned C library with no ABI guarantees. Nothing in the build checks
    /// that the Rust declarations still match the C definitions — a changed struct
    /// layout or argument order compiles fine and produces wrong output, and wrong
    /// output here means unspendable coins or a commitment that does not balance.
    ///
    /// These vectors were produced by this crate against `grin_secp256k1zkp 0.7.15`
    /// (regenerate with the `print_abi_vectors` procedure in the module docs). They
    /// are deliberately values, not round-trips: a round-trip stays self-consistent
    /// under an ABI change that corrupts both directions equally.
    mod abi_vectors {
        use super::*;

        const BLIND: [u8; 32] = [0x11; 32];
        const SK: [u8; 32] = [0x22; 32];
        const MSG: [u8; 32] = [0x33; 32];
        const VALUE: u64 = 1_000_000;

        fn hex(b: &[u8]) -> alloc::string::String {
            b.iter().map(|x| alloc::format!("{x:02x}")).collect()
        }

        #[test]
        fn pedersen_commit_vector() {
            let secp = Secp256k1::new();
            assert_eq!(
                hex(&pedersen_commit(VALUE, &BLIND, &secp).unwrap()),
                "0873f0cc05263feb39f6a9ffa3bee023086925aeb9bda34087d1b134294284a3c8"
            );
        }

        #[test]
        fn blind_switch_vector() {
            let secp = Secp256k1::new();
            assert_eq!(
                hex(&blind_switch(&BLIND, VALUE, &secp).unwrap()),
                "abd8840f3a9271f4bb04059000d8716f28806bd22b5e11d5e7679e71ac4e4493"
            );
        }

        #[test]
        fn switch_commit_vector() {
            let secp = Secp256k1::new();
            assert_eq!(
                hex(&switch_commit(&BLIND, VALUE, &secp).unwrap()),
                "09378091f6a15ad8bf50258613ef495eb022dbdd381d6fefaaca4ed07b53d7d733"
            );
        }

        #[test]
        fn scalar_inverse_vector() {
            assert_eq!(
                hex(&scalar_inverse(&BLIND).unwrap()),
                "88c6ff2ac8df283bc73779d656efe5a179e0e12fd46a933b663fc60e85bd8977"
            );
            // And it really is an inverse: a * a⁻¹ == 1.
            let one = secret_mul(&BLIND, &scalar_inverse(&BLIND).unwrap()).unwrap();
            let mut expected = [0u8; 32];
            expected[31] = 1;
            assert_eq!(one, expected);
        }

        #[test]
        fn blind_sum_vectors() {
            assert_eq!(hex(&secret_add(&BLIND, &SK).unwrap()), hex(&[0x33; 32]));
            assert_eq!(
                hex(&secret_mul(&BLIND, &SK).unwrap()),
                "6b366461789ec75ba4c07f575cf9dba878328988726146263532b3725cf60983"
            );
            // Subtraction is the inverse of addition through the same FFI call.
            assert_eq!(secret_sub(&[0x33; 32], &SK).unwrap(), BLIND);
        }

        #[test]
        fn commitment_to_pubkey_vector() {
            let secp = Secp256k1::new();
            let commit = pedersen_commit(VALUE, &BLIND, &secp).unwrap();
            assert_eq!(
                hex(&commitment_to_pubkey(&commit).unwrap().serialize()),
                "0273f0cc05263feb39f6a9ffa3bee023086925aeb9bda34087d1b134294284a3c8"
            );
        }

        /// F-07: the signature must be the serialized wire form.
        ///
        /// `schnorr_sign` used to fall back to emitting the opaque `secp256k1`
        /// struct when serialization failed, on the assumption its layout matched
        /// wire `R || s`. This vector is what makes that assumption checkable: it
        /// was produced through the serializer, so if the serializer ever stops
        /// running the bytes change and this fails.
        #[test]
        fn schnorr_sign_vector() {
            assert_eq!(
                hex(&schnorr_sign(&SK, &MSG).unwrap()),
                "ff13bc2c8e63d4645eb4d917e23244fc6b951ecca4d98fabce243b49ba03f02e\
                 7833402034182ca295276d6e71514c5faf8d59ff71e7d3bb0639e550d4dd1dac"
            );
        }

        /// The signing nonce is derived deterministically from the key and message,
        /// so two signatures over the same input must be byte-identical. If this ever
        /// starts failing, the nonce function changed — which for a Schnorr signature
        /// is a key-recovery risk if the nonce is ever reused across messages.
        #[test]
        fn schnorr_sign_is_deterministic() {
            let a = schnorr_sign(&SK, &MSG).unwrap();
            let b = schnorr_sign(&SK, &MSG).unwrap();
            assert_eq!(a, b);
            // A different message must give a different signature.
            let c = schnorr_sign(&SK, &[0x34; 32]).unwrap();
            assert_ne!(a, c);
        }

        /// The opaque signature struct currently *does* have the same bytes as the
        /// serialized wire form, which is why the removed fallback in `schnorr_sign`
        /// never produced a visibly wrong signature.
        ///
        /// That equality is a property of how this build of `grin_secp256k1zkp`
        /// happens to lay out `secp256k1_schnorrsig`, not a guarantee — the type is
        /// opaque precisely so the library may change it. The fallback was removed
        /// rather than kept because a layout change would have turned it from
        /// harmless into a silent producer of invalid signatures.
        ///
        /// This test pins the coincidence so it is visible. If it starts failing,
        /// the layout changed and removing the fallback was what prevented a bug.
        #[test]
        fn opaque_signature_layout_matches_wire_form_in_this_build() {
            let sig = schnorr_sign(&SK, &MSG).unwrap();
            let opaque = mw::schnorr_sign_opaque_for_test(&SK, &MSG).unwrap();
            assert_eq!(
                sig, opaque,
                "the opaque layout diverged from the wire form; the removed \
                 `schnorr_sign` serialize fallback would now be emitting invalid \
                 signatures"
            );
        }

        /// A tampered signature must not verify, and verification must not panic on
        /// arbitrary 64-byte input.
        #[test]
        fn schnorr_verify_rejects_tampered_signatures() {
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&SK).unwrap();
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let sig = schnorr_sign(&SK, &MSG).unwrap();
            assert!(schnorr_verify(&sig, &pk, &MSG).unwrap());

            for byte in [0usize, 31, 32, 63] {
                let mut bad = sig;
                bad[byte] ^= 1;
                assert!(
                    !schnorr_verify(&bad, &pk, &MSG).unwrap_or(false),
                    "a signature with byte {byte} flipped verified"
                );
            }
            // Right signature, wrong message.
            assert!(!schnorr_verify(&sig, &pk, &[0x34; 32]).unwrap_or(false));
            // Structurally invalid input must error or return false, never panic.
            let _ = schnorr_verify(&[0xFF; 64], &pk, &MSG);
            let _ = schnorr_verify(&[0x00; 64], &pk, &MSG);
        }

        /// The proof length is fixed by the wire format, and the FFI copies into a
        /// buffer of exactly that size.
        #[test]
        fn bulletproof_length_is_fixed() {
            let secp = Secp256k1::new();
            let blind = blind_switch(&BLIND, VALUE, &secp).unwrap();
            let proof = bulletproof_prove(VALUE, &blind, &[]).unwrap();
            assert_eq!(proof.len(), BULLETPROOF_LEN);

            // Proofs are randomized, so two are different, but both must verify.
            let commit = pedersen_commit(VALUE, &blind, &secp).unwrap();
            let proof2 = bulletproof_prove(VALUE, &blind, &[]).unwrap();
            assert_ne!(proof, proof2, "bulletproof nonces are not being randomized");
            assert!(bulletproof_verify(&commit, &proof, &[]).unwrap());
            assert!(bulletproof_verify(&commit, &proof2, &[]).unwrap());
        }

        /// `extra_data` is bound into the proof, so a proof made under one context
        /// must not verify under another. MWEB uses this to tie a proof to its
        /// output.
        #[test]
        fn bulletproof_binds_extra_data() {
            let secp = Secp256k1::new();
            let blind = blind_switch(&BLIND, VALUE, &secp).unwrap();
            let commit = pedersen_commit(VALUE, &blind, &secp).unwrap();
            let proof = bulletproof_prove(VALUE, &blind, b"context-a").unwrap();
            assert!(bulletproof_verify(&commit, &proof, b"context-a").unwrap());
            assert!(!bulletproof_verify(&commit, &proof, b"context-b").unwrap());
            assert!(!bulletproof_verify(&commit, &proof, &[]).unwrap());
        }

        /// A proof for one value must not verify against another value's commitment.
        #[test]
        fn bulletproof_binds_value_and_commitment() {
            let secp = Secp256k1::new();
            let blind = blind_switch(&BLIND, VALUE, &secp).unwrap();
            let proof = bulletproof_prove(VALUE, &blind, &[]).unwrap();

            let other_commit = pedersen_commit(VALUE + 1, &blind, &secp).unwrap();
            assert!(!bulletproof_verify(&other_commit, &proof, &[]).unwrap());

            let commit = pedersen_commit(VALUE, &blind, &secp).unwrap();
            let mut tampered = proof;
            tampered[0] ^= 1;
            assert!(!bulletproof_verify(&commit, &tampered, &[]).unwrap());
        }

        /// F-13c: measure per-proof `bulletproof_verify` cost. Not an
        /// assertion-style test — run manually and record the numbers in
        /// `docs/SECURITY_PLAN.md`:
        ///
        /// ```sh
        /// cargo test -p bdk_mweb --release --features zkp \
        ///     measure_bulletproof_verify_cost -- --ignored --nocapture
        /// ```
        ///
        /// This is the per-owned-output cost of `MwebSyncer::verify_rangeproofs`.
        #[cfg(feature = "std")]
        #[test]
        #[ignore = "timing measurement, run in release with --nocapture"]
        #[allow(clippy::print_stdout)] // measurement output is the point of this test
        fn measure_bulletproof_verify_cost() {
            let secp = Secp256k1::new();
            let blind = blind_switch(&BLIND, VALUE, &secp).unwrap();
            let commit = pedersen_commit(VALUE, &blind, &secp).unwrap();
            let proof = bulletproof_prove(VALUE, &blind, &[]).unwrap();

            const ITERS: u32 = 50;
            let start = std::time::Instant::now();
            for _ in 0..ITERS {
                assert!(bulletproof_verify(&commit, &proof, &[]).unwrap());
            }
            let per_proof = start.elapsed() / ITERS;
            println!("bulletproof_verify: {per_proof:?} per proof ({ITERS} iterations)");
        }
    }

    #[test]
    fn switch_commit_is_deterministic() {
        let secp = Secp256k1::new();
        let mut blind = [7u8; 32];
        blind[0] = 0x01;
        let c1 = switch_commit(&blind, 100_000, &secp).unwrap();
        let c2 = switch_commit(&blind, 100_000, &secp).unwrap();
        assert_eq!(c1, c2);
        assert!(
            c1[0] == 8 || c1[0] == 9,
            "pedersen prefix, got {:02x}",
            c1[0]
        );
    }
}
