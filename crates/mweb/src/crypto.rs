//! Consensus-crypto helpers: switch commitments + MW bulletproof / schnorr FFI.
//!
//! Switch commitments match Litecoin Core `Pedersen::BlindSwitch` / `Commitment::Switch`:
//! `r' = r + SHA256(ser_commit(v·H+r·G) || ser_compressed(r·J))`, then `C = v·H + r'·G`.
//!
//! Bulletproofs and Schnorr use Grin’s vendored `secp256k1-zkp` (same modules Litecoin Core’s
//! `Bulletproofs.cpp` / `Schnorr.cpp` call). Elements CT `rangeproof_sign` is the wrong proof
//! system (not the fixed 675-byte MWEB bulletproof).

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{All, PublicKey, Scalar, SecretKey};

use crate::error::Error;

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
) -> Result<[u8; 675], Error> {
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
    proof: &[u8; 675],
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
pub fn random_secret(_secp: &Secp256k1<All>) -> [u8; 32] {
    use rand::RngCore;
    // Avoid `SecretKey::new` so this works without `bitcoin/rand-std` (no-default-features CI).
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk.secret_bytes();
        }
    }
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
    use super::Error;
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

    fn sign_ctx() -> *mut ffi::Context {
        static CTX: OnceBox<usize> = OnceBox::new();
        let p = *CTX.get_or_init(|| {
            let ctx = unsafe {
                ffi::secp256k1_context_create(
                    ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY,
                )
            };
            assert!(!ctx.is_null());
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
    ) -> Result<[u8; 675], Error> {
        let secp = secp();
        let blind = GrinSk::from_slice(secp, switched_blind).map_err(|_| Error::InvalidTweak)?;
        // Generate nonces via bitcoin RNG (grin crate pins rand 0.5).
        let rewind = GrinSk::from_slice(secp, &{
            let btc = bitcoin::secp256k1::Secp256k1::new();
            super::random_secret(&btc)
        })
        .map_err(|_| Error::InvalidTweak)?;
        let private = GrinSk::from_slice(secp, &{
            let btc = bitcoin::secp256k1::Secp256k1::new();
            super::random_secret(&btc)
        })
        .map_err(|_| Error::InvalidTweak)?;
        let proof = secp.bullet_proof(
            value,
            blind,
            rewind,
            private,
            Some(extra_data.to_vec()),
            None,
        );
        if proof.plen != 675 {
            return Err(Error::Crypto(format!(
                "unexpected bulletproof length {}",
                proof.plen
            )));
        }
        let mut out = [0u8; 675];
        out.copy_from_slice(&proof.proof[..675]);
        Ok(out)
    }

    pub(super) fn bulletproof_verify(
        commitment: &[u8; 33],
        proof: &[u8; 675],
        extra_data: &[u8],
    ) -> Result<bool, Error> {
        let secp = secp();
        let mut proof_bytes = [0u8; 675];
        proof_bytes.copy_from_slice(proof);
        let rp = RangeProof {
            proof: proof_bytes,
            plen: 675,
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
            // Opaque layout matches wire form in this zkp fork.
            out = opaque;
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
