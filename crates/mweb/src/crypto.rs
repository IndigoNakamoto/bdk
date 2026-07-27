//! Consensus-crypto façade over `secp256k1-zkp` (Elements bindings).
//!
//! See [`docs/MWEB_ARCHITECTURE.md`](../../../docs/MWEB_ARCHITECTURE.md) for the Phase 4 gate:
//! Litecoin Core vendors its own `bulletproofs` / `aggsig` modules. Smoke tests here only prove
//! the FFI links; they do **not** claim litecoind will accept Elements proofs for MWEB spends.

use crate::error::Error;

/// Pedersen commitment + rangeproof smoke helpers (feature = `zkp`).
#[cfg(feature = "zkp")]
pub mod zkp {
    use super::Error;
    use secp256k1_zkp::rand::{thread_rng, RngCore};
    use secp256k1_zkp::{
        Generator, PedersenCommitment, RangeProof, Secp256k1, SecretKey, Tag, Tweak,
    };

    /// Create a Pedersen commitment to `value` and prove/verify a rangeproof (FFI smoke test).
    pub fn commit_and_verify_rangeproof(value: u64) -> Result<(), Error> {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();

        let value_blinding = Tweak::new(&mut rng);
        let generator_blinding = Tweak::new(&mut rng);
        let mut tag_bytes = [0u8; 32];
        rng.fill_bytes(&mut tag_bytes);
        let tag = Tag::from(tag_bytes);

        let generator = Generator::new_blinded(&secp, tag, generator_blinding);
        let commitment = PedersenCommitment::new(&secp, value, value_blinding, generator);

        let sk = SecretKey::new(&mut rng);
        let proof = RangeProof::new(
            &secp,
            0,
            commitment,
            value,
            value_blinding,
            &[],
            &[],
            sk,
            0,
            52,
            generator,
        )
        .map_err(|_| Error::InvalidTweak)?;

        proof
            .verify(&secp, commitment, &[], generator)
            .map_err(|_| Error::InvalidTweak)?;
        Ok(())
    }
}

/// Stub when built without `zkp`.
#[cfg(not(feature = "zkp"))]
pub mod zkp {
    use super::Error;
    /// See feature `zkp`.
    pub fn commit_and_verify_rangeproof(_value: u64) -> Result<(), Error> {
        Err(Error::ZkpDisabled)
    }
}

#[cfg(all(test, feature = "zkp"))]
mod tests {
    use super::zkp::commit_and_verify_rangeproof;

    #[test]
    fn pedersen_rangeproof_smoke() {
        commit_and_verify_rangeproof(42).expect("zkp FFI smoke test");
    }
}
