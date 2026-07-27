//! Errors for `bdk_mweb`.

use alloc::string::String;
use core::fmt;

/// Errors produced by MWEB key derivation, addressing, or crypto helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// BIP32 derivation failed.
    Bip32(bitcoin::bip32::Error),
    /// secp256k1 operation failed.
    Secp256k1(bitcoin::secp256k1::Error),
    /// Invalid tweak / scalar for address index derivation.
    InvalidTweak,
    /// Feature `zkp` is disabled.
    ZkpDisabled,
    /// Transaction builder / amount mismatch.
    InsufficientFunds,
    /// Missing spend key or blind on an input coin.
    MissingCoinSecrets,
    /// Recipient is not an MWEB stealth address.
    NotMwebAddress,
    /// Consensus / FFI crypto failure.
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bip32(e) => write!(f, "BIP32 error: {e}"),
            Self::Secp256k1(e) => write!(f, "secp256k1 error: {e}"),
            Self::InvalidTweak => write!(f, "invalid address-index tweak"),
            Self::ZkpDisabled => write!(f, "bdk_mweb built without the `zkp` feature"),
            Self::InsufficientFunds => write!(f, "input amount does not cover recipients + fee"),
            Self::MissingCoinSecrets => write!(f, "MWEB coin missing spend_key or blind"),
            Self::NotMwebAddress => write!(f, "address is not an MWEB stealth address"),
            Self::Crypto(e) => write!(f, "MWEB crypto error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bip32(e) => Some(e),
            Self::Secp256k1(e) => Some(e),
            _ => None,
        }
    }
}

impl From<bitcoin::bip32::Error> for Error {
    fn from(e: bitcoin::bip32::Error) -> Self {
        Self::Bip32(e)
    }
}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}
