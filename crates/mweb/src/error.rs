//! Errors for `bdk_mweb`.

use alloc::string::String;
use core::fmt;

/// Why a peer-attributable error justifies banning the peer and rotating.
///
/// This is the typed discriminant behind
/// [`crate::mweb_sync::is_banworthy_peer_error`] (F-18): classification is
/// carried in the error itself, so no message wording is load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BanReason {
    /// A payload failed verification against a committed root or anchor
    /// (leafset root, PMMR output root, segment proof, HogEx anchoring).
    BadProof,
    /// The peer sent something the protocol does not allow: bad framing or
    /// magic, out-of-bounds sizes, unsorted batches, a wrong-block response,
    /// or a batch that cannot advance the sync cursor.
    ProtocolViolation,
    /// The transport failed mid-conversation: timeout, closed socket, broken
    /// pipe, or another I/O failure attributable to the connection.
    Transport,
    /// The peer refused to serve because it is rate-limiting us, not because
    /// anything is wrong with it.
    ///
    /// Litecoin Core 0.21.5.6 rate-limits `getmwebleafset` / `getmwebutxos`
    /// with a node-wide token bucket and *silently drops* over-limit requests
    /// (`AllowMWEBServe`, commits `cb65fc5` / `f24dec1`). The bucket is shared
    /// across every non-whitelisted light client, so a peer can throttle us
    /// while being perfectly healthy and honest.
    ///
    /// Unlike the other reasons this is **not** banworthy — see
    /// [`crate::mweb_sync::is_banworthy_peer_error`]. Banning here would take a
    /// good node out of the pool for busy-ness, and in the common single-peer
    /// deployment it would take out the only node the wallet has.
    Throttled,
}

impl fmt::Display for BanReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadProof => write!(f, "bad proof"),
            Self::ProtocolViolation => write!(f, "protocol violation"),
            Self::Transport => write!(f, "transport failure"),
            Self::Throttled => write!(f, "rate limited"),
        }
    }
}

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
    /// Peer-attributable failure; the [`BanReason`] drives ban/rotate decisions.
    ///
    /// Custom [`crate::lip0006::MwebUtxoSource`] implementations should use the
    /// [`Error::bad_proof`] / [`Error::protocol`] / [`Error::transport`]
    /// constructors for failures the peer caused, so peer rotation keeps
    /// working. The message is diagnostics only and carries no semantics.
    Peer(BanReason, String),
}

impl Error {
    /// A payload failed verification against a committed root or anchor.
    pub fn bad_proof(msg: impl Into<String>) -> Self {
        Self::Peer(BanReason::BadProof, msg.into())
    }

    /// The peer violated the wire protocol (framing, bounds, ordering, liveness).
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Peer(BanReason::ProtocolViolation, msg.into())
    }

    /// The transport to the peer failed (timeout, disconnect, I/O error).
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::Peer(BanReason::Transport, msg.into())
    }

    /// The peer is rate-limiting us. Peer-attributable but not banworthy.
    pub fn throttled(msg: impl Into<String>) -> Self {
        Self::Peer(BanReason::Throttled, msg.into())
    }

    /// The typed ban classification, when this error is peer-attributable.
    ///
    /// Peer-attributable is not the same as banworthy: [`BanReason::Throttled`]
    /// identifies the peer as the source without justifying a ban. Use
    /// [`crate::mweb_sync::is_banworthy_peer_error`] for the ban decision.
    pub fn ban_reason(&self) -> Option<BanReason> {
        match self {
            Self::Peer(reason, _) => Some(*reason),
            _ => None,
        }
    }
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
            Self::Peer(reason, e) => write!(f, "MWEB peer error ({reason}): {e}"),
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
