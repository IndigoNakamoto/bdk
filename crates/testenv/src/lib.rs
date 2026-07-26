#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod utils;

pub use anyhow;

/// A regtest environment running `bitcoind` with an `electrs` instance connected to it.
///
/// This is gated behind the non-default `daemon` feature: it drives Bitcoin Core through
/// `electrsd`, which depends on the upstream `bitcoin` crate rather than `litecoin`, so its types
/// do not unify with the rest of this fork. It stays available for upstream merges but cannot be
/// used for Litecoin testing until a `litecoind` + `electrs-ltc` harness replaces it.
#[cfg(feature = "daemon")]
mod daemon;
#[cfg(feature = "daemon")]
pub use daemon::*;
