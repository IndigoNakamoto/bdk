#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod utils;

pub use anyhow;

// A regtest environment running `bitcoind` with an `electrs` instance connected to it.
//
// This drives Bitcoin Core through `electrsd`, which depends on the upstream `bitcoin` crate
// rather than `litecoin`, so its types do not unify with the rest of this fork and it does not
// currently compile. It is kept in tree so that upstream merges stay clean, and will come back
// once a `litecoind` + `electrs-ltc` harness replaces it.
//
// Building it takes two switches: the `daemon` feature pulls in `electrsd`, and the
// `daemon_tests` cfg compiles the code. Splitting them keeps `--all-features` green.
#[cfg(all(feature = "daemon", daemon_tests))]
mod daemon;
#[cfg(all(feature = "daemon", daemon_tests))]
pub use daemon::*;
