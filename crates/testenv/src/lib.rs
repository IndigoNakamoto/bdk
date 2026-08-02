#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod utils;

pub use anyhow;

// A regtest environment running `bitcoind` with an `electrs` instance connected to it.
//
// This drives Bitcoin Core through `electrsd`, which depends on the upstream `bitcoin` crate
// rather than `litecoin`, so its types do not unify with the rest of this fork and it does not
// currently compile. It is kept in tree so that upstream merges stay clean.
//
// Building it takes two switches: the `daemon` feature pulls in `electrsd`, and the
// `daemon_tests` cfg compiles the code. Splitting them keeps `--all-features` green.
#[cfg(all(feature = "daemon", daemon_tests))]
mod daemon;
#[cfg(all(feature = "daemon", daemon_tests))]
pub use daemon::*;

/// Litecoin regtest harness (`litecoind` + `electrs-ltc` from env-provided binaries).
#[cfg(feature = "litecoin-daemon")]
pub mod litecoin_regtest;
#[cfg(feature = "litecoin-daemon")]
pub use litecoin_regtest::{
    require_litecoind, try_from_env, try_node_from_env, try_node_from_env_with_policy,
    LitecoinNodeEnv, LitecoinTestEnv, PeerPolicy, RpcClient, FIRST_MWEB_HEIGHT,
    MWEB_PEGIN_MATURITY,
};
