//! LIP-0006 sync against a litecoind that is actively rate-limiting us.
//!
//! Litecoin Core 0.21.5.6 meters `getmwebleafset` / `getmwebutxos` through a
//! node-wide token bucket (`AllowMWEBServe`) and *silently discards* requests
//! over budget — no reject, no disconnect, no reply. Before the client learned to
//! detect that, a drained bucket turned into a 180-second socket read timeout, an
//! `Error::transport`, and a ban applied to a node that had done nothing wrong.
//!
//! The rest of the node-backed suite cannot reach this: the harness passes
//! `-whitelist=noban@127.0.0.1`, which exempts it from the limit entirely. This
//! test asks for [`PeerPolicy::RateLimited`] so litecoind treats it as it would
//! any other light client.
//!
//! Needs `LITECOIND_EXE` (skips when unset).

#![cfg(feature = "lip0006")]
// The timings are the point of running this by hand: they say whether the peer
// actually throttled and how much latency that cost. Run with `--nocapture`.
#![allow(clippy::print_stderr)]

use std::time::{Duration, Instant};

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006::{sync_mweb_at_tip, MwebUtxoSource, VerifyMode};
use bdk_mweb::lip0006_tcp::TcpMwebPeer;
use bdk_mweb::{AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};
use bdk_testenv::{try_node_from_env_with_policy, PeerPolicy};
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, Network};
use hex_conservative::FromHex;

const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Core's `MWEB_SERVE_MAX_TOKENS`. Enough requests to spend the whole burst.
const DRAIN_REQUESTS: usize = 40;

/// A sync that has to wait out the bucket is slow, but it must not be unbounded.
/// Without a ceiling here a regression would wedge CI instead of failing it.
const SYNC_BUDGET: Duration = Duration::from_secs(120);

#[test]
fn sync_completes_against_a_rate_limiting_peer() {
    let Some(env) = try_node_from_env_with_policy(PeerPolicy::RateLimited).expect("harness") else {
        return;
    };

    let seed = <Vec<u8>>::from_hex(SEED_HEX).unwrap();
    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &seed,
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .unwrap();
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp).unwrap();
    let addr = keys.address(2, Network::Regtest, &secp).unwrap();

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let amount = Amount::from_btc(1.0).unwrap();
    env.finalize_mweb_pegin(&addr, amount)
        .expect("Core sendtoaddress mweb");
    env.mine_mweb_activation(&mining).expect("activate");

    let tip_height = env.rpc.get_block_count().unwrap();
    let tip_hash = env.rpc.get_block_hash(tip_height).unwrap();

    // Spend the node's serving budget so the sync below starts against an empty
    // bucket. Each of these is a real request the node either answers or drops;
    // the client absorbs the drops, so they all resolve either way.
    let mut drain_peer =
        TcpMwebPeer::connect(env.p2p_addr(), Network::Regtest).expect("p2p connect");
    let drain_start = Instant::now();
    for i in 0..DRAIN_REQUESTS {
        drain_peer
            .get_leafset(tip_hash)
            .unwrap_or_else(|e| panic!("leafset request {i} failed under rate limiting: {e}"));
    }
    let drain_elapsed = drain_start.elapsed();
    eprintln!("drained {DRAIN_REQUESTS} leafset requests in {drain_elapsed:?}");

    let mut peer = TcpMwebPeer::connect(env.p2p_addr(), Network::Regtest).expect("p2p connect");
    let mut db = MwebCoinDatabase::new();
    let sync_start = Instant::now();
    let result = sync_mweb_at_tip(
        &mut peer,
        &keys,
        &book,
        &mut db,
        &secp,
        tip_hash,
        tip_height,
        VerifyMode::HeaderAndPmmr,
    )
    .expect("sync must survive a drained serving bucket");
    let sync_elapsed = sync_start.elapsed();
    eprintln!("sync against a rate-limited peer took {sync_elapsed:?}");

    assert!(
        !result.found.is_empty(),
        "expected at least one owned output"
    );
    assert_eq!(
        db.balance(),
        amount.to_sat(),
        "rate limiting must delay a sync, never change its result"
    );
    assert!(
        sync_elapsed < SYNC_BUDGET,
        "sync took {sync_elapsed:?}, over the {SYNC_BUDGET:?} budget: the client is \
         probably waiting out socket read timeouts instead of detecting dropped requests"
    );
}
