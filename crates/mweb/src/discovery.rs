//! Finding public MWEB-serving peers, so a wallet works without litecoind.
//!
//! Litecoin's DNS seeders implement the `x<flags>` service-bit query, but only
//! answer it for the low flags — `x1` and `x9` return records while
//! `x8388608` (`NODE_MWEB_LIGHT_CLIENT`) returns nothing. So candidates come
//! back unfiltered and we check the bit ourselves with a short version
//! handshake. In practice most seeder results do serve MWEB, so a single round
//! of probes fills the pool.
//!
//! Ported from ltc-wallet-mac's `discovery.rs` so mobile (UniFFI) and desktop
//! consumers share one implementation.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, ServiceFlags};
use bitcoin::Network;

/// `NODE_MWEB_LIGHT_CLIENT` from Litecoin Core `protocol.h`: the peer answers
/// LIP-0006 light-client requests.
pub const NODE_MWEB_LIGHT_CLIENT: u64 = 1 << 23;

const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
/// Wallets tend to sync on a short timer; re-crawling that often would be rude
/// to the seeders.
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_PROBES: usize = 32;
const WANT_PEERS: usize = 8;

/// Litecoin Core's DNS seeds for `network` (empty for regtest/signet).
pub fn dns_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Bitcoin => &[
            "seed-a.litecoin.loshan.co.uk",
            "dnsseed.thrasher.io",
            "dnsseed.litecointools.com",
            "dnsseed.litecoinpool.org",
            "dnsseed.koin-project.com",
        ],
        Network::Testnet4 => &[
            "testnet-seed.litecointools.com",
            "seed-b.litecoin.loshan.co.uk",
            "dnsseed-testnet.thrasher.io",
        ],
        Network::Signet | Network::Regtest => &[],
    }
}

/// Default P2P port for `network` (mainnet 9333, testnet 19335).
pub fn p2p_port(network: Network) -> u16 {
    match network {
        Network::Bitcoin => 9333,
        Network::Testnet4 | Network::Signet => 19335,
        Network::Regtest => 19444,
    }
}

struct Cached {
    network: Network,
    at: Instant,
    addrs: Vec<SocketAddr>,
}

static CACHE: Mutex<Option<Cached>> = Mutex::new(None);

/// Peers that completed a handshake advertising MWEB light-client support.
///
/// Cached for 15 minutes. Returns an empty vec when the seeds are unreachable
/// or nothing answers, which callers treat as "MWEB unavailable" rather than
/// an error.
pub fn discover_mweb_peers(network: Network) -> Vec<SocketAddr> {
    if let Ok(guard) = CACHE.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached.network == network
                && cached.at.elapsed() < CACHE_TTL
                && !cached.addrs.is_empty()
            {
                return cached.addrs.clone();
            }
        }
    }
    let addrs = crawl(network);
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some(Cached {
            network,
            at: Instant::now(),
            addrs: addrs.clone(),
        });
    }
    addrs
}

/// Forget cached peers so the next call re-crawls (used after a settings change).
pub fn clear_cache() {
    if let Ok(mut guard) = CACHE.lock() {
        *guard = None;
    }
}

fn crawl(network: Network) -> Vec<SocketAddr> {
    let port = p2p_port(network);
    let mut candidates: Vec<SocketAddr> = Vec::new();
    for host in dns_seeds(network) {
        let Ok(resolved) = (*host, port).to_socket_addrs() else {
            continue;
        };
        for addr in resolved {
            if !candidates.contains(&addr) {
                candidates.push(addr);
            }
        }
    }
    // Spread load across the seeder's answer instead of always taking the
    // first few, which would concentrate every install on the same nodes.
    shuffle(&mut candidates);
    candidates.truncate(MAX_PROBES);

    let found = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for &addr in &candidates {
            let found = &found;
            scope.spawn(move || {
                if serves_mweb(addr, network) {
                    if let Ok(mut found) = found.lock() {
                        found.push(addr);
                    }
                }
            });
        }
    });

    let mut addrs = found.into_inner().unwrap_or_default();
    addrs.truncate(WANT_PEERS);
    addrs
}

fn serves_mweb(addr: SocketAddr, network: Network) -> bool {
    peer_services(addr, network).is_some_and(|s| s & NODE_MWEB_LIGHT_CLIENT != 0)
}

/// Handshake far enough to read the peer's advertised service flags, then hang up.
fn peer_services(addr: SocketAddr, network: Network) -> Option<u64> {
    let magic = network.magic();
    let mut stream = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ours = ServiceFlags::from(
        u64::from(ServiceFlags::NETWORK)
            | u64::from(ServiceFlags::WITNESS)
            | NODE_MWEB_LIGHT_CLIENT,
    );
    let version = VersionMessage {
        version: 70017,
        services: ours,
        timestamp: now,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&([0, 0, 0, 0], 0).into(), ours),
        nonce: 0,
        user_agent: "/bdk-mweb:0.1.0/".into(),
        start_height: 0,
        relay: false,
    };
    let raw = RawNetworkMessage::new(magic, NetworkMessage::Version(version));
    stream.write_all(&serialize(&raw)).ok()?;

    for _ in 0..8 {
        let msg = recv(&mut stream)?;
        if let NetworkMessage::Version(peer) = msg.payload() {
            return Some(u64::from(peer.services));
        }
    }
    None
}

fn recv(stream: &mut TcpStream) -> Option<RawNetworkMessage> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes(header[16..20].try_into().ok()?) as usize;
    // A peer that claims a huge payload is broken or hostile; drop it.
    if len > 4_000_000 {
        return None;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).ok()?;
    }
    let mut full = Vec::with_capacity(24 + len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&payload);
    deserialize(&full).ok()
}

/// Fisher-Yates with a xorshift seeded from the clock. Peer choice only needs
/// to be spread out, not unpredictable, so this avoids pulling in more `rand`.
fn shuffle(addrs: &mut [SocketAddr]) {
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        | 1;
    for i in (1..addrs.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        addrs.swap(i, (state % (i as u64 + 1)) as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mweb_light_client_bit_matches_core() {
        assert_eq!(NODE_MWEB_LIGHT_CLIENT, 8_388_608);
    }

    #[test]
    fn shuffle_preserves_membership() {
        let mut addrs: Vec<SocketAddr> = (0..16u16)
            .map(|i| SocketAddr::from(([127, 0, 0, 1], 9000 + i)))
            .collect();
        let original = addrs.clone();
        shuffle(&mut addrs);
        assert_eq!(addrs.len(), original.len());
        for addr in &original {
            assert!(addrs.contains(addr), "{addr} lost in shuffle");
        }
    }

    #[test]
    fn every_public_network_has_seeds_and_a_port() {
        for network in [Network::Bitcoin, Network::Testnet4] {
            assert!(!dns_seeds(network).is_empty());
            assert_ne!(p2p_port(network), 0);
        }
        assert!(dns_seeds(Network::Regtest).is_empty());
    }

    /// Hits the real DNS seeds and real peers; run with `--ignored`.
    #[test]
    #[ignore = "requires network access"]
    fn discovers_live_mainnet_peers() {
        let peers = discover_mweb_peers(Network::Bitcoin);
        eprintln!("discovered {} MWEB peers: {peers:?}", peers.len());
        assert!(!peers.is_empty(), "no MWEB peers found via DNS seeds");
    }
}
