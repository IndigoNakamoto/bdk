//! Thin TCP client for LIP-0006 messages against litecoind.
//!
//! Performs a minimal `version` / `verack` handshake, then exchanges
//! `getdata`(MSG_MWEB_HEADER / MSG_MWEB_LEAFSET) and `getmwebutxos` as raw
//! unknown payloads. Intended for regtest; prefer [`crate::lip0006::VerifyMode::HeaderAndPmmr`].

// Every byte received here is peer-controlled; a reachable panic is a remote DoS.
#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::blockdata::block::BlockHash;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::consensus::Decodable;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use bitcoin::Network;

use crate::error::Error;
use crate::limits::MAX_P2P_PAYLOAD;
use crate::lip0006::MwebUtxoSource;
use crate::p2p::{
    mweb_inv, GetMwebUtxos, MwebHeaderMsg, MwebLeafset, MwebUtxos, MSG_MWEB_HEADER,
    MSG_MWEB_LEAFSET, MSG_MWEB_TX,
};
use crate::tx_builder::kernel_id;

/// Wall-clock budget for one [`TcpMwebPeer::recv_until_cmd`] call.
///
/// Generous enough for litecoind to assemble a large UTXO batch under load, but
/// bounded so a peer trickling filler messages cannot stall a sync indefinitely.
const RECV_UNTIL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

/// Requests to put in flight per serve round.
///
/// Litecoin Core 0.21.5.6 rate-limits `getmwebleafset` / `getmwebutxos` with a
/// node-wide token bucket (`AllowMWEBServe`): `MWEB_SERVE_MAX_TOKENS = 32`
/// burst, `MWEB_SERVE_REFILL_PER_SECOND = 0.5`. Matching the burst means the
/// first round of a sync is served in full on an idle node.
///
/// This is a pacing hint, not a correctness boundary. The bucket is shared
/// across every non-whitelisted light client on the node, so the tokens
/// actually available to us are unknowable from here; correctness comes from
/// [`TcpMwebPeer::serve_round`] detecting what was dropped and re-issuing it.
const MWEB_SERVE_BURST: usize = 32;

/// How long to wait for the peer to accrue one serving token.
///
/// The reciprocal of Core's `MWEB_SERVE_REFILL_PER_SECOND = 0.5`. Also a hint:
/// waiting too little costs a wasted round, waiting too much costs latency, and
/// neither loses data.
const THROTTLE_REFILL_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Rounds that may serve nothing at all before a sync gives up on the peer.
///
/// The re-issue loop only terminates because a round either makes progress or
/// increments this counter (cf. F-05b): without the bound, a peer that accepts
/// requests and answers none would spin forever.
const MAX_CONSECUTIVE_THROTTLED_ROUNDS: u32 = 5;

/// Split a served round into the responses we got and the requests that were dropped.
///
/// Over-limit requests are discarded by the node without any reply, so the only
/// way to tell served from dropped is to match responses back to requests. Match
/// on `start_index` rather than assuming the served set is a prefix of the round:
/// the bucket refills while the node works through our messages, so a later
/// request can be served after an earlier one was dropped.
///
/// `block_hash` is deliberately not checked here. A response carrying the right
/// `start_index` for the wrong block still has to prove itself against the
/// header's `output_root` in `verify_utxo_batch`, and duplicating that check with
/// weaker information would only add a way to reject honest data.
fn partition_round(
    reqs: &[GetMwebUtxos],
    responses: Vec<MwebUtxos>,
) -> Result<(Vec<MwebUtxos>, Vec<GetMwebUtxos>), Error> {
    let mut slots: Vec<Option<MwebUtxos>> = (0..reqs.len()).map(|_| None).collect();
    let mut by_start: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, req) in reqs.iter().enumerate() {
        // A schedule chunk starts at a distinct leaf, so a duplicate here would
        // be our own bug; keep the first so matching stays deterministic.
        by_start.entry(req.start_index).or_insert(i);
    }

    for resp in responses {
        let Some(&i) = by_start.get(&resp.start_index) else {
            return Err(Error::protocol(alloc::format!(
                "mwebutxos for unrequested start_index {}",
                resp.start_index
            )));
        };
        if slots.get(i).map(Option::is_some).unwrap_or(false) {
            return Err(Error::protocol(alloc::format!(
                "duplicate mwebutxos for start_index {}",
                resp.start_index
            )));
        }
        if let Some(slot) = slots.get_mut(i) {
            *slot = Some(resp);
        }
    }

    let mut served = Vec::new();
    let mut unserved = Vec::new();
    for (i, slot) in slots.into_iter().enumerate() {
        match (slot, reqs.get(i)) {
            (Some(batch), _) => served.push(batch),
            (None, Some(req)) => unserved.push(req.clone()),
            (None, None) => {}
        }
    }
    Ok((served, unserved))
}

/// Outcome of [`TcpMwebPeer::broadcast_tx`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastAck {
    /// The peer served the tx back via `getdata` — it was accepted to the
    /// mempool and entered the peer's relay set.
    Confirmed,
    /// The peer processed the `tx` message without erroring, but acceptance
    /// could not be confirmed before the polling deadline. The tx may still
    /// propagate; callers should treat this as an optimistic success.
    Sent,
}

/// TCP peer implementing [`MwebUtxoSource`].
pub struct TcpMwebPeer {
    stream: TcpStream,
    magic: Magic,
    /// Peer address for reconnect (host:port form).
    addr: String,
    network: Network,
    /// Requests to put in flight per serve round, shrunk when the peer throttles.
    ///
    /// Core's bucket is node-wide precisely so reconnecting cannot reset it
    /// (`f24dec1`), so this survives [`TcpMwebPeer::reconnect`] too — dropping it
    /// there would just relearn the same limit from scratch every reconnect.
    serve_window: usize,
}

impl TcpMwebPeer {
    /// Connect and complete version/verack handshake.
    pub fn connect(addr: impl ToSocketAddrs, network: Network) -> Result<Self, Error> {
        let sock = addr
            .to_socket_addrs()
            .map_err(|e| Error::Crypto(alloc::format!("resolve: {e}")))?
            .next()
            .ok_or_else(|| Error::Crypto("no address resolved".into()))?;
        Self::connect_sock(sock, sock.to_string(), network)
    }

    /// Peer address string used for reconnect / [`crate::mweb_sync::PeerPool`] bans.
    pub fn addr_string(&self) -> &str {
        &self.addr
    }

    /// Parsed socket address when `addr` is `host:port` form.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        self.addr.parse().ok()
    }

    fn connect_sock(
        sock: std::net::SocketAddr,
        addr_str: String,
        network: Network,
    ) -> Result<Self, Error> {
        let stream = TcpStream::connect(sock)
            .map_err(|e| Error::Crypto(alloc::format!("tcp connect: {e}")))?;
        // Long UTXO syncs need generous timeouts (litecoind may stall under load).
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(180)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(60)))
            .ok();
        let magic = network.magic();
        let mut peer = Self {
            stream,
            magic,
            addr: addr_str,
            network,
            serve_window: MWEB_SERVE_BURST,
        };
        peer.handshake()?;
        Ok(peer)
    }

    /// Drop the socket and handshake again (same address).
    pub fn reconnect(&mut self) -> Result<(), Error> {
        let sock = self
            .addr
            .to_socket_addrs()
            .map_err(|e| Error::Crypto(alloc::format!("resolve: {e}")))?
            .next()
            .ok_or_else(|| Error::Crypto("no address resolved".into()))?;
        let mut fresh = Self::connect_sock(sock, self.addr.clone(), self.network)?;
        fresh.serve_window = self.serve_window;
        *self = fresh;
        Ok(())
    }

    /// Broadcast a transaction and poll the peer for mempool acceptance.
    ///
    /// Designed for pure MWEB transactions (MWEB→MWEB sends and peg-outs),
    /// which Electrum servers cannot relay. Works as follows:
    ///
    /// 1. Send the unsolicited `tx` message (Core validates those regardless of a prior `inv`). The
    ///    litecoin consensus encoding carries the MWEB body (segwit flag bit `0x08`).
    /// 2. `ping`/`pong` flush: litecoind processes a peer's messages in order, so the pong proves
    ///    the tx was fully processed.
    /// 3. Poll `getdata` for the tx. Core withholds *fresh* mempool txs from `getdata` replies for
    ///    privacy (`UNCONDITIONAL_RELAY_DELAY`), but serves them from its relay map as soon as it
    ///    announces them to other peers (typically 5–15s), and it always answers a tx `getdata`
    ///    promptly with either `tx` or `notfound`.
    ///
    /// Persistent `notfound` until the deadline yields [`BroadcastAck::Sent`]
    /// (not an error): a node with slow trickle timing or no peers to
    /// announce to looks identical to a rejected tx from here.
    pub fn broadcast_tx(&mut self, tx: &bitcoin::Transaction) -> Result<BroadcastAck, Error> {
        let inv = tx_inventory(tx)?;
        self.send(NetworkMessage::Tx(tx.clone()))?;

        let nonce = ping_nonce();
        self.send(NetworkMessage::Ping(nonce))?;
        self.wait_pong(nonce)?;

        const POLL_ATTEMPTS: u32 = 6;
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
        for attempt in 0..POLL_ATTEMPTS {
            self.send(NetworkMessage::GetData(vec![inv]))?;
            let mut served = None;
            for _ in 0..64 {
                let msg = self.recv()?;
                match msg.payload() {
                    NetworkMessage::Tx(_) => {
                        served = Some(true);
                        break;
                    }
                    NetworkMessage::NotFound(_) => {
                        served = Some(false);
                        break;
                    }
                    NetworkMessage::Ping(n) => self.send(NetworkMessage::Pong(*n))?,
                    _ => {}
                }
            }
            match served {
                Some(true) => return Ok(BroadcastAck::Confirmed),
                Some(false) | None => {
                    if attempt + 1 < POLL_ATTEMPTS {
                        std::thread::sleep(POLL_INTERVAL);
                    }
                }
            }
        }
        Ok(BroadcastAck::Sent)
    }

    fn wait_pong(&mut self, nonce: u64) -> Result<(), Error> {
        for _ in 0..64 {
            let msg = self.recv()?;
            match msg.payload() {
                NetworkMessage::Pong(n) if *n == nonce => return Ok(()),
                NetworkMessage::Ping(n) => self.send(NetworkMessage::Pong(*n))?,
                _ => {}
            }
        }
        Err(Error::Crypto("p2p: no pong after tx broadcast".into()))
    }

    /// Send a `ping` and read until its `pong`, collecting every `want` payload seen.
    ///
    /// This is what turns a silent drop into an observable event. litecoind
    /// processes one peer's messages strictly in order, so by the time it writes
    /// the `pong` it has already decided the fate of every request queued ahead of
    /// it. Whatever has not arrived was dropped, not delayed — no timeout needed,
    /// and no ambiguity with a merely slow node.
    fn collect_until_pong(
        &mut self,
        want: &str,
        max_payloads: usize,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let nonce = ping_nonce();
        self.send(NetworkMessage::Ping(nonce))?;

        // Budget for the payloads themselves plus unrelated traffic (addr, inv,
        // feefilter, the peer's own pings) interleaved with them.
        let budget = max_payloads.saturating_mul(2).saturating_add(64);
        let deadline = std::time::Instant::now() + RECV_UNTIL_DEADLINE;
        let mut out: Vec<Vec<u8>> = Vec::new();

        for _ in 0..budget {
            if std::time::Instant::now() >= deadline {
                return Err(Error::transport(alloc::format!(
                    "p2p: timed out collecting {want} (deadline exceeded)"
                )));
            }
            let msg = self.recv()?;
            let cmd = msg.command().to_string();
            match msg.payload() {
                NetworkMessage::Pong(n) if *n == nonce => return Ok(out),
                NetworkMessage::Ping(n) => self.send(NetworkMessage::Pong(*n))?,
                NetworkMessage::NotFound(inv) => {
                    return Err(Error::protocol(alloc::format!(
                        "p2p: notfound while collecting {want}: {inv:?}"
                    )))
                }
                NetworkMessage::Unknown { command, payload }
                    if command.as_ref() == want || cmd == want =>
                {
                    if out.len() >= max_payloads {
                        return Err(Error::protocol(alloc::format!(
                            "p2p: peer sent more than {max_payloads} {want} messages in one round"
                        )));
                    }
                    out.push(payload.clone());
                }
                other => {
                    let _ = other;
                }
            }
        }
        Err(Error::transport(alloc::format!(
            "p2p: no pong while collecting {want} within {budget} messages"
        )))
    }

    /// Issue one round of `getmwebutxos` and return only the batches actually served.
    ///
    /// A short return is normal, not an error: it means the peer's serving bucket
    /// ran dry partway through. The caller re-issues what is missing.
    fn serve_round(&mut self, reqs: &[GetMwebUtxos]) -> Result<Vec<MwebUtxos>, Error> {
        for req in reqs {
            let payload = serialize(req);
            self.send_cmd("getmwebutxos", &payload)?;
        }
        let payloads = self.collect_until_pong("mwebutxos", reqs.len())?;
        let mut out = Vec::with_capacity(payloads.len());
        for payload in payloads {
            let mut cursor = std::io::Cursor::new(payload);
            out.push(
                MwebUtxos::consensus_decode(&mut cursor)
                    .map_err(|e| Error::protocol(alloc::format!("mwebutxos decode: {e}")))?,
            );
        }
        Ok(out)
    }

    fn is_transient(err: &Error) -> bool {
        let msg = alloc::format!("{err}");
        msg.contains("p2p read")
            || msg.contains("p2p write")
            || msg.contains("timed out")
            || msg.contains("Connection reset")
            || msg.contains("Broken pipe")
            || msg.contains("connection abort")
            || msg.contains("NotConnected")
    }

    fn with_reconnect<T>(
        &mut self,
        mut op: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        // Retry briefly to ride out a single dropped socket, then give up: sync
        // progress is checkpointed (utxo cursor / differential state), the peer
        // pool rotates on failure, and callers re-run sync shortly after. A dead
        // or misbehaving peer must not stall the caller for minutes.
        const MAX_ATTEMPTS: u32 = 4;
        let mut attempt = 0u32;
        loop {
            match op(self) {
                Ok(v) => return Ok(v),
                Err(e) if Self::is_transient(&e) && attempt + 1 < MAX_ATTEMPTS => {
                    attempt += 1;
                    let sleep_ms = (500u64 * (1u64 << attempt.min(6))).min(2_000);
                    #[cfg(feature = "std")]
                    {
                        eprintln!(
                            "warn: P2P error ({e}); reconnecting to {} in {sleep_ms}ms (attempt {attempt}/{})…",
                            self.addr,
                            MAX_ATTEMPTS - 1
                        );
                        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                    }
                    if let Err(re) = self.reconnect() {
                        #[cfg(feature = "std")]
                        eprintln!("warn: reconnect failed ({re}); will retry…");
                        // Count this toward attempts; loop will retry op (which fails
                        // fast on a dead stream) or succeed after a later reconnect.
                        continue;
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn handshake(&mut self) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        // NODE_NETWORK | NODE_WITNESS | NODE_MWEB_LIGHT_CLIENT (1<<23).
        let services = ServiceFlags::from(
            u64::from(ServiceFlags::NETWORK) | u64::from(ServiceFlags::WITNESS) | (1u64 << 23),
        );
        let version = VersionMessage {
            version: 70017,
            services,
            timestamp: now,
            receiver: Address::new(&([0, 0, 0, 0], 0).into(), ServiceFlags::NONE),
            sender: Address::new(&([0, 0, 0, 0], 0).into(), services),
            nonce: 0,
            user_agent: "/bdk_mweb:0.1.0/".into(),
            start_height: 0,
            relay: true,
        };
        self.send(NetworkMessage::Version(version))?;
        let mut saw_version = false;
        let mut saw_verack = false;
        for _ in 0..16 {
            let msg = self.recv()?;
            match msg.payload() {
                NetworkMessage::Version(_) => {
                    self.send(NetworkMessage::Verack)?;
                    saw_version = true;
                }
                NetworkMessage::Verack => {
                    saw_verack = true;
                }
                NetworkMessage::Ping(nonce) => {
                    self.send(NetworkMessage::Pong(*nonce))?;
                }
                _ => {}
            }
            if saw_version && saw_verack {
                break;
            }
        }
        if !saw_version || !saw_verack {
            return Err(Error::protocol("p2p handshake: incomplete version/verack"));
        }
        Ok(())
    }

    fn send(&mut self, payload: NetworkMessage) -> Result<(), Error> {
        let raw = RawNetworkMessage::new(self.magic, payload);
        let bytes = serialize(&raw);
        self.stream
            .write_all(&bytes)
            .map_err(|e| Error::transport(alloc::format!("p2p write: {e}")))?;
        Ok(())
    }

    fn send_cmd(&mut self, command: &str, payload: &[u8]) -> Result<(), Error> {
        // Do not use `NetworkMessage::Unknown`: `Vec<u8>` consensus-encoding prefixes a
        // CompactSize length, which corrupts litecoind's message body. Write the P2P
        // header + raw payload ourselves.
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::{sha256d, Hash};
        let cmd = bitcoin::p2p::message::CommandString::try_from(command)
            .map_err(|_| Error::Crypto("invalid command string".into()))?;
        let mut msg = Vec::with_capacity(24 + payload.len());
        self.magic
            .consensus_encode(&mut msg)
            .map_err(|e| Error::Crypto(alloc::format!("magic encode: {e}")))?;
        cmd.consensus_encode(&mut msg)
            .map_err(|e| Error::Crypto(alloc::format!("cmd encode: {e}")))?;
        let len = payload.len() as u32;
        len.consensus_encode(&mut msg)
            .map_err(|e| Error::Crypto(alloc::format!("len encode: {e}")))?;
        let checksum = sha256d::Hash::hash(payload);
        msg.extend_from_slice(&checksum[..4]);
        msg.extend_from_slice(payload);
        self.stream
            .write_all(&msg)
            .map_err(|e| Error::transport(alloc::format!("p2p write: {e}")))?;
        Ok(())
    }

    fn recv(&mut self) -> Result<RawNetworkMessage, Error> {
        let mut header = [0u8; 24];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| Error::transport(alloc::format!("p2p read header: {e}")))?;
        // Validate magic and bound the length *before* allocating: the declared
        // length is peer-controlled, and `deserialize` only checks magic and
        // checksum after the buffer already exists.
        let len = frame_payload_len(self.magic, &header)?;
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.stream
                .read_exact(&mut payload)
                .map_err(|e| Error::transport(alloc::format!("p2p read payload: {e}")))?;
        }
        parse_frame(self.magic, &header, &payload)
    }

    fn recv_until_cmd(&mut self, want: &str) -> Result<Vec<u8>, Error> {
        // The message counter alone is not a bound on time: each `recv` can block for
        // the full socket read timeout, so 64 messages of filler can stall a single
        // call for hours. Cap wall-clock time as well.
        let deadline = std::time::Instant::now() + RECV_UNTIL_DEADLINE;
        for _ in 0..64 {
            if std::time::Instant::now() >= deadline {
                return Err(Error::transport(alloc::format!(
                    "p2p: timed out waiting for {want} (deadline exceeded)"
                )));
            }
            let msg = self.recv()?;
            let cmd = msg.command().to_string();
            match msg.payload() {
                NetworkMessage::Unknown { command, payload }
                    if command.as_ref() == want || cmd == want =>
                {
                    return Ok(payload.clone());
                }
                NetworkMessage::Ping(nonce) => {
                    self.send(NetworkMessage::Pong(*nonce))?;
                }
                NetworkMessage::NotFound(inv) => {
                    return Err(Error::protocol(alloc::format!(
                        "p2p: notfound while waiting for {want}: {inv:?}"
                    )));
                }
                // Ignore addr / feefilter / inv / etc.
                other => {
                    let _ = other;
                }
            }
        }
        Err(Error::transport(alloc::format!(
            "p2p: timed out waiting for {want}"
        )))
    }
}

/// Nonce for a flush `ping`, distinct enough to tell our pong from any other.
fn ping_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0xB40A_DCA5)
}

/// Validate a P2P message header against `magic` and return its declared payload length.
///
/// Split out from `TcpMwebPeer::recv` so the framing rules are testable and
/// fuzzable without a socket. Errors are worded "protocol violation" rather than
/// "p2p read" so they are treated as peer misbehavior (ban and rotate) instead of
/// a transient IO fault worth reconnecting for.
pub fn frame_payload_len(magic: Magic, header: &[u8; 24]) -> Result<usize, Error> {
    if header[..4] != magic.to_bytes() {
        return Err(Error::protocol("p2p protocol violation: bad network magic"));
    }
    let len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if len > MAX_P2P_PAYLOAD {
        return Err(Error::protocol(alloc::format!(
            "p2p protocol violation: payload length {len} exceeds cap {MAX_P2P_PAYLOAD}"
        )));
    }
    Ok(len)
}

/// Parse a complete P2P frame (24-byte header plus payload) into a message.
pub fn parse_frame(
    magic: Magic,
    header: &[u8; 24],
    payload: &[u8],
) -> Result<RawNetworkMessage, Error> {
    let len = frame_payload_len(magic, header)?;
    if payload.len() != len {
        return Err(Error::protocol(alloc::format!(
            "p2p protocol violation: payload is {} bytes, header declared {len}",
            payload.len()
        )));
    }
    let mut full = Vec::with_capacity(24 + payload.len());
    full.extend_from_slice(header);
    full.extend_from_slice(payload);
    deserialize(&full).map_err(|e| Error::protocol(alloc::format!("p2p decode: {e}")))
}

/// `getdata` inventory identifying `tx` for mempool polling.
///
/// Pure MWEB transactions (empty canonical vin/vout) are identified by the
/// first kernel's hash (Core `CTransaction::ComputeHash` special case), with
/// inv type `MSG_MWEB_TX`. Anything else is identified by txid.
fn tx_inventory(tx: &bitcoin::Transaction) -> Result<Inventory, Error> {
    if tx.input.is_empty() && tx.output.is_empty() {
        let kernel = tx
            .mw_tx
            .as_ref()
            .and_then(|mw| mw.body.kernels.first())
            .ok_or_else(|| Error::Crypto("broadcast: MWEB tx has no kernel".into()))?;
        return Ok(Inventory::Unknown {
            inv_type: MSG_MWEB_TX,
            hash: kernel_id(kernel),
        });
    }
    Ok(Inventory::Transaction(tx.compute_txid()))
}

#[cfg(test)]
mod frame_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn header_with(magic: Magic, len: u32) -> [u8; 24] {
        let mut h = [0u8; 24];
        h[..4].copy_from_slice(&magic.to_bytes());
        h[4..16].copy_from_slice(b"mwebleafset\0");
        h[16..20].copy_from_slice(&len.to_le_bytes());
        h
    }

    /// F-04: the declared length is peer-controlled and sizes an allocation made
    /// before any authentication, so it has to be capped up front.
    #[test]
    fn frame_rejects_oversized_payload() {
        let magic = Network::Bitcoin.magic();
        let err = frame_payload_len(magic, &header_with(magic, u32::MAX)).unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(msg.contains("exceeds cap"), "got {msg}");
        assert!(
            crate::mweb_sync::is_banworthy_peer_error(&err),
            "an oversized frame must rotate the peer, got {msg}"
        );
    }

    /// Magic is checked before allocating, not left to `deserialize` afterwards.
    #[test]
    fn frame_rejects_bad_magic() {
        let magic = Network::Bitcoin.magic();
        let wrong = Network::Regtest.magic();
        let err = frame_payload_len(magic, &header_with(wrong, 0)).unwrap_err();
        let msg = alloc::format!("{err}");
        assert!(msg.contains("bad network magic"), "got {msg}");
        assert!(crate::mweb_sync::is_banworthy_peer_error(&err));
        // Bad magic is peer misbehavior, not a transient socket fault: reconnecting
        // to the same peer would just replay it.
        assert!(!TcpMwebPeer::is_transient(&err));
    }

    #[test]
    fn frame_accepts_length_within_cap() {
        let magic = Network::Bitcoin.magic();
        assert_eq!(
            frame_payload_len(magic, &header_with(magic, 4096)).unwrap(),
            4096
        );
    }

    #[test]
    fn frame_rejects_payload_length_mismatch() {
        let magic = Network::Bitcoin.magic();
        let err = parse_frame(magic, &header_with(magic, 10), &[0u8; 3]).unwrap_err();
        assert!(alloc::format!("{err}").contains("header declared"));
    }
}

/// Rate-limit handling: response matching and the re-issue loop.
///
/// The regtest harness whitelists its node (`-whitelist=noban@127.0.0.1`), which
/// exempts it from `AllowMWEBServe` entirely, so a node-backed suite cannot reach
/// these paths by default. These drive them directly instead — no socket, and no
/// real waiting.
#[cfg(test)]
mod throttle_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::error::BanReason;
    use crate::p2p::OUTPUT_FORMAT_FULL;
    use bitcoin::hashes::Hash;

    fn hash() -> BlockHash {
        BlockHash::from_byte_array([0x42; 32])
    }

    fn req(start_index: u64) -> GetMwebUtxos {
        GetMwebUtxos {
            block_hash: hash(),
            start_index,
            num_requested: 4096,
            output_format: OUTPUT_FORMAT_FULL,
        }
    }

    fn resp(start_index: u64) -> MwebUtxos {
        MwebUtxos {
            block_hash: hash(),
            start_index,
            output_format: OUTPUT_FORMAT_FULL,
            utxos: Vec::new(),
            parent_hashes: Vec::new(),
        }
    }

    fn schedule(n: u64) -> Vec<GetMwebUtxos> {
        (0..n).map(req).collect()
    }

    #[test]
    fn partition_round_takes_every_response_when_nothing_is_dropped() {
        let reqs = schedule(4);
        let responses = vec![resp(0), resp(1), resp(2), resp(3)];
        let (served, unserved) = partition_round(&reqs, responses).unwrap();
        assert_eq!(
            served.iter().map(|b| b.start_index).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert!(unserved.is_empty());
    }

    /// The bucket refills while the node works through a window, so a later request
    /// can be served after an earlier one was dropped. Matching must not assume the
    /// served set is a prefix.
    #[test]
    fn partition_round_handles_non_contiguous_drops() {
        let reqs = schedule(5);
        // Deliberately out of order as well, to pin that ordering comes from the
        // schedule rather than from arrival.
        let responses = vec![resp(3), resp(0)];
        let (served, unserved) = partition_round(&reqs, responses).unwrap();
        assert_eq!(
            served.iter().map(|b| b.start_index).collect::<Vec<_>>(),
            vec![0, 3]
        );
        assert_eq!(
            unserved.iter().map(|r| r.start_index).collect::<Vec<_>>(),
            vec![1, 2, 4]
        );
    }

    #[test]
    fn partition_round_rejects_a_response_we_did_not_ask_for() {
        let reqs = schedule(3);
        let err = partition_round(&reqs, vec![resp(99)]).unwrap_err();
        assert_eq!(err.ban_reason(), Some(BanReason::ProtocolViolation));
        assert!(alloc::format!("{err}").contains("unrequested start_index 99"));
    }

    #[test]
    fn partition_round_rejects_a_duplicated_response() {
        let reqs = schedule(3);
        let err = partition_round(&reqs, vec![resp(1), resp(1)]).unwrap_err();
        assert_eq!(err.ban_reason(), Some(BanReason::ProtocolViolation));
        assert!(alloc::format!("{err}").contains("duplicate"));
    }

    /// A peer that drops nothing — a whitelisted node, or any node before
    /// 0.21.5.6 — must be driven at full width with no waiting at all.
    #[test]
    fn unthrottled_peer_is_served_in_one_round_without_waiting() {
        let reqs = schedule(20);
        let mut window = MWEB_SERVE_BURST;
        let mut rounds = 0usize;
        let mut delivered = Vec::new();
        let mut sleeps: Vec<std::time::Duration> = Vec::new();

        drive_serve_rounds(
            &reqs,
            &mut window,
            |round| {
                rounds += 1;
                Ok(round.iter().map(|r| resp(r.start_index)).collect())
            },
            &mut |batch| {
                delivered.push(batch.start_index);
                Ok(())
            },
            |d| sleeps.push(d),
        )
        .unwrap();

        assert_eq!(rounds, 1, "a peer serving everything needs one round");
        assert_eq!(delivered, (0..20).collect::<Vec<_>>());
        assert!(sleeps.is_empty(), "no throttle means no waiting");
    }

    /// The headline case: a node-wide bucket with a burst and a slow refill. Every
    /// batch must arrive exactly once and in order, with dropped requests re-issued
    /// rather than lost.
    #[test]
    fn throttled_peer_is_fully_downloaded_by_re_issuing_dropped_requests() {
        let reqs = schedule(86); // ~mainnet at a 4096-wide batch
        let mut window = MWEB_SERVE_BURST;
        let mut tokens = MWEB_SERVE_BURST;
        let mut delivered = Vec::new();
        let mut sleeps: Vec<std::time::Duration> = Vec::new();

        drive_serve_rounds(
            &reqs,
            &mut window,
            |round| {
                // Serve while tokens last, silently drop the rest, then refill by
                // one so the next round can make progress.
                let served: Vec<MwebUtxos> = round
                    .iter()
                    .take(tokens)
                    .map(|r| resp(r.start_index))
                    .collect();
                tokens = tokens.saturating_sub(served.len()) + 1;
                Ok(served)
            },
            &mut |batch| {
                delivered.push(batch.start_index);
                Ok(())
            },
            |d| sleeps.push(d),
        )
        .unwrap();

        assert_eq!(
            delivered,
            (0..86).collect::<Vec<_>>(),
            "every request must be delivered exactly once, in schedule order"
        );
        assert!(!sleeps.is_empty(), "a throttled sync must pace itself");
    }

    #[test]
    fn peer_that_serves_nothing_gives_up_instead_of_spinning() {
        let reqs = schedule(10);
        let mut window = MWEB_SERVE_BURST;
        let mut rounds = 0usize;
        let mut delivered = Vec::new();
        let mut sleeps: Vec<std::time::Duration> = Vec::new();

        let err = drive_serve_rounds(
            &reqs,
            &mut window,
            |_round| {
                rounds += 1;
                Ok(Vec::new())
            },
            &mut |batch| {
                delivered.push(batch.start_index);
                Ok(())
            },
            |d| sleeps.push(d),
        )
        .unwrap_err();

        assert_eq!(rounds as u32, MAX_CONSECUTIVE_THROTTLED_ROUNDS);
        assert!(delivered.is_empty());
        assert_eq!(err.ban_reason(), Some(BanReason::Throttled));
        // The operator's likeliest fix has to be in the message they will see.
        assert!(alloc::format!("{err}").contains("-whitelist"));
    }

    /// The window follows what the peer actually supplies: narrow while it is
    /// throttling, wide again once it is not, and never past Core's burst.
    #[test]
    fn window_tracks_the_peers_observed_allowance() {
        let reqs = schedule(12);
        let mut window = MWEB_SERVE_BURST;
        let mut widths = Vec::new();
        let mut round = 0usize;
        let mut delivered = Vec::new();

        drive_serve_rounds(
            &reqs,
            &mut window,
            |batch| {
                widths.push(batch.len());
                round += 1;
                // Throttle hard for two rounds, then serve freely.
                let allowance = if round <= 2 { 2 } else { batch.len() };
                Ok(batch
                    .iter()
                    .take(allowance)
                    .map(|r| resp(r.start_index))
                    .collect())
            },
            &mut |b| {
                delivered.push(b.start_index);
                Ok(())
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(delivered, (0..12).collect::<Vec<_>>());
        assert_eq!(widths.first().copied(), Some(12), "starts at full burst");
        assert_eq!(
            widths.get(1).copied(),
            Some(2),
            "narrows to what the peer served"
        );
        assert!(
            window <= MWEB_SERVE_BURST,
            "window must never exceed Core's burst, got {window}"
        );
    }

    /// A throttle is peer-attributable but must not evict the peer: banning a node
    /// for being busy would, in a single-peer deployment, ban the only node there is.
    #[test]
    fn throttle_is_attributable_but_not_banworthy() {
        let err = throttled_error(7);
        assert_eq!(err.ban_reason(), Some(BanReason::Throttled));
        assert!(!crate::mweb_sync::is_banworthy_peer_error(&err));
    }
}

#[cfg(test)]
mod broadcast_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Round-trip a `MSG_MWEB_TX` getdata against a live node: an unknown hash
    /// must come back as `notfound`, proving the inv encoding is accepted and
    /// the reply handling in `broadcast_tx`'s poll loop works.
    ///
    /// Requires litecoind on mainnet: run with
    /// `cargo test -p bdk_mweb --features std,lip0006 -- --ignored probe_mweb_tx_getdata`
    #[test]
    #[ignore = "requires local litecoind at 127.0.0.1:9333"]
    fn probe_mweb_tx_getdata_notfound() {
        let mut peer =
            TcpMwebPeer::connect("127.0.0.1:9333", bitcoin::Network::Bitcoin).expect("connect");
        let inv = Inventory::Unknown {
            inv_type: MSG_MWEB_TX,
            hash: [0xAB; 32],
        };
        peer.send(NetworkMessage::GetData(vec![inv]))
            .expect("getdata");
        for _ in 0..64 {
            let msg = peer.recv().expect("recv");
            match msg.payload() {
                NetworkMessage::NotFound(items) => {
                    assert_eq!(items.len(), 1);
                    return;
                }
                NetworkMessage::Tx(_) => panic!("node served a tx for a random hash"),
                NetworkMessage::Ping(n) => peer.send(NetworkMessage::Pong(*n)).expect("pong"),
                _ => {}
            }
        }
        panic!("no notfound reply for MSG_MWEB_TX getdata");
    }

    /// F-01f: the gate for making [`crate::lip0006::VerifyMode::Anchored`] the
    /// default.
    ///
    /// `tests/mweb_anchoring.rs` proves the anchoring chain holds on regtest.
    /// Regtest is not mainnet: the chain there is a handful of blocks with a
    /// two-transaction merkle tree, and litecoind takes different code paths
    /// once a block has real depth and a real transaction count. This probe
    /// asks a live mainnet node for a header at a recent height and runs the
    /// full [`MwebHeaderMsg::verify_anchored`] against it.
    ///
    /// Run and passed on 2026-08-01 against litecoind 0.21.5.5, mainnet block
    /// 3,152,700 — the gate for the `VerifyMode::Anchored` default is satisfied;
    /// the result is recorded under F-01f in `docs/SECURITY_PLAN.md`. Re-run
    /// (and re-record) if litecoind changes how it serves `mwebheader`.
    ///
    /// ```text
    /// LITECOIN_P2P=127.0.0.1:9333 LITECOIN_ANCHOR_BLOCK=<hash from a trusted source> \
    ///   cargo test -p bdk_mweb --features std,lip0006 -- --ignored probe_mainnet_anchor
    /// ```
    ///
    /// `LITECOIN_ANCHOR_BLOCK` must come from somewhere other than this peer —
    /// your own node's RPC, or a block explorer. Taking it from the peer would
    /// make the probe as circular as the thing it exists to fix.
    #[test]
    #[ignore = "requires a live mainnet litecoind and a trusted block hash"]
    fn probe_mainnet_anchor() {
        use crate::lip0006::MwebUtxoSource;
        use core::str::FromStr;

        let addr = std::env::var("LITECOIN_P2P").unwrap_or_else(|_| "127.0.0.1:9333".to_string());
        let block_hash = std::env::var("LITECOIN_ANCHOR_BLOCK").expect(
            "set LITECOIN_ANCHOR_BLOCK to a mainnet block hash from a source other than \
             this peer",
        );
        let block_hash = BlockHash::from_str(block_hash.trim()).expect("valid block hash");

        let mut peer = TcpMwebPeer::connect(&addr, bitcoin::Network::Bitcoin)
            .expect("connect to mainnet peer");
        let msg = peer
            .get_header(block_hash)
            .expect("mwebheader from mainnet");

        msg.verify_anchored(block_hash).unwrap_or_else(|e| {
            panic!(
                "mainnet mwebheader for {block_hash} failed verify_anchored: {e}. \
                 VerifyMode::Anchored must not become the default until this passes."
            )
        });

        // A peer that echoed our request back would pass the check above only if
        // it also produced a valid merkle proof, which it cannot forge. Confirm
        // the negative case too, so a `verify_anchored` that had degenerated
        // into `Ok(())` would fail this probe rather than bless the flip.
        let wrong = {
            use bitcoin::hashes::Hash;
            BlockHash::from_byte_array([0x11; 32])
        };
        assert!(
            msg.verify_anchored(wrong).is_err(),
            "verify_anchored accepted a header for an unrelated block"
        );
    }
}

impl MwebUtxoSource for TcpMwebPeer {
    fn get_header(&mut self, block_hash: BlockHash) -> Result<MwebHeaderMsg, Error> {
        self.with_reconnect(|this| {
            let inv: Vec<Inventory> = vec![mweb_inv(MSG_MWEB_HEADER, block_hash)];
            this.send(NetworkMessage::GetData(inv))?;
            let payload = this.recv_until_cmd("mwebheader")?;
            let mut cursor = std::io::Cursor::new(payload);
            MwebHeaderMsg::consensus_decode(&mut cursor)
                .map_err(|e| Error::protocol(alloc::format!("mwebheader decode: {e}")))
        })
    }

    /// Fetch the leafset, retrying if the peer's serving budget dropped the request.
    ///
    /// `getmwebleafset` goes through the same `AllowMWEBServe` bucket as
    /// `getmwebutxos`, so it can be silently discarded too. There is only one of
    /// these per pass and it gates everything after it, so a drop here would stall
    /// the whole sync on a read timeout.
    fn get_leafset(&mut self, block_hash: BlockHash) -> Result<MwebLeafset, Error> {
        self.with_reconnect(|this| {
            for _ in 0..MAX_CONSECUTIVE_THROTTLED_ROUNDS {
                let inv: Vec<Inventory> = vec![mweb_inv(MSG_MWEB_LEAFSET, block_hash)];
                this.send(NetworkMessage::GetData(inv))?;
                let mut payloads = this.collect_until_pong("mwebleafset", 1)?;
                if let Some(payload) = payloads.pop() {
                    let mut cursor = std::io::Cursor::new(payload);
                    return MwebLeafset::consensus_decode(&mut cursor)
                        .map_err(|e| Error::protocol(alloc::format!("mwebleafset decode: {e}")));
                }
                std::thread::sleep(THROTTLE_REFILL_WAIT);
            }
            Err(Error::throttled(alloc::format!(
                "peer dropped {MAX_CONSECUTIVE_THROTTLED_ROUNDS} getmwebleafset requests; \
                 litecoind 0.21.5.6+ rate-limits MWEB serving node-wide, so run the node with \
                 `-whitelist=noban@<client>` or use a less contended peer"
            )))
        })
    }

    fn get_utxos(&mut self, req: GetMwebUtxos) -> Result<MwebUtxos, Error> {
        self.with_reconnect(|this| {
            let round = [req.clone()];
            for _ in 0..MAX_CONSECUTIVE_THROTTLED_ROUNDS {
                let responses = this.serve_round(&round)?;
                let (mut served, _) = partition_round(&round, responses)?;
                if let Some(batch) = served.pop() {
                    return Ok(batch);
                }
                std::thread::sleep(THROTTLE_REFILL_WAIT);
            }
            Err(throttled_error(1))
        })
    }

    /// Pipelined download that survives the peer's serving rate limit.
    ///
    /// litecoind processes a peer's messages in order, so a window of requests in
    /// flight lets it build batch `k + 1` while we verify and scan batch `k`. Since
    /// 0.21.5.6 it also silently drops requests over its serving budget, so each
    /// window is flushed with a `ping`: whatever has not arrived by the `pong` was
    /// dropped and is re-issued in the next round. The window then tracks what the
    /// peer actually served, which converges on its real allowance without us
    /// having to guess it — and stays wide open on a whitelisted or pre-0.21.5.6
    /// node, where nothing is ever dropped.
    fn get_utxos_pipelined(
        &mut self,
        reqs: &[GetMwebUtxos],
        on_batch: &mut dyn FnMut(MwebUtxos) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut window = self.serve_window;
        let outcome = drive_serve_rounds(
            reqs,
            &mut window,
            |round| self.serve_round(round),
            on_batch,
            std::thread::sleep,
        );
        self.serve_window = window;
        match outcome {
            Ok(()) => Ok(()),
            Err(e) => {
                // Responses for requests we never read may still be queued on the
                // socket; reconnect so later sequential requests don't consume them.
                let _ = self.reconnect();
                Err(e)
            }
        }
    }
}

/// The re-issue loop, with the socket and the clock factored out.
///
/// Split from [`TcpMwebPeer::get_utxos_pipelined`] so the window and stall
/// accounting can be tested against a peer that drops whatever a test wants it
/// to, without a socket and without spending the wall-clock time (cf. the same
/// treatment given to `parse_frame`).
///
/// Termination: every iteration either delivers at least one batch or increments
/// `stalled_rounds`, which is capped, so the loop cannot spin against a peer that
/// accepts requests and answers none.
fn drive_serve_rounds<R, W>(
    reqs: &[GetMwebUtxos],
    window: &mut usize,
    mut round_fn: R,
    on_batch: &mut dyn FnMut(MwebUtxos) -> Result<(), Error>,
    mut wait: W,
) -> Result<(), Error>
where
    R: FnMut(&[GetMwebUtxos]) -> Result<Vec<MwebUtxos>, Error>,
    W: FnMut(std::time::Duration),
{
    let mut pending: Vec<GetMwebUtxos> = reqs.to_vec();
    let mut stalled_rounds = 0u32;

    while !pending.is_empty() {
        let width = (*window).clamp(1, MWEB_SERVE_BURST).min(pending.len());
        let round: Vec<GetMwebUtxos> = pending.iter().take(width).cloned().collect();
        let rest: Vec<GetMwebUtxos> = pending.iter().skip(width).cloned().collect();

        let responses = round_fn(&round)?;
        let (served, unserved) = partition_round(&round, responses)?;
        let served_count = served.len();
        for batch in served {
            on_batch(batch)?;
        }

        if unserved.is_empty() {
            stalled_rounds = 0;
            // Widen again after a clean round: a throttle early in a sync should
            // not pin the rest of it narrow.
            *window = (*window).saturating_mul(2).clamp(1, MWEB_SERVE_BURST);
            pending = rest;
            continue;
        }

        if served_count == 0 {
            stalled_rounds += 1;
            if stalled_rounds >= MAX_CONSECUTIVE_THROTTLED_ROUNDS {
                return Err(throttled_error(unserved.len()));
            }
        } else {
            stalled_rounds = 0;
        }

        // Ask next time for what the peer proved it can supply, and give the bucket
        // long enough to refill that many tokens before asking again.
        *window = served_count.max(1);
        let mut next = unserved;
        next.extend(rest);
        pending = next;

        #[cfg(feature = "std")]
        eprintln!(
            "  peer is rate-limiting mweb serving ({served_count}/{width} served); \
             {} request(s) to re-issue with window {window}",
            pending.len()
        );
        wait(THROTTLE_REFILL_WAIT * (*window) as u32);
    }
    Ok(())
}

/// Error for a peer that accepted our requests and served none of them.
///
/// Worded to point at the fix, because the usual cause is not an attack: the
/// operator's own archive node is missing `-whitelist`, and the node-wide bucket
/// is being shared with every other light client pointed at it.
fn throttled_error(outstanding: usize) -> Error {
    Error::throttled(alloc::format!(
        "peer served none of {outstanding} outstanding getmwebutxos request(s) across \
         {MAX_CONSECUTIVE_THROTTLED_ROUNDS} rounds; litecoind 0.21.5.6+ rate-limits MWEB \
         serving node-wide, so run the node with `-whitelist=noban@<client>` or use a \
         less contended peer"
    ))
}
