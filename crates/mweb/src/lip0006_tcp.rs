//! Thin TCP client for LIP-0006 messages against litecoind.
//!
//! Performs a minimal `version` / `verack` handshake, then exchanges
//! `getdata`(MSG_MWEB_HEADER / MSG_MWEB_LEAFSET) and `getmwebutxos` as raw
//! unknown payloads. Intended for regtest; prefer [`VerifyMode::HeaderAndPmmr`].

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
use crate::lip0006::MwebUtxoSource;
use crate::p2p::{
    mweb_inv, GetMwebUtxos, MwebHeaderMsg, MwebLeafset, MwebUtxos, MSG_MWEB_HEADER,
    MSG_MWEB_LEAFSET,
};

/// TCP peer implementing [`MwebUtxoSource`].
pub struct TcpMwebPeer {
    stream: TcpStream,
    magic: Magic,
    /// Peer address for reconnect (host:port form).
    addr: String,
    network: Network,
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
        let fresh = Self::connect_sock(sock, self.addr.clone(), self.network)?;
        *self = fresh;
        Ok(())
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
        // litecoind often drops light-client sockets under UTXO-sync load; back off
        // and keep trying rather than failing the whole multi-hour download.
        const MAX_ATTEMPTS: u32 = 12;
        let mut attempt = 0u32;
        loop {
            match op(self) {
                Ok(v) => return Ok(v),
                Err(e) if Self::is_transient(&e) && attempt + 1 < MAX_ATTEMPTS => {
                    attempt += 1;
                    let sleep_ms = (500u64 * (1u64 << attempt.min(6))).min(30_000);
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
            u64::from(ServiceFlags::NETWORK)
                | u64::from(ServiceFlags::WITNESS)
                | (1u64 << 23),
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
            return Err(Error::Crypto("p2p handshake: incomplete version/verack".into()));
        }
        Ok(())
    }

    fn send(&mut self, payload: NetworkMessage) -> Result<(), Error> {
        let raw = RawNetworkMessage::new(self.magic, payload);
        let bytes = serialize(&raw);
        self.stream
            .write_all(&bytes)
            .map_err(|e| Error::Crypto(alloc::format!("p2p write: {e}")))?;
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
            .map_err(|e| Error::Crypto(alloc::format!("p2p write: {e}")))?;
        Ok(())
    }

    fn recv(&mut self) -> Result<RawNetworkMessage, Error> {
        let mut header = [0u8; 24];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| Error::Crypto(alloc::format!("p2p read header: {e}")))?;
        let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.stream
                .read_exact(&mut payload)
                .map_err(|e| Error::Crypto(alloc::format!("p2p read payload: {e}")))?;
        }
        let mut full = Vec::with_capacity(24 + len);
        full.extend_from_slice(&header);
        full.extend_from_slice(&payload);
        deserialize(&full).map_err(|e| Error::Crypto(alloc::format!("p2p decode: {e}")))
    }

    fn recv_until_cmd(&mut self, want: &str) -> Result<Vec<u8>, Error> {
        for _ in 0..64 {
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
                    return Err(Error::Crypto(alloc::format!(
                        "p2p: notfound while waiting for {want}: {inv:?}"
                    )));
                }
                // Ignore addr / feefilter / inv / etc.
                other => {
                    let _ = other;
                }
            }
        }
        Err(Error::Crypto(alloc::format!(
            "p2p: timed out waiting for {want}"
        )))
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
                .map_err(|e| Error::Crypto(alloc::format!("mwebheader decode: {e}")))
        })
    }

    fn get_leafset(&mut self, block_hash: BlockHash) -> Result<MwebLeafset, Error> {
        self.with_reconnect(|this| {
            let inv: Vec<Inventory> = vec![mweb_inv(MSG_MWEB_LEAFSET, block_hash)];
            this.send(NetworkMessage::GetData(inv))?;
            let payload = this.recv_until_cmd("mwebleafset")?;
            let mut cursor = std::io::Cursor::new(payload);
            MwebLeafset::consensus_decode(&mut cursor)
                .map_err(|e| Error::Crypto(alloc::format!("mwebleafset decode: {e}")))
        })
    }

    fn get_utxos(&mut self, req: GetMwebUtxos) -> Result<MwebUtxos, Error> {
        self.with_reconnect(|this| {
            let payload = serialize(&req);
            this.send_cmd("getmwebutxos", &payload)?;
            let resp = this.recv_until_cmd("mwebutxos")?;
            let mut cursor = std::io::Cursor::new(resp);
            MwebUtxos::consensus_decode(&mut cursor)
                .map_err(|e| Error::Crypto(alloc::format!("mwebutxos decode: {e}")))
        })
    }
}
