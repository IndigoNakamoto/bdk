//! Thin TCP client for LIP-0006 messages against litecoind.
//!
//! Performs a minimal `version` / `verack` handshake, then exchanges
//! `getdata`(MSG_MWEB_LEAFSET) and `getmwebutxos` as raw unknown payloads.
//! Intended for regtest / trusted peers; not a full Bitcoin P2P stack.

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
use crate::p2p::{mweb_inv, GetMwebUtxos, MwebLeafset, MwebUtxos, MSG_MWEB_LEAFSET};

/// TCP peer implementing [`MwebUtxoSource`].
pub struct TcpMwebPeer {
    stream: TcpStream,
    magic: Magic,
}

impl TcpMwebPeer {
    /// Connect and complete version/verack handshake.
    pub fn connect(addr: impl ToSocketAddrs, network: Network) -> Result<Self, Error> {
        let stream = TcpStream::connect(addr)
            .map_err(|e| Error::Crypto(alloc::format!("tcp connect: {e}")))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        let magic = network.magic();
        let mut peer = Self { stream, magic };
        peer.handshake()?;
        Ok(peer)
    }

    fn handshake(&mut self) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let version = VersionMessage {
            version: 70016,
            services: ServiceFlags::NONE,
            timestamp: now,
            receiver: Address::new(&([0, 0, 0, 0], 0).into(), ServiceFlags::NONE),
            sender: Address::new(&([0, 0, 0, 0], 0).into(), ServiceFlags::NONE),
            nonce: 0,
            user_agent: "/bdk_mweb:0.1.0/".into(),
            start_height: 0,
            relay: false,
        };
        self.send(NetworkMessage::Version(version))?;
        let mut saw_verack = false;
        for _ in 0..8 {
            let msg = self.recv()?;
            match msg.payload() {
                NetworkMessage::Version(_) => {
                    self.send(NetworkMessage::Verack)?;
                }
                NetworkMessage::Verack => {
                    saw_verack = true;
                    break;
                }
                _ => {}
            }
        }
        if !saw_verack {
            return Err(Error::Crypto("p2p handshake: no verack".into()));
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
        let cmd = bitcoin::p2p::message::CommandString::try_from(command)
            .map_err(|_| Error::Crypto("invalid command string".into()))?;
        self.send(NetworkMessage::Unknown {
            command: cmd,
            payload: payload.to_vec(),
        })
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
        for _ in 0..32 {
            let msg = self.recv()?;
            match msg.payload() {
                NetworkMessage::Unknown { command, payload } if command.as_ref() == want => {
                    return Ok(payload.clone());
                }
                NetworkMessage::Ping(nonce) => {
                    self.send(NetworkMessage::Pong(*nonce))?;
                }
                _ => {}
            }
        }
        Err(Error::Crypto(alloc::format!(
            "p2p: timed out waiting for {want}"
        )))
    }
}

impl MwebUtxoSource for TcpMwebPeer {
    fn get_leafset(&mut self, block_hash: BlockHash) -> Result<MwebLeafset, Error> {
        let inv: Vec<Inventory> = vec![mweb_inv(MSG_MWEB_LEAFSET, block_hash)];
        self.send(NetworkMessage::GetData(inv))?;
        let payload = self.recv_until_cmd("mwebleafset")?;
        let mut cursor = std::io::Cursor::new(payload);
        MwebLeafset::consensus_decode(&mut cursor)
            .map_err(|e| Error::Crypto(alloc::format!("mwebleafset decode: {e}")))
    }

    fn get_utxos(&mut self, req: GetMwebUtxos) -> Result<MwebUtxos, Error> {
        let payload = serialize(&req);
        self.send_cmd("getmwebutxos", &payload)?;
        let resp = self.recv_until_cmd("mwebutxos")?;
        let mut cursor = std::io::Cursor::new(resp);
        MwebUtxos::consensus_decode(&mut cursor)
            .map_err(|e| Error::Crypto(alloc::format!("mwebutxos decode: {e}")))
    }
}
