//! LIP-0006 MWEB P2P message codecs.
//!
//! These types are not yet in the published `litecoin` crate `p2p` module. Wire them
//! here and re-export when upstream adds them.
//!
//! **Note:** `mwebutxos` follows litecoind's on-wire layout (`block_hash`, `start_index`,
//! …), which differs slightly from the LIP-0006 table (litecoind is authoritative for P2P).

use alloc::vec::Vec;

use bitcoin::blockdata::block::{BlockHash, MwebBlockHeader};
use bitcoin::blockdata::mimblewimble::Output;
use bitcoin::consensus::encode::{self, Decodable, Encodable, VarInt};
use bitcoin::hashes::Hash;
use bitcoin::io::{self, Read, Write};
use bitcoin::Transaction;
use bitcoin::MerkleBlock;

/// `getdata` inventory type for MWEB header (LIP-0006).
pub const MSG_MWEB_HEADER: u32 = 0x2000_0008;
/// `getdata` inventory type for MWEB leafset (LIP-0006).
pub const MSG_MWEB_LEAFSET: u32 = 0x2000_0009;

/// FULL_UTXO — commitment, keys, message, rangeproof, signature.
pub const OUTPUT_FORMAT_FULL: u8 = 0x00;
/// HASH_ONLY — blake3 of the UTXO.
pub const OUTPUT_FORMAT_HASH_ONLY: u8 = 0x01;
/// COMPACT_UTXO — without rangeproof (rangeproof hash provided).
pub const OUTPUT_FORMAT_COMPACT: u8 = 0x02;

/// `getmwebutxos` request (LIP-0006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetMwebUtxos {
    /// Snapshot block hash.
    pub block_hash: BlockHash,
    /// First leaf index requested.
    pub start_index: u64,
    /// Max UTXOs in this batch.
    pub num_requested: u16,
    /// Output serialization format.
    pub output_format: u8,
}

impl Encodable for GetMwebUtxos {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.block_hash.consensus_encode(w)?;
        len += VarInt(self.start_index).consensus_encode(w)?;
        // Wire format matches litecoind (uint16 little-endian, same as Bitcoin Serialize).
        len += self.num_requested.consensus_encode(w)?;
        len += self.output_format.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for GetMwebUtxos {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            block_hash: BlockHash::consensus_decode(r)?,
            start_index: VarInt::consensus_decode(r)?.0,
            num_requested: u16::consensus_decode(r)?,
            output_format: u8::consensus_decode(r)?,
        })
    }
}

/// One UTXO entry in a `mwebutxos` message (FULL_UTXO).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MwebUtxoEntry {
    /// Leaf index in the output PMMR.
    pub leaf_index: u64,
    /// Fully serialized MWEB output.
    pub output: Output,
}

/// `mwebutxos` response (FULL_UTXO path) — litecoind wire layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MwebUtxos {
    /// Snapshot block hash (echoed from the request).
    pub block_hash: BlockHash,
    /// Start index echoed from the request.
    pub start_index: u64,
    /// Serialization format of the UTXOs.
    pub output_format: u8,
    /// UTXOs in this batch.
    pub utxos: Vec<MwebUtxoEntry>,
    /// Parent hashes for output PMMR membership proofs (`proof_hashes` in Core).
    pub parent_hashes: Vec<[u8; 32]>,
}

impl Encodable for MwebUtxos {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.block_hash.consensus_encode(w)?;
        len += VarInt(self.start_index).consensus_encode(w)?;
        len += self.output_format.consensus_encode(w)?;
        len += VarInt(self.utxos.len() as u64).consensus_encode(w)?;
        for entry in &self.utxos {
            len += VarInt(entry.leaf_index).consensus_encode(w)?;
            len += entry.output.consensus_encode(w)?;
        }
        len += VarInt(self.parent_hashes.len() as u64).consensus_encode(w)?;
        for h in &self.parent_hashes {
            len += h.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for MwebUtxos {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let block_hash = BlockHash::consensus_decode(r)?;
        let start_index = VarInt::consensus_decode(r)?.0;
        let output_format = u8::consensus_decode(r)?;
        let n = VarInt::consensus_decode(r)?.0 as usize;
        let mut utxos = Vec::with_capacity(n);
        for _ in 0..n {
            if output_format != OUTPUT_FORMAT_FULL {
                return Err(encode::Error::ParseFailed(
                    "bdk_mweb only decodes FULL_UTXO (0x00) mwebutxos",
                ));
            }
            let leaf_index = VarInt::consensus_decode(r)?.0;
            let output = Output::consensus_decode(r)?;
            utxos.push(MwebUtxoEntry { leaf_index, output });
        }
        let nh = VarInt::consensus_decode(r)?.0 as usize;
        let mut parent_hashes = Vec::with_capacity(nh);
        for _ in 0..nh {
            parent_hashes.push(<[u8; 32]>::consensus_decode(r)?);
        }
        Ok(Self {
            block_hash,
            start_index,
            output_format,
            utxos,
            parent_hashes,
        })
    }
}

/// `mwebheader` message (BIP37 merkle block + HogEx + MWEB header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MwebHeaderMsg {
    /// BIP37 partial merkle tree for the block (includes the HogEx txid).
    pub merkle: MerkleBlock,
    /// HogEx (Hogwarts Express) bridge transaction.
    pub hogex: Transaction,
    /// MWEB extension-block header at this tip.
    pub mweb_header: MwebBlockHeader,
}

impl Encodable for MwebHeaderMsg {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.merkle.consensus_encode(w)?;
        len += self.hogex.consensus_encode(w)?;
        len += self.mweb_header.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for MwebHeaderMsg {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Self {
            merkle: MerkleBlock::consensus_decode(r)?,
            hogex: Transaction::consensus_decode(r)?,
            mweb_header: MwebBlockHeader::consensus_decode(r)?,
        })
    }
}

/// `mwebleafset` message (LIP-0006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MwebLeafset {
    /// Block hash the leafset corresponds to.
    pub block_hash: BlockHash,
    /// Zero-padded bitset (big-endian bit order within the blob per LIP-0006).
    pub leafset: Vec<u8>,
}

impl Encodable for MwebLeafset {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.block_hash.consensus_encode(w)?;
        len += VarInt(self.leafset.len() as u64).consensus_encode(w)?;
        w.write_all(&self.leafset)?;
        len += self.leafset.len();
        Ok(len)
    }
}

impl Decodable for MwebLeafset {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let block_hash = BlockHash::consensus_decode(r)?;
        let size = VarInt::consensus_decode(r)?.0 as usize;
        let mut leafset = vec![0u8; size];
        r.read_exact(&mut leafset)?;
        Ok(Self {
            block_hash,
            leafset,
        })
    }
}

impl MwebLeafset {
    /// Collect leaf indices whose bits are set.
    ///
    /// Bit `i` is bit `(7 - i % 8)` of byte `i / 8` (MSB-first within each byte).
    pub fn unspent_leaf_indices(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for (byte_i, byte) in self.leafset.iter().enumerate() {
            for bit in 0..8u64 {
                if byte & (1 << (7 - bit)) != 0 {
                    out.push(byte_i as u64 * 8 + bit);
                }
            }
        }
        out
    }

    /// Build a leafset bitset from set leaf indices (for tests / scripted peers).
    pub fn from_indices(block_hash: BlockHash, indices: &[u64]) -> Self {
        let max = indices.iter().copied().max().unwrap_or(0);
        let nbytes = (max as usize / 8) + 1;
        let mut leafset = vec![0u8; nbytes];
        for &i in indices {
            let byte_i = (i / 8) as usize;
            let bit = i % 8;
            leafset[byte_i] |= 1 << (7 - bit);
        }
        Self {
            block_hash,
            leafset,
        }
    }
}

/// Inventory item for MWEB header / leafset getdata.
pub fn mweb_inv(inv_type: u32, hash: BlockHash) -> bitcoin::p2p::message_blockdata::Inventory {
    bitcoin::p2p::message_blockdata::Inventory::Unknown {
        inv_type,
        hash: hash.to_byte_array(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::hashes::Hash;

    #[test]
    fn getmwebutxos_roundtrip() {
        let msg = GetMwebUtxos {
            block_hash: BlockHash::from_byte_array([9u8; 32]),
            start_index: 100,
            num_requested: 50,
            output_format: OUTPUT_FORMAT_FULL,
        };
        let enc = serialize(&msg);
        assert_eq!(&enc[enc.len() - 3..enc.len() - 1], &50u16.to_le_bytes());
        let dec: GetMwebUtxos = deserialize(&enc).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn leafset_indices_roundtrip() {
        let hash = BlockHash::from_byte_array([1u8; 32]);
        let ls = MwebLeafset::from_indices(hash, &[0, 1, 7, 8, 15]);
        assert_eq!(ls.unspent_leaf_indices(), vec![0, 1, 7, 8, 15]);
        let enc = serialize(&ls);
        let dec: MwebLeafset = deserialize(&enc).unwrap();
        assert_eq!(dec.unspent_leaf_indices(), vec![0, 1, 7, 8, 15]);
    }
}
