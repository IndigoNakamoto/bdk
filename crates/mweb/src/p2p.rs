//! LIP-0006 MWEB P2P message codecs.
//!
//! These types are not yet in the published `litecoin` crate `p2p` module. Wire them
//! here and re-export when upstream adds them.
//!
//! **Note:** `mwebutxos` follows litecoind's on-wire layout (`block_hash`, `start_index`,
//! …), which differs slightly from the LIP-0006 table (litecoind is authoritative for P2P).

// Every byte handled here is peer-controlled; a reachable panic is a remote DoS.
#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use bitcoin::blockdata::block::{BlockHash, MwebBlockHeader};
use bitcoin::blockdata::mimblewimble::Output;
use bitcoin::consensus::encode::{self, Decodable, Encodable, VarInt};
use bitcoin::hashes::Hash;
use bitcoin::io::{self, Read, Write};
use bitcoin::MerkleBlock;
use bitcoin::Transaction;

use crate::error::Error;
use crate::limits::{
    MAX_LEAFSET_BYTES, MAX_OUTPUT_MMR_SIZE, MAX_PARENT_HASHES, MAX_UTXOS_PER_BATCH, RESERVE_CHUNK,
};

/// `getdata` inventory type for MWEB header (LIP-0006).
pub const MSG_MWEB_HEADER: u32 = 0x2000_0008;
/// `getdata` inventory type for MWEB leafset (LIP-0006).
pub const MSG_MWEB_LEAFSET: u32 = 0x2000_0009;
/// `inv`/`getdata` type for an MWEB transaction:
/// `MSG_WITNESS_TX (1 | 1<<30) | MSG_MWEB_FLAG (1<<29)` per Core `protocol.h`.
pub const MSG_MWEB_TX: u32 = 0x6000_0001;

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
        // Checked before the entry loop, not inside it: a zero-entry message with a
        // format we cannot parse is still a message we must reject.
        if output_format != OUTPUT_FORMAT_FULL {
            return Err(encode::Error::ParseFailed(
                "bdk_mweb only decodes FULL_UTXO (0x00) mwebutxos",
            ));
        }
        let n = VarInt::consensus_decode(r)?.0;
        if n > MAX_UTXOS_PER_BATCH as u64 {
            return Err(encode::Error::ParseFailed(
                "mwebutxos utxo count exceeds MAX_UTXOS_PER_BATCH",
            ));
        }
        let n = n as usize;
        // Reserve for what the peer will plausibly deliver, not for what it claimed:
        // the count is capped above, but the cap is still far above a real batch.
        let mut utxos = Vec::with_capacity(n.min(RESERVE_CHUNK));
        for _ in 0..n {
            let leaf_index = VarInt::consensus_decode(r)?.0;
            let output = Output::consensus_decode(r)?;
            utxos.push(MwebUtxoEntry { leaf_index, output });
        }
        let nh = VarInt::consensus_decode(r)?.0;
        if nh > MAX_PARENT_HASHES as u64 {
            return Err(encode::Error::ParseFailed(
                "mwebutxos parent_hashes count exceeds MAX_PARENT_HASHES",
            ));
        }
        let nh = nh as usize;
        let mut parent_hashes = Vec::with_capacity(nh.min(RESERVE_CHUNK));
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

/// BLAKE3 hash of the consensus serialization of an MWEB extension-block header.
///
/// This is the value the HogEx transaction commits to on the canonical chain, so it
/// is what binds a peer-supplied `mwebheader` to a block. MWEB uses BLAKE3
/// throughout (see [`crate::hash`]) rather than the double-SHA256 used for
/// canonical Litecoin headers.
pub fn header_hash(header: &MwebBlockHeader) -> [u8; 32] {
    crate::hash::blake3_hash(&bitcoin::consensus::serialize(header))
}

/// Witness-version opcode prefixing the HogEx MWEB header commitment (`OP_8`).
///
/// Confirmed against Litecoin Core source, not just regtest observation:
/// `CScript::IsMWEBHogAddr(mw::Hash* header_hash)` in `src/script/script.h`
/// recognises exactly a witness-v8 program of `WITNESS_MWEB_HEADERHASH_SIZE`
/// (= 32) bytes, with `OP_8 = 0x58` in the same header. Core's consensus checks
/// (audited as Chk1/Chk3 in the Quarkslab MWEB audit, 21-08-872-REP) require the
/// HogEx to be the final transaction in the block (`mw::Node::CheckBlock`) and the
/// MWEB header hash to match the hash the HogEx commits to
/// (`BlockValidator::Validate`). The MWEB light-client sync spec states the same
/// layout: HogEx `vout[0]` script is `<OP_8><0x20><32-byte blake3(mweb_header)>`.
/// Witness v9 (`0x59`) is the *peg-in* program (`CScript::IsMWEBPegin`), not this.
const HOGEX_COMMITMENT_OPCODE: u8 = 0x58;
/// Length of the HogEx commitment script: `OP_8` + `PUSH32` + 32-byte hash.
const HOGEX_COMMITMENT_SPK_LEN: usize = 34;

impl MwebHeaderMsg {
    /// Prove this header belongs to `block_hash` on the canonical chain.
    ///
    /// Without this, [`crate::lip0006::VerifyMode::HeaderAndPmmr`] is circular: the
    /// leafset and UTXO batches are checked against `leafset_root` / `output_root`
    /// taken from `mweb_header`, which arrived from the same peer that supplied the
    /// data being checked. A peer can serve a wholly invented MWEB chain and every
    /// check passes.
    ///
    /// The chain of custody this establishes, each link verified on regtest by
    /// `tests/mweb_anchoring.rs` and matching Litecoin Core's own consensus rules
    /// (see `HOGEX_COMMITMENT_OPCODE` for the Core source references):
    ///
    /// 1. `merkle.header` hashes to `block_hash`, which the caller obtained from its own trusted
    ///    header chain rather than from this peer.
    /// 2. The partial merkle tree reproduces `merkle.header.merkle_root`, so the txids it yields
    ///    really are in that block.
    /// 3. The supplied HogEx is one of those txids, at the final position. Litecoin consensus
    ///    places the HogEx last, so position plus merkle inclusion identifies it uniquely.
    /// 4. Its first output commits to `blake3(mweb_header)`.
    ///
    /// Note that `Transaction::is_hog_ex` is deliberately *not* relied on. It comes
    /// from the segwit flag byte, which is outside the txid, so a peer can set it on
    /// any transaction without invalidating the merkle proof. Step 3's position
    /// check is what actually identifies the HogEx.
    pub fn verify_anchored(&self, block_hash: BlockHash) -> Result<(), Error> {
        if self.merkle.header.block_hash() != block_hash {
            return Err(Error::bad_proof(alloc::format!(
                "mwebheader anchor: merkle block is for {}, expected {block_hash}",
                self.merkle.header.block_hash()
            )));
        }

        let mut txids = Vec::new();
        let mut indexes = Vec::new();
        self.merkle
            .extract_matches(&mut txids, &mut indexes)
            .map_err(|e| {
                Error::bad_proof(alloc::format!(
                    "mwebheader anchor: partial merkle tree invalid: {e:?}"
                ))
            })?;

        let hogex_txid = self.hogex.compute_txid();
        let Some(slot) = txids.iter().position(|t| *t == hogex_txid) else {
            return Err(Error::bad_proof(
                "mwebheader anchor: HogEx is not proven to be in the block",
            ));
        };
        let num_txs = self.merkle.txn.num_transactions();
        if indexes[slot] + 1 != num_txs {
            return Err(Error::bad_proof(alloc::format!(
                "mwebheader anchor: HogEx is at index {} of {num_txs}, expected last",
                indexes[slot]
            )));
        }

        let Some(out) = self.hogex.output.first() else {
            return Err(Error::bad_proof(
                "mwebheader anchor: HogEx has no outputs, so no header commitment",
            ));
        };
        let spk = out.script_pubkey.as_bytes();
        if spk.len() != HOGEX_COMMITMENT_SPK_LEN
            || spk[0] != HOGEX_COMMITMENT_OPCODE
            || spk[1] != 32
        {
            return Err(Error::bad_proof(
                "mwebheader anchor: HogEx vout[0] is not an MWEB header commitment script",
            ));
        }
        let expected = header_hash(&self.mweb_header);
        if spk[2..] != expected {
            return Err(Error::bad_proof(
                "mwebheader anchor: HogEx does not commit to this mweb_header",
            ));
        }
        Ok(())
    }
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
        let size = VarInt::consensus_decode(r)?.0;
        // The length prefix is attacker-controlled and the buffer is allocated in
        // full before `read_exact` gets a chance to fail, so the cap must come first.
        if size > MAX_LEAFSET_BYTES as u64 {
            return Err(encode::Error::ParseFailed(
                "mwebleafset size exceeds MAX_LEAFSET_BYTES",
            ));
        }
        let mut leafset = vec![0u8; size as usize];
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
    ///
    /// Each set bit becomes a `u64`, so the result is up to 64x the size of the
    /// bitset. The blob itself is capped at [`MAX_LEAFSET_BYTES`] on decode, which
    /// bounds that amplification; [`Self::unspent_leaf_indices_bounded`] lets a
    /// caller impose a tighter policy.
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

    /// [`Self::unspent_leaf_indices`], erroring once more than `max` bits are set.
    ///
    /// Stops scanning at the limit rather than building the full vector first.
    pub fn unspent_leaf_indices_bounded(&self, max: usize) -> Result<Vec<u64>, Error> {
        let mut out = Vec::new();
        for (byte_i, byte) in self.leafset.iter().enumerate() {
            if *byte == 0 {
                continue;
            }
            for bit in 0..8u64 {
                if byte & (1 << (7 - bit)) != 0 {
                    if out.len() == max {
                        return Err(Error::protocol(alloc::format!(
                            "leafset has more than {max} unspent leaves"
                        )));
                    }
                    out.push(byte_i as u64 * 8 + bit);
                }
            }
        }
        Ok(out)
    }

    /// Build a leafset bitset from set leaf indices (for tests / scripted peers).
    ///
    /// Indices at or above [`MAX_OUTPUT_MMR_SIZE`] are ignored, since the bitset
    /// needed to hold them could not be delivered over the wire. Use
    /// [`Self::try_from_indices`] to be told about them instead.
    pub fn from_indices(block_hash: BlockHash, indices: &[u64]) -> Self {
        let mut leafset = Vec::new();
        for &i in indices {
            if i >= MAX_OUTPUT_MMR_SIZE {
                continue;
            }
            let byte_i = (i / 8) as usize;
            let bit = i % 8;
            if byte_i >= leafset.len() {
                leafset.resize(byte_i + 1, 0u8);
            }
            leafset[byte_i] |= 1 << (7 - bit);
        }
        if leafset.is_empty() {
            leafset.push(0u8);
        }
        Self {
            block_hash,
            leafset,
        }
    }

    /// [`Self::from_indices`], but reject an index too large to represent on the wire.
    pub fn try_from_indices(block_hash: BlockHash, indices: &[u64]) -> Result<Self, Error> {
        if let Some(&bad) = indices.iter().find(|&&i| i >= MAX_OUTPUT_MMR_SIZE) {
            return Err(Error::Crypto(alloc::format!(
                "leaf index {bad} exceeds MAX_OUTPUT_MMR_SIZE"
            )));
        }
        Ok(Self::from_indices(block_hash, indices))
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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

    /// F-02: a huge `VarInt` length must be rejected before the buffer is allocated.
    /// The message body here is a handful of bytes, so a decoder that allocated
    /// first would try for terabytes and abort the process.
    #[test]
    fn leafset_decode_rejects_oversized_length() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[7u8; 32]);
        // CompactSize 0xFF marker followed by a u64 length of ~1 TiB.
        raw.push(0xFF);
        raw.extend_from_slice(&(1u64 << 40).to_le_bytes());
        let err = deserialize::<MwebLeafset>(&raw).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("MAX_LEAFSET_BYTES"),
            "expected a cap rejection, got {err}"
        );
    }

    /// A length just under the cap is still rejected, but by running out of input
    /// rather than by the cap: the cap must not be so tight it rejects valid sizes.
    #[test]
    fn leafset_decode_allows_length_under_cap() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[7u8; 32]);
        raw.push(0xFD);
        raw.extend_from_slice(&1024u16.to_le_bytes());
        raw.extend_from_slice(&[0u8; 1024]);
        let dec = deserialize::<MwebLeafset>(&raw).expect("1 KiB leafset is well under the cap");
        assert_eq!(dec.leafset.len(), 1024);
    }

    /// F-03: an unbounded entry count must be rejected before `reserve`.
    #[test]
    fn utxos_decode_rejects_oversized_counts() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[7u8; 32]); // block_hash
        raw.push(0); // start_index
        raw.push(OUTPUT_FORMAT_FULL);
        raw.push(0xFF);
        raw.extend_from_slice(&(1u64 << 40).to_le_bytes()); // utxo count
        let err = deserialize::<MwebUtxos>(&raw).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("MAX_UTXOS_PER_BATCH"),
            "expected a cap rejection, got {err}"
        );

        let mut raw = Vec::new();
        raw.extend_from_slice(&[7u8; 32]);
        raw.push(0);
        raw.push(OUTPUT_FORMAT_FULL);
        raw.push(0); // zero utxos
        raw.push(0xFF);
        raw.extend_from_slice(&(1u64 << 40).to_le_bytes()); // parent_hashes count
        let err = deserialize::<MwebUtxos>(&raw).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("MAX_PARENT_HASHES"),
            "expected a cap rejection, got {err}"
        );
    }

    /// The format check used to sit inside the entry loop, so a zero-entry message
    /// claiming an unparseable format decoded successfully.
    #[test]
    fn utxos_decode_rejects_non_full_format_with_zero_entries() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&[7u8; 32]);
        raw.push(0);
        raw.push(OUTPUT_FORMAT_HASH_ONLY);
        raw.push(0); // zero utxos
        raw.push(0); // zero parent hashes
        assert!(deserialize::<MwebUtxos>(&raw).is_err());
    }

    /// F-17: `from_indices` allocates `max_index / 8` bytes, so an out-of-range
    /// index must not be able to size that allocation.
    #[test]
    fn from_indices_ignores_unrepresentable_indices() {
        let hash = BlockHash::from_byte_array([1u8; 32]);
        let ls = MwebLeafset::from_indices(hash, &[3, u64::MAX]);
        assert_eq!(ls.unspent_leaf_indices(), vec![3]);
        assert!(ls.leafset.len() <= 1);

        assert!(MwebLeafset::try_from_indices(hash, &[3, u64::MAX]).is_err());
        assert!(MwebLeafset::try_from_indices(hash, &[3]).is_ok());
    }

    /// Build an `mwebheader` whose HogEx is the last of two transactions and commits
    /// to `mweb_header`, mirroring what litecoind serves (confirmed against a live
    /// node in `tests/mweb_anchoring.rs`).
    fn synthetic_anchored_msg(mweb_header: MwebBlockHeader) -> (MwebHeaderMsg, BlockHash) {
        use bitcoin::{Amount, ScriptBuf, TxOut};

        let mut spk = alloc::vec![0x58u8, 0x20];
        spk.extend_from_slice(&header_hash(&mweb_header));
        let outputs = alloc::vec![TxOut {
            value: Amount::from_sat(2),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }];
        synthetic_anchored_msg_with_hogex_outputs(mweb_header, outputs)
    }

    /// Like [`synthetic_anchored_msg`], but with caller-chosen HogEx outputs. The
    /// merkle proof is built *after* the outputs are fixed, so a defective HogEx
    /// still arrives with a valid inclusion proof — that is what lets tests reach
    /// the commitment-script checks rather than failing at the merkle step.
    fn synthetic_anchored_msg_with_hogex_outputs(
        mweb_header: MwebBlockHeader,
        hogex_outputs: alloc::vec::Vec<bitcoin::TxOut>,
    ) -> (MwebHeaderMsg, BlockHash) {
        use bitcoin::absolute::LockTime;
        use bitcoin::block::{Header, Version};
        use bitcoin::merkle_tree::PartialMerkleTree;
        use bitcoin::{Amount, CompactTarget, ScriptBuf, Transaction, TxMerkleNode, TxOut};

        let filler = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: alloc::vec![],
            output: alloc::vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
            mw_tx: None,
            is_hog_ex: false,
        };
        let hogex = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: alloc::vec![],
            output: hogex_outputs,
            mw_tx: None,
            is_hog_ex: true,
        };

        let txids = alloc::vec![filler.compute_txid(), hogex.compute_txid()];
        let txn = PartialMerkleTree::from_txids(&txids, &[false, true]);
        let merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(txids.iter().copied())
            .map(|h| TxMerkleNode::from_byte_array(h.to_byte_array()))
            .expect("two txids");

        let header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
            merkle_root,
            time: 1,
            bits: CompactTarget::from_consensus(1),
            nonce: 1,
        };
        let block_hash = header.block_hash();
        (
            MwebHeaderMsg {
                merkle: MerkleBlock { header, txn },
                hogex,
                mweb_header,
            },
            block_hash,
        )
    }

    fn sample_mweb_header() -> MwebBlockHeader {
        MwebBlockHeader {
            height: 7,
            output_root: [0xA1; 32],
            kernel_root: [0xA2; 32],
            leafset_root: [0xA3; 32],
            kernel_offset: [0xA4; 32],
            stealth_offset: [0xA5; 32],
            output_mmr_size: 42,
            kernel_mmr_size: 9,
        }
    }

    /// Every anchoring rejection must classify as [`crate::error::BanReason::BadProof`]
    /// via the typed discriminant, so peer rotation never depends on message wording.
    #[track_caller]
    fn assert_bad_proof(err: &Error) {
        assert_eq!(
            err.ban_reason(),
            Some(crate::error::BanReason::BadProof),
            "anchor rejection must be typed BadProof, got: {err}"
        );
    }

    /// F-01: an honest message anchors. Without this the rejection tests below could
    /// pass against a `verify_anchored` that rejected everything.
    #[test]
    fn anchored_accepts_an_honest_message() {
        let (msg, block_hash) = synthetic_anchored_msg(sample_mweb_header());
        msg.verify_anchored(block_hash).unwrap();
    }

    /// The check that makes anchoring mean anything: the header must belong to the
    /// block the caller asked about, not merely to *some* block.
    #[test]
    fn anchored_rejects_a_header_for_a_different_block() {
        let (msg, block_hash) = synthetic_anchored_msg(sample_mweb_header());
        let other = BlockHash::from_byte_array([0xFE; 32]);
        assert_ne!(other, block_hash);
        let err = msg.verify_anchored(other).unwrap_err();
        assert!(alloc::format!("{err}").contains("merkle block is for"));
        assert_bad_proof(&err);
    }

    /// Every field of the MWEB header is covered by the commitment, so none of the
    /// roots that verification depends on can be swapped out.
    #[test]
    fn anchored_rejects_any_mweb_header_mutation() {
        type Mut = fn(&mut MwebBlockHeader);
        let mutators: [(&str, Mut); 8] = [
            ("height", |h| h.height ^= 1),
            ("output_root", |h| h.output_root[0] ^= 1),
            ("kernel_root", |h| h.kernel_root[0] ^= 1),
            ("leafset_root", |h| h.leafset_root[0] ^= 1),
            ("kernel_offset", |h| h.kernel_offset[0] ^= 1),
            ("stealth_offset", |h| h.stealth_offset[0] ^= 1),
            ("output_mmr_size", |h| h.output_mmr_size ^= 1),
            ("kernel_mmr_size", |h| h.kernel_mmr_size ^= 1),
        ];
        for (field, mutate) in mutators {
            let (mut msg, block_hash) = synthetic_anchored_msg(sample_mweb_header());
            mutate(&mut msg.mweb_header);
            let err = msg.verify_anchored(block_hash).unwrap_err();
            assert!(
                alloc::format!("{err}").contains("does not commit to this mweb_header"),
                "mutating `{field}` was not caught by the commitment: {err}"
            );
            assert_bad_proof(&err);
        }
    }

    /// A commitment script of the wrong shape must be rejected outright rather than
    /// parsed leniently; a lenient parse is how a wrong-length push slips through.
    #[test]
    fn anchored_rejects_malformed_commitment_scripts() {
        use bitcoin::ScriptBuf;

        let good_hash = header_hash(&sample_mweb_header());
        let cases: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("wrong opcode", {
                let mut v = alloc::vec![0x51u8, 0x20];
                v.extend_from_slice(&good_hash);
                v
            }),
            ("wrong push length", {
                let mut v = alloc::vec![0x58u8, 0x1F];
                v.extend_from_slice(&good_hash[..31]);
                v
            }),
            ("truncated hash", alloc::vec![0x58u8, 0x20, 0x00]),
            ("trailing bytes", {
                let mut v = alloc::vec![0x58u8, 0x20];
                v.extend_from_slice(&good_hash);
                v.push(0x00);
                v
            }),
        ];

        for (name, spk) in cases {
            let (mut msg, _) = synthetic_anchored_msg(sample_mweb_header());
            msg.hogex.output[0].script_pubkey = ScriptBuf::from_bytes(spk);
            // Mutating the HogEx changes its txid, so the merkle proof fails too;
            // either rejection is correct, but it must not be accepted.
            let block_hash = msg.merkle.header.block_hash();
            let err = msg.verify_anchored(block_hash).expect_err(
                alloc::format!("commitment script case `{name}` was accepted").as_str(),
            );
            assert_bad_proof(&err);
        }
    }

    /// The HogEx must be the *last* transaction. Position is what identifies it:
    /// `is_hog_ex` comes from the segwit flag byte, which is outside the txid and so
    /// can be set by a peer on any transaction without breaking the merkle proof.
    #[test]
    fn anchored_rejects_a_commitment_carrier_that_is_not_last() {
        use bitcoin::absolute::LockTime;
        use bitcoin::merkle_tree::PartialMerkleTree;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxMerkleNode, TxOut};

        let mweb_header = sample_mweb_header();
        let mut spk = alloc::vec![0x58u8, 0x20];
        spk.extend_from_slice(&header_hash(&mweb_header));

        // The commitment carrier is now first of two, which consensus forbids.
        let carrier = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: alloc::vec![],
            output: alloc::vec![TxOut {
                value: Amount::from_sat(2),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            mw_tx: None,
            // Set the flag a peer would set to masquerade; it must not help.
            is_hog_ex: true,
        };
        let trailer = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: alloc::vec![],
            output: alloc::vec![TxOut {
                value: Amount::from_sat(3),
                script_pubkey: ScriptBuf::new(),
            }],
            mw_tx: None,
            is_hog_ex: false,
        };

        let txids = alloc::vec![carrier.compute_txid(), trailer.compute_txid()];
        let txn = PartialMerkleTree::from_txids(&txids, &[true, false]);
        let merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(txids.iter().copied())
            .map(|h| TxMerkleNode::from_byte_array(h.to_byte_array()))
            .unwrap();
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
            merkle_root,
            time: 1,
            bits: bitcoin::CompactTarget::from_consensus(1),
            nonce: 1,
        };
        let block_hash = header.block_hash();
        let msg = MwebHeaderMsg {
            merkle: MerkleBlock { header, txn },
            hogex: carrier,
            mweb_header,
        };

        let err = msg.verify_anchored(block_hash).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("expected last"),
            "a non-final transaction was accepted as the HogEx: {err}"
        );
        assert_bad_proof(&err);
    }

    /// A merkle proof that does not reproduce its own header's root proves nothing.
    #[test]
    fn anchored_rejects_a_merkle_root_mismatch() {
        let (mut msg, _) = synthetic_anchored_msg(sample_mweb_header());
        msg.merkle.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0xCC; 32]);
        let block_hash = msg.merkle.header.block_hash();
        let err = msg.verify_anchored(block_hash).unwrap_err();
        assert!(alloc::format!("{err}").contains("partial merkle tree invalid"));
        assert_bad_proof(&err);
    }

    /// F-01a: known-answer test against a real mainnet `mwebheader`.
    ///
    /// The fixture is the byte-for-byte P2P `mwebheader` payload litecoind 0.21.5.5
    /// served for mainnet block 3,152,700
    /// (`57250d2f79a10c41920ce7fb4ed4ab19381a71e02a6635c28b7002426f38a3ea`, hash
    /// cross-checked against litecoinspace.org on 2026-08-01; captured with
    /// `examples/capture_mwebheader.rs`). Unlike the synthetic tests above, nothing
    /// here was produced by this crate's encoders, so it pins [`header_hash`] and
    /// [`MwebHeaderMsg::verify_anchored`] against what the network actually
    /// commits to: a drift in `MwebBlockHeader`'s serialization, the blake3
    /// domain, or the commitment-script shape all fail this test offline.
    #[cfg(feature = "std")]
    #[test]
    fn mainnet_header_hash_known_answer() {
        extern crate std;
        use hex_conservative::FromHex;

        let path = alloc::format!(
            "{}/tests/fixtures/mainnet_mwebheader_3152700.hex",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        let bytes = <alloc::vec::Vec<u8>>::from_hex(raw.trim()).unwrap();
        let msg: MwebHeaderMsg = deserialize(&bytes).unwrap();

        // The known answer: blake3 of the header as committed by the mainnet chain.
        let expected = <[u8; 32]>::from_hex(
            "3b749e33dccd189fdeb5a519e184e8c10975597877cb7b801d054b67e45de538",
        )
        .unwrap();
        assert_eq!(header_hash(&msg.mweb_header), expected);

        // And the full anchoring chain holds against the trusted mainnet block hash.
        let block_hash: BlockHash =
            "57250d2f79a10c41920ce7fb4ed4ab19381a71e02a6635c28b7002426f38a3ea"
                .parse()
                .unwrap();
        msg.verify_anchored(block_hash).unwrap();

        // Field-level sanity so a fixture mix-up is caught with a readable message.
        assert_eq!(msg.mweb_header.height, 3_152_700);
        assert_eq!(msg.mweb_header.output_mmr_size, 349_044);
        assert_eq!(msg.merkle.txn.num_transactions(), 517);

        // Re-encoding must reproduce the wire bytes exactly, or the hash above is
        // being computed over something other than what litecoind serializes.
        assert_eq!(serialize(&msg), bytes);
    }

    /// Anchoring failures must rotate the peer: a peer serving an unanchored header
    /// is either broken or hostile, and retrying it forever helps neither.
    #[test]
    fn anchor_failures_are_banworthy() {
        let (msg, _) = synthetic_anchored_msg(sample_mweb_header());
        let err = msg
            .verify_anchored(BlockHash::from_byte_array([0xFE; 32]))
            .unwrap_err();
        assert!(crate::mweb_sync::is_banworthy_peer_error(&err));
    }

    /// The three rejection paths the tests above only reach indirectly, each hit on
    /// its own branch and classified as typed `BadProof`. Together with the tests
    /// above, every `return Err` in [`MwebHeaderMsg::verify_anchored`] is now pinned
    /// to the typed discriminant.
    #[test]
    fn remaining_anchor_rejection_paths_are_banworthy() {
        use bitcoin::{Amount, ScriptBuf, TxOut};

        // "HogEx is not proven to be in the block": the supplied HogEx's txid is
        // not among the merkle-matched txids. Tweaking the version changes the
        // txid while the (valid) proof still names the original.
        let (mut msg, block_hash) = synthetic_anchored_msg(sample_mweb_header());
        msg.hogex.version = bitcoin::transaction::Version::TWO;
        let err = msg.verify_anchored(block_hash).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("not proven to be in the block"),
            "wrong branch: {err}"
        );
        assert_bad_proof(&err);

        // "HogEx has no outputs": baked in before the merkle proof is built, so the
        // inclusion proof is valid and the no-commitment branch is what fires.
        let (msg, block_hash) =
            synthetic_anchored_msg_with_hogex_outputs(sample_mweb_header(), alloc::vec![]);
        let err = msg.verify_anchored(block_hash).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("has no outputs"),
            "wrong branch: {err}"
        );
        assert_bad_proof(&err);

        // "not an MWEB header commitment script": a merkle-proven HogEx whose
        // vout[0] has the wrong shape, reaching the script check itself rather than
        // failing earlier on the txid.
        let (msg, block_hash) = synthetic_anchored_msg_with_hogex_outputs(
            sample_mweb_header(),
            alloc::vec![TxOut {
                value: Amount::from_sat(2),
                script_pubkey: ScriptBuf::from_bytes(alloc::vec![0x51, 0x20]),
            }],
        );
        let err = msg.verify_anchored(block_hash).unwrap_err();
        assert!(
            alloc::format!("{err}").contains("not an MWEB header commitment script"),
            "wrong branch: {err}"
        );
        assert_bad_proof(&err);
    }

    /// F-14: the bounded accessor stops instead of materializing a 64x blowup.
    #[test]
    fn unspent_leaf_indices_bounded_stops_at_limit() {
        let hash = BlockHash::from_byte_array([1u8; 32]);
        let ls = MwebLeafset::from_indices(hash, &[0, 1, 2, 3]);
        assert_eq!(
            ls.unspent_leaf_indices_bounded(4).unwrap(),
            vec![0, 1, 2, 3]
        );
        assert!(ls.unspent_leaf_indices_bounded(3).is_err());
    }
}
