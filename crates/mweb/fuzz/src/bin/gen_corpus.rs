//! Regenerate the checked-in seed corpus under `hfuzz_input/`.
//!
//! Coverage-guided fuzzing of consensus decoders starves without valid
//! encodings to mutate: random bytes almost never survive the first length
//! prefix. Each seed here is either a real ltcd-generated payload (the
//! `output_roundtrip_*.hex` fixtures produced by `scripts/ltcd_mweb_fixtures`
//! on regtest) or an honest encoding produced by the same encoders the wallet
//! uses on the wire.
//!
//! Deterministic by construction — run `cargo run --bin gen_corpus` from
//! `crates/mweb/fuzz/` and the tree under `hfuzz_input/` is reproduced
//! byte-for-byte, so corpus changes show up in review as ordinary diffs.

use bdk_mweb::p2p::{GetMwebUtxos, MwebLeafset, MwebUtxoEntry, MwebUtxos, OUTPUT_FORMAT_FULL};
use litecoin::blockdata::mimblewimble::Output;
use litecoin::consensus::encode::{deserialize, serialize};
use litecoin::hashes::{sha256d, Hash};
use litecoin::{BlockHash, Network};
use std::fs;
use std::path::{Path, PathBuf};

fn input_dir(target: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("hfuzz_input")
        .join(target)
        .join("input");
    fs::create_dir_all(&dir).expect("create corpus dir");
    dir
}

fn write_seed(target: &str, name: &str, bytes: &[u8]) {
    let path = input_dir(target).join(name);
    fs::write(&path, bytes).expect("write seed");
    println!("{} ({} bytes)", path.display(), bytes.len());
}

/// Real ltcd-generated MWEB outputs, decoded from the shared test fixtures.
fn fixture_outputs() -> Vec<(String, Vec<u8>)> {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures");
    let mut out = Vec::new();
    for name in [
        "output_roundtrip_0",
        "output_roundtrip_1",
        "output_roundtrip_10",
        "output_roundtrip_index0_deadbeef",
        "output_wrong_scan_target",
    ] {
        let hex = fs::read_to_string(fixtures.join(format!("{name}.hex")))
            .expect("read ltcd output fixture");
        let mut bytes = Vec::new();
        bdk_mweb_fuzz::extend_vec_from_hex(hex.trim(), &mut bytes);
        // Sanity: the fixture must be a decodable Output, or the seed is junk.
        let _: Output = deserialize(&bytes).expect("fixture decodes as Output");
        out.push((name.to_string(), bytes));
    }
    out
}

fn block_hash() -> BlockHash {
    BlockHash::from_byte_array([0xaa; 32])
}

/// A LIP-0006 wire frame: 24-byte header (magic, command, length, checksum)
/// followed by the payload, prefixed with the `p2p_frame` target's one-byte
/// network selector (2 => regtest, matching `c.u8() % 3`).
fn framed(command: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![2u8];
    buf.extend_from_slice(&Network::Regtest.magic().to_bytes());
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    buf.extend_from_slice(&cmd);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let checksum = sha256d::Hash::hash(payload);
    buf.extend_from_slice(&checksum[..4]);
    buf.extend_from_slice(payload);
    buf
}

/// A structurally honest `mwebheader` message (self-consistent, not anchored).
fn mweb_header_msg() -> bdk_mweb::p2p::MwebHeaderMsg {
    use litecoin::block::{Header, Version};
    use litecoin::blockdata::block::MwebBlockHeader;
    use litecoin::merkle_tree::PartialMerkleTree;
    use litecoin::{CompactTarget, MerkleBlock, Transaction, TxMerkleNode, Txid};

    bdk_mweb::p2p::MwebHeaderMsg {
        merkle: MerkleBlock {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 0,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txn: PartialMerkleTree::from_txids(&[Txid::from_byte_array([1u8; 32])], &[true]),
        },
        hogex: Transaction {
            version: litecoin::transaction::Version::ONE,
            lock_time: litecoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
            mw_tx: None,
            is_hog_ex: true,
        },
        mweb_header: MwebBlockHeader {
            height: 11,
            output_root: [2u8; 32],
            kernel_root: [3u8; 32],
            leafset_root: [4u8; 32],
            kernel_offset: [5u8; 32],
            stealth_offset: [6u8; 32],
            output_mmr_size: 4,
            kernel_mmr_size: 1,
        },
    }
}

fn main() {
    let outputs = fixture_outputs();

    // rewind_output: real Output wire bytes drive shape 1 (consensus decode)
    // directly; the structured shape 2 mutates fine from the same material.
    for (name, bytes) in &outputs {
        write_seed("rewind_output", &format!("{name}.bin"), bytes);
    }

    // decode_mweb_utxos: honest batches wrapping the real outputs.
    for (i, n) in [1usize, 2, 5].iter().enumerate() {
        let utxos: Vec<MwebUtxoEntry> = outputs
            .iter()
            .cycle()
            .take(*n)
            .enumerate()
            .map(|(leaf, (_, bytes))| MwebUtxoEntry {
                leaf_index: leaf as u64,
                output: deserialize(bytes).expect("fixture decodes"),
            })
            .collect();
        let msg = MwebUtxos {
            block_hash: block_hash(),
            start_index: 0,
            output_format: OUTPUT_FORMAT_FULL,
            utxos,
            parent_hashes: (0..*n).map(|j| [j as u8; 32]).collect(),
        };
        write_seed(
            "decode_mweb_utxos",
            &format!("batch_{i}.bin"),
            &serialize(&msg),
        );
    }

    // decode_mweb_leafset: empty, small, and multi-byte bitsets.
    for (name, indices) in [
        ("empty", &[][..]),
        ("small", &[0u64, 1, 3][..]),
        ("sparse", &[0u64, 7, 8, 63, 64, 200][..]),
    ] {
        let leafset = MwebLeafset::from_indices(block_hash(), indices);
        write_seed(
            "decode_mweb_leafset",
            &format!("{name}.bin"),
            &serialize(&leafset),
        );
    }

    // decode_get_mweb_utxos: an honest request.
    let req = GetMwebUtxos {
        block_hash: block_hash(),
        start_index: 5,
        num_requested: 512,
        output_format: OUTPUT_FORMAT_FULL,
    };
    write_seed("decode_get_mweb_utxos", "request.bin", &serialize(&req));

    // decode_mweb_header: an honest header message. Random bytes essentially
    // never survive the nested MerkleBlock + Transaction decode, so this seed
    // is what makes the target explore past the first field.
    let header_msg = mweb_header_msg();
    write_seed("decode_mweb_header", "header.bin", &serialize(&header_msg));

    // p2p_frame: well-formed regtest frames for each LIP-0006 command, so the
    // fuzzer starts from headers that pass the magic/length checks.
    let leafset_payload = serialize(&MwebLeafset::from_indices(block_hash(), &[0, 1, 2]));
    write_seed(
        "p2p_frame",
        "mwebleafset.bin",
        &framed("mwebleafset", &leafset_payload),
    );
    let utxos_payload = serialize(&MwebUtxos {
        block_hash: block_hash(),
        start_index: 0,
        output_format: OUTPUT_FORMAT_FULL,
        utxos: vec![MwebUtxoEntry {
            leaf_index: 0,
            output: deserialize(&outputs[0].1).expect("fixture decodes"),
        }],
        parent_hashes: vec![[7u8; 32]],
    });
    write_seed(
        "p2p_frame",
        "mwebutxos.bin",
        &framed("mwebutxos", &utxos_payload),
    );
}
