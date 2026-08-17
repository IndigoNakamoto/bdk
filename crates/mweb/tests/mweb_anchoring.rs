//! MWEB header anchoring, verified against a live litecoind.
//!
//! `VerifyMode::Anchored` binds a peer-supplied `mwebheader` to the canonical chain
//! through the HogEx commitment. The exact shape of that commitment is not written
//! down in LIP-0006, so rather than encode it from memory these tests read it off a
//! regtest node, assert the relationship they find, and then break each link of the
//! chain to confirm every one is load-bearing.
//!
//! What the first two tests established (printed with `--nocapture`):
//! HogEx `vout[0].script_pubkey` is `OP_8 PUSH32 <blake3(mweb_header)>`, 34 bytes,
//! and litecoind's P2P `mwebheader` carries a merkle proof placing that HogEx last
//! in the block whose header hashes to the requested `block_hash`.
//!
//! Synthetic counterparts that need no node live in `p2p.rs`'s test module.
//!
//! Needs `LITECOIND_EXE` (skips when unset).

#![cfg(feature = "lip0006")]
// These tests print what they observe on the node. Running them with `--nocapture`
// is how the commitment format gets re-derived if litecoind ever changes it, so the
// output is the deliverable rather than leftover debugging.
#![allow(clippy::print_stdout)]

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006::VerifyMode;
use bdk_mweb::p2p::header_hash;
use bdk_testenv::try_node_from_env;
use bitcoin::key::Secp256k1;
use bitcoin::{Amount, Network};

#[test]
fn hogex_commits_to_blake3_of_the_mweb_header() {
    let Some(env) = try_node_from_env().expect("harness") else {
        return;
    };

    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &[0x42u8; 32],
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .expect("keys");
    let mweb_addr = keys.address(0, Network::Regtest, &secp).expect("address");

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    // A peg-in makes the MWEB block non-trivial, so the header carries real roots
    // rather than the all-zero values of an empty extension block.
    env.finalize_mweb_pegin(&mweb_addr, Amount::from_btc(1.0).unwrap())
        .expect("peg-in");
    env.mine_mweb_activation(&mining).expect("activate");
    // A couple more blocks so at least one has a settled MWEB extension.
    env.rpc.generate_to_address(2, &mining).expect("mine");

    let tip = env.rpc.get_block_count().expect("count");

    let mut examined = 0;
    for height in (1..=tip).rev() {
        let hash = env.rpc.get_block_hash(height).expect("hash");
        let block = env.rpc.get_block(&hash).expect("block");
        let Some(mweb) = block.mweb_block.as_ref() else {
            continue;
        };
        let Some(hogex) = block.txdata.last() else {
            continue;
        };
        if !hogex.is_hog_ex {
            continue;
        }
        examined += 1;

        let expected = header_hash(&mweb.header);
        println!("--- height {height} ---");
        println!("  blake3(mweb_header) = {}", hex(&expected));
        println!("  hogex txid          = {}", hogex.compute_txid());
        println!("  hogex outputs       = {}", hogex.output.len());
        for (i, out) in hogex.output.iter().enumerate() {
            let spk = out.script_pubkey.as_bytes();
            println!(
                "    vout[{i}] value={} spk_len={} spk={}",
                out.value,
                spk.len(),
                hex(spk)
            );
            if let Some(pos) = find(spk, &expected) {
                println!("      ^ CONTAINS blake3(mweb_header) at byte offset {pos}");
            }
        }

        // The commitment must be locatable somewhere in the HogEx, otherwise
        // anchoring is impossible and `VerifyMode::Anchored` cannot be built.
        let found = hogex
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| find(o.script_pubkey.as_bytes(), &expected).is_some());
        assert!(
            found.is_some(),
            "no HogEx output contains blake3(mweb_header) at height {height}; \
             the header commitment is computed differently than assumed"
        );
        let (vout, out) = found.unwrap();
        let spk = out.script_pubkey.as_bytes();
        println!(
            "  => commitment in vout[{vout}], opcode prefix {:#04x}, spk_len {}",
            spk[0],
            spk.len()
        );

        // Only the first block with an extension is needed to learn the layout.
        if examined >= 1 {
            break;
        }
    }

    assert!(examined > 0, "no block with an MWEB extension was produced");
}

/// F-01f: does the `mwebheader` message litecoind serves over P2P actually carry a
/// usable anchor?
///
/// The block-level probe above proves the commitment exists on chain. It does not
/// prove the peer *sends* enough to check it — the merkle block could arrive with a
/// header that does not hash to the block we asked for, or the HogEx could arrive
/// stripped of its MWEB flag. `VerifyMode::Anchored` is only safe to make the
/// default once this passes, so it is asserted rather than merely printed.
#[test]
fn p2p_mwebheader_carries_a_verifiable_anchor() {
    use bdk_mweb::lip0006::MwebUtxoSource;
    use bdk_mweb::lip0006_tcp::TcpMwebPeer;

    let Some(env) = try_node_from_env().expect("harness") else {
        return;
    };

    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &[0x43u8; 32],
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .expect("keys");
    let mweb_addr = keys.address(0, Network::Regtest, &secp).expect("address");

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    env.finalize_mweb_pegin(&mweb_addr, Amount::from_btc(1.0).unwrap())
        .expect("peg-in");
    env.mine_mweb_activation(&mining).expect("activate");
    env.rpc.generate_to_address(2, &mining).expect("mine");

    let tip = env.rpc.get_block_count().expect("count");
    let tip_hash = env.rpc.get_block_hash(tip).expect("hash");

    let mut peer = TcpMwebPeer::connect(format!("127.0.0.1:{}", env.p2p_port), Network::Regtest)
        .expect("connect to regtest peer");
    let msg = peer.get_header(tip_hash).expect("mwebheader over p2p");

    println!("--- p2p mwebheader for {tip_hash} ---");
    println!(
        "  merkle.header.block_hash = {}",
        msg.merkle.header.block_hash()
    );
    println!("  requested block_hash     = {tip_hash}");
    println!(
        "  merkle num_transactions  = {}",
        msg.merkle.txn.num_transactions()
    );
    println!("  hogex.is_hog_ex          = {}", msg.hogex.is_hog_ex);
    println!("  hogex txid               = {}", msg.hogex.compute_txid());
    println!("  hogex outputs            = {}", msg.hogex.output.len());
    for (i, out) in msg.hogex.output.iter().enumerate() {
        println!("    vout[{i}] spk={}", hex(out.script_pubkey.as_bytes()));
    }
    let mut txids = Vec::new();
    let mut indexes = Vec::new();
    let extract = msg.merkle.extract_matches(&mut txids, &mut indexes);
    println!("  extract_matches          = {extract:?}");
    println!("  matched txids            = {txids:?}");
    println!("  matched indexes          = {indexes:?}");
    println!(
        "  blake3(mweb_header)      = {}",
        hex(&header_hash(&msg.mweb_header))
    );

    // Each of these is a link in the anchoring chain. If any fails, `Anchored`
    // cannot be implemented as designed and the design must change rather than the
    // check being weakened.
    assert_eq!(
        msg.merkle.header.block_hash(),
        tip_hash,
        "the merkle block does not hash to the block we asked for, so nothing binds \
         this header to our chain"
    );
    extract.expect("partial merkle tree must validate against its own header");
    assert!(
        txids.contains(&msg.hogex.compute_txid()),
        "the supplied HogEx is not proven to be in the block"
    );
    assert!(
        !msg.hogex.output.is_empty(),
        "HogEx has no outputs, so it carries no header commitment"
    );
    let spk = msg.hogex.output[0].script_pubkey.as_bytes();
    let expected = header_hash(&msg.mweb_header);
    assert_eq!(
        spk.len(),
        34,
        "HogEx vout[0] is not the expected 34-byte commitment script"
    );
    assert_eq!(spk[0], 0x58, "expected OP_8 witness-version prefix");
    assert_eq!(spk[1], 0x20, "expected a 32-byte push");
    assert_eq!(
        &spk[2..],
        &expected,
        "HogEx vout[0] does not commit to blake3(mweb_header)"
    );
}

/// F-01e: each link in the anchoring chain must be independently load-bearing.
///
/// A `verify_anchored` that checked only, say, the commitment script would still
/// pass the happy-path probe above while accepting a header lifted from a different
/// block. Every mutation here breaks exactly one link and must be rejected.
#[test]
fn anchored_verification_rejects_each_broken_link() {
    use bdk_mweb::lip0006::MwebUtxoSource;
    use bdk_mweb::lip0006_tcp::TcpMwebPeer;
    use bitcoin::ScriptBuf;

    let Some(env) = try_node_from_env().expect("harness") else {
        return;
    };

    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &[0x44u8; 32],
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .expect("keys");
    let mweb_addr = keys.address(0, Network::Regtest, &secp).expect("address");

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    env.finalize_mweb_pegin(&mweb_addr, Amount::from_btc(1.0).unwrap())
        .expect("peg-in");
    env.mine_mweb_activation(&mining).expect("activate");
    env.rpc.generate_to_address(3, &mining).expect("mine");

    let tip = env.rpc.get_block_count().expect("count");
    let tip_hash = env.rpc.get_block_hash(tip).expect("hash");
    let prev_hash = env.rpc.get_block_hash(tip - 1).expect("prev hash");

    let mut peer = TcpMwebPeer::connect(format!("127.0.0.1:{}", env.p2p_port), Network::Regtest)
        .expect("connect");
    let good = peer.get_header(tip_hash).expect("mwebheader");
    let prev = peer.get_header(prev_hash).expect("mwebheader for prev");

    // Baseline: the honest message verifies. Without this the rejections below could
    // all be passing for an unrelated reason.
    good.verify_anchored(tip_hash)
        .expect("an honest mwebheader must anchor");
    prev.verify_anchored(prev_hash).expect("prev must anchor");

    // Link 1: the merkle block must be for the block we asked about. This is the
    // check that stops a peer replaying a valid header from another block.
    assert!(
        good.verify_anchored(prev_hash).is_err(),
        "a header for the tip verified against the previous block"
    );
    assert!(
        prev.verify_anchored(tip_hash).is_err(),
        "a header for the previous block verified against the tip"
    );

    // Link 4: the commitment must match the header actually supplied. Splicing
    // another block's MWEB header into an otherwise valid message must fail.
    let mut spliced = good.clone();
    spliced.mweb_header = prev.mweb_header.clone();
    let err = spliced.verify_anchored(tip_hash).unwrap_err();
    assert!(
        format!("{err}").contains("does not commit to this mweb_header"),
        "splicing a foreign mweb_header was caught by the wrong check: {err}"
    );

    // The roots are what everything else is verified against, so each must be
    // covered by the commitment individually.
    type HeaderMutator = fn(&mut bitcoin::blockdata::block::MwebBlockHeader);
    let mutators: [(&str, HeaderMutator); 5] = [
        ("output_root", |h| h.output_root[0] ^= 1),
        ("leafset_root", |h| h.leafset_root[0] ^= 1),
        ("output_mmr_size", |h| h.output_mmr_size ^= 1),
        ("kernel_root", |h| h.kernel_root[0] ^= 1),
        ("height", |h| h.height ^= 1),
    ];
    for (field, mutate) in mutators {
        let mut tampered = good.clone();
        mutate(&mut tampered.mweb_header);
        assert!(
            tampered.verify_anchored(tip_hash).is_err(),
            "tampering with `{field}` was not caught: it is outside the HogEx commitment"
        );
    }

    // Link 3: the HogEx must be the merkle-proven last transaction. Swapping in
    // another transaction from the block breaks the inclusion proof.
    let block = env.rpc.get_block(&tip_hash).expect("block");
    if block.txdata.len() >= 2 {
        let mut swapped = good.clone();
        swapped.hogex = block.txdata[0].clone();
        assert!(
            swapped.verify_anchored(tip_hash).is_err(),
            "a non-HogEx transaction was accepted as the header commitment carrier"
        );
    }

    // Link 4 again, from the other side: a commitment script of the right shape but
    // the wrong hash, and one of the wrong shape.
    let expected = header_hash(&good.mweb_header);
    let mut wrong_hash = good.clone();
    let mut spk = vec![0x58u8, 0x20];
    spk.extend_from_slice(&expected);
    spk[2] ^= 1;
    wrong_hash.hogex.output[0].script_pubkey = ScriptBuf::from_bytes(spk);
    assert!(
        wrong_hash.verify_anchored(tip_hash).is_err(),
        "a commitment to a different hash was accepted"
    );

    let mut wrong_shape = good.clone();
    wrong_shape.hogex.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x00, 0x20]);
    assert!(
        wrong_shape.verify_anchored(tip_hash).is_err(),
        "a malformed commitment script was accepted"
    );

    // Mutating the HogEx at all changes its txid, so the merkle proof fails first.
    // That is the point: the commitment script is pinned by the txid.
    let mut no_outputs = good.clone();
    no_outputs.hogex.output.clear();
    assert!(no_outputs.verify_anchored(tip_hash).is_err());
}

/// F-01d: a full `VerifyMode::Anchored` sync against a real node finds the coin.
///
/// The mutation tests prove `verify_anchored` rejects bad input. This proves it does
/// not reject *good* input in the live path — a check that is too strict to sync
/// against litecoind would be silently disabled by the first user who hit it.
#[test]
fn anchored_sync_against_regtest_finds_the_pegin() {
    use bdk_mweb::lip0006_tcp::TcpMwebPeer;
    use bdk_mweb::mweb_sync::{FixedHeaderProvider, MwebSyncer, ReadyNotifier, SyncState};
    use bdk_mweb::{AddressBook, MwebCoinDatabase, DEFAULT_GAP_LIMIT};

    let Some(env) = try_node_from_env().expect("harness") else {
        return;
    };

    let secp = Secp256k1::new();
    let keys = MasterKeys::from_seed(
        &[0x45u8; 32],
        Network::Regtest,
        MasterKeyScheme::LitecoinCore,
        &secp,
    )
    .expect("keys");
    let book = AddressBook::from_keys(&keys, DEFAULT_GAP_LIMIT, &secp).expect("book");
    let mweb_addr = keys.address(3, Network::Regtest, &secp).expect("address");

    let mining = env.mine_to_pre_mweb().expect("pre-mweb");
    let amount = Amount::from_btc(1.0).unwrap();
    env.finalize_mweb_pegin(&mweb_addr, amount).expect("peg-in");
    env.mine_mweb_activation(&mining).expect("activate");
    env.rpc.generate_to_address(2, &mining).expect("mine");

    let tip = env.rpc.get_block_count().expect("count");
    let tip_hash = env.rpc.get_block_hash(tip).expect("hash");

    let mut peer = TcpMwebPeer::connect(format!("127.0.0.1:{}", env.p2p_port), Network::Regtest)
        .expect("connect");

    let syncer = MwebSyncer {
        verify: VerifyMode::Anchored,
        ..MwebSyncer::tip_only()
    };
    // The header provider stands in for the wallet's own trusted header chain. That
    // independence is the whole basis of anchoring: if `tip_hash` came from the MWEB
    // peer, the check would be circular again.
    let headers = FixedHeaderProvider::tip_only(tip_hash, tip);
    let mut notifier = ReadyNotifier { tip_height: tip };
    let mut state = SyncState::default();
    let mut db = MwebCoinDatabase::new();

    let result = syncer
        .run_once(
            &headers,
            &mut notifier,
            &mut peer,
            &mut state,
            &keys,
            &book,
            &mut db,
            &secp,
            None,
        )
        .expect("anchored sync must succeed against an honest node");

    assert!(
        !result.found.is_empty(),
        "anchored sync did not find the peg-in output"
    );
    assert_eq!(db.balance(), amount.to_sat());
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .filter(|_| !needle.is_empty())
}
