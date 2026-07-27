//! Live check: fetch a mainnet UTXO batch and verify PMMR roots.
//! Usage: LITECOIN_P2P=127.0.0.1:9333 cargo run -p bdk_mweb --example verify_mainnet_batch --features lip0006
use bdk_mweb::lip0006_tcp::TcpMwebPeer;
use bdk_mweb::lip0006::MwebUtxoSource;
use bdk_mweb::p2p::{GetMwebUtxos, OUTPUT_FORMAT_FULL};
use bdk_mweb::pmmr::{verify_leafset, verify_utxo_batch};
use bitcoin::Network;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("LITECOIN_P2P").unwrap_or_else(|_| "127.0.0.1:9333".into());
    let tip_hash: bitcoin::BlockHash = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            // default: ask via RPC if available
            String::new()
        })
        .parse()
        .unwrap_or_else(|_| {
            let out = std::process::Command::new("litecoin-cli")
                .arg("getbestblockhash")
                .output()
                .expect("litecoin-cli");
            String::from_utf8(out.stdout)
                .unwrap()
                .trim()
                .parse()
                .expect("blockhash")
        });
    let start: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(347131);
    let n: u16 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    println!("tip={tip_hash} start={start} n={n} peer={addr}");
    let mut peer = TcpMwebPeer::connect(&addr, Network::Bitcoin)?;
    let hdr = peer.get_header(tip_hash)?;
    let leafset = peer.get_leafset(tip_hash)?;
    verify_leafset(&leafset, &hdr.mweb_header.leafset_root, hdr.mweb_header.output_mmr_size)?;
    println!("leafset ok mmr_size={}", hdr.mweb_header.output_mmr_size);

    let batch = peer.get_utxos(GetMwebUtxos {
        block_hash: tip_hash,
        start_index: start,
        num_requested: n,
        output_format: OUTPUT_FORMAT_FULL,
    })?;
    println!(
        "got utxos={} parents={} first={:?} last={:?}",
        batch.utxos.len(),
        batch.parent_hashes.len(),
        batch.utxos.first().map(|e| e.leaf_index),
        batch.utxos.last().map(|e| e.leaf_index),
    );
    verify_utxo_batch(&batch, &leafset, &hdr.mweb_header)?;
    println!("verify_utxo_batch OK");
    Ok(())
}
