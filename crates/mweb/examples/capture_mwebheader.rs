//! One-off: capture a mainnet `mwebheader` message as a hex fixture.
//! Usage: cargo run -p bdk_mweb --example capture_mwebheader --features lip0006 -- <block_hash>
//! <out_path>
#![allow(clippy::print_stdout)]
use bdk_mweb::lip0006::MwebUtxoSource;
use bdk_mweb::lip0006_tcp::TcpMwebPeer;
use bitcoin::consensus::serialize;
use bitcoin::Network;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("LITECOIN_P2P").unwrap_or_else(|_| "127.0.0.1:9333".into());
    let block_hash: bitcoin::BlockHash = std::env::args().nth(1).expect("block hash").parse()?;
    let out_path = std::env::args().nth(2).expect("output path");

    let mut peer = TcpMwebPeer::connect(&addr, Network::Bitcoin)?;
    let msg = peer.get_header(block_hash)?;
    msg.verify_anchored(block_hash)?;
    println!("verify_anchored OK for {block_hash}");
    println!("mweb height = {}", msg.mweb_header.height);
    println!("output_mmr_size = {}", msg.mweb_header.output_mmr_size);
    println!("num_transactions = {}", msg.merkle.txn.num_transactions());
    println!("hogex outputs = {}", msg.hogex.output.len());
    let hh: String = bdk_mweb::p2p::header_hash(&msg.mweb_header)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("header_hash = {hh}");
    let hex: String = serialize(&msg).iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&out_path, format!("{hex}\n"))?;
    println!("wrote {} hex chars to {out_path}", hex.len());
    Ok(())
}
