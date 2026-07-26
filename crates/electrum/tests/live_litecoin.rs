//! Live sync tests against a public Electrum-LTC server.
//!
//! These are ignored by default so CI stays offline. Run with:
//!
//! ```bash
//! just test-live
//! # or
//! cargo test -p bdk_electrum --test live_litecoin -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Use a single test thread: the Electrum client's rustls setup races when installing a
//! process-wide `CryptoProvider` from multiple connections at once.

use std::str::FromStr;

use bdk_chain::bitcoin::{constants::genesis_block, Address, BlockHash, Network, Txid};
use bdk_chain::local_chain::LocalChain;
use bdk_chain::spk_client::SyncRequest;
use bdk_chain::{ConfirmationBlockTime, TxGraph};
use bdk_electrum::BdkElectrumClient;

const ELECTRUM_MAINNET: &str = "ssl://electrum-ltc.bysh.me:50002";

/// First seen in tx [`KNOWN_TXID`] at height [`ANCHOR_HEIGHT`].
const P2PKH_ADDR: &str = "LctkjnisKKZcvRtLjMMny9u2uKuMbUhXi8";
/// Same transaction; also exercises the modern Litecoin P2SH (`M...`) prefix.
const P2SH_ADDR: &str = "MUuVUXCmKwc71ZC2wS8hX63JfdEARrjSZb";

const KNOWN_TXID: &str = "dac020122dd97124397bf9a88bf8905501c7cf76289ed22d196b4aa4983ce298";
const ANCHOR_HEIGHT: u32 = 2_000_000;
const ANCHOR_HASH: &str = "3a4d8e7c77a85554fc8bd30d4e42d56eb71010e769ea9737f16241ba79bed9c5";

/// History can grow; assert a floor so the fixture stays usable.
const MIN_TXS: usize = 1;

#[test]
#[ignore = "live network: Electrum-LTC"]
fn electrum_syncs_mainnet_p2pkh_fixture() {
    sync_and_assert(P2PKH_ADDR);
}

#[test]
#[ignore = "live network: Electrum-LTC"]
fn electrum_syncs_mainnet_p2sh_fixture() {
    let address = Address::from_str(P2SH_ADDR)
        .expect("P2SH address must parse")
        .require_network(Network::Bitcoin)
        .expect("M... is Litecoin mainnet");
    assert!(
        address.to_string().starts_with('M'),
        "display must keep the modern Litecoin P2SH prefix, got {}",
        address
    );
    sync_and_assert(P2SH_ADDR);
}

fn sync_and_assert(address: &str) {
    let network = Network::Bitcoin;
    let address = Address::from_str(address)
        .unwrap_or_else(|e| panic!("{address} must parse: {e}"))
        .require_network(network)
        .unwrap_or_else(|e| panic!("{address} must be mainnet: {e}"));
    let known_txid = Txid::from_str(KNOWN_TXID).unwrap();
    let anchor_hash = BlockHash::from_str(ANCHOR_HASH).unwrap();

    let (chain, _) = LocalChain::from_genesis(genesis_block(network).block_hash());

    // Public Electrum-LTC servers present self-signed certificates.
    let config = bdk_electrum::electrum_client::Config::builder()
        .validate_domain(false)
        .build();
    let client = BdkElectrumClient::new(
        bdk_electrum::electrum_client::Client::from_config(ELECTRUM_MAINNET, config)
            .unwrap_or_else(|e| panic!("connect to {ELECTRUM_MAINNET} failed: {e}")),
    );

    let request = SyncRequest::builder()
        .chain_tip(chain.tip())
        .spks([address.script_pubkey()]);
    let response = client
        .sync(request, 1, false)
        .unwrap_or_else(|e| panic!("sync against {ELECTRUM_MAINNET} failed: {e}"));

    let mut graph = TxGraph::<ConfirmationBlockTime>::default();
    let _ = graph.apply_update(response.tx_update);

    let tx_count = graph.full_txs().count();
    assert!(
        tx_count >= MIN_TXS,
        "expected at least {MIN_TXS} txs for {address}, got {tx_count}"
    );

    let node = graph
        .get_tx_node(known_txid)
        .unwrap_or_else(|| panic!("known fixture txid {KNOWN_TXID} must be present for {address}"));

    assert!(
        node.anchors.iter().any(|a| {
            a.block_id.height == ANCHOR_HEIGHT && a.block_id.hash == anchor_hash
        }),
        "txid {KNOWN_TXID} must be anchored at height {ANCHOR_HEIGHT} / {ANCHOR_HASH}, got {:?}",
        node.anchors
    );
}
