//! Litecoin regression tests for the Esplora deserialization path.
//!
//! These do not need a running node: they replay a response captured from litecoinspace.org.

use bdk_chain::{ConfirmationBlockTime, TxGraph};
use bdk_esplora::esplora_client::api::Tx;

/// The Esplora response for a real mainnet HogEx transaction, the last transaction of block
/// 3,149,263. HogEx transactions bridge value in and out of the MWEB extension block, and every
/// block since MWEB activation ends with one, so even a transparent-only wallet meets them.
const HOGEX_TX_JSON: &str = include_str!("data/hogex_tx.json");

const HOGEX_TXID: &str = "9fead093fdf13adf4eb7c2cedff68dbdca6646f3d1be30cbe3e1eb78cdb9fa60";

#[test]
fn esplora_decodes_hogex_transaction() {
    let api_tx: Tx = serde_json::from_str(HOGEX_TX_JSON).expect("response must deserialize");
    assert_eq!(api_tx.txid.to_string(), HOGEX_TXID);

    let tx = api_tx.to_tx();
    assert_eq!(
        tx.compute_txid().to_string(),
        HOGEX_TXID,
        "the rebuilt transaction must hash to the same txid",
    );

    // Esplora's JSON says nothing about MWEB, so the rebuilt transaction is plain transparent even
    // though the wire encoding of this one carries the HogEx marker. The txid is unaffected.
    assert!(tx.mw_tx.is_none());
    assert!(!tx.is_hog_ex);
}

#[test]
fn tx_graph_ingests_esplora_hogex_transaction() {
    let api_tx: Tx = serde_json::from_str(HOGEX_TX_JSON).unwrap();
    let tx = api_tx.to_tx();
    let txid = tx.compute_txid();

    let mut graph = TxGraph::<ConfirmationBlockTime>::default();
    let _ = graph.insert_tx(tx.clone());

    assert_eq!(
        *graph
            .get_tx(txid)
            .expect("transaction must be in the graph"),
        tx,
        "esplora_client and bdk_chain must agree on the Transaction type",
    );
}
