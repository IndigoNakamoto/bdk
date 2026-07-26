//! Litecoin regression tests for the Electrum deserialization path.
//!
//! Electrum serves transactions as raw consensus bytes, so this needs no running node: it decodes
//! a captured mainnet transaction with the client's own `bitcoin` re-export and then hands it to
//! `bdk_chain`, which only compiles if both crates agree on the `Transaction` type.

use std::str::FromStr;

use bdk_chain::{ConfirmationBlockTime, TxGraph};
use bdk_electrum::electrum_client::bitcoin::{
    consensus::deserialize, hex::FromHex, Transaction, Txid,
};

/// A real mainnet HogEx transaction, the last transaction of block 3,149,263. The `0x08` segwit
/// flag bit that marks it would make the upstream `bitcoin` decoder fail.
const HOGEX_TX_HEX: &str = "02000000000802bb03318fafc391a712d7f91a62cc9d1c505d50510b393e6ad91a8a47fcdd5b780000000000ffffffff57eee2ab0d098d12f89ce605c9d557c4260b254c61561789e41c0dc3a1e6754f0000000000ffffffff031b418561f5250000225820fd5fdb1335f2798d173cc602b6dc167acc7f8d927cae162cb1cb822789ea7899ec0e6e040000000016001428ea10e4b98adffc8c8169fb4adcab8fb739aa3260dcdb4b00000000160014f9ab13f3deb53dd5e50be7927a9ab4ecb6f2df3b0000000000";

const HOGEX_TXID: &str = "9fead093fdf13adf4eb7c2cedff68dbdca6646f3d1be30cbe3e1eb78cdb9fa60";

#[test]
fn electrum_decodes_hogex_transaction() {
    let raw = Vec::from_hex(HOGEX_TX_HEX).unwrap();
    let tx: Transaction = deserialize(&raw).expect("HogEx transaction must decode");

    assert!(tx.is_hog_ex);
    assert_eq!(tx.compute_txid(), Txid::from_str(HOGEX_TXID).unwrap());
}

#[test]
fn tx_graph_ingests_electrum_hogex_transaction() {
    let raw = Vec::from_hex(HOGEX_TX_HEX).unwrap();
    let tx: Transaction = deserialize(&raw).unwrap();
    let txid = tx.compute_txid();

    let mut graph = TxGraph::<ConfirmationBlockTime>::default();
    let _ = graph.insert_tx(tx.clone());

    assert_eq!(
        *graph
            .get_tx(txid)
            .expect("transaction must be in the graph"),
        tx,
        "electrum_client and bdk_chain must agree on the Transaction type",
    );
}
