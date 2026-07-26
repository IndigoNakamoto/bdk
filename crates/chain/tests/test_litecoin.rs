//! Regression tests for what the `litecoin` alias silently changes.
//!
//! The port swaps the `bitcoin` dependency for `litecoin` without touching any source, so nothing
//! in the BDK test suite notices that the chain changed. These tests pin the differences down.

use std::str::FromStr;

use bdk_chain::bitcoin::{
    address::NetworkUnchecked,
    consensus::{deserialize, serialize},
    constants::genesis_block,
    hex::{DisplayHex, FromHex},
    p2p::Magic,
    Address, Network, Transaction, Txid,
};
use bdk_chain::{ConfirmationBlockTime, Merge, TxGraph};

/// A real mainnet HogEx transaction: the last transaction of block 3,149,263.
///
/// HogEx ("Hogwarts Express") transactions bridge value in and out of the MWEB extension block.
/// They are serialized with segwit flag bit `0x08` set and no MWEB body, which the upstream
/// `bitcoin` decoder rejects outright.
const HOGEX_TX_HEX: &str = "02000000000802bb03318fafc391a712d7f91a62cc9d1c505d50510b393e6ad91a8a47fcdd5b780000000000ffffffff57eee2ab0d098d12f89ce605c9d557c4260b254c61561789e41c0dc3a1e6754f0000000000ffffffff031b418561f5250000225820fd5fdb1335f2798d173cc602b6dc167acc7f8d927cae162cb1cb822789ea7899ec0e6e040000000016001428ea10e4b98adffc8c8169fb4adcab8fb739aa3260dcdb4b00000000160014f9ab13f3deb53dd5e50be7927a9ab4ecb6f2df3b0000000000";

const HOGEX_TXID: &str = "9fead093fdf13adf4eb7c2cedff68dbdca6646f3d1be30cbe3e1eb78cdb9fa60";

#[test]
fn genesis_hashes_are_litecoins() {
    assert_eq!(
        genesis_block(Network::Bitcoin).block_hash().to_string(),
        "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2",
    );
    assert_eq!(
        genesis_block(Network::Testnet4).block_hash().to_string(),
        "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0",
    );
    assert_eq!(
        genesis_block(Network::Regtest).block_hash().to_string(),
        "530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9",
    );
}

#[test]
fn network_magic_is_litecoins() {
    assert_eq!(
        Network::Bitcoin.magic(),
        Magic::from_bytes([0xfb, 0xc0, 0xb6, 0xdb])
    );
    assert_eq!(
        Network::Testnet4.magic(),
        Magic::from_bytes([0xfd, 0xd2, 0xc8, 0xf1])
    );

    // Litecoin regtest reuses Bitcoin's magic verbatim, so connecting to the wrong daemon on
    // regtest fails no earlier than the genesis hash check.
    assert_eq!(
        Network::Regtest.magic(),
        Magic::from_bytes([0xfa, 0xbf, 0xb5, 0xda])
    );
}

#[test]
fn addresses_round_trip() {
    let cases = [
        ("LXLjh9AFmeSjQZEM7qNaKk735Jp43f3SNf", Network::Bitcoin),
        ("MQmSgrLBGkwxsaqULx1MsAYLywd6qpoMCN", Network::Bitcoin),
        (
            "ltc1qsn57m9drscflq5nl76z6ny52hck5w4x52uhpum",
            Network::Bitcoin,
        ),
        ("msdjiywQW1dvvs1ofGMeseFbj63Ukq6muV", Network::Testnet4),
        ("QdUGZiiUxCeyR3xAYJfukAie1ygeWnvLJX", Network::Testnet4),
        (
            "tltc1qsn57m9drscflq5nl76z6ny52hck5w4x5aw5g03",
            Network::Testnet4,
        ),
    ];

    for (address, network) in cases {
        let parsed = Address::from_str(address)
            .unwrap_or_else(|e| panic!("{address} must parse: {e}"))
            .require_network(network)
            .unwrap_or_else(|e| panic!("{address} must be valid on {network}: {e}"));
        assert_eq!(parsed.to_string(), address);
    }
}

#[test]
fn bitcoin_addresses_are_rejected() {
    for address in [
        "1D7nRvrRgzCg9kYBwhPH3j3Gs6SmsRg3Wq",
        "bc1qsn57m9drscflq5nl76z6ny52hck5w4x5wqd9yt",
    ] {
        let parsed = Address::from_str(address)
            .ok()
            .and_then(|a: Address<NetworkUnchecked>| a.require_network(Network::Bitcoin).ok());
        assert!(
            parsed.is_none(),
            "{address} is a Bitcoin address and must not parse"
        );
    }
}

/// Litecoin Core keeps the older `3…` (mainnet) and `2…` (testnet) P2SH prefixes it inherited from
/// Bitcoin spendable alongside the `M…` / `Q…` forms. The `litecoin` crate accepts both on parse
/// but always renders the modern form, so an address paid in the legacy form comes back out of BDK
/// looking different.
#[test]
fn legacy_p2sh_addresses_parse_and_are_normalised() {
    for (legacy, modern, network) in [
        (
            "3JZJNxvDKe6Y55ZaF5223XHwfF2eoMNnoV",
            "MQmSgrLBGkwxsaqULx1MsAYLywd6qpoMCN",
            Network::Bitcoin,
        ),
        (
            "2NA7WShrEw6btGsC7vCdtfUHCsbEpbsuRtd",
            "QdUGZiiUxCeyR3xAYJfukAie1ygeWnvLJX",
            Network::Testnet4,
        ),
    ] {
        let parsed = legacy
            .parse::<Address<NetworkUnchecked>>()
            .unwrap_or_else(|e| panic!("{legacy} must parse: {e}"))
            .require_network(network)
            .unwrap_or_else(|e| panic!("{legacy} must be valid on {network}: {e}"));

        assert_eq!(
            parsed.to_string(),
            modern,
            "the legacy form is not preserved"
        );
        assert_eq!(
            parsed.script_pubkey(),
            modern
                .parse::<Address<NetworkUnchecked>>()
                .unwrap()
                .assume_checked()
                .script_pubkey()
        );
    }
}

#[test]
fn decodes_mainnet_hogex_transaction() {
    let raw = Vec::from_hex(HOGEX_TX_HEX).unwrap();
    let tx: Transaction = deserialize(&raw).expect("HogEx transaction must decode");

    assert!(
        tx.is_hog_ex,
        "flag bit 0x08 with no MWEB body marks a HogEx transaction"
    );
    assert!(tx.mw_tx.is_none(), "HogEx transactions carry no MWEB body");
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 3);

    assert_eq!(tx.compute_txid(), Txid::from_str(HOGEX_TXID).unwrap());
    assert_eq!(
        serialize(&tx).to_lower_hex_string(),
        HOGEX_TX_HEX,
        "re-encoding must reproduce the wire bytes, MWEB marker included",
    );
}

/// A transparent-only wallet still has to cope with HogEx transactions, because every block after
/// MWEB activation ends with one.
#[test]
fn tx_graph_ingests_hogex_transaction() {
    let raw = Vec::from_hex(HOGEX_TX_HEX).unwrap();
    let tx: Transaction = deserialize(&raw).unwrap();
    let txid = tx.compute_txid();

    let mut graph = TxGraph::<ConfirmationBlockTime>::default();
    let changeset = graph.insert_tx(tx.clone());
    assert!(!changeset.is_empty());

    let stored = graph
        .get_tx(txid)
        .expect("transaction must be in the graph");
    assert_eq!(*stored, tx);
    assert_eq!(
        graph.floating_txouts().count(),
        0,
        "all outputs belong to the transaction itself",
    );
}
