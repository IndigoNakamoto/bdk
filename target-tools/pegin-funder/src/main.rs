//! Peg testnet LTC from the smoke wallet's transparent balance into its own
//! MWEB side (LitecoinCore-scheme keys from the same mnemonic), broadcasting
//! over LIP-0006 P2P. One-off funding step for the mobile smoke apps.

use anyhow::bail;
use bdk_electrum::electrum_client::{Client, ConfigBuilder};
use bdk_electrum::BdkElectrumClient;
use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::lip0006_tcp::{BroadcastAck, TcpMwebPeer};
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Amount, Network};
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::template::Bip84;
use bdk_wallet::{extract_prepared_mweb_pegin, KeychainKind, SignOptions, Wallet};
use std::str::FromStr;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ELECTRUM: &str = "ssl://electrum.ltc.xurious.com:51002";
const PEGIN_AMOUNT: u64 = 200_000;
const MWEB_FEE: u64 = 10_000;
const TRANSPARENT_FEE: u64 = 10_000;

fn main() -> anyhow::Result<()> {
    let network = Network::Testnet4;
    let secp = Secp256k1::new();

    let mnemonic = Mnemonic::from_str(MNEMONIC)?;
    let seed = mnemonic.to_seed("");
    let xprv = bdk_wallet::bitcoin::bip32::Xpriv::new_master(network, &seed)?;
    let mut wallet = Wallet::create(
        Bip84(xprv, KeychainKind::External),
        Bip84(xprv, KeychainKind::Internal),
    )
    .network(network)
    .create_wallet_no_persist()?;

    eprintln!("electrum full scan…");
    let config = ConfigBuilder::new().validate_domain(false).build();
    let client = BdkElectrumClient::new(Client::from_config(ELECTRUM, config)?);
    let request = wallet.start_full_scan().build();
    let update = client.full_scan(request, 20, 20, false)?;
    wallet.apply_update(update)?;
    let balance = wallet.balance();
    eprintln!("transparent balance: {} litoshi", balance.total().to_sat());

    if std::env::args().any(|a| a == "--status") {
        eprintln!("tip: {}", wallet.latest_checkpoint().height());
        for canonical_tx in wallet.transactions() {
            eprintln!("tx {} — {:?}", canonical_tx.txid, canonical_tx.pos);
        }
        return Ok(());
    }

    if balance.total().to_sat() < PEGIN_AMOUNT + MWEB_FEE + TRANSPARENT_FEE {
        bail!("insufficient transparent funds for the peg-in");
    }

    let keys = MasterKeys::from_seed(&seed, network, MasterKeyScheme::LitecoinCore, &secp)?;
    let addr = keys.address(0, network, &secp)?;
    eprintln!("pegging {PEGIN_AMOUNT} litoshi into MWEB address {addr}");

    let mut prepared = wallet.prepare_mweb_pegin(
        &keys,
        0,
        Amount::from_sat(PEGIN_AMOUNT),
        Amount::from_sat(MWEB_FEE),
        Amount::from_sat(TRANSPARENT_FEE),
        &secp,
    )?;
    let finalized = wallet.sign(&mut prepared.psbt, SignOptions::default())?;
    if !finalized {
        for (i, input) in prepared.psbt.inputs.iter().enumerate() {
            eprintln!(
                "input {i}: witness_utxo={} partial_sigs={} final_witness={} bip32_derivations={}",
                input.witness_utxo.is_some(),
                input.partial_sigs.len(),
                input.final_script_witness.is_some(),
                input.bip32_derivation.len(),
            );
        }
        bail!("peg-in PSBT not fully signed");
    }
    let tx = extract_prepared_mweb_pegin(&prepared.psbt)?;
    let txid = tx.compute_txid();

    let peers = bdk_mweb::discovery::discover_mweb_peers(network);
    if peers.is_empty() {
        bail!("no MWEB peers discovered");
    }
    let mut last_err = String::new();
    for addr in peers {
        match TcpMwebPeer::connect(addr, network) {
            Ok(mut peer) => match peer.broadcast_tx(&tx) {
                Ok(BroadcastAck::Confirmed) => {
                    println!("peg-in {txid} accepted by {addr}");
                    return Ok(());
                }
                Ok(BroadcastAck::Sent) => {
                    println!("peg-in {txid} sent to {addr} (ack deadline passed)");
                    return Ok(());
                }
                Err(e) => last_err = format!("{addr}: {e}"),
            },
            Err(e) => last_err = format!("{addr}: {e}"),
        }
    }
    bail!("broadcast failed on every peer: {last_err}");
}
