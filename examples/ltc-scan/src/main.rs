//! Scan a Litecoin descriptor against live infrastructure and report what it owns.
//!
//! This is the smallest end-to-end exercise of the Litecoin port: a descriptor goes in, script
//! pubkeys are derived through `miniscript`, a full scan runs against litecoinspace or an
//! Electrum-LTC server, and the resulting transactions are canonicalised by `bdk_chain`. It is
//! watch-only; spending needs `bdk_wallet`.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{anyhow, Context};
use bdk_chain::bitcoin::{constants::genesis_block, Address, Amount, Network};
use bdk_chain::keychain_txout::{FullScanRequestBuilderExt, KeychainTxOutIndex};
use bdk_chain::local_chain::LocalChain;
use bdk_chain::miniscript::descriptor::Descriptor;
use bdk_chain::spk_client::{FullScanRequest, FullScanResponse};
use bdk_chain::{ConfirmationBlockTime, IndexedTxGraph};
use bdk_electrum::BdkElectrumClient;
use bdk_esplora::EsploraExt;
use clap::{Parser, ValueEnum};

const ESPLORA_MAINNET: &str = "https://litecoinspace.org/api";
const ESPLORA_TESTNET: &str = "https://litecoinspace.org/testnet/api";
const ELECTRUM_MAINNET: &str = "ssl://electrum-ltc.bysh.me:50002";
const ELECTRUM_TESTNET: &str = "ssl://electrum-ltc.bysh.me:51002";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Keychain {
    External,
    Internal,
}

impl fmt::Display for Keychain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Keychain::External => write!(f, "external"),
            Keychain::Internal => write!(f, "internal"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Backend {
    Esplora,
    Electrum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Chain {
    Mainnet,
    Testnet,
}

impl From<Chain> for Network {
    fn from(chain: Chain) -> Self {
        match chain {
            Chain::Mainnet => Network::Bitcoin,
            // Litecoin's only testnet. The name is a data directory that predates BIP-94.
            Chain::Testnet => Network::Testnet4,
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Scan a Litecoin descriptor against litecoinspace or an Electrum-LTC server")]
struct Args {
    /// Receive descriptor, for example `wpkh(tpub.../0/*)`.
    descriptor: String,

    /// Change descriptor. Scanned as a second keychain when given.
    #[arg(long)]
    change_descriptor: Option<String>,

    #[arg(long, value_enum, default_value_t = Backend::Esplora)]
    backend: Backend,

    #[arg(long, value_enum, default_value_t = Chain::Mainnet)]
    network: Chain,

    /// Server URL. Defaults to litecoinspace or electrum-ltc.bysh.me for the chosen network.
    #[arg(long)]
    url: Option<String>,

    /// Consecutive unused script pubkeys that end the scan.
    #[arg(long, default_value_t = 20)]
    stop_gap: usize,

    /// Esplora: parallel HTTP requests. Electrum: script pubkeys per batch.
    #[arg(long, default_value_t = 5)]
    batch_size: usize,

    /// Script pubkeys derived past the last revealed index.
    #[arg(long, default_value_t = 25)]
    lookahead: u32,

    /// Require a CA-signed certificate from the Electrum server. Most public Electrum-LTC servers
    /// present self-signed certificates, which is why this is off by default.
    #[arg(long)]
    validate_domain: bool,
}

impl Args {
    fn url(&self) -> &str {
        if let Some(url) = &self.url {
            return url;
        }
        match (self.backend, self.network) {
            (Backend::Esplora, Chain::Mainnet) => ESPLORA_MAINNET,
            (Backend::Esplora, Chain::Testnet) => ESPLORA_TESTNET,
            (Backend::Electrum, Chain::Mainnet) => ELECTRUM_MAINNET,
            (Backend::Electrum, Chain::Testnet) => ELECTRUM_TESTNET,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let network: Network = args.network.into();
    let secp = bdk_chain::bitcoin::secp256k1::Secp256k1::new();

    let mut index = KeychainTxOutIndex::<Keychain>::new(args.lookahead, true);
    let (descriptor, _) = Descriptor::parse_descriptor(&secp, &args.descriptor)
        .context("receive descriptor is not valid")?;
    index.insert_descriptor(Keychain::External, descriptor)?;
    if let Some(change) = &args.change_descriptor {
        let (descriptor, _) = Descriptor::parse_descriptor(&secp, change)
            .context("change descriptor is not valid")?;
        index.insert_descriptor(Keychain::Internal, descriptor)?;
    }

    let mut graph = IndexedTxGraph::<ConfirmationBlockTime, _>::new(index);
    let (mut chain, _) = LocalChain::from_genesis(genesis_block(network).block_hash());

    let url = args.url();
    eprintln!("scanning {network} via {:?} at {url}", args.backend);

    let request = FullScanRequest::builder()
        .chain_tip(chain.tip())
        .spks_from_indexer(&graph.index)
        .inspect(|keychain, index, _| eprint!("\r  derived {keychain} #{index}          "));

    let response = match args.backend {
        Backend::Esplora => scan_esplora(url, request, args.stop_gap, args.batch_size)?,
        Backend::Electrum => scan_electrum(
            url,
            request,
            args.stop_gap,
            args.batch_size,
            args.validate_domain,
        )?,
    };
    eprintln!();

    let FullScanResponse {
        chain_update,
        tx_update,
        last_active_indices,
    } = response;
    if let Some(update) = chain_update {
        chain.apply_update(update)?;
    }
    let _ = graph.index.reveal_to_target_multi(&last_active_indices);
    let _ = graph.apply_update(tx_update);

    report(&chain, &graph, network, &last_active_indices);

    if args.backend == Backend::Esplora {
        match fee_rates(url) {
            Ok(rates) => println!("\nfee rates (sat/vB): {rates}"),
            Err(e) => eprintln!("\nfee rates unavailable: {e}"),
        }
    }

    Ok(())
}

fn scan_esplora(
    url: &str,
    request: bdk_chain::spk_client::FullScanRequestBuilder<Keychain>,
    stop_gap: usize,
    parallel_requests: usize,
) -> anyhow::Result<FullScanResponse<Keychain>> {
    let client = bdk_esplora::esplora_client::Builder::new(url).build_blocking();
    Ok(client.full_scan(request, stop_gap, parallel_requests)?)
}

fn scan_electrum(
    url: &str,
    request: bdk_chain::spk_client::FullScanRequestBuilder<Keychain>,
    stop_gap: usize,
    batch_size: usize,
    validate_domain: bool,
) -> anyhow::Result<FullScanResponse<Keychain>> {
    let config = bdk_electrum::electrum_client::Config::builder()
        .validate_domain(validate_domain)
        .build();
    let client = BdkElectrumClient::new(bdk_electrum::electrum_client::Client::from_config(
        url, config,
    )?);
    Ok(client.full_scan(request, stop_gap, batch_size, true)?)
}

fn report(
    chain: &LocalChain,
    graph: &IndexedTxGraph<ConfirmationBlockTime, KeychainTxOutIndex<Keychain>>,
    network: Network,
    last_active_indices: &BTreeMap<Keychain, u32>,
) {
    let tip = chain.tip().block_id();
    println!("tip:      {} ({})", tip.height, tip.hash);

    let view = chain.canonical_view(graph.graph(), tip, Default::default());
    println!("txs:      {}", view.txs().len());

    for (keychain, index) in last_active_indices {
        println!("last used {keychain} index: {index}");
    }

    let outpoints = graph.index.outpoints().iter().cloned();
    let mut utxos = view
        .filter_unspent_outpoints(outpoints.clone())
        .collect::<Vec<_>>();
    utxos.sort_by_key(|(_, txout)| core::cmp::Reverse(txout.txout.value));

    println!("utxos:    {}", utxos.len());
    for ((keychain, derivation_index), txout) in &utxos {
        let address = Address::from_script(&txout.txout.script_pubkey, network)
            .map(|a| a.to_string())
            .unwrap_or_else(|_| txout.txout.script_pubkey.to_string());
        println!(
            "  {:>16} {address} ({keychain} #{derivation_index}) {}",
            sats(txout.txout.value),
            txout.outpoint,
        );
    }

    // Every script pubkey belongs to the descriptor being scanned, so all of it is trusted.
    let balance = view.balance(outpoints, |_, _| true, 0);
    println!("\nconfirmed:        {}", sats(balance.confirmed));
    println!("pending:          {}", sats(balance.trusted_pending));
    println!("immature:         {}", sats(balance.immature));
    println!("total:            {}", sats(balance.total()));
}

/// The `litecoin` crate inherited rust-bitcoin's `Amount` display, which says "BTC".
fn sats(amount: Amount) -> String {
    format!("{} sat", amount.to_sat())
}

/// litecoinspace serves no `/fee-estimates`, but it does serve the mempool.space style endpoint.
fn fee_rates(base_url: &str) -> anyhow::Result<String> {
    let client = bdk_esplora::esplora_client::Builder::new(base_url).build_blocking();
    let response = client
        .get_request("/v1/fees/recommended")?
        .send()
        .map_err(|e| anyhow!("{e}"))?;
    let body = response.as_str().map_err(|e| anyhow!("{e}"))?;
    let rates: serde_json::Value = serde_json::from_str(body)?;
    Ok(rates.to_string())
}
