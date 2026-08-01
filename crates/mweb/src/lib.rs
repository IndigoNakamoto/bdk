//! MWEB (MimbleWimble Extension Blocks) support for Litecoin BDK.
//!
//! Stealth keys, receive scan, MWEB→MWEB spend, peg-in/out authoring, and (with
//! feature `persist`) a parallel `ChangeSet` for coin persistence. Optional
//! `rusqlite` / `encrypt` / `lip0006` backends. See `docs/MWEB_ARCHITECTURE.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
// Sync/P2P helpers intentionally log with eprintln until a shared log facade is wired;
// several LIP-0006 entry points exceed the default argument threshold by design.
#![allow(clippy::print_stderr)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

#[macro_use]
extern crate alloc;

pub mod address;
#[cfg(feature = "persist")]
pub mod changeset;
pub mod coin_db;
pub mod crypto;
#[cfg(feature = "encrypt")]
pub mod encrypt;
pub mod error;
pub mod hash;
pub mod keys;
pub mod limits;
#[cfg(feature = "lip0006")]
pub mod lip0006;
#[cfg(feature = "lip0006")]
pub mod lip0006_tcp;
#[cfg(feature = "lip0006")]
pub mod mweb_sync;
#[cfg(feature = "lip0006")]
pub mod p2p;
#[cfg(feature = "lip0006")]
pub mod pmmr;
pub mod psbt;
pub mod psbt_fund;
pub mod psbt_ltcd;
pub mod scan;
pub mod secret;
#[cfg(feature = "serde")]
mod serde_util;
#[cfg(feature = "rusqlite")]
pub mod sqlite;
pub mod tx_builder;

pub use address::{is_mweb_address, parse_mweb_address, receive_address};
#[cfg(feature = "persist")]
pub use changeset::ChangeSet;
pub use coin_db::{MwebBalance, MwebCoin, MwebCoinDatabase, MWEB_PEGIN_MATURITY};
#[cfg(feature = "encrypt")]
pub use encrypt::{
    is_v2, open, open_with_context, open_with_context_at_least, seal, seal_with_context,
    seal_with_context_and_counter, SealContext,
};
#[cfg(feature = "encrypt-changeset")]
pub use encrypt::{
    open_changeset, open_changeset_with_context, seal_changeset, seal_changeset_with_context,
};
pub use error::Error;
pub use keys::{address_index_tweak, master_keys_from_seed, MasterKeyScheme, MasterKeys};
#[allow(deprecated)]
pub use psbt::MwebPsbt;
pub use psbt::{
    enrich_input_from_coin, extract_tx_with_mweb, is_mweb_complete, mweb_input_from_wire,
    mweb_kernel_from_wire, mweb_output_from_wire, populate_mweb_key_origins, populate_pegin_psbt,
    populate_psbt_from_mw, psbt_from_finished_mweb_tx, scrub_sensitive_fields,
    sign_mweb_components, validate_mweb_key_origins, validate_mweb_key_origins_against,
    MwebPsbtInput, MwebPsbtKernel, MwebPsbtOutput, MWEB_KERNEL_COUNT_TYPE,
    MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE, MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE, MWEB_TX_OFFSET_TYPE,
    MWEB_TX_STEALTH_OFFSET_TYPE,
};
pub use psbt_fund::{
    change_from_funded, fund_mweb_pegin, fund_mweb_spend, sign_funded_mweb, sign_funded_mweb_pegin,
    FundedMwebPegin, FundedMwebPsbt, StagedMwebOutput,
};
pub use psbt_ltcd::psbt_from_ltcd_v2;
pub use scan::{
    output_id, rewind_output, scan_litecoin_tx, scan_litecoin_tx_at, scan_mweb_tx, scan_mweb_tx_at,
    scan_outputs, scan_outputs_at, scan_utxo_entries_at, AddressBook, DEFAULT_GAP_LIMIT,
};
pub use secret::{ct_eq32, ct_eq32_opt, Secret32};
#[allow(deprecated)]
pub use tx_builder::build_pegin;
pub use tx_builder::{
    kernel_id, FinishedMwebPegin, FinishedMwebTx, MwebTxBuilder, CHANGE_ADDRESS_INDEX,
};

pub use bitcoin as litecoin;
