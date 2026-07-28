//! MWEB (MimbleWimble Extension Blocks) support for Litecoin BDK.
//!
//! Stealth keys, receive scan, MWEB→MWEB spend, peg-in/out authoring, and (with
//! feature `persist`) a parallel `ChangeSet` for coin persistence. Optional
//! `rusqlite` / `encrypt` / `lip0006` backends. See `docs/MWEB_ARCHITECTURE.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

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
pub mod scan;
#[cfg(feature = "serde")]
mod serde_util;
#[cfg(feature = "rusqlite")]
pub mod sqlite;
pub mod psbt;
pub mod psbt_fund;
pub mod tx_builder;

pub use address::{is_mweb_address, parse_mweb_address, receive_address};
#[cfg(feature = "persist")]
pub use changeset::ChangeSet;
pub use coin_db::{MwebBalance, MwebCoin, MwebCoinDatabase, MWEB_PEGIN_MATURITY};
#[cfg(feature = "encrypt")]
pub use encrypt::{open, seal};
#[cfg(all(feature = "encrypt-changeset"))]
pub use encrypt::{open_changeset, seal_changeset};
pub use error::Error;
pub use keys::{address_index_tweak, master_keys_from_seed, MasterKeyScheme, MasterKeys};
pub use psbt::{
    enrich_input_from_coin, extract_tx_with_mweb, is_mweb_complete, mweb_input_from_wire,
    mweb_kernel_from_wire, mweb_output_from_wire, populate_pegin_psbt, populate_psbt_from_mw,
    psbt_from_finished_mweb_tx, scrub_sensitive_fields, sign_mweb_components, MwebPsbtInput,
    MwebPsbtKernel, MwebPsbtOutput, MWEB_KERNEL_COUNT_TYPE, MWEB_TX_OFFSET_TYPE,
    MWEB_TX_STEALTH_OFFSET_TYPE,
};
#[allow(deprecated)]
pub use psbt::MwebPsbt;
pub use psbt_fund::{
    change_from_funded, fund_mweb_spend, sign_funded_mweb, FundedMwebPsbt, StagedMwebOutput,
};
pub use scan::{
    output_id, rewind_output, scan_litecoin_tx, scan_litecoin_tx_at, scan_mweb_tx, scan_mweb_tx_at,
    scan_outputs, scan_outputs_at, scan_utxo_entries_at, AddressBook, DEFAULT_GAP_LIMIT,
};
pub use tx_builder::{
    build_pegin, kernel_id, FinishedMwebPegin, FinishedMwebTx, MwebTxBuilder, CHANGE_ADDRESS_INDEX,
};

pub use bitcoin as litecoin;
