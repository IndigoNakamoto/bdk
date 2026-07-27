//! MWEB (MimbleWimble Extension Blocks) support for Litecoin BDK.
//!
//! Phase 5: stealth keys, receive scan, MWEB→MWEB spend, and peg-in/out authoring
//! without Core key custody. LIP-0006 P2P sync remains deferred — see
//! `docs/MWEB_ARCHITECTURE.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[macro_use]
extern crate alloc;

pub mod address;
pub mod coin_db;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod keys;
pub mod scan;
pub mod tx_builder;

pub use address::{is_mweb_address, parse_mweb_address, receive_address};
pub use coin_db::{MwebCoin, MwebCoinDatabase};
pub use error::Error;
pub use keys::{address_index_tweak, master_keys_from_seed, MasterKeyScheme, MasterKeys};
pub use scan::{
    output_id, rewind_output, scan_litecoin_tx, scan_mweb_tx, scan_outputs, AddressBook,
    DEFAULT_GAP_LIMIT,
};
pub use tx_builder::{
    build_pegin, kernel_id, FinishedMwebPegin, FinishedMwebTx, MwebTxBuilder, CHANGE_ADDRESS_INDEX,
};

pub use bitcoin as litecoin;
