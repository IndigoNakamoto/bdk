//! MWEB (MimbleWimble Extension Blocks) support for Litecoin BDK.
//!
//! Phase 2 provides Core-compatible stealth key derivation and a secp256k1-zkp FFI façade.
//! Scan, spend, and coin DB land in later phases — see `docs/MWEB_ARCHITECTURE.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[macro_use]
extern crate alloc;

pub mod address;
pub mod coin_db;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod scan;
pub mod tx_builder;

pub use address::{is_mweb_address, parse_mweb_address, receive_address};
pub use error::Error;
pub use keys::{address_index_tweak, master_keys_from_seed, MasterKeyScheme, MasterKeys};

pub use bitcoin as litecoin;
