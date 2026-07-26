# BDK Core

This crate is a collection of core structures used by the bdk_chain, bdk_wallet, and bdk chain data source crates.

## Litecoin

This is a Litecoin fork. The `bitcoin` dependency is aliased to the [`litecoin`] crate, so
`bdk_core::bitcoin::Transaction` and friends are Litecoin types; `bdk_core::litecoin` is
re-exported as a clearer spelling of the same crate. See [PORTING.md](../../PORTING.md) for the
full picture, including the two extra MWEB fields on `Transaction`.

[`litecoin`]: https://crates.io/crates/litecoin
