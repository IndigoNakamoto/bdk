# BDK Chain

BDK keychain tracker, tools for storing and indexing chain data.

## Litecoin

This is a Litecoin fork. The `bitcoin` dependency is aliased to the [`litecoin`] crate, so
`bdk_chain::bitcoin::Transaction` and friends are Litecoin types; `bdk_chain::litecoin` is
re-exported as a clearer spelling of the same crate. See [PORTING.md](../../PORTING.md) for the
full picture, including the two extra MWEB fields on `Transaction`.

[`litecoin`]: https://crates.io/crates/litecoin
