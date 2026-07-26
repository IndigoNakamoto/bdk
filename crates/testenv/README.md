# BDK TestEnv

This crate sets up a regtest environment with a single [`bitcoind`] node
connected to an [`electrs`] instance. This framework provides the infrastructure
for testing chain source crates, e.g., [`bdk_chain`], [`bdk_electrum`],
[`bdk_esplora`], etc.

## Status in the Litecoin fork

The harness is Bitcoin-only and does not currently compile. `electrsd` drives Bitcoin Core and is
typed on the upstream `bitcoin` crate, whose types do not unify with the `litecoin` crate the rest
of this fork is built on. Replacing it with `litecoind` plus [`electrs-ltc`] is future work.

What still works, and is what the rest of the workspace uses, is `bdk_testenv::utils`: the
`block_id!`, `hash!`, `local_chain!`, `chain_update!` and `changeset!` macros, plus `new_tx` and
`DESCRIPTORS`. Those have no daemon dependency and are available by default.

Reaching the harness takes two switches, so that `--all-features` builds stay green:

```bash
RUSTFLAGS="--cfg daemon_tests" cargo test --workspace --features bdk_testenv/daemon
```

The `daemon` feature pulls in `electrsd`; the `daemon_tests` cfg compiles the code that uses it.

[`electrs-ltc`]: https://github.com/rust-litecoin/electrs-ltc
