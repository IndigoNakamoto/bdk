# BDK TestEnv

Utilities and optional regtest harnesses for BDK chain-source crates.

## Always available: `utils`

`bdk_testenv::utils` provides the `block_id!`, `hash!`, `local_chain!`, `chain_update!` and
`changeset!` macros, plus `new_tx` and `DESCRIPTORS`. Those have no daemon dependency and are what
the default workspace test run uses.

## Litecoin regtest: `litecoin-daemon`

Feature `litecoin-daemon` exposes `LitecoinTestEnv`, which spawns locally provided binaries:

| Env var | Binary |
| --- | --- |
| `LITECOIND_EXE` | Litecoin Core `litecoind` |
| `ELECTRS_LTC_EXE` | [`electrs-ltc`](https://github.com/rust-litecoin/electrs-ltc) |

When either variable is unset, `try_from_env()` returns `Ok(None)` and tests that call it skip with
a printed notice. There is no packaged regtest Esplora for Litecoin, so Esplora daemon coverage
stays on live testnet (`just test-live`).

```bash
export LITECOIND_EXE=/path/to/litecoind
export ELECTRS_LTC_EXE=/path/to/electrs
just test-regtest
```

`electrs-ltc` has no prebuilt releases and must be built from source.

## Bitcoin-only harness (upstream merge aid)

The original `TestEnv` (`bitcoind` + `electrs` via `electrsd`) does not compile against the
`litecoin` alias. It remains behind the non-default `daemon` feature plus `RUSTFLAGS='--cfg
daemon_tests'` so upstream merges stay clean and `--all-features` stays green:

```bash
RUSTFLAGS="--cfg daemon_tests" cargo test --workspace --features bdk_testenv/daemon
```
