alias b := build
alias c := check
alias f := fmt
alias t := test
alias p := pre-push
alias d := doc

_default:
  @just --list

# Build the project
build:
   cargo build

# Check code: formatting, compilation, linting, and commit signature
check:
   cargo +nightly fmt --all -- --check
   cargo check --workspace --all-features
   cargo clippy --all-features --all-targets -- -D warnings
   @[ "$(git log --pretty='format:%G?' -1 HEAD)" = "N" ] && \
       echo "\n⚠️  Unsigned commit: BDK requires that commits be signed." || \
       true

# Format all code
fmt:
   cargo +nightly fmt

# Run all tests for all crates with all features enabled
# bdk_bitcoind_rpc is absent: it is excluded from the workspace until a Litecoin build of
# bitcoincore-rpc exists. See PORTING.md.
test:
   @just _test-chain
   @just _test-core
   @just _test-electrum
   @just _test-esplora
   @just _test-file_store
   @just _test-testenv

_test-chain:
    cargo test -p bdk_chain --all-features

_test-core:
    cargo test -p bdk_core --all-features

_test-electrum:
    cargo test -p bdk_electrum --all-features

_test-esplora:
    cargo test -p bdk_esplora --all-features

_test-file_store:
    cargo test -p bdk_file_store --all-features

_test-testenv:
    cargo test -p bdk_testenv --all-features

# Live sync against litecoinspace / Electrum-LTC (ignored by default; needs network).
test-live:
    cargo test -p bdk_esplora --test live_litecoin --features blocking-https -- --ignored --nocapture
    cargo test -p bdk_electrum --test live_litecoin -- --ignored --nocapture --test-threads=1

# Regtest against locally provided litecoind + electrs-ltc.
# Requires LITECOIND_EXE and ELECTRS_LTC_EXE. Esplora daemon tests stay gated (no regtest Esplora).
test-regtest:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -z "${LITECOIND_EXE:-}" || -z "${ELECTRS_LTC_EXE:-}" ]]; then
      echo "Set LITECOIND_EXE and ELECTRS_LTC_EXE to absolute binary paths."
      echo "electrs-ltc has no prebuilt releases; build from https://github.com/rust-litecoin/electrs-ltc"
      exit 1
    fi
    cargo test -p bdk_chain --test test_indexed_tx_graph relevant_conflicts -- --exact --nocapture
    cargo test -p bdk_electrum --lib \
      bdk_electrum_client::test:: \
      -- --nocapture --test-threads=1

# Run pre-push suite: format, check, and test
pre-push: fmt check test

# Check documentation for all workspace packages
doc:
   RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
