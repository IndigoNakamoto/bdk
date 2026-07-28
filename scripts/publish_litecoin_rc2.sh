#!/usr/bin/env bash
# Publish litecoin 0.32.8-rc.2 after PR https://github.com/rust-litecoin/rust-litecoin/pull/9 merges
# (or from the fork branch). Requires crates.io ownership + CARGO_REGISTRY_TOKEN / cargo login.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LTC="${LITECOIN_REPO:-$ROOT/../rust-litecoin}"
cd "$LTC"
cargo test -p litecoin psbt
cargo publish -p litecoin
echo "Published. Remove [patch.crates-io] litecoin path from BDK Cargo.toml files."
