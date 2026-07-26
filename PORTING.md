# Porting BDK to Litecoin

This branch (`litecoin`) is a fork of [bitcoindevkit/bdk](https://github.com/bitcoindevkit/bdk)
that targets Litecoin instead of Bitcoin. It is maintained as a thin, re-appliable layer on top of
upstream so that `git merge upstream/master` stays cheap.

## Strategy: alias, don't rewrite

Crate names stay `bdk_*` and every `use bitcoin::` path in the source is left untouched. The swap
happens entirely in the manifests, using Cargo's dependency renaming:

```toml
bitcoin = { package = "litecoin", version = "0.32.8-rc.1", default-features = false }
```

The [`litecoin`](https://crates.io/crates/litecoin) crate is a fork of `rust-bitcoin` 0.32.x that
mirrors its module layout, so the rename is sufficient: `bdk_core` compiles against it with zero
source changes. This is the same pattern
[rust-litecoin/electrs-ltc](https://github.com/rust-litecoin/electrs-ltc) runs in production behind
litecoinspace.org.

Because the dependency is renamed rather than replaced, the existing `pub use bitcoin;` re-exports
in `bdk_core` and `bdk_chain` keep working, and downstream code still writes
`bdk_chain::bitcoin::Transaction` — it simply resolves to Litecoin types. Both crates also re-export
it as `litecoin` for clarity.

## Why the dependency forks exist

`miniscript`, `electrum-client`, and `esplora-client` are typed on `bitcoin::Transaction`. Wire
compatibility is irrelevant here: `litecoin::Transaction` is a distinct Rust type, so those crates
would not unify with `bdk_core`'s types. Each is forked with the same one-line manifest alias and
nothing else, keeping the upstream *package* names so BDK manifests only change their source.

| Dependency | Fork | Upstream base |
| --- | --- | --- |
| `miniscript` | `IndigoNakamoto/rust-miniscript` branch `litecoin-12.x` | 12.3.7 |
| `electrum-client` | `IndigoNakamoto/rust-electrum-client` branch `litecoin` | 0.24.1 |
| `esplora-client` | `IndigoNakamoto/rust-esplora-client` branch `litecoin` | 0.12.3 |

### Why miniscript sits on the 12.x line

Upstream `bdk_chain` master requires `miniscript` 13, but `bdk_wallet` 3.1.0 requires `^12.3.1`, and
two majors of the same crate cannot coexist in one dependency graph. Since `bdk_chain` only touches
`Descriptor`, `DescriptorPublicKey`, `at_derivation_index`, and `derived_descriptor` — all
unchanged across the 12/13 boundary — moving the chain crate down to 12.x costs nothing, while
moving the wallet up would mean rewriting `policy.rs`, `dsl.rs`, and `signer.rs` against
miniscript 13's Taproot and error-type rewrite.

A port of 13.1.0 also exists, on the `litecoin` branch of the same fork. It is parked until
`bdk_wallet` upstream moves to miniscript 13.

The `litecoin` crate depends on unforked `secp256k1`, `bitcoin_hashes`, `bitcoin-internals`,
`bitcoin-io`, and `base58ck`, so the dependency tree stays shared with the rust-bitcoin ecosystem
and no duplicate types appear.

## Scope

Ported: `bdk_core`, `bdk_chain`, `bdk_file_store`, `bdk_electrum`, `bdk_esplora`, and the
dependency-free parts of `bdk_testenv`.

Deferred:

- **`bdk_bitcoind_rpc`** — needs a `bitcoincore-rpc` 0.19 fork. The only Litecoin-aware fork
  (`ynohtna92/rust-bitcoincore-rpc`) is 0.17, unpublished, and last touched in February 2024.
- **Daemon-backed integration tests** — `bdk_testenv`'s `TestEnv` drives `electrsd` plus a
  downloaded Bitcoin Core binary. Replacing it with `litecoind` + `electrs-ltc` is its own project;
  until then that surface lives behind the non-default `daemon` feature.
- **`bdk_wallet`** — descriptors, address generation, and PSBT live in a separate upstream repo.

## Merging upstream

`master` tracks `upstream/master` unmodified. To take a new upstream release:

```bash
git checkout master && git pull upstream master
git checkout litecoin && git merge master
```

Conflicts should be confined to manifests. If a conflict appears in `.rs` files, that is a signal
the port is drifting from the alias-only approach and should be corrected rather than patched over.

## What the alias changes in the API

Almost nothing, with one exception worth knowing about: `litecoin::Transaction` has two fields that
`bitcoin::Transaction` does not, `mw_tx: Option<mimblewimble::Transaction>` and `is_hog_ex: bool`.
Struct literals therefore have to initialise them, which accounts for most of the source diff
against upstream. There is no `Default` impl to fall back on.

Both fields are decode-only for a transparent wallet. Every block since MWEB activation ends with a
HogEx ("Hogwarts Express") transaction that bridges value in and out of the extension block; it is
serialized with segwit flag bit `0x08` set, which the upstream `bitcoin` decoder rejects outright.
`crates/chain/tests/test_litecoin.rs` pins this down against a real mainnet transaction.

## Running the Bitcoin-only test harness

`bdk_testenv`'s `TestEnv` does not currently compile, because `electrsd` is typed on the upstream
`bitcoin` crate. Reaching it takes two switches, which is deliberate: the `daemon` cargo feature
pulls in the dependency, and the `daemon_tests` cfg compiles the code. Keeping them separate means
`--all-features` stays green.

```bash
RUSTFLAGS="--cfg daemon_tests" cargo test --workspace --features bdk_testenv/daemon
```

Every test that needs a node is gated the same way, so the default test run covers only what works
against Litecoin today.

## Known limitations

These are inherited from the `litecoin` crate and the Litecoin infrastructure, not introduced here.

- **The `litecoin` crate is a pre-release.** `0.32.8-rc.1` is the only published version; there is
  no stable release and the upstream repo publishes no git tags.
- **Legacy P2SH addresses are silently renamed.** Litecoin Core keeps the `3…` (mainnet) and `2…`
  (testnet) P2SH prefixes it inherited from Bitcoin spendable alongside `M…` and `Q…`. The crate
  parses all four, but always renders the modern form, so an address handed to BDK in the legacy
  form comes back out looking different. The script and the funds are the same.
- **litecoinspace does not serve `/fee-estimates`.** The Esplora instance at
  `https://litecoinspace.org/api` (testnet: `https://litecoinspace.org/testnet/api`, *not*
  `/testnet4/api`) implements the endpoints `bdk_esplora` needs for syncing, but
  `esplora_client::get_fee_estimates` returns 404 against it.
- **Litecoin's "testnet4" is not BIP-94 Testnet4.** It is only the data directory name, present
  since roughly 2017. The chain ID is `test`, there is no `-testnet4` flag, RPC is on 19332 (19335
  is P2P), and Litecoin Core carries no timewarp fix. The `litecoin` crate nonetheless spells this
  network `Network::Testnet4`, and it is the sole Litecoin testnet.
- **Mainnet is spelled `Network::Bitcoin`.** The fork kept rust-bitcoin's variant names, so the
  enum reads oddly but behaves correctly.
- **Litecoin regtest magic is byte-identical to Bitcoin's** (`fabfb5da`), so regtest gives no
  protection against connecting to the wrong daemon. The genesis hashes do differ.
- **Litecoin signet is a stub.** Litecoin Core maps `-signet` onto testnet parameters. Do not use
  it.
