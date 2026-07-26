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
| `miniscript` | `IndigoNakamoto/rust-miniscript` branch `litecoin` | 13.0.0 |
| `electrum-client` | `IndigoNakamoto/rust-electrum-client` branch `litecoin` | 0.24.1 |
| `esplora-client` | `IndigoNakamoto/rust-esplora-client` branch `litecoin` | 0.12.3 |

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

## Known limitations

These are inherited from the `litecoin` crate and the Litecoin infrastructure, not introduced here.

- **The `litecoin` crate is a pre-release.** `0.32.8-rc.1` is the only published version; there is
  no stable release and the upstream repo publishes no git tags.
- **Legacy P2SH addresses are rejected.** The crate only accepts and emits P2SH as `M…` (mainnet)
  and `Q…` (testnet). Litecoin Core still honors the older `3…` / `2…` forms, so those cannot be
  parsed or paid.
- **litecoinspace does not serve `/fee-estimates`.** The Esplora instance at
  `https://litecoinspace.org/api` (testnet: `https://litecoinspace.org/testnet/api`, *not*
  `/testnet4/api`) implements the endpoints `bdk_esplora` needs for syncing, but
  `esplora_client::get_fee_estimates` will fail against it.
- **Litecoin's "testnet4" is not BIP-94 Testnet4.** It is only the data directory name, present
  since roughly 2017. The chain ID is `test`, there is no `-testnet4` flag, RPC is on 19332 (19335
  is P2P), and Litecoin Core carries no timewarp fix. The `litecoin` crate nonetheless spells this
  network `Network::Testnet4`, which is the sole Litecoin testnet.
- **Litecoin regtest magic is byte-identical to Bitcoin's** (`fabfb5da`), so regtest gives no
  protection against connecting to the wrong daemon. The genesis hashes do differ.
- **Litecoin signet is a stub.** Litecoin Core maps `-signet` onto testnet parameters. Do not use
  it.
