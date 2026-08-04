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

Ported: `bdk_core`, `bdk_chain`, `bdk_file_store`, `bdk_electrum`, `bdk_esplora`, and
`bdk_testenv` (including the Litecoin regtest harness). Wallet work lives in the separate
[`IndigoNakamoto/bdk_wallet`](https://github.com/IndigoNakamoto/bdk_wallet) `litecoin` branch.

Deferred:

- **Regtest Esplora** — there is no packaged Litecoin regtest Esplora server, so Esplora coverage
  stays on live testnet (`just test-live`). Chain/Electrum daemon tests use `litecoind` +
  `electrs-ltc` via `just test-regtest` (**Electrum-first**).
- **miniscript 13** — parked until upstream `bdk_wallet` moves off 12.x.

Ported extras:

- **`bdk_bitcoind_rpc`** — uses a vendored `bitcoincore-rpc` 0.19 with `bitcoin → litecoin`
  alias ([`vendor/bitcoincore-rpc`](./vendor/bitcoincore-rpc)). Litecoin emitter smoke test:
  `cargo test -p bdk_bitcoind_rpc --test test_emitter_litecoin` (needs `LITECOIND_EXE`).
  Upstream Bitcoin `TestEnv` tests are parked as `*.upstream`.

For upstream PRs to rust-litecoin or BDK, see
[`docs/REVIEWERS_GUIDE.md`](docs/REVIEWERS_GUIDE.md) (why / false paths / live proof).

## Repo topology and dependency pinning

The fork ecosystem mirrors upstream's repo boundaries, but since the crates
are not published to crates.io (the `bdk_*` names belong upstream), the repos
link through **rev-pinned git dependencies** instead of registry versions:

```
rust-litecoin  ←  bdk (this repo)  ←  bdk_wallet  ←  bdk-ffi      → AAR / xcframework / ltc-swift
   (patch)                  ↖︎______________↖︎______  ltc-wallet-mac → macOS/Linux app
```

- [`IndigoNakamoto/bdk`](https://github.com/IndigoNakamoto/bdk) (this repo, `litecoin` branch)
  holds the core crates (`bdk_chain`, `bdk_electrum`, `bdk_esplora`, `bdk_mweb`, …) and patches
  crates-io `litecoin` to a pinned rev of
  [`IndigoNakamoto/rust-litecoin`](https://github.com/IndigoNakamoto/rust-litecoin).
- [`IndigoNakamoto/bdk_wallet`](https://github.com/IndigoNakamoto/bdk_wallet) (`litecoin` branch)
  pins this repo's crates by rev in its `Cargo.toml`.
- [`IndigoNakamoto/bdk-ffi`](https://github.com/IndigoNakamoto/bdk-ffi) (`litecoin-mweb` branch)
  pins `bdk_wallet` and this repo by rev. Its CI asserts the bdk rev it pins matches the one its
  pinned `bdk_wallet` pins (`scripts/check-rev-coherence.sh`).
- [`ltc-wallet-mac`](https://github.com/IndigoNakamoto/ltc-wallet-mac) pins `bdk_wallet` and this
  repo by rev the same way.

**Coherence rule:** every consumer must pin the *same* `bdk.git` rev that its pinned `bdk_wallet`
rev pins internally. If they diverge, Cargo treats them as two different sources, builds two copies
of `bdk_chain`/`bdk_mweb`, and the build fails on type mismatches (loudly, which is the point).
The same applies to the `litecoin` crates-io patch rev.

**Bumping revs** (order matters, leaves to root):

1. Push the change to this repo (`litecoin` branch); note the new SHA.
2. In `bdk_wallet`, update every `bdk.git` rev to that SHA, build, push; note the new SHA.
3. In `bdk-ffi` and `ltc-wallet-mac`, update the `bdk_wallet.git` rev *and* the `bdk.git` revs
   (to the SHA from step 1), rebuild so `Cargo.lock` updates, push.

**Local development:** to hack across repos without pushing, add `[patch]` overrides in a
gitignored `.cargo/config.toml` at the consumer's root pointing at sibling checkouts — see the
"Local development" section of each consumer's README. The committed manifests always keep the
pinned revs.

**Publishing story:** the distribution artifacts are the Android AAR + Swift xcframework from
bdk-ffi's release workflow, the [`ltc-swift`](https://github.com/IndigoNakamoto/ltc-swift) SwiftPM
tag, and ltc-wallet-mac's app bundles. Publishing the Rust crates to crates.io would require
renaming them (e.g. an `ltc-` prefix), since the `bdk_*` names are owned upstream; that is a
possible future step, not a current one.

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

### HogAddr vs peg-out (Phase 0)

Do **not** skip every HogEx output. HogEx also carries **peg-out** transparent outputs (normal
p2wpkh/p2tr) that are real spendable UTXOs. The indexer filters only MWEB **bridge** scripts:

| Witness version | Role | Indexed as spendable? |
| --- | --- | --- |
| v8 | HogAddr (integration balance) | No |
| v9 | Peg-in (`WITNESS_MWEB_PEGIN`) | No |
| v0 / v1 / … | Peg-outs and ordinary payments | Yes, if watched |

Helper: `bdk_chain::is_mweb_bridge_output`. See also [`docs/MWEB_PEGIN.md`](docs/MWEB_PEGIN.md).

### Peg-in / peg-out (Phases 1 + 5)

The v9 program is a **kernel id** (`Kernel::GetHash`). Phase 1 wallet glue
(`add_mweb_pegin` / `attach_mweb_tx`) still applies; Phase 5 BDK authors the `mw_tx` body.

- `bdk_mweb::build_pegin` → `FinishedMwebPegin { mw_tx, kernel_id, … }`; wallet
  `prepare_mweb_pegin` / `TxBuilder::apply_mweb_pegin` (feature `mweb`) or `add_mweb_pegin` + attach.
- `Wallet::build_mweb_pegout` / `MwebTxBuilder::add_pegout` → HogEx credit.
- Core `sendtoaddress` finalize remains a supported alternate for peg-in.
- Empty stealth SPKs raise `CreateTxError::MwebPegInRequiresKernel`.

See [`docs/MWEB_PEGIN.md`](docs/MWEB_PEGIN.md).

### MWEB crypto + receive + spend + facade (Phases 2–6)

Architecture ADR: [`docs/MWEB_ARCHITECTURE.md`](docs/MWEB_ARCHITECTURE.md).

- Crate [`crates/mweb`](crates/mweb) (`bdk_mweb`): Core-compatible stealth keys
  (`m/0'/100'/{0,1}'` + BLAKE3 `'A'` tweak), `Address::mweb` helpers, `rewind_output` /
  `MwebCoinDatabase`, `MwebTxBuilder` (MWEB→MWEB + peg-out), and `build_pegin`.
- Wallet feature `mweb`: `balance_combined`, `prepare_mweb_pegin`, `fund_mweb_send`,
  `fund_mweb_pegout` — caller still owns `MwebCoinDatabase`. (`build_mweb_*` deprecated.)
- Feature `persist` on `bdk_mweb`: parallel `ChangeSet` for `bdk_file_store` and SQLite
  (`rusqlite` feature). Wallet `MwebStore` (feature `mweb` / `mweb-sqlite`) loads beside the
  wallet. **Not** part of `Wallet::ChangeSet`. Encrypt at rest with `encrypt` /
  `seal_changeset` (apps own the key).
- Crypto: Grin/MW `grin_secp256k1zkp` FFI for **675-byte bulletproofs** + schnorr (Elements CT
  rangeproofs rejected). Switch commitments keep Core’s H prefix `0x0b`.
- Regtest: `cargo test -p bdk_mweb` and `cargo test -p bdk_wallet --test mweb_facade`;
  needs `LITECOIND_EXE`. Persist: `persist_filestore` / `persist_sqlite`. Example:
  `cargo run -p bdk_wallet --example mweb_regtest --features "mweb,file_store,test-utils"`.
- **Electrum-first** regtest chain source (`litecoind` + `electrs-ltc`). No regtest Esplora.
- **Not** embedding Nexus/`lndltc` (GPL) or gomobile-`mwebd`.
- **ltcsuite reference:** copy PSBTv2 MWEB + align sync with `mwebsync` — see
  [`docs/LTCSUITE_ALIGNMENT.md`](docs/LTCSUITE_ALIGNMENT.md). Golden fixtures live in
  `crates/mweb/tests/fixtures/` (regen: `scripts/ltcd_mweb_fixtures`). Legacy ltcwallet
  path `m/1000'/2'/…` is intentionally unsupported.

**Also landed:** LIP-0006 verified sync (`mwebheader` / leafset_root / PMMR parent_hashes,
`VerifyMode::HeaderAndPmmr` default) + `sync_mweb_at_tip` / `TcpMwebPeer` (feature
`lip0006`); peg-in maturity + `disconnect_from` reorg seam; `bdk_bitcoind_rpc` via
vendored `bitcoincore-rpc` Litecoin alias.

## Regtest harness (`litecoind` + `electrs-ltc`)

Feature `bdk_testenv/litecoin-daemon` spawns binaries from `LITECOIND_EXE` and `ELECTRS_LTC_EXE`.
Tests skip with a printed notice when those are unset, so the default `just test` stays green
without local daemons. To run the migrated daemon tests:

```bash
export LITECOIND_EXE=/path/to/litecoind
export ELECTRS_LTC_EXE=/path/to/electrs   # build from rust-litecoin/electrs-ltc
just test-regtest
```

Node-only (MWEB peg-in acceptance, no electrs):

```bash
export LITECOIND_EXE=/path/to/litecoind
cargo test -p bdk_testenv --features litecoin-daemon --test mweb_pegin
```

The upstream Bitcoin `TestEnv` (`electrsd`) remains behind `daemon` + `RUSTFLAGS='--cfg
daemon_tests'` for merge hygiene only; it does not compile against the `litecoin` alias.

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
