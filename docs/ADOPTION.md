# LitecoinDevKit adoption guide

Audience: wallet engineers evaluating or integrating **native Rust MWEB** via LitecoinDevKit (LDK).

LDK is a production-grade Litecoin port of BDK with first-class MWEB (typed PSBTv2 maps, peg-in/out, combined balances, LIP-0006 sync). The hard crypto and wallet logic is mainnet-validated; this guide is the low-friction path onto that stack.

**If you currently embed mwebd, start with [`MIGRATE_FROM_MWEBD.md`](MIGRATE_FROM_MWEBD.md) before this guide.**

### Repo map

This file lives in **[`LitecoinDevKit/bdk`](https://github.com/LitecoinDevKit/bdk)** (`litecoin` branch), under `docs/`. Relative links below stay in this repo’s `docs/` (or `PORTING.md` at the repo root).

| Path | Repo | Needed for |
| --- | --- | --- |
| This guide + `bdk_mweb` crates | [`bdk`](https://github.com/LitecoinDevKit/bdk) `litecoin` | Always (docs); Rust path builds |
| Wallet facade / examples | sibling [`bdk_wallet`](https://github.com/LitecoinDevKit/bdk_wallet) `litecoin` | Rust path |
| AAR / xcframework | [`bdk-ffi`](https://github.com/LitecoinDevKit/bdk-ffi) `litecoin-mweb` | Mobile packaging |
| SwiftPM wrapper | [`ltc-swift`](https://github.com/LitecoinDevKit/ltc-swift) | iOS / macOS consumers |
| Rust product reference | [`ltc-wallet-mac`](https://github.com/LitecoinDevKit/ltc-wallet-mac) | Optional UX reference |
| Mobile UniFFI checklists | [`ltc-wallet-ios`](https://github.com/LitecoinDevKit/ltc-wallet-ios) / [`ltc-wallet-android`](https://github.com/LitecoinDevKit/ltc-wallet-android) | Optional |

**Blessed pin table below is the single source of truth.** Other READMEs should link here rather than invent divergent pins. Prove the guide with [`DOGFOOD_CHECKLIST.md`](DOGFOOD_CHECKLIST.md).

## Decide in one sitting

| You want… | Use… |
| --- | --- |
| Native Rust wallet / desktop / server | [`bdk_wallet`](https://github.com/LitecoinDevKit/bdk_wallet) + this repo’s crates (`mweb` feature) |
| iOS / macOS app (no Rust in-process) | [`ltc-swift`](https://github.com/LitecoinDevKit/ltc-swift) → UniFFI from [`bdk-ffi`](https://github.com/LitecoinDevKit/bdk-ffi) |
| Android app | GitHub-release **AAR** from [`bdk-ffi`](https://github.com/LitecoinDevKit/bdk-ffi/releases) |
| Reference product UX (Rust, not UniFFI) | [`ltc-wallet-mac`](https://github.com/LitecoinDevKit/ltc-wallet-mac) |
| Mobile API checklist | [`ltc-wallet-ios`](https://github.com/LitecoinDevKit/ltc-wallet-ios) / [`ltc-wallet-android`](https://github.com/LitecoinDevKit/ltc-wallet-android) |
| Coming from embedded `mwebd` | [`MIGRATE_FROM_MWEBD.md`](MIGRATE_FROM_MWEBD.md) **first** |

**Not LDK:** embedding Go/`mwebd`, GPL Nexus/`lndltc`, inventing a proprietary PSBT map, or treating HogAddr/v9 as transparent UTXOs. See [`MWEB_ARCHITECTURE.md`](MWEB_ARCHITECTURE.md).

## Architecture (tip + LIP)

```text
Transparent tip          MWEB UTXOs
─────────────────        ──────────────────────────────
Electrum / Esplora /     LIP-0006 P2P (MwebSyncer)
litecoind RPC            → MwebCoinDatabase / MwebStore
        │                         │
        └──── Wallet facade ──────┘
              balance_combined / prepare_mweb_pegin /
              fund_mweb_* → sign_and_extract_funded_mweb
```

- Transparent coins live in `IndexedTxGraph` (normal BDK).
- MWEB coins live in a **parallel** `MwebCoinDatabase` (caller-owned `MwebStore`). Never fold HogAddr/v9 into the transparent index.
- There is **no** Electrum/Esplora API for MWEB UTXOs. Sync is LIP-0006 against archive peers. Details: [`INDEXING_NOTES.md`](INDEXING_NOTES.md), [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).

## Blessed consumer pin (this phase) — source of truth

Update this table when cutting a release; mirror only by linking here.

| Artifact | Pin | Notes |
| --- | --- | --- |
| `bdk-ffi` release / AAR / xcframework | **`3.1.0-litecoin.1`** | [GitHub release](https://github.com/LitecoinDevKit/bdk-ffi/releases/tag/3.1.0-litecoin.1) |
| `ltc-swift` (SwiftPM) | **`3.1.0-litecoin.2`** | Thin wrapper; binary still `3.1.0-litecoin.1` |
| `bdk_wallet` (Rust) | **`3.1.0-litecoin.0`** | Rev-pinned from `bdk-ffi`; bump only with coherence check |
| Core crates (`bdk`, `bdk_mweb`, …) | rev pinned by wallet / ffi | See [`PORTING.md`](../PORTING.md) topology |

Android smoke and iOS smoke both consume the **same** `3.1.0-litecoin.1` binaries (AAR directly; Swift via `ltc-swift` `.2`).

Crates are **not** on crates.io under `bdk_*` (upstream owns those names). Consumers use git revs or published mobile artifacts. The `litecoin` crate `0.32.8-rc.2` may still be path/git-patched until crates.io publish — that is supported.

## Start here

### ≈30 minutes — transparent + MWEB receive / sync / balance

Realistic first session (no peg-in maturity wait):

| Goal | Where |
| --- | --- |
| Transparent testnet receive + spend | Clone this repo + sibling `bdk_wallet`; follow [`LITECOIN_E2E.md`](LITECOIN_E2E.md) Start here → Electrum BIP84. Prefer Electrum-LTC over litecoinspace when tips diverge. |
| MWEB address + LIP sync + combined balance | `bdk_wallet` `mainnet_mweb` / `mweb_regtest` **or** mobile smoke: address → Electrum tip → `MwebStore` + `MwebSyncer` → `balance_combined` / `balanceCombined`. |

You should leave this block with a transparent spend (or funded receive) and a non-empty MWEB sync path (even if spendable MWEB is still zero).

### Longer — full peg-in → mature → spend

Mainnet soft-key loop needs **6 confirmations** after peg-in before `fund_mweb_*` selects coins — budget hours/days, not 30 minutes. Prefer **regtest** (`mweb_regtest`) to exercise the full loop in one sitting.

1. Sync transparent tip → LIP sync into `MwebStore`.
2. `prepare_mweb_pegin` → broadcast → wait `MWEB_PEGIN_MATURITY` (6).
3. `fund_mweb_send` / `fund_mweb_pegout` → `sign_and_extract_funded_mweb` → broadcast (RPC + **wtxid** for MWEB-only).
4. Canonical product shape: [`ltc-wallet-mac`](https://github.com/LitecoinDevKit/ltc-wallet-mac) (`wallet-core`, not UniFFI).

Recipes: [`LITECOIN_E2E.md`](LITECOIN_E2E.md) § MWEB facade / BDK ↔ Nexus.

### Mobile bindings (no Rust)

**Android** — download AAR (file dependency is the primary path; Maven Central is later):

```bash
# from your app repo
curl -fL -o app/libs/bdk-ltc-android.aar \
  https://github.com/LitecoinDevKit/bdk-ffi/releases/download/3.1.0-litecoin.1/bdk-ltc-android.aar
```

```kotlin
implementation(files("libs/bdk-ltc-android.aar"))
implementation("net.java.dev.jna:jna:5.14.0@aar")
// package: org.litecoindevkit
```

**Swift** — SwiftPM:

```swift
.package(url: "https://github.com/LitecoinDevKit/ltc-swift", exact: "3.1.0-litecoin.2")
```

Mirror the smoke checklist: mnemonic → BIP84 wallet → MWEB address → Electrum sync → `MwebStore` + `MwebSyncer` → `balanceCombined` → fund/sign/extract. See smoke READMEs and [`bdk-ffi` README](https://github.com/LitecoinDevKit/bdk-ffi).

`MwebSyncer` is **blocking** — call off the UI thread.

## Common first-run failures

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| LIP sync hangs / “dead peer” / empty downloads | No archive MWEB peer, or Core 0.21.5.6+ rate-limit without whitelist | Point at a non-pruned peer; `litecoind -whitelist=noban@…` for your clients. See [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md). |
| Faucet / spend invisible on Esplora | Electrum tip ahead of litecoinspace (common on testnet) | Prefer Electrum-LTC for live E2E; don’t assume Esplora tip matches. |
| `fund_mweb_*` fails / selects nothing while UI shows MWEB | Peg-in not yet mature (need 6 confs) or using `trusted_spendable` as selection | Wait maturity; select via `unspent_spendable` (see Balance semantics). |
| Explorer shows weird/empty tx; wallet “lost” the send | Pure MWEB `txid` collides (empty transparent skeleton) | Identify and track by **wtxid**; broadcast via litecoind RPC when Esplora strips `mw_tx`. |
| Cargo type errors / duplicate `bdk_*` | Rev pin ladder out of coherence | Bump `bdk` + `bdk_wallet` + `bdk-ffi` together; run `check-rev-coherence.sh`. |
| Android can’t resolve `org.litecoindevkit` from Maven | Looking for Central / SNAPSHOT | Use the **file AAR** from the GitHub release (blessed pin above). |

## Maps-first MWEB API (do not use deprecated builders)

| Step | Rust (`bdk_wallet`, feature `mweb`) | UniFFI |
| --- | --- | --- |
| Peg-in | `prepare_mweb_pegin` → sign transparent → extract/broadcast | `prepareMwebPegin` |
| Send | `fund_mweb_send` → `sign_and_extract_funded_mweb` | `fundMwebSend` → `signAndExtractFundedMweb` |
| Peg-out | `fund_mweb_pegout` → `sign_and_extract_funded_mweb` | `fundMwebPegout` → `signAndExtractFundedMweb` |
| Balance | `balance_combined` / `balance_combined_store` | `balanceCombined` |
| Sync | `MwebStore` + `MwebSyncer` / `sync_differential*` | `MwebStore` + `MwebSyncer` |

Deprecated: `build_mweb_*`, `attach_mweb_tx`, legacy `build_pegin`. Do not recommend them in new code.

## Balance semantics (footgun)

`CombinedBalance::trusted_spendable()` = transparent trusted-spendable **+ all confirmed MWEB**.

Coin selection uses the stricter `MwebCoinDatabase::unspent_spendable(tip, MWEB_PEGIN_MATURITY)` (default maturity **6**). UI “confirmed MWEB” can exceed what `fund_mweb_*` will select until peg-ins mature. Prefer showing a separate “spendable MWEB” line from `unspent_spendable`.

## Pin model (rev ladder)

```text
rust-litecoin  ←  bdk (this repo)  ←  bdk_wallet  ←  bdk-ffi  → AAR / xcframework / ltc-swift
                         ↖︎_____________________  ltc-wallet-mac (path/rev, not UniFFI)
```

`bdk-ffi` CI runs `scripts/check-rev-coherence.sh` so the `bdk` rev pinned by ffi matches the one pinned by its `bdk_wallet` commit. Bump in lockstep or types diverge (loud Cargo failure). Release steps: [`bdk-ffi` release ladder](https://github.com/LitecoinDevKit/bdk-ffi/blob/litecoin-mweb/docs/RELEASE_LADDER.md).

## HD / keys

Default: **Litecoin Core** paths `m/0'/100'/{0,1}'` + BLAKE3 `'A'` tweak (Nexus-compatible). LIP-0004 alternate paths are opt-in. Legacy ltcwallet `m/1000'/2'/…` is unsupported.

## PSBT / HWI prep (not HWI product)

BIP32 origins `0x9A` (scan) / `0x9B` (spend) are populated on fund and **kept through scrub** for external-signer routing. Soft-key signing is shipped; hardware wallets are a later phase. See [`LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md) § Key origins.

## Deeper docs

| Doc | When |
| --- | --- |
| [`DOGFOOD_CHECKLIST.md`](DOGFOOD_CHECKLIST.md) | Timed pass of this guide on a clean clone |
| [`PORTING.md`](../PORTING.md) | Alias strategy, fork pins, ecosystem limits |
| [`LITECOIN_E2E.md`](LITECOIN_E2E.md) | Full testnet / regtest / mainnet recipes |
| [`MIGRATE_FROM_MWEBD.md`](MIGRATE_FROM_MWEBD.md) | Leave embedded mwebd |
| [`INDEXING_NOTES.md`](INDEXING_NOTES.md) | Why no MWEB Esplora; integrator sync contract |
| [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md) | Archive peers, whitelist, broadcast/wtxid |
| [`REVIEWERS_GUIDE.md`](REVIEWERS_GUIDE.md) | Invariants and rejected backends |
| [`SECURITY_PLAN.md`](SECURITY_PLAN.md) | Threat model / hardening status |
