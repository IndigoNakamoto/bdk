# ltcsuite alignment (reference inventory)

Status: **Inventory locked** (2026-07-27, re-verified vs ltcd `master` `ltcutil/psbt/types.go`).  
**Superseded for v24 interop** (2026-08-17): [LIP-0007](https://github.com/DavidBurkett/lips/blob/lip0007/lip-0007.mediawiki) + Core v24 are the target map. This file remains the **0.21-era / ltcd** inventory. See [`LIP0007.md`](LIP0007.md) and [`V24_REVIEW.md`](V24_REVIEW.md). Light sync still follows **`mwebsync`**.  
Rust ports semantics into `litecoin` / `bdk_mweb` / `bdk_wallet` — **no Go FFI**.

**Lock notes**

- All `0x90+` / kernel type codes in [`crates/mweb/src/psbt.rs`](../crates/mweb/src/psbt.rs) match ltcd.
- Finalize/extract must emit **stealth address** on outputs (`scan||spend`, 66 bytes) — see ltcd
  `extractor.go` / `psbt.go` (`StealthAddress`).
- BIP32 origins `0x9A` / `0x9B` are `(PublicKey, KeySource)` in rust-litecoin; BDK
  `populate_mweb_key_origins` / `validate_mweb_key_origins` fill them on fund (ltcwallet
  `populateMwebKeyOrigins`).
- Upstream absorption checklist: [`RUST_LITECOIN_PSBT_PR.md`](RUST_LITECOIN_PSBT_PR.md).

Canonical sources:

- PSBT: [`ltcsuite/ltcd` `ltcutil/psbt`](https://github.com/ltcsuite/ltcd/tree/master/ltcutil/psbt) + [`ltcwallet/wallet/psbt.go`](https://github.com/ltcsuite/ltcwallet/blob/master/wallet/psbt.go)
- Sync: [`ltcsuite/mwebsync`](https://github.com/ltcsuite/mwebsync) ([ARCHITECTURE](https://github.com/ltcsuite/mwebsync/blob/main/docs/ARCHITECTURE.md))

---

## 1. PSBTv2 MWEB field map (copy exactly)

First-class key types in the `0x90+` range (not BIP174 proprietary `0xFC` stuffing of a raw `mw_tx`).

### Global

| Type | Code | Purpose |
| --- | --- | --- |
| `MwebTxOffsetType` | `0x90` | Kernel offset (blinding) |
| `MwebTxStealthOffsetType` | `0x91` | Stealth offset |
| `MwebKernelCountType` | `0x92` | Number of kernels |

PSBTv2 also uses `TxVersionType`, `InputCountType`, `OutputCountType`, etc. (standard v2 globals).

### Input (`PInput`)

| Field | Type code | Notes |
| --- | --- | --- |
| `MwebOutputId` | `0x90` | Spent output id (pure MWEB input marker) |
| `MwebCommit` | `0x91` | Spent output commitment |
| `MwebOutputPubkey` | `0x92` | Receiver / output pubkey |
| `MwebInputPubkey` | `0x93` | Input pubkey (stealth feature) |
| `MwebFeatures` | `0x94` | `MwebInputFeatureBit` |
| `MwebInputSig` | `0x95` | Input signature (finalize) |
| `MwebAddressIndex` | `0x96` | LE u32 |
| `MwebAmount` | `0x97` | LE u64 litoshis |
| `MwebSharedSecret` | `0x98` | Optional shared secret |
| `MwebKeyExchangePubkey` | `0x99` | Ke |
| `MwebMasterScanKey` | `0x9A` | BIP32 derivation origin |
| `MwebMasterSpendKey` | `0x9B` | BIP32 derivation origin |
| `MwebExtraData` | `0x9C` | Extra data feature |

ltcwallet populates origins via `populateMwebKeyOrigins` / `validateMwebKeyOrigins`; signs with `BasicMwebInputSigner` + `SignMwebComponents`.

### Output (`POutput`)

| Type | Code |
| --- | --- |
| `MwebStealthAddressOutputType` | `0x90` |
| `MwebCommitOutputType` | `0x91` |
| `MwebFeaturesOutputType` | `0x92` |
| `MwebSenderPubKeyOutputType` | `0x93` |
| `MwebOutputPubKeyOutputType` | `0x94` |
| `MwebStandardFieldsOutputType` | `0x95` (Ke \|\| view_tag \|\| enc_value \|\| enc_nonce) |
| `MwebRangeProofOutputType` | `0x96` |
| `MwebSignatureOutputType` | `0x97` |
| `MwebExtraDataOutputType` | `0x98` |

### Kernel (`PKernel`)

| Type | Code |
| --- | --- |
| `MwebKernelExcessCommitType` | `0` |
| `MwebKernelStealthCommitType` | `1` |
| `MwebKernelFeeType` | `2` |
| `MwebKernelPeginAmountType` | `3` |
| `MwebKernelPegoutType` | `4` (repeated; pegout index in key data; TxOut wire value) |
| `MwebKernelLockHeightType` | `5` |
| `MwebKernelFeaturesType` | `6` |
| `MwebKernelExtraDataType` | `7` |
| `MwebKernelSignatureType` | `8` |

### BDK today vs ltcsuite

| | BDK now | ltcsuite reference |
| --- | --- | --- |
| Container | Native `bitcoin::psbt::mweb` (`litecoin` **0.32.8-rc.2**); `mw_tx` **extract-only** via `Psbt::extract_tx_with_mweb` | Native PSBTv2 MWEB maps in `litecoin` |
| Sign path | `fund_mweb_*` → `sign_funded_mweb` → scrub → extract (ltcwallet-shaped) | `SignMwebComponents` inside PSBT |
| Interop | Mainnet Nexus send proven; map round-trip + fund/sign + KeySource origin unit tests | Cross-wallet PSBT round-trip |

**Upstream absorb:** staging removed; native maps in rust-litecoin **0.32.8-rc.2** (patch +
dry-run publish ready — see [`RUST_LITECOIN_PSBT_PR.md`](RUST_LITECOIN_PSBT_PR.md)). Workspace
keeps `[patch.crates-io]` until crates.io lists rc.2.

---

## 2. mwebsync vs `bdk_mweb` LIP path

### mwebsync architecture (reference)

```text
WaitHeaders → Rollback → StratifiedHeaderSample → VerifyTip(header+leafset)
  → DifferentialUTXOSync → UpdateDB/Notify → IdleUntilNewTip → loop
```

Interfaces:

- `BlockHeaderProvider` — tip + header by height  
- `PeerQuerier` / peer provider — multi-peer query + ban  
- `SyncStateNotifier` — wait for transparent headers  
- `CoinDatabase` — leafset, coins, rollback, leaves-at-height map  

Behaviors BDK lacks or only partially has:

| Capability | mwebsync | `bdk_mweb` today |
| --- | --- | --- |
| Continuous tip loop | Yes | `MwebSyncer::run_loop` / `run_loop_with_pool` (+ `PollingTipNotifier`) |
| Stratified height→leaf index / UTXO dating | Yes | Fine window **4000** default (+ `FINE_WINDOW_FAST=500`, tip-only) |
| Differential leafset sync | Yes | `diff_leafsets` → fetch added only |
| Multi-peer + ban | Yes | `PeerPool` + `with_failover` / `run_once_with_pool` (ban on leafset/PMMR/timeout/connect) |
| Header wait vs Electrum tip | Explicit notifier | `SyncNotifier` / `PollingTipNotifier` after Esplora; `ReadyNotifier` is one-shot |
| Reorg | Rollback ≤10 rewind / >10 purge | `disconnect_from` heights + shorter-tip in syncer |
| Verify | header + leafset + UTXO MMR | `HeaderAndPmmr` leafset + batch (aligned in spirit) |

What already matches: LIP-0006 message order, leafset blake3, PMMR `output_root` checks (`pmmr.rs`), tip seam `(hash, height)`.

**MVP landed:** [`crates/mweb/src/mweb_sync.rs`](../crates/mweb/src/mweb_sync.rs) — differential sync + UTXO dating. `mainnet_mweb sync` persists `mweb_sync.json` (`SyncState`) beside `mweb.db`.

---

## 3. Ordered backlog

1. ~~**PSBTv2 MWEB types**~~ — native in `litecoin` 0.32.8-rc.2; BDK consumes via thin helpers
   ([`RUST_LITECOIN_PSBT_PR.md`](RUST_LITECOIN_PSBT_PR.md); live crates.io upload = maintainer
   step after PR merge).
2. ~~**In-PSBT fund/sign/finalize**~~ — `fund_mweb_*` + `sign_funded_mweb` + scrub +
   `Psbt::extract_tx_with_mweb`; wallet `build_mweb_*` deprecated.
2b. ~~**In-PSBT peg-in + BIP32 origins**~~ — `fund_mweb_pegin` / `sign_funded_mweb_pegin`;
   `populate_mweb_key_origins`; `build_pegin` deprecated.
3. ~~**Deprecate `attach_mweb_tx` on happy path**~~ — marked `#[deprecated]`.
4. ~~**mwebsync-shaped syncer**~~ — tip-loop wait, `PeerPool::with_failover` /
   `run_once_with_pool`, fine window 4000 default.
5. ~~**Confirmation UX**~~ — CLI balance buckets + maturity copy.
6. ~~**Broadcast policy**~~ — RPC-first for MWEB-only + wtxid; see [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).
7. Mempool watch — deferred (wallet callback, not syncer).

---

## 4. Key origins (HWI prep — not HWI product)

Soft-key fund/sign is shipped. Hardware / external-signer **product** work is deferred. The
PSBT story below is locked so HWI can plug in later without a wire-format change.

| Item | Behavior |
| --- | --- |
| `MwebMasterScanKey` | PSBT type **`0x9A`** — `(PublicKey, KeySource)` |
| `MwebMasterSpendKey` | PSBT type **`0x9B`** — `(PublicKey, KeySource)` |
| Populate | `bdk_mweb::psbt::populate_mweb_key_origins` on fund (ltcwallet `populateMwebKeyOrigins`) |
| Validate present | `validate_mweb_key_origins` |
| Validate match wallet | `validate_mweb_key_origins_against` — rejects mismatched fingerprint/path (coordinators / HWI routing) |
| Scrub | `scrub_sensitive_fields` **keeps** `0x9A`/`0x9B`; strips amount / shared secret / address index / Ke from inputs |

**Integrator rules until HWI lands**

1. Do not invent alternate origin key types or drop origins before handoff to an external signer.
2. Prefer maps-first `fund_mweb_*` → sign → scrub → `extract_tx_with_mweb` so origins are populated consistently.
3. Soft-key path may sign in-process after populate; an HWI path should stop after fund (+ optional scrub policy), ship the PSBT, and verify origins on return with `validate_mweb_key_origins_against`.
4. No USB transport, `SignMwebComponents`-shaped device trait, or HWI crate in this tree yet.

See also [`ADOPTION.md`](ADOPTION.md) § PSBT / HWI prep.

---

## 5. Non-goals

- Vendoring Go / FFI to ltcd  
- Replacing zkp FFI with Go `mw`  
- Nexus/GPL embedding  
- Inventing a different PSBT key map  
- Supporting ltcwallet **legacy** MWEB HD scope `m/1000'/2'/…` (`KeyScopeMwebLegacy`) —
  only Core `m/0'/100'/{0,1}'` and explicit `MasterKeyScheme::Lip0004`  
- Porting ltcwallet aezeed / import / recovery / routing tests or mwebsync Go suites
  (BDK wallet + `MwebSyncer` coverage is Rust-native)
- Shipping an HWI / USB external-signer product in this phase (origins only — §4)

---

## 6. Test parity (golden fixtures)

Port **data**, not Go test logic:

| Source | In-tree |
| --- | --- |
| ltcd `keychain_test` / ltcwallet `mweb_compat` vectors | `bdk_mweb` unit tests (`ltcd_*`) + master scan/spend **pubkeys** |
| Multi-index `createOutput` + wrong-scan target | Go dumps under [`crates/mweb/tests/fixtures/`](../crates/mweb/tests/fixtures/); Rust asserts commitment/keys/message preimage match (bulletproofs differ across `ltcsuite/secp256k1` vs `grin_secp256k1zkp`) |
| `TestSignMwebComponents` / `TestExtract_ValidMWEB` / kernel all-fields | Same fixtures dir; ingest via [`psbt_from_ltcd_v2`](../crates/mweb/src/psbt_ltcd.rs) (ltcd PSBTv2 ≠ rust-litecoin v0 global encoding) |

Regenerate (dev machine with Go + CGO, not CI):

```bash
cd scripts/ltcd_mweb_fixtures
git clone --depth 1 https://github.com/ltcsuite/ltcd.git vendor-ltcd   # once
CGO_ENABLED=1 go run .
cargo test -p bdk_mweb --lib -- ltcd_
cargo test -p bdk_mweb --test ltcd_psbt_fixtures
```

See [`scripts/ltcd_mweb_fixtures/README.md`](../scripts/ltcd_mweb_fixtures/README.md).
