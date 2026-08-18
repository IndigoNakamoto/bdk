# BDK vs Litecoin Core v24.0.1 pre-release

Status: **review + parked alignment** (2026-08-17). No CI pin. LIP-0007 types live on `v24-rmweb` only.

Pre-release tree: `/Users/indigo/Dev/litecoin-v24-master` (`Litecoin Core version v24.0.1`).
Local binary used for this pass: `src/litecoind` (built `--with-gui=no --without-miniupnpc`; macOS needed the same `scrypt.h` / `scrypt.cpp` endian guards already present on the 0.21.5.6 tree).

LIP-0007 draft: [DavidBurkett/lips `lip0007`](https://github.com/DavidBurkett/lips/blob/lip0007/lip-0007.mediawiki). Official [lips](https://github.com/litecoin-project/lips) still only publishes LIP-0001–0006. Matrix: [`LIP0007.md`](LIP0007.md).

---

## Verdict

Consensus, stealth derivation, LIP-0006 wire, and HogEx layout look unchanged from 0.21.5.6.
**Regtest interop is blocked** by a new MWEB HRP (`rmweb` vs BDK/rust-litecoin `tmweb`).
**Wallet defaults** broke seed-parity (`createwallet` → descriptor wallet; `sethdseed` is legacy-only).
**PSBT maps have already diverged** (Core / LIP-0007 `0x96` = `mweb()` descriptor; the 2026-07-27 ltcd lock is u32 index + `0x9A`/`0x9B` origins). **BDK is the lagging peer.** Alignment is parked on `v24-rmweb`; `litecoin` stays on the ltcd map until a public v24 pin.

---

## Suite results (`LITECOIND_EXE` = v24.0.1)

| Suite | Result | First error |
| --- | --- | --- |
| `core_bulletproof_gate` | FAIL | `sendtoaddress`: invalid `tmweb1…` |
| `core_receive_scan` | FAIL | same `tmweb1…` |
| `core_seed_parity` | FAIL | `sethdseed`: “Only legacy wallets are supported by this command” |
| `core_spend` | FAIL | same `tmweb1…` |
| `core_pegin_pegout_roundtrip` | FAIL* | HogEx output present; `getreceivedbyaddress` = 0 |
| `lip0006_sync` | FAIL / 1 unit OK | node test: `tmweb1…`; `verify_mode_rejects_tampered_leafset` passed |
| `lip0006_p2p` | FAIL | `tmweb1…` |
| `lip0006_throttle` | FAIL | `tmweb1…` |
| `mweb_anchoring` (4 tests) | FAIL | `tmweb1…` |
| `bdk_testenv` `mweb_pegin` | FAIL | `tmweb1…` |
| `bdk_bitcoind_rpc` `test_emitter_litecoin` | **PASS** | transparent `rltc1…` already matches rust-litecoin |

\*This is the only node suite that got past address decode: BDK-authored peg-in + peg-out were mempool-accepted and the tip HogEx contained the peg-out SPK. Wallet credit failed (see §Wallet).

CI [`.github/workflows/regtest_mweb.yml`](../.github/workflows/regtest_mweb.yml) stays on **0.21.5.6** until a public v24 artifact exists.

---

## What still matches (do not re-litigate)

| Area | Evidence |
| --- | --- |
| Stealth HD | Core still derives `m/0'/100'/{0,1}'`. Live `walletcreatefundedpsbt` descriptor: `mweb([f36b0fbf/0'/100'/0']…,[f36b0fbf/0'/100'/1']…)` |
| HogAddr v8 / peg-in v9 / HogEx | Unchanged in `script.h`; peg-out round-trip saw `is_hog_ex` tip tx |
| 675-byte BPs / BlindSwitch | No consensus delta in tree; gate suite never reached a Core `mw_tx` (HRP block) |
| LIP-0006 | Same commands / `MAX_REQUESTED_MWEB_UTXOS=4096` / 32 burst / 0.5 req/s / `MAX_MWEB_LEAFSET_DEPTH=10` |
| Regtest MWEB BIP9 | `nStartTime=1601450001`, window 144 → [`FIRST_MWEB_HEIGHT=432`](../crates/testenv/src/litecoin_regtest.rs) still correct |
| Transparent RPC emitter | `rltc` HRP already in rust-litecoin; `bdk_bitcoind_rpc` green |

`getblockchaininfo` no longer has `softforks` (use `getdeploymentinfo` → `deployments.mweb`). Not on the BDK test path (`testenv` uses raw JSON; `bdk_bitcoind_rpc` never calls it). Vendor `bitcoincore-rpc` typed `get_blockchain_info` would break if used.

---

## 1. Wallet / harness

### Descriptor default (confirmed live)

`createwallet "bdk"` on v24:

- `descriptors: true`, `format: sqlite`
- `getnewaddress` → `rltc1q…` (P2WPKH)
- `getnewaddress "" "mweb"` → **`rmweb1…`**
- `sethdseed` → `-4 Only legacy wallets are supported by this command`

Legacy still works: `createwallet` with `descriptors=false` (needs BDB). `sethdseed` then succeeds. `getnewaddress "" "mweb"` on that legacy wallet is still **`rmweb1…`**.

v24 only materializes MWEB on `upgradewallet` for old wallets (`LoadMWEBKeychain` comment in `scriptpubkeyman.cpp`). New wallets already have MWEB.

### Seed-parity fix options

1. **Harness:** `createwallet` with `descriptors=false` so `core_seed_parity` keeps `sethdseed` (closest to 0.21). Legacy is deprecated in Core.
2. **Descriptor-era rewrite:** import/export `mweb(xprv/0'/100'/0', xpub/0'/100'/1', *)` via `importdescriptors` / `listdescriptors` and compare `getnewaddress "" "mweb"` (indices 0–1 still reserved for change/peg-in on legacy; confirm descriptor next-index).
3. Do both: default harness stays descriptor (production-shaped); seed-parity creates an explicit legacy wallet.

### Peg-out credit (`core_pegin_pegout_roundtrip`)

BDK peg-in/peg-out were accepted. HogEx paid the watched SPK. `getreceivedbyaddress(addr, 1)` returned 0.

v24 `GetReceived` skips `IsTxImmature` unless `include_immature_coinbase=true`. HogEx uses `PEGOUT_MATURITY = 6` (`consensus.h`), so 1 confirmation is not enough. Fix options: pass the immature flag, or mine 6+ blocks before asserting wallet credit. On-chain HogEx check can stay as the consensus assertion.

---

## 2. Regtest MWEB HRP (the blocker)

| Network | Core 0.21.5.6 | Core v24.0.1 | rust-litecoin 0.32.8-rc.2 / BDK |
| --- | --- | --- | --- |
| mainnet | `ltcmweb` | `ltcmweb` | `ltcmweb` |
| testnet | `tmweb` | `tmweb` | `tmweb` |
| **regtest** | **`tmweb`** | **`rmweb`** | **`rmweb`** via `Network::Regtest` (`MwebHrp`); `NetworkKind::Test` still encodes `tmweb` |

Transparent regtest HRP was already `rltc` on both sides (emitter passed).

Local rust-litecoin now stores `MwebHrp` on MWEB addresses (same idea as segwit `KnownHrp`). BDK node suites pass `Network::Regtest`. `NetworkKind::Test` remains `tmweb` so published testnet vectors stay stable. 0.21.5.6 CI will reject `rmweb` until a public v24 pin (follow-on 4).

---

## 3. PSBT / LIP-0007 matrix

Live Core `walletcreatefundedpsbt` (descriptor wallet, after a Core `sendtoaddress` peg-in) decoded as **PSBTv2**:

- Globals: `psbt_version=2`, `tx_version=2`, `input_count`, `output_count`, `kernel_count`, `kernels[]` — **no** `unsigned_tx`
- Input `mweb`: `output_id`, `output_commit`, `output_pubkey`, **`address_descriptor`**, `amount`, `shared_secret`
- No `0x9A` / `0x9B` origin fields
- Outputs: `mweb.address` = `rmweb1…` (stealth string) before sign
- Kernel: `features`, `fee`

`address_descriptor` on the wire was an origin-wrapped `mweb(...)` (scan `0'/100'/0'`, spend `0'/100'/1'`), matching [`doc/mweb/mweb-descriptors.md`](../../litecoin-v24-master/doc/mweb/mweb-descriptors.md).

### Key codes

| Key | BDK / ltcd (locked 2026-07-27) | Core v24 pre-release |
| --- | --- | --- |
| Global `0x90`–`0x92` | offset / stealth offset / kernel count | same |
| Kernels `0`–`8` | excess, stealth, fee, pegin, pegout, lock, features, extra, sig | same |
| Input `0x90`–`0x95`, `0x97`–`0x99`, `0x9C` | output id … extra data | same |
| Input **`0x96`** | **`MwebAddressIndex` (LE u32)** | **`PSBT_IN_MWEB_ADDR_DESCRIPTOR`** — ASCII `mweb(...)` |
| Input **`0x9A` / `0x9B`** | BIP32 origins `(PublicKey, KeySource)` | **absent** |
| Output `0x90`–`0x98` | stealth … extra | same codes |

Core `psbt.h` still **accepts** a 4-byte `0x96` as pre-descriptor compat and otherwise requires `mweb(` ASCII. rust-litecoin now does the same (ignore 4 bytes; otherwise require ASCII `mweb(`). BDK updater emits the descriptor; ltcd’s 4-byte index is ingest-only.

### Container / version

On `v24-rmweb`, rust-litecoin serializes MWEB packets as **PSBTv2** (BIP-370 globals, kernel section after outputs, MWEB maps after canonical). `psbt_ltcd` remains the **read** path for 0.21-era ltcd fixtures (index `0x96`, origins). Probe: [`crates/mweb/tests/core_psbt_lip0007.rs`](../crates/mweb/tests/core_psbt_lip0007.rs). Core golden bytes: `src/test/util/psbt_vectors.h`, `test/functional/mweb_psbt.py`.

### Losh / LIP-0007 stance

- Draft exists on Burkett’s fork ([`lip-0007.mediawiki`](https://github.com/DavidBurkett/lips/blob/lip0007/lip-0007.mediawiki)); not yet in official lips.
- v24 already implements that draft: `0x96` = `mweb()`, `0x9A`/`0x9B` reserved, 4-byte `0x96` ignored, PSBTv2 + kernel section.
- **BDK / rust-litecoin on `v24-rmweb` align to that map** (descriptor emit, no origins on the wire, v2 + kernel sections). ltcd index/origins remain a **read** path (`psbt_ltcd`) for 0.21-era fixtures.
- Do **not** merge to `litecoin` until official LIP-0007 or a public v24 artifact. See [`LIP0007.md`](LIP0007.md).

---

## 4. Recommended follow-ons (not done here)

1. **rust-litecoin `rmweb` + LIP-0007 (on `v24-rmweb`, rev `2e4577f`):** `MwebHrp` + PSBTv2 descriptor wire. `core_psbt_lip0007` passes against v24.0.1. Do not merge to `litecoin` until CI can pin a public v24 artifact.
2. **Harness:** explicit `createwallet` `descriptors` flag; seed-parity on legacy or descriptors; peg-out credit via `include_immature_coinbase` or 6-block wait.
3. **Probe test:** `core_psbt_lip0007` — Core `walletcreatefundedpsbt` must keep `address_descriptor`; BDK fund must `decodepsbt` as v2. Vectors: v24 `src/test/util/psbt_vectors.h`.
4. **CI pin:** only after a public v24 tarball + SHA256; keep 0.21.5.6 until then.
5. Watch `generatetoaddress` around height 431 (`CreateNewBlock: bad-txns-vin-empty` seen once on this pre-release). BDK’s 431-then-activate sequence may still be right.

---

## Build notes (local only)

macOS 26 SDK: `miniupnpc` `UPNP_GetValidIGD` arity changed (configure `--without-miniupnpc`); `le32dec` / `be32dec` clash with `sys/endian.h` (same `#if __APPLE__` guards as 0.21.5.6 `scrypt.h` / `scrypt.cpp`). Not a BDK change.
