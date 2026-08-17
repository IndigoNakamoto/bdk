# BDK vs Litecoin Core v24.0.1 pre-release

Status: **review only** (2026-08-17). No CI pin, no rust-litecoin / BDK PSBT rewrite.

Pre-release tree: `/Users/indigo/Dev/litecoin-v24-master` (`Litecoin Core version v24.0.1`).
Local binary used for this pass: `src/litecoind` (built `--with-gui=no --without-miniupnpc`; macOS needed the same `scrypt.h` / `scrypt.cpp` endian guards already present on the 0.21.5.6 tree).

Losh’s LIP-0007 MWEB PSBT work is recorded as a finding. Official [lips](https://github.com/litecoin-project/lips) still only publishes LIP-0001–0006.

---

## Verdict

Consensus, stealth derivation, LIP-0006 wire, and HogEx layout look unchanged from 0.21.5.6.
**Regtest interop is blocked** by a new MWEB HRP (`rmweb` vs BDK/rust-litecoin `tmweb`).
**Wallet defaults** broke seed-parity (`createwallet` → descriptor wallet; `sethdseed` is legacy-only).
**PSBT maps have already diverged** (Core `0x96` = `mweb()` descriptor; BDK/ltcd `0x96` = u32 index + `0x9A`/`0x9B` origins). Leave BDK on the ltcd map until Losh’s LIP-0007 lands; do not rewrite types from this review.

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

Core `psbt.h` still **accepts** a 4-byte `0x96` as pre-descriptor compat and otherwise requires `mweb(` ASCII. BDK-authored **index** `0x96` can parse in Core; Core-authored **descriptor** `0x96` is dropped by rust-litecoin (`apply_kv_field` requires `value.len() == 4`) and does not land in `unknown` (type is in the MWEB range).

### Container / version (second interop gap)

BDK / rust-litecoin still serialize **PSBTv0 + `unsigned_tx`**, with parallel pure-MWEB maps as **global keys** (`type_value = field`, key = 4-byte index). Core v24 forbids MWEB fields on v0 and puts input fields **in the input map** (empty key). `walletcreatefundedpsbt` + `decodepsbt` / `finalizepsbt` will not round-trip a BDK packet as-is.

`bdk_mweb::psbt_ltcd` already ingests ltcd’s true v2 section layout for fixtures; that path is closer to Core than rust-litecoin’s default `Psbt` serialize.

### Losh / LIP-0007 stance

- No LIP-0007 text in the official lips repo or this v24 tree.
- v24 already encodes the descriptor-era map (`0x96` = `mweb()`, no `0x9A`/`0x9B`), with explicit 4-byte-index backward compat.
- **Leave BDK on the ltcd map** until Losh publishes the remaining LIP-0007 delta (or Core drops the 4-byte compat).
- Do **not** treat this pre-release as a reason to rewrite rust-litecoin types this week.
- When aligning: add `address_descriptor: Option<String>` (or reuse `0x96` as an enum), keep reading 4-byte indexes, and emit PSBTv2 section maps if Core is the interop peer.

---

## 4. Recommended follow-ons (not done here)

1. **rust-litecoin `rmweb` (on `v24-rmweb`):** `MwebHrp` distinguishes `Network::Regtest` (`rmweb`) from `NetworkKind::Test` (`tmweb`). BDK address APIs take `impl Into<MwebHrp>`; node suites pass `Network::Regtest`. Re-run on v24.0.1: `core_receive_scan`, `core_bulletproof_gate`, `core_spend`, `lip0006_*`, `mweb_anchoring` pass. Still failing: `core_seed_parity` (`sethdseed` / descriptor wallet) and `core_pegin_pegout_roundtrip` (`getreceivedbyaddress` = 0). Parked on branch `v24-rmweb` (rust-litecoin rev `dbf93a12`); do not merge to `litecoin` until CI can pin a public v24 artifact.
2. **Harness:** explicit `createwallet` `descriptors` flag; seed-parity on legacy or descriptors; peg-out credit via `include_immature_coinbase` or 6-block wait.
3. **Optional probe test:** Core `walletcreatefundedpsbt` → rust-litecoin parse (expect dropped `0x96` descriptor today) and BDK fund → Core `decodepsbt` (expect v0 / unknown globals today).
4. **CI pin:** only after a public v24 tarball + SHA256; keep 0.21.5.6 until then.
5. Watch `generatetoaddress` around height 431 (`CreateNewBlock: bad-txns-vin-empty` seen once on this pre-release). BDK’s 431-then-activate sequence may still be right.

---

## Build notes (local only)

macOS 26 SDK: `miniupnpc` `UPNP_GetValidIGD` arity changed (configure `--without-miniupnpc`); `le32dec` / `be32dec` clash with `sys/endian.h` (same `#if __APPLE__` guards as 0.21.5.6 `scrypt.h` / `scrypt.cpp`). Not a BDK change.
