# Test evidence (transparent + MWEB)

**Start here** if you are reviewing this fork for Litecoin Core or ltcsuite.
This page is the run-this packet. Design narrative, recipes, and finding→test
IDs live in the appendices.

Two independent claims:

| Claim | Meaning |
| --- | --- |
| **Transparent** | We are on Litecoin wire and types, not Bitcoin with LTC branding. HogEx does not inflate spendable balance. |
| **MWEB** | Keys, proofs, kernels, and PSBT maps match Core / ltcsuite. `litecoind` accepts what we author. |

Nexus interop is last, not first. Default `cargo test` / the `bdk_mweb` CI job
**compile** the node-backed suites and then **skip** them when `LITECOIND_EXE`
is unset. That green is not a Core gate.

---

## Run this (~30 minutes)

From the repo root. Layers 1–2 need no node.

```bash
# 1. Pin we are on Litecoin (genesis, magic, addresses, HogEx, bridge filter)
cargo test -p bdk_chain --test test_litecoin
cargo test -p bdk_electrum --test litecoin
cargo test -p bdk_esplora --test litecoin

# 2. Golden data from ltcd (port vectors, not Go tests)
cargo test -p bdk_mweb --lib -- ltcd_
cargo test -p bdk_mweb --test ltcd_psbt_fixtures
```

Layer 3 — live `litecoind` as oracle. Use **your** binary if you have one;
CI pins Litecoin Core **0.21.5.6**.

```bash
export LITECOIND_EXE=/path/to/litecoind
export REQUIRE_LITECOIND=1   # skip → hard fail

cargo test -p bdk_mweb --all-features --test-threads=1 \
  --test core_seed_parity \
  --test core_bulletproof_gate \
  --test core_receive_scan \
  --test core_spend \
  --test core_pegin_pegout_roundtrip
```

Optional extras (same env): `--test lip0006_sync --test lip0006_p2p --test lip0006_throttle --test mweb_anchoring`.

---

## Trust ladder

### 1. Pin we are on Litecoin (always-on CI)

[`crates/chain/tests/test_litecoin.rs`](../crates/chain/tests/test_litecoin.rs)
plus Electrum / Esplora HogEx fixtures.

- Genesis + magic for mainnet / testnet4 / regtest
- `L` / `M` / `ltc1` / `tltc1` parse; Bitcoin `1` / `bc1` rejected
- Real mainnet HogEx (`9fead093…`, last tx of block 3,149,263) decodes and re-encodes
- **Bridge filter:** HogAddr v8 / peg-in v9 never spendable; peg-out p2wpkh in the same HogEx still indexes

A transparent-only wallet still meets a HogEx at the end of every post-activation
block. Esplora JSON rebuilds that tx **without** `is_hog_ex`; the filter is
script inspection, not the flag.

### 2. Golden data from *their* repos (no node)

Port **data**, not Go test logic. Regen (dev machine, not CI):
[`scripts/ltcd_mweb_fixtures/README.md`](../scripts/ltcd_mweb_fixtures/README.md).

- ltcd `createOutput` / `SignMWEBComponents` / kernel maps under
  [`crates/mweb/tests/fixtures/`](../crates/mweb/tests/fixtures/)
- Rust asserts commitment, keys, `OutputMessage` preimage
- **Bulletproofs are not byte-identical** (`ltcsuite/secp256k1` vs
  `grin_secp256k1zkp`). Tests rewind both sides; they do not compare proof bytes
- `psbt_from_ltcd_v2`: ltcd PSBTv2 globals ≠ rust-litecoin v0 encoding
- Map inventory locked against ltcd `ltcutil/psbt/types.go`
  ([`LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md))

### 3. Live `litecoind` as oracle

| Test | Proves |
| --- | --- |
| `core_seed_parity` | After `sethdseed`, `getnewaddress "" "mweb"` == BDK `LitecoinCore` `m/0'/100'/{0,1}'` |
| `core_bulletproof_gate` | A **Core-authored** 675-byte peg-in proof verifies under the Grin/MW FFI |
| `core_receive_scan` | Core `sendtoaddress` → BDK `rewind_output` finds the coin |
| `core_spend` | BDK-authored spend; node accepts |
| `core_pegin_pegout_roundtrip` | Transparent → MWEB → transparent through the node |

CI that actually runs this:
[`.github/workflows/regtest_mweb.yml`](../.github/workflows/regtest_mweb.yml)
(`REQUIRE_LITECOIND=1`, serial, Core 0.21.5.6 pinned by SHA256).

### 4. Transparent live stack (Electrum-first)

Recorded 2026-07-27 in [`LITECOIN_E2E.md`](LITECOIN_E2E.md):

| | |
| --- | --- |
| Receive | `tltc1q5yxey46gne59mksrqe3rjrwpw7zjltcn9hkhzw` |
| Funding | `d2b2be15…` @ height 4824749 (Electrum-LTC) |
| Spend | `a0b4b80f…` send-to-self 5000 lit, mempool-accepted |

```bash
just test-live       # ignored tests: litecoinspace + electrum-ltc.bysh.me
just test-regtest    # needs LITECOIND_EXE + ELECTRS_LTC_EXE; narrow (not the MWEB suite)
```

No packaged Litecoin regtest Esplora. At the recorded run, litecoinspace testnet
lagged Electrum-LTC by tens of thousands of blocks.

### 5. Mainnet Nexus loop (last)

Operator + `mainnet_mweb` CLI vs archive litecoind. Nexus is an address/tx
counterparty only — no Nexus / `lndltc` / `mwebd` code. Identify pure MWEB by
**wtxid** (empty-skeleton `txid` collision). Full rows:
[`LITECOIN_E2E.md`](LITECOIN_E2E.md) § BDK ↔ Nexus.

| Date | Step | Id |
| --- | --- | --- |
| 2026-07-27 | Peg-in 0.001 | tx [`dd5c2b03…`](https://litecoinspace.org/tx/dd5c2b03fe609fdc4ae65e8909b12c5a4155cb3cef20d889b7fa5459986b6853) |
| 2026-07-27 evening | Peg-in 0.001 | tx [`3720023e…`](https://litecoinspace.org/tx/3720023e2017b152794a5e58fa66e8fc615c04787db452d0b29dd467504b3632) |
| 2026-07-27 evening | BDK → Nexus 0.0004 | **wtxid** `fd2aed89…` |
| 2026-07-27 evening | Peg-out 0.001 | **wtxid** `e8a3f735…` |
| 2026-07-28 | Transparent BDK → Nexus 0.001 | tx [`6c47ce79…`](https://litecoinspace.org/tx/6c47ce792c1e2ab463ec1bb3f6a2b696116a56712544efb1b88f133eb5b388b8) |
| 2026-07-28 | Transparent Nexus → BDK 0.001 | tx [`0bfd6404…`](https://litecoinspace.org/tx/0bfd64041e18a14fd2bb96e93a3061618ed8d430cdfd49f943b7f6cd14a7b536) |
| 2026-07-28 | Peg-in 0.001 | tx [`912414f1…`](https://litecoinspace.org/tx/912414f11d0d58035e51bece3a21d7bd9da84352aa12c458d002ba732cbcb032) |
| 2026-07-28 | BDK → Nexus MWEB 0.0004 | **wtxid** `1ce1ea99…` |
| 2026-07-28 | Peg-out 0.001 | **wtxid** `420ecc76…` |

---

## What CI actually proves

| Workflow | What it runs | What it does not |
| --- | --- | --- |
| [`cont_integration.yml`](../.github/workflows/cont_integration.yml) `build-mweb` | `cargo test --all-features` (no node) | Core gates — they return early |
| [`regtest_mweb.yml`](../.github/workflows/regtest_mweb.yml) | Node-backed `core_*` + LIP + anchoring | Wallet facade (sibling repo) |
| [`fuzz.yml`](../.github/workflows/fuzz.yml) | honggfuzz LIP codecs / PMMR / rewind | Consensus accept |
| `cont_integration.yml` Miri | `pmmr::` `p2p::` `limits::` `secret::` (no zkp FFI) | Crypto / node |

Fuzz and Miri are the hostile-peer / UB layer. They do not replace layer 3.

---

## Live demo (Core call)

1. `core_seed_parity` — addresses match `getnewaddress "" "mweb"`
2. `core_bulletproof_gate` — their proof, our FFI
3. `core_pegin_pegout_roundtrip` — `sendrawtransaction` accepted
4. One mainnet **wtxid** on litecoinspace

For **ltcsuite**: open [`LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md) at the
`0x90+` map and “port data, not Go tests,” then run `ltcd_psbt_fixtures`.

---

## Honest gaps

- LIP sync **admits** UTXOs on header + leafset + PMMR. Rangeproofs are not
  verified at sync; they are checked at spend. Adversarial PMMR:
  [`crates/mweb/tests/pmmr_adversarial.rs`](../crates/mweb/tests/pmmr_adversarial.rs)
- Multi-peer **omission** defense incomplete (a malicious peer can hide owned UTXOs)
- Mempool watch deferred
- No packaged Litecoin regtest Esplora (`just test-regtest` is Electrum-narrow)
- First LIP sync downloads the full tip leafset; later passes are incremental
- `litecoin` **0.32.8-rc.2** not on crates.io yet (workspace path patch)
- Wallet facade tests (`mweb_facade`, `mweb_pegin`) live in sibling `bdk_wallet`
- ltcwallet legacy HD `m/1000'/2'/…` unsupported; Core paths only

Finding → test IDs: [`SECURITY_PLAN.md`](SECURITY_PLAN.md).

---

## Appendices

| Doc | Role |
| --- | --- |
| [`LITECOIN_CORE_BRIEFING.md`](LITECOIN_CORE_BRIEFING.md) | What landed, asks for Core |
| [`REVIEWERS_GUIDE.md`](REVIEWERS_GUIDE.md) | Invariants, rejected backends |
| [`LITECOIN_E2E.md`](LITECOIN_E2E.md) | Recipes + full recorded runs |
| [`LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md) | PSBT map + mwebsync inventory |
| [`SECURITY_PLAN.md`](SECURITY_PLAN.md) | Threat model / finding→test IDs |
| [`MWEB_ARCHITECTURE.md`](MWEB_ARCHITECTURE.md) | Crate shape |
| [`crates/mweb/README.md`](../crates/mweb/README.md) | Crate-local test commands |
| [`crates/mweb/fuzz/README.md`](../crates/mweb/fuzz/README.md) | Fuzz targets |
