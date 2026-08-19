# Briefing for a Litecoin Core developer

**Suggested subject:** BDK Litecoin + native MWEB: light wallet stack aligned with Core / ltcsuite

**How we tested (run this first):** [TEST_EVIDENCE.md](TEST_EVIDENCE.md).

---

## What this is

We’ve forked [bitcoindevkit/bdk](https://github.com/bitcoindevkit/bdk) onto a `litecoin` branch ([LitecoinDevKit/bdk](https://github.com/LitecoinDevKit/bdk)) so wallet apps can target Litecoin (transparent + MWEB) without rewriting BDK’s `bitcoin::` API surface.

**Design choices Core would care about:**

- **Alias, don’t rewrite:** Cargo renames `bitcoin` → crates.io/`path` `litecoin` (rust-bitcoin 0.32 fork). Source keeps `use bitcoin::…`. Same pattern as electrs-ltc / litecoinspace.
- **Native Rust MWEB** (`bdk_mweb`): port semantics from ltcsuite — **no Go FFI**, no GPL Nexus/`lndltc`, no embedded `mwebd`.
- **Thin re-appliable layer** so `git merge upstream/master` stays cheap (19 `ltc:` commits on top of upstream as of 2026-07-27).

Wallet facade lives in sibling repo `LitecoinDevKit/bdk_wallet` (`litecoin`); this repo holds `bdk_core` / `bdk_chain` / clients / `bdk_mweb`.

### Validation path: Nexus first, then BDK

Practical starting point was the Litecoin Foundation **Nexus** wallet on phone — the shipped Private Litecoin / MWEB UX most users actually have. That informed what “done” had to feel like (stealth addresses, peg-in/out, MWEB send/receive) and what we refused to ship as a library backend (GPL `lndltc` / Nexus embed).

On mainnet we then used Nexus only as an **address/tx counterparty**:

1. Peg dust transparent → MWEB in BDK (`LitecoinCore`-scheme seed, Nexus-compatible).
2. **BDK → Nexus** MWEB send (proven 2026-07-27; identify by **wtxid**, not empty-skeleton `txid`).
3. **Nexus → BDK** receive via LIP sync or `scan-tx` hex paste.
4. Peg out back to BIP84 transparent.

So: Nexus is the production reference wallet and interop peer; BDK is the MIT/Apache light-wallet stack that talks to it without linking any Nexus code. Details: [LITECOIN_E2E.md](LITECOIN_E2E.md) § BDK ↔ Nexus.

---

## Commit timeline (what landed)

| Phase | Commits (summary) |
| --- | --- |
| Transparent port | Alias `bdk_core`/`bdk_chain` to rust-litecoin; Litecoin forks of miniscript 12.x, electrum-client, esplora-client; litecoind+electrs-ltc regtest; testnet Electrum receive/spend E2E |
| MWEB 0–2 | Bridge filter (don’t index HogAddr v8 / peg-in v9 as spendable); `bdk_mweb` crate; Core-compatible stealth keys; zkp smoke tests |
| MWEB 3–5 | Receive/scan, MWEB→MWEB spend, peg-in/out kernels; regtest Transparent→MWEB→Transparent |
| Persist + sync | Parallel `MwebCoinDatabase` (not in transparent graph); LIP-0006 codecs; confirmation/maturity/reorg; SQLite helpers |
| Facade + parity | Phase 6 wallet facade; mwebsync-shaped sync + PMMR verify; in-PSBT fund/sign; consume `litecoin` **0.32.8-rc.2** native `psbt::mweb`; PeerPool ban/failover |

Latest tip: `58171f0a` — *consume litecoin 0.32.8-rc.2 PSBT maps and harden PeerPool sync*.

---

## Features enabled for MWEB

**Keys / addresses**

- Stealth addresses; default derivation matches **Litecoin Core 0.21** (`m/0'/100'/{0,1}'` + BLAKE3 `'A'` tweak) so regtest lines up with `getnewaddress "" "mweb"` (not LIP-0004’s alternate paths).

**Transparent indexer correctness (Phase 0)**

- Only MWEB **bridge** scripts are non-spendable to the transparent graph: HogAddr (v8), peg-in (v9). Peg-outs and ordinary outputs still index if watched. Avoids inflated transparent balance.

**Crypto (consensus-facing)**

- `grin_secp256k1zkp` FFI: **675-byte** bulletproofs + schnorr; BlindSwitch with Core H prefix `0x0b`.
- Gate: Core peg-in `mw_tx` proofs verify under this FFI.
- Explicitly **not** Elements CT rangeproofs.

**Tx building**

- `MwebTxBuilder`: MWEB→MWEB, peg-in (`build_pegin` / wallet `prepare_mweb_pegin`), peg-out kernels.
- Peg-in kernel id follows Core (`Kernel::GetHash` = v9 program).

**PSBT (ltcsuite-shaped)**

- Typed PSBTv2 MWEB maps (`0x90+`) matching ltcd `ltcutil/psbt/types.go` (inventory locked 2026-07-27).
- Happy path: `fund_mweb_*` → `sign_funded_mweb` → scrub → `Psbt::extract_tx_with_mweb` (`mw_tx` at extract).
- Peg-in: `fund_mweb_pegin` → `sign_funded_mweb_pegin` → merge maps onto transparent PSBT → extract.
- BIP32 origins `0x9A`/`0x9B` populated via `populate_mweb_key_origins` (survive scrub).
- Extract emits stealth address `scan||spend` (66 bytes) like ltcd `extractor.go`.
- Consumes native `bitcoin::psbt::mweb` from rust-litecoin rc.2 (not proprietary `0xFC` blob stuffing).

**Light sync (LIP-0006 / mwebsync-shaped)**

- Flow: `mwebheader` → `mwebleafset` → batched `mwebutxos`.
- Differential leafset, resume, fine window **4000**, tip-wait loop.
- Default verify: header + PMMR (`leafset_root` / parent hashes vs `output_root`); multi-mountain segment bagging fixed.
- `PeerPool`: ban on connect/leafset/PMMR/timeout failures; failover in-library.
- Esplora/Electrum remain **transparent tip only** — no LIP UTXO API there.

**Wallet facade (bdk_wallet `mweb`)**

- Combined balance, `MwebStore`, peg-in prepare, fund send/peg-out; legacy `attach_mweb_tx` / `build_mweb_*` deprecated.
- MWEB coins persist in parallel ChangeSet — never inside `IndexedTxGraph`.

---

## Proven E2E

- **Testnet:** BIP84 receive + spend via Electrum-LTC.
- **Regtest:** `bdk_mweb` tests, wallet `mweb_facade`, peg-in/spend, bulletproof gate vs Core proofs.
- **Mainnet (2026-07-27):** peg-in → **send to Nexus** → peg-out loop; receive-from-Nexus path ready (`sync` / `scan-tx`). Broadcast lesson — prefer local `sendrawtransaction` + **wtxid** (empty-skeleton `txid` collision on explorers).

---

## Alignment with Core / ltcsuite (intentional)

| Area | Reference | Our stance |
| --- | --- | --- |
| PSBTv2 MWEB | ltcd `ltcutil/psbt` | Copy key map; native types in rust-litecoin |
| Sign path | ltcwallet `SignMwebComponents` | fund → sign → scrub → extract |
| Sync | `mwebsync` | Port shape; Rust peer + coin DB |
| Crypto | Core Bulletproofs/Schnorr | Same modules via zkp FFI |
| Stealth | Core `LoadMWEBKeychain` | Core paths by default |

Per Losh guidance documented in-repo: **copy ltcsuite PSBTv2 MWEB**; light sync follows **mwebsync**; do not invent a divergent map.

Related docs: [TEST_EVIDENCE.md](TEST_EVIDENCE.md), [LTCSUITE_ALIGNMENT.md](LTCSUITE_ALIGNMENT.md), [MWEB_ARCHITECTURE.md](MWEB_ARCHITECTURE.md), [PORTING.md](../PORTING.md), [LITECOIN_E2E.md](LITECOIN_E2E.md), [MWEB_PEER_OPS.md](MWEB_PEER_OPS.md).

---

## Known gaps (honest)

- `litecoin` **0.32.8-rc.2** not yet on crates.io for consumers — workspace still patches path until publish (local branch ready; push/publish blocked on GitHub write + `CARGO_REGISTRY_TOKEN`).
- Mempool watch deferred.
- Multi-peer **omission** defense incomplete (malicious peer can still omit owned UTXOs).
- No packaged Litecoin regtest Esplora (Electrum-first).
- First sync downloads full tip leafset (can be slow); later incremental via sync state.

---

## Ask / useful Core input

1. Confirm stealth path + BlindSwitch/`0x0b` expectations match what Core wants light wallets to ship long-term vs LIP-0004.
2. Any PSBT extract / kernel-id edge cases we should add as consensus test vectors.
3. Preferred trust model for LIP peers (archive litecoind vs multi-peer + omission checks).
4. When rust-litecoin rc.2 lands on crates.io, we can drop the path patch and point apps at published types.

---

## One-liner

> BDK on Litecoin can author/verify MWEB pegs and spends with Core-compatible crypto and stealth keys, sync via LIP-0006 against an archive peer with PMMR checks, and round-trip PSBTv2 MWEB maps matching ltcd — while keeping confidential coins out of the transparent UTXO index and HogAddr/v9 out of spendable balance.
