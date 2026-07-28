# Reviewer's Guide — Litecoin BDK / rust-litecoin MWEB

Attach this (or the paste block at the bottom) when opening PRs to **rust-litecoin** or **BDK**.
It is the narrative half of a PR summary: *why* choices were made, what was rejected, and how
live interop was proven. Test/publish checklists stay in
[`RUST_LITECOIN_PR_BODY.md`](RUST_LITECOIN_PR_BODY.md) and
[`RUST_LITECOIN_PSBT_PR.md`](RUST_LITECOIN_PSBT_PR.md).

Longer context: [`PORTING.md`](../PORTING.md), [`MWEB_ARCHITECTURE.md`](MWEB_ARCHITECTURE.md),
[`LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md), [`LITECOIN_E2E.md`](LITECOIN_E2E.md),
[`LITECOIN_CORE_BRIEFING.md`](LITECOIN_CORE_BRIEFING.md).

---

## One-liner

> BDK on Litecoin authors and verifies MWEB pegs/spends with Core-compatible crypto and stealth
> keys, syncs via LIP-0006 with PMMR checks, and round-trips PSBTv2 MWEB maps matching ltcd —
> without embedding Go/GPL, inventing a proprietary PSBT map, or stuffing HogAddr/v9 into the
> transparent UTXO index.

---

## What landed (map)

| Layer | Deliverable |
| --- | --- |
| Transparent port | Cargo alias `bitcoin` → `litecoin`; thin re-appliable `litecoin` branch |
| Phase 0 | Bridge filter: HogAddr (v8) / peg-in (v9) not spendable; peg-outs still indexed |
| `bdk_mweb` | Stealth keys, rewind scan, `MwebTxBuilder`, peg-in/out, parallel `MwebCoinDatabase` |
| Crypto | `grin_secp256k1zkp` FFI — 675-byte bulletproofs + schnorr; BlindSwitch H prefix `0x0b` |
| Sync | LIP-0006 + mwebsync-shaped tip loop / PeerPool; default `HeaderAndPmmr` |
| PSBT | Native `bitcoin::psbt::mweb` in rust-litecoin **0.32.8-rc.2**; BDK fund/sign/scrub/extract |
| Wallet facade | Sibling `bdk_wallet` `mweb` feature — combined balance, prepare/fund paths |

---

## Design invariants (non-negotiables)

1. **Alias, don’t rewrite** — source keeps `use bitcoin::`; swap is manifest-only
   ([`PORTING.md`](../PORTING.md)). `.rs` merge conflicts vs upstream = port drift.
2. **MIT OR Apache-2.0** — no GPL Nexus/`lndltc` or in-process Go runtime.
3. **Bifurcated state** — MWEB coins live in `MwebCoinDatabase`, never in transparent
   `IndexedTxGraph`.
4. **Copy ltcsuite PSBT / sync shape** — do not invent a parallel key map; port semantics, don’t
   FFI Go.
5. **Consensus crypto via C-FFI** — same bulletproof/schnorr modules Core uses; not Elements CT,
   not pure-Rust Bulletproofs.
6. **Core-compatible stealth by default** — `m/0'/100'/{0,1}'` + BLAKE3 `'A'` tweak (matches
   Core `LoadMWEBKeychain`, not LIP-0004’s alternate paths).

---

## False paths (explicitly rejected)

| Approach | Why rejected |
| --- | --- |
| Embed Nexus / `lndltc` | GPL-3.0; wrong library product shape |
| Embedded gomobile-`mwebd` | Go runtime / GC / battery; nested FFI |
| Opaque BIP174 `0xFC` proprietary `mw_tx` blob | Wrong interop; use ltcd `0x90+` maps |
| Index HogAddr / v9 as UTXOs | Inflates transparent balance |
| Elements CT `rangeproof_sign` | Wrong proof system (not 675-byte MWEB BPs) |
| Pure-Rust Bulletproofs | Consensus risk |
| Go FFI to ltcd/mwebsync | License/ops; port semantics instead |
| Divergent PSBT key map | Breaks cross-wallet interop |
| ltcwallet legacy HD `m/1000'/2'/…` | Unsupported; Core paths only (+ explicit LIP-0004 opt-in) |

---

## Reference lock

| Area | Reference | Stance |
| --- | --- | --- |
| Stealth / BlindSwitch | Litecoin Core 0.21 | Core paths + H prefix `0x0b` |
| Bulletproofs / Schnorr | Core / `grin_secp256k1zkp` | Gate: Core peg-in proofs verify under FFI |
| PSBTv2 MWEB | ltcd `ltcutil/psbt` | Key codes locked 2026-07-27; see alignment doc |
| Sign path | ltcwallet `SignMwebComponents` | fund → sign → scrub → `extract_tx_with_mweb` |
| Light sync | `mwebsync` | Differential leafset, tip loop, PeerPool failover |
| Interop peer | Foundation Nexus | Address/tx counterparty only — no linked Nexus code |

Golden data (port vectors, not Go tests): `crates/mweb/tests/fixtures/` + `ltcd_*` tests
(regen: `scripts/ltcd_mweb_fixtures`).

---

## Live proof

| Stage | Evidence |
| --- | --- |
| Unit / Core gate | Seed parity; `core_bulletproof_gate` verifies Core peg-in proofs |
| Regtest | `bdk_mweb` receive/spend/peg round-trips; wallet `mweb_facade` (`LITECOIND_EXE`) |
| Testnet | BIP84 Electrum receive + spend (faucet-funded; see E2E doc) |
| Mainnet (2026-07-27) | Peg-in → **BDK → Nexus** send → peg-out; receive via LIP sync / `scan-tx` |

**Broadcast lesson:** pure MWEB txs share an empty-skeleton `txid`; identify by **wtxid** and
prefer local `sendrawtransaction` when explorers/Esplora lag. Details and txids:
[`LITECOIN_E2E.md`](LITECOIN_E2E.md).

---

## How to read the diff (by PR target)

### rust-litecoin (types / PSBT)

Open PR: https://github.com/rust-litecoin/rust-litecoin/pull/9 (`0.32.8-rc.2`)

Focus on:

- First-class `psbt::mweb` maps (`0x90+` globals/inputs/outputs + kernel fields)
- `Psbt::extract_tx_with_mweb` — assemble `Transaction.mw_tx` from maps only (no sidecar)
- BIP32 origins `0x9A`/`0x9B` as `(PublicKey, KeySource)` matching ltcd wire
- Reject `unsigned_tx.mw_tx` / `is_hog_ex` on PSBT construct

BDK already consumes this via path patch until crates.io publishes rc.2.

### BDK (`litecoin` branch / `bdk_mweb`)

Focus on:

- Manifest alias + HogEx field init (almost no Bitcoin-source rewrite)
- Phase 0 bridge filter in the indexer
- New crate `crates/mweb` (`bdk_mweb`) — crypto, scan, tx build, LIP/mwebsync, thin PSBT helpers
- Parallel persist (`ChangeSet` / `MwebStore`) — not folded into `Wallet::ChangeSet`
- Wallet facade lives in sibling [`IndigoNakamoto/bdk_wallet`](https://github.com/IndigoNakamoto/bdk_wallet)
  `litecoin` branch

Merge hygiene: `master` tracks upstream unmodified; `litecoin` should stay re-appliable
(manifest conflicts OK; `.rs` drift is a bug).

---

## Honest gaps / non-goals

- `litecoin` **0.32.8-rc.2** not yet on crates.io for consumers (workspace path patch retained)
- Mempool watch deferred
- Multi-peer **omission** defense incomplete
- No packaged Litecoin regtest Esplora (Electrum-first)
- First LIP sync downloads full tip leafset (later passes incremental via `SyncState`)
- Not embedding Nexus/mwebd; not supporting ltcwallet legacy MWEB HD scope

---

## Suggested PR summary paste

Copy into `gh pr create --body` (link the full Guide from the fork/docs tree):

```markdown
## Summary

Native Litecoin/MWEB work for light wallets — not speculative.

- **Alias, don’t rewrite:** Cargo renames `bitcoin` → `litecoin`; source keeps `use bitcoin::`.
- **Native Rust MWEB** (`bdk_mweb`): Core-compatible stealth + zkp FFI (675-byte BPs); no Go/GPL embed.
- **PSBT:** First-class ltcd `0x90+` maps (rust-litecoin 0.32.8-rc.2); fund → sign → scrub → extract.
- **Sync:** LIP-0006 / mwebsync-shaped tip loop with PMMR verify; MWEB coins stay out of IndexedTxGraph.
- **Phase 0:** HogAddr v8 / peg-in v9 are not spendable UTXOs; peg-outs still index if watched.

### False paths rejected

Nexus/`lndltc` embed, gomobile-mwebd, proprietary BIP174 `0xFC` mw_tx blobs, Elements CT
rangeproofs, pure-Rust Bulletproofs, inventing a non-ltcsuite PSBT map.

### Live proof

Regtest Core gates + testnet Electrum spend; mainnet 2026-07-27 peg-in → BDK→Nexus send → peg-out
(identify pure MWEB by **wtxid**). Fixtures: ltcd golden vectors under `crates/mweb/tests/fixtures/`.

### Reviewer's Guide

Full invariants / gaps / how to read the diff:
`docs/REVIEWERS_GUIDE.md` (this fork).
```
