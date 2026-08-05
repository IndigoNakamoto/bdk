# Adoption guide dogfood checklist

Run this against **[`ADOPTION.md`](ADOPTION.md) only** (plus docs it links). Goal: prove the guide works on a clean machine and capture every unwritten assumption.

**Rules**

- Fresh clone(s); no pre-warmed `target/`, sibling tribal knowledge, or local `.cargo/config.toml` patches unless the guide says so.
- Clock each block. Note wall time and blockers in the log table at the bottom.
- Do **not** update the blessed pin during a dogfood window — freeze pins from [`ADOPTION.md`](ADOPTION.md) § Blessed consumer pin.
- If you currently ship embedded mwebd, do Part 0 first.

## Part 0 — mwebd migrants only (≈15–30 min read)

- [ ] Open [`MIGRATE_FROM_MWEBD.md`](MIGRATE_FROM_MWEBD.md) **before** the rest of ADOPTION.
- [ ] Can you map your current roles (keys / coin DB / sync / build-sign) to the replacement table without asking anyone?
- [ ] Gap notes: _______________________________________________

## Part 1 — Orient (≈10 min)

- [ ] From the GitHub `bdk` repo root README, land on ADOPTION in one click.
- [ ] Repo map is clear: which repos you need for Rust vs mobile.
- [ ] Decision table routes your case (Rust / Swift / Android / mwebd).
- [ ] Tip + LIP diagram answers “where do MWEB UTXOs come from?” without opening other docs.

## Part 2 — ≈30 min path (transparent + MWEB sync/balance)

### Rust

- [ ] Clone `bdk` (`litecoin`) + sibling `bdk_wallet` (`litecoin`) using only guide instructions.
- [ ] Transparent Electrum BIP84 receive and/or spend per linked E2E Start here.
- [ ] Prefer Electrum when Esplora tip lags (hit or note the failure table).
- [ ] Obtain an MWEB receive address; run LIP sync into `MwebStore`; print `balance_combined` (spendable may be zero — OK).
- [ ] Did not need deprecated `build_mweb_*`.

### Mobile (pick one)

- [ ] Pin matches ADOPTION source-of-truth table (AAR `3.1.0-litecoin.1` or `ltc-swift` exact `3.1.0-litecoin.2`).
- [ ] Android: file AAR + JNA works **without** Maven Central.
- [ ] Swift: SwiftPM resolves the exact tag.
- [ ] Smoke or your stub: mnemonic → addresses → Electrum update → MWEB sync → `balanceCombined` (background thread for syncer).

**Part 2 elapsed:** ________  **Blockers:** ________

## Part 3 — Longer path (peg-in → mature → spend)

Prefer **regtest** for a single sitting; mainnet is multi-block / multi-hour.

- [ ] Chose regtest (`mweb_regtest`) or mainnet (`mainnet_mweb`) consciously from the guide’s timing split.
- [ ] Peg-in via `prepare_mweb_pegin` (or UniFFI equivalent); broadcast OK.
- [ ] Hit “not mature” / empty selection before 6 confs? Guide’s failure table / balance footgun explained it.
- [ ] After maturity: `fund_mweb_send` or `fund_mweb_pegout` → `sign_and_extract_funded_mweb`.
- [ ] Broadcast: RPC path and **wtxid** identification understood if explorer looks wrong.

**Part 3 elapsed:** ________  **Blockers:** ________

## Part 4 — Failure surface spot-checks

Without fixing the environment, confirm the guide names the issue:

| Scenario (simulate or recall) | Doc covered it? |
| --- | --- |
| No archive peer / sync stall | [ ] |
| Electrum vs Esplora tip mismatch | [ ] |
| Peg-in immature selection | [ ] |
| MWEB-only txid collision / wtxid | [ ] |
| Wrong Maven/SNAPSHOT Android install | [ ] |

## Part 5 — Pin freeze audit

- [ ] `bdk-ffi` README defers to ADOPTION as pin source of truth (no conflicting “blessed” numbers).
- [ ] Smoke app READMEs match the ADOPTION table.
- [ ] No one bumped pins mid-dogfood.

## Log (copy per run)

| Field | Value |
| --- | --- |
| Date / operator | |
| Machine (OS) | |
| Path chosen (Rust / iOS / Android) | |
| Part 2 time | |
| Part 3 time (or skipped) | |
| Unwritten knowledge required | |
| Doc fixes filed | |
| Guide grade (ship / needs edit) | |

## After the run

1. Patch ADOPTION (and linked quickstarts) for every “unwritten knowledge” line.
2. Keep the blessed pin frozen until those patches land.
3. Optional: one external/semi-external reader (ex-mwebd or evaluating native MWEB) repeats Parts 1–2.
