# Indexing reality check (light)

Status: **supporting notes** for integrators — not a roadmap to build a greenfield MWEB indexer.

## What “indexing” means in LDK today

| Domain | Backend | Maturity |
| --- | --- | --- |
| Transparent tip + UTXOs | `bdk_electrum` / `bdk_esplora` / `bdk_bitcoind_rpc` | Production (Electrum-first for Litecoin) |
| MWEB UTXOs | LIP-0006 P2P via `MwebSyncer` / `TcpMwebPeer` / `PeerPool` | Production (mainnet-validated) |
| Combined wallet view | Tip seam + parallel `MwebCoinDatabase` | Production |

Electrum and Esplora forks in this workspace are **transparent-only**. They may decode HogEx for bridge filtering; they do **not** expose an LIP UTXO API. Do not plan on “Esplora-for-MWEB” as a prerequisite to ship.

## Tip seam (integrator contract)

```text
1. Sync transparent chain → Wallet::apply_update / apply_block
2. tip = (block_hash, height) from wallet.latest_checkpoint()
3. On shorter tip → MwebStore::disconnect_from(new_tip + 1)
4. MwebSyncer::run_once / sync_differential* (or one-shot sync_mweb_at_tip)
5. Persist MwebStore + SyncState (leafset + height map)
```

Apps must supply:

1. **Tip provider** — Electrum, Esplora, or RPC (already in BDK).
2. **LIP peer(s)** — archive Litecoin Core (or equivalent) serving `mwebheader` / `mwebleafset` / `getmwebutxos`. See [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md) (whitelist `noban` on 0.21.5.6+).
3. **Persist** — `MwebStore` + optional `mweb_sync.json` so passes after the first are differential.

## `MwebUtxoSource` (API surface, docs-only summary)

Trait in `bdk_mweb::lip0006` (implementations: `TcpMwebPeer`, test doubles):

| Method | Role |
| --- | --- |
| `get_header(block_hash)` | `mwebheader` |
| `get_leafset(block_hash)` | leafset for differential sync |
| `get_utxos` / `get_utxos_pipelined` | FULL_UTXO batches |

Higher level: `MwebSyncer` owns the mwebsync-shaped loop (verify modes, fine window, failover). Wallet code should prefer syncer/`MwebStore` helpers over hand-rolling the trait unless you are adding a new transport (e.g. future external HTTP bridge).

**Not building now:** a second parallel coin graph, Electrum method extensions for MWEB, or embedding `mwebd` as the `MwebUtxoSource` inside the app. An external server could *conceptually* implement the trait later; that is an option list item, not current work.

## First-sync cost (measured shape)

- On empty `SyncState`, the client downloads the **full tip leafset** UTXO set, then persists cursor state.
- Later passes use `diff_leafsets` and fetch **added** leaves only (`mweb_sync.json` beside the store).
- Default dating on first sync: **tip-only** (fast). Fine window default after that: **4000** (mwebsync-aligned); override with `MWEB_FINE_SYNC=tip` for interactive runs.
- Core 0.21.5.6+ rate-limits non-whitelisted serve (~0.5 req/s refill). Whitelist clients or expect multi-minute first syncs even with large batches (`MAX_REQUESTED_MWEB_UTXOS` = 4096).
- Rough request count at full batch width: on the order of **tens to low hundreds** of `getmwebutxos` calls for a full mainnet tip leafset (not thousands), dominated by throttle and PMMR verify — not by missing “an Esplora.”

Exact wall-clock depends on peer hardware, whitelist, and network; treat first sync as a **product UX** concern (progress, resume via `SyncState`), not as evidence that LDK needs a new indexer crate.

## Honest gaps (deferred)

| Gap | Stance |
| --- | --- |
| Multi-peer **omission** defense | Incomplete — malicious peer can omit owned UTXOs; compare-across-peers is future work |
| Mempool watch | Deferred (wallet callback, not syncer) |
| Public seed product | Apps ship `LITECOIN_P2P` / discover helpers; no Foundation-wide guaranteed free archive SLA |
| Packaged Litecoin regtest Esplora | None — Electrum-first regtest |

## Options for later (explicitly not this phase)

1. **Harden the P2P light client** — omission defense, richer seed lists, better UX around throttle.
2. **Optional external indexer** — server-side `mwebd` or custom service implementing `MwebUtxoSource`-shaped APIs; app stays MIT/Apache without Go embed.
3. **Do not** rewrite sync as Bitcoin-style compact filters or invent Electrum MWEB methods without a Litecoin ecosystem standard.

## Related docs

- [`ADOPTION.md`](ADOPTION.md) — integrator entry
- [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md) — ops
- [`LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md) §2 — mwebsync parity table
- [`LITECOIN_E2E.md`](LITECOIN_E2E.md) — tip seam recipes
