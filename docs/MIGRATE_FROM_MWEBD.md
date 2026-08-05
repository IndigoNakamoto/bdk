# Migrate off embedded mwebd

This guide maps a typical **gomobile / embedded `mwebd`** wallet architecture onto LitecoinDevKit’s native Rust MWEB stack.

Design stance (unchanged): **do not embed `mwebd`**. `mwebd` remains acceptable only as an **external** server-side indexer or alternate peg-in finalizer. **Never ship `mwebd` inside the mobile/desktop binary.** See [`MWEB_ARCHITECTURE.md`](MWEB_ARCHITECTURE.md).

After this doc, use [`ADOPTION.md`](ADOPTION.md) for blessed pins and the maps-first API table (keep names in sync — maps-first only).

## Role mapping

| mwebd / Go-era role | LitecoinDevKit replacement | Notes |
| --- | --- | --- |
| In-process Go runtime (gomobile AAR/xcframework) | **Remove** | Battery/GC/nested FFI — rejected for library apps |
| Stealth key / address derivation | `MasterKeys` (`bdk_mweb` / UniFFI) | Default **Core** paths `m/0'/100'/{0,1}'` |
| Own-coin scan / rewind | LIP-0006 + `MwebSyncer` → `MwebCoinDatabase` | Scan key stays on-device |
| MWEB UTXO index inside Go | Parallel `MwebStore` (file / SQLite) | Never inside transparent `IndexedTxGraph` |
| Build MWEB / peg txs | Maps-first: `prepare_mweb_pegin`, `fund_mweb_send` / `fund_mweb_pegout` → `sign_and_extract_funded_mweb` | ltcd PSBTv2 `0x90+` maps |
| Transparent sync | Unchanged: Electrum / Esplora / RPC → `Wallet::apply_update` | Tip seam feeds MWEB dating |
| Server-side “indexer” process | Optional **external** `mwebd` or your own LIP peers | Backend/infra only — never inside the app binary |
| Core/`mwebd` peg-in finalize | Still OK as alternate | Prefer in-process maps-first when you author bodies |

## What moves in-process

1. **Keys** — derive `MasterKeys` from your seed/mnemonic. **The app owns key custody and encryption at rest** (`bdk_mweb` `encrypt` / `seal` helpers are available; LDK does not replace your secure store / Keychain / Keystore story).
2. **Coin DB** — `MwebStore` beside the wallet (`mweb.db` / SQLite + optional `mweb_sync.json` `SyncState`).
3. **Authoring** — fund → sign → scrub → `extract_tx_with_mweb` (no opaque proprietary `mw_tx` blob). Prefer maps-first whenever you author bodies in-process.
4. **Sync client** — `TcpMwebPeer` / `PeerPool` against archive Litecoin Core (or any LIP-0006 peer).

**First sync is slow.** On an empty `SyncState`, the client downloads the **full tip leafset** UTXO set (minutes under throttle; longer without peer whitelist). Later passes are differential via persisted `SyncState`. Budget product UX for resume/progress — not a missing indexer. See [`INDEXING_NOTES.md`](INDEXING_NOTES.md), [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).

## What may stay external

- **Archive LIP peers** you operate (or a public fleet) — see [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).
- **External `mwebd`** as a *server* that your backend talks to (not shipped inside the app binary).
- **litecoind RPC** for broadcast (`sendrawtransaction`) when explorers strip / mishandle `mw_tx`.

**Why wtxid:** pure MWEB txs often have an empty transparent skeleton, so many txs share the same `txid`. Explorers and naive trackers can show the wrong shell or “lose” the send. Identify and confirm by **wtxid**; prefer RPC broadcast for MWEB-only.

## Persist / recovery model

| Concern | Guidance |
| --- | --- |
| Wallet changeset | Transparent BDK persist as today |
| MWEB coins | Separate `MwebStore` — **not** folded into `Wallet::ChangeSet` |
| Differential sync cursor | Persist `SyncState` (`mweb_sync.json`) so later passes download added leaves only |
| Wiped `mweb.db` | Recoverable by full LIP tip sync + scan key (slow first pass); treat as spend-equivalent secret material while present |
| Reorg | `MwebStore::disconnect_from(height)` when transparent tip shortens |

## HD / import caveats

- LDK defaults to **Core-compatible** stealth (matches Foundation Nexus / Core `LoadMWEBKeychain`).
- **ltcwallet legacy** scope `m/1000'/2'/…` is **unsupported**.
- LIP-0004 alternate paths exist as an explicit scheme opt-in — do not mix schemes in one store.
- There is no port of ltcwallet aezeed / full recovery suite; import is seed/mnemonic → `MasterKeys` + descriptor wallet.

## Phased cutover (recommended)

**Do not dual-embed** Go/`mwebd` and LDK in the same production binary (two runtimes, two coin DBs, parity hell).

Recommended style:

1. Keep shipping the current mwebd-based app until LDK is proven.
2. Build a **secondary** LDK build / TestFlight / internal track (or feature-flagged *replacement*, not side-by-side embed).
3. Run the acceptance checks below against the same seed on regtest (and a mainnet canary if you have one).
4. Flip production to the LDK build and **delete** the gomobile AAR/xcframework from the app and CI in the same release.

There is no supported “mwebd for read, LDK for write” in-process mode. Optional external server-side `mwebd` for your backend is fine; it must not ship inside the client.

## Acceptance checks before deleting embedded mwebd

Treat cutover as done only when all of these pass on the LDK build (regtest for the loop; mainnet canary optional):

| Check | Pass criteria |
| --- | --- |
| Address parity | Same mnemonic + **Core** scheme → same `ltcmweb1…` / `tmweb1…` receive addresses as your mwebd/Core reference |
| Sync parity | After full LIP tip sync (+ persisted `SyncState`), owned UTXO set matches what you expect from the old stack (same output ids / amounts at tip; document any known height/dating differences) |
| Balance rules | UI uses maturity-aware spendable (`unspent_spendable` / maturity 6); `trusted_spendable` is not used as the sole sendable figure — see [`ADOPTION.md`](ADOPTION.md) § Balance semantics |
| Peg loop | Peg-in → wait 6 confs → MWEB send (or peg-out) succeeds end-to-end with maps-first APIs |
| Broadcast | MWEB-only txs tracked by **wtxid**; RPC broadcast works when explorers mis-display |

Only then remove gomobile/`mwebd` from the binary and CI.

## Suggested cutover steps

1. **Keep transparent wallet** on Electrum/Esplora; stop routing MWEB through gomobile in the LDK build.
2. **Introduce `MwebStore` + `MasterKeys`** from the same seed policy you standardize on (Core paths recommended); encrypt via your app secure store.
3. **Point LIP sync** at a whitelisted archive peer (`LITECOIN_P2P` / app seed list). Expect a **long first sync**; later syncs are differential via `SyncState`.
4. **Replace build/sign calls** with maps-first facade / UniFFI (`prepareMwebPegin`, `fundMwebSend` / `fundMwebPegout`, `signAndExtractFundedMweb`) — same names as [`ADOPTION.md`](ADOPTION.md).
5. **Broadcast policy:** RPC-first for MWEB-only; identify by wtxid.
6. **Run acceptance checks** (table above), then **delete embedded mwebd** from the app binary and CI.
7. Optional: keep a **backend** mwebd only if you still want a server-side indexer — wire it as infrastructure, not an app dependency.

## API cheat sheet

Canonical table: [`ADOPTION.md`](ADOPTION.md) § Maps-first MWEB API. Minimum happy path:

```text
Electrum tip → apply_update
MwebSyncer / sync_differential → MwebStore
prepare_mweb_pegin → broadcast → wait MWEB_PEGIN_MATURITY (6)
fund_mweb_send | fund_mweb_pegout → sign_and_extract_funded_mweb → broadcast
balance_combined / unspent_spendable for UI vs selection
```

Reference implementations: [`ltc-wallet-mac`](https://github.com/LitecoinDevKit/ltc-wallet-mac) (Rust product), mobile smokes (UniFFI checklist).

## Out of scope for migration

- Greenfield “MWEB Esplora” — not required; see [`INDEXING_NOTES.md`](INDEXING_NOTES.md).
- Hardware wallet signing — origins `0x9A`/`0x9B` are prepared; HWI product comes later.
- Multi-peer omission defense / mempool watch — documented gaps, not blockers for soft-key cutover.
- Dual-embed / dual-runtime parity in one production app — not supported; use a secondary build, then delete Go.
