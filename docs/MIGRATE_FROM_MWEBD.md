# Migrate off embedded mwebd

This guide maps a typical **gomobile / embedded `mwebd`** wallet architecture onto LitecoinDevKit’s native Rust MWEB stack.

Design stance (unchanged): **do not embed `mwebd`**. `mwebd` remains acceptable only as an **external** server-side indexer or alternate peg-in finalizer. See [`MWEB_ARCHITECTURE.md`](MWEB_ARCHITECTURE.md).

## Role mapping

| mwebd / Go-era role | LitecoinDevKit replacement | Notes |
| --- | --- | --- |
| In-process Go runtime (gomobile AAR/xcframework) | **Remove** | Battery/GC/nested FFI — rejected for library apps |
| Stealth key / address derivation | `MasterKeys` (`bdk_mweb` / UniFFI) | Default **Core** paths `m/0'/100'/{0,1}'` |
| Own-coin scan / rewind | LIP-0006 + `MwebSyncer` → `MwebCoinDatabase` | Scan key stays on-device |
| MWEB UTXO index inside Go | Parallel `MwebStore` (file / SQLite) | Never inside transparent `IndexedTxGraph` |
| Build MWEB / peg txs | Maps-first: `prepare_mweb_pegin`, `fund_mweb_send` / `fund_mweb_pegout` → `sign_and_extract_funded_mweb` | ltcd PSBTv2 `0x90+` maps |
| Transparent sync | Unchanged: Electrum / Esplora / RPC → `Wallet::apply_update` | Tip seam feeds MWEB dating |
| Server-side “indexer” process | Optional **external** `mwebd` or your own LIP peers | Not linked into the app binary |
| Core/`mwebd` peg-in finalize | Still OK as alternate | Prefer in-process maps-first when you author bodies |

## What moves in-process

1. **Keys** — derive and store `MasterKeys` (encrypt at rest; `bdk_mweb` `encrypt` / app key custody).
2. **Coin DB** — `MwebStore` beside the wallet (`mweb.db` / SQLite + optional `mweb_sync.json` `SyncState`).
3. **Authoring** — fund → sign → scrub → `extract_tx_with_mweb` (no opaque proprietary `mw_tx` blob).
4. **Sync client** — `TcpMwebPeer` / `PeerPool` against archive Litecoin Core (or any LIP-0006 peer).

## What may stay external

- **Archive LIP peers** you operate (or a public fleet) — see [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).
- **External `mwebd`** as a *server* that your backend talks to (not shipped inside the mobile binary).
- **litecoind RPC** for broadcast (`sendrawtransaction`) when explorers strip / mishandle `mw_tx`. Prefer **wtxid** for pure MWEB txs (empty transparent skeleton → colliding `txid`).

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

## Suggested cutover steps

1. **Keep transparent wallet** on Electrum/Esplora; stop routing MWEB through gomobile.
2. **Introduce `MwebStore` + `MasterKeys`** from the same seed policy you standardize on (Core paths recommended).
3. **Point LIP sync** at a whitelisted archive peer (`LITECOIN_P2P` / app seed list). First sync downloads the full tip leafset; later syncs are differential.
4. **Replace build/sign calls** with maps-first facade / UniFFI (`fundMweb*` / `signAndExtractFundedMweb`).
5. **Broadcast policy:** RPC-first for MWEB-only; identify by wtxid.
6. **Delete embedded mwebd** from the app binary and CI once balances and peg loops match your acceptance tests.
7. Optional: keep a **backend** mwebd only if you still want a server-side indexer — wire it as infrastructure, not an app dependency.

## API cheat sheet

See [`ADOPTION.md`](ADOPTION.md) for the full table. Minimum happy path:

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
