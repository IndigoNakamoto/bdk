# Litecoin end-to-end: sync, receive, spend

This walkthrough is the "works end to end" artifact for the Litecoin fork. It uses the
ported `bdk_wallet` against live Litecoin testnet infrastructure.

## Prerequisites

- This BDK workspace (`IndigoNakamoto/bdk`, branch `litecoin`) with `examples/ltc-scan`
- Nested or sibling [`IndigoNakamoto/bdk_wallet`](https://github.com/IndigoNakamoto/bdk_wallet)
  on branch `litecoin`
- Network access to Electrum-LTC (`ssl://electrum-ltc.bysh.me:51002`) and optionally
  `https://litecoinspace.org/testnet/api`
- A Litecoin testnet faucet (e.g. [CypherFaucet](https://cypherfaucet.com/ltc-testnet) API or UI)

## Recorded run (2026-07-27)

| Field | Value |
| --- | --- |
| Receive address | `tltc1q5yxey46gne59mksrqe3rjrwpw7zjltcn9hkhzw` |
| Descriptor | BIP84 `wpkh(tprv…/84'/1'/0'/{0,1}/*)` on `Network::Testnet4` |
| Funding | CypherFaucet `POST /api/v1/claim` → **0.01 tLTC** |
| Funding txid | `d2b2be15b6dc0b70529c7b01fa277d52df0eba3457445afd15b0aca297f0f9e0` |
| Funding anchor | height **4824749** (Electrum-LTC `electrum-ltc.bysh.me:51002`) |
| Spend | send-to-self **5000** litoshis at **1 sat/vB** via `examples/electrum` |
| Spend txid | `a0b4b80f9c123a359a586850d3ffcccb6d7d0f6c6fca6b911255bbf135d2a323` |
| Spend status | accepted into Electrum mempool (`height: 0`, fee 141 litoshis) after broadcast |

**Note:** At the time of this run, litecoinspace testnet Esplora tip (~4777631) lagged Electrum-LTC
(~4824749) by tens of thousands of blocks, so the faucet funding and spend were invisible to
`https://litecoinspace.org/testnet/api`. Prefer the Electrum example for live E2E until Esplora
catches up.

## 1. Watch-only sync (Phase 1 crates only)

From the BDK workspace:

```bash
cargo run -p ltc-scan -- \
  "wpkh(tpub.../0/*)" \
  --network testnet \
  --backend electrum
```

Defaults: Esplora `https://litecoinspace.org/testnet/api`, Electrum
`ssl://electrum-ltc.bysh.me:51002`. Live regression tests:

```bash
just test-live
```

## 2. Create a BIP84 testnet wallet and receive

From `bdk_wallet` (path-deps against this workspace when nested under `bdk/`):

```bash
cargo run --example electrum --features "std,rusqlite"
```

The example:

- Opens `bdk-example-electrum.sqlite`
- Uses a BIP84 `wpkh(tprv…/84'/1'/0'/{0,1}/*)` descriptor on `Network::Testnet4`
- Syncs against `ssl://electrum-ltc.bysh.me:51002` with `validate_domain(false)`
- Prints a `tltc1…` receive address

Example output from a fresh run:

```
Generated Address: tltc1q5yxey46gne59mksrqe3rjrwpw7zjltcn9hkhzw
```

Fund that address from a faucet (CypherFaucet API example):

```bash
curl -X POST https://cypherfaucet.com/api/v1/claim \
  -H 'Content-Type: application/json' \
  -d '{"network":"ltc-testnet","address":"tltc1q5yxey46gne59mksrqe3rjrwpw7zjltcn9hkhzw"}'
```

Amounts print as "BTC" because the `litecoin` crate inherited rust-bitcoin's `Amount` display;
the unit is litoshis (1e-8 LTC).

Re-run the example until the balance is non-zero. It then builds a send-to-self transaction at an
**explicit fee rate**, signs, and broadcasts via `ElectrumClient::transaction_broadcast`.

Esplora path (when litecoinspace tip matches the network):

```bash
cargo run --example esplora_blocking --features "std,rusqlite"
```

## 3. Confirm the broadcast

After broadcast the example prints a litecoinspace tx URL (may 404 while Esplora lags). Verify on
Electrum-LTC or wait for a testnet block, then re-sync:

```bash
cargo run --example electrum --features "std,rusqlite"
```

Expect the outgoing transaction in the wallet's history; once mined it anchors at a testnet height.

## 4. Local regtest (optional)

Chain and Electrum daemon tests can run against `litecoind` + [`electrs-ltc`](https://github.com/rust-litecoin/electrs-ltc)
(no prebuilt electrs releases; build from source):

```bash
export LITECOIND_EXE=/path/to/litecoind
export ELECTRS_LTC_EXE=/path/to/electrs
just test-regtest
```

**Electrum-first regtest:** chain/daemon coverage uses `litecoind` + `electrs-ltc` via
`just test-regtest`. There is no packaged Litecoin regtest Esplora; Esplora stays on live
testnet via `just test-live`.

MWEB peg-in acceptance (node-only, needs `LITECOIND_EXE`):

```bash
cargo test -p bdk_testenv --features litecoin-daemon --test mweb_pegin
# and from bdk_wallet:
cargo test --test mweb_pegin
```

See [`MWEB_PEGIN.md`](MWEB_PEGIN.md) for the spike vectors and Core-finalize decision.

### MWEB facade + LIP-0006 tip seam

```text
Electrum/Esplora/RPC → Wallet::apply_update / apply_block
  → tip = wallet.latest_checkpoint()
  → (on shorter tip) MwebStore::disconnect_from(new_tip + 1)
  → MwebSyncer::run_once (differential leafset + fine-window dating)
     or sync_mweb_at_tip (one-shot full UTXO download at tip height)
  → persist MwebStore (+ optional mweb_sync.json SyncState)
```

1. Author peg-in with `Wallet::prepare_mweb_pegin` (feature `mweb`), sign,
   `extract_pegin_with_mweb_psbt`, broadcast **before** mining MWEB activation (mempool peg-in
   required on regtest).
2. Mine peg-in maturity (`MWEB_PEGIN_MATURITY` = 6), sync transparent tip with `apply_block`.
3. Optional reorg: `MwebStore::disconnect_from(fork_height)`.
4. Verified LIP sync: `TcpMwebPeer::connect(env.p2p_addr(), …)` +
   `MwebStore::sync_differential` / `bdk_mweb::mweb_sync::MwebSyncer`
   (or legacy `sync_at_tip` / `sync_mweb_at_tip`).
5. Persist beside the wallet: `MwebStore::persist_file_store` / `mweb-sqlite`. Encrypt with
   `bdk_mweb::seal` / `seal_changeset`. Persist `SyncState` (`leafset` + height map) beside the store
   so the next pass only downloads **added** leaves.
6. Peg-out / send from **spendable** coins (`unspent_spendable` / maturity gate):
   `build_mweb_pegout` / `build_mweb_send` (`*_with(..., include_unconfirmed)` bypass).

No separate Electrum+MWEB binary is required for regtest; the tip seam is identical.

Example:

```bash
cargo run --example mweb_regtest --features "mweb,file_store,test-utils"
```

### BDK ↔ Nexus (mainnet)

Use the existing transparent wallet from `mainnet_receive` plus the `mainnet_mweb` CLI.
Nexus on your phone is only an address/tx counterparty (no Nexus code in BDK).

```bash
cd bdk_wallet
# 1) Print BDK ltcmweb1… for Nexus to pay (or copy Nexus receive into send --to)
cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- address

# 2) Peg dust from transparent into MWEB (wait 6 confirmations before spending)
cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- pegin --amount 0.001

# 3) Send MWEB → Nexus
cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- \
  send --to ltcmweb1… --amount 0.0005

# 4a) Receive from Nexus: LIP sync (needs a reachable mainnet litecoind P2P)
#     See [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md). After IBD (`initialblockdownload=false`):
export LITECOIN_P2P=127.0.0.1:9333
#     First sync tip-dates by default; MWEB_FINE_SYNC=1 for fine-window dating.
cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- sync

# 4b) Or paste raw tx hex (no litecoind / no IBD) after Nexus payment is on explorers
cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- \
  scan-tx --hex <rawtx>

# 5) Peg out to a fresh BIP84 ltc1… (or --to)
cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- pegout --amount 0.0005

cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- balance
```

Secrets / store (keep private):

- `mainnet-e2e-wallet/SECRET_DO_NOT_SHARE.txt` — transparent BIP84
- `mainnet-e2e-wallet/mweb_SECRET.txt` — MWEB `LitecoinCore` seed (Nexus-compatible)
- `mainnet-e2e-wallet/mweb.db` — `MwebStore` (magic `bdk_mweb_v2`; pre-`leaf_index` v1 files are
  auto-backed-up and rebuilt on `sync`)
- `mainnet-e2e-wallet/mweb_sync.json` — differential sync cursor (`SyncState`)

If Esplora rejects an MWEB-only broadcast, set `LITECOIN_RPC_URL` (+ `LITECOIN_RPC_USER` /
`LITECOIN_RPC_PASS`) for `sendrawtransaction`. Peg-in maturity is **6** blocks
(`MWEB_PEGIN_MATURITY`) before `send` / `pegout` select coins.

### Mainnet LIP sync status (Phase 0)

- litecoind IBD complete (`blocks == headers`, `initialblockdownload=false`) and P2P `9333` accepts
  `TcpMwebPeer` (validated 2026-07-27).
- First differential sync downloads the **full** tip leafset UTXO set (can take a long time); later
  passes are incremental via `mweb_sync.json`. Tip-only dating is the default on empty SyncState.
- Peer ops: [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).

### Mainnet E2E loop (2026-07-27)

| Step | Result |
| --- | --- |
| Baseline `sync` + `balance` | Transparent `0.00398650`; MWEB spendable `0.00006100` (leaf `347131`); tip `3149837`. |
| Peg-in `0.001` (fee `50000`) | Tx [`dd5c2b03…`](https://litecoinspace.org/tx/dd5c2b03fe609fdc4ae65e8909b12c5a4155cb3cef20d889b7fa5459986b6853) via **Esplora** (`extract_pegin_with_mweb_psbt`). Kernel `52536241…`. Inclusion `3149838`; mature after 6 confs. |
| Send → Nexus `0.0004` (fee `3900`) | Destination `ltcmweb1qqv6mpy9…`. Pure MWEB: **`txid` ignores `mw_tx`** (all empty-skeleton txs share `4ebd325a…`); identify by **wtxid**. On-chain: spent peg-in leaf, change `0.00006100` at height `3149847`. CLI now prefers `LITECOIN_RPC_URL` for MWEB-only. |
| Receive ← Nexus | BDK address ready via `address` (e.g. idx 6 `ltcmweb1qqdqpp0…`). Pay from Nexus → `sync` / `scan-tx` (operator). |
| Peg-out `0.00002` (fee `3900`) | HogEx credited BIP84 `ltc1q4caq8…`; transparent `+0.00002` (balance `0.00299650`). Remaining MWEB change `0.00000200` + prior send change. |

**Broadcast lesson:** litecoinspace may show a 12-byte empty shell under the colliding MWEB `txid`. Use local `sendrawtransaction` + **wtxid**; see [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).

CLI happy path uses `MwebPsbt` extract only (`attach_mweb_tx` deprecated).

## Notes

- Litecoin testnet here is Litecoin Core's testnet4 directory layout, unrelated to Bitcoin BIP-94.
- In the aliased API, `Network::Bitcoin` means Litecoin mainnet; `Network::Testnet4` means Litecoin testnet.
- **HogAddr (v8) / peg-in (v9)** bridge outs are never indexed as spendable UTXOs; **peg-out**
  p2wpkh/p2tr outs in the same HogEx still credit the wallet when watched.
- MWEB stealth destinations (`ltcmweb1…` / `tmweb1…`) raise `CreateTxError::MwebPegInRequiresKernel`.
  Peg-in: `Wallet::prepare_mweb_pegin` + `extract_pegin_with_mweb_psbt` (Core finalize still OK).
- Facade: `balance_combined` (confirmation buckets), `MwebStore`, `prepare_mweb_pegin`,
  `fund_mweb_send` / `fund_mweb_pegout` → `sign_and_extract_funded_mweb`, plus legacy
  `build_mweb_send` / `build_mweb_pegout` (feature `mweb`). See [`MWEB_ARCHITECTURE.md`](MWEB_ARCHITECTURE.md).

MWEB spend / peg / facade acceptance (needs `LITECOIND_EXE`):

```bash
cargo test -p bdk_mweb --test core_spend --test core_bulletproof_gate --test core_pegin_pegout_roundtrip
cargo test -p bdk_wallet --test mweb_facade
```
- HogEx transactions decode and can be ingested; bridge outputs never inflate transparent balance.
