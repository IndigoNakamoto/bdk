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

There is no regtest Esplora for Litecoin; Esplora stays on live testnet via `just test-live`.

## Notes

- Litecoin testnet here is Litecoin Core's testnet4 directory layout, unrelated to Bitcoin BIP-94.
- In the aliased API, `Network::Bitcoin` means Litecoin mainnet; `Network::Testnet4` means Litecoin testnet.
- MWEB stealth addresses (`ltcmweb1…`) are rejected by `TxBuilder` (`CreateTxError::EmptyScriptPubkey`).
- HogEx transactions decode and can be ingested; they do not inflate a transparent wallet's balance
  unless they pay a watched script pubkey.
