# Litecoin end-to-end: sync, receive, spend

This walkthrough is the "works end to end" artifact for the Litecoin fork. It uses the
ported `bdk_wallet` against live Litecoin testnet infrastructure.

## Prerequisites

- This BDK workspace (`IndigoNakamoto/bdk`, branch `litecoin`) with `examples/ltc-scan`
- Nested or sibling `IndigoNakamoto/bdk_wallet` on branch `litecoin`
- Network access to `https://litecoinspace.org/testnet/api`
- A Litecoin testnet faucet (for example [litecoinspace faucet](https://litecoinspace.org/testnet/faucet) if available, or community faucets)

## 1. Watch-only sync (Phase 1 crates only)

From the BDK workspace:

```bash
cargo run -p ltc-scan -- \
  "wpkh(tpub.../0/*)" \
  --network testnet \
  --backend esplora
```

Defaults: Esplora `https://litecoinspace.org/testnet/api`, Electrum
`ssl://electrum-ltc.bysh.me:51002`. Live regression tests:

```bash
just test-live
```

## 2. Create a BIP84 testnet wallet and receive

From `bdk_wallet` (path-deps against this workspace when nested under `bdk/`):

```bash
cargo run --example esplora_blocking --features "std,rusqlite"
```

The example:

- Opens `bdk-example-esplora-blocking.sqlite`
- Uses a BIP84 `wpkh(tprv…/84'/1'/0'/{0,1}/*)` descriptor on `Network::Testnet4`
- Syncs against `https://litecoinspace.org/testnet/api`
- Prints a `tltc1…` receive address

Example output from a fresh run:

```
Next unused address: (0) tltc1q5yxey46gne59mksrqe3rjrwpw7zjltcn9hkhzw
```

Fund that address from a faucet. Amounts print as "BTC" because the `litecoin` crate
inherited rust-bitcoin's `Amount` display; the unit is litoshis (1e-8 LTC).

Re-run the example until the balance is non-zero. The example then builds a send-to-self
transaction at an **explicit fee rate** (litecoinspace has no `/fee-estimates`; fee hints
come from `/api/v1/fees/recommended` when you need them elsewhere), signs, and broadcasts
via Esplora `POST /tx`.

## 3. Confirm the broadcast

After broadcast the example prints a litecoinspace tx URL. You can also re-sync and check:

```bash
cargo run --example esplora_blocking --features "std,rusqlite"
```

Expect the outgoing transaction to appear in the wallet's canonical view and, once mined,
to be anchored at a testnet height.

## 4. Electrum path (optional)

```bash
cargo run --example electrum --features "std,rusqlite"
```

Uses `ssl://electrum-ltc.bysh.me:51002` with the same descriptors. Public Electrum-LTC
servers present self-signed certificates; the client fork allows that when certificate
validation is left off (the default for these examples).

## 5. Local regtest (optional)

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
