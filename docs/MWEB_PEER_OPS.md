# MWEB LIP-0006 peer operations

Light wallets do **not** require every user to run litecoind. They need **at least one**
reachable peer that serves LIP-0006 (`mwebheader`, `mwebleafset`, `getmwebutxos`).

## Node requirements

- Litecoin Core **with MWEB** (mainnet), fully synced (`initialblockdownload=false`)
- **Non-pruned** (archive) so historical `getmwebutxos` can be served during first sync
- P2P listening (default mainnet `9333`)
- Prefer advertising MWEB / light-client service bits so peers discover capability

## Local developer peer

```bash
# After IBD completes:
litecoin-cli getblockchaininfo | jq '{blocks,headers,initialblockdownload}'
nc -vz 127.0.0.1 9333

export LITECOIN_P2P=127.0.0.1:9333
# Optional failover list:
# export LITECOIN_P2P=127.0.0.1:9333,other.host:9333

cd bdk_wallet
cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- sync
```

First sync uses **tip-only dating** by default (fast). For full fine-window dating:

```bash
MWEB_FINE_SYNC=1 cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- sync
```

## Product / vendor fleet

- Run one or more non-pruned archive nodes behind DNS or a static allow-list
- Ship `LITECOIN_P2P` (comma-separated) or future seed list in the app
- Clients use `connect_first_peer` failover (no ban manager in MVP)
- Broadcast: try Esplora, fall back to `LITECOIN_RPC_URL` for MWEB-only txs when explorers reject fees

## Trust model

- Esplora/Electrum supplies the transparent tip `(hash, height)`
- LIP peer supplies MWEB header + leafset + UTXOs; BDK verifies leafset / PMMR batch roots (`HeaderAndPmmr`)
- A malicious peer can still **omit** owned UTXOs (omission); multi-peer compare is future work
- Tor for both HTTP and P2P is recommended for IP unlinkability (app concern)

## What Esplora cannot do

Esplora has **no** LIP-0006 UTXO API. Transparent sync alone cannot discover or date MWEB-only receives/change.
