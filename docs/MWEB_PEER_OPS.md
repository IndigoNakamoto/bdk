# MWEB LIP-0006 peer operations

Light wallets do **not** require every user to run litecoind. They need **at least one**
reachable peer that serves LIP-0006 (`mwebheader`, `mwebleafset`, `getmwebutxos`).

## Node requirements

- Litecoin Core **with MWEB** (mainnet), fully synced (`initialblockdownload=false`)
- **Non-pruned** (archive) so historical `getmwebutxos` can be served during first sync
- P2P listening (default mainnet `9333`)
- Prefer advertising MWEB / light-client service bits so peers discover capability
- **0.21.5.6+: whitelist your clients** — see below

## Serving rate limit (Litecoin Core 0.21.5.6+)

0.21.5.6 meters `getmwebleafset` and `getmwebutxos` through a token bucket
(`AllowMWEBServe`): **32 request burst, refilling at 0.5/s**. Three properties
matter for operations:

- It is **node-wide**, not per-peer, and deliberately survives reconnects. Every
  non-whitelisted light client pointed at the node shares one allowance.
- Over-budget requests are **silently dropped** — no reject message, no
  disconnect. From the client they look exactly like a dead peer.
- Peers with `PF_NOBAN` are **exempt**.

On a node you operate, whitelist the clients:

```bash
litecoind -whitelist=noban@127.0.0.1        # local wallet
litecoind -whitelist=noban@10.0.0.0/8       # your own fleet
```

Without this a first sync is throttled to roughly one batch every two seconds no
matter how well-behaved the client is, and it competes with every other wallet
using the same node.

`bdk_mweb` handles the limit rather than assuming it away: each window of
requests is flushed with a `ping`, and since litecoind processes one peer's
messages in order, anything missing when the `pong` arrives was dropped and is
re-issued. Throttling therefore costs latency, never correctness, and a
rate-limiting peer is **not** banned (`BanReason::Throttled`) — see
[`lip0006_tcp.rs`](../crates/mweb/src/lip0006_tcp.rs). A peer that serves
*nothing* across several rounds still fails the pass, with a message pointing at
`-whitelist`.

Batches are requested at Core's maximum `num_requested` of **4096**
(`MAX_REQUESTED_MWEB_UTXOS`), because the bucket charges per request rather than
per UTXO: a full mainnet sync is ~86 requests at that width instead of ~700 at
500.

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

First sync uses **tip-only dating** by default (fast). After the first leafset is stored, the
default fine window is **4000** (mwebsync). Overrides:

```bash
# Force fine window 4000 even on first sync
MWEB_FINE_SYNC=1 cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- sync
# Tip-loop: idle until Esplora tip advances, then sync again (ban/failover on peer errors)
MWEB_TIP_POLL_SECS=30 cargo run --example mainnet_mweb --features "mweb,file_store,rusqlite" -- sync --follow
```

## Product / vendor fleet

- Run one or more non-pruned archive nodes behind DNS or a static allow-list
- Ship `LITECOIN_P2P` (comma-separated) or future seed list in the app
- Clients use [`PeerPool`](../crates/mweb/src/mweb_sync.rs): round-robin + temporary ban on
  **connect fail**, **leafset/PMMR verify fail**, and **read timeout** via
  `with_failover` / `MwebSyncer::run_once_with_pool` (`is_banworthy_peer_error`).
  `connect_first_peer` remains as a thin wrapper.
- Fine dating default window is **4000** (mwebsync); first CLI sync stays tip-only unless
  `MWEB_FINE_SYNC=1`.
- Broadcast: for MWEB-only txs set `LITECOIN_RPC_URL` (cookie auth OK) **first**. Esplora often
  accepts an empty transparent shell (`txid` ignores `mw_tx`). Prefer **wtxid** + local
  `sendrawtransaction`.

## Trust model

- Esplora/Electrum supplies the transparent tip `(hash, height)`
- LIP peer supplies MWEB header + leafset + UTXOs; BDK verifies leafset / PMMR batch roots (`HeaderAndPmmr`)
- A malicious peer can still **omit** owned UTXOs (omission); multi-peer compare is future work
- Tor for both HTTP and P2P is recommended for IP unlinkability (app concern)

## What Esplora cannot do

Esplora has **no** LIP-0006 UTXO API. Transparent sync alone cannot discover or date MWEB-only receives/change.
