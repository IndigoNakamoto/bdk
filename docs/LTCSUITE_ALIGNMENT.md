# ltcsuite alignment (reference inventory)

Status: **Inventory complete** (2026-07-27). Per Losh: **copy ltcsuite PSBTv2 MWEB**; light sync follows **`mwebsync`**.  
Rust ports semantics into `litecoin` / `bdk_mweb` / `bdk_wallet` — **no Go FFI**.

Canonical sources:

- PSBT: [`ltcsuite/ltcd` `ltcutil/psbt`](https://github.com/ltcsuite/ltcd/tree/master/ltcutil/psbt) + [`ltcwallet/wallet/psbt.go`](https://github.com/ltcsuite/ltcwallet/blob/master/wallet/psbt.go)
- Sync: [`ltcsuite/mwebsync`](https://github.com/ltcsuite/mwebsync) ([ARCHITECTURE](https://github.com/ltcsuite/mwebsync/blob/main/docs/ARCHITECTURE.md))

---

## 1. PSBTv2 MWEB field map (copy exactly)

First-class key types in the `0x90+` range (not BIP174 proprietary `0xFC` stuffing of a raw `mw_tx`).

### Global

| Type | Code | Purpose |
| --- | --- | --- |
| `MwebTxOffsetType` | `0x90` | Kernel offset (blinding) |
| `MwebTxStealthOffsetType` | `0x91` | Stealth offset |
| `MwebKernelCountType` | `0x92` | Number of kernels |

PSBTv2 also uses `TxVersionType`, `InputCountType`, `OutputCountType`, etc. (standard v2 globals).

### Input (`PInput`)

| Field | Type code | Notes |
| --- | --- | --- |
| `MwebOutputId` | `0x90` | Spent output id (pure MWEB input marker) |
| `MwebCommit` | `0x91` | Spent output commitment |
| `MwebOutputPubkey` | `0x92` | Receiver / output pubkey |
| `MwebInputPubkey` | `0x93` | Input pubkey (stealth feature) |
| `MwebFeatures` | `0x94` | `MwebInputFeatureBit` |
| `MwebInputSig` | `0x95` | Input signature (finalize) |
| `MwebAddressIndex` | `0x96` | LE u32 |
| `MwebAmount` | `0x97` | LE u64 litoshis |
| `MwebSharedSecret` | `0x98` | Optional shared secret |
| `MwebKeyExchangePubkey` | `0x99` | Ke |
| `MwebMasterScanKey` | `0x9A` | BIP32 derivation origin |
| `MwebMasterSpendKey` | `0x9B` | BIP32 derivation origin |
| `MwebExtraData` | `0x9C` | Extra data feature |

ltcwallet populates origins via `populateMwebKeyOrigins` / `validateMwebKeyOrigins`; signs with `BasicMwebInputSigner` + `SignMwebComponents`.

### Output (`POutput`)

| Type | Code |
| --- | --- |
| `MwebStealthAddressOutputType` | `0x90` |
| `MwebCommitOutputType` | `0x91` |
| `MwebFeaturesOutputType` | `0x92` |
| `MwebSenderPubKeyOutputType` | `0x93` |
| `MwebOutputPubKeyOutputType` | `0x94` |
| `MwebStandardFieldsOutputType` | `0x95` (Ke \|\| view_tag \|\| enc_value \|\| enc_nonce) |
| `MwebRangeProofOutputType` | `0x96` |
| `MwebSignatureOutputType` | `0x97` |
| `MwebExtraDataOutputType` | `0x98` |

### Kernel (`PKernel`)

| Type | Code |
| --- | --- |
| `MwebKernelExcessCommitType` | `0` |
| `MwebKernelStealthCommitType` | `1` |
| `MwebKernelFeeType` | `2` |
| `MwebKernelPeginAmountType` | `3` |
| `MwebKernelPegoutType` | `4` |
| `MwebKernelLockHeightType` | `5` |
| `MwebKernelFeaturesType` | `6` |
| `MwebKernelExtraDataType` | `7` |
| `MwebKernelSignatureType` | `8` |

### BDK today vs ltcsuite

| | BDK now | ltcsuite reference |
| --- | --- | --- |
| Container | Transparent PSBT + **`attach_mweb_tx` after extract** | **PSBTv2 with MWEB input/output/kernel maps** |
| Sign path | `MwebTxBuilder` outside PSBT | `SignMwebComponents` inside PSBT |
| Interop | Nexus saw raw broadcast only | Cross-wallet PSBT round-trip |

**Port target:** extend Rust `litecoin` PSBT (fork) with these types, then teach `bdk_wallet` fund/sign/finalize to match ltcwallet. Keep `attach_mweb_tx` as interim for the CLI until parity.

---

## 2. mwebsync vs `bdk_mweb` LIP path

### mwebsync architecture (reference)

```text
WaitHeaders → Rollback → StratifiedHeaderSample → VerifyTip(header+leafset)
  → DifferentialUTXOSync → UpdateDB/Notify → IdleUntilNewTip → loop
```

Interfaces:

- `BlockHeaderProvider` — tip + header by height  
- `PeerQuerier` / peer provider — multi-peer query + ban  
- `SyncStateNotifier` — wait for transparent headers  
- `CoinDatabase` — leafset, coins, rollback, leaves-at-height map  

Behaviors BDK lacks or only partially has:

| Capability | mwebsync | `bdk_mweb` today |
| --- | --- | --- |
| Continuous tip loop | Yes | `MwebSyncer::run_loop` (+ `run_once`) |
| Stratified height→leaf index / UTXO dating | Yes | Fine window (last 500) + tip fallback (`mweb_sync`) |
| Differential leafset sync | Yes | `diff_leafsets` → fetch added only |
| Multi-peer + ban | Yes | Single `TcpMwebPeer` (API allows multi later) |
| Header wait vs Electrum tip | Explicit notifier | `SyncNotifier` / `ReadyNotifier` after Esplora |
| Reorg | Rollback ≤10 rewind / >10 purge | `disconnect_from` heights + shorter-tip in syncer |
| Verify | header + leafset + UTXO MMR | `HeaderAndPmmr` leafset + batch (aligned in spirit) |

What already matches: LIP-0006 message order, leafset blake3, PMMR `output_root` checks (`pmmr.rs`), tip seam `(hash, height)`.

**MVP landed:** [`crates/mweb/src/mweb_sync.rs`](../crates/mweb/src/mweb_sync.rs) — differential sync + UTXO dating. `mainnet_mweb sync` persists `mweb_sync.json` (`SyncState`) beside `mweb.db`.

---

## 3. Ordered backlog

1. ~~**PSBTv2 MWEB types**~~ — **MVP in `bdk_mweb::psbt`** (ltcd `0x90+` / kernel map codes +
   `MwebPsbt` extract helpers). Upstream absorption into published `litecoin` crate still open.
2. ~~**`bdk_wallet` extract path**~~ — CLI `pegin` / `send` / `pegout` use
   `extract_pegin_with_mweb_psbt` / `extract_finished_mweb_tx` (attach helper retained).
3. Deprecate library reliance on `attach_mweb_tx` after native PSBTv2 in `litecoin` crate.
4. ~~**mwebsync-shaped syncer**~~ — MVP + harden: tip-only dating, coarse heights, reorg leafset
   invalidate, `connect_first_peer` failover. Remaining: ban manager, mempool watch.
5. Confirmation UX — heights set by syncer; buckets via `CombinedBalance`.
6. Broadcast policy — Esplora then RPC; see [`MWEB_PEER_OPS.md`](MWEB_PEER_OPS.md).

---

## 4. Non-goals

- Vendoring Go / FFI to ltcd  
- Replacing zkp FFI with Go `mw`  
- Nexus/GPL embedding  
- Inventing a different PSBT key map
