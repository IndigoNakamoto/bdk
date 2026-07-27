# bdk_mweb

MWEB primitives for the Litecoin BDK fork:

- LIP-0004 / Litecoin Core stealth addresses
- Core-compatible output rewind (`RewindOutput`) and in-memory `MwebCoinDatabase`
- `MwebTxBuilder` for MWEB→MWEB spends and peg-outs (change + fee / peg-out kernel)
- `build_pegin` / `FinishedMwebPegin` for BDK-authored peg-in bodies (`kernel_id` = v9 program)
- MW `secp256k1-zkp` FFI: 675-byte bulletproofs + schnorr (not Elements CT rangeproofs)

See [`docs/MWEB_ARCHITECTURE.md`](../../docs/MWEB_ARCHITECTURE.md) and
[`docs/MWEB_PEGIN.md`](../../docs/MWEB_PEGIN.md). Unified balance API and LIP-0006 P2P sync
remain Phase 6+.

```bash
export LITECOIND_EXE=/path/to/litecoind
cargo test -p bdk_mweb
```
