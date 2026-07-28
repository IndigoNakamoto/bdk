# MWEB peg-in

Captured against Litecoin Core **v0.21.5.5** on regtest (`setup_mweb_chain` style: mine to height 431, then peg-in).

## What a peg-in looks like on the canonical chain

`Address::mweb(...).script_pubkey()` is **empty** by design in `litecoin` 0.32.8-rc.1. A real peg-in is **not** “pay the stealth script”; it is a transparent transaction that:

1. Spends ordinary transparent UTXOs.
2. Creates a **witness version 9** output (`OP_9` + 32-byte program) whose value is the peg-in amount.
3. Carries an **`mw_tx`** body whose peg-in kernel id **equals** that 32-byte program.

Core labels the script type `witness_mweb_pegin`. Consensus helper: `CScript::IsMWEBPegin` → program is the peg-in `kernel_id` (= Core `Kernel::GetHash` / untagged BLAKE3 of the serialized kernel).

### Regtest vector (abbreviated)

| Field | Value |
| --- | --- |
| Stealth destination | `tmweb1qq20j0mn5kek3l0cshuha4r4v7h6rs2rz4g8plrecf9wey45uqwetgq…` |
| Transparent SPK | `5920` \|\| `a1bb62e05ad15c83223cac521b7a9f39ca08c485823a24ba959771ec67eed41a` |
| `vkern[0].kernel_id` | `a1bb62e05ad15c83223cac521b7a9f39ca08c485823a24ba959771ec67eed41a` (same as program) |
| Activation | BIP9 `mweb` active from height **432** on default regtest params (`FIRST_MWEB_HEIGHT`) |

Full decoded sample: [`mweb_pegin_regtest.decoded.json`](mweb_pegin_regtest.decoded.json). Raw hex: [`mweb_pegin_regtest.hex`](mweb_pegin_regtest.hex).

## Maturity

Peg-ins are only safe to spend inside MWEB after **6 confirmations** (Litecoin Core / LIP guidance). Regtest acceptance mines ≥6 blocks after broadcast.

## Authoring (Phase 5)

**BDK can author the peg-in body** via `bdk_mweb::build_pegin` (bulletproofs + kernel signing). Order:

1. `FinishedMwebPegin = build_pegin(...)` → `kernel_id`, `pegin_amount`, `mw_tx`
2. Transparent coin selection: `TxBuilder::apply_mweb_pegin(&pegin)` (feature `mweb`) or
   `add_mweb_pegin(kernel_id, amount)` + `mweb_tx(mw_tx)`
3. `finish_mweb_pegin` → sign PSBT → `extract_pegin_with_mweb_psbt` → broadcast

BIP174 still cannot carry `mw_tx`; the body stays aside until extract. Paying a stealth address with an empty SPK still yields **`MwebPegInRequiresKernel`**.

### Alternate: Core / mwebd finalize

litecoind `sendtoaddress(<mweb>, X)` (or mwebd) remains a valid finalizer when you do not want to author the body in-process. The Phase 1 TxBuilder APIs still accept an externally supplied `kernel_id` + `mw_tx`.

## Regtest activation recipe

```text
generatetoaddress 431 <addr>   # pre-MWEB tip
# BDK: build_pegin + transparent v9 + extract_pegin_with_mweb_psbt + sendrawtransaction
# (or: sendtoaddress <tmweb1…> <amt> for Core finalize)
generatetoaddress 1 <addr>     # height 432, MWEB active + confirms peg-in
generatetoaddress 5 <addr>     # ≥6 confirmations total
```
