# MWEB peg-in (Phase 1 spike)

Captured against Litecoin Core **v0.21.5.5** on regtest (`setup_mweb_chain` style: mine to height 431, then peg-in).

## What a peg-in looks like on the canonical chain

`Address::mweb(...).script_pubkey()` is **empty** by design in `litecoin` 0.32.8-rc.1. A real peg-in is **not** “pay the stealth script”; it is a transparent transaction that:

1. Spends ordinary transparent UTXOs.
2. Creates a **witness version 9** output (`OP_9` + 32-byte program) whose value is the peg-in amount.
3. Carries an **`mw_tx`** body whose peg-in kernel id **equals** that 32-byte program.

Core labels the script type `witness_mweb_pegin`. Consensus helper: `CScript::IsMWEBPegin` → program is the peg-in `kernel_id`.

### Regtest vector (abbreviated)

| Field | Value |
| --- | --- |
| Stealth destination | `tmweb1qq20j0mn5kek3l0cshuha4r4v7h6rs2rz4g8plrecf9wey45uqwetgq…` |
| Transparent SPK | `5920` \|\| `a1bb62e05ad15c83223cac521b7a9f39ca08c485823a24ba959771ec67eed41a` |
| `vkern[0].kernel_id` | `a1bb62e05ad15c83223cac521b7a9f39ca08c485823a24ba959771ec67eed41a` (same as program) |
| Activation | BIP9 `mweb` active from height **432** on default regtest params (`FIRST_MWEB_HEIGHT`) |

Full decoded sample: [`mweb_pegin_regtest.decoded.json`](mweb_pegin_regtest.decoded.json). Raw hex: [`mweb_pegin_regtest.hex`](mweb_pegin_regtest.hex).

Core’s `sendtoaddress(<mweb>, X)` typically pegs the **selected transparent input(s)** into MWEB (v9 value ≈ input − fee) and allocates `X` to the stealth address as an MWEB output, with MWEB change as additional `ismweb` vouts in `decoderawtransaction`.

## Maturity

Peg-ins are only safe to spend inside MWEB after **6 confirmations** (Litecoin Core / LIP guidance). Regtest acceptance mines ≥6 blocks after broadcast.

## Can pure BDK author a peg-in?

**No — not from the stealth address + amount alone.**

The 32-byte program is the **kernel id** of a peg-in kernel inside `mw_tx`. Building that kernel requires MWEB wallet crypto (commitments, range proofs / Bulletproofs, kernel excess signatures). `rust-litecoin` can **decode** `mw_tx` but does not author kernels.

### Decision (locked)

Implement a **Core / mwebd finalize** path:

1. BDK performs transparent **coin selection** (and can construct the v9 `scriptPubKey` once a `kernel_id` is known).
2. **litecoind** (or mwebd) authors the kernel + `mw_tx` and produces the broadcastable transaction (today: `sendtoaddress` / wallet send to an `mweb` address, optionally with coin control).
3. TxBuilder exposes:
   - `add_mweb_pegin(kernel_id, amount)` — transparent half when a finalizer already supplied a kernel id.
   - `mweb_tx(...)` + `finish_mweb_pegin()` — keep the body aside (BIP174 PSBTs reject MWEB/HogEx).
   - After `sign` / `extract_tx`, call `attach_mweb_tx` before broadcast.
   - Paying a stealth address with an empty SPK yields **`MwebPegInRequiresKernel`**.

Phase 2+ (`bdk_mweb` scan/spend, Bulletproofs, LIP-0006) stays out of scope. Prior art: [ltcmweb/mwebd](https://github.com/ltcmweb/mwebd).

## Regtest activation recipe

```text
generatetoaddress 431 <addr>   # pre-MWEB tip
sendtoaddress <tmweb1…> <amt>  # peg-in (mempool)
generatetoaddress 1 <addr>     # height 432, MWEB active + confirms peg-in
generatetoaddress 5 <addr>     # ≥6 confirmations total
```
