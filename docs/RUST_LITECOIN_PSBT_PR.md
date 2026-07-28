# Upstream PR: native PSBTv2 MWEB maps in `litecoin`

Status: **Consumed in BDK** (2026-07-27) against local/path `litecoin` **0.32.8-rc.2**.
Staging types were removed from `bdk_mweb::psbt`; wallet helpers thin-wrap
[`bitcoin::psbt::mweb`](https://github.com/rust-litecoin/rust-litecoin) (`MwebInput`,
`MwebOutput`, `MwebKernel`) and call [`Psbt::extract_tx_with_mweb`].

Until crates.io publishes `0.32.8-rc.2`, this workspace patches:

```toml
[patch.crates-io]
litecoin = { path = "../rust-litecoin/litecoin" }
```

## Why

Published `litecoin` 0.32.8-rc.1 PSBT rejected MWEB bodies (BIP174 has no slots). ltcd defines
first-class `0x90+` keys in `ltcutil/psbt/types.go`. BDK must not invent a parallel proprietary
map.

## Inventory lock (ltcd master, 2026-07-27)

Codes match [`docs/LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md) §1 and
`bitcoin::psbt::mweb::types` 1:1. Extractor emits stealth address on outputs as
`scan (33) || spend (33)`.

## Upstream layout (rust-litecoin)

```text
src/psbt/mweb/
  mod.rs          // re-exports
  types.rs        // key type constants
  input.rs        // MwebInput
  output.rs       // MwebOutput (+ stealth address)
  kernel.rs       // MwebKernel
  extract.rs      // assemble_mw_tx
```

`Psbt` carries `mweb_tx_offset`, `mweb_stealth_offset`, `mweb_kernels`, `mweb_inputs`,
`mweb_outputs`.

## BDK consume path (done)

1. Bump `bitcoin = { package = "litecoin", version = "0.32.8-rc.2" }` (+ patch until publish).
2. `bdk_mweb::psbt` re-exports native types; keeps `scrub_sensitive_fields`,
   `sign_mweb_components`, `populate_psbt_from_mw`, peg-in helpers.
3. Happy path: `fund_mweb_spend` → `sign_funded_mweb` → scrub → `Psbt::extract_tx_with_mweb`.
4. Delete parallel key-constant / map-owner structs (completed).

## Acceptance (upstream crate)

1. Serialize/deserialize round-trip of globals `0x90`–`0x92`, input/output `0x90+`, kernel pairs.
2. Port or mirror ltcd MWEB PSBT vectors from `ltcutil/psbt/*_test.go`.
3. `Psbt` may carry empty transparent vin with MWEB input maps (pure MWEB).
4. Finalize/extract builds `Transaction.mw_tx` from maps only (no sidecar).
