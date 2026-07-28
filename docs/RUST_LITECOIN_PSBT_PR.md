# Upstream PR: native PSBTv2 MWEB maps in `litecoin`

Status: **Staging complete in `bdk_mweb::psbt`** (2026-07-27). Ready to land in
[`rust-litecoin/rust-litecoin`](https://github.com/rust-litecoin/rust-litecoin) when maintainers
accept the types. Until crates.io publishes a bump, BDK keeps the typed maps here and treats
`mw_tx` as **extract-only**.

## Why

Published `litecoin` 0.32.8-rc.1 PSBT rejects MWEB bodies (BIP174 has no slots). ltcd defines
first-class `0x90+` keys in `ltcutil/psbt/types.go`. BDK must not invent a parallel proprietary
map; this document is the absorption checklist for the `litecoin` crate.

## Inventory lock (ltcd master, 2026-07-27)

Codes match [`docs/LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md) §1 and
`bdk_mweb::psbt` constants 1:1. Extractor emits stealth address on outputs as
`scan (33) || spend (33)` (`ltcutil/psbt/psbt.go`).

## Suggested crate layout (rust-litecoin)

```text
src/psbt/mweb/
  mod.rs          // re-exports
  types.rs        // key type constants (copy from bdk_mweb::psbt)
  input.rs        // MwebInput fields on psbt::Input
  output.rs       // MwebOutput fields on psbt::Output (+ stealth address)
  kernel.rs       // PKernel list on Psbt
  extract.rs      // assemble mw_tx from maps (ltcd Extract)
```

## Acceptance for the upstream PR

1. Serialize/deserialize round-trip of globals `0x90`–`0x92`, input/output `0x90+`, kernel pairs.
2. Port or mirror ltcd MWEB PSBT vectors from `ltcutil/psbt/*_test.go`.
3. `Psbt` may carry empty transparent vin with MWEB input maps (pure MWEB).
4. Finalize/extract builds `Transaction.mw_tx` from maps only (no sidecar).

## Vector staging (this repo)

Until the upstream crate lands, BDK locks codes via:

- Unit: `bdk_mweb::psbt::tests::type_codes_match_ltcd`
- Unit: `fund_sign_extract_emits_stealth_and_scrubs` (stealth `scan||spend` + scrub)
- Unit: `input_map_roundtrip_unknown` / `finished_mweb_tx_maps_roundtrip_and_extract`

Copy those fixtures into `litecoin` crate tests when opening the PR. Prefer checked-in hex from
ltcd `*_test.go` over a Go FFI harness.

## BDK consume path

After publish: bump `bitcoin = { package = "litecoin", version = "…" }`, thin-wrap native types in
`bdk_mweb::psbt`, delete duplicate key constants. Until then this fork stages the native maps in
`bdk_mweb` (no crates.io bump available yet).
