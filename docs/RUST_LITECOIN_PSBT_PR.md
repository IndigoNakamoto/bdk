# Upstream PR: native PSBTv2 MWEB maps in `litecoin`

Status: **PR open** — https://github.com/rust-litecoin/rust-litecoin/pull/9  
Local branch: `mweb-psbt-typed-maps` (fork `IndigoNakamoto/rust-litecoin`)  
BDK consumes via path patch until crates.io has **0.32.8-rc.2**.

**Remaining for distribution:**
- `cargo login` / `CARGO_REGISTRY_TOKEN` as crates.io owner of `litecoin`
- `cargo publish -p litecoin`
- Remove `[patch.crates-io]` from workspace + `bdk_wallet/Cargo.toml`

Staging types were removed from `bdk_mweb::psbt`; wallet helpers thin-wrap
[`bitcoin::psbt::mweb`](https://github.com/rust-litecoin/rust-litecoin) (`MwebInput`,
`MwebOutput`, `MwebKernel`) and call [`Psbt::extract_tx_with_mweb`].

Until crates.io publishes `0.32.8-rc.2`, this workspace patches:

```toml
[patch.crates-io]
litecoin = { path = "../rust-litecoin/litecoin" }
```

(Also mirrored in `bdk_wallet/Cargo.toml`.)

## Why

Published `litecoin` 0.32.8-rc.1 PSBT rejected MWEB bodies (BIP174 has no slots). ltcd defines
first-class `0x90+` keys in `ltcutil/psbt/types.go`. BDK must not invent a parallel proprietary
map.

## Inventory lock (ltcd master, 2026-07-27)

Codes match [`docs/LTCSUITE_ALIGNMENT.md`](LTCSUITE_ALIGNMENT.md) §1 and
`bitcoin::psbt::mweb::types` 1:1. Extractor emits stealth address on outputs as
`scan (33) || spend (33)`. BIP32 origins `0x9A`/`0x9B` are `(PublicKey, KeySource)` with
pubkey as PSBT key data and BIP174 KeySource as value (ltcd `partial_input.go`).

## Upstream layout (rust-litecoin)

```text
src/psbt/mweb/
  mod.rs          // re-exports
  types.rs        // key type constants
  input.rs        // MwebInput (+ KeySource origins)
  output.rs       // MwebOutput (+ stealth address)
  kernel.rs       // MwebKernel
  extract.rs      // assemble_mw_tx
```

`Psbt` carries `mweb_tx_offset`, `mweb_stealth_offset`, `mweb_kernels`, `mweb_inputs`,
`mweb_outputs`.

## BDK consume path (done)

1. Bump `bitcoin = { package = "litecoin", version = "0.32.8-rc.2" }` (+ patch until publish).
2. `bdk_mweb::psbt` re-exports native types; keeps `scrub_sensitive_fields`,
   `sign_mweb_components`, `populate_psbt_from_mw`, peg-in helpers,
   `populate_mweb_key_origins` / `validate_mweb_key_origins`.
3. Happy path send: `fund_mweb_spend` → `sign_funded_mweb` → scrub → `Psbt::extract_tx_with_mweb`.
4. Happy path peg-in: `fund_mweb_pegin` → `sign_funded_mweb_pegin` → merge maps onto transparent
   PSBT → sign → `extract_tx_with_mweb` (`build_pegin` deprecated).
5. Delete parallel key-constant / map-owner structs (completed).

## Unblock publish

```bash
# After write access to rust-litecoin or a fork:
cd ../rust-litecoin
git push -u <remote> mweb-psbt-typed-maps
gh pr create --base 0.32 --title "psbt: first-class MWEB maps (0.32.8-rc.2)" \
  --body-file ../bdk/docs/RUST_LITECOIN_PR_BODY.md

cargo login   # or export CARGO_REGISTRY_TOKEN
cargo publish -p litecoin
```

Then remove `[patch.crates-io]` from workspace + `bdk_wallet/Cargo.toml`.

## Acceptance (upstream crate)

1. Serialize/deserialize round-trip of globals `0x90`–`0x92`, input/output `0x90+`, kernel pairs.
2. ltcd-mirrored inventory + KeySource origin wire tests + empty-vin extract (landed).
3. `Psbt` may carry empty transparent vin with MWEB input maps (pure MWEB).
4. Finalize/extract builds `Transaction.mw_tx` from maps only (no sidecar).
