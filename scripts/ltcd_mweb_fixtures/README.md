# ltcd MWEB fixture generator

One-off Go helper that dumps **deterministic** (where possible) ltcd wire/PSBT
payloads into [`crates/mweb/tests/fixtures/`](../../crates/mweb/tests/fixtures/).
Rust CI never runs this.

## Prerequisites

- Go 1.23+
- CGO enabled (`secp256k1` range proofs)
- Local [ltcsuite/ltcd](https://github.com/ltcsuite/ltcd) checkout (PSBT MWEB APIs
  are not always on the module proxy). Default path: `./vendor-ltcd`

```bash
git clone --depth 1 https://github.com/ltcsuite/ltcd.git vendor-ltcd
```

`go.mod` uses `replace` directives pointing at `./vendor-ltcd`.

## Regenerate

```bash
cd scripts/ltcd_mweb_fixtures
CGO_ENABLED=1 go run .
```

## Fixed seeds

| Purpose | Value |
| --- | --- |
| Keychain scan/spend | Core vectors from seed `2a64df08…` (`b3c91b72…` / `2fe1982b…`) |
| Multi-index senders | Go `TestOutputRoundTripMultipleIndices` (`01aaaa…`, `02abab…`, …) |
| Wrong-scan sender | `0123456789abcdef…` |
| PSBT unsigned construction | Fixed `11…`/`22…`/`33…`/`44…` secrets |

**Note:** `SignMwebComponents` still draws ephemeral/kernel keys via `crypto/rand`.
Re-running will change `psbt_sign_mweb_signed.base64` and
`psbt_sign_mweb_extracted.hex`. Prefer regenerating those only when intentionally
refreshing the committed Go-signed interop vectors. Output `*.hex` fixtures and
the unsigned PSBT are fully deterministic.

**Bulletproofs:** Go (`ltcsuite/secp256k1`) and Rust (`grin_secp256k1zkp`) proofs are
not byte-identical for the same (value, blind, message). Rust tests assert
commitment / pubkeys / `OutputMessage` preimage equality against Go dumps, then
rewind both sides.

**PSBT wire:** ltcd emits PSBTv2 map sections; rust-litecoin round-trips MWEB on
PSBTv0 global keys. Ingest Go bytes with `bdk_mweb::psbt_from_ltcd_v2`.
