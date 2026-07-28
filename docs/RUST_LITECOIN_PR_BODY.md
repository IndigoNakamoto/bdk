# PR body for rust-litecoin (MWEB PSBT typed maps)

**Opened:** https://github.com/rust-litecoin/rust-litecoin/pull/9  
Target: `rust-litecoin/rust-litecoin` base `0.32`  
Head: `IndigoNakamoto:mweb-psbt-typed-maps`  
Version: **0.32.8-rc.2**

## Summary

- Add first-class ltcd-compatible MWEB PSBT maps (`0x90+` input/output/global, kernel field list).
- `Psbt::extract_tx_with_mweb` assembles `Transaction.mw_tx` from maps only.
- Type BIP32 origins `0x9A`/`0x9B` as `(PublicKey, KeySource)` matching ltcd wire
  (pubkey key data + BIP174 KeySource value).
- Keep rejecting `unsigned_tx.mw_tx` / `is_hog_ex` on PSBT construct.
- README + CHANGELOG for rc.2.

## Test plan

- [x] `cargo test -p litecoin psbt` (including MWEB round-trip / extract / KeySource origins)
- [x] BDK fork consumes via `[patch.crates-io] litecoin = { path = "..." }` and passes `bdk_mweb` lib + wallet `prepare_mweb_pegin`

## Publish (after merge / as crates.io owner)

```bash
cd /Users/indigo/Dev/rust-litecoin
cargo login   # or export CARGO_REGISTRY_TOKEN
cargo publish -p litecoin --dry-run
cargo publish -p litecoin
```

Then remove BDK workspace `[patch.crates-io]` once crates.io serves `0.32.8-rc.2`.
