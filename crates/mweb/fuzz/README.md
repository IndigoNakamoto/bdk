# Fuzzing `bdk_mweb`

Every byte a LIP-0006 peer sends is attacker-controlled, and none of it is
authenticated before it is parsed. These targets cover that boundary: the wire
decoders, the P2P framing, the PMMR index arithmetic, the verification
functions, and the sync loop itself.

The harness mirrors [`rust-litecoin/fuzz`](https://github.com/LitecoinDevKit/rust-litecoin)
— same honggfuzz driver, same `fuzz.sh` / `fuzz-util.sh` layout, same
`duplicate_crash` reproduction flow — so a crash is triaged the same way in
either repo.

## Running

```bash
cd crates/mweb/fuzz
./fuzz.sh                      # every target, 60s each
./fuzz.sh verify_utxo_batch    # one target
RUN_TIME=3600 ./fuzz.sh        # an hour each
```

Or from the repo root: `just fuzz` / `just fuzz rewind_output`.

CI runs the same script on a schedule (`.github/workflows/fuzz.yml`), plus a
short smoke run whenever the harness itself changes.

To run a single target indefinitely:

```bash
cargo hfuzz run verify_utxo_batch
```

honggfuzz needs `libunwind`, plus `libopcodes` and `libbfd` from binutils
**2.38** (2.39 broke the API). On Nix:

```bash
nix-shell -p libopcodes_2_38 -p libunwind
```

This crate is excluded from the workspace so it can set its own release
profile. It builds with `overflow-checks = true` and `debug-assertions = true`:
the arithmetic in `pmmr.rs` is exactly what we want the fuzzer to trip on, and a
silent wrap would otherwise look like a clean run.

## Targets

| Target | What it covers |
| --- | --- |
| `decode_mweb_leafset` | `mwebleafset` decode; the length-prefix allocation cap and the 64x index expansion |
| `decode_mweb_utxos` | `mwebutxos` decode; two length prefixes, nested `Output`, `output_id` on unverified entries |
| `decode_mweb_header` | `mwebheader` decode; reaches `MerkleBlock` and `Transaction` consensus decoders, plus `extract_matches` |
| `decode_get_mweb_utxos` | `getmwebutxos` decode round-trip |
| `p2p_frame` | Header framing: magic validation and the payload cap that runs before the buffer is allocated |
| `pmmr_math` | `leaf_position` / `num_nodes_for_leaves` overflow, `MemMmr` construction |
| `verify_leafset` | Accepts the true root, rejects any mutation inside the committed prefix |
| `verify_utxo_batch` | Accepts a self-consistent batch, rejects substituted / reordered / truncated ones |
| `rewind_output` | `rewind_output` on hostile outputs vs a fixed keyset; must never panic and never yield a coin |
| `sync_driver` | Liveness: a peer replaying leaves below `start_index` must not loop forever |
| `open_sealed` | `encrypt::open` on hostile bytes; v2 envelope context binding and rollback counter |

### Why several targets assert on the *accept* path

Feeding noise to `verify_leafset` tests the reject path and nothing else —
random bytes never hash to a random root. Those targets instead compute the
correct root for the fuzzer's own data, assert it verifies, then mutate and
assert it does not. The fuzzer's job becomes finding a mutation the check
tolerates, which is the property that actually protects the wallet.

`sync_driver` works the same way for liveness. A hang is a weak signal —
honggfuzz reports it only as a timeout, after burning the budget — so the
scripted peer counts its own calls and panics past a bound no honest sync
reaches. An infinite loop becomes an immediate, minimizable crash.

## Seed corpus

`hfuzz_input/<target>/input/` holds checked-in seeds: real ltcd-generated MWEB
outputs (from `tests/fixtures/`, produced by `scripts/ltcd_mweb_fixtures` on
regtest) and honest encodings from the wallet's own encoders. Structured
decoders starve without them — random bytes rarely survive the first length
prefix. `fuzz.sh` passes the directory to honggfuzz automatically when it
exists.

Regenerate deterministically with `just fuzz-corpus` (or
`cargo run --bin gen_corpus` from this directory); CI fails if the checked-in
corpus does not match what the generator produces.

## Reproducing a crash

honggfuzz prints the offending input as hex on the last line of its report.
Paste it into the target's `duplicate_crash` test and run `cargo test`:

```rust
#[test]
fn duplicate_crash() {
    let mut a = Vec::new();
    extend_vec_from_hex("fff400610004", &mut a);
    super::do_test(&a);
}
```

## Adding a target

Copy an existing file in `fuzz_targets/`, edit `do_test`, and add a matching
`[[bin]]` stanza to `Cargo.toml`. Keep the `duplicate_crash` test so the
reproduction flow stays uniform.
