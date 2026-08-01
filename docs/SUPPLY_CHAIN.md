# Supply chain

What this fork depends on that upstream BDK does not, why, and what would have
to happen for each dependency to hurt us. Written for the moment someone asks
"where did this crypto come from?" — the answer should already be here.

Companion to [SECURITY_PLAN.md](SECURITY_PLAN.md) (finding F-20).

## Enforcement

| Mechanism | Where | Runs |
| --- | --- | --- |
| `cargo audit` | `.github/workflows/audit.yml` | Nightly, and on any `Cargo.toml` / `Cargo.lock` / `audit.toml` change |
| `cargo deny check advisories bans licenses sources` | `.github/workflows/supply_chain.yml`, config in `deny.toml` | Weekly (Mon 06:00 UTC), and on dependency changes |
| Dependabot, `cargo` + `github-actions` ecosystems | `.github/dependabot.yml` | Weekly (monthly for the fuzz workspace) |
| SHA-pinned actions | every workflow | Enforced by review; `zizmor` flags regressions |
| litecoind-backed regtest suite | `.github/workflows/regtest_mweb.yml` | Weekly and on `crates/mweb` changes |

`cargo audit` and `cargo deny` overlap on advisories deliberately: `audit` reads
`.cargo/audit.toml`, `deny` reads `deny.toml`, and the ignore lists are kept in
sync by hand. If they drift, one of the two starts failing, which is the
intended failure mode.

`unknown-git = "deny"` in `deny.toml` is the load-bearing setting. Only one git
dependency is allowed; anything else arriving through a transitive bump fails
CI rather than shipping.

## `grin_secp256k1zkp` — the consensus crypto

`crates/mweb` performs every Pedersen commitment, bulletproof, and Schnorr
signature through this crate. A defect here is a fund-loss defect: a
bulletproof that verifies when it should not means accepting an output whose
value is not what the wallet believes.

| | |
| --- | --- |
| Crate | `grin_secp256k1zkp` 0.7.15 (crates.io) |
| Checksum | `bf7bb95f155b1eede2648a1b9afbba82bc3d9f2af0518b478767559a572bd973` (`Cargo.lock`) |
| Repository | <https://github.com/mimblewimble/rust-secp256k1-zkp/> |
| License | CC0-1.0 |
| Lineage | Grin's fork of `apoelstra/rust-secp256k1`, tracking upstream on a `vendor` branch with Grin's changes merged on top (see the crate's `FORK` file) |
| Vendored C | `depend/secp256k1-zkp`, with modules `aggsig`, `bulletproofs`, `commitment`, `ecdh`, `generator`, `rangeproof`, `recovery`, `schnorrsig`, `surjection`, `whitelist` |
| Features enabled | `bullet-proof-sizing` only, `default-features = false` |
| Optional | Yes — gated behind the `zkp` feature; `crates/mweb` builds and scans without it |

### Why this crate and not `secp256k1-zkp`

Litecoin's MWEB uses Grin's MimbleWimble bulletproof construction, not Elements'
confidential-transaction rangeproofs. The two are not interchangeable: MWEB
proofs are a fixed 675 bytes with a specific extra-commit layout, and the
Elements-derived `secp256k1-zkp` crate cannot verify them. This is confirmed
empirically rather than assumed — `crates/mweb/tests/core_bulletproof_gate.rs`
takes a bulletproof authored by litecoind and verifies it through this FFI.

### Relationship to what Litecoin Core ships

Not byte-identical, and we do not claim it is. Litecoin Core vendors its own
copy of `secp256k1-zkp` under `src/secp256k1`. What is verified is *behavioural*
equivalence on the paths we use, by the regtest suite: Core authors a
transaction, `bdk_mweb` verifies its proof; `bdk_mweb` authors a transaction,
Core accepts it into its mempool. That is the property that actually matters,
and it is checked on every `crates/mweb` change by the `regtest-mweb` job.

The FFI surface itself is pinned separately. `crates/mweb/src/crypto.rs`
declares `extern "C"` prototypes by hand, so a change to the C ABI would be
silent at compile time; the `abi_vectors` test module holds known-answer vectors
for every FFI entry point, and a dependency bump that changes any result fails
those tests.

### Vendoring decision

**Not vendored, revisit if the crate stops being maintained.**

`vendor/bitcoincore-rpc` shows the pattern exists here, and vendoring would
pin the C source against a yank or re-publish and make the diff against
Litecoin Core directly auditable. Against that: vendoring means owning security
updates to ~40k lines of C that we are not equipped to review, and the crates.io
checksum in `Cargo.lock` already prevents a silent substitution — crates.io
does not permit overwriting a published version.

The residual risk is a *yank*, which breaks the build rather than corrupting
it, and a compromised future release, which the `abi_vectors` known-answer
tests and the regtest suite would both catch before it reached users.

Revisit if: the crate is yanked, `mimblewimble/rust-secp256k1-zkp` goes
unmaintained for a release cycle in which we need a fix, or an advisory lands
against it.

## `litecoin` (rust-litecoin fork)

| | |
| --- | --- |
| Source | `https://github.com/IndigoNakamoto/rust-litecoin.git`, branch `mweb-psbt-typed-maps` |
| Locked rev | `0b3285337f3cc508a5549d245ce20d3b52418f3a` (`Cargo.lock`) |
| Applied via | `[patch.crates-io]` in the workspace `Cargo.toml` |
| Why | Native PSBTv2 MWEB typed maps, not yet published as `litecoin` 0.32.8-rc.2 |

The `[patch]` names a *branch*, so the branch moving changes what a fresh
`cargo update` resolves. The lockfile pins the rev, and CI runs `--locked`
where it matters, but the safer end state is patching by `rev`. Tracked in
[SECURITY_PLAN.md](SECURITY_PLAN.md).

`crates/mweb/fuzz` is its own workspace (it needs a release profile with
overflow checks), so it repeats the same `[patch]`. The two must stay in sync;
they are checked together by the `cargo deny (fuzz harness)` CI step.

## Ignored advisories

Kept in `.cargo/audit.toml` and `deny.toml`. Every entry needs a reason and an
exit condition, restated in both files, because an undocumented ignore becomes a
permanent blind spot.

| Advisory | What | Reaches `bdk_mweb`? | Clears when |
| --- | --- | --- | --- |
| `RUSTSEC-2026-0098` | rustls 0.21 | No | `rust-esplora-client` and `jsonrpc` move off rustls 0.21 |
| `RUSTSEC-2026-0099` | rustls 0.21 | No | as above |
| `RUSTSEC-2026-0104` | rustls-webpki 0.101 | No | as above |
| `RUSTSEC-2025-0141` | `bincode` unmaintained | Tests only | `bdk_file_store` changes its encoding |

None are on a `bdk_mweb` code path. The crate has no TLS dependency at all: its
only network code is the plain-TCP LIP-0006 peer in `lip0006_tcp.rs`, and
`bincode` arrives through `bdk_file_store`, which `bdk_mweb` uses only in the
`persist_filestore` test.

## Direct dependencies of `crates/mweb`

| Crate | Role | Notes |
| --- | --- | --- |
| `litecoin` | Consensus types and encoding | Forked; see above |
| `blake3` | MWEB hashing (`output_id`, kernel ids, header hash) | Upstream, widely reviewed |
| `grin_secp256k1zkp` | Bulletproofs, Schnorr, Pedersen | Optional (`zkp`); see above |
| `chacha20poly1305` | At-rest encryption | Optional (`encrypt`); RustCrypto |
| `zeroize` | Secret wiping | Best effort by construction — see `crates/mweb/src/secret.rs` |
| `rand` | Nonces, blinding factors | `thread_rng`, OS-seeded |
| `once_cell` | FFI context memoisation | Optional (`zkp`) |
| `serde`, `serde_json` | Changeset encoding | Optional |
| `rusqlite` | SQLite changeset backend | Optional |
| `bdk_core` | `Merge` for `ChangeSet` | Optional (`persist`) |

Dependabot groups routine minor/patch bumps into one PR but deliberately
excludes `grin_secp256k1zkp`, `litecoin`, `chacha20poly1305`, `blake3`, and
`zeroize`, so each of those arrives as its own PR and gets read.
