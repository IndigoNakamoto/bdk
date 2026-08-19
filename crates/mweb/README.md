# bdk_mweb

MWEB primitives for the Litecoin BDK fork:

- LIP-0004 / Litecoin Core stealth addresses
- Core-compatible output rewind (`RewindOutput`) and `MwebCoinDatabase` (with `block_height`)
- In-PSBT fund/sign/scrub/extract:
  - send/peg-out: `fund_mweb_spend` / `sign_funded_mweb` → `Psbt::extract_tx_with_mweb`
  - peg-in: `fund_mweb_pegin` / `sign_funded_mweb_pegin` → merge maps → extract
    (`build_pegin` deprecated)
- BIP32 origins `0x9A`/`0x9B` via `populate_mweb_key_origins` /
  `validate_mweb_key_origins_against` (ltcwallet-shaped; hardware / multi-sig
  coordinators can route on fingerprint + path; scrub leaves origins on the PSBT)
- MW `secp256k1-zkp` FFI: 675-byte bulletproofs + schnorr
- Feature `persist`: parallel `ChangeSet` for file_store
- Feature `rusqlite`: SQLite-beside-wallet tables
- Feature `encrypt` / `encrypt-changeset`: ChaCha20-Poly1305 seal helpers
- Feature `lip0006`: LIP-0006 codecs, `sync_mweb_utxos`, `mweb_sync::MwebSyncer`
  (differential leafset + fine/tip-only dating, `PeerPool` ban/rotate)
- `psbt` module: thin helpers over `bitcoin::psbt::mweb` (`MwebInput` / `MwebOutput` /
  `MwebKernel`) until apps call the crate types directly
- `psbt_from_ltcd_v2`: ingest Go/ltcd PSBTv2 MWEB packets into rust-litecoin maps
- Golden fixtures: [`tests/fixtures/`](tests/fixtures/) (regenerate via
  [`scripts/ltcd_mweb_fixtures`](../../scripts/ltcd_mweb_fixtures)); HD is Core
  `m/0'/100'/{0,1}'` only — **no** ltcwallet legacy `m/1000'/2'/…`

Wallet integration (feature `mweb` on `bdk_wallet`): `CombinedBalance`, `MwebStore`,
`prepare_mweb_pegin`, `fund_mweb_send`, `fund_mweb_pegout` (+ deprecated `build_mweb_*`).

## Parallel persistence

```rust
use bdk_file_store::Store;
use bdk_mweb::{ChangeSet, MwebCoinDatabase};

const MAGIC: &[u8] = b"bdk_mweb_v2";

let staged = db.take_staged();
store.append(&staged)?;

let (store, cs) = Store::<ChangeSet>::load(MAGIC, path)?;
let db = MwebCoinDatabase::from_changeset(cs.unwrap_or_default());
```

Or SQLite (`ChangeSet::init_sqlite_tables` / `persist_to_sqlite` / `from_sqlite`).
`blind`, `shared_secret`, and `spend_key` are spend-equivalent — use `seal` /
`seal_changeset` with an app-owned key. **Not** folded into `Wallet::ChangeSet`.

Showing Core / ltcsuite the full transparent + MWEB packet:
[`docs/TEST_EVIDENCE.md`](../../docs/TEST_EVIDENCE.md).

```bash
export LITECOIND_EXE=/path/to/litecoind
cargo test -p bdk_mweb --all-features
cargo test -p bdk_mweb --test ltcd_psbt_fixtures
cargo test -p bdk_wallet --test mweb_facade
```
