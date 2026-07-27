# bdk_mweb

MWEB primitives for the Litecoin BDK fork:

- LIP-0004 / Litecoin Core stealth addresses
- Core-compatible output rewind (`RewindOutput`) and `MwebCoinDatabase` (with `block_height`)
- `MwebTxBuilder` for MWEB→MWEB spends and peg-outs
- `build_pegin` / `FinishedMwebPegin` for BDK-authored peg-in bodies
- MW `secp256k1-zkp` FFI: 675-byte bulletproofs + schnorr
- Feature `persist`: parallel `ChangeSet` for file_store
- Feature `rusqlite`: SQLite-beside-wallet tables
- Feature `encrypt` / `encrypt-changeset`: ChaCha20-Poly1305 seal helpers
- Feature `lip0006`: LIP-0006 codecs, `sync_mweb_utxos`, scripted + TCP peers (trusted-peer MVP)

Wallet integration (feature `mweb` on `bdk_wallet`): `CombinedBalance`, `MwebStore`,
`prepare_mweb_pegin`, `build_mweb_send`, `build_mweb_pegout`.

## Parallel persistence

```rust
use bdk_file_store::Store;
use bdk_mweb::{ChangeSet, MwebCoinDatabase};

const MAGIC: &[u8] = b"bdk_mweb_v1";

let staged = db.take_staged();
store.append(&staged)?;

let (store, cs) = Store::<ChangeSet>::load(MAGIC, path)?;
let db = MwebCoinDatabase::from_changeset(cs.unwrap_or_default());
```

Or SQLite (`ChangeSet::init_sqlite_tables` / `persist_to_sqlite` / `from_sqlite`).
`blind`, `shared_secret`, and `spend_key` are spend-equivalent — use `seal` /
`seal_changeset` with an app-owned key. **Not** folded into `Wallet::ChangeSet`.

```bash
export LITECOIND_EXE=/path/to/litecoind
cargo test -p bdk_mweb --all-features
cargo test -p bdk_wallet --test mweb_facade
```
