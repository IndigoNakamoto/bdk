# BDK Esplora

BDK Esplora extends [`esplora-client`] (with extension traits: [`EsploraExt`] and
[`EsploraAsyncExt`]) to update [`bdk_chain`] structures from an Esplora server.

The extension traits are primarily intended to satisfy [`SyncRequest`]s with [`sync`] and
[`FullScanRequest`]s with [`full_scan`].

## Litecoin servers

The public Litecoin Esplora instance is [litecoinspace.org](https://litecoinspace.org):

| Network | Base URL |
| --- | --- |
| mainnet | `https://litecoinspace.org/api` |
| testnet | `https://litecoinspace.org/testnet/api` |

Note that the testnet path is `/testnet`, not `/testnet4`, even though the `litecoin` crate spells
that network `Network::Testnet4`. Litecoin's "testnet4" is a data directory name dating to around
2017 and is unrelated to Bitcoin's BIP-94 Testnet4.

litecoinspace does not implement `/fee-estimates`, so
[`esplora_client::get_fee_estimates`](https://docs.rs/esplora-client/) fails against it. Syncing is
unaffected; fee estimation needs another source.

## Usage

For blocking-only:
```toml
bdk_esplora = { version = "0.19", features = ["blocking"] }
```

For async-only:
```toml
bdk_esplora = { version = "0.19", features = ["async"] }
```

For async-only (with https):

You can additionally specify to use either rustls or native-tls, e.g. `async-https-native`, and this applies to both async and blocking features.
```toml
bdk_esplora = { version = "0.19", features = ["async-https"] }
```

For async-only (with tokio):
```toml
bdk_esplora = { version = "0.19", features = ["async", "tokio"] }
```

To use the extension traits:
```rust
// for blocking
#[cfg(feature = "blocking")]
use bdk_esplora::EsploraExt;

// for async
#[cfg(feature = "async")]
use bdk_esplora::EsploraAsyncExt;
```

[`esplora-client`]: https://docs.rs/esplora-client/
[`bdk_chain`]: https://docs.rs/bdk-chain/
[`EsploraExt`]: crate::EsploraExt
[`EsploraAsyncExt`]: crate::EsploraAsyncExt
[`SyncRequest`]: bdk_core::spk_client::SyncRequest
[`FullScanRequest`]: bdk_core::spk_client::FullScanRequest
[`sync`]: crate::EsploraExt::sync
[`full_scan`]: crate::EsploraExt::full_scan
