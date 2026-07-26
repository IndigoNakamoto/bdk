# BDK Electrum

BDK Electrum extends [`electrum-client`] to update [`bdk_chain`] structures
from an Electrum server.

## Litecoin servers

Litecoin Electrum servers run [`electrs-ltc`], the same implementation that backs
litecoinspace.org. There is no published Docker image for it, though the repository ships a
Dockerfile.

Transactions come off the wire as raw consensus bytes, so HogEx transactions — which every block
has carried since MWEB activation — decode correctly here where the upstream `bitcoin` decoder
would reject them.

## Minimum Supported Rust Version (MSRV)
This crate has a MSRV of 1.75.0.

To build with MSRV you will need to pin dependencies as follows:
```shell
cargo update -p home --precise "0.5.9"
```

[`electrum-client`]: https://docs.rs/electrum-client/
[`electrs-ltc`]: https://github.com/rust-litecoin/electrs-ltc
[`bdk_chain`]: https://docs.rs/bdk-chain/
