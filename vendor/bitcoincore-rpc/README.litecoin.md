# Litecoin alias fork of `bitcoincore-rpc` 0.19.0

Vendored from [rust-bitcoin/rust-bitcoincore-rpc](https://github.com/rust-bitcoin/rust-bitcoincore-rpc)
at commit `839fcb6` (v0.19.0), with a one-line manifest change in `json/Cargo.toml`:

```toml
bitcoin = { package = "litecoin", version = "0.32.8-rc.1", features = ["serde", "std"] }
```

Used by `bdk_bitcoind_rpc` via a path dependency. When a public
`IndigoNakamoto/rust-bitcoincore-rpc` `litecoin` branch is published, the workspace
can switch to a git dependency and drop this vendor tree.
