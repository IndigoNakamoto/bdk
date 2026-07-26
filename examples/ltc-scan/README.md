# ltc-scan

A watch-only scanner that exercises the whole Litecoin sync path: descriptor parsing through
`miniscript`, script pubkey derivation through `bdk_chain`, a full scan against a real Litecoin
server, and canonicalisation into a balance and a UTXO set.

```bash
cargo run -p ltc-scan -- "wpkh(xpub.../0/*)"
cargo run -p ltc-scan -- "wpkh(tpub.../0/*)" --network testnet
cargo run -p ltc-scan -- "wpkh(xpub.../0/*)" --backend electrum
cargo run -p ltc-scan -- "wpkh(xpub.../0/*)" --change-descriptor "wpkh(xpub.../1/*)"
```

## Defaults

| Backend | mainnet | testnet |
| --- | --- | --- |
| Esplora | `https://litecoinspace.org/api` | `https://litecoinspace.org/testnet/api` |
| Electrum | `ssl://electrum-ltc.bysh.me:50002` | `ssl://electrum-ltc.bysh.me:51002` |

Override either with `--url`.

## Things worth knowing

Public Electrum-LTC servers present self-signed certificates, so certificate validation is off by
default. Pass `--validate-domain` to turn it on, which works only against a server with a CA-signed
certificate.

Fee rates come from litecoinspace's mempool.space-style `/v1/fees/recommended`, because Esplora's
own `/fee-estimates` is not implemented there. That endpoint is mainnet-only; on testnet the scan
still runs and the fee line reports that it is unavailable.

Amounts print in satoshis. The `litecoin` crate inherited rust-bitcoin's `Amount` display, which
would otherwise label litoshis as "BTC".
