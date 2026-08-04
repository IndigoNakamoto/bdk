module github.com/LitecoinDevKit/bdk/scripts/ltcd_mweb_fixtures

go 1.23.0

require (
	github.com/ltcsuite/ltcd v0.23.6-0.20250505084124-c37ac1524e04
	github.com/ltcsuite/ltcd/chaincfg/chainhash v1.0.2
	github.com/ltcsuite/ltcd/ltcutil v1.1.5-0.20250724031157-a9e8b8c8340e
	github.com/ltcsuite/ltcd/ltcutil/psbt v0.0.0-00010101000000-000000000000
	github.com/ltcsuite/secp256k1 v0.1.1
	lukechampine.com/blake3 v1.2.1
)

require (
	github.com/btcsuite/btclog v0.0.0-20241003133417-09c4e92e319c // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/ltcsuite/ltcd/btcec/v2 v2.3.2 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace github.com/ltcsuite/ltcd => ./vendor-ltcd

replace github.com/ltcsuite/ltcd/ltcutil => ./vendor-ltcd/ltcutil

replace github.com/ltcsuite/ltcd/ltcutil/psbt => ./vendor-ltcd/ltcutil/psbt
