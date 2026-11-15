module github.com/relux-works/swarma-keymaker

go 1.26.10

require github.com/relux-works/swarma-registrar v0.0.0-20261025040811-264660e5dabb

require golang.org/x/sys v0.38.0

require github.com/relux-works/swarma-user-manager v0.0.0-20261024191358-505fb9f55a6d

require github.com/relux-works/swarma-envelope v0.0.0-20261026200550-5636986d0de5

require (
	github.com/btcsuite/btcd/btcec/v2 v2.5.1
	github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a
)

require (
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
)
