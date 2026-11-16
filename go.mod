module github.com/relux-works/swarma-keymaker

go 1.26.10

// Sort the local replacement below published pseudo-versions for downstream consumers.
require github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000

replace github.com/relux-works/swarma-keymaker/messageauthor => ./messageauthor

require github.com/relux-works/swarma-registrar v0.0.0-20261025040811-264660e5dabb

require golang.org/x/sys v0.47.0

require github.com/relux-works/swarma-user-manager v0.0.0-20261024191358-505fb9f55a6d

require github.com/relux-works/swarma-envelope v0.0.0-20261114153213-065e25f69da8

require (
	github.com/btcsuite/btcd/btcec/v2 v2.5.1
	github.com/relux-works/swarma-chain-lab/experiments/rental v0.5.1-0.20261114210947-e70a35a41dec
	github.com/relux-works/swarma-chain-lab/experiments/single-use v0.3.1-0.20261114202108-27d39435cdc4
	github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a
)

require (
	github.com/btcsuite/btcd v0.24.2 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/relux-works/swarma-chain-lab/experiments/payment-chain v0.2.1-0.20261114202108-27d39435cdc4 // indirect
	github.com/relux-works/swarma-chain-lab/experiments/sealwatch v0.2.1-0.20261114202108-27d39435cdc4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
)
