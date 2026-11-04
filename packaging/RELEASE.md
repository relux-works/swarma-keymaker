# swarma-keymaker v0.1.0

The released artifact is the `keymaker` binary for linux/amd64, built with
the official Go 1.26.10 toolchain. Run the following block from the root of a
fresh clean clone of the release's tagged commit, using an already available
official Go 1.26.10 toolchain.
The recipe must succeed in two independent builds with byte-identical outputs
before the expected SHA-256 is finalized. The signed release tag is created
later with the platform release key, never a development signing key.

## Build

```sh
set -eu
export GOTOOLCHAIN=local GOENV=off GOWORK=off LC_ALL=C
test "$(go env GOVERSION)" = go1.26.10
GOCACHE="$(mktemp -d)"
export GOCACHE
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOFLAGS=-mod=readonly GOEXPERIMENT= GOFIPS140=off
go build -trimpath -buildvcs=false -ldflags=-buildid= -o keymaker ./cmd/keymaker
```

`GOCACHE` must be a fresh, empty directory for each build; retain or remove that
scratch directory after verification as appropriate. Module dependencies must
match the committed `go.mod` and `go.sum`. The environment and build flags match
the linux/amd64 bundle build; its private module-cache permissions and build
parallelism flags do not change binary bytes. The bundle tool builds for its
own architecture, so use a Linux amd64 builder for this artifact's bundle.

Documentation-only commits do not change binary bytes with the same source,
dependencies and toolchain because `-trimpath` removes build paths and
`-buildvcs=false` disables VCS stamping.

## Verify before installation

EXPECTED_SHA256_LINUX_AMD64: f336ee8c56cb22bf110626882ce461d47238cc902ac5df02f1c4b442f3925780

The expected binary is 7365001 bytes. A darwin/arm64 cross-build of the final
recipe, from a fresh clean clone with an empty `GOCACHE`, reproduces this digest.
The earlier native linux/amd64 build agreed on this digest; native confirmation
of the final environment pins is pending.

Run `sha256sum keymaker` and compare its full digest to the expected value above.
Any checksum mismatch must stop installation; do not install or activate the
mismatching binary.

On the same commit, with Go 1.26.10 and the build environment above, run:

```sh
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
```

The pinned `govulncheck@v1.1.4` scan must report no called vulnerabilities before
installation. A failed or incomplete scan is not acceptance.

On Linux amd64, `go test ./tools/release-bundle -run '^TestReleaseBundle$' -count=1 -v`
builds an actual bundle and independently executes this document's build block
from the same committed source with a fresh cache, then compares binary bytes.
Run after `go mod download`; the test uses cached dependencies without network
fallback. This proves bundle/recipe equivalence for that source and toolchain;
it does not replace the two independent release builds.

## Release notes

v0.1.0 contains the Linux daemon, SSH-agent subset and native control socket,
protected key custody, durable binding/result and audit storage, registration
proofs, explicit enrollment reconciliation, the generation-journal adapter,
qualified-time checks and offline bundle assembly.

This release does not install or start a service or activate proposed methods.
Protected enrollment, bootstrap and restart reconciliation, provisioning and
qualification of the generation source, qualified-time inputs, deployment and
all remaining activation gates stay with the operator. Packaging and matching
binary checksums alone do not qualify runtime activation.
