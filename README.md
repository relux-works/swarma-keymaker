# swarma-keymaker

Role: per-station key custody. Lore name: Keymaker.

Keymaker derives hardened Ed25519 keys and performs narrowly permitted
operations for Unix peers identified by the kernel and an active account
generation. Private identity keys never enter station processes.

**Status: Linux v0 core ready for review.** The SSH-agent subset, durable binding
store and audit journal have fixture-backed tests, including real Unix/OpenSSH/
Git integration. Production `keymaker serve` refuses
`generation_source_unavailable` until the authoritative journal format and
ordering adapter exist. No fixture authority is compiled into that command.
Native method integration, enrollment and the registration helper are separate work.
There is no deployed security boundary or installer in this repository.

`internal/control` implements bounded CCJ-1 framing, version negotiation and
sequential request dispatch. Peer/generation authority, request-ID admission,
method execution and final release fencing are required injected interfaces;
no production control adapters are supplied. The proposed Linux v0 and
publication gates are in [`spec/keymaker.md`](spec/keymaker.md).

| Path | Contents |
| --- | --- |
| `spec/keymaker.md` | Normative candidate contract, operator runbook and test plan |
| `internal/control/` | Native framing/codec, injected authority and dispatch interfaces, socket tests |
| `go.mod` | Standard-library-only module and Go version |
| `vectors/` | Paired refusal cases, published derivation controls and path examples |
| `cmd/keymaker/` | Production `serve` and `version` entry points |
| `internal/keymaker/` | Linux custody, derivation, bindings, audit and SSH-agent server |
| `cmd/keymaker-window/`, `internal/testwindow/` | Nonroot integration-window harness; separate from the daemon |
| `docs/k1a-coverage.md` | Every refusal-vector row mapped to execution or explicit K1b scope |
| `docs/linux-testing.md` | Test isolation, window configuration and remaining qualification gates |
| `tools/mutations/` | Bounded authorization, recovery and refusal control plants using Go overlays |
| `tools/vectors/` | Reproducible derivation generator and fixture checks |
| `tools/runbook-check/` | Offline specification shell-guard checks using stubs |
| `UNRESOLVED_QUESTIONS.md` | Specification decisions and activation gates |

## Tools

Linux and Go 1.26 are required; `go.mod` uses only the standard library.
The single-UID integration needs Git and OpenSSH (`ssh-keygen`). The runbook
checker needs Bash. Multi-UID qualification additionally requires the owner's
pre-provisioned test accounts and noninteractive sudo permissions.

Run from the repository root. Set `SCRATCH` to an existing absolute scratch
path outside tracked files; export `TMPDIR="$SCRATCH"` so Go test fixtures
follow it. A canonical path without `..` or symlink components is required by
the protected-directory tests. The multi-UID fixture parent separately needs
client traversal; see [Linux testing](docs/linux-testing.md).

| Tool | Purpose and exact command | Outputs |
| --- | --- | --- |
| Go | Test the native wire layer: `go test ./internal/control/...` | Test verdicts; temporary sockets cleaned by tests |
| Go | Vet the native wire layer: `go vet ./internal/control/...` | Diagnostics on stdout/stderr |
| gofmt | Check formatting: `gofmt -l internal/control/*.go` | Names of unformatted files; empty output expected |
| Go | Bounded decoder fuzzing: `GOMAXPROCS=2 go test ./internal/control -run '^$' -fuzz '^FuzzCCJRoundTrip$' -fuzztime=20s -parallel=1` | Verdicts and Go fuzz cache; failing corpus under `internal/control/testdata/fuzz/` |
| Go | Narrow core/CLI/harness checks: `go test ./internal/keymaker ./cmd/keymaker ./internal/testwindow ./cmd/keymaker-window` | Verdicts; temporary fixtures under `TMPDIR` |
| Go | Static checks: `go vet ./internal/keymaker ./cmd/keymaker ./internal/testwindow ./cmd/keymaker-window ./tools/mutations` | Diagnostics |
| gofmt | Format check: `gofmt -l cmd internal tools/mutations` | Unformatted paths, if any |
| Go | Build daemon: `go build -o "$SCRATCH/keymaker" ./cmd/keymaker`; run `"$SCRATCH/keymaker" version` or `"$SCRATCH/keymaker" serve --config "$CONFIG"` | Binary; version or readiness refusal on stderr |
| Go | Build canonical window runner: `go build -o "$SCRATCH/keymaker-window" ./cmd/keymaker-window` | Runner binary in scratch |
| Window runner | Qualify: `"$SCRATCH/keymaker-window" -config "$WINDOW_CONFIG"`; append `-check` for preflight only | Exact status below; retained report outside its own fixture directory |
| Make | Convenience wrapper: `make test-multiuid SCRATCH="$SCRATCH" WINDOW_CONFIG="$WINDOW_CONFIG"` | Prints runner status; make may normalize nonzero to 2 |
| Go | Compile pending suite: `go test -c -buildvcs=false -tags multiuid -o "$SCRATCH/multiuid.test" ./internal/keymaker` | Tagged binary; compilation is not qualification |
| Go | Run narrowing controls: `go run ./tools/mutations/main.go -scratch "$SCRATCH"` | Overlay files/logs in scratch; each mutant test must fail with exit 1; wrapper exits 0 only when all ten are killed |
| Go | Check published controls and fixture integrity: `go run ./tools/vectors/main.go -check` | Summary; no service qualification |
| Go | Regenerate path examples: `go run ./tools/vectors/main.go -write` | `vectors/keymaker-paths.json` |
| Go + Bash | Check actual marked shell preflights with stubbed NSS and mutations: `go run ./tools/runbook-check/main.go -check` | Named verdicts; temporary path fixtures under `TMPDIR`, then removed; no account writes |
| Go + Bash | Plant inverted-getent and window-path bypass regressions in memory: `go run ./tools/runbook-check/main.go -plant` | Expected exit 1 naming collision/lookup and `TestRunbookWindowPathBeforeMutation` failures; production files unchanged |
| Python 3 | JSON syntax: `python3 -c 'import json,pathlib; [json.loads(p.read_text()) for p in pathlib.Path("vectors").glob("*.json")]'` | Exit status; no files |
| Git | Scope: `git diff --check`; signatures: `git log --format="%h %G?"` | Diagnostics and signature verdicts |

| Direct window-runner status | Meaning |
| --- | --- |
| 0 | PASS (with `-check`, provisioning preflight only) |
| 1 | Test or execution failure |
| 2 | Usage or configuration error |
| 3 | PENDING; stderr is exactly `PENDING: test window not provisioned` |

`make test-multiuid` prints, for example, `multiuid runner status: 3 (PENDING)`.
Make's own exit 2 does not distinguish failure from PENDING. CI and reviewers
requiring that distinction call the compiled runner directly. A missing window
is never a skipped or passing multi-UID qualification.

## Native wire layer

The wire loop takes a caller-supplied listener or connection and enforces one
sequential request at a time. Clients must wait for replies; it does not inspect
kernel receive queues to infer when clients wrote subsequent bytes. Socket
provisioning, connection/workload limits, method-specific parameter schemas,
authorization, durable retries and audit remain core integration obligations.
A successful hello pins the connection's UID and generation. A changed tuple or
failed generation evidence refuses and closes; continuing work requires a fresh
connection. `ReleaseFence.WithActive` must serialize authoritative generation,
final result/binding checks and durable audit with the actual response write for
hello and methods. Encoding and write-deadline setup precede the barrier; a
retirement that wins the barrier suppresses success and closes after a typed
refusal where transport permits it. A partial success write closes without a
second reply. The interface can wrap the core's `GenerationSource.WithActive`;
a lookup followed by an unprotected write does not satisfy its contract.

Exact retries may pass the request-ID interface for handler-owned result recovery;
changed arguments must be refused by that generation-scoped interface.

The native wire checks validate transport behavior with injected peers. They do
not qualify a production daemon, enforce real kernel peer authentication or
replace the pending integration tests listed in the specification.
