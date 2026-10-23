# swarma-keymaker

Role: per-station key custody. Lore name: Keymaker.

Keymaker holds an installation's key material and performs narrowly permitted
operations for Unix peers identified by the kernel and an active account
generation. Private identity keys never enter station processes.

**Status: specification and native wire layer.** `internal/control` implements
bounded CCJ-1 framing, version negotiation and sequential request dispatch.
Peer/generation authority, request-ID admission, method execution and final
release fencing are required injected interfaces; no production adapters are
supplied. There is no service binary, installer or deployed security boundary. The vector tool is offline test tooling.
The proposed Linux v0 and publication gates are in
[`spec/keymaker.md`](spec/keymaker.md).

| Path | Contents |
| --- | --- |
| `spec/keymaker.md` | Normative candidate contract, operator runbook and test plan |
| `internal/control/` | Native framing/codec, injected authority and dispatch interfaces, socket tests |
| `go.mod` | Standard-library-only module and Go version |
| `vectors/` | Paired refusal cases, published derivation controls and path examples |
| `tools/vectors/` | Reproducible Go derivation generator and fixture checks |
| `tools/runbook-check/` | Offline regression of the specification's shell guards, using stubs |
| `UNRESOLVED_QUESTIONS.md` | Index of decisions and activation gates |

## Tools

Run commands from the repository root. The implementation and both tools use
only the Go standard library (Go 1.26); the runbook check also needs Bash.
Tests use temporary Unix sockets and injected peers, not service credentials
or host account-management commands.

| Tool | Purpose and exact command | Outputs |
| --- | --- | --- |
| Go | Test the native wire layer: `go test ./internal/control/...` | Test verdicts; temporary sockets cleaned by tests |
| Go | Vet the native wire layer: `go vet ./internal/control/...` | Diagnostics on stdout/stderr |
| gofmt | Check formatting: `gofmt -l internal/control/*.go` | Names of unformatted files; empty output expected |
| Go | Bounded decoder fuzzing: `GOMAXPROCS=2 go test ./internal/control -run '^$' -fuzz '^FuzzCCJRoundTrip$' -fuzztime=20s -parallel=1` | Verdicts and Go fuzz cache; failing corpus under `internal/control/testdata/fuzz/` |
| Go | Check published SLIP-0010 controls, regenerate in memory and compare: `go run ./tools/vectors/main.go -check` | Summary on stdout; refuses mismatched fixtures |
| Go | Regenerate Keymaker derivation examples: `go run ./tools/vectors/main.go -write` | `vectors/keymaker-paths.json` |
| Go + Bash | Check actual marked shell preflights with stubbed NSS and mutations: `go run ./tools/runbook-check/main.go -check` | Named regression verdicts on stdout; no host writes |
| Go + Bash | Plant the inverted-getent regression in memory: `go run ./tools/runbook-check/main.go -plant` | Expected nonzero exit 1 naming `TestRunbookCollisionBeforeMutation`; production files unchanged |
| Python 3 | Check all JSON: `python3 -c 'import json,pathlib; [json.loads(p.read_text()) for p in pathlib.Path("vectors").glob("*.json")]'` | Exit status; no files |
| Git | Inspect scope: `git diff --check`; verify signed commits: `git log --format="%h %G?"` | Diagnostics on stdout |

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

The checks validate transport behavior, fixtures and derivation tooling. They do
not qualify a daemon, enforce real kernel peer authentication or replace the
pending integration tests listed in the specification.
