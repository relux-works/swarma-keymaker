# swarma-keymaker

Role: per-station key custody. Lore name: Keymaker.

Keymaker derives hardened Ed25519 keys and performs narrowly permitted
operations for Unix peers identified by the kernel and an active account
generation. Private identity keys never enter station processes.

**Status: Linux v0 core, native integration and local enrollment authority ready for review.** Both the
SSH-agent subset and native control socket use the same binding/result store,
audit journal, generation authority and admission limits. Tests include real
Unix sockets and OpenSSH/Git with fixture authority. Production `keymaker serve`
still refuses `generation_source_unavailable` until the authoritative generation
journal and ordering adapter exist. No fixture authority is compiled into it.
Persistent operator revocation remains closed without a signed-act verifier;
`sign_registration` is unsupported. Registration-helper wiring is separate work.
The pure registration proof builder has local fixture-backed checks. There is no
deployed security boundary or installer here.

`internal/control` provides bounded CCJ-1 framing and dispatch.
`internal/keymaker` supplies its kernel peer, durable request-ID, method,
workload/audit and final release adapters. The normative contract and publication
gates are in [`spec/keymaker.md`](spec/keymaker.md).

`internal/enrollment` supplies protected pins, isolated signed-Git verification,
durable rollback state and local enrollment authority using the registrar
packages. First acceptance requires an explicit operator bootstrap through the
[reconcile command](internal/enrollment/README.md#operator-reconciliation-procedure); the service never initializes empty state. Every restart
requires explicit operator reconciliation. The proposed
Linux v0 and publication gates are in [`spec/keymaker.md`](spec/keymaker.md).

| Path | Contents |
| --- | --- |
| `spec/keymaker.md` | Normative candidate contract, operator runbook and test plan |
| `internal/control/` | Native framing/codec, injected authority and dispatch interfaces, socket tests |
| `internal/enrollment/` | Linux protected pins, isolated signed-Git verification, durable CAS state and enrollment authority; [API and limits](internal/enrollment/README.md) |
| `internal/registration/` | Registrar-owned proof construction, trusted time/entropy/signing and final recheck; [API, vector coverage and limits](internal/registration/README.md) |
| `go.mod`, `go.sum` | Go version and exact registrar dependency pin |
| `vectors/` | Paired refusal cases, published derivation controls and path examples |
| `cmd/keymaker/` | Production `serve`, `version` and operator `enrollment reconcile` entry points |
| `internal/keymaker/` | Linux custody, derivation, bindings/results, audit and both socket servers |
| `cmd/keymaker-window/`, `internal/testwindow/` | Nonroot integration-window harness; separate from the daemon |
| `docs/k1a-coverage.md` | Surface A coverage and retained recovery controls |
| `docs/k1b-coverage.md` | Native daemon coverage, recovery limits and deferred helper rows |
| `docs/linux-testing.md` | Test isolation, window configuration and remaining qualification gates |
| `tools/mutations/` | Bounded authorization, recovery and refusal control plants using Go overlays |
| `tools/vectors/` | Reproducible derivation generator and fixture checks |
| `tools/runbook-check/` | Offline specification shell-guard checks using stubs |
| `UNRESOLVED_QUESTIONS.md` | Specification decisions and activation gates |

## Tools

Linux and Go 1.26 are required. Enrollment validation uses the pinned registrar
packages below; the core, wire layer and offline tools use the Go standard library.
The single-UID integration needs Git and OpenSSH (`ssh-keygen`). The runbook
checker needs Bash and uses `/usr/sbin/visudo` when installed. Multi-UID
qualification additionally requires the owner's
pre-provisioned test accounts and noninteractive sudo permissions.

Run from the repository root. Set `SCRATCH` to an existing absolute scratch
path outside tracked files; export `TMPDIR="$SCRATCH"` so Go test fixtures
follow it. A canonical path without `..` or symlink components is required by
the protected-directory tests. The multi-UID fixture parent separately needs
client traversal; see [Linux testing](docs/linux-testing.md).

| Tool | Purpose and exact command | Outputs |
| --- | --- | --- |
| Go | Test pure proof construction: `go test ./internal/registration -count=1` | Local pinned registration vectors and generated in-memory fixture keys; no host SSH access |
| Go | Race-check proof construction: `GOMAXPROCS=2 go test -race ./internal/registration -count=1 -p=1` | Race diagnostics and verdicts |
| Go | Vet proof construction: `go vet ./internal/registration ./tools/mutations` | Diagnostics |
| gofmt | Check proof formatting: `gofmt -l internal/registration/*.go tools/mutations/main.go` | Empty output expected |
| keymaker | Reconcile before enrollment startup: `keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG"` (root operator, stopped helper; optionally `--confirm "$EXACT_STATE_SHA256"`) | JSON lines on stdout, summary/prompt on stderr; one-use approval in protected enrollment state directory |
| Go | Test enrollment authority: `go test ./internal/enrollment` | Named verdicts; isolated fixture registries/keys under the Go temporary directory, cleaned by tests |
| Go | Targeted race check: `GOMAXPROCS=2 go test -race ./internal/enrollment -run 'TestConcurrentReloadAuthorize\|TestStoreCompareAndSwap\|TestInterruptedWriteFencesUntilRestart' -count=1 -p=1` | Race diagnostics and verdicts |
| Go | Run the published enrollment fixture integration: `GOPROXY=off go test -v ./internal/enrollment -run '^TestRegistrarEnrollmentConformance$' -count=1` | 114 negative/25 positive local pinned-module rows; no test-time fetch |
| Go | Vet enrollment authority: `go vet ./internal/enrollment` | Diagnostics on stdout/stderr |
| gofmt | Check enrollment formatting: `gofmt -l internal/enrollment/*.go` | Empty output expected |
| Git + OpenSSH | Production uses `/usr/bin/git cat-file` and `merge-base --is-ancestor`; fixture tests invoke `/usr/bin/ssh-keygen -t ed25519` and Git `commit-tree -S` | Local objects and temporary test-only keys; no network or inherited SSH agent |
| Go | Test the native wire layer: `go test ./internal/control/...` | Test verdicts; temporary sockets cleaned by tests |
| Go | Vet the native wire layer: `go vet ./internal/control/...` | Diagnostics on stdout/stderr |
| gofmt | Check formatting: `gofmt -l internal/control/*.go` | Names of unformatted files; empty output expected |
| Go | Bounded decoder fuzzing: `GOMAXPROCS=2 go test ./internal/control -run '^$' -fuzz '^FuzzCCJRoundTrip$' -fuzztime=20s -parallel=1` | Verdicts and Go fuzz cache; failing corpus under `internal/control/testdata/fuzz/` |
| Go | Native integration checks: `go test ./internal/keymaker -run '^TestNative' -count=1`; race: `go test -race ./internal/keymaker -run '^TestNative' -count=1` | Verdicts; temporary fixtures under `TMPDIR` |
| Go | Static checks: `go vet ./internal/keymaker ./cmd/keymaker ./internal/testwindow ./cmd/keymaker-window ./tools/mutations` | Diagnostics |
| gofmt | Format check: `gofmt -l cmd internal tools/mutations` | Unformatted paths, if any |
| Go | Build daemon: `go build -o "$SCRATCH/keymaker" ./cmd/keymaker`; run `"$SCRATCH/keymaker" version` or `"$SCRATCH/keymaker" serve --config "$CONFIG"` | Binary; version or readiness refusal on stderr |
| Go | Build canonical window runner: `go build -o "$SCRATCH/keymaker-window" ./cmd/keymaker-window` | Runner binary in scratch |
| Window runner | Qualify: `"$SCRATCH/keymaker-window" -config "$WINDOW_CONFIG"`; append `-check` for preflight only | Exact status below; retained report outside its own fixture directory |
| Make | Convenience wrapper: `make test-multiuid SCRATCH="$SCRATCH" WINDOW_CONFIG="$WINDOW_CONFIG"` | Prints runner status; make may normalize nonzero to 2 |
| Go | Compile pending suite: `go test -c -buildvcs=false -tags multiuid -o "$SCRATCH/multiuid.test" ./internal/keymaker` | Tagged binary; compilation is not qualification |
| Go | Run narrowing controls (default `core`, including native): `go run ./tools/mutations/main.go -scratch "$SCRATCH"` | Overlay files/logs in scratch; each mutant test must fail with exit 1; wrapper exits 0 only when all eighteen are killed |
| Go | Run only native narrowing controls: `go run ./tools/mutations/main.go -group native -scratch "$SCRATCH"` | Eight native plants from the default core group; wrapper 0 only when all are killed |
| Go | Run proof narrowing controls: `go run ./tools/mutations/main.go -group registration -scratch "$SCRATCH"` | Five named plants; child logs/PIDs in scratch, wrapper 0 only when all are killed |
| Go | Check published controls and fixture integrity: `go run ./tools/vectors/main.go -check` | Summary; no service qualification |
| Go | Regenerate path examples: `go run ./tools/vectors/main.go -write` | `vectors/keymaker-paths.json` |
| Go + Bash + visudo | Check marked shell guards, provisioning order and generated sudoers syntax with stubbed NSS/mutations: `go run ./tools/runbook-check/main.go -check` | Named verdicts; real unprivileged `visudo -cf` on private scratch, or explicit SKIPPED with reason when absent; temporary fixtures under `TMPDIR`, then removed; no account writes |
| Go + Bash + visudo | Plant lookup/path bypasses, unsupported `requiretty` and validation-after-allocation in memory: `go run ./tools/runbook-check/main.go -plant` | Expected exit 1 naming guard, `TestRunbookWindowSudoersCompatibility` and `TestRunbookWindowValidationBeforeMutation` failures; missing parser is SKIPPED; production files unchanged |
| Python 3 | JSON syntax: `python3 -c 'import json,pathlib; [json.loads(p.read_text()) for p in pathlib.Path("vectors").glob("*.json")]'` | Exit status; no files |
| Git | Scope: `git diff --check`; signatures: `git log --format="%h %G?"` | Diagnostics and signature verdicts |

The parser case is counted as passed only when the real parser executes and
accepts the exact constrained rules. An absent parser is printed as SKIPPED with
a reason and a separate count; compatibility remains unverified. All account,
group, install and rename steps in the order checks are stubs; the generated
policy is parsed from private scratch without changing installed sudoers.

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
kernel receive queues to infer when clients wrote subsequent bytes. The core daemon supplies
socket provisioning, shared connection/workload limits, exact parameter schemas,
authorization, durable retries and audit. Its Observer is mandatory: every
framed attempt obtains shared work credit before parsing/hashing; every refusal
is durably reported or closes service health. Handler receives the complete
admitted Request, including its exact ID, without per-peer request guessing.
The daemon calls `ServeConnAccepted` with its validated UID/generation tuple
before reading hello. `ServeConn` remains available to transport owners that
pin at first successful hello. A changed tuple or failed generation evidence refuses and closes; continuing work requires a fresh
connection. `ReleaseFence.WithActive` must serialize authoritative generation,
final result/binding checks and durable audit with the actual response write for
hello and methods. Encoding and write-deadline setup precede the barrier; a
retirement that wins the barrier suppresses success and closes after a typed
refusal where transport permits it. A partial success write closes without a
second reply. The native adapter uses `GenerationSource.WithActive` for
hello/self reads and one `WithEvidence` barrier for mutation release, carrying
every generation predicate required by the fresh effect through the actual write. Exact historical
retries recover their original result under current caller authority. Transaction
selection rechecks retained state under the Store lock inside the generation
barrier before applying fresh-target predicates, including concurrent retries.
`GenerationCondition.Verdict` defers a target predicate to that callback; it must
be enforced before a fresh effect. Release conditions never defer predicates.
A lookup followed by an unprotected write does not satisfy this contract.

Hello does not select a binding. The first self `pubkey` pins that connection's
registration number; revocation/unbinding closes it, including while idle.
Request, transaction and release checks also reject an invalid pin without
waiting for notification. A replacement requires a fresh connection. Operator
mutations address target registrations without adopting them as the operator's
self identity, so an operator connection that has used only hello/mutations
requires no station binding. If it requests its own pubkey, that self binding
then pins the connection in the same way.

Exact retries may pass the request-ID interface for handler-owned result recovery;
changed arguments must be refused by that generation-scoped interface.

The wire package tests use injected peers; `TestNative*` separately exercises the
real dual-surface daemon, Linux `SO_PEERCRED`, Master and paired durable Store.
These are fixture-authority tests, not production generation-journal or live
multi-UID qualification. See [coverage](docs/k1b-coverage.md).

Protected daemon configuration includes numeric `service_uid`, `service_gid`,
`control_gid` and `operator_principal: {"uid": <number>, "generation": "<token>"}`,
plus `socket_dir`, `state_dir`, `master_file`, `registry_file`, `master_epoch`
and `registry_revision`. Every member is required; paths must satisfy protected
ownership rules. `control_gid` selects the helper group; startup fails if it
cannot publish an exactly 0660 service-owned socket with that group. The
operator's complete UID/generation tuple, rather than group membership, grants
register/revoke intake. No supplied object can enable the absent act verifier.
Native public results contain `public_key` (base64 of 32 raw Ed25519 bytes),
`path`, `registration_number` and `master_epoch`; they contain no key material
beyond the public key. A revoke result contains the registration number and
`status: "revoked"`.

## Registrar dependency

The registration proof format, enrollment schema, publisher verification,
registry snapshot loader and name rules belong to
`github.com/relux-works/swarma-registrar`. The dependency is pinned
to reviewed main commit `263ca7fcfd97518ace7e740792500f6c92f4ba1e`
(`v0.0.0-20261023150327-263ca7fcfd97`). Keymaker supplies caller-side trust,
persistence and local authorization; it does not maintain a second loader.

Any registrar API or behavior change requires a separate reviewed pull request
there and must land on its main first. Raise this dependency only in an explicit
pin-bump commit here: run `go get github.com/relux-works/swarma-registrar@<full-commit-id>`,
review and commit both `go.mod` and `go.sum`, update this pin, and run the affected
enrollment tests against that exact revision. A branch name or an API inventory
check is not behavior approval.
