# swarma-keymaker

Role: per-station key custody. Lore name: Keymaker.

Keymaker derives hardened Ed25519 keys and performs narrowly permitted
operations for Unix peers identified by the kernel and an active account
generation. Private identity keys never enter station processes.

**Status: Linux v0 core, native integration and local enrollment authority ready for review.** Both the
SSH-agent subset and native control socket use the same binding/result store,
audit journal, generation authority and admission limits. Tests include real
Unix sockets and OpenSSH/Git with fixture authority. Production `keymaker serve`
uses the root-policy `gen-journal/1` adapter when protected configuration supplies
`generation_journal: {path, initial_floor: {seq, hash}}`. Without it, readiness
refuses `generation_source_unavailable`. Pristine enrollment accepts that explicit
floor only before any binding has been issued; damaged established anchors,
rollback, fork, stale writers and reserve incidents fence without automatic
recovery. The real root-owned journal remains an activation qualification gate.
No fixture authority is compiled into normal production builds.
Persistent operator revocation remains closed pending signed-act integration
and qualified fact sources. The [Q7 audit schema](spec/keymaker.md#111-operator-record-audit-extension)
specifies a closed operator-only extension with unchanged historical bytes;
[historical-recovery acceptance](spec/keymaker.md#112-q7-historical-recovery-acceptance-rows)
is PENDING implementation and qualification.
`sign_registration` builds registrar proofs with a separate purpose-2 key,
current binding/enrollment authority and durable same-ID recovery. The curator-approved
`custody_unavailable` refusal uses one response for every custody cause; only the
local audit distinguishes `closed`, `unloaded` and `protection_failed`. There is no
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

The [option C witness proposal](spec/keymaker-witness.md) defines a separate
Keymaker stream, witnessed state epochs and startup/commit recovery rules.
It is spec only: option A remains in use, and witness placement, keys,
freshness, exclusion and lifecycle qualification remain open activation gates.
The [shared witness-service candidate](spec/witness-service.md) proposes typed
streams, append/head/proof operations, registry-checkpoint inclusion and server
restore rules. It is spec only; implementation ownership, consumer-wire/transport
acceptance, independent retention and capacity qualification remain open.

The [Swarm Signer message proposal](spec/keymaker-msg.md) defines a purpose-4
message key, constrained native signing, certification and paired text vectors.
The native method remains a proposal. Stable persistent-key continuity, generation-bound authority
attestations, an owner-pinned purpose-5 issuer and its 24-hour ceiling are
decided. Signing checks `key`, `body.author` and `body.author_attestation`
against the caller's own active key and current purpose-5 attestation. The
proposal aligns to accepted waggle `67df75bec015ea463f685e4daf4975ecda18816a`:
exact `swarma-msg/2`, 24576-byte/depth12 signed records, attestation/1 and
separate registry-owner revocation authority. The
[supplement's alignment ledger](spec/keymaker-msg.md#44-landed-s0-alignment-and-qualification-gates)
records resolved mappings; native signing, publication and qualification
remain gates.
No new method is enabled.

The [pre-active provision/confirm proposal](spec/keymaker-provision.md) reserves
a binding while a bump successor is `creating`, without key issuance before
`active`. It recommends a separate operator method and authenticated metadata
query. Joint confirmation-currency and adapter qualification remain gates;
normal create keeps register-after-active. No new method is enabled.

| Path | Contents |
| --- | --- |
| `spec/keymaker-operator-record.md` | Proposed S1 operator-record integration, fact sources, durable replay and audit delta; no runtime activation |
| `spec/keymaker.md` | Normative candidate contract, operator runbook and test plan |
| `spec/witness-service.md` | Proposed shared typed witness protocol, registry intent/resolution inclusion, server durability and paired text vectors; no implementation or activation |
| `spec/keymaker-witness.md` | Proposed external-state witness, lifecycle vectors and curator review changes; no implementation or activation |
| `spec/keymaker-provision.md` | Proposed pre-active binding, generation-pin ordering, local confirmation and paired text vectors; no activation |
| `spec/keymaker-pc2.md` | Normative candidate PC2 root/intent, terminal authority fence, exact-attempt recovery and paired KR/KI/KP qualification; combined S2 storage and three joint gates remain open, production bump closed |
| `spec/keymaker-msg.md` | Proposed Swarm Signer message domain, lifecycle, certification and text vectors; no implementation or activation |
| `spec/keymaker-msg-state.md` | Proposed K3 schema, exact-outcome recovery, issuance audit and durable registry/WC1 publication proof; no runtime activation |
| `internal/control/` | Native framing/codec, injected authority and dispatch interfaces, socket tests |
| `internal/enrollment/` | Linux protected pins, isolated signed-Git verification, durable CAS state and enrollment authority; [API and limits](internal/enrollment/README.md) |
| `internal/registration/` | Registrar-owned proof construction, trusted time/entropy/signing and final recheck; [API, vector coverage and limits](internal/registration/README.md) |
| `go.mod`, `go.sum` | Go version and exact dependency pins |
| `vectors/` | Paired refusal cases, published derivation controls and path examples |
| `cmd/keymaker/` | Production `serve`, `version` and operator `enrollment reconcile` entry points |
| `internal/keymaker/` | Linux custody, derivation, bindings/results, audit and both socket servers |
| `cmd/keymaker-window/`, `internal/testwindow/` | Nonroot integration-window harness; separate from the daemon |
| `docs/k1a-coverage.md` | Surface A coverage and retained recovery controls |
| `docs/k1b-coverage.md` | Native/helper daemon coverage, recovery limits and pending deployment gates |
| `docs/linux-testing.md` | Test isolation, window configuration and remaining qualification gates |
| `tools/mutations/` | Bounded authorization, recovery and refusal control plants using Go overlays |
| `packaging/` | Exact specification unit and real daemon example config; [fields, bundle contract and dependency gates](packaging/README.md) |
| `tools/release-bundle/` | Offline clean-commit binary, validated inputs and SHA256SUMS assembly; no installation |
| `tools/vectors/` | Reproducible derivation generator and fixture checks |
| `tools/runbook-check/` | Offline specification shell-guard checks using stubs |
| `UNRESOLVED_QUESTIONS.md` | Specification decisions and activation gates |

The [PC2 authority requirements](spec/keymaker-pc2.md) do not change the shipped
binding/audit/enrollment implementation. Its combined S2 format/migration,
durable handoff, independent restore custody and withdrawal-blocking gates remain
open; production bump is closed. Existing runtime and tool checks below do not
qualify PC2, and historical binding-pair documentation is not its commit model.

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
| Go | Trusted time integration: `go test ./cmd/keymaker ./internal/keymaker ./internal/registration ./internal/enrollment ./internal/control -run '^(TestTimeConfidence\|TestCollectorEntryFirst)' -count=1 -v` | Provider age/uncertainty/hold boundaries, missing-policy refusal, final audit recheck, approval invalidation, null audit time and production collector/pin isolation; private TMPDIR fixtures |
| Go | Verify copied generation-vector provenance and bounded drift controls: `go test ./internal/keymaker -run '^TestGenerationVector(Provenance\|DriftControl)$' -count=1 -v` | Exact public source hashes and 67-case inventory; this does not run adapter verdicts |
| Go | Check terminal generation refusal handling: `GOMAXPROCS=2 GOFLAGS=-p=2 GORACE=atexit_sleep_ms=0 go test -race ./internal/control ./internal/keymaker -run '^Test(GenerationSourceFencedContract\|NativeGenerationAdmissionRefusal\|ResponseRefusals\|RetryableAllowlist)$' -count=1 -v` | Nonretryable typed refusals, one admission audit and no effects, paired active controls; private test sockets under TMPDIR |
| Go | Check local generation anchors and bounded callbacks: `go test ./internal/keymaker ./internal/control -run '^TestGeneration(AnchorContinuity\|SourceIncidentClassification\|EvidencePredicates\|DeadlineAgentAudit\|DeadlineTransport\|JournalConfig)$' -count=1 -v` | Local verified-view fakes, restart/incident evidence and actual bounded transport; no root-owned journal qualification |
| Go | Tagged source fixture contracts: `go test -tags genjournal_testseam ./internal/keymaker -run '^TestGenerationTagged' -count=1 -v` | All 67 vectors, source no-create and real-flock ordering; isolated nonroot fixture policy. Semantic fixtures use the owner's explicit 5s window in normal and race runs; dedicated deadline tests retain 250ms |
| Go | Race-check tagged journal paths: `GOMAXPROCS=2 GOFLAGS=-p=2 GORACE=atexit_sleep_ms=0 go test -race -tags genjournal_testseam ./internal/keymaker -run '^TestGenerationTagged' -count=1 -v` | All 67 vectors, lock winners, writer progress, exact gap and restart; semantic windows accommodate instrumentation and local anchor sync without changing production timing |
| Go | Untagged byte anchor timing regression: `go test ./internal/keymaker -run '^TestGenerationByteAnchorSyncDelay$' -count=1 -v` | Real 300ms Sync preserves intact/corrupt semantics under the explicit 5s test window; the 250ms neighbor refuses before callback |
| Go | Check delayed-sync fixture isolation: `go test -tags genjournal_testseam ./internal/keymaker -run '^TestGenerationTagged(VectorSyncDelay\|AnchorSyncDeadline\|ReaderHoldWindow)$' -count=1 -v` | Real 300ms anchor audit sync admits both semantic control histories but refuses before callback with default 250ms; durable publication, source preservation and fresh default controls checked |
| Go | Check normal production build isolation: `go test ./internal/keymaker -run '^TestGenerationProductionBuildBoundary$' -count=1 -v` | Dependency inventory and `go version -m` metadata for a temporary binary; detects a planted forbidden test tag |
| Go | All four generation controls: `go run ./tools/mutations/main.go -group genjournal -scratch "$SCRATCH"` | Four named expected failures; the dependency controls use an exact public module snapshot and test-only go.work outside GOMODCACHE, with a green unmutated control; no product module replacements |
| Go | Local generation narrowing controls: `go run ./tools/mutations/main.go -group genjournal-core -scratch "$SCRATCH"` | Two exact failing local anchor/classification witnesses under scratch |
| Go | Test pure proof construction: `go test ./internal/registration -count=1` | Local pinned registration vectors and generated in-memory fixture keys; no host SSH access |
| Go | Race-check proof construction: `GOMAXPROCS=2 go test -race ./internal/registration -count=1 -p=1` | Race diagnostics and verdicts |
| Go | Vet proof construction: `go vet ./internal/registration ./tools/mutations` | Diagnostics |
| gofmt | Check proof formatting: `gofmt -l internal/registration/*.go tools/mutations/main.go` | Empty output expected |
| keymaker | Reconcile before enrollment startup: `keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG"` (root operator, stopped helper; optionally `--confirm "$EXACT_STATE_SHA256"`) | JSON lines on stdout, summary/prompt on stderr; one-use approval in protected enrollment state directory |
| Go | Test enrollment authority: `go test ./internal/enrollment` | Named verdicts; isolated fixture registries/keys under the Go temporary directory, cleaned by tests |
| Keymaker | Initial operator acceptance: `keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG" --bootstrap [--confirm "$EXACT_STATE_SHA256"]` | v1 JSON (`bootstrap: true`) on stdout; summary on stderr; confirmed state and one-use receipt in the protected state directory |
| Go | Targeted race check: `GOMAXPROCS=2 go test -race ./internal/enrollment -run 'TestConcurrentReloadAuthorize\|TestStoreCompareAndSwap\|TestInterruptedWriteFencesUntilRestart' -count=1 -p=1` | Race diagnostics and verdicts |
| Go | Run the published enrollment fixture integration: `GOPROXY=off go test -v ./internal/enrollment -run '^TestRegistrarEnrollmentConformance$' -count=1` | 114 negative/25 positive local pinned-module rows; no test-time fetch |
| Go | Vet enrollment authority: `go vet ./internal/enrollment` | Diagnostics on stdout/stderr |
| gofmt | Check enrollment formatting: `gofmt -l internal/enrollment/*.go` | Empty output expected |
| Git + OpenSSH | Production uses `/usr/bin/git cat-file` and `merge-base --is-ancestor`; fixture tests invoke `/usr/bin/ssh-keygen -t ed25519` and Git `commit-tree -S` | Local objects and temporary test-only keys; no network or inherited SSH agent |
| Go | Packaging parser and unit checks: `go test ./internal/keymaker -run '^TestPackagingConfig' -count=1`; `go test ./tools/release-bundle -count=1` | Paired refusals, clean-clone fixtures and offline real builds under verified private test TMPDIR roots; caller TMPDIR mode is independent |
| Go | Packaging static checks: `go vet ./tools/release-bundle ./tools/mutations ./internal/keymaker`; `gofmt -l tools/release-bundle/*.go internal/keymaker/config_linux*.go internal/keymaker/runtime_linux.go` | Diagnostics; empty formatting output expected |
| Go | Build offline assembler: `go build -trimpath -o "$SCRATCH/release-bundle" ./tools/release-bundle` | Tool binary under scratch |
| release-bundle | Assemble: `"$SCRATCH/release-bundle" -repo "$SOURCE" -commit "$COMMIT" -version "$VERSION" -target "$BUNDLE" -config "$CONFIG" -name-indices "$REGISTRY" -module-cache "$MODULE_CACHE"` | New offline bundle directory; child work uses private TMPDIR scratch; unknown child files are retained |
| sha256sum | Verify before the root step: `(cd "$BUNDLE" && sha256sum -c SHA256SUMS)` | Every listed file must report OK; exit 0 required |
| Go | Test the native wire layer: `go test ./internal/control/...` | Test verdicts; temporary sockets cleaned by tests |
| Go | Vet the native wire layer: `go vet ./internal/control/...` | Diagnostics on stdout/stderr |
| gofmt | Check formatting: `gofmt -l internal/control/*.go` | Names of unformatted files; empty output expected |
| Go | Bounded decoder fuzzing: `GOMAXPROCS=2 go test ./internal/control -run '^$' -fuzz '^FuzzCCJRoundTrip$' -fuzztime=20s -parallel=1` | Verdicts and Go fuzz cache; failing corpus under `internal/control/testdata/fuzz/` |
| Go | Concurrent valid helper/pubkey control: `GOMAXPROCS=1 go test -race ./internal/keymaker -run '^TestHelperConcurrentPubkeyControl$' -count=20 -p=1`; repeat with `GOMAXPROCS=2` | Both responses verify/succeed at the normal native budget; no reload traffic |
| Go | Reader/writer admission fairness: `GOMAXPROCS=1 go test -race ./internal/enrollment ./internal/keymaker -run '^Test(AdmissionGate\|ReviewR2SocketReloadFairness\|HelperReloadFairnessControl)' -count=3 -p=1` | Finite reader handoff, cancellation, failed-publication fencing, writer progress and real helper socket control |
| Go | Reload deadline and publication regressions: `GOMAXPROCS=2 go test -race ./internal/keymaker -run '^Test(ReviewHelperReloadDeadline\|HelperReloadPreparesOutsideWrite)$' -count=1 -p=1` | Fixture pin I/O, real daemon sockets and authority barriers; allowed pubkey retention plus refusal-only helper audit |
| Go | Native integration checks: `go test ./internal/keymaker -run '^TestNative' -count=1`; race: `go test -race ./internal/keymaker -run '^TestNative' -count=1` | Verdicts; temporary fixtures under `TMPDIR` |
| Go | Native generation admission regressions: `GOMAXPROCS=2 go test -race ./internal/keymaker ./internal/control -run '^Test(NativeGenerationAdmission\|RefusedConnection)' -count=1 -p=1` | Typed audited first-frame refusals, no execution/effect, bounded silent-peer closure and active controls |
| Go | Refusal audit deadline regressions: `GOMAXPROCS=2 go test -race ./internal/keymaker -run '^Test(ReviewAdmissionQueuedAuditDeadline\|NativeAdmissionStartedAuditDeadline\|NativeOrdinaryRefusalAuditDeadline\|JournalCancelledBeforeAppend\|JournalDeadlineDuringPreparation)$' -count=1 -p=1` | Journal contention abandons only unstarted appends, releases slots and closes without late audit; started sync completes exactly once; healthy same-daemon controls |
| Go | Static checks: `go vet ./internal/keymaker ./cmd/keymaker ./internal/testwindow ./cmd/keymaker-window ./tools/mutations` | Diagnostics |
| gofmt | Format check: `gofmt -l cmd internal tools/mutations` | Unformatted paths, if any |
| Go | Custody response/audit regressions: `go test -race ./internal/keymaker -run '^Test(CustodyAudit|CustodySign|CustodyUnavailable|MasterUnavailable)' -count=1 -p=1`; `go run ./tools/mutations/main.go -group core -scratch "$SCRATCH"` | Real-socket byte-equal refusals, local cause enumeration, open signing controls; logs/overlays under private scratch |
| Go | Build daemon: `go build -o "$SCRATCH/keymaker" ./cmd/keymaker`; run `"$SCRATCH/keymaker" version` or `"$SCRATCH/keymaker" serve --config "$CONFIG"` | Binary; version or readiness refusal on stderr |
| Go | Build canonical window runner: `go build -o "$SCRATCH/keymaker-window" ./cmd/keymaker-window` | Runner binary in scratch |
| Window runner | Qualify: `"$SCRATCH/keymaker-window" -config "$WINDOW_CONFIG"`; append `-check` for preflight only | Exact status below; retained report outside its own fixture directory |
| Make | Convenience wrapper: `make test-multiuid SCRATCH="$SCRATCH" WINDOW_CONFIG="$WINDOW_CONFIG"` | Prints runner status; make may normalize nonzero to 2 |
| Go | Compile pending suite: `go test -c -buildvcs=false -tags multiuid -o "$SCRATCH/multiuid.test" ./internal/keymaker` | Tagged binary; compilation is not qualification |
| Go | Run narrowing controls (default `core`, including native): `go run ./tools/mutations/main.go -scratch "$SCRATCH"` | Overlay files/logs in scratch; each mutant test must fail with exit 1; wrapper exits 0 only when all twenty are killed |
| Go | Run only native narrowing controls: `go run ./tools/mutations/main.go -group native -scratch "$SCRATCH"` | Ten native plants from the default core group; wrapper 0 only when all are killed |
| Go | Run proof narrowing controls: `go run ./tools/mutations/main.go -group registration -scratch "$SCRATCH"` | Five named plants; child logs/PIDs in scratch, wrapper 0 only when all are killed |
| Go | Packaging control plants: `go run ./tools/mutations/main.go -group packaging -scratch "$SCRATCH"` | Twelve named tests must fail with exit 1 and the intended witness; wrapper exits 0 only when all twelve are killed, logs/PIDs in scratch |
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

## Internal message-key slice

K3 S1 adds an internal purpose-4 sibling key capability and canonical waggle
key IDs. It has no production constructor or dispatch; `sign_message` remains
unsupported. Surface A and ordinary key APIs retain purpose-1 identity keys.
S2 adds an internal fixed-body purpose-5 issuer and schema-2 certification state,
described below. Native message admission and publication qualification remain
later K3 slices.

The byte/crypto helper is pinned to waggle
`9b42338b8a57d12a21da4db4375b269deacdd6bf`
(`v0.0.0-20261024213811-9b42338b8a57`). It shares the existing registrar pin;
the shared time provider requires `golang.org/x/sys v0.38.0`.

| Tool | Exact entry point | Evidence |
| --- | --- | --- |
| Go | `go test ./internal/keymaker -run '^TestMsg' -count=1` | Independent static SLIP-0010 fixtures, binding/custody guards and production boundary controls; task scratch logs |
| Mutation tool | `go run ./tools/mutations/main.go -group message-key -scratch "$SCRATCH"` | Four overlay controls with named failing tests, child PIDs and logs below the supplied task scratch directory |

`internal/keymaker/testdata/message-key.json` records the pinned upstream
SLIP-0010 Python reference, its hash, the independent Ed25519 backend and public
test seed. The three custom purpose tuples are reference-generated goldens,
checked after all 12 committed published SLIP nodes matched the reference.
They are not claimed to be published SLIP vectors. Tests read static fixtures;
no Python dependency or fixture-generation code enters the production daemon.

## Internal certification state

S2 implements the internal fixed-body purpose-5 issuer, strict schema-2
migration/floor checks, immutable hashed artifacts, durable intent/prepared/issued
phases and offline exact-outcome recovery. The state budget includes original
artifacts and recovery snapshots; admission reserves transition/proof bytes and
journal headroom before writing an intent. Count or byte exhaustion applies
backpressure without evicting history. Every pending transaction remains fenced.
The [artifact codec reference](docs/message-state-codec.md) publishes the exact
typed intent, candidate effect, resolution and migration formats for review.

There is no production constructor, issuance trigger, administration CLI,
publisher or activation transition. An issued candidate never becomes current;
message authority selection stays `key_not_enrolled`. Reconciliation holds the
exclusive state lock, has no signing dependency, restores only exact retained
committed bytes, and refuses unknown outcomes without discarding evidence.
Only known pre-issuance transactions may abort; issued candidates retain pending.

PENDING before production: independently enforced reader-floor deployment,
protected root policy, real multi-UID integration, qualified Now/W and uncertainty
mapping, provider/audit collection outside generation windows with bounded
original authority through persistence, and owner-registry/WC1 evidence. S4 must
recheck publication slots and `VerifyJournal` inputs against its accepted
freshness profile. S2 rejects nonempty publication slots and current pointers;
qualified-T1 renewal/activation and message-result release require later slices.
No S4 module pin or production fake evidence source is introduced.

| Tool | Exact entry point | Evidence |
| --- | --- | --- |
| Go | `go test ./internal/keymaker -run '^TestMsg' -count=1 -timeout=120s` | Issuer/profile/status refusals, original key controls, migration, graph/budget checks and real-store recovery |
| Go | `go test ./internal/keymaker -run '^TestMsg(NativeCapacityCommitAfterRefusal|CapacityCommitAfterRefusal)$' -count=1 -timeout=120s` | Real 256 MiB retained-history boundary, last-fitting positive controls, unchanged journal on refusal and clean restart; native accounting covers the intent/effect persistence pair |
| Go race detector | `go test -race ./internal/keymaker -run '^TestMsg(ConcurrentCertification|V27RenewalRestart|CrashMatrix|JournalUncertainty)$' -count=1 -timeout=120s` | Deterministic barriers and injected process/journal interruptions; does not simulate hardware power loss |
| Mutation tool | `go run ./tools/mutations/main.go -group message-state -scratch "$SCRATCH"` | Eight named expected-red controls, child exits/PIDs and overlay logs under private scratch; reconciliation control checks signer dependency exclusion |
| Go | `go mod graph`; `go mod verify`; `go vet ./internal/keymaker ./cmd/keymaker ./tools/mutations` | Module graph, checksum and affected static validation; capture logs in private scratch |

## Registrar dependency

The registration proof format, enrollment schema, publisher verification,
registry snapshot loader and name rules belong to
`github.com/relux-works/swarma-registrar`. The dependency is pinned
to reviewed main revision `5f44ebf3f788`
(`v0.0.0-20261023164451-5f44ebf3f788`). Keymaker supplies caller-side trust,
persistence and local authorization; it does not maintain a second loader.

Any registrar API or behavior change requires a separate reviewed pull request
there and must land on its main first. Raise this dependency only in an explicit
pin-bump commit here: run `go get github.com/relux-works/swarma-registrar@<full-commit-id>`,
review and commit both `go.mod` and `go.sum`, update this pin, and run the affected
enrollment tests against that exact revision. A branch name or an API inventory
check is not behavior approval.

## Registration helper configuration and validation

An optional `registration_helper` object in the protected daemon configuration
contains exactly:

```json
{
  "names": {"purpose":"host-registration","product":"sample","project":"core","agent":"station-a"},
  "enrollment_config": "/etc/swarma-keymaker/enrollment-pins.json",
  "approval_file": "/etc/swarma-keymaker/enrollment-approval.json"
}
```

Names resolve once through the configured registry to purpose 2. No request can
select a path or key. Omitting this object leaves the helper unavailable while
surface A and other control methods retain their authority rules. The existing
`OperatorReconciler` supplies a public startup challenge; status output reports
it. After independent freshness reconciliation and protected approval publication,
SIGHUP retries enrollment loading with that same challenge. A failed reload fences
only helper authority. The operator reconciliation command described above
provides independent freshness approval; the service never bootstraps enrollment.
Reload prepares all file/Git validation outside the enrollment write barrier,
then publishes one complete snapshot or failure fence. New helper admissions
wait cancellably during reload and return `request_deadline_exceeded` when their
request budget ends, releasing the shared generation and Store locks.

Trusted UTC uses the public `swarma-credential-broker/timeconf` provider pinned to
`3924ab6e811b5512ad8763a392c2c88abcdd1b2c`. `CollectorEntry` is the first main
statement. The daemon's root-owned protected configuration may embed `time_policy`
using the provider's exact [policy schema](https://github.com/relux-works/swarma-credential-broker/blob/3924ab6e811b5512ad8763a392c2c88abcdd1b2c/docs/time-policy.md).
Enrollment pin configuration uses the same optional member for operator approval
time. Invalid policy is rejected during configuration decoding. Missing/off policy
or unavailable evidence refuses `clock_untrusted` before service readiness. There is no source flag, environment override,
or kernel synchronization fallback. Policy changes require a new process.

Startup samples fresh confidence before time decisions. The daemon shares that
provider between helper and audit; enrollment approvals retain one provider across
their initial and later publication/consumption checks. Every helper decision and
post-audit release samples again. The returned uncertainty narrows key/proof
validity and the exclusive authority endpoint is retained for each prepared proof
through persistence and live release, including same-ID retry preparation. Reauthorization
checks current enrollment without renewing that grant.
Missing audit confidence retains section11's null-time/unknown behavior. Request
budgets, rate limiting and the independent CLOCK_BOOTTIME approval TTL use elapsed
time; they never establish UTC confidence.

Real host provider, NTS inventory, collector isolation and storage latency
qualification remain PENDING. Durable decision-bound/hold continuity across process
replacement also remains an activation integration gate under the shared policy;
this adapter adds fresh start sampling and within-process holds, not durable hold
storage. Restart still requires independently reconciled enrollment. Root-owned
generation qualification and the operator-act adapter remain activation gates.

| Tool | Purpose / exact command | Artifacts |
| --- | --- | --- |
| Go tests | `GOPROXY=off go test -race ./internal/keymaker -run 'Test(Helper|DaemonHelper|Native|CustodyUnavailable|Master|PublishedDerivation|Registry|Production|RefusalVectors)' -count=1 -p=1` | Task scratch logs; generated fixture keys only |
| Go tests | `GOPROXY=off go test -race ./internal/registration -count=1 -p=1` and `GOPROXY=off go test -race ./internal/enrollment -run 'Test(WithAuthorized|HelperVectors|AuthorityCheckOrder)' -count=1 -p=1` | Task scratch logs |
| Mutation tool | `GOPROXY=off go run ./tools/mutations/main.go -group helper -scratch "$SCRATCH"` | Scratch Go overlays, exact test exits and child PIDs |
| Go vet / gofmt | `go vet ./internal/keymaker ./internal/control ./internal/enrollment ./internal/registration ./cmd/keymaker ./cmd/keymaker-window ./tools/mutations`; `gofmt -l internal/keymaker/*.go internal/enrollment/*.go internal/registration/*.go internal/control/*.go tools/mutations/main.go` | Diagnostics to task scratch |
| Multi-UID compiler | `go test -c -tags multiuid -o "$SCRATCH/multiuid.test" ./internal/keymaker` | Test binary only; reviewer runs live window |

The existing compiled window runner selects `^TestMultiUID`, including helper
cases. Without configured provisioning it still returns exact PENDING/status 3;
compilation does not qualify real foreign-UID execution. Follow the existing
fixture HOME/no SSH_AUTH_SOCK isolation and keep artifacts in task scratch.


## Offline release handoff

Set SOURCE to a clean checkout at the full reviewed COMMIT and VERSION to its
`keymaker version` string. Set BUNDLE to a new directory under an existing
operator-controlled scratch parent, outside SOURCE and system paths. CONFIG and
REGISTRY are regular operator-supplied files. MODULE_CACHE is a prepopulated Go
module cache (locate it with `go env GOMODCACHE`) containing the exact committed
dependency versions. The assembler uses its download cache as a read-only file
proxy, with no network fallback; writable child caches use private TMPDIR scratch. The
[packaging contract](packaging/README.md) documents every member and refusal.

The Linux assembler requires `openat2` and Landlock ABI 3 or later. It trusts
no repository-local configuration to authorize program execution: filters
selected for tracked paths are refused explicitly; cleanliness compares raw file
hashes and index metadata without Git conversion programs. Hooks, fsmonitor,
textconv and external diff are disabled or excluded by the selected commands.
Every Git child has a private scratch write boundary. Git alone may also open a
pinned, verified `/dev/null` character device (major 1, minor 3) for read/write;
that inode gets no truncate, create, remove or rename rights. Builds have no
such exception. Trusted installed Git/Go executables remain prerequisites.

The target parent must be private to its owner, or sticky and owned by the
caller or root. Output uses pinned directory handles and exclusive files. An
adopted root must be empty, mode 0700 and owned by the caller. Failure cleanup
checks each recorded creation's device/inode through its pinned parent handle,
never recursively deletes unknown contents, and retains the target directory.
Child-created cache/binary files cannot be attributed by parent-side creation
handles: private `release-build-*` scratch under TMPDIR is retained and its path
is printed. Use a private, disposable TMPDIR, then dispose of it separately after
reviewing the bundle. The tool removes only its recorded source/scratch objects;
unknown entries, including actor substitutions, remain untouched. VERSION.json
records the full commit and independently verified exported Git tree hash.

After assembly, verify SHA256SUMS with the exact command in the Tools table
before handing files to the owner. Follow only
[specification section 12.1](spec/keymaker.md#121-explicit-preflight-and-dynamic-service-ids)
for protected staging and the root step. Supply `-enrollment "$ENROLLMENT_CONFIG"`
to include the validated local enrollment pin configuration as enrollment.json;
omission leaves it out. Parsing does not qualify installed ownership, registry
signatures, snapshot freshness or operator reconciliation.
The control socket uses the landed native schema. Production activation
remains gated; this tool does not install or run a service.
