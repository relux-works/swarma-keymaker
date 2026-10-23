# Registration proof builder

This pure package builds Ed25519 registration/1 proofs from the public result of
`enrollment.Authorize`. It imports neither `internal/keymaker` nor
`internal/control`. The daemon calls it under its generation, binding and enrollment barriers.

```go
type Input struct {
    Name     string
    Audience string
    Enrolled enrollment.EnrolledKey
}
type TrustedClock interface {
    Now(context.Context) (time.Time, bool)
}
type Signer interface {
    Sign(context.Context, []byte) ([]byte, Code)
}
func New(clock TrustedClock, random io.Reader, signer Signer) (*Builder, error)
func (b *Builder) Build(ctx context.Context, in Input) (*Proof, Code)
func (p *Proof) Recheck(ctx context.Context) Code
func (p *Proof) Envelope() []byte
```

Only name and audience come from the request. The caller must obtain `Enrolled`
from current trusted authorization; it is not a request field or a substitute
for authorization. No request body, key selector, timestamp, TTL, nonce or signing
bytes enter this API. The signer must use the admitted purpose-2 key, honor
cancellation and support concurrent calls. The entropy Reader must be a bounded
trusted CSPRNG adapter; deterministic Readers are test fixtures only.

The pinned registrar `registration.Build` constructs the typed body and returns
its canonical bytes and registration/1 signing preimage. `Check` runs before
signing, then `Assemble` and `Verify` enforce output encoding, identity and strict
signature verification. Keymaker supplies a fresh 16-byte nonce, trusted UTC
whole-second issue time and exactly 120 seconds of lifetime. It does not define
a parallel schema, name grammar, codec, signature encoder or point validator.
Only the local Ed25519 algorithm policy uses a key prefix check; registrar still
owns format and cryptographic validation.

Both issue and release time must be in the key's half-open window, without skew.
A proof cannot be released at or after expiry. The Builder checks again after
signing and `Recheck` samples its clock anew. It strips Go monotonic metadata to
detect wall-clock rollback, including a backwards nanosecond. Clock health loss
or rollback permanently fences that Builder and all its proofs. Source recovery
alone does not clear the fence; the owner must establish fresh trusted authority.
Concurrent builds serialize clock sampling and entropy reads. Cancellation does
not turn into clock failure.

`Envelope` returns a byte copy and grants no release authority. Integration must
revalidate binding, generation and enrollment and call `Recheck` **inside the
final authority barrier after durable audit and immediately before writing**.
This package cannot make a later write atomic, enforce current registry state,
retain same-ID results or reserve registrar replay state. Those belong to the daemon integration in `internal/keymaker/registration.go`. Same-ID retry must retain the original proof rather
than call Build again; each fresh Build deliberately consumes independent entropy.

## Approved custody refusal and typed failures

Every failed Build returns a nil proof. Local clock, entropy, window, expiry,
audience and algorithm refusals use existing helper spellings. A canceled call
returns `request_deadline_exceeded`. Registrar typed failures retain their exact
spelling, including `name_invalid`; they are not renamed to
`name_not_permitted` or `request_malformed`.

Self-check failures retain `registration_signature_invalid`,
`registration_id_mismatch` or `registration_malformed`. With healthy dependencies
these are internal-consistency failures, not ordinary caller refusals; no envelope
escapes. Signer failures propagate the existing section-15 Code supplied by the
trusted adapter without diagnostics or an invented generic signing code.
`TestSigningFailures/typed-error` exercises `sign_key_mismatch`, with a valid
signing control. The curator-approved core custody refusal is
`custody_unavailable` with `retryable=false`. Only local audit records its cause
(`closed`, `unloaded` or `protection_failed`); the response never distinguishes
these causes.
It is not mapped to `audit_unavailable`.

## Vector coverage

`vector-coverage.json` explicitly assigns every one of the pinned module's 166
registration-1 rows to a tested stage or an exclusion. Tests locate the exact
module locally with network access disabled. No fixture is downloaded, altered,
re-signed or replaced by a synthetic enrollment. Public fixture signatures are
retained for round trips; builder tests generate independent test-only keys.

| Stage | Rows | Executed claim |
| --- | ---: | --- |
| verify | 76 negatives | Unchanged published proof bytes receive their exact registrar stateless verification code, paired with the published positive control. Includes P-256 dependency validation and the proof-size case R89. |
| name | 8 negatives | Verify then Check rejects the published name under its configured audience; the builder rejects that name/audience before signing with its own fixture key. |
| window | 5 negatives | Release guard uses original verified issue time and a registrar-parsed signed key window; paired published window controls pass. This does not admit a registry record or host. |
| audience | 2 negatives | Builder rejects unequal request/configured audiences before signing, with published-name positive controls. |
| expiry | 2 negatives | Helper release guard rejects the published late time exactly; a local one-nanosecond-before-expiry control passes. |
| roundtrip | 30 positives | PR1 through PR30 Verify, Check, Build, Assemble and Verify while preserving the published preimage and signature. Receiver admission/state is not exercised. |
| excluded | 43 negatives | Listed below with the pure-layer scope clause; these do not run as passing or skipped conformance subtests. |

P-256 fixture verification qualifies the dependency, not this Ed25519-only
builder. `TestEd25519Only` verifies the published P-256 control, then rejects it
locally with `enrollment_unsupported`, beside a valid Ed25519 build. PR11's
receiver expiry-skew acceptance is intentionally not a helper release control:
the task requires exact expiry without skew. Likewise positive receiver HTTP,
clock/restart, rate/replay, registry, audit and JWT scenarios qualify only their
proof bytes in this package.

| Excluded rows | Reason and scope clause |
| --- | --- |
| R83, R84, R85, R86, R87, R88, R99, R105, R111, R129 | Receiver nonce consumption/reservation or rate accounting; no receiver state or native request-ID store in this pure layer. |
| R95, R96, R97, R106, R128 | Receiver JWT signer generation or audit availability/precedence; helper signer failures and release checks are tested separately. |
| R90, R91, R92, R93, R114, R136, R137 | HTTP routing, media type or content encoding is outside proof construction/self-verification. |
| R62, R63, R67, R73, R74, R75, R94, R98, R123 | Registry/key membership, host state or name membership needs current enrollment authority; pure builder receives an already-authorized key. |
| R78, R79, R80, R81, R124, R125, R126, R127, R130, R131, R132, R133 | Receiver startup barrier, skew allowance or process clock-health policy; builder clock_untrusted and exact expiry are separate narrower local contracts. |

The scope clauses above follow the assignment's pure-layer boundary: Input
already contains an authorized EnrolledKey; this layer owns construction and
self-verification, not registrar HTTP admission or daemon authority.

`TestHelperVectors` runs the original Keymaker `helper-name-slash`,
`helper-mxid-length` and `helper-wrong-audience` rows and their declared controls
as name/audience projections. `TestKeyWindow`, `TestReleaseExpiry` and
`TestPostSigningRefusals` add local key-window and expiry boundary cases with
valid controls. No UID, executable or generation qualification is claimed.
The remaining helper rows are out of this pure-layer contract:
`helper-uid-absent`, `helper-name-not-mapped`, `helper-enrollment-missing`,
`helper-enrollment-unverified`, `helper-enrollment-revoked`, `helper-map-required`,
`helper-key-unenrolled`, `helper-reused-uid`,
`helper-revoked-binding-fresh-connection`, `helper-missing-binding`,
`helper-wrong-executable`, `helper-undeterminable-executable`, and
`helper-matching-executable`. They require the enrollment/peer/binding authority
which the assignment explicitly keeps outside this package.

The assignment contains no formal attack-surface table (brief gap). The vector
map is stage coverage, not a claim that each dependency vector has an independent
local narrowing mutant. Existing reviewer tests elsewhere are unchanged.

## Narrow validation and mutation controls

Use the root README's scratch/isolation instructions, an empty fixture HOME and
no inherited SSH_AUTH_SOCK. Only generated in-memory test keys are used here;
no SSH tools or host keys are needed. Required module files must already be in
the local cache. Commands run from the repository root:

```sh
go test ./internal/registration -count=1
GOMAXPROCS=2 go test -race ./internal/registration -count=1 -p=1
go vet ./internal/registration ./tools/mutations
gofmt -l internal/registration/*.go tools/mutations/main.go
go run ./tools/mutations/main.go -group registration -scratch "$SCRATCH"
```

The optional registration group extends the existing overlay tool; its default
core group is unchanged. It records each child PID, actual exit and log in
scratch. A plant counts as killed only for test exit 1 with both the named
failure and the expected behavioral witness. A compile/setup failure does not
count. All five controls were killed; no survivors are claimed.

| Mutant | Gate narrowed to | Named failing test | Result |
| --- | --- | --- | --- |
| registration-nonce-reuse | Fresh per-build entropy rather than a repeated fixed nonce | TestFreshNonce | Killed, child exit 1 |
| registration-caller-iat | Trusted clock alone chooses iat; added caller selector is actually used by plant | TestNoCallerTime | Killed, child exit 1 |
| registration-release-time | Release uses fresh time rather than saved issue time for window and expiry | TestReleaseExpiry; TestKeyWindow/release-at-end | Killed, child exit 1 |
| registration-self-verify | Invalid 64-byte signer output cannot escape as a proof | TestSigningFailures/bad-signature | Killed, child exit 1 |
| registration-wrong-preimage | Signer receives exactly the registrar-produced registration/1 preimage | TestSigningInput | Killed, child exit 1 |

These are bounded witnesses for the named gates, not exhaustive mutation
coverage. `TestSSHSIGDomainSeparation` separately checks both signature directions
against one standard SSHSIG-v1 git preimage, with positive controls; it does not
qualify the live SSH-agent transport. Entropy short/error reads, clock rollback
and health loss, signer errors, failed self-checks, cancellation, delayed-sign
expiry and concurrent use have direct negative/positive tests.

Durable helper retry uses `Builder.Restore` to verify retained bytes and current
key/name/audience/window/expiry without entropy or signing. `Builder.Time` supplies
the same rollback-detecting time source to the enrollment authorization barrier.
`TestRestoreRetained` covers refusal/control boundaries and a fresh clock owner
that observes a retained proof issued in the future.
