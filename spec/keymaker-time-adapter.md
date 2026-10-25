# Qualified-time adapter slices

This plan adopts the broker's [qualified-time contract](https://github.com/relux-works/swarma-credential-broker/blob/a1c69eb9ed6576d3b060dfb3e697de2fd2180f0d/docs/time-contract.md)
and [shared policy](https://github.com/relux-works/swarma-credential-broker/blob/a1c69eb9ed6576d3b060dfb3e697de2fd2180f0d/docs/time-policy.md).
**Activation stays closed.** Slice A tightens existing checks; it does not
implement the eleven-fact receipt or qualify time consumption.

The `timeconf` package tree at that contract commit is byte-identical to our
`3924ab6e811b5512ad8763a392c2c88abcdd1b2c` module pin (tree
`c5dc4922ceefb9322773022dd65d675dbfd44191`), so slice A needed no dependency change.
The shipped `Sample`/`StartSample` API supplies O, delta, A, boot and confidence,
not authenticated receipts, provider-owned durable W/hold/in-flight settlement,
rollback witness or end-to-end bounded consumption. An ordinary sample must
never be represented as that missing receipt.

## Clause to path and slice

| Contract clause | Keymaker path and present limit | Slice |
| --- | --- | --- |
| Facts and binding: `[L,U]=[O-delta,O+delta]`, `U<A`; known ns values, no overflow or clock fallback | `internal/timeconfidence.Bounds`, `Valid`, `Start`, `Sample`; all existing callers inherit the stricter shape predicate. This does not validate an enrolled identity or current boot. | A |
| Interval-preserving projections: floor L and exclusive A, ceil U and retained upper floors; require original and converted predicates | `timeconfidence.ProjectSeconds` supplies pure L/U/A arithmetic over the original sample. G4 retained-floor projection and live K3 wiring await the complete receipt mapping; the helper has no serving caller. | A arithmetic; C integration |
| Final windows: enrollment preserves current delta/A | `internal/enrollment/approval_linux.go` carries provider delta (`time.Duration`) and A (`time.Time`) unchanged in `approvalInstant`; uses U for the current authority and approval-age comparisons, retaining same-boot BOOTTIME TTL. | A |
| Enrollment 600-second boundary: `D<=L_issue+600`, `U_current<D` | Existing `confirmed_utc_ns` remains O_issue, with unchanged bytes and semantics. Current U tightens its existing point-based age check, but a replacement process cannot recover L_issue. The 99/101/699 ns pair tests arithmetic only, not restart safety or activation. | A current-sample tightening; B durable issue bound |
| Exclusive authority on a retained registration proof | `internal/registration.Proof.validAt` compares current U to the original A; a later sample cannot extend that grant. This single tightening adds no receipt or continuity state. | A |
| Durable continuity: provider owns every consumed W, in-flight observation and hold, including failed operations; `L>max(W,J)` | Registration's volatile `last`/`fenced`, enrollment replay ledger and G4 `Plan.Watermark` cannot replace provider history. The 140 -> 200 +/-1 -> W=201 vector is arithmetic-only; no restore protection is claimed. | B |
| Native operation/challenge binding; unchanged consumer schemas | Registration native tuple and original argument digest; complete enrollment approval/challenge/ledger and configuration/state identity; provider challenge remains distinct. No new consumer field is added here. | B/C jointly reviewed profiles |
| Final C/F/generation/store/journal locks: collect before final window, one bounded handoff, local checks only | `internal/keymaker/audit.go`, `binding_commit.go`: today's append can collect under outer Store/generation locks **and** the journal gate. This is a known contract gap, not a compliant state. Merely moving collection before the journal gate leaves the outer-lock violation. Audit behavior is unchanged in A. | B |
| Receipt codec/authenticity and complete retained evidence; nanosecond and G4 views both pass | `message_attestation.go`, `message_state.go`, `message_verifier.go` currently project points/seconds without a qualified receipt. Pure projection arithmetic does not repair that gap. | C |
| Qualified full call/completion; original 250/1000/2000 ms budgets, fresh observation and current boot | Provider observation/settlement before final locks, original absolute operation deadline, qualified remaining-delay reserve in delta, no renewed budget or cached pass; subsequent local one-use handoff. No such capability exists in the current provider API. | B/C then activation |
| Emergency stop independent of time/store leaves | Preserve cancellation/stop dispatch without collecting, acquiring provider leaves or waiting on continuity storage; qualify indirect lock holders separately. Transactional revoke/unbind is not an already-qualified emergency path. | Activation |

## External inputs and gates

These record slice A's dependencies; B-1 below updates API availability.

**B: durable continuity and pre-window handoff.** The broker must publish and
implement its versioned durable begin/settle/recover API, including operation
association, W, in-flight/hold, boot transitions and immutable acknowledged
receipts. A deployment owner must choose the independent monotonic
`(generation, record_digest)` CAS authority, provision it outside **all**
provider/consumer/witness restore domains, and supply enforceable restore and
old-instance exclusions. The concrete store/witness transaction and recovery
design must be reviewed before implementation. A possible remote witness is
not a selected or qualified substitute for local CAS. Keymaker/broker must
jointly publish the native identity profiles and the durable issue delta,
exclusive deadline and receipt-reference representation; the closed approval
format is unchanged here. A bounded pre-window handoff/receipt checkable without
provider calls is required to remove collection from audit's outer/final locks.
Its qualification must cover original deadlines, one-use scope/challenge, boot,
remaining delay and final local work, with no callback or renewed allowance.

**C: K3 receipt.** The broker or registry owner must publish the authenticated
receipt API and closed codec/validator with complete original evidence and
retained descriptors, authority/root/adapter/policy bindings, protected native
operation profiles, challenge, current boot and confirmed continuity. Keymaker
and registry consumers must accept a complete interval-aware mapping into
existing G4/K3 facts and floors. Keep original ns facts; ceil retained upper
floors and U, floor L and exclusive endpoints, reject nonrepresentable values,
and require both views. Do not infer W, availability or rollback safety from
point time or an unverified hash. Existing closed journals stay unchanged.

**Activation.** B and C must land and receive consumer review. The deployment
owner must qualify the independent witness and restore boundaries, protected
policy, native collector/executable closure (`CollectorEntry` first), selected
NTS evidence and authdata where required. Whole-subtree termination/fencing,
one absolute deadline over collection/storage/handoff, latency reserves,
current-boot transitions, fsync/CAS crash recovery and independently reachable
emergency stop all need native qualification. No passing arithmetic test or
configuration-only fixture supplies those inputs.

## Explicit pending qualification

The `qualifiedtime` build tag exposes four deliberately failing, never-skipped
rows: `TestQualifiedTimePendingEnrollmentIssueBound`,
`TestQualifiedTimePendingRegistrationContinuity`,
`TestQualifiedTimePendingAuditPreWindow`, and
`TestQualifiedTimePendingK3Receipt`. Each names its missing external input.
Run them explicitly using the README command and report their real nonzero
status as PENDING; ordinary unit-test success does not satisfy these gates.
Audit's under-lock sampling mutant is deferred with its implementation; no
killed mutant or impossible-under-lock construction is claimed for today's
known gap. Slice A adds no durable state, codec field or production activation.

## B-1: inactive consumer and fixture integration plan

This section updates the available B inputs against Keymaker `28b1c88` and
broker [`8cdea829b261e97908623376fe6857e9960fe877`](https://github.com/relux-works/swarma-credential-broker/blob/8cdea829b261e97908623376fe6857e9960fe877/docs/qualified-time-api.md).
It proposes implementation slices; this documentation change bumps no pin,
changes no codec and runs no fixture. Production activation remains closed.

**B-1a: dependency and containment.** Bump the broker module from `3924ab6` to
`8cdea82`, with tidy module metadata. Ordinary `Provider.Sample`/`StartSample`
remain available with their existing behavior. The added Linux API is a separate
`NewConsumer`/`ConsumeBeforePin` path: protected `Enrollment`, effective-policy
digest, original absolute `Deadline`, independently derived `OperationDigest`,
fresh `Challenge` and imported `JournalFloor`. The closed eleven-fact
`EncodeReceipt`/`DecodeReceipt` codec preserves decimal-string ns/generations;
decoding supplies structural validation, not authentication. Settlement retains
begin/hold/W, operation/challenge history, originals and exact receipt bytes.
Production construction installs only `ClosedWitness`; consumption gives typed
`ActivationRefusal`. `timeconftest` defaults to refusing stubs; its positive
`FixtureConsumer` implementation and `SetNextSample` require
`swarma_timeconf_fixture`. Its witness is in memory; its store must start empty.

Proposed `TestTimeconfFixtureDependencyPolicy` uses Go ASTs:

- Scan all repository Go files, including files excluded by platform/build tags,
  and unquote every import regardless of alias, blank or dot use. A
  `timeconftest` import requires an `_test.go` filename and a parsed build
  constraint that logically implies `swarma_timeconf_fixture`. Use
  `go/build/constraint`; setting that tag false must make the constraint
  unsatisfiable. Missing guards and `fixture-tag || other-tag` refuse.
- Check successful, non-test `go list -deps -compiled -json` graphs for default
  tags (`-tags= ./...`) and for `-tags=swarma_timeconf_fixture ./...`. Neither
  graph may import `timeconftest`. Inspect compiled broker sources in the default
  graph for fixture implementation/construction: the tag enables a bridge in `timeconf`
  even without importing `timeconftest`. The fixture tag is never an approved
  production/release tag. Graph-command errors fail the check.
- Prove each guard separately with isolated plants: aliased/blank application
  imports, a build-excluded application import, an unguarded test and an OR-guarded
  test must fail the named AST/constraint assertion; an identical properly
  guarded test import passes. Independently feed each graph guard a successful
  real graph containing an application import and require its dependency refusal.
  A private dependency copy with fixture construction compiled by default must
  fail default containment. Mutants omit excluded files, allow application/test
  imports, accept OR guards or omit graph/compiled-source enforcement. Each must
  fail its named control; compilation/setup failures do not kill these plants.

**B-1b: closed adapter seam.** Add a separate receipt-consumption seam beside
`internal/timeconfidence`'s ordinary sample helpers. Enrollment hooks are
`approvalSourceFor`, approval issue and recheck in `approval_linux.go`;
registration hooks are `Builder.Build`, `Recheck` and retained-proof
reauthorization in `internal/registration`; audit's future hook precedes the
outer C/F/generation/Store locks as well as the journal gate in
`audit.go`/`binding_commit.go`. Do not install a consumer into today's synchronous
`AuditClock.UTC` path: that retains the under-lock gap.

Production constructors continue selecting today's provider path through a
closed, code-owned gate, with no configuration, environment or public injection
switch. Tests alone select a separate fixture implementation from tagged
`_test.go` files and a protected test-owned empty root. An attempted qualified
consumption must never fall back to the ordinary provider. Independently bind
the actual operation, enrollment, challenge, boot and original deadline; neither
a caller-supplied digest nor `VerifyReceipt` authenticates them. Preserve the
original context and deadline across all stages: the broker cannot detect
replacement of both on an unconsumed request. No cached receipt or callback may
stand in for the missing final-lock handoff. The [QT-2c profiles](keymaker-qt2c-profile.md)
follow the [broker schema at unlanded 7294b7a](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-window-profile.md#5-final-admission-durable-use-and-recovery):
complete initial persistence/use-CAS admission and select protected exact
head/epoch/unused operation-window-slot revision under all final locks before
exactly one fixed, qualified suspend-aware monotonic read m, outside pure `VerifyWindow`; pass its captured value to
that check, followed by burn under retained admission. Here s is the original
receipt observation, no distinct pre-lock p is required (p=s), and T covers s
through the full endpoint. No provider call, `Clock` callback, `time.Now()` or other clock read
is allowed there. Preserve original boot/start/deadline, uncertainty bounds and
reserve: D/T/reserve cannot grow or be spent twice. The read-to-act span through
durable local commit of the act together with use state requires an independently
enforced bound or an act that itself honors the original deadline; otherwise
the handoff remains `handoff_unqualified` and activation stays closed.

Proposed tests `TestQualifiedTimeGateClosed` and
`TestQualifiedTimeFixtureRequestBinding` pair default typed refusal/current-path
selection with a tagged positive consume/codec path. Reject changed operation,
challenge, enrollment, expired original deadline, replay and fixture/production
domain substitution, without issuing a consumer artifact. Mutants open the gate,
fall back after consumption failure, trust decode alone, drop a binding or renew
the deadline/context. Preserve already-settled W when the caller later rejects.

### Four qualification rows

These are proposed fixture tests, not passing evidence. Keep all four existing
`TestQualifiedTimePending…` names and their deliberate failures until their full
qualification clauses are supplied; add separately named fixture-path tests.
Update dynamic PENDING inventories only to describe the actual remaining gaps.

| Existing PENDING row | B-1 executable fixture claim | Remaining qualification/input |
| --- | --- | --- |
| `TestQualifiedTimePendingRegistrationContinuity` | B-1c: real consumer settlement and codec, original proof grant, replay and lost-response W retention; mandatory J=140, O=200/delta=1 -> W=201, [170,172] refuses, [210,212] passes as a time control. | Independent durable rollback witness, provisioning/recovery and old-instance exclusions; accepted native registration profile and authenticated receipt mapping. Fixture files plus an in-memory witness do not qualify restore protection. |
| `TestQualifiedTimePendingEnrollmentIssueBound` | B-1d, conditional on codec acceptance: retain receipt-derived L_issue and D, reload the approval, enforce D<=L_issue+600 and U_current<D without renewing the bound. | Accepted approval encoding/migration and protected receipt/original retention; native enrollment identity/deadline mapping and authentication; qualified provider restart/rollback behavior. |
| `TestQualifiedTimePendingAuditPreWindow` | B-1b can check the closed gate and request construction; no final-window positive qualification test is available. | QT-2c authenticated one-use handoff: pure local verification without provider/clock calls; exactly one qualified suspend-aware read m outside that check after all final locks and initial persistence/use-CAS admission with exact unused revision selected, preserving original deadline/reserve and an enforced read-to-durable-act bound as specified in the QT-2c profiles. |
| `TestQualifiedTimePendingK3Receipt` | B-1b can round-trip the real receipt codec and reject malformed/domain-mismatched fixtures; this does not exercise a K3 receipt. | Slice C: authenticated receipt/original-evidence validator and protected profiles, current-boot/continuity checks, accepted interval-preserving G4/K3 mapping and unchanged closed journal formats. |

**B-1c: registration settlement fixtures**, after B-1b. Proposed
`TestQualifiedTimeFixtureRegistrationSettlement` exercises the table's vector
through the adapter/registration path, then replay and lost-reply refusal.
After a refusal, use a fresh registration caller with the same provider/history;
do not clear the existing builder's sticky fence to obtain the positive control.
`TestQualifiedTimeFixtureRegistrationGrant` pairs U just below the original A
with U at A in separate fixture histories, even if a later sample grants more
authority. Assert no proof on refusal and no W rollback after settlement or
caller failure. Mutants use O
instead of U for W, forget W after lost reply, admit L<=max(W,J), refresh the
original grant or reuse a consumed challenge. `SetNextSample` uses a distinct
synthetic qualified boot for each explicit sample; the backward-interval vector
therefore proves neither same-boot clock-step recovery nor native reboot safety.

**B-1d: durable enrollment fixtures**, after B-1b and codec acceptance. Persisting
the issue lower bound is a change to the closed version-1 `commandApproval`
codec in `reconcile_command_linux.go`; it needs acceptance before implementation.
The new version must represent exact ns L_issue, exclusive D and a protected
receipt reference/retention binding, preserving `confirmed_utc_ns` as O_issue.
Its exact versioned encoding, atomic publication and migration rules remain an
explicit joint codec decision. No automatic backfill can recover delta/L_issue
from version 1: legacy approvals keep today's path and never acquire qualified
status. Qualified reissue needs fresh approval; reload/retry must not renew D.

Proposed `TestQualifiedTimeFixtureEnrollmentIssueReload` reloads the consumer's
approval bytes while the fixture provider remains alive; `New` cannot reopen a
populated fixture store, so this is not a provider/process-restart qualification.
Use same-boot `Advance` controls for approval age, not successive
`SetNextSample` boots. In separate histories, pair U_current=D-1ns with U_current=D
and D=L_issue+600 with an excessive D. Reject absent,
malformed, overflowed or receipt-inconsistent issue bounds, another boot and
missing retained evidence. Assert no approval consumption/issuance on failure;
provider observation may still burn W. Mutants derive D from O_issue, reconstruct
it from the current sample, extend it after reload, ignore the strict boundary
or treat a receipt hash as authentication. Preserve the BOOTTIME cap and add
an increased-delta refusal paired with a narrower accepted interval.

**B-1e: review and inventory**, after B-1c/B-1d. Keep current production behavior,
all existing reviewer tests and the four broad PENDING gates. Bind each new test
and killed mutant to its fixture claim; do not count a setup error as a kill.
`TestQualifiedTimePendingInventory` must detect row-removal and skip mutants
through the inventory guard, paired with the unchanged four-row control.
No audit lock refactor or K3 serving integration is part of B-1.

### Inputs still required after B-1

QT-2c must provide the authenticated, bounded, one-use final-lock handoff.
Keymaker/broker owners must accept native operation/enrollment/registration
profiles, the durable approval codec/migration and receipt-reference/retention
mapping. Slice C still needs the enrolled owner authenticator, complete original
evidence/descriptors and interval-aware G4/K3 mapping; the new structural codec
and fixture verifier do not supply them. Production still needs a selected,
provisioned independent durable CAS authority outside every restore domain,
genesis/recovery/hold rules and enforceable old-instance exclusion. All native
activation inputs above remain: protected policy/authority, collector/executable
closure and selected NTS/authdata evidence, boot transitions, subtree termination
and fencing, original-deadline/remaining-delay qualification, fsync/CAS fault
recovery and independently reachable emergency stop. None is supplied by a
fixture pass or a pin bump.
