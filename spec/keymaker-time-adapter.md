# Qualified-time adapter slices

This plan adopts the broker's [qualified-time contract](https://github.com/relux-works/swarma-credential-broker/blob/a1c69eb9ed6576d3b060dfb3e697de2fd2180f0d/docs/time-contract.md)
and [shared policy](https://github.com/relux-works/swarma-credential-broker/blob/a1c69eb9ed6576d3b060dfb3e697de2fd2180f0d/docs/time-policy.md).
**Activation stays closed.** Slice A tightens existing checks; it does not
implement the eleven-fact receipt or qualify time consumption.

The `timeconf` package tree at that contract commit is byte-identical to our
`3924ab6e811b5512ad8763a392c2c88abcdd1b2c` module pin (tree
`c5dc4922ceefb9322773022dd65d675dbfd44191`), so no dependency change is needed.
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
