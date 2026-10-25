# Keymaker QT-2c final-window profiles

Status: **proposed consumer transitions; activation closed on Linux and macOS**.
This profile amends the final-window timing rule in the
[adapter plan](keymaker-time-adapter.md#b-1-inactive-consumer-and-fixture-integration-plan).
It supplies neither a handoff codec nor an accepting adapter. In particular,
`handoff_unqualified` below is an activation disposition in the proposed shared
handoff design, **not a new Keymaker public refusal code**.

The source contracts are the broker's
[time contract at a1c69eb](https://github.com/relux-works/swarma-credential-broker/blob/a1c69eb9ed6576d3b060dfb3e697de2fd2180f0d/docs/time-contract.md#final-issuance-enrollment-and-registration-windows)
and [provider API at 8cdea82](https://github.com/relux-works/swarma-credential-broker/blob/8cdea829b261e97908623376fe6857e9960fe877/docs/qualified-time-api.md),
and Keymaker's [budgets and audit](keymaker.md#10-process-sockets-and-resource-budgets),
[PC2 transaction](keymaker-pc2.md#3-participating-writers-and-durable-ordering) and
[G4 preimage/order rules](keymaker-authority-root.md#6-exact-manager-read-set-under-f).
The revised timing and use rules here are explicit consumer requirements;
they do not assert that the pinned broker contract already contains this amendment.
The documentation schema is [broker PR #28 at exact unlanded head 7294b7a](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-window-profile.md#profile-schema),
with its [handoff contract and N1–N3 controls](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff.md)
and [mandatory macOS binding](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff-macos.md).
These are source pins for this proposal, not a landed dependency or activation.
Field-per-row tables below resolve consumer requirements; the schema introduces
no broker or consumer wire members. Missing mechanisms are implementation gaps.

## Common admission and timing rule

Use option (d): a qualified protected original reader validates the authentic
retained settlement, complete originals and independent witness **before all
final locks**, then places immutable owned copies and a private commitment in
the trusted consumer process. The trust domain is one process on one host.
Neither a requester hash, raw receipt decoding nor a caller-supplied expected
operation is an authenticated anchor. Crossing that domain requires another
reviewed delivery profile; no Keymaker purpose or secret is borrowed.

Derive the operation, expected revision, challenge, boot and original start and
deadline independently from protected enrollment and the retained native intent.
A fresh challenge does not create a new logical operation. Native mutations
retain `(caller_uid,caller_generation,request_id)` and original canonical argument
digest; G4 additionally binds its pre-audit authority transaction identity.
Pin the reader/validator version, retained original closure and witness ancestry
outside locks. Missing originals, unqualified provenance, a known hold/step or
unknown provider continuity refuse. The admission qualification must exclude
or invalidate intervening provider authority/hold changes and original deletion;
a pure copied snapshot cannot detect an unobserved later storage change.

Before the sole read, complete initial persistence admission and consuming
use/CAS admission under **every final lock named for the selected window**;
select the independently current exact head/epoch and exact unused `QTUse/1`
revision for that original operation/window/slot. Even nonwaiting initial
admission after the read is forbidden. With that admission retained, the
adapter performs exactly one fixed qualified suspend-aware monotonic read m. It
passes that captured integer to pure `VerifyWindow`; the verifier reads no clock,
provider, callback, descriptor or ambient state and does no I/O or mutation.
The read is outside the verifier. There is no `Clock` injection or `time.Now()`
substitute. Startup/preparation captures are outside this one final-window read.
If a lock/revision/boot check fails, exit the window; recollection is unlocked.
An abandoned handoff cannot enter another window, even before a durable burn.

Use the schema's canonical `s` for the receipt's original elapsed observation
and `m` for the sole final capture. The former native final symbol `c` maps only
to m. This Keymaker profile requires no separate pre-lock capture p: set `p=s`;
do not infer a distinct p from m. `D` is the preserved exclusive local deadline;
`T` is the finite positive original allowance **from s through the full endpoint**,
never a newly computed remainder. `f` is the enforced positive bound from m
through durable act/use commit; `epsilon>=0` is the qualified mapping/rate/error
allowance. In checked same-boot/domain integer nanoseconds require
`m>=p>=s`, `T>0`, `f>0`, `m-s+f+epsilon<=T` and **`m+f+epsilon<D`**.
Equality at D refuses.
For intersecting deadlines, use the earliest; retain each original start and
limit independently. A lock acquisition, retry, new receipt or recovery cannot
restart any of them. `T` is not a second operation budget.

Keep the original `[L,U]=[O-delta,O+delta]`, `U<A`, `L>max(prior_W,J)` and all
narrower consumer authority/expiry predicates. Total delta, including the
pre-reserved delay/rate/mapping allowance, is at most **1.5 seconds**, or the
stricter effective policy cap. Do not advance O, shrink delta, increase D/T or
increase/reuse the reserve. Elapsed time consumes its already reserved allowance;
adding the same reserve to delta again or allocating it afresh to a nested window
is forbidden. Distinct windows need distinct newly settled evidence/challenges,
while their deadlines remain constrained by the same original operation.

The final read detects pre-admission delay. It does **not** detect a later pause.
A qualification must enforce f across verification, use-state writes, rotation,
GC/preemption, page faults, suspend, all file/namespace barriers and commit.
Alternatively the act primitive itself must enforce the original deadline through
that durable endpoint. A context cancellation, timer flag, nonblocking lock,
watchdog, average latency or post-sync suppression of a late response proves
neither. There is currently no such qualified primitive for either profile:
**both are `handoff_unqualified` on both OSes**. The specification of f is an
activation gate, not permission to fill in a measured percentile as a hard bound.

## Window A: audit append

An audit append consumes this window only when it claims qualified time. The
legacy unknown-time audit path remains as specified in [base §11](keymaker.md#11-audit-and-fail-closed-recovery);
it cannot serve as a qualified-time fallback for an authorized act.

| Property | Audit profile A |
| --- | --- |
| Final locks | `Journal.mu` audit serialization; on generation-authorized calls, the shared source data lock and separate in-process generation gate, `C_Store` (`Store.mu`) and, for enrollment-authorized helper calls, `C_enrollment` (`Authority.mu` read serialization) remain held. The generation reader first [acquires shared data](https://github.com/relux-works/swarma-user-manager/blob/505fb9f55a6d4f3f71db49e5037cd863679a3e41/tools/genjournal/secure_linux.go#L191), [starts the original 250 ms window](https://github.com/relux-works/swarma-user-manager/blob/505fb9f55a6d4f3f71db49e5037cd863679a3e41/tools/genjournal/secure_linux.go#L195), then [releases the shared source gate](https://github.com/relux-works/swarma-user-manager/blob/505fb9f55a6d4f3f71db49e5037cd863679a3e41/tools/genjournal/secure_linux.go#L196), before the callback -> Store -> enrollment -> audit -> F chain. The separate in-process generation gate remains held; do not reacquire or upgrade the shared source gate. For a G4 constituent append, acquire audit before terminal `F_auth` and retain all of them; never take audit beneath F. A standalone health/refusal append takes only its actual journal gate and grants no generation or root authority. |
| Original budget | The caller's **remaining** original deadline: a generation reader's data/final-handoff limit is at most 250 ms from its original data-window start; a native operation is at most its original `timeout_ms` (1..2000 ms from completed frame), additionally capped by 2 seconds. Audit gets no new 250 ms or 2-second timer. If an enclosing manager operation applies, retain its original 1000 ms writer and send-start+2000 ms observation limits too; this does not permit an under-F daemon RPC. An unbounded background `Append` is not a qualified window. |
| Read point | After all applicable outer locks and the journal gate (and F for G4) have been admitted, with initial persistence and consuming use/CAS admission complete and exact protected head/epoch, audit tail/binding revision, immutable frame/rotation reservation and unused `QTUse/1` revision for the operation/window/slot selected before m. Then take m, perform pure local verification and only afterward burn under the retained admission. No rotation, write or consumption precedes this read. |
| Post-read mechanism | `handoff_unqualified`: today's checked context then blocking `Write`/`Sync` cannot enforce f. Qualification must cover the full append, any sealed rotation/new-segment namespace durability, and use-state commit. |
| Deadline endpoint | Complete checked frame append and its file durability; required rotation seal, new segment and parent-directory durability; the same transaction's durable A-use state. The already locked tail advances only after these succeed. Admission, buffered bytes and return/acknowledgement are not the endpoint. For a nested G4 append this proves only A; it cannot authorize root publication. |
| Uncertainty | Original total delta <=1.5 s, narrower policy if set; original U<A and floor predicates still pass. |
| Public refusals | Clean lock contention `busy` where the existing caller exposes it; clean original-deadline expiry `request_deadline_exceeded`; untrusted/unqualified time `clock_untrusted`; unknown/failed audit or use-state durability `audit_unavailable`, with admission closed. Preserve the enclosing operation's more precise existing authority refusal. No shared handoff reason is emitted as a new public code. |

Today's clock calls inside audit locks (`internal/keymaker/audit.go:422/424`
and `internal/keymaker/audit_gate.go:24`), plus the under-lock clock paths in
registration and generation, remain the known slice-B gap and must be removed
before any activation; this profile does not fix them. `binding_commit.go`
still calls the under-lock audit path. `authority_audit_prep.go` only prepares
exact bytes; it acquires/consumes no live reservation or use capability.

## Window P: binding and authority-root publication

This profile covers the recoverable multi-file transaction, including its
constituent binding audit and root publication. A standalone legacy binding
snapshot is not a PC2 root and must not be advertised as one.

| Property | Publication profile P |
| --- | --- |
| Final locks | Source generation gate then data; `C_Store` then `C_enrollment` commit serialization; audit serialization already acquired **before** terminal `F_auth`. On reader entry, acquire shared data, start the original 250 ms window, then release the shared source gate before the callback -> Store -> enrollment -> audit -> F chain, as pinned in A. Keep the separate in-process generation gate held and the shared source gate's no-reacquire/no-upgrade rule. F is distinct from package `F_pkg`; no C/audit acquisition, RPC, provider or implicit locking read beneath F. A root tool must join the same reviewed C/F exclusion protocol; lacking it refuses. |
| Original budget | Use the original enclosing operation deadline, intersected with any <=250 ms reader data/final-handoff window and native <=2 s/`timeout_ms` deadline. A manager writer's own 1000 ms attempt/append/finish and send-start+2000 ms observation limits stay at their original starts when applicable; they are not generic Keymaker publication timers. There is **`undefined` standalone root-tool timing budget** (admission refuses): until its owning operation supplies and qualifies one, it is `handoff_unqualified`, not assigned 1000 ms by analogy. |
| Read point | Once the entire C/audit/F chain is held and exact current root, guard, floor, tail and reservations match the unlocked preparation; with initial persistence and consuming use/CAS admission complete and the exact unused `QTUse/1` revision for the operation/window/slot selected under protected head/epoch before m; before any P-use burn/authority intent/live write. Take m, pass it to the pure check, then burn under retained admission; all necessary final metadata operations remain in the bound f. |
| Post-read mechanism | `handoff_unqualified`: neither Linux's nor macOS's ordinary multi-file sync/rename sequence enforces a durable deadline. Must qualify the entire intent/participants/audit/root/use/cleanup span or select a deadline-enforcing transaction primitive. |
| Deadline endpoint | Checked full intent write, file sync, close, parent sync before live changes; exact participants and audit durable; exact new root file write/sync/close, same-filesystem rename and root directory sync; all linked guards validated; committed P-use outcome durable; exact intent cleanup and its parent directory sync. Only this complete local transaction may open authority. Independent root-link custody remains an additional pre-release obligation, within any still-applicable release deadline. |
| Uncertainty | Original total delta <=1.5 s and stricter policy; do not reuse A's reserve/evidence for P. Preparing frames does not consume A; an actual nested A and P each have their own challenge/use slot, with their reserved work accounted once and no deadline extension. |
| Public refusals | Clean contention `busy`, clean expiry `request_deadline_exceeded`, unqualified time `clock_untrusted`, possible/unknown root/audit/use write or cleanup `audit_unavailable`. Retain existing generation/enrollment/custody/revocation/capacity refusals; no new public member. |

The [G4 DAG](keymaker-authority-root.md) fixes the authority transaction identity
from base root, next revision and candidate body **before audit**. Do not key use
by a final root hash that itself depends on audit, or feed H into the body to
manufacture that key. Frame preparation can reserve A/P in advance outside locks;
it cannot assert that either final window has been consumed. If nested A needs
its own read, that is exactly one read for A, not a second P read; P's original
post-read bound includes that entire nested span. Failure of either window holds
the parent transaction. A pre-persisted audit append is not a durable P commit.

## Versioned consumer use transition

Propose semantic transition **`QTUse/1`**, a new versioned consumer transition
requiring separate consumer/code/format review before implementation. It has no
wire encoding in this change. The owning transaction's next reviewed version
must carry and retain these states with its existing act/intent, rather than an
independently acknowledged side ledger. Existing audit records, G4 intent/root,
S2 snapshots, native request/result and eleven-fact receipt remain closed and
unchanged. There is no spare H field in any of them. In particular, the audit
request ID remains `binding:<revision>` and its payload digest keeps its current
body preimage; no reinterpretation or hidden filename field is allowed.

The following are exact semantic keys, compared as tuples, not new hash recipes:

| Window | Key and expected revision | Consumer-owned durable home in the proposed next transaction version |
| --- | --- | --- |
| A within G4 | `(authority_incarnation, authority_transaction_id, binding_revision, A, audit_slot)`; expected serialized predecessor `(seq,hash)` and binding version `binding_revision-1`; `audit_slot` is the selected frame's ordinal in that exact prepared transaction. | Owning authority transaction's retained use state plus the exact append/tail linkage. The binding commit is one such slot; do not assume all eight reserved audit records have been used. |
| A without G4 | `(consumer_incarnation, original_operation_identity, A, audit_slot)`; expected serialized `(seq,hash)` and owning operation revision. | Owning operation's versioned retained state paired with its exact audit frame. If that operation has no durable identity/use state, its qualified adapter stays closed; a requester-selected ID or unlinked tail is insufficient. |
| P | `(authority_incarnation, authority_transaction_id, binding_revision, P)`; expected exact base-root/revision, guard, journal and use revision. | Owning authority transaction's next version of intent/retained outcome, linked to exact installed participants and root. The retained outcome survives live-intent cleanup. |

The owning operation fixes the complete allowed frame/slot set before preparation;
neither a requester nor a replacement H can allocate another ordinal to evade a
burn. Extra audit acts require independently authorized logical windows.

At most one candidate handoff may be admitted at a time for an operation/window.
`unused(v)` means the
protected owning transaction, its independently checked continuity and current
exclusion prove no prior use; absence of a file is not unused. The transition is:

1. Under the final locks, complete initial persistence and consuming use/CAS
   admission and select exact current head/epoch/unused owning revision for the
   operation/window/slot; only then take m and run the pure check. Pure checks
   may be repeated as computations; their results never become act authority.
2. Atomically serialize `unused(v) -> burned(v+1, exact original intent)` in the
   **same versioned owning transaction**, making the burn durable before any
   separable act. Every H, even a fresh challenge/commitment, now refuses for
   that logical operation/window. The durable key, not a digest-specific cache,
   supplies one-use. Immutable H is private preparation evidence; no persisted H
   is assumed. Provider W/holds were already settled independently and never undo.
3. For a genuinely atomic audit-frame/use store, burn and act may become durable
   together in one commit. Today's append-plus-another-file does not supply
   that atomicity. Otherwise write the owning transaction's burn-intent first;
   only that still-live admitted execution can make its one act attempt, within
   the original bound. P uses this intent-first case, with its use burn durable
   no later than PC2 step 2 and before any participant/audit/root live change.
4. `burned -> committed(exact outcome)` requires the profile's full act/use
   durability endpoint. `burned -> held` records an incomplete or unknown act.
   Both remain burned forever for this operation/window. Failed act, expired
   deadline, lost reply, restart or new H never transitions back to unused.
   Retain enough exact original evidence and tombstones in the same owner's
   capacity/custody domain after intent cleanup to prevent reuse and recover the
   original outcome. Do not discard use history to reclaim a revision.

A failed pre-burn validation makes no act/use write; discard its prepared handoff.
There is no generic exactly-once promise for separable effects. The original
native dedup result is still the only result cache. Reconciliation reads exact
retained evidence and fences conflicting authority; it does not run another act
using the burned handoff. Already durable outcomes may be recovered without
repeating the act; any new time-dependent publication/release needs its own
fresh admitted window and retains the old operation's burned state.

| Crash cut | A disposition | P disposition |
| --- | --- | --- |
| Before burn, including lost preparation | No frame; discard old run/window, prove owning state and obtain new evidence for any still-permitted operation. | No live publication; same original deadline, root and intent checks remain. |
| Burn durable, before act | Slot stays burned; no second frame attempt from a new run/H. Resolve/hold exact intent even if the operation is lost. | Intent/use retained, admission closed; no new authority transaction identity to bypass an unresolved original. |
| Partial write or unknown commit | Preserve partial segment/rotation and use state; audit unavailable, no release; reconcile once from exact evidence. | Preserve all old/new participants, intent, root, use state and hold; no old-root fallback. Root rename without directory durability is not success. |
| Act durable, before use/outcome or cleanup proven | Without proved atomic frame/use or complete intent protocol, hold; bytes alone cannot reopen admission. | Known root commit with unknown use outcome/intent cleanup remains held; readable root or absent marker is not resolution. |
| Full act/use commit, acknowledgement lost | Recover original frame/outcome; replay is a refusal, not another append. | Recover exact committed root/result after qualified reconciliation, never republish as a fresh transaction. |
| Consumer restore or competing instance | Independent continuity/live-instance fencing must retain the burned key; otherwise activation remains closed. | Same; a restored old root/revision/use record cannot restore unused state. |

If the owning transaction cannot carry this versioned use state and retain it
within its reviewed capacity/recovery protocol, stop that adapter. A separate
use journal, its custodian and independent restore protection require the owner's
explicit decision; this profile neither creates nor presumes one.

## Linux and macOS parity

These are equivalent **requirements**, not native qualification results. The
macOS authority lock, protected storage/identity and root tooling still need a
reviewed implementation matching PC2's exclusion/read-set guarantees; a Darwin
clock wrapper alone does not provide parity with Linux fs-verity or fencing.

| OS fact / required mapping | Linux | macOS | Primary source |
| --- | --- | --- | --- |
| Suspend-aware final read, A and P | Fixed `clock_gettime(CLOCK_BOOTTIME)` read; includes suspended time. Do not substitute Linux `CLOCK_MONOTONIC` or `CLOCK_MONOTONIC_RAW`, which exclude suspend. | Fixed `mach_continuous_time()` read, converted using the preloaded `mach_timebase_info` ratio with checked conservative integer arithmetic; counts sleep. Apple's documented ns equivalent `clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)` is also suspend-aware on Darwin, but this profile selects the Mach API. `mach_absolute_time`/uptime substitutes are forbidden. | [Linux clocks](https://man7.org/linux/man-pages/man2/clock_gettime.2.html), [Apple continuous clock](https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time), [Apple header](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/osfmk/mach/mach_time.h) |
| Boot, A and P | Validate the kernel `/proc/sys/kernel/random/boot_id` UUID outside final locks; receipt and operation must match it. The kernel documents a value fixed after its first retrieval. | Read and validate `kern.bootsessionuuid` outside final locks using the native sysctl interface; compare its protected captured value to receipt, operation and run. XNU exposes it as a read-only kernel string. A process nonce, hostname or wall-clock boot timestamp is not a substitute. Its clone/VM restore behavior still requires independent fencing. | [Linux boot ID](https://docs.kernel.org/admin-guide/sysctl/kernel.html#random), [Apple XNU sysctl declaration](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/kern/kern_sysctl.c#L2869) |
| Original deadline, A and P | Original operation start and exclusive D in the same boot/BOOTTIME domain; conservative mapping preserves the original caller deadline. | Capture original start/D in the same boot/continuous domain; retain original UTC deadline identity and qualified tick/ns/rate mapping. Conversion can shorten the deadline, never extend it; round current elapsed upward and allowed deadline downward. Do not interpret serialized Go wall time as a continuous-clock deadline. | Clock APIs above establish domains; mapping/error, original-budget intersection and strict endpoint are consumer requirements in this profile, not an OS guarantee. |
| File durability, A and P | Checked file sync and namespace directory sync, including newly created/renamed entries; Linux documents that file fsync alone need not persist the directory entry. | Require checked `fcntl(F_FULLFSYNC)` on durable written files where supported/qualified, plus separately qualified directory/rename/cleanup ordering. Apple documents that fsync alone can leave volatile drive caches and reordered persistence; F_FULLFSYNC requests a device flush too. No silent fallback to fsync, F_BARRIERFSYNC or ignored errors. | [Linux fsync](https://man7.org/linux/man-pages/man2/fsync.2.html), [Apple fsync](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html), [Apple fcntl](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html) |

Apple's archived filesystem support list is not evidence for the deployed APFS
volume/device. F_FULLFSYNC is not a multi-file atomic transaction or a bounded
completion primitive. Neither source establishes that a directory flush alone
persists every rename/cleanup or that a device always honors flush requests.
Qualify exact OS/filesystem/device, namespace barriers, power-loss/crash recovery
and latency; unsupported or unproven behavior stays `handoff_unqualified`.

| Window | macOS act and use commit | Deadline and parity disposition |
| --- | --- | --- |
| A | Exact serialized frame and A-use transaction; full file flush and any rotation seal/new segment/parent namespace barriers; recover exact tail after crash. | Same inherited 250 ms/native/writer/observation intersections as A above, from their original starts. Initial persistence/use admission selects the exact protected head/epoch/unused A revision for this operation/slot before the one continuous read m; pure check then burn under retained admission; pause/suspend after it must prevent a late act. No qualified enforced bound: `handoff_unqualified`. |
| P | Same intent-before-live-change graph, exact participants/audit, root full flush and same-volume rename with qualified namespace durability; committed P-use state, intent cleanup and parent durability before authority opens. | Same inherited deadlines as P above; no new root-tool budget. Initial persistence/use admission selects the exact protected head/epoch/unused P revision for this operation before the one continuous read m under the full C/audit/F-equivalent chain; pure check then burn under retained admission; full multi-file endpoint must be on time. Lock/storage/act equivalence and post-read bound unqualified: `handoff_unqualified`. |

## Other time consumers

| Path | QT-2c scope and outstanding condition |
| --- | --- |
| Enrollment approval issue/recheck/consume | Named but **out of this A/P adapter slice**. Its approval/reload lock and root-owned invalidation/consumed-ID protocol require a separate reviewed profile and new approval version. Preserve D_approval<=L_issue+600 s, U_current<D_approval and same-boot elapsed age <600 s; 600 s is an approval lifetime, not a new operation budget. A/P burns do not consume approval IDs. Version 1's `confirmed_utc_ns` remains O_issue, not L_issue. `TestQualifiedTimePendingEnrollmentIssueBound` stays pending. |
| Registration proof construction, reauthorization and actual release | Named but **out of this A/P adapter slice**. B-1c fixtures concern provider settlement, not a qualified final-lock adapter. Preserve original proof A, U_current<A and the native <=2 s/remaining timeout and generation <=250 ms final release when applicable. The retained native request is dedup, not a shared handoff ledger. Needs its own exact enrollment/generation/Store/release locks, use key and durable release semantics; no registration QT-2c activation here. `TestQualifiedTimePendingRegistrationContinuity` stays pending. |
| K3 message issuance/receipt/actual release | A/P cover its audit/root constituents only. The interval-preserving authenticated G4/K3 receipt mapping, native per-method operation and final transport release profile are slice C, still unqualified; do not treat an A/P commit as one-use permission to disclose a signature. `TestQualifiedTimePendingK3Receipt` stays pending. |
| Read/hello/refusal/public response | A may audit them; A is not permission for the later transport act. Any qualified release needs its separate operation/window identity, original deadline and one-use endpoint. No generic audit-to-release capability is created. |

`TestQualifiedTimePendingAuditPreWindow` also stays pending. All four existing
PENDING rows keep their names and deliberate failures. Neither this document
nor a future arithmetic fixture closes them.

## Future paired controls

All rows below are **PENDING / NOT RUN**. They describe required future executable
claims and controls, not tests implemented by this docs-only change. Run each
for A and P on Linux and macOS. Keep a nearby on-time positive with the same
operation, evidence, locks and storage protocol; assert named refusal, no
forbidden act/release and exact provider/use/recovery post-state.

| Proposed named test | Negative and expected invariant | Positive / narrowing control |
| --- | --- | --- |
| `QT2cStaleCapture` | Pause after pre-window capture until original D has passed; unchanged packet cannot authorize an act. The final qualified read gives expiry, or an unqualified path refuses `clock_untrusted`. | Same inputs, on-time admission and qualified post-read enforcement may commit once. Remove the final read in a control: the stale-admission assertion must fail. |
| `QT2cUseAdmissionOrder` | Capture m before initial persistence/use admission or before protected exact head/epoch/unused revision selection; refuse with no burn/act, even if later admission is nonwaiting. | Complete all initial admissions/state selection before m, pure check then burn under retained admission. Move initial admission after m: the order assertion must fail (`HandoffUseAdmissionOrder`). |
| `QT2cDoubleCheckOneUse` | Run pure verification twice with identical unused snapshot; race serialized consumes and present another H/challenge for the same key. At most one consume/act; burned window refuses every H. | Distinct authorized next operation/window, new evidence and remaining original budget may commit. Remove revision/use comparison: named duplicate-act assertion must fail. |
| `QT2cTimelyAndLateAct` | Actually pause **after the final read**, before act, past D; qualify that the act is prevented, not merely that the response is suppressed. No late frame/root/use-success commit. | Timely qualified run reaches the full durable endpoint strictly before D. Remove act enforcement while retaining pure arithmetic: the late-act assertion must fail. Without enforcement both timings remain unqualified. |
| `QT2cAuditPostCaptureCuts` | A: pause at verification-to-burn, burn-to-write, rotation seal/new segment, short frame write, file flush and required parent flush. Pre-act expiry forbids append; possible writes retain burn/hold and forbid release. A blocked sync cannot be called a timely commit. | Same exact tail/slot with every required barrier before D commits once. Omit rotation/parent durability: crash-reopen exact-tail/use assertion must fail. |
| `QT2cPublicationPostCaptureCuts` | P: pause before burn/intent, each intent/file/parent barrier, each participant/audit install, root rename/dir sync, use outcome and cleanup/parent sync. No premature authority; unknown stays held and burned, including known-root/unknown-cleanup. | Complete graph within D may open authority only after all barriers. Omit root directory or use/cleanup durability: the no-early-authority assertion must fail. |
| `QT2cBootSuspendAndMapping` | Suspend after the final read and resume past D; changed boot, tick conversion overflow, non-suspend clock, later deadline or refreshed reserve refuses. Restore original use state under a rolled-back process must not permit use. | Same-boot timely Linux BOOTTIME and macOS continuous runs with preserved original interval/mapping pass only their time predicates. Replace continuous clock with uptime or refresh D: the suspend/deadline assertion must fail. |
| `QT2cBurnCrashLostAck` | Exercise every crash row above with real retained consumer state; replacing H, restarting or losing acknowledgement never clears a burn or provider W. | Recover exact committed outcome without repeating act. Remove retained burned state: named restart-replay assertion must fail. |
| `QT2cDeadlineEquality` | Admission whose complete bound reaches exactly D refuses `request_deadline_exceeded` without act/use mutation; U=A also refuses its authority/time predicate. | With the same independently qualified bound, a durable endpoint one ns before D and U<A may pass the time predicates. Change strict comparison to inclusive: the equality assertion must fail. |

A fake elapsed integer proves arithmetic only. Actual process pause, suspend,
blocked durability and restore probes need isolated authorized native targets and
independent exclusion/observation; no production fault injection is authorized
here. A setup failure, skipped test or un-applied control is not a killed mutant.
The source [named vectors](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff.md#named-future-controls)
now define separate `HandoffN1BeforeBurn` and `HandoffN1AfterBurn`: provider W
survives both, but only the independently current still-unused original window
may reprepare before burn; no H can revive it after burn. N2 additionally fences
old/delegated writers after burn, and N3 retires candidates on lock release or
run/epoch change. These controls remain future requirements, not executed proof.

## Open ownership and implementation gates

1. **Deployment owner:** select/provision the independent witness and its
   custodian, restore domains, rollback anchors and old/live-instance exclusion.
   Provider W/hold retention and consumer burned-state retention must not roll
   back together. Boot UUIDs and hashes alone do not provide this separation.
2. **Consumer and time-provider owners:** accept the protected original-reader
   and witness-validation interfaces and exact native operation/window profiles;
   qualify interval/reserve/rate mapping, change invalidation and original
   retention. Option (d)'s trust boundary must hold throughout both windows.
3. **Consumer/storage owners:** review QTUse/1's next owning transaction format,
   capacity accounting, durable burn-before-act and retained-outcome protocol on
   both OSes. Existing closed bytes/hashes stay unchanged. If this cannot be
   integrated, take any proposed separate use journal and its custody/restore
   obligations to the deployment owner before implementation.
4. **Platform and consumer owners:** supply the enforced read-to-durable-act
   bound or deadline-aware act for each window, including suspend, storage and
   independent emergency stop. No supplied native guarantee currently closes
   this item; the codec cannot confer one. macOS lock, integrity, storage and
   power-loss equivalence need the same review and evidence as Linux.

No gate is closed by this spec. Production activation and the new use transition
need separate review after these inputs exist.
