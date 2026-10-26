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
The documentation schema is [broker PR #28 at exact landed head 7294b7a](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-window-profile.md#profile-schema),
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
neither. There is currently no such qualified primitive for any consuming profile:
**all are `handoff_unqualified` on both OSes**. The specification of f is an
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

The protected **Keymaker QT-2c name mapping, version 1**, is this single closed
field-scoped table. It assigns native profile identifiers to the window selectors
used here; these are proposed enrolled names, not active profiles.

| Broker destination / selector | Native name | Exact enrolled value |
| --- | --- | --- |
| `transition_version` / all consuming windows | `QTUse/1` | `QTUse:1` |
| `window.profile` / A | `keymaker-audit/1` | `keymaker-audit:1` |
| `window.profile` / P | `keymaker-publication/1` | `keymaker-publication:1` |
| `window.profile` / E-I | `keymaker-enrollment-issue/1` | `keymaker-enrollment-issue:1` |
| `window.profile` / E-C | `keymaker-enrollment-consume/1` | `keymaker-enrollment-consume:1` |
| `window.profile` / R-S | `keymaker-registration-stage/1` | `keymaker-registration-stage:1` |
| `window.profile` / R-X | `keymaker-registration-release/1` | `keymaker-registration-release:1` |
| `NativeOperationDigest` profile argument / all consuming windows | `keymaker-operation/1` | `keymaker-operation:1` |

Authenticated enrollment fixes the table version, destination field and native
window selector. Preparation and handoff encoding apply that **same exact
lookup**; the expected operation and final check retain those bindings. Decode
requires exact enrolled equality in the correct field/window before interpreting
the native name. Literal slashes, wrong versions, swapped fields/windows and
unregistered names refuse before burn/act. There is no generic slash substitution
or fallback. Table changes need reviewed enrollment/version migration and cannot
create a fresh logical use key or reset a burned operation.

The [broker identifier alphabet][r6-alphabet] accepts every enrolled value above,
and its [handoff check][r6-encoding] applies it to window profile and transition
version. Alphabet acceptance alone is not enrollment authority. For the
[operation-digest helper][r6-operation], use the table's mapped profile argument
and exact owner-validated canonical native identity bytes, including the original
operation kind/tuple, arguments and protected predecessor/read-set bindings.
Do not serialize tuple/path labels directly into an identifier, truncate a digest
into a generation, or let a requester choose this profile. Its native identity
codec still needs the owning transition's review; the mapping supplies no codec.

Restricted-name audit: the seven receipt names (authority ID/version, machine,
consumer, purpose, continuity scope and store) are exact **protected provider
enrollment values**, not derived native labels or paths; validate their alphabet
and exact enrollment match without rewriting original receipt facts. This
profile assigns no additional native aliases to them. Any future native alias
needs an explicit field-scoped table revision before use; absent enrollment
refuses. Native method names, lock/store paths and G4 codec tags remain in their
original native bindings, not broker name fields. The broker's fixed envelope,
retained-anchor and witness-placeholder version/profile literals have their own
closed literal checks (including their specified slashes), so this table must
not rewrite those. Boot IDs, run/challenge nonces, digests and numeric sequence/
revision fields keep their distinct grammars; they are not names in this table.
R-B/R-V/R-A and the other nonconsuming paths have no broker window identifier.

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
The [pinned macOS binding](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff-macos.md#clock-boot-and-deadline)
also identifies a representation gap for **every** consuming profile: the
current closed receipt accepts only `CLOCK_BOOTTIME`. The proposed
`MACH_CONTINUOUS_TIME/ns` identifier is not accepted. A reviewed Darwin platform
version is required; relabeling a Linux receipt cannot qualify it.

| Window | macOS act and use commit | Deadline and parity disposition |
| --- | --- | --- |
| A | Exact serialized frame and A-use transaction; full file flush and any rotation seal/new segment/parent namespace barriers; recover exact tail after crash. | Same inherited 250 ms/native/writer/observation intersections as A above, from their original starts. Initial persistence/use admission selects the exact protected head/epoch/unused A revision for this operation/slot before the one continuous read m; pure check then burn under retained admission; pause/suspend after it must prevent a late act. No qualified enforced bound: `handoff_unqualified`. |
| P | Same intent-before-live-change graph, exact participants/audit, root full flush and same-volume rename with qualified namespace durability; committed P-use state, intent cleanup and parent durability before authority opens. | Same inherited deadlines as P above; no new root-tool budget. Initial persistence/use admission selects the exact protected head/epoch/unused P revision for this operation before the one continuous read m under the full C/audit/F-equivalent chain; pure check then burn under retained admission; full multi-file endpoint must be on time. Lock/storage/act equivalence and post-read bound unqualified: `handoff_unqualified`. |

## Remaining windows: scope and shared schema fields

The following profiles distinguish today's provider observations from proposed
QT-2c consumption. They add no active adapter. Source links in these profiles
pin Keymaker **b232f6aec52e9327daffd8e889b52ed0ebd2fd3f**; broker requirements
remain the landed 7294b7a pins above. Each consuming row inherits the common
admission, interval/reserve, QTUse/1 crash rules, and Linux/macOS requirements;
its native read set, locks, budget and endpoint below specialize those fields.
Private-helper rows explicitly exclude use/act fields; a successful helper
does not authorize either durable retention or later transport.

For E-I, E-C, R-S and R-X, expected input includes the protected native identity
below, original caller/confirmation occurrence, window/slot, current consumer
incarnation/epoch, exact predecessor and unused revision, original boot/start/D,
receipt and complete authenticated original/witness closure. These identities
are fixed before preparing H; neither a future post-state hash nor H identifies
the operation. The provider's restricted operation ID needs a reviewed protected
mapping from each native tuple, not direct encoding of slash-separated labels.
The owning approval, enrollment, registrar envelope, retained-request, audit and
G4 codecs/hashes remain closed. QTUse/1 is a proposed **next owning transition**,
not a field available in any of those current records.

Preparation is outside final locks; retain bounded immutable owned originals
and live custody/invalidation until completion. Apply the pinned schema's
64-object, 8 MiB, depth-16 original-closure limits and 65536-byte receipt bound;
missing/excess closure refuses without a truncated bundle. Enrollment currently
limits an approval read to 4096 bytes ([startup:635][enrollment-startup]) and the
consumed ledger to 16 MiB with room for a 65-byte entry
([approval_linux.go:185][approval-capacity], [store_linux.go:22][enrollment-cap]).
Native results share the existing 256 MiB state budget and 65536-byte frame
limit ([base:764][native-resource]). These are existing size limits, **not**
qualified f bounds. The next transitions still need exact worst-case file,
history, rollback retention and namespace-work reservations before admission;
no eviction or second state allowance is granted.
These are request/confirmation-driven profiles, with no scheduled occurrence.
R-S's staged-signature extension is mandatory as specified below. They use
native intent/outcome recovery, not the optional separately witnessed immutable
content/completion bridge; no new content-witness protocol is inferred.

For each consuming row, after every listed final exclusion and initial
persistence/use-CAS admission, select its exact protected head/epoch/unused
revision **before m**. Take the sole fixed qualified read m, pure-check that
unchanged read set, then burn under retained admission before a separable act.
No row permits today's under-lock provider samples as an implementation of m.
Nested A/P work has fresh evidence/use and remains inside the parent's f/D;
later visibility is a separate window. All proposed f/epsilon/rate and storage
enforcement qualifications are absent: `handoff_unqualified`, with admission
closed even when a native timeout is specified. Independent stop and old-writer
exclusion must cover every paused holder and ambiguous write, on both OSes.

### Enrollment E-I: approval issue and publication

| Field | E-I profile |
| --- | --- |
| Native operation / expected read set | Root `enrollment reconcile`, including explicit bootstrap: confirmed exact state digest, protected config-path/pin digests, service identity, boot, fixed approval ID and consumed-ledger generation, existing approval/fence/high-water predecessor and command occurrence. Freeze these before H. Current issue construction is [approval_linux.go:87][approval-check]; confirmation, protected reread and reinspection precede it at [reconcile_command_linux.go:352][enrollment-confirm]. A new independently authorized confirmation is a new operation; a retry is not. |
| Locks | Root-exclusive directory lease, then existing high-water Store inode EX/nonwaiting for normal reconcile ([reconcile_command_linux.go:305][enrollment-command-locks]); bootstrap instead uses the initial publisher's own Store exclusion ([reconcile_command_linux.go:403][enrollment-bootstrap]). Retain the applicable chain through final publication. Admit exact approval/fence/ledger head and unused E-I slot before m. Current provider sampling while these exclusions are held remains a gap; unlocked preparation needs review. |
| Original budget and authority | **Owner budget decision — proposal: E-I <=60 seconds**, from original command entry **before** config/provider lookup, lease/Store acquisition, inspection, output or human confirmation, through the complete issue endpoint below. Intersect that exclusive deadline with any shorter original caller deadline; retain both starts. Each existing 10-second inspection is a subdeadline, shortened by the remaining command allowance, never another command budget. Today the CLI has only a signal context ([main.go:45][command-context]); no whole-command enforcement is implemented. The [10-minute TTL:24][approval-ttl] and [strict age checks:121][approval-check] remain approval lifetime, not command allowance. The next encoding retains L_issue and D_approval<=L_issue+600 s, U_current<D_approval, U_current<A and same-boot elapsed age <600 s; version 1 retains O_issue, not L_issue ([approval_linux.go:132][approval-check]). |
| Read / enforcement | Use the shared before-m admission rule under the exact normal/bootstrap chain, with matching confirmed state, fixed occurrence/original start/D and reserved publication workload. After all persistence/use-CAS admission, take the sole m, pure-check, then durably burn E-I before separable publication. The enforced f must cover all remaining pre-commit output, file/namespace barriers, fence cleanup and durable use outcome, strictly before D. Neither the proposed 60 seconds nor a post-write `approvalValid` call supplies that enforcement: `handoff_unqualified`. |
| Endpoint | The proposed complete owning issue transaction commits the exact approval and conservative issue bound, ledger initialization where needed, bootstrap acceptance/high-water where applicable, and their checked writes/full file syncs/closes/parent syncs; completes provisional pre-commit output and publication-fence removal **including its parent-directory sync**; and durably commits the same occurrence's E-I use/outcome. Startup may accept only this complete exact tuple, never a readable approval, report or use record alone. Only a subsequent notification may report successful completion; notification loss/failure returns no new authority and cannot refund the committed occurrence. A provisional report is never that success. Today's post-output marker removal has **no following directory sync** ([reconcile_command_linux.go:441][approval-publication]); that safe-refusal protocol is not this endpoint. A matching next-version issuer and startup reader/transaction protocol remain required. |
| Use transition key / recovery | The next owning approval-issue transaction durably binds consumer incarnation, original independently confirmed command occurrence/start/D, fixed approval ID, ledger generation, E-I publication slot, exact state/pin/config-path and expected approval/fence/state predecessors. It carries QTUse/1 burned/held/committed state and exact outcome through fence cleanup and lost output. A retry identifies that same occurrence; no new approval ID, confirmation replay, challenge, Run or Epoch refunds it. Unknown burn/publication/use durability holds issuance until qualified reconciliation, never re-issues. No such durable occurrence/use slot exists today; format/migration/capacity review is mandatory. A/P uses cannot substitute. |
| Existing refusals | Preserve command errors such as `clock_untrusted`, `approval_expired`, `approval_boot_changed`, `approval_clock_rollback`, `approval_clock_discontinuity`, `store_writer_live`, configuration/trust and I/O failures ([approval checks][approval-check], [command locks][enrollment-command-locks]). Unadopted/unqualified QT-2c admission remains closed; it is not a new CLI success or public code. |
| macOS | Same identity, proposed original 60-second command budget, lifetime predicates and complete act/use endpoint; continuous clock/boot/deadline mapping and checked full file flush plus separately qualified namespace cleanup as above. Linux-only root lease/Store metadata and bootstrap/publication code do not prove a Darwin port. No accepted Darwin receipt platform representation or qualified post-read act/stop exists; `handoff_unqualified`. |

### Enrollment E-C: approval recheck, consumption and authority admission

| Field | E-C profile |
| --- | --- |
| Native operation / expected read set | Protected startup approval: exact invalidated approval bytes and inode, approval ID/ledger generation, config/pin/state digests, current retained high-water and registry/policy identity, boot, original issue interval and expiry, exact unused consumer-use revision and candidate authority epoch. Current startup's rename and directory sync invalidate approval **before every retained-state/consent check** ([reconcile_command_linux.go:569][enrollment-startup]). Preserve that ordering even when arranging unlocked preparation; no pre-invalidation consent read is authorized. Invalidation is a required fail-closed precondition, not a successful QT act, and remains effective on refusal before m. |
| Locks | Today startup holds the service directory lease and Store EX, without `Authority.mu` ([authority.go:143][enrollment-load], [startup:569][enrollment-startup]); reload holds reloadMu, pauses new readers, privately loads, then takes the admission write barrier only for the swap ([authority.go:99][enrollment-reload]). The proposed two-phase handover below retains reload serialization/directory exclusion, prepares outside final locks, then takes Store EX and the admission write barrier before m. Select exact ledger/high-water/authority heads and unused E-C revision with all final persistence/use admissions complete. Retain that chain through commit/swap/opening; no initial use admission at the later swap. This is a next-version proposal, not today's lock span. |
| Original budget and authority | **Owner budget decision — proposal: E-C <=10 seconds** from original Reload entry **before reloadMu acquisition or reader pause**, through validation, durable consumption/high-water/use commit and the final admission swap/opening. For initial startup, start at the original authority-open entry before private load/lease acquisition. Intersect with every shorter original caller deadline. The private `load` retains its own **10 seconds from load entry** ([authority.go:129][enrollment-load]), shortened by the remaining E-C/caller allowance; neither load return nor swap starts a new timer. Today no whole-reload deadline covers both phases ([authority.go:111][enrollment-reload]). Keep E-I's original D_approval<=L_issue+600 s, current U<D_approval/A and same-boot elapsed bound. A fresh recheck cannot renew issue time or D. |
| Read / enforcement | After durable invalidation and authenticated preparation, complete the proposed final handover and unused E-C selection before the sole m; pure-check then durably burn before separable consumption. Enforce f through consumed-ID/high-water durability, cleanup, exact use outcome and final gated swap/opening, strictly before the earliest original D. Current samples at [startup:647/657/684][enrollment-startup] occur under Store and are not QT-2c reads. No enforced full endpoint exists: `handoff_unqualified`. |
| Endpoint | Complete the exact consumed-ID append with checked full write/sync/close; remove the invalidated inode, verify no remaining links, sync its directory and check close; durably persist the validated registry/high-water. Under the retained admission barrier stage the exact candidate/epoch swap while still inaccessible, durably commit the same occurrence's linked E-C use/outcome, and only then open admissions within f/D. No required durability may follow visibility. A completed load or consumed ledger alone is not the endpoint ([approval_linux.go:236][approval-consume], [startup:650][enrollment-startup], [authority.go:196][enrollment-load], [authority.go:112][enrollment-reload]). Provider/Git work moves to preparation; exact cross-phase/recovery and deadline-enforcing publication remain unimplemented. |
| Use transition key / recovery | The proposed next owning enrollment transition durably binds consumer incarnation, original startup/reload occurrence/start/D, approval ID/ledger generation where consumed, E-C slot, exact candidate and expected high-water/authority/use predecessors. Live reload with retained reconciliation binds that exact retained state instead of inventing a startup approval. Retain burned/held/committed use and original outcome across swap, restart and lost response. Existing ID append prevents approval replay but carries no generic QTUse/1 state; never add H to the closed approval or reinterpret an ID as H. Invalidation stays effective on refusal, even before burn; unknown consumption/use/swap outcome holds admission and never consumes or opens again. |
| Existing refusals | Approval checks keep their existing precise diagnostics internally; startup failures keep authority `enrollment_unverified` ([authority.go:125/156][enrollment-load]). Preserve existing caller deadline, trust/registry/revocation and I/O refusals. Neither an expired approval nor failed consumption grants a callback. |
| macOS | Same post-invalidation order, exact ID/ledger/use retention, original proposed 10-second full-endpoint budget and shortened load subdeadline. A reviewed Darwin lease, metadata/link verification, no-replace rename and namespace/full-flush protocol plus continuous clock/receipt/stop qualification are missing. `handoff_unqualified`; no Linux startup evidence transfers. |

### Proposed enrollment occurrence and final handover

The **60-second E-I / 10-second E-C values are owner budget decisions**, not
accepted latency bounds or activation. E-I allows at most the existing two
10-second inspections plus 40 seconds shared by configuration, lock admission,
human confirmation, output and full publication; this is rationale for a finite
proposal, not evidence that any step meets it. A supplied `--confirm` still uses
the same original command entry. Confirmation arriving too late refuses; it
cannot start a fresh 60 seconds. E-C deliberately reuses the existing 10-second
load ceiling for the **whole** operation: waiting for reload serialization,
preparation and barrier/swap now spend it, so load may have less than 10 seconds.
A shorter original caller deadline always wins. Name the original native entry
captures t_I (command) and t_C (Reload, or initial authority-open entry): the
exclusive native ceilings are D_I=t_I+60 s and D_C=t_C+10 s, respectively, with
checked same-boot arithmetic. The effective D is the earliest qualified mapping
of that ceiling and every applicable original caller, load, approval or authority
limit. These symbols are timing requirements, not new serialized members.

These budgets bound original native operations. Preserve their suspend-aware
same-boot start/deadline in the next owning transaction; a Go context is not the
enforcement primitive. They neither supply a post-read f nor expand the shared
1.5-second total uncertainty/reserve, approval TTL or any stricter enclosing
250 ms/native 2 s window. Keep the receipt's original s/T distinct from the
command/reload start; intersect its existing grant with the original operation
D using the common inequalities, never reset s or allocate another reserve.
If no qualifying final evidence and enforced f fit, refuse. A retry, fresh
receipt, human reconfirmation of the same occurrence or load-to-swap handoff
cannot restart the native deadline.

The next owning transaction must retain the independently authorized occurrence,
original argument/read-set/predecessor bindings and fixed IDs, not merely a new
random invocation token. Exact retry resolves that occurrence from protected
retained state; absence of a local record is not proof of unused. After final
admission and the sole m, the first durable burn binds that occurrence and
original start/D before any separable approval publication or consumption.
`burned -> committed(exact outcome)` requires the complete endpoint in its row;
unknown burn, act, cleanup or outcome durability is held and never refunds use.
Lost output/acknowledgement returns only the resolved original outcome, never
another issuance or admission act. A separately authorized new confirmation
needs a distinct protected occurrence after the prior outcome is conclusively
resolved; changing IDs, argv, a challenge or the process is not that decision.
Bootstrap inspection/confirmation remains read-only before this admitted
transaction; prior attempt evidence still forbids a pristine-state reset.

For E-C the proposed handover is specifically:

1. Start the original deadline before reload serialization; pause new admissions
   while existing bounded readers finish. Retain the directory/lifetime lease.
   On startup, take Store EX only to locate/invalidate the approval durably
   **before** retained-state or consent checks; refusal never renames it back.
2. Release Store EX for authenticated provider/Git and complete candidate
   preparation outside the final critical section, retaining the directory
   exclusion and invalidation evidence. Bind exact protected high-water,
   approval/consumed ledger (where applicable), authority epoch and candidate.
   This phase grants no admission; it is not the current startup implementation.
3. Reacquire Store EX, then acquire the admission write barrier; revalidate the
   exact prepared heads/epoch and predecessor under that chain. A change closes
   this window and requires unlocked preparation within the **same** original D.
   Complete all persistence and use-CAS admission before m; retain these locks
   through burn, durable consumption/high-water/cleanup and the staged swap.
4. Stage the candidate under the barrier with admissions still closed; the next
   transaction's durable committed E-C outcome binds that exact candidate and
   epoch before the final gate opens. Opening and any barrier-release gap are
   inside the enforced f/D, with no second m, provider call or new use admission.
   Failure fences the authority, rather than falling back to the old snapshot;
   uncertain commit requires reconciliation. A durably committed record before
   opening is not permission for a restarted process to open from the same use.

This handover and the issuer/consumer visibility gate require joint format,
locking, storage/capacity and recovery review before code. Keep process `Run`
identity separate from independently current ownership `Epoch` and the durable
use revision; pin and validate each independently. Consumer incarnation is
a protected authority identity, not a new process nonce. Neither changing it
nor replacing Epoch erases the original burn; Epoch replacement fences the
old execution even after burn. None creates a new logical occurrence or clears
a burned slot. A restarted Run must resolve the retained outcome; it cannot
continue an old final act.
Independent original/witness custody and old/restored-instance exclusion must
retain this distinction across coherent restore. A new use file, spare codec
member or assumed atomicity of unrelated files is not supplied by this proposal.
Linux, macOS, native endpoints and custody/time qualification all stay closed.

Enrollment-specific paired controls below are **PENDING / NOT RUN**, semantic
specifications only. Every negative uses the same authorized timely control,
exact predecessor/occurrence, workload and original allowance; check the exact
burned/held/committed and visibility state, not just an error or timeout.

| Pending specification | Positive control and forbidden neighboring outcome |
| --- | --- |
| `QT2cEnrollmentIssueEndpoint.TimelyLate` | Fully admitted issue completes all publication/fence/use durability strictly before the earliest D. Pair command/confirmation delay that exhausts the original 60 seconds, a shorter caller D, and endpoint equality at D: no new usable approval or successful issue; post-burn uncertainty stays held. No new timer after confirmation or second inspection. |
| `QT2cEnrollmentConsumeEndpoint.TimelyLate` | Same candidate completes consumption, high-water/use durability and barrier/swap/opening within the original 10 seconds and load subdeadline. Pair time spent waiting for reloadMu, returning from load just before expiry but swapping at/after D, and a shorter caller D: no candidate admission, old authority fenced, invalidation retained. |
| `QT2cEnrollmentIssueEndpoint.PostReadPause` / `QT2cEnrollmentConsumeEndpoint.PostReadPause` | Same on-time endpoint succeeds. Pair suspend/preemption after m and pauses at output/fence sync or ledger/high-water/use/swap/opening: enforcement must prevent a late authoritative act, retaining exact debt. A post-commit refusal message alone does not pass this control. |
| `QT2cEnrollmentIssueEndpoint.SecondRead` / `QT2cEnrollmentConsumeEndpoint.SecondRead` | Exactly one admitted m authorizes the timely control. A second clock read, refreshed H or use admission after m cannot rescue the same window: no publication/opening; any prior burn remains burned. Pure verification repeated on the same captured integer is not another clock read. |
| `QT2cEnrollmentIssueEndpoint.UnknownRetry` / `QT2cEnrollmentConsumeEndpoint.UnknownRetry` | Resolve a complete original endpoint with a lost reply to its exact original outcome and no second act. Pair crash/unknown burn, partial approval/consumption, lost cleanup/use sync or a new Run: retain held/unknown evidence, no new approval ID, fresh occurrence, second consumption or swap. |
| `QT2cEnrollmentConsumeEndpoint.Handover` | Exact prepared heads remain current through Store EX/barrier acquisition and gate opening. Pair a changed high-water/use head/epoch, invalidation refusal, or a pause between staged swap, use commit and opening: no stale candidate or old-snapshot fallback, and no restored approval. |

Named future narrowing controls remove the original-start intersection, complete
endpoint, invalidation-before-checks, sole-read admission, durable occurrence/use
or final handover check respectively. Each must fail its corresponding negative
above while the timely control still passes. These controls and all storage/
stop/restore evidence remain pending; listing them adds no executable tests.

### Registration private helpers R-B, R-V and R-A

These are **not QT-2c consuming windows today**. The private proof API samples
the ordinary provider and returns a proof or verdict; it has no handoff, durable
use home or release capability. Their callers must separately qualify R-S/R-X.

| Field | R-B: `Builder.Build` | R-V: `Proof.Recheck` | R-A: `Proof.Reauthorize` / `Builder.Restore` |
| --- | --- | --- | --- |
| Native operation / expected read set | Trusted enrolled key/name/audience/window, original sample interval/A, fixed purpose-2 preimage/nonce, signer and resulting exact envelope ([registration.go:156][proof-build]). | Existing proof bytes, issue/expiry, enrolled window and **original** authorityUntil; fresh current interval ([registration.go:127][proof-recheck]). | Exact retained envelope and current authorized name/audience/key/window; rebuild/check canonical body before accepting it ([registration.go:230][proof-restore]). Reauthorize preserves original A; Restore for an independent request establishes a new observation, not an extension of the earlier grant. |
| Locks | Builder `clockMu` for provider sample/sticky rollback state and `entropyMu` for nonce; signer callback has its own custody ([registration.go:77][proof-clock], [registration.go:168][proof-build]). Native callers currently additionally hold generation -> Store -> enrollment read barrier ([keymaker/registration.go:101][registration-stage]). | `clockMu` during fresh sample; native release additionally retains the R-X outer chain. | Same `clockMu`/rollback fencing; R-X caller supplies current enrollment read barrier. |
| Original budget | Only caller context; standalone helper budget **`undefined`**, so no qualified admission by itself. Native caller inherits completed-frame 1..2000 ms and actual generation window below. The [issued+120 s expiry:177][proof-build] is signed proof lifetime, not a Build execution budget. | No new budget; inherit unchanged caller D and original proof A/expiry. Standalone budget **`undefined`**. | No new budget; retained-proof reauthorization inherits original A/expiry and current caller D. Standalone budget **`undefined`**. |
| Read / mechanism / endpoint | No QT-2c m/use admission or enforced post-read act. Build performs private signing then Recheck and returns private bytes ([registration.go:193/208][proof-build]); it does not persist or transport them. | No QT-2c m/use admission. Returns a private verdict after sample/interval checks; it burns nothing and cannot authorize an arbitrary later callback. | No QT-2c m/use admission. Returns a private restored proof/current verdict; signing is not repeated. None of these helpers qualifies R-S/R-X by moving a sample under their locks. |
| Use key | Inapplicable: private staging has no durable act/use transition. Bind any later R-S to the fixed native occurrence and staged bytes. | Inapplicable: pure consumer predicate outcome plus provider observation is not a use ledger. Provider W must nevertheless retain its settlement on refusal. | Inapplicable: exact-byte restore/validation does not consume a release slot. It cannot refund a burned R-S/R-X. |
| Existing refusals | `clock_untrusted`, `request_deadline_exceeded`, `entropy_unavailable`, `key_not_valid_now`, `audience_mismatch`, `enrollment_unsupported`, registrar validation/custody codes ([registration.go:23][proof-codes]). | `clock_untrusted`, `request_expired`, `key_not_valid_now`, deadline refusal; preserve strict current U<original A and U<expiry. | Same plus canonical envelope/key/name/audience rejection; backward time fences the builder ([registration.go:284][proof-restore]). |
| macOS | No QT-2c port or clock/receipt qualification is implied by these platform-neutral private functions. Future consuming callers must use the continuous mapping and full native R-S/R-X qualification. | Same; a Darwin provider observation is not m. | Same; a different OS cannot recreate or enlarge the retained original grant. |

### Registration R-S: staged result commit; R-X: actual transport release

R-X **does consume qualified time when activated**: the native contract requires
issue and actual release inside the enrolled key's validity and a recheck after
audit ([base:577][registration-release-rule]). A private signature or durable
audit alone is not that release. R-S covers the earlier time-qualified durable
retention of the exact staged result; it is a separate window from R-X.

| Field | R-S profile | R-X profile |
| --- | --- | --- |
| Native operation / expected read set | `sign_registration`, protected `(caller_uid,generation,request_id)`, exact canonical params digest, pinned binding number/path/master epoch, current enrolled record/revision/policy/key/name/audience/window, fixed staged envelope digest/issue/expiry/original A, exact retained-request predecessor and unused R-S slot. Current [stage/persist:179][registration-stage] serializes same-ID retention. | Same independent tuple/args/binding and current enrolled authority, exact retained result and connection proof/original A, current generation and unused R-X release slot. Current release requires retained-result byte equality and matching connection proof ([keymaker/registration.go:219][registration-release]). A fresh H or retry connection alone is not independent authorization for another exposure. |
| Locks | Generation source data/final reader chain as A, separate in-process generation gate -> `Store.mu` -> `Authority.mu` read, then A audit gate for a nested append ([keymaker/registration.go:109/150/186][registration-stage]). All initial persistence/use admission and exact unused R-S revision selection precede m. No Store/enrollment/audit acquisition below terminal F if a future caller is also under F. | `Native.WithActive` release generation fence -> Store -> enrollment read barrier, then nested audit gate ([native.go:643][native-release], [keymaker/registration.go:239][registration-release]). Same before-m persistence/use admission with exact locked retained-result/epoch/unused R-X revision; retain release exclusion through the endpoint. No unlock/provider/relock inside this final window. |
| Original budget | Native `timeout_ms` **1..2000 ms from completed frame** ([base:524][native-timeout], [server.go:207/265][native-deadline]); cap by original caller and actual generation read's **250 ms from the original reader-window start**, never a fresh timer ([genjournal:13/191/195][generation-budget]). Require original U<A and key-validity/expiry predicates; 120-second proof lifetime does not extend D. | Same original native D, with this final release entry's actual generation data window intersected from its own original start; preparation/persistence elapsed still consumes native D. Existing socket write deadline is shortened by the fence context ([server.go:384][transport-write]). A fresh final generation entry cannot renew the completed-frame deadline, original proof A or expiry. |
| Read / enforcement | Prepare/freeze signed bytes, purpose/key, issue/expiry and original grant outside final locks **before H**, avoiding a time/H-dependent signed-preimage cycle. After full initial admission/read-set match take m, pure check, burn R-S then nested audit/result commit. Current Build/provider calls are under outer locks ([keymaker/registration.go:142/162][registration-stage]); moving them is an unresolved implementation change. No enforced m-through-durability bound: `handoff_unqualified`. | Prepare fresh evidence unlocked; after the whole chain and exact unused R-X selection take m, pure check, durably burn and commit the exact release authorization/use endpoint **before any response byte**. Enforce separate precommit and actual-send bounds as below, retaining the same burned window throughout. Current `Time`, `Reauthorize`, final `Recheck`, audit and socket paths still sample clocks under locks ([keymaker/registration.go:231/244/253][registration-release], [server.go:389][transport-write]); these are not a conforming final adapter. `SetWriteDeadline` plus post-write checks is not proof of the full use/storage/transport endpoint or exclusion of late delegated writers: `handoff_unqualified`. |
| Endpoint | Exact audit and retained result fully durable with committed R-S use/outcome, every file/namespace/readback barrier in the owning state transaction, before returning a private release candidate. Today's retention-before-release is [keymaker/registration.go:189][registration-stage]; no current QTUse/1 is present. R-S completion grants no transport use. | Before transport, the owning transaction durably commits the R-X burn plus exact one-attempt release authorization, all required outcome/recovery bindings, readback and namespace/intent cleanup with retained burned evidence. Then the still-live admitted executor may send the bound frame once within the separate send bound and original D. No required success binding is deferred until after the frame. Later delivery accounting records observations only, never creates or retracts authorization; its failure cannot undo peer success or permit resend. Socket delivery is not atomic with storage; authorization does not prove delivery. No current owning transaction realizes this endpoint. |
| Use transition key / retry | Proposed next binding/result transaction: consumer incarnation, native tuple + original args identity, R-S staged-result slot and exact state predecessor. Fixed bytes are a read-set binding, not a replacement operation identity. Existing retained requests deduplicate a nonce; they are not generic handoff-use records. | Proposed next binding/result **exposure** transition: consumer incarnation, original authorized native occurrence + args identity, R-X slot and protected retained-result/use predecessor. Every H for a burned slot refuses. Existing same-ID envelope retry semantics ([base:597][registration-release-rule]) do not supply durable once-only transport use: a reviewed independent re-exposure occurrence/slot and authorization would be required, never one invented per retry/H. Until that contract/format exists admission stays closed. |
| Existing refusals | Registration helper codes above, current enrollment/generation/binding/custody refusals, `request_conflict`, `state_capacity_exceeded`, `audit_unavailable` for unknown durable result/use; no new wire members or codes. | Preserve same plus `request_expired` and original deadline refusal. After possible bytes, close/contain ambiguous exposure rather than claiming a clean typed no-effect error ([server.go:407][transport-write]). Lost reply recovers the exact pre-send authorization and any known delivery observations without retransmission. A missing later delivery record means unknown delivery, never unused credit; any subsequent exposure requires its own independently authorized window. |
| macOS | Continuous clock/boot/D, original staged artifact and interval, exact generation/Store/enrollment exclusion, checked full-file and namespace/use durability all required. Linux generation/credential/custody paths and current receipt literal do not qualify Darwin; `handoff_unqualified`. | Same pre-send durable authorization, stable burn, separate send bound, post-delivery accounting-failure control and no recovery resend as Linux, plus native peer/connection binding, partial delivery containment and independent stop/executor exclusion on Darwin. Linux socket behavior supplies no Darwin timing/storage proof; receipt representation and endpoint remain unqualified. |

R-X specializes the [broker's durable-success rule][r6-success] without weakening
peer success. The proposed next owning exposure transition must retain the
original logical operation/window/slot and unused predecessor, exact encoded
response frame, retained result, native arguments/binding, current authority and
peer/connection identity, original boot/run/epoch, interval/A/expiry and D.
Commit that exact one-attempt authorization with its durable burn, recovery
bindings and required barriers/readback before the first byte. This is local
release readiness, not a claim that delivery has occurred. For R-X the durable
committed outcome is this one-attempt authorization, never a claim of delivery;
the generic post-act outcome rule must not introduce a required post-send
durability step. Burn alone or an audit append is insufficient. No new wire
field or separate use ledger is allocated here; next-format/capacity/custody review remains mandatory.

Reserve positive enforced subbounds `f_release` from m through that durable
pre-send endpoint and `g_send` for the actual send, including pauses/delegation
until the last authoritative byte leaves. Require `f_release+g_send<=f` and
`m-s+f_release+g_send+epsilon<=T`, with
**`m+f_release+g_send+epsilon<D`**, plus the unchanged authority/expiry predicates.
The timed R-X endpoint includes precommit and send, not later nonauthoritative
delivery bookkeeping. Both bounds consume the original allowance; there is no
extra read, refreshed receipt, start or D after precommit. Continuous final exclusion and qualified
stop/deadline enforcement cover the executor through send completion. Ordinary
socket deadlines and a post-send clock check do not establish g_send. If either
bound, exact peer binding or pre-send durability cannot be qualified, R-X is
**unavailable (`handoff_unqualified`) on Linux and macOS**.

Only the same still-live admitted call may attempt the send after precommit.
A crash before the first byte, partial send, lost reply or failed later delivery
accounting keeps the stable original window burned. Recovery reports retained
authorization and known/unknown delivery status; it never sends again. A complete
frame followed by delivery-accounting write, sync or readback failure already
has its required durable release/use endpoint: retain it, do not report a clean
no-effect failure, unburn, or require a later record to validate the peer's
success. If the owner requires a post-send record for success, this protocol
cannot satisfy that requirement and R-X stays unavailable pending a reviewed
peer protocol; weakening peer success is an owner decision, not a fallback.

A/P/R-S check: as specified, A advances its admitted tail/reports qualified
append success only after full frame/use/rotation durability; P opens authority
only after complete root/use/cleanup and required independent pre-release
custody; R-S returns a private release candidate only after retained result/use
is durable and grants no transport authority. None places required durability
after an authoritative success response. These are proposed admission conditions,
not proof that today's files are atomically invisible: if an audit reader, root
reader or result consumer can treat intermediate bytes as authority, its window
stays unavailable. All three remain `handoff_unqualified`; R-X's later actual
exposure requires the distinct pre-send endpoint above.

### Paths that do not yet consume these handoffs

| Path | Anchored scope and remaining condition |
| --- | --- |
| K3 message issuance/receipt/actual release | The [adapter's K3 row](keymaker-time-adapter.md#b-1-inactive-consumer-and-fixture-integration-plan) remains slice C: A/P cover constituents only. Its exact authenticated interval/receipt mapping and method-specific visibility/use endpoint are not supplied by R-S/R-X's purpose-2 `sign_registration` tuple. `TestQualifiedTimePendingK3Receipt` stays pending; activation stays closed, not covered by analogy. |
| Public key, hello and refusal response | These do not consume a QT-2c handoff in the current API. Ordinary native release invokes its callback ([native.go:715][native-release], [server.go:397][transport-write]); hello uses the ordinary success fence and refusals use their error path ([server.go:347][ordinary-response]). Generation/custody/audit and their original deadlines remain mandatory where applicable. If qualified time is claimed for later exposure, first supply its own native operation/window/use endpoint; A is never transport authority. |
| Ordinary SSH signature transport | No time-bearing registration proof or QT-2c handoff is consumed: private SSH signing precedes the generation -> Store -> audit -> actual release chain ([engine.go:267][ssh-release]). Its audit's time belongs to A; that does not make the signature write an A act. Original generation/custody/deadline checks remain mandatory, and any future qualified transport use needs its own profile. |

The consuming profiles require additional **PENDING / NOT RUN** paired native
controls: `QT2cEnrollmentIssueEndpoint` (proposed original 60-second budget, L_issue
substitution, blocked output/fence cleanup), `QT2cEnrollmentConsumeEndpoint`
(proposed original 10-second reload-through-swap budget, invalidation before
checks, pause at ledger/cleanup/swap, no approval replay),
`QT2cRegistrationStageEndpoint` (immutable staged bytes/original A through
retention), and `QT2cRegistrationReleaseEndpoint` (enrollment change, U=expiry/A,
post-audit pause, partial transport, lost reply and replacement H). Each pairs
the same on-time authorized case, exact retained state and named narrowing
control removing the respective budget/issue-bound/invalidation/use/act check.
Apply the shared admission-order, post-m pause, restart and macOS controls below
to every consuming profile; no helper-only pass qualifies an endpoint.

[r6-alphabet]: https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/timeconf/receipt.go#L103
[r6-encoding]: https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/timeconf/handoff_linux.go#L158
[r6-operation]: https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/timeconf/receipt.go#L286-L296

[r6-success]: https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/docs/time-handoff.md#L148-L155

[command-context]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/cmd/keymaker/main.go#L43-L67
[enrollment-command-locks]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/reconcile_command_linux.go#L293-L334
[enrollment-confirm]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/reconcile_command_linux.go#L352-L401
[enrollment-bootstrap]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/reconcile_command_linux.go#L403-L412
[approval-ttl]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/approval_linux.go#L24
[approval-check]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/approval_linux.go#L87-L143
[approval-capacity]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/approval_linux.go#L149-L189
[enrollment-cap]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/store_linux.go#L22
[approval-publication]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/reconcile_command_linux.go#L441-L527
[approval-consume]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/approval_linux.go#L236-L259
[enrollment-startup]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/reconcile_command_linux.go#L562-L687
[enrollment-load]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/authority.go#L122-L210
[enrollment-reload]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/enrollment/authority.go#L96-L117
[proof-codes]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/registration/registration.go#L23-L32
[proof-clock]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/registration/registration.go#L77-L102
[proof-build]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/registration/registration.go#L156-L211
[proof-recheck]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/registration/registration.go#L127-L153
[proof-restore]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/registration/registration.go#L230-L296
[registration-stage]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/keymaker/registration.go#L101-L202
[registration-release]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/keymaker/registration.go#L205-L260
[native-timeout]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/spec/keymaker.md#L522-L525
[native-resource]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/spec/keymaker.md#L758-L790
[native-deadline]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/control/server.go#L207-L272
[transport-write]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/control/server.go#L380-L413
[ordinary-response]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/control/server.go#L329-L371
[ssh-release]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/keymaker/engine.go#L267-L315
[native-release]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/internal/keymaker/native.go#L628-L730
[registration-release-rule]: https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/spec/keymaker.md#L561-L602
[generation-budget]: https://github.com/relux-works/swarma-user-manager/blob/505fb9f55a6d4f3f71db49e5037cd863679a3e41/tools/genjournal/secure_linux.go#L13-L196

`TestQualifiedTimePendingAuditPreWindow` also stays pending. All four existing
PENDING rows keep their names and deliberate failures. Neither this document
nor a future arithmetic fixture closes them.

## Future paired controls

All rows below are **PENDING / NOT RUN**. They describe required future executable
claims and controls, not tests implemented by this docs-only change. Run the
applicable rows for A, P, E-I, E-C, R-S and R-X on Linux and macOS. Keep a nearby
on-time positive with the same
operation, evidence, locks and storage protocol; assert named refusal, no
forbidden act/release and exact provider/use/recovery post-state.

| Proposed named test | Negative and expected invariant | Positive / narrowing control |
| --- | --- | --- |
| `QT2cTransitionVersionMapping` | For every row of the one closed name table, literal slash, wrong version, mismatched prepare/encode values, swapped destination fields/window selectors and unregistered names refuse before burn/act; generic slash substitution must not admit another native label. | Every exact field/window/native-name tuple maps to its enrolled value at preparation and encoding and may pass alphabet/enrollment checks; protected receipt names remain unchanged. Remove exact field-scoped lookup while retaining alphabet validation: wrong-version/swapped-field assertions must fail. Alphabet-only checks are not native qualification. |
| `QT2cReleaseDurableBeforeFrame` | On Linux and macOS, deliver the full frame, then fail or crash each delivery-accounting write, sync or readback: the exact pre-send authorization/use endpoint must already be durable; window remains burned and recovery never resends. Also fail each required pre-send barrier: no response byte may leave. | Same authorized frame commits all release/use bindings before the first byte and sends once under f_release/g_send within original D. Move a required success binding after the frame: the crash-reopen durable-authorization assertion must fail. Separate late-send/pause controls must prevent late bytes, not just suppress a local success. |
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
   retention. Option (d)'s trust boundary must hold throughout every consuming window.
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
