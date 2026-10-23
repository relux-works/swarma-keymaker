# Linux fixture qualification

The core implements surfaces A and B with injected generation authority in
tests. The production command refuses `generation_source_unavailable` until the
authoritative generation journal and ordering contract are published. There is
no static UID fallback or production fixture switch. Enrollment and the
registration helper remain outside this integration. The implementation follows
`spec/keymaker.md` at the integration base and its decided operator-principal
and signed-act gates.

## Single UID

`TestRealClients` starts the actual server/engine, loads a public fixture seed,
uses a durable journal and obtains credentials with Linux `SO_PEERCRED`.
Stock OpenSSH and Git sign and independently verify the exact derived fixture
key. Other namespaces and raw data refuse on that same socket. Every Git and
OpenSSH invocation uses an allowlisted environment, temporary HOME, disabled
system/global Git configuration and only the fixture socket. The Git
verification checks the exact fixture fingerprint, so a host key cannot pass.
No private host key or production service path is used.

`TestReleaseFences` pauses signing and commits revocation, retirement or
incarnation replacement before release. It asserts the precise refusal, no
released signature and refusal audit on both in-flight and next requests.
`TestLiveConnectionInvalidation` additionally tests real idle connection closure.
These fake generation transitions do not qualify a cross-process journal adapter
or an operating-system account allocator. `TestAuditFailureClosesListener`
checks actual socket closure, no signature/state change, and the bounded
`audit_unavailable` service-health return on a journal fault.

## Recovery and refusal budgets

`TestMissingSnapshotRecovery` reproduces snapshot loss after durable revocation;
the intact control preserves the tombstone and advances the next issued number.
`TestCustodyStartupReconciliation` exercises the same store/journal opener used
by startup. First use requires a protected, completely empty state directory.
Configure `state_dir` as a dedicated binding/journal directory, with
`master_file` and `socket_dir` outside it; a pre-existing seed is not proof that
binding state is new. The production activation workflow must provision this
layout before the unavailable generation adapter can be enabled.
The state lock uses the directory inode without creating a file. Under that
lock, first use creates and syncs the protected audit directory, opens its
journal, commits version 1 for an explicit empty binding array, then writes the
snapshot. A pre-created audit directory, even empty, is retained evidence and
cannot authorize first use. Interrupted initialization requires operator
recovery. `OpenStore` opens this reconciled pair; its `Close` releases the owned
audit descriptors, while the caller retains the state directory and lock.

Every durable register, revoke and unbind/retirement transition increments the
snapshot version and commits a SHA-256 digest of canonical CCJ-1
`{version,next_registration_number,records,requests}`. The trusted audit record uses the
existing exact schema: `surface=control`, `operation=binding_commit`,
`domain=control`, `request_id=binding:<version>` and `payload_digest=<digest>`.
Other actor fields remain explicitly unknown. Replay requires binding versions
1 through the latest without gaps. The snapshot includes that record's
`audit_seq` and `audit_hash`; these references are excluded from the body digest
to avoid a circular hash. All snapshot members, including nested binding,
registrar, retained-request and caller fields, are required. An empty `records` array is valid; omission,
null, unknown members and case aliases refuse. Older snapshot formats without the required request array
also fence; there is no automatic upgrade that discards recovery evidence.

Write order is journal append and file sync, then exclusive `bindings.next`
creation, snapshot write and file sync, rename to `bindings.json`, and state
directory sync. A failure fences the running store. A crash before any journal
change leaves the previous complete pair. Rotation or seal failures also fence
under the journal's replay rules. A crash after journal append
but before snapshot replacement leaves an unmatched commit (or partial audit
record); a crash during snapshot writing also leaves an unresolved intent.
Either fences restart. After rename but before directory sync, restart admits
only whichever complete matching pair actually survived; a stale, absent or
partial snapshot refuses. The operation reports success only after both stores
are durable. A snapshot ahead of its journal also refuses.

Startup replays evidence read-only before opening or creating an audit writer.
It requires the latest binding commit's version, sequence, chain hash and body
digest to match the snapshot. This proves the referenced record exists and
rejects any later unreflected binding commit. Later ordinary audit records are
allowed. A populated or empty committed snapshot cannot accept a zeroed or
missing journal, or truncation before its referenced commit. Partial records
also refuse. Independently valid but mismatched files refuse
without rewriting evidence. `TestSnapshotJournalDivergence` retains the real
socket/Master signing reproduction and active signing control;
`TestBindingCommitRecovery`, `TestBindingCommitCrashWindows` and
`TestSnapshotSchemaRequired` cover the additional restore, crash and schema
boundaries.

The snapshot determines bindings, tombstones and issued registration numbers.
The journal independently vetoes admission when evidence is unavailable; it
never reconstructs a snapshot or grants registration authority. Recovery requires
the operator to restore and validate the intact pair from retained evidence
while the service is stopped. Deleting remaining evidence to obtain an empty
directory is not recovery. No automatic reconciliation or re-admission occurs.
These checks cannot detect rollback of a complete, internally valid pair without
an independent checkpoint; a test explicitly retains that limitation. Removing
a complete ordinary-audit suffix after the referenced binding commit likewise
needs an independent checkpoint for detection. Production generation/act verification remains a publication gate. The native
transaction and durable-result behavior below is fixture-qualified; local
commitments do not qualify the missing authority adapters.

`TestBindingHistoryUniqueness` rejects active or revoked predecessors hidden by
later unbound records. Retained registration numbers must increase in order;
each persistent path predecessor must already be unbound before a later
registration. Owner and lifetime remain immutable. The valid
`[unbound, unbound, active]` control signs for the latest principal and refuses
the older principals.

`TestFrameRefusalAccounting` uses real oversize frames and saturated dispatch.
With a fixed budget clock, 52 reconnects drain the real per-principal burst of
40, produce one overload indication, and count the remaining 11 refusals
without further journal writes. Restored credit admits a valid identity request.
`TestOverloadRefusalBudget` checks the framed-request overload path as well.
Framing, busy and normal requests share the global 200/s burst-256 and
UID/generation 20/s burst-40 work buckets. They charge before parsing, hashing,
signing or journal work. Over-budget requests never execute; they share a
separate global aggregate journal indication budget of 1/s, burst one, with
operation `overload` and no input digest. Further suppressed writes increment
`Engine.AggregatedRefusals()`, a process-local counter saturating at the largest
CCJ-1 integer. This counter is volatile telemetry, not a durable per-attempt
record. Allowed operation responses still require durable individual audit.
Socket framing/allocation and generation lookup at connection admission remain
bounded by frame size, connection caps and deadlines, outside these work buckets.
This is a bounded-write claim, not throughput or hard-sandbox qualification.

Startup validates the current registry and checks every binding's epoch,
registry revision and numeric path membership. `Registry.Extends` is a tested
update primitive; startup has no prior registry snapshot and does not call it.
Append-only name-history verification must be supplied by the trusted operator
registry update workflow; its production integration remains unqualified.

## Native integration and retained results

`TestNativeVectors` runs all 23 assigned native refusal/control pairs through
`NewDaemonServer` and actual kernel credentials, Master, paired state and audit.
Vector role equality is projected onto the current kernel UID and configured
operator; the suite never fabricates a kernel UID. Production `serve` uses the
same constructor but cannot pass its unavailable generation gate. Positive
signed-act fixtures implement a trusted verifier interface; no wire object or
boolean supplies authority. Production always supplies nil and refuses
persistent operator revocation. `sign_registration` is unsupported and an
instrumented Signer observes zero signing calls beside a valid pubkey control.

Control admission passes the validated accept-time UID/generation to
`ServeConnAccepted`; the wire loop compares every identified tuple before ID
admission, including the first hello. Delayed notifications cannot authorize
adoption of a new generation. `TestNativeAcceptTupleBeforeHello` pairs a changed
incarnation with unchanged and fresh-connection controls; the changed socket
retains no hello ID. `TestAcceptedTupleBeforeHello` also checks changed UID and
missing accepted generation at the transport boundary.

Hello needs no binding. The first self `pubkey` pins its registration number
and atomically subscribes to that binding's revocation/unbind while holding the
Store lock. Revocation closes idle sockets; synchronous request, transaction
and release checks reject an obsolete pin even if notification lags. The binding
may be replaced only on a fresh connection. `TestNativeConnectionBindingPin`
performs real revoke/re-register requests and preserves the fresh-connection
control. `TestNativeHelloDoesNotPinBinding` shows that hello-only sockets can
first use a later registered self binding, then close on its revocation.
An operator using only hello and mutations has no station binding requirement;
mutation targets do not pin its self identity. Its first self pubkey does.
The configured operator tuple gates all mutations.
Register and ephemeral cleanup use `GenerationSource.WithEvidence` to hold
caller and target generation evidence under one retirement barrier; this avoids
nested authority lookups or check/write races. Cleanup requires that exact target
to be retiring/removed and the operator to be the original registrar. A future
authoritative adapter must implement that multi-principal ordering contract,
as well as `WithActive`; the unavailable adapter grants neither.

Hello and self-read success release occurs inside `WithActive`, final Store
checks and durable audit. Each mutation uses one `WithEvidence` release barrier
with the exact predicates carried from its fresh effect: active caller and
active register target, or exact retired target for ephemeral cleanup. Signed-act
operator revoke requires the caller predicate and verified act for its specific
binding, without inventing an active-target requirement. Exact historical
replays use current caller authority and their retained original result; they
never re-execute the effect or carry a stale fresh-target predicate.
`TestNativeMutationReleasePrincipals` checks caller retirement, target retirement
and target reuse before the actual write; `TestNativeMutationReleaseWins` checks
both principals and the identical-principal case with the write already inside
the barrier. `TestNativeEphemeralReleaseEvidence` covers retired target reuse,
and `TestNativeMutationHistoricalRelease` keeps same-connection historical
retry semantics beside a rejected new ID. A committed effect remains durably
recoverable if its first response loses the release race. `TestNativeReleaseFence`
covers hello and pubkey in both orderings. Its watch notification is deliberately delayed to isolate the
actual final barrier from the independent idle closer; authority still changes
before the retirement-wins barrier. These controlled orderings do not qualify
cross-process journal ordering.

`control.sock` is initially bound inside a newly created 0700 staging directory,
then assigned and verified as exactly 0660, service-owned and configured-group
owned before rename publishes it. No unassignable group or unsafe existing path
can trigger a 0666 fallback. Both listeners share 128 connections, 8 per UID,
16 active requests, the engine rate buckets, the audit journal, overload
aggregation and health shutdown. Native mutations additionally charge 2/s,
burst 4, including exact retries and conflicts. Deterministic saturation tests
exercise both dispatch branches; this is not a throughput/RSS qualification.

Retained entries contain caller UID/generation, ID, method, complete canonical
params, status and original result. Canonical arguments are stored as a JSON
string and decoded/validated on startup so snapshot nesting cannot reduce the
wire's permitted argument depth. The protected state stores these arguments;
the audit contains only their digest, never raw evidence. Transport timeout is
excluded from deduplication. Different arguments/method under the same tuple/ID
refuse; exact mutation retries return the original result even after later
binding transitions, but require fresh current operator authority. Successful
hello/pubkey IDs are also retained and cannot be reused in their generation.
A new generation has an independent ID scope. No ID expires or is reclaimed.

Admission preflights at most 65,536 retained requests and 256 MiB of combined
encoded binding/result snapshot before any new intent or effect. These are
storage bounds, not a claim that heap use is at most 256 MiB. Budget exhaustion
refuses `state_capacity_exceeded`; deployment memory/load qualification remains
pending. Native mutations durably audit operation intent, commit a pending ID
with unchanged bindings through the journal-first pair, then commit binding
effect and result in the same second paired snapshot. A pending intent fences
the entire service on restart, a conservative extension of the affected-binding
requirement; it is never reported as absent. A completed effect whose response
was interrupted retains its result. A journal ahead of either snapshot fences.
The journal does not reconstruct results. `TestNativeTransactionCrash`,
`TestNativeDurableRetries`, `TestNativeConcurrentRetry`,
`TestNativeCanonicalRetainedArguments` and `TestNativeRetainedSchema` cover these
boundaries. Complete-pair rollback still needs an independent checkpoint.

## Reusable multi-UID window

The `multiuid` build tag retains real second-UID cases in `TestMultiUID`:
foreign key, unbound UID and retired generation, each followed by a fresh active
control. The suite also signs as the other configured client and checks the
actual kernel UID, exact journal verdict and unchanged bindings. No test is
skipped. The compiled runner reports PENDING before invoking this suite when
provisioning is absent. Compiling the tagged suite is not a live test pass.

After the owner provisions the shared test window, the runner supplies its own
readable JSON configuration. The minimal setup writes no root state file or
runner configuration. Using the section 12 defaults, for example:

```json
{
  "runner_user": "<runner>",
  "client_a": "platform-test-a",
  "client_b": "platform-test-b",
  "registration_group": "platform-test-reg",
  "scratch_dir": "/tmp"
}
```

Replace `<runner>` with the actual unprivileged account. Names are
configuration, never compiled into the harness. All accounts must
have distinct nonzero UIDs. The runner must be the current user; only A belongs
to the test group. Pre-provisioned sudo permission must allow `sudo -n -u A/B`
and runner-as-self with the test group. Optional `runner_uid`, `client_a_uid`,
`client_b_uid` and `registration_gid` pin numeric IDs. UID resolution here checks
the test window only; it never supplies generation authority to the daemon.
The runner does not create or remove accounts, groups or sudoers entries.

The scratch parent must already allow both clients to traverse to the fixture
socket and execute the test binary. Private home-directory ancestors may prevent
this; the runner never changes their permissions. Fixture master/state paths
remain 0700 with 0600 files; only the run directory, test binary and socket
subdirectory are traversable. The test seed is public fixture data.

From the repository root, set `SCRATCH` to an existing absolute build/log
scratch directory and `WINDOW_CONFIG` to the owner's configuration:

```sh
go build -o "$SCRATCH/keymaker-window" ./cmd/keymaker-window
"$SCRATCH/keymaker-window" -config "$WINDOW_CONFIG" -check
"$SCRATCH/keymaker-window" -config "$WINDOW_CONFIG"
make test-multiuid SCRATCH="$SCRATCH" WINDOW_CONFIG="$WINDOW_CONFIG"
```

The direct runner is the canonical interface: 0 pass, 1 failure, 2 malformed
usage/configuration and 3 PENDING. PENDING prints exactly
`PENDING: test window not provisioned` on stderr. Make prints the runner's
status but normally exits 2 for either failure or PENDING. Call the runner
directly to distinguish these outcomes. None is converted to success.

Each run records its canonical work path, owner, device/inode and random token,
and its direct test child's PID/start identity. Clients exit themselves within
five seconds and create no child processes or files. The runner waits for its
child, syncs a retained report outside the work tree, checks directory/manifest
identity, then removes only its own tree. A report or identity failure retains
the work tree. There is no pattern-based process killing or global cleanup.

## Alignment with specification section 12

Section 12 describes the minimal shared window: two nonroot system test
accounts, only A in the test group, and the root-owned 0440 sudoers drop-in
`/etc/sudoers.d/agent-platform-test`. It does not require a root state file or
root-owned numeric-pinned runner configuration. The runner accepts names-only
readable JSON; numeric pins and root ownership are optional hardening. It still
checks distinct nonzero UIDs, the current runner, sudo readbacks and A-only
group membership. These checks establish test provisioning, never production
generation authority or a change to service ownership rules.

The canonical `keymaker-window` command creates its own directory, records
its own process and automatically retains a durable report outside that
directory before cleanup, as described in section 12. There is no standalone
cleanup command for abandoned runs. Interrupted trees remain for owner inspection;
the runner never guesses that another process or directory belongs to it.
`TestMultiUIDControl` also runs through the canonical runner's existing
`^TestMultiUID` filter. If necessary it invokes the same compiled test under the
already-authorized runner-as-self test-group sudo rule, then binds the real
0660 control socket with that primary group. Client A exercises foreign-UID,
unbound and retired refusals, each beside an active own-key control. Client B
must receive kernel EACCES before any daemon audit entry. This uses no new
sudo permission or account mutation. Both the group child and clients are
bounded direct processes with recorded PIDs and timeouts. These tests are
compiled but live execution remains PENDING without the provisioned window.

Owner rollback first removes the sudoers drop-in, then deletes the two test
accounts and test group. Because the window is shared and has no state file,
the owner must inspect ownership and confirm all consumers are idle before
removal. Runner cleanup never removes these shared resources, its configuration
or retained reports.

## Remaining qualification gates

The real multi-UID window has not been exercised. Production generation-journal
ordering, signed operator acts, helper/enrollment, deployment and root provisioning
remain outside this change. There is no macOS qualification.

Process startup disables core dumps and dumpability, caps descriptors at 512,
uses one Go scheduler CPU, a 256 MiB Go soft memory limit and a 64-thread runtime
cap. The specification's hard memory/task/CPU quotas and network-egress denial
require the separately provisioned service sandbox; these Go settings alone
are not equivalent hard limits. Master locking is attempted and readiness would
report the actual result; Go/crypto stack and heap copies make zeroisation best
effort. The system UTC clock is the production audit trust input; an injected
uncertain clock records null time and an unknown result. Local hash-chain audit
cannot detect malicious rollback or rewriting without an independent checkpoint.

The brief supplies vector rows and scope clauses, but no separate attack-surface
catalog table. The coverage document maps every vector, declares deferred helper rows, and
records seventeen narrowing mutants; it does not claim a killed mutant
for every implementation surface. Existing committed wire/core reviewer tests are retained under their original
names; the narrow validation does not substitute for the reviewer's full suite. Existing vector and specification tooling remains unchanged.

## Dispatch interpretation

Surface A has only SSH opcodes, with no named decrypt operation. All unsupported
opcodes use section 6's `agent_message_unsupported` audit code and SSH failure;
native JSON is never dispatched as a native method on this socket. No decrypt
branch was added to recognize a method that this protocol does not have.
The task's conditional `operation_unsupported` decrypt rule therefore has no
surface-A method to apply to; that code belongs to native unsupported methods.
The command-line `decrypt` token is invalid usage (exit 2). This interpretation
preserves the specification's opcode contract and keeps decryption outside v0.
