# Linux fixture qualification

The core implements surface A and is tested with injected generation authority.
The production command refuses `generation_source_unavailable` until the
user-manager publishes its journal and ordering contract. There is no static
UID fallback, production fixture switch, native control socket, enrollment
loader or registration helper. The read-only generation adapter is a later task.
The implementation reference is `spec/keymaker.md` at `25ea2ad`.

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
lock, startup durably writes an empty snapshot before creating the audit
directory and journal. A pre-created audit directory, even empty, is retained
evidence and cannot authorize first use. Subsequent startup requires both a
valid snapshot and retained, replayable journal evidence. Missing, unsafe,
incomplete or corrupt evidence fences admission; initialization interrupted
between these steps also requires operator recovery.

The snapshot determines bindings, tombstones and issued registration numbers.
The journal independently vetoes admission when evidence is unavailable; it
never reconstructs a snapshot or grants registration authority. Recovery requires
the operator to restore and validate the intact pair from retained evidence
while the service is stopped. Deleting remaining evidence to obtain an empty
directory is not recovery. No automatic reconciliation or re-admission occurs.
These checks cannot detect rollback of a complete, internally valid pair without
an independent checkpoint. Native lifecycle/audit transactions remain K1b work.

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
Surface A needs no registration-group socket; the harness verifies group access
but does not implement surface B's group-restricted socket setup.

Owner rollback first removes the sudoers drop-in, then deletes the two test
accounts and test group. Because the window is shared and has no state file,
the owner must inspect ownership and confirm all consumers are idle before
removal. Runner cleanup never removes these shared resources, its configuration
or retained reports.

## Remaining qualification gates

The real multi-UID window has not been exercised. Production generation-journal
ordering, native mutations/helper/enrollment, deployment and root provisioning
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
catalog table. The coverage document maps every vector, declares K1b rows, and
records eight narrowing mutants; it does not claim a killed mutant
for every implementation surface. No prior committed implementation reviewer
tests existed. Existing vector and specification tooling remains unchanged.

## Dispatch interpretation

Surface A has only SSH opcodes, with no named decrypt operation. All unsupported
opcodes use section 6's `agent_message_unsupported` audit code and SSH failure;
native JSON is never dispatched as a native method on this socket. No decrypt
branch was added to recognize a method that this protocol does not have.
The task's conditional `operation_unsupported` decrypt rule therefore has no
surface-A method to apply to; that code belongs to native unsupported methods.
The command-line `decrypt` token is invalid usage (exit 2). This interpretation
preserves the specification's opcode contract and keeps decryption outside v0.
