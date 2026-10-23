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

## Reusable multi-UID window

The `multiuid` build tag retains real second-UID cases in `TestMultiUID`:
foreign key, unbound UID and retired generation, each followed by a fresh active
control. The suite also signs as the other configured client and checks the
actual kernel UID, exact journal verdict and unchanged bindings. No test is
skipped. The compiled runner reports PENDING before invoking this suite when
provisioning is absent. Compiling the tagged suite is not a live test pass.

The owner supplies a JSON configuration, for example:

```json
{
  "runner_user": "test-runner",
  "client_a": "test-client-a",
  "client_b": "test-client-b",
  "registration_group": "test-registration",
  "scratch_dir": "/tmp"
}
```

Names are configuration, never compiled into the harness. All accounts must
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

## Differences from specification section 12

The task permits the minimal names-only, pre-provisioned window. This runner
therefore accepts runner-readable configuration without requiring section 12's
root-owned numeric-pinned config or root state file. Numeric pins are optional;
nonroot identities, current runner, sudo readback and asymmetric group membership
are still checked. That is a test-harness provisioning relaxation, not production
generation authority or a change to service ownership rules.

Section 12 sketches `keymaker-integration run/cleanup` with caller-created
work directory and report path. The implemented command is `keymaker-window`,
which creates its own directory, records its own process and automatically
retains a report outside that directory before cleanup. There is no standalone
cleanup command for abandoned runs. Interrupted trees remain for owner inspection;
the runner never guesses that another process or directory belongs to it.
Surface A needs no registration-group socket; the harness verifies group access
but does not implement surface B's group-restricted socket setup.

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
records the two requested narrowing mutants; it does not claim a killed mutant
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
