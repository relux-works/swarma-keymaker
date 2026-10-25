# Local enrollment authority

The proposed [option C witness supplement](../../spec/keymaker-witness.md)
describes future external freshness and C-specific consumption ordering; the
option A startup consumption contract below remains unchanged and implemented
without a witness.

This Linux package supplies the caller interfaces for the pinned registrar
packages. Enrollment parsing, publisher verification, snapshot phase ordering,
current record selection, name syntax/ownership and historical rollback rules
run in the registrar implementation. There is no Keymaker enrollment loader.
This package performs no signing and does not establish a station binding.

The entry points are:

```go
func New(configPath string, files Files, reconcile Reconciler) *Authority
func (a *Authority) Reload(ctx context.Context) Code
func (a *Authority) Close() error
func (a *Authority) Authorize(ctx context.Context, peerUID uint32,
    generation, key, name, aud string, issuedAt, now time.Time) (EnrolledKey, Code)
func NewOperatorReconciler(path string, files Files) (*OperatorReconciler, error)
func (r *OperatorReconciler) Challenge() string
type Reconciler interface {
    Check(context.Context, *registry.HighWater) error
}
```

`files == nil` selects the production `LinuxFiles` implementation. Fixtures
substitute ownership metadata; production must never install a fixture adapter.
`key` is the trusted core's derived purpose-2 public key, not a request selector.
`issuedAt` and `now` come from the trusted clock. Returned `EnrolledKey` contains
only the exact public key, host, record ID, revision, configured audience and
window bounds. The future core integration must establish an active binding,
construct/sign the body and repeat authority at its final release barrier.

## Protected configuration

The JSON file contains exactly these members; unknown, case-aliased and duplicate members
are refused. This shape shows placeholders, not deployable verification keys:

```json
{
  "maintainers": ["ssh-ed25519 <canonical-base64-SSH-public-key>"],
  "object_format": "sha1",
  "revision": "<approved-full-lowercase-commit-id>",
  "publisher": "ed25519:<canonical-unpadded-base64url-public-key>",
  "audience": "carrier.example.invalid",
  "registry": "/var/lib/enrollment-registry.git",
  "state_dir": "/var/lib/keymaker/enrollment",
  "stations": {"sample": true},
  "generations": {"30001": "00000000000000000000000000000001"},
  "service_uid": 30001
}
```

The config is a regular nonsymlink root-owned file without group/world write;
all ancestors must be protected root-owned directories. Reads use `O_NOFOLLOW`
and check the opened inode. The required protected `object_format` is exactly
`sha1` or `sha256`, with no default, trimming or inference from an ID's length.
Missing, empty, unknown or nonstring values refuse as `enrollment_unverified`.
The approved revision, retained revision, commit parents and all tree/blob IDs
must be exactly 40 lowercase hex digits for `sha1`, or exactly 64 for `sha256`,
never a ref. The protected pin must match the registry's Git object format.
Every registrar Loader receives that same pin; a missing/unknown format or
cross-format revision refuses as `registry_unavailable` upstream. The local
registry is the explicit absolute Git directory
of a root-managed bare repository or `.git` directory. Its files and directories
must also be root-owned, nonsymlinked and not writable by group/others. External
object alternates are refused. Working-tree bytes never provide authority.

The maintainer allowlist supports OpenSSH Ed25519 public keys; optional comments
carry no trust. The offline publisher is a separate pinned Ed25519 key. The
canonical ASCII Matrix server name is local policy. `stations` independently
classifies every host; a signed record cannot classify itself. The registrar
requires `uid_map` for a station and rejects the entire snapshot if it is absent.
`generations` is the root-controlled per-UID narrowing policy. A different or
unadmitted generation refuses until this file explicitly re-admits it.

`/usr/bin/git` reads commit/tree/blob objects using `cat-file` and tests ancestry
using `merge-base --is-ancestor`. Each subprocess has a three-second deadline,
a fresh environment, explicit Git/object directories, null global/system config,
disabled hooks, replacements, grafts, shallow metadata and lazy fetch, and no
allowed network protocols. No inherited `GIT_*` or SSH agent state is used.
Object hashes are checked, and SSHSIG verification happens in Go against the
allowlist in namespace `git`. Author text and embedded keys never establish trust.
Commit metadata is bounded to 1 MiB and tree metadata to 8 MiB; envelope aggregate
caps remain the registrar's 10,000 records/16 MiB. Reload has a ten-second context
budget for validation and durable-state lock waits.
Publishing the result also drains already admitted bounded release callbacks,
even after context expiry, so a failed reload always installs its fence.

## Durable state and reconciliation

The state directory must already exist, mode 0700, owned by root or the dedicated
service UID, outside disposable caches. Protected ancestors can be root- or
service-owned. State comprises `high-water.json`, a consumed-bootstrap marker
`accepted`, and `high-water.lock`. High water retains the accepted revision,
per-host highest sequence/ID/tombstone, complete sequence-ID history, and
permanent key/name ownership. A locked compare-and-swap publishes a temporary
file with file fsync, rename and directory fsync. During explicit initial publication, before any temporary high-water
file is created or written, the acceptance marker's directory entry is synced,
then its contents are written, synced and closed, and the directory is synced.
An empty/partial marker or orphaned temporary file is retained attempt evidence,
never a new bootstrap. Failed writes are not cleaned up by deleting that marker.

The service never bootstraps. Empty or missing high water, lock-only leftovers,
partial markers and orphaned entries always fence admission. The removed
`first_use` configuration member is unknown and refuses even when false.
First acceptance is an explicit operator action through
`keymaker enrollment reconcile --config /etc/keymaker/enrollment.json --bootstrap`.
It verifies the pinned
snapshot read-only, presents its full state digest and requires exact confirmation
before initial publication. Only a directory without any prior evidence is
eligible; failed attempts require another explicit operator decision or repair.
The service store opens an existing lock and performs CAS only against existing
accepted high water. It cannot create initial state or acceptance markers.
Missing state, a mismatching CAS or restored old state fences admission.
Persisted state (including nested registrar high-water
members) and operator approval inputs use the same exact, case-sensitive member
checks as configuration. Integer history keys also require canonical decimal
spelling, so distinct JSON keys cannot collapse into one sequence entry.
The service never obtains `Reconciled=true` from mere
local-file readability. The `Reconciler` receives a copy and must establish
freshness from independently trusted evidence. A nil reconciler selects the
one-use operator-command policy below; without its protected receipt, an
existing-state restart refuses. Successful in-process commits retain the known-latest
state for subsequent reloads. `StateDigest` can identify that state; calculating
a digest from the local file does not itself establish freshness.

While reload prepares a private candidate, new admissions wait with their own
request contexts; existing bounded releases finish on one consistent snapshot.
All pin, Git, validation and durable-state I/O runs outside the enrollment write
barrier. Reload takes that barrier only to publish the complete candidate or
failure fence. After a failed reload returns, no old snapshot is usable. A normal
validation failure can recover only with a fully valid reload. **Any Commit error poisons
that Authority instance:** another live reload cannot recover it. Startup with
independent reconciliation is required. In particular, directory fsync can fail
after rename: the replacement may already be visible and its durability is
indeterminate. No all-error rollback guarantee or compensating-rename guarantee
is claimed. This follows the [pinned registrar Store contract](https://github.com/relux-works/swarma-registrar/blob/fd2df68e861d45c955efa250ede342bc04468066/registry/doc.go):
a Commit error returns neither snapshot nor replacement high water, durable state
is indeterminate, and admission stays fenced until operator reconciliation.

Every restart needs a new operator decision; a local file alone never sets
`Reconciled=true`. `New(configPath, nil, nil)` selects the command-record policy.
The legacy explicit `OperatorReconciler` challenge adapter remains for callers
that implement their own qualified operator interface; its input is incompatible
with command records. Production callers should use the default policy.

## Operator reconciliation procedure

Use this procedure **before every enrollment-authority restart**, including a
restart after a failed commit. Stop the enrollment helper/daemon first. Every
`Authority` holds a shared `flock` on the state-directory inode from its first
reload until `Close`; stop serving and call `Close` at shutdown. The command
requires that inode's exclusive lock and also exclusively locks the
Store lock file. Initial publication creates that lock only after confirmation. A live or starting helper, another operator command, or an
active Store writer causes refusal. There are no PID-file or socket guesses.
The current `serve` entry point still refuses at the unavailable generation
journal gate; this procedure supplies the enrollment API's startup policy,
not a deployed daemon integration.

The protected pin config must include the actual nonzero `service_uid`. The
state directory must be mode 0700, owned by that service UID (so the service can
consume its one-use approval), with
**root-owned protected ancestors**. These stronger reconciliation rules prevent
the service from replacing the locked directory inode. Run the following single
command as the root operator, with the installed binary and protected pin path:

```sh
# Initial acceptance: the directory must have no prior state or other entries.
keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG" --bootstrap
# An operator interface can supply the independently approved full digest.
keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG" --bootstrap --confirm "$EXACT_STATE_SHA256"
# All later startups reconcile existing accepted state.
keymaker enrollment reconcile --config "$ENROLLMENT_CONFIG"
```

Bootstrap inspection is read-only: no lock, marker, state or approval is created
while displaying the snapshot or awaiting confirmation. The initial pin is the
first history anchor; there is no retained ancestor before initial acceptance.
The production verifier and registrar loader validate its signed snapshot with
an in-memory Store. Normal reconciliation and later service reloads retain the
production ancestry and monotonic-history checks. Bootstrap reports
`bootstrap: true`; normal reconciliation reports `bootstrap: false`.

Only a directory containing **no entries at all** qualifies for bootstrap.
A lock-only leftover is prior evidence, as are complete/partial markers,
high-water files, receipts, pending/orphan files and a root publication fence.
Bootstrap refuses all of them and directs the operator to normal reconciliation
or separate privileged repair. Even a failed attempt that left no evidence
requires a fresh explicit bootstrap invocation: the service always refuses
empty state. Stop a fenced helper too; it retains its lifecycle lease until Close.

After the full digest is confirmed and the pin/state are rechecked, bootstrap
holds both locks through initial state and receipt publication. New state, marker
and lock inodes are owned by `service_uid` with mode 0600; the receipt remains
root-owned and service-readable. The same publication code is used by the
initial-state fault and crash fixtures. A failure cannot supply usable startup
consent. A visible receipt is guarded by the root publication fence until its
fsync sequence and command output succeed. Require exit 0 before treating an
`approved` report as usable. A later crash may conservatively restore the fence.


Stdout is newline-delimited JSON, schema `version: 1`. The first object contains
`pin_revision`, `pin_sha256` (the canonical complete protected configuration),
`publisher_fingerprint` (`SHA256:` followed by lowercase hex over the decoded
Ed25519 publisher key), `audience`, `local_revision`, sorted `hosts` (host, seq,
id, revoked), `bootstrap`, `state_sha256`, `snapshot_sha256`, `evidence`, `match`, `reason`,
and `approved: false`. `state_sha256` hashes the versioned complete high-water
record, including sequence history and permanent key/name ownership. A human
summary and confirmation prompt go to stderr. Bootstrap-marker presence is
reported as evidence of prior acceptance; a partial marker, missing high water,
or any orphan/pending/unrecognized file refuses in normal reconciliation.
Never-used state requires the explicit bootstrap mode above.

Normal reconciliation reads state without creating a lock file or calling its
persistent Commit. It recomputes the pinned registry through the production Git verifier,
ancestry check and registrar loader, capturing proposed Commits only in
memory. An isolated fresh preview derives state from the pin without trusting
local history; its registrar `FirstUse` validation mode has only an in-memory
Store and cannot bootstrap local state. A separate retained-state validation
performs the real ancestry/history checks. Both must succeed. Local and proposed **complete** state must match, including the accepted
revision. Reasons distinguish changed revision, missing host, changed ID or
revocation, history/ownership mismatch and registrar rejection (including
rollback). It never silently advances a lagging accepted revision.

Independently establish that the protected pin represents the current approved
registry and that the retained history is the latest known state. This is the
operator freshness decision under interim option A; matching local bytes alone
cannot establish it. Type the exact 64-character `state_sha256`, then Enter.
For an operator interface that already made this decision, the same command
accepts `--confirm "$EXACT_STATE_SHA256"`. Whitespace, wrong/stale digests, EOF
without a digest and changed state/pin refuse. Policy and snapshot/state are
re-read after confirmation while the locks remain held.

Success emits a second JSON object with `approved: true` and exits 0. Exit 1
means refusal or I/O failure; malformed command flags exit 2. Start the helper
with the default reconciliation policy. It accepts only the command's strict
record with the current full state digest, **full pin digest and protected config
path hash**, a fresh random approval ID and the consumed ledger's random ID.
Both modes record `/proc/sys/kernel/random/boot_id`, trusted UTC and boot elapsed
time at confirmation. Approvals expire at ten minutes, including suspended time.
Startup refuses another boot, unavailable boot identity, an unsynchronized or
erroneous Linux clock (`adjtimex` query), backwards UTC/boot elapsed time, or a
UTC/boot elapsed discrepancy exceeding two seconds. This tolerance accommodates
clock slewing and sampling; boot elapsed time independently bounds the TTL.
Nanosecond timestamps are decimal strings to preserve exact integers in the
strict JSON format.

### Startup consumption contract

This state machine applies to a fresh Authority using the default command
approval policy. An already admitted Authority reload and explicitly injected
reconciliation policies do not consume command approvals.

- **Not begun:** only the exhaustive pre-lock gates below may refuse. They read
  no consent or retained-state contents, write nothing, and grant nothing.
- **Attempt begun:** acquiring the exclusive Store lock begins the attempt.
  Its first filesystem action is an atomic, non-replacing rename of
  `reconciliation.json` to `reconciliation.consuming`, followed by directory
  fsync. No receipt/state read, parsing, digest, pin, boot, TTL, clock, ledger,
  pending-marker or directory-evidence validation precedes that rename.
- **Invalidated:** validate the consuming inode, protected policy, retained state,
  receipt format/bindings/digests, boot identity, TTL and clock. Then append the
  approval ID with full write, file fsync and checked close. Unlink the consuming
  inode, check zero links, and fsync the directory before granting authority.
  Any refusal or crash after successful rename leaves consuming evidence or a
  consumed ID. No failure path restores consent or removes its evidence.
- **Granted:** the approval has been consumed exactly once. Another start needs
  a new confirmation. A leftover consuming file fences startup and BOTH command
  modes, even beside another receipt. Recovery requires a separate privileged
  investigation/cleanup preserving complete consumed IDs and retained history,
  followed by a NEW confirmation. Neither command clears this evidence; cleanup
  alone grants no consent.

Exhaustive pre-lock refusal list (each is a not-begun outcome):

1. **Lifetime/target guard:** this Authority is closed, has a prior indeterminate
   Commit failure, or a previously selected state-directory target changed.
   These in-memory guards inspect no consent or retained state and grant nothing.
2. **Protected config location:** the config or its ancestors cannot be read
   safely, it exceeds 1 MiB, its JSON has invalid syntax/duplicate decoded member
   names at any depth, or its `state_dir` cannot be extracted as one canonical
   absolute string. Only the protected config is read; no consent or retained
   state is read and nothing is granted. Other members' scalars remain opaque:
   canonical scalar restrictions, all other member/type checks and semantic
   pin/policy checks occur after invalidation, including refusal of fractions,
   exponent notation, unsafe integers and negative zero.
   The JSON syntax gate has a maximum nesting depth of 10000. A deeper document
   refuses before the Store lock and therefore leaves consent unconsumed, like
   any other pre-lock syntax refusal.
3. **Protected directory/lifecycle lease:** the state path/ancestors or opened
   directory inode fail ownership/type/mode/identity checks, cannot be opened,
   or its shared lifecycle lease is unavailable. Only directory metadata is
   inspected; no consent or retained state is read and nothing is granted.
4. **Existing Store lock acquisition:** protected parent/directory/lock metadata
   or opening/statting the existing regular lock file fails, or exclusive flock
   cannot be acquired. No lock file is created and no consent or retained-state
   contents are read; nothing is granted.
5. **Cancellation/deadline before lock:** an already canceled context, or a
   deadline/cancellation while waiting for the Store lock, refuses without
   reading consent or retained state, writing files, or granting authority.

There are exactly two retry windows in this local consumption contract: an
atomic rename failure with no filesystem effect, and a refusal on the exhaustive
pre-lock list. Both are indistinguishable from an attempt that never began;
a later start within the approval TTL may consume the unchanged approval at
most once. Every error after a successful rename is terminal for that approval.
The separately accepted whole-host/root restoration residual remains below and
in [UNRESOLVED_QUESTIONS.md](../../UNRESOLVED_QUESTIONS.md).

The operator creates and directory-fsyncs the service-owned mode-0600 ledger
under the publication fence; startup never creates, truncates or replaces it.
Appends use `O_APPEND`. Missing, substituted, malformed, hard-linked, or full
ledgers refuse after receipt invalidation. Entries are never pruned; the 16 MiB
bound requires separate operator recovery when exhausted. A crash after rename
leaves consuming evidence, or a consumed ID if the receipt was already removed.
Process-crash probes exercise these boundaries; physical power loss remains
unqualified.

A later restart needs a fresh command confirmation and random ID. Restoring a
root-owned receipt, or rolling state back to its approved digest, cannot revive
a consumed ID. Preserve the consumed record across recovery; restoring it too
can defeat local replay detection. The whole-host/root-surgery residual and
future external-witness requirement are recorded in
[UNRESOLVED_QUESTIONS.md](../../UNRESOLVED_QUESTIONS.md).

Approval publication uses an independently durable pending marker in the
root-owned pin-config directory (named from the full config-path hash), then a
full-write/file-fsync/close/rename/directory-fsync sequence. Every summary, prompt
and stdout error is returned. Final JSON and final summary must both succeed
before the fence is removed, in both modes. The service cannot
remove that root-directory fence. Any failure retains
the pending fence, even if rename made an approval visible. Removing the marker
is the final fallible action. Its removal is intentionally not fsynced afterwards:
a crash can conservatively resurrect the fence, never expose a candidate whose
publication was not synced. A failed command cannot clear a previous fence. An
already-present approval refuses replacement: consume it at startup, or investigate it through separate
privileged recovery if it is stale or damaged.

On a mismatch or interrupted-write fence, **leave the helper stopped** and
retain the JSON report and error. Investigate against independently trusted
registry history/backups. Repair or recovery is a separate privileged operator
action outside this command; it must preserve monotonic history, tombstones and
permanent ownership. Bootstrap cannot repair/reset prior state. Do not clear
evidence or edit approval/high-water files to force admission. After authorized
recovery, rerun this same procedure; no file editing is part of reconciliation.

## Check order and helper codes

Lookup the exact current key, check `Window.ValidAt(issuedAt, now)`, check host
revocation, then call snapshot name authorization with its configured audience.
Only then resolve integer UID, executable qualification, explicit names,
admitted generation and request audience. Request audience never changes name
validation. Any matched `exe` refuses even when an observed path would match;
there is no executable snapshot input or group-only fallback.

| Evidence or diagnostic | Helper code |
| --- | --- |
| Missing/unreadable protected config, registry directory or local state I/O | `enrollment_unavailable` |
| Unverifiable pin, unsafe config/source, failed Git object/signature binding, loader prerequisite/schema/ID/publisher/conflict/rollback failure, corrupt/missing evidenced state, unreconciled restart or Commit failure | `enrollment_unverified` |
| Station `uid_map` missing (`enrollment_malformed`, whole load refused) | `enrollment_unverified` |
| Current key absent or historical-only | `key_not_enrolled` |
| Either instant outside the exact half-open key window | `key_not_valid_now` |
| Verified tombstone | `host_revoked` |
| Registrar invalid name or denied ownership | `name_invalid`, `name_not_permitted` respectively |
| No matching UID row | `uid_not_permitted` |
| Matched row has `exe` | `enrollment_unsupported` |
| Name absent from the matched row | `name_not_permitted` |
| Generation differs from or is absent in protected admission policy | `generation_mismatch` |
| Request audience differs from protected audience | `audience_mismatch` |

These are helper responses, not changes to registrar diagnostic spelling.
`uid_map_required` was removed from the contract: station schema rejection
precedes local peer admission. Failed authorization returns no `EnrolledKey`
and never mutates durable state.

## Validation scope

`TestHelperVectors` executes 14 negative/control pairs from the authored refusal
file through real OpenSSH-signed Git repositories and the actual registrar loader.
`helper-missing-binding` and `helper-revoked-binding-fresh-connection` are deferred
to core integration. Fixture keys are generated in isolated temporary directories;
Git fixtures have no host SSH agent or host signing-key access. Fixture metadata
substitution does not qualify deployment ownership or real peer credentials.

Narrow package tests additionally cover pin provenance/content binding, isolated
Git environment, non-descendant pins, entry types/caps, time/name check ordering,
current-only keys, failed reloads, generation re-admission, rollback history,
tombstones, CAS, corrupt/restored state, interrupted writes and restart fencing.
`TestRegistrarEnrollmentConformance` discovers all enrollment rows in the local
pinned module directory obtained with `go list -m -json`. Test-time module fetch
is disabled. All 130 negative and 27 positive published rows run, with no deferred
conformance rows. The ten codec controls use the public codec; the 147 registry
rows use the production Git verifier, ancestry and CAS store. Fixture revision
labels satisfying the protected grammar are instantiated with real signed Git
object IDs while preserving the specified equality/ancestry/approval
relationships. Invalid and cross-format IDs are passed unchanged; both
protected formats use real signed repositories in their positive controls.
Signed enrollment bytes and
expected record IDs are unchanged. Aggregate repeats expand actual bytes under
distinct paths. Exact registrar codes, diagnostic-to-helper-code mappings,
installed/current high-water state, retained history and readiness are asserted
separately. These rows do not call `Authority.Reload`: local-source availability
mapping is observed by the separate paired helper tests through that public
entry point, never assigned from a fixture availability flag. This is registry
conformance, not HTTP, nonce, limiter, audit or binding qualification.

The runner discovers later published rows automatically after an explicit pin
bump. New external fixture inputs or event modes fail explicitly until supported;
no unrecognized row can silently pass. Unpublished rows are not claimed as run.

`Authority.WithAuthorized` checks the same rules as `Authorize` while retaining
the read barrier through a bounded callback. The daemon uses this to hold current
enrollment authority through actual helper response release. Callbacks must not
reenter Authority. `TestWithAuthorizedReleaseBarrier` proves rejection never
invokes release and a live reload waits for an admitted release before fencing.

`TestReloadPreparesOutsideReleaseBarrier` checks that pin I/O proceeds during a
held release while the swap waits, including failure fencing and valid recovery.
`TestEnrollmentGateDeadline` checks cancellation without callback effects and a
valid post-publication control. Admission cancellation maps to the existing
`request_deadline_exceeded` code. No lock-wait goroutines are left behind.

Each publication reserves admission for its already queued readers. A phase
counter distinguishes that finite cohort from later arrivals. The next pause
closes admission to new arrivals, admits the reserved cohort or accounts for
its cancellation, then proceeds with reload preparation. The final write barrier
still drains admitted callbacks before publication. Continuous readers cannot
extend the handoff or starve the writer. No sleep, yield or waiter goroutine
implements fairness. `TestAdmissionGatePublicationHandoff` checks cancellation
before/after publication and its unpaused control at one scheduler processor;
`TestAdmissionGateWriterProgress` checks sustained readers and 40 publications;
`TestAdmissionGateFailedPublication` checks that immediate valid recovery cannot
erase the failed fence for its reserved cohort.

## Offline pin configuration parsing

`ParseConfig([]byte)` exposes the same strict member, scalar and policy decoder
used after startup invalidation, with the protected loader's 1 MiB byte bound.
The release assembler uses it before copying optional enrollment.json. It reads
no files or Git objects, changes no retained state, consumes no approval and
grants no authority. Installed protection, signature/snapshot verification and
operator reconciliation still belong to the runtime paths described above.
