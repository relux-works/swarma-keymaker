# Local enrollment authority

This Linux package supplies the caller interfaces for the pinned registrar
packages. Enrollment parsing, publisher verification, snapshot phase ordering,
current record selection, name syntax/ownership and historical rollback rules
run in the registrar implementation. There is no Keymaker enrollment loader.
This package performs no signing and does not establish a station binding.

The entry points are:

```go
func New(configPath string, files Files, reconcile Reconciler) *Authority
func (a *Authority) Reload(ctx context.Context) Code
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
  "revision": "<approved-full-lowercase-commit-id>",
  "publisher": "ed25519:<canonical-unpadded-base64url-public-key>",
  "audience": "carrier.example.invalid",
  "registry": "/var/lib/enrollment-registry.git",
  "state_dir": "/var/lib/keymaker/enrollment",
  "stations": {"sample": true},
  "generations": {"30001": "00000000000000000000000000000001"},
  "first_use": false
}
```

The config is a regular nonsymlink root-owned file without group/world write;
all ancestors must be protected root-owned directories. Reads use `O_NOFOLLOW`
and check the opened inode. The approved revision is an exact 40- or 64-digit
commit ID, never a ref. The local registry is the explicit absolute Git directory
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
caps remain the registrar's 10,000 records/16 MiB. Reload has a ten-second context budget for Git work and lock waits.

## Durable state and reconciliation

The state directory must already exist, mode 0700, owned by root or the dedicated
service UID, outside disposable caches. Protected ancestors can be root- or
service-owned. State comprises `high-water.json`, a consumed-bootstrap marker
`accepted`, and `high-water.lock`. High water retains the accepted revision,
per-host highest sequence/ID/tombstone, complete sequence-ID history, and
permanent key/name ownership. A locked compare-and-swap publishes a temporary
file with file fsync, rename and directory fsync. Before any temporary high-water
file is created or written, the bootstrap marker's directory entry is synced,
then its contents are written, synced and closed, and the directory is synced.
An empty/partial marker or orphaned temporary file is retained attempt evidence,
never a new bootstrap. Failed writes are not cleaned up by deleting that marker.

An initial empty state requires the protected `first_use` decision. Disable that
bootstrap decision after initial acceptance. Missing state with its marker or
retained in-process evidence, malformed state, a mismatching CAS or restored old
state fences admission. Persisted state (including nested registrar high-water
members) and operator approval inputs use the same exact, case-sensitive member
checks as configuration. Integer history keys also require canonical decimal
spelling, so distinct JSON keys cannot collapse into one sequence entry.
The service never obtains `Reconciled=true` from mere
local-file readability. The `Reconciler` receives a copy and must establish
freshness from independently trusted evidence. A nil reconciler refuses an
existing-state restart. Successful in-process commits retain the known-latest
state for subsequent reloads. `StateDigest` can identify that state; calculating
a digest from the local file does not itself establish freshness.

Any failed reload withdraws the old snapshot immediately. A normal validation
failure can recover only with a fully valid reload. **Any Commit error poisons
that Authority instance:** another live reload cannot recover it. Startup with
independent reconciliation is required. In particular, directory fsync can fail
after rename: the replacement may already be visible and its durability is
indeterminate. No all-error rollback guarantee or compensating-rename guarantee
is claimed. This follows the [pinned registrar Store contract](https://github.com/relux-works/swarma-registrar/blob/fd2df68e861d45c955efa250ede342bc04468066/registry/doc.go):
a Commit error returns neither snapshot nor replacement high water, durable state
is indeterminate, and admission stays fenced until operator reconciliation.

Every restart needs a new operator decision; a local file alone never sets
`Reconciled=true`. `OperatorReconciler` is the only shipped reconciliation policy.
Create a fresh `NewOperatorReconciler(approvalPath, nil)` for each process start,
pass it to `New`, and expose its public `Challenge()` to the trusted operator
interface. After reconciling the actual latest approved revision, history,
tombstones and freshness, the operator supplies a protected root-owned file:

```json
{
  "startup_id": "<this-startup-Challenge-value>",
  "state_sha256": "<StateDigest-of-the-reconciled-high-water>"
}
```

The file can live at `/etc/keymaker/enrollment-reconciliation.json`, with the
same protected-file rules as the pin configuration. The digest identifies the
complete state, not just its revision. For an unchanged file written by this
store it is also the SHA-256 of the exact `high-water.json` bytes. The operator
must establish freshness before approving that digest; merely copying a local
file hash is not reconciliation. Earlier-start approvals, wrong digests and
unsafe files cannot authorize a restart. Reload after the new approval performs
full validation again. There is no service CLI yet; this root input and the Go
API are the integration contract. An external-witness policy is not shipped.

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
is disabled. All 114 negative and 25 positive published rows run, with no deferred
conformance rows. The ten codec controls use the public codec; the 129 registry
rows use the production Git verifier, ancestry and CAS store. Fixture revision
labels are instantiated with real signed Git object IDs while preserving the
specified equality/ancestry/approval relationships. Signed enrollment bytes and
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
