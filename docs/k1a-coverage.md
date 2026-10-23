# K1a coverage map

The original K1a implementation follows the normative reference at `25ea2ad`.
Its 31 executed pairs remain below. [K1b coverage](k1b-coverage.md) maps the
additional 23 native daemon pairs and 16 helper pairs; together the documents
cover the original 70 vector IDs plus the proposed custody refusal pair.

Each executed row runs `TestRefusalVectors/<id>/negative` first, then
`TestRefusalVectors/<id>/control`. Tests assert the exact code, no released
response on refusal, unchanged bindings, and the exact refusal audit. Audit
failure rows inject actual append/sync faults and assert closed admission;
the healthy control independently verifies a real Ed25519 signature. Successful
agent responses must contain exactly one fully consumed packet, the caller's
public key or a verifiable signature, and no additional fields/material.

The `binding_authorize` and `derive_path` rows exercise the production primitive
and common audited refusal path, not a client-selected binding/path endpoint.
Such endpoints do not exist on surface A. Their controls then execute a valid
engine signature. `ssh_agent` rows use actual frame parsing and engine dispatch.
Static connection rows are supplemented by controlled in-flight and real socket
invalidation tests; static inputs alone do not prove a race fence.

## Executed refusal pairs

| Row ID | Evaluation | Negative test (control replaces final `/negative` with `/control`) |
| --- | --- | --- |
| `binding-wrong-uid` | `binding_authorize` | `TestRefusalVectors/binding-wrong-uid/negative` |
| `binding-retired-generation` | `binding_authorize` | `TestRefusalVectors/binding-retired-generation/negative` |
| `binding-retiring-generation` | `binding_authorize` | `TestRefusalVectors/binding-retiring-generation/negative` |
| `binding-reused-uid` | `binding_authorize` | `TestRefusalVectors/binding-reused-uid/negative` |
| `binding-source-unavailable` | `binding_authorize` | `TestRefusalVectors/binding-source-unavailable/negative` |
| `connection-revoked-before_release` | `binding_authorize` | `TestRefusalVectors/connection-revoked-before_release/negative` |
| `connection-retired-before_release` | `binding_authorize` | `TestRefusalVectors/connection-retired-before_release/negative` |
| `connection-reused-before_release` | `binding_authorize` | `TestRefusalVectors/connection-reused-before_release/negative` |
| `connection-revoked-next_request` | `binding_authorize` | `TestRefusalVectors/connection-revoked-next_request/negative` |
| `connection-retired-next_request` | `binding_authorize` | `TestRefusalVectors/connection-retired-next_request/negative` |
| `connection-reused-next_request` | `binding_authorize` | `TestRefusalVectors/connection-reused-next_request/negative` |
| `derive-nonhardened` | `derive_path` | `TestRefusalVectors/derive-nonhardened/negative` |
| `derive-unknown-purpose` | `derive_path` | `TestRefusalVectors/derive-unknown-purpose/negative` |
| `derive-extra-level` | `derive_path` | `TestRefusalVectors/derive-extra-level/negative` |
| `ssh-raw-data` | `ssh_agent` | `TestRefusalVectors/ssh-raw-data/negative` |
| `ssh-namespace` | `ssh_agent` | `TestRefusalVectors/ssh-namespace/negative` |
| `ssh-userauth` | `ssh_agent` | `TestRefusalVectors/ssh-userauth/negative` |
| `ssh-reserved` | `ssh_agent` | `TestRefusalVectors/ssh-reserved/negative` |
| `ssh-short-digest` | `ssh_agent` | `TestRefusalVectors/ssh-short-digest/negative` |
| `ssh-trailing` | `ssh_agent` | `TestRefusalVectors/ssh-trailing/negative` |
| `ssh-flags` | `ssh_agent` | `TestRefusalVectors/ssh-flags/negative` |
| `ssh-foreign-key` | `ssh_agent` | `TestRefusalVectors/ssh-foreign-key/negative` |
| `ssh-add-identity` | `ssh_agent` | `TestRefusalVectors/ssh-add-identity/negative` |
| `ssh-remove-identity` | `ssh_agent` | `TestRefusalVectors/ssh-remove-identity/negative` |
| `ssh-remove-all` | `ssh_agent` | `TestRefusalVectors/ssh-remove-all/negative` |
| `ssh-lock` | `ssh_agent` | `TestRefusalVectors/ssh-lock/negative` |
| `ssh-unlock` | `ssh_agent` | `TestRefusalVectors/ssh-unlock/negative` |
| `ssh-add-constrained` | `ssh_agent` | `TestRefusalVectors/ssh-add-constrained/negative` |
| `domain-registration-on-agent` | `ssh_agent` | `TestRefusalVectors/domain-registration-on-agent/negative` |
| `audit-append-failure` | `audit_release` | `TestRefusalVectors/audit-append-failure/negative` |
| `audit-sync-failure` | `audit_release` | `TestRefusalVectors/audit-sync-failure/negative` |

## Rows outside the original K1a assignment

The original assignment excluded native control, helper and enrollment work.
Native control's 23 pairs are now exercised by K1b integration; the 16
`helper-*` rows now run through the daemon control socket. Their complete row
table is in [K1b coverage](k1b-coverage.md).

## Additional evidence and limits

| Claim | Named test/control | Limit |
| --- | --- | --- |
| Published hardened Ed25519 derivation | `TestPublishedDerivation` | All 12 published nodes, including chain/public values; chains exposed only inside tests |
| Scoped registry and path mapping | `TestRegistryPathVectors`, `TestRegistryRejectsInvalidHistory` | Five path controls, invalid history, duplicate/implicit allocations |
| Protected master storage | `TestMasterStorageGuards` | Owner/mode/parent/symlink/hardlink/type/length refusals and valid sign/verify |
| Persistent lifecycle/tombstones | `TestBindingLifecycle`, `TestPersistentRetirement`, `TestBindingRecoveryFences` | Trusted internal lifecycle, no native mutation or signed-act verifier qualification |
| Snapshot/journal recovery | `TestMissingSnapshotRecovery`, `TestCustodyStartupReconciliation`, `TestSnapshotJournalDivergence`, `TestBindingCommitRecovery`, `TestBindingCommitCrashWindows` | Journal-first version/digest commitments and snapshot position/hash must agree; missing, stale, substituted, zeroed, truncated and interrupted pairs fence before evidence changes; real socket signing control; complete-pair rollback needs an independent checkpoint |
| Complete snapshot schema | `TestSnapshotSchemaRequired` | Missing top-level/nested members, null records and unknown/case-alias members refuse; complete empty/revoked controls admit; raw decoder test isolates schema from reconciliation |
| Whole retained path history | `TestBindingHistoryUniqueness` | Hidden active/revoked predecessors, owner/lifetime/order violations refuse; valid persistent history signs for latest principal |
| Generation unavailable | `TestProductionGenerationRefuses`, `TestProductionBinaryGenerationGate` | Actual production binary refuses; injected fake-backed positive, no journal adapter |
| Release and next-request fencing | `TestReleaseFences` | Controlled sign pause; revoke/retire/reuse win before release |
| Real connection invalidation | `TestLiveConnectionInvalidation` | Kernel socket closure for all three transitions; same UID fixture |
| Durable audit failure/replay/rotation | `TestAuditWriteFailures`, `TestAuditFailureClosesListener`, `TestAuditRecoveryAndRotation`, `TestAuditStartupRejectsIncompleteEvidence` | Append/short/sync/budget faults, corrupt/truncated/unsafe/discontinuous evidence |
| Audit schema/dependencies | `TestAuditCanonicalSchema`, `TestAuditDependencyFailures` | Exact null schema/canonical strings, missing entropy and untrusted clock |
| Bounded input/state instances | `TestAgentFrameBounds`, `TestStateJSONRejectsAmbiguity`, `TestSocketGuards`, `TestStateLock`, `TestRateLimits` | Frame/JSON/repeated-instance/rate checks; not a performance or hard-sandbox qualification |
| Refusal work and journal amplification | `TestFrameRefusalAccounting`, `TestOverloadRefusalBudget` | Real malformed/busy reconnects drain burst; fixed aggregate counter and bounded overload journal indications; valid responses recover with credit |
| Current UID, stock OpenSSH/Git | `TestRealClients` | Actual SO_PEERCRED; negative namespace/raw; exact fixture-key verification; isolated HOME/Git configuration |
| Second real UID | `TestMultiUID/{foreign-key,unbound,retired}/{negative,control}` | PENDING without the owner-provisioned window; compiled, not qualified |
| PENDING cannot be deny-all | `TestPendingAndConfiguredCheck`, `TestMinimalWindow` | Missing window gives exact stderr/3; configured fake reaches real checker, minimal valid fake passes |

## Narrowing controls

`go run ./tools/mutations/main.go -scratch "$SCRATCH"` plants only Go overlay
files and requires the intended assertion failure; compilation/setup errors do
not count. Its own exit is 0 only when all eighteen mutant subprocesses (the ten original K1a controls below and eight native controls in the K1b map) exit 1 for the
named assertion. No source file is overwritten.

| Mutant | Property narrowed to | Named failing test | Outcome/bound |
| --- | --- | --- | --- |
| Remove binding peer UID equality | The binding authorization primitive must reject a different authenticated UID | `TestRefusalVectors/binding-wrong-uid/negative` | Killed (mutant test exit 1); tests this primitive, not every possible UID-check site |
| Disable namespace comparison while retaining parsing | Agent dispatch must reject an otherwise valid non-Git SSHSIG preimage | `TestRefusalVectors/ssh-namespace/negative` | Killed (mutant test exit 1); does not qualify future protocols |
| Ignore retained entries on missing snapshot | The snapshot loader cannot bootstrap over retained audit evidence | `TestMissingSnapshotRecovery/missing` | Killed (mutant test exit 1); isolates the primitive guard, with paired startup checked separately |
| Restore last-record-only active comparison | An intervening unbound record cannot conceal an active predecessor | `TestBindingHistoryUniqueness/hidden-active` | Killed (mutant test exit 1); scoped to retained path transitions |
| Remove framing work charge | Actual oversize frames must consume work credit before journal writes | `TestFrameRefusalAccounting/oversize` | Killed (mutant test exit 1); bounded flood, not load qualification |
| Remove busy work charge | Saturated dispatch must consume the same credit | `TestFrameRefusalAccounting/busy` | Killed (mutant test exit 1); actual server dispatch branch |
| Journal every overload | Exhaustion cannot turn framed refusals into unlimited journal writes | `TestOverloadRefusalBudget` | Killed (mutant test exit 1); fixed clock bounds writes independently of wall time |
| Permit absent binding commitment for an existing snapshot | Existing state cannot silently bootstrap missing journal evidence | `TestCustodyStartupReconciliation/empty-audit` | Killed (mutant test exit 1); existing missing-journal plant now targets the strengthened reconciliation guard |
| Remove cross-binding check, retain missing-file refusal | An older valid snapshot cannot grant revoked signing authority beside the later journal | `TestSnapshotJournalDivergence/snapshot-before-revoke` | Killed (mutant test exit 1); demonstrates the forbidden signature over a real socket with the actual Master |
| Make records optional, retain other schema checks | The decoder must require explicit records independently of the journal veto | `TestSnapshotSchemaRequired/revoked/missing-records` | Killed (mutant test exit 1); isolates omitted-member admission, with paired tombstone preservation checked separately |

No surviving mutant is claimed killed. These ten K1a narrowing
mutants remain in the wrapper alongside the eight native controls. No separate implementation attack-surface
table was provided in the brief; this vector map is not a claim of mutation coverage for
every implementation line. See [Linux testing](linux-testing.md)
for recovery rules, actual limits and remaining deployment/generation gates.
