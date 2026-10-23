# K1a coverage map

This implementation follows the normative reference at `25ea2ad`. All 70
negative vector IDs are accounted for below: 31 executed K1a pairs and 39
explicitly deferred K1b pairs. No in-scope vector is unexecuted.

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

## Rows outside this task

The assignment's explicit “Out of K1a (goes to K1b): surface B native control
ops (pubkey/register/revoke), registration helper, enrollment loading” clause
excludes the following rows. Native decrypt/material-export probes remain
listed here because their evaluation endpoint is native; no decrypt or export
path is implemented by the agent. Agent unknown opcodes already refuse.
These rows are not claimed passing and are not silently covered by fixture
syntax checks.

| Row ID | Deferred evaluation |
| --- | --- |
| `native-oversize` | `native_framing` (K1b clause above) |
| `native-truncated` | `native_framing` (K1b clause above) |
| `native-zero-length` | `native_framing` (K1b clause above) |
| `native-noncanonical` | `native_framing` (K1b clause above) |
| `native-duplicate-key` | `native_framing` (K1b clause above) |
| `native-negative-zero` | `native_framing` (K1b clause above) |
| `native-float` | `native_framing` (K1b clause above) |
| `native-unsafe-integer` | `native_framing` (K1b clause above) |
| `native-invalid-unicode` | `native_framing` (K1b clause above) |
| `native-unknown-version` | `native_framing` (K1b clause above) |
| `native-claimed-uid` | `native_framing` (K1b clause above) |
| `register-wrong-uid` | `native_method` (K1b clause above) |
| `revoke-wrong-uid` | `native_method` (K1b clause above) |
| `revoke-persistent-as-ephemeral` | `native_method` (K1b clause above) |
| `revoke-no-act-verifier` | `native_method` (K1b clause above) |
| `revoke-invalid-act` | `native_method` (K1b clause above) |
| `helper-uid-absent` | `registration_helper` (K1b clause above) |
| `helper-name-not-mapped` | `registration_helper` (K1b clause above) |
| `helper-wrong-audience` | `registration_helper` (K1b clause above) |
| `helper-enrollment-missing` | `registration_helper` (K1b clause above) |
| `helper-enrollment-unverified` | `registration_helper` (K1b clause above) |
| `helper-enrollment-revoked` | `registration_helper` (K1b clause above) |
| `helper-map-required` | `registration_helper` (K1b clause above) |
| `helper-key-unenrolled` | `registration_helper` (K1b clause above) |
| `helper-reused-uid` | `registration_helper` (K1b clause above) |
| `domain-native-sign` | `native_method` (K1b clause above) |
| `domain-decrypt-deferred` | `native_method` (K1b clause above) |
| `no-material-private_key` | `native_method` (K1b clause above) |
| `no-material-chain_code` | `native_method` (K1b clause above) |
| `no-material-extended_private_key` | `native_method` (K1b clause above) |
| `no-material-parent_seed` | `native_method` (K1b clause above) |
| `no-material-sibling_seed` | `native_method` (K1b clause above) |
| `helper-revoked-binding-fresh-connection` | `registration_helper` (K1b clause above) |
| `helper-missing-binding` | `registration_helper` (K1b clause above) |
| `helper-wrong-executable` | `registration_helper` (K1b clause above) |
| `helper-undeterminable-executable` | `registration_helper` (K1b clause above) |
| `helper-matching-executable` | `registration_helper` (K1b clause above) |
| `helper-name-slash` | `registration_helper` (K1b clause above) |
| `helper-mxid-length` | `registration_helper` (K1b clause above) |

## Additional evidence and limits

| Claim | Named test/control | Limit |
| --- | --- | --- |
| Published hardened Ed25519 derivation | `TestPublishedDerivation` | All 12 published nodes, including chain/public values; chains exposed only inside tests |
| Scoped registry and path mapping | `TestRegistryPathVectors`, `TestRegistryRejectsInvalidHistory` | Five path controls, invalid history, duplicate/implicit allocations |
| Protected master storage | `TestMasterStorageGuards` | Owner/mode/parent/symlink/hardlink/type/length refusals and valid sign/verify |
| Persistent lifecycle/tombstones | `TestBindingLifecycle`, `TestPersistentRetirement`, `TestBindingRecoveryFences` | Trusted internal lifecycle, no native mutation or signed-act verifier qualification |
| Generation unavailable | `TestProductionGenerationRefuses`, `TestProductionBinaryGenerationGate` | Actual production binary refuses; injected fake-backed positive, no journal adapter |
| Release and next-request fencing | `TestReleaseFences` | Controlled sign pause; revoke/retire/reuse win before release |
| Real connection invalidation | `TestLiveConnectionInvalidation` | Kernel socket closure for all three transitions; same UID fixture |
| Durable audit failure/replay/rotation | `TestAuditWriteFailures`, `TestAuditFailureClosesListener`, `TestAuditRecoveryAndRotation`, `TestAuditStartupRejectsIncompleteEvidence` | Append/short/sync/budget faults, corrupt/truncated/unsafe/discontinuous evidence |
| Audit schema/dependencies | `TestAuditCanonicalSchema`, `TestAuditDependencyFailures` | Exact null schema/canonical strings, missing entropy and untrusted clock |
| Bounded input/state instances | `TestAgentFrameBounds`, `TestStateJSONRejectsAmbiguity`, `TestSocketGuards`, `TestStateLock`, `TestRateLimits` | Frame/JSON/repeated-instance/rate checks; not a performance or hard-sandbox qualification |
| Current UID, stock OpenSSH/Git | `TestRealClients` | Actual SO_PEERCRED; negative namespace/raw; exact fixture-key verification; isolated HOME/Git configuration |
| Second real UID | `TestMultiUID/{foreign-key,unbound,retired}/{negative,control}` | PENDING without the owner-provisioned window; compiled, not qualified |
| PENDING cannot be deny-all | `TestPendingAndConfiguredCheck`, `TestMinimalWindow` | Missing window gives exact stderr/3; configured fake reaches real checker, minimal valid fake passes |

## Narrowing controls

`go run ./tools/mutations/main.go -scratch "$SCRATCH"` plants only Go overlay
files and requires the intended assertion failure; compilation/setup errors do
not count. Its own exit is 0 only when both mutant subprocesses exit 1 for the
named assertion. No source file is overwritten.

| Mutant | Property narrowed to | Named failing test | Outcome/bound |
| --- | --- | --- | --- |
| Remove binding peer UID equality | The binding authorization primitive must reject a different authenticated UID | `TestRefusalVectors/binding-wrong-uid/negative` | Killed (mutant test exit 1); tests this primitive, not every possible UID-check site |
| Disable namespace comparison while retaining parsing | Agent dispatch must reject an otherwise valid non-Git SSHSIG preimage | `TestRefusalVectors/ssh-namespace/negative` | Killed (mutant test exit 1); does not qualify future protocols |

No surviving mutant is claimed killed. Only these two specified narrowing
mutants were planted. No separate implementation attack-surface table was
provided in the brief; this vector map is not a claim of mutation coverage for
every implementation line or deferred surface. See [Linux testing](linux-testing.md)
for remaining deployment/generation gates and section 12 provisioning differences.
