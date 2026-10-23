# K1b native daemon coverage

The integration task covers surface B and explicitly excludes the registration
helper. All 70 refusal rows are accounted for: 31 existing surface-A pairs in
[k1a-coverage.md](k1a-coverage.md), 23 native pairs below, and 16 deferred helper
rows below. No native row in this assignment is unexecuted. The brief names
vector rows but supplies no separate attack-surface catalog table; the map does
not claim a killed mutant for every line or every vector.

## Executed native pairs

Every row runs `TestNativeVectors/<id>/negative` then `/control` through the
real dual-surface daemon control socket, real Linux credentials, Master and
cross-bound Store/journal. It asserts the exact CCJ-1 wrapper and code/retryable
value, no binding/result snapshot change on refusal, durable control audit and
no material/signature/envelope fields. Controls validate the exact hello,
revoke tombstone or expected derived public key. Role equality from fixtures
is projected onto the current UID/configured operator; generation and signed-act
authority remain injected test interfaces. This does not claim live second-UID
or production signed-act qualification.

| Row | Exact refusal | Negative test (paired control changes `/negative` to `/control`) |
| --- | --- | --- |
| `native-oversize` | `frame_too_large` | `TestNativeVectors/native-oversize/negative` |
| `native-truncated` | `frame_truncated` | `TestNativeVectors/native-truncated/negative` |
| `native-zero-length` | `frame_malformed` | `TestNativeVectors/native-zero-length/negative` |
| `native-noncanonical` | `ccj_noncanonical` | `TestNativeVectors/native-noncanonical/negative` |
| `native-duplicate-key` | `ccj_noncanonical` | `TestNativeVectors/native-duplicate-key/negative` |
| `native-negative-zero` | `ccj_noncanonical` | `TestNativeVectors/native-negative-zero/negative` |
| `native-float` | `ccj_noncanonical` | `TestNativeVectors/native-float/negative` |
| `native-unsafe-integer` | `ccj_noncanonical` | `TestNativeVectors/native-unsafe-integer/negative` |
| `native-invalid-unicode` | `ccj_noncanonical` | `TestNativeVectors/native-invalid-unicode/negative` |
| `native-unknown-version` | `version_unsupported` | `TestNativeVectors/native-unknown-version/negative` |
| `native-claimed-uid` | `request_malformed` | `TestNativeVectors/native-claimed-uid/negative` |
| `register-wrong-uid` | `role_not_permitted` | `TestNativeVectors/register-wrong-uid/negative` |
| `revoke-wrong-uid` | `role_not_permitted` | `TestNativeVectors/revoke-wrong-uid/negative` |
| `revoke-persistent-as-ephemeral` | `persistent_revoke_requires_operator` | `TestNativeVectors/revoke-persistent-as-ephemeral/negative` |
| `revoke-no-act-verifier` | `operator_record_unavailable` | `TestNativeVectors/revoke-no-act-verifier/negative` |
| `revoke-invalid-act` | `operator_record_invalid` | `TestNativeVectors/revoke-invalid-act/negative` |
| `domain-native-sign` | `operation_unsupported` | `TestNativeVectors/domain-native-sign/negative` |
| `domain-decrypt-deferred` | `operation_unsupported` | `TestNativeVectors/domain-decrypt-deferred/negative` |
| `no-material-private_key` | `request_malformed` | `TestNativeVectors/no-material-private_key/negative` |
| `no-material-chain_code` | `request_malformed` | `TestNativeVectors/no-material-chain_code/negative` |
| `no-material-extended_private_key` | `request_malformed` | `TestNativeVectors/no-material-extended_private_key/negative` |
| `no-material-parent_seed` | `request_malformed` | `TestNativeVectors/no-material-parent_seed/negative` |
| `no-material-sibling_seed` | `request_malformed` | `TestNativeVectors/no-material-sibling_seed/negative` |

## Additional contracts and bounds

| Contract | Named evidence | Bound |
| --- | --- | --- |
| No helper signing path | `TestNativeHelperUnsupported` | Unsupported response, unchanged state, zero instrumented Sign calls and own-pubkey control |
| UID and generation operator authority | `TestNativeOperatorGeneration`, assigned wrong-UID vectors | Configured tuple, no wire role switch |
| Exact self pubkey and register schema | `TestNativePubkeySelectors`, `TestNativeRegisterGuards` | Selector/schema/UID-range/target evidence refusals leave state unchanged; own-key/valid registration controls |
| Ephemeral retirement | `TestNativeEphemeralRetirement`, `TestNativeOriginalRegistrar` | Active/replaced targets and changed registrar refuse; exact retiring/removed target plus original registrar admits cleanup |
| Actual write barrier | `TestNativeReleaseFence/{hello,pubkey}/{retirement-wins,release-wins}` | Delayed notification isolates final authority barrier; retirement-wins has no success or retained result; release-wins orders write first |
| Mutation release evidence | `TestNativeMutationReleasePrincipals`, `TestNativeMutationReleaseWins`, `TestNativeEphemeralReleaseEvidence`, `TestNativeMutationHistoricalRelease` | First release retains caller/target predicates in one barrier; both orderings and target reuse; historical replay remains caller-authorized |
| Accepted tuple before hello | `TestNativeAcceptTupleBeforeHello`, `TestAcceptedTupleBeforeHello` | Delayed notification cannot admit a replacement generation or retain its hello ID; unchanged and fresh-connection controls |
| First self binding on connection | `TestNativeConnectionBindingPin`, `TestNativeHelloDoesNotPinBinding` | Real revoke/re-registration cannot be adopted by the old socket; fresh socket admits; idle pinned socket closes; hello/operator mutations do not select a self binding |
| Safe socket publication | `TestNativeSocketPermissions` | Invalid group/existing file/symlink/stage refuse; intact exact 0660/UID/GID; existing evidence preserved |
| Shared work/rate and health | `TestNativeSharedConnectionBudget`, `TestNativeSharedWorkBudget`, `TestNativeSharedRateBudget`, `TestNativeAuditClosesBothSurfaces` | Mixed sockets share the eight-per-UID cap; saturated slots/rate refuse on both listeners; restored credit admits; sync fault closes both without success |
| Audit reserve | `TestNativeAuditReserve` | Control/refusal evidence can use the reserved tail; ordinary agent success cannot; small writer budget, not journal load qualification |
| Mutation retry accounting | `TestNativeMutationRetryBudget` | Four exact retries consume burst, fifth refuses without state change; restored credit recovers one effect |
| Durable complete arguments/results | `TestNativeDurableRetries`, `TestNativeConcurrentRetry`, `TestNativeCanonicalRetainedArguments` | Changed method/args/signed evidence conflict; exact retry/restart/concurrent attempt produces one effect; timeout change is not new identity |
| Concurrent revoke planning | `TestNativeConcurrentRevokeReplay/{same-id,different-id,changed-arguments}` | The retained winner outranks a stale revoked-plan refusal; a fresh ID sees the tombstone and changed arguments conflict, without another effect |
| Fresh target verdict | `TestNativeFreshTargetEvidence/{active,retired,reused,missing,unverified,verdict-not-recorded}` | Only the active control commits; exact inactive/mismatched/unavailable refusals retain no intent, result, binding or allocated number; an unrecorded verdict fails closed |
| Concurrent target changes | `TestNativeConcurrentTargetReplay/{same-id,same-id-retired,same-id-reused,different-id,changed-arguments,retired-caller}`, `TestNativeMutationHistoricalRelease` | A paused real-socket request sees the concurrent winner before target refusal; original result, unchanged snapshot and one effect; fresh retired target, changed arguments, distinct ID and retired caller refuse under their respective contracts |
| Crash windows | `TestNativeTransactionCrash` | Intent-only and result-journal-only fence; durable result before response replays after restart; intact control |
| Retained schema | `TestNativeRetainedSchema`, `TestSnapshotSchemaRequired` | Missing/null/unknown caller/entry members, noncanonical args, invalid ID/method/status/result and duplicate IDs reject without rewrite; intact paired reopen |
| Protected config shape | `TestNativeConfigSchema` | Required group/operator/UID/generation; no numeric-zero default authority; file provisioning is not exercised |
| Bounded state | `TestNativeResultCapacity` | 65,536-ID primitive preflight plus valid empty control; encoded 256 MiB check is not a load/RSS qualification |
| Bounded audit metadata | `TestNativeAuditMetadataBounded` | Unknown method bytes never become operation metadata; digest only, healthy public response |
| Real second UID/control group | `TestMultiUIDControl/{foreign-uid,unbound,retired}/{negative,control}` | Tagged compilation only here; live PENDING without window; B kernel EACCES case is also retained |

## Narrowing mutants

`go run ./tools/mutations/main.go -scratch "$SCRATCH"` uses bounded Go overlays,
never overwrites source, and requires a named assertion witness rather than a
compile/setup failure. The ten existing K1a controls remain. The four original
native controls plus three lifecycle controls and one concurrent replay control
bring the wrapper to eighteen; wrapper exit 0 means every mutant's named test
exited 1 with the intended witness.

| Mutant | Property narrowed to | Named failing test | Outcome/bound |
| --- | --- | --- | --- |
| `native-replay-before-target-barrier` | Move the authoritative retained lookup outside the generation barrier, preserving Store synchronization and all authority predicates | `TestNativeConcurrentTargetReplay/same-id-retired`, `/same-id-reused` | Killed; the winner commits while the retry waits, and the still-current caller must recover its result after target retirement or reuse |
| `native-operator` | Remove exact configured operator tuple check | `TestNativeVectors/register-wrong-uid/negative` | Killed; real kernel UID projected against a different configured operator; not live multi-UID qualification |
| `native-persistent-revoke` | Remove persistent-as-ephemeral refusal | `TestNativeVectors/revoke-persistent-as-ephemeral/negative` | Killed; exact required code, not generic failure |
| `native-socket-permissions` | Replace group/mode validation with 0666 fallback | `TestNativeSocketPermissions/invalid-group` | Killed; unassignable group cannot admit a daemon |
| `native-release-fence` | Remove generation barrier around actual native release | `TestNativeReleaseFence/hello/retirement-wins` | Killed; delayed watch cannot mask an unsafe success write |
| `native-target-release` | Keep only caller evidence at fresh mutation release | `TestNativeMutationReleasePrincipals/target` | Killed; a target retired after commit cannot receive a first success |
| `native-binding-pin` | Bypass first self binding pin and subscription | `TestNativeConnectionBindingPin` | Killed; old connection cannot adopt replacement while a fresh one succeeds |
| `native-accepted-generation` | Drop validated accept tuple before wire loop | `TestNativeAcceptTupleBeforeHello/true` | Killed; replacement before first frame cannot negotiate or retain an ID |

No surviving mutant is claimed killed. These controls do not constitute
exhaustive mutation coverage. All existing reviewer test names remain present.

## Out of integration contract

The request states: “The registration helper is not part of this task” and
requires helper rows to remain deferred. These rows and enrollment loading are
owned by the separate helper task; `sign_registration` stays unsupported here.
None is claimed passing by compilation, fixture validation or a generic refusal.

| Row | Deferred evaluation and acceptance reason |
| --- | --- |
| `helper-uid-absent` | `registration_helper`; explicit helper exclusion |
| `helper-name-not-mapped` | `registration_helper`; explicit helper exclusion |
| `helper-wrong-audience` | `registration_helper`; explicit helper exclusion |
| `helper-enrollment-missing` | `registration_helper`; explicit helper exclusion |
| `helper-enrollment-unverified` | `registration_helper`; explicit helper exclusion |
| `helper-enrollment-revoked` | `registration_helper`; explicit helper exclusion |
| `helper-map-required` | `registration_helper`; explicit helper exclusion |
| `helper-key-unenrolled` | `registration_helper`; explicit helper exclusion |
| `helper-reused-uid` | `registration_helper`; explicit helper exclusion |
| `helper-revoked-binding-fresh-connection` | `registration_helper`; explicit helper exclusion |
| `helper-missing-binding` | `registration_helper`; explicit helper exclusion |
| `helper-wrong-executable` | `registration_helper`; explicit helper exclusion |
| `helper-undeterminable-executable` | `registration_helper`; explicit helper exclusion |
| `helper-matching-executable` | `registration_helper`; explicit helper exclusion |
| `helper-name-slash` | `registration_helper`; explicit helper exclusion |
| `helper-mxid-length` | `registration_helper`; explicit helper exclusion |

## Pending gates and interpretations

Production generation-journal ordering and signed operator-act verification
remain unavailable. Live multi-UID execution, root provisioning, service sandbox,
deployment and macOS are unqualified. The helper/enrollment package is untouched.
No specification disagreement was found. Public result names use `master_epoch`
and raw-32-byte base64 `public_key`; these spell the spec's epoch/public-key
results without adding signing authority. Multi-principal generation evidence,
complete Request delivery to Handler and mandatory workload/refusal Observer
are core/wire seams needed to implement the existing contract, not new wire
methods. Recovery refuses older snapshots without `requests`; no automatic
migration or reconstruction is claimed. See [Linux testing](linux-testing.md).
