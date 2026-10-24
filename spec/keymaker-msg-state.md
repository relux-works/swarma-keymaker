# Message certification: durable state, recovery and issuance audit

Status: normative candidate, **spec only**. This answers the state-schema,
reconciliation and issuance-audit questions for K3 S2. It extends the
[message contract](keymaker-msg.md), not the shipped daemon or native methods.
S1 supplies only an internal purpose-4 key. Nothing here enables message signing,
a publisher transport, purpose 5 or an administration command.

The journal profile and `verifier.VerifyJournal` are pinned to landed waggle
[S3, §2.7](https://github.com/relux-works/waggle/blob/9b42338b8a57d12a21da4db4375b269deacdd6bf/spec/swarm-envelope-2.md#27-identity-journal-and-checkpoints).
This adds journal/checkpoint dependencies to the message supplement's S0 pin;
it does not silently upgrade the module or replace its message profile.
WC1 below means the separately reviewed state-witness service's registry stream:
independent checkpoint observer, intent and matching committed resolution,
original receipts, authenticated fresh head and continuity/control evidence.
Its accepted wire profile, deployment and transport are activation gates. The
[Option C supplement](keymaker-witness.md) records the independent-witness
boundary; a registry confirmation is not a Keymaker complete-state witness.

## 1. Authority and readiness

Issuance is an internal step after an authoritative binding becomes active;
renewal is an internal step by expiry under protected lifetime policy. Neither
is a caller-selectable RPC. Binding activation alone grants no message authority.
Renew early enough for publication, but do not infer a scheduling or publication
latency guarantee. A missed expiry closes signing; it never extends a certificate.
A committed binding remains a binding if certification is unavailable.

For each exact `(uid,generation,registration_number,master_epoch,owner,path)`
association, retain one current ID, zero or one pending certification transaction,
and all predecessor evidence. The key is the service-selected purpose-4 sibling.
T identifies the attestation body, not its envelope bytes or journal entry.
The exact signed envelope is retained as well; equal T never permits substituting
another envelope, binding, issuer policy or transaction outcome.

Once the issuance/renewal intent wins the shared admission/release ordering,
fence new message signing **and retained-result disclosure**. A previous current
T1 may remain recorded as predecessor evidence, but cannot be used through that
fence. T2 becomes current only in a durable activation transaction containing its
exact certificate, qualified publication proof, binding association and successful
audit. Candidate issuance commit alone MUST NOT make T2 current. Until publication
is qualified, refuse `key_not_enrolled`, including exact retries; **no fallback
to T1**. Other precise generation, binding and custody refusals retain priority.
Corrupt/unknown durable transactions close admission under base §11 rather than
being disguised as an ordinary missing publication.

After activation, all normal active-binding, time, revocation and current-T checks
still apply at admission and actual release. A stored acknowledgement is durable
inclusion evidence, not a lease on active status or witness freshness. If live
publication confirmation is unavailable/stale, message admission and disclosure
close with `key_not_enrolled`; expired certification independently retains
`key_not_valid_now`. Foreign/noncurrent T under otherwise ready authority retains
`signer_identity_mismatch`, and changed params under a retained ID retain
`request_conflict`. No refusal deletes the original result.

## 2. State schema and bounds

### 2.1 Versioned protected inventory

The proposed snapshot schema is **2**. Existing untagged snapshots are schema 1;
the existing `version` remains the monotonically increasing transaction counter,
not a schema tag. Closed top-level schema 2 is the six existing members
`next_registration_number,records,requests,version,audit_seq,audit_hash`, plus
required `schema_version:2` and required `messages`. Unknown versions, missing
members, null arrays and unknown members refuse. Do not guess an empty message
state from parse failure. The following is the logical closed inventory for
`messages`; names are proposed persisted members, never new wire/audit fields.

| Member / location | Required retained content and invariant |
| --- | --- |
| `messages.certificates` | Immutable rows `{transaction,binding,key_id,issuer_policy,envelope,content_id}`. `binding` is the six-field association above with the purpose-4 path; `issuer_policy` is the exact protected root/tuple/epoch/revision policy used. `envelope` is original signed bytes in canonical unpadded base64url; rederive T and verify profile/signature. No private key or chain code. |
| `messages.associations` | Rows `{binding,current,pending}` unique by the complete binding. `current` is null or an exact certificate-row transaction reference; `pending` is null or an exact transaction ID. Never choose current by largest time, T or registration. A non-null pending reference is the durable fence. Retired associations and references survive. |
| `messages.transactions` | Rows `{id,kind,base_version,base_digest,previous_current,intent,candidate,phase,resolution}`. `kind` is `issue` or `renew`; `id` is service-generated 32 lowercase hex, installation-unique and never recycled. `intent` retains the exact binding, key, policy, lifetime, prior T, reserved capacity and base manifest. `candidate` is null before preparation or an immutable artifact reference to the exact proposed transition effects and manifest; no reconstruction from hashes. `phase` is `intent`, `prepared`, `issued`, `published`, `active`, `aborted` or `closed`; `resolution` is null or retained exact recovery decision/evidence references. Only the ordered transitions in §3 are legal. |
| `messages.publications` | Immutable records `{transaction,content_id,entry,suffix,checkpoint,conflict,snapshot,validation,witness}` per §4. Original signed/unsigned record bytes are retained, not a URL, Boolean or an inferred acknowledgement. `conflict` is null unless a second checkpoint was supplied. |
| `requests` (existing store) | Selected message outcomes stay in the existing retained native-ID namespace, never a second cache: method, exact canonical params, selected binding/registration, purpose-4 key ID, exact T, pending/committed status and original result bytes. Extending that closed row for message selections is an explicit schema-2 change; old methods keep their original arguments/results. Certification IDs are not native request IDs. |
| Protected staging, same state directory | Immutable service-owned `message-tx/<id>/` artifacts: exact canonical intent, exact attestation envelope, candidate effect/manifests and publication evidence when available. O_EXCL creation, file sync and directory sync precede their commit reference. Every artifact has its byte length and SHA-256 in the candidate manifest. Conflicting, missing or unexpected artifacts fence; orphan artifacts are attempt evidence, never authority. |
| `bindings.next`, `bindings.json`, audit linkage | Retain the existing staged snapshot, atomic replacement and directory-sync protocol. The content digest includes schema tag, complete messages inventory, retained selections and every staged artifact reference as well as original bindings/allocator/version. Exclude only the snapshot's own audit seq/hash, as today, to avoid circular hashing. Audit alone is not the artifact backup. |

Intent, candidate and resolution artifacts are immutable separate objects.
Each reference is exactly `{hash,bytes}`: lowercase SHA-256 of complete canonical
artifact bytes and nonnegative safe-integer byte length. The candidate effect
contains the selected certificate, exact binding, prior/current references,
publication reference if available, and intended phase/pending changes against
the exact base version/digest. It is not an embedded copy of its own containing
snapshot. References form an acyclic graph to already synced artifacts.
The implementation must publish exact CCJ-1 codecs for these typed internal
artifacts before S2 review; no opaque free-form intent may authorize recovery.

Before each commit, retain the exact resulting snapshot body separately as
`message-tx/<id>/snapshot-<version>` as well as `bindings.next`. Its journal
`binding_commit` full-body digest authenticates those bytes; that body does not
include a reference to its own recovery copy. Unexpected snapshot-copy versions
or a copy not matching its version's commit/retained pending decision fence.
Copies are charged to capacity and retained for recovery, not new authority.
No manifest hashes itself, and no audit hash is part of its own payload digest.

All certificate IDs, journal IDs and manifest digests must be recomputed from
retained bytes. All cross-references resolve exactly once; duplicate IDs,
misassociated results and contradictory phases fence. Transactions, certificate
rows and associations are append-only histories; phase/current changes create
new snapshot versions while preserving previous intent/candidate/resolution bytes.

### 2.2 Migration and downgrade

Migration is a trusted offline service operation under the exclusive state lock,
with serving instances excluded, after full schema-1 snapshot/journal validation.
It preserves every binding, allocator, native ID, result and audit anchor, creates
empty explicit message inventories and commits schema 2 through `binding_commit`.
A clean schema-1 store has no message authority. Existing unmatched intent,
`bindings.next`, broken audit or uncertain restore is not migration eligibility.
Retain the exact old body, new body and migration decision for interrupted replay.

Before enabling schema-2 serving, protected owner deployment policy must raise a
minimum-reader-schema floor to 2 and exclude old binaries and restored old serving
instances. The floor lives outside the service-writable snapshot/backup domain;
it is not a station-supplied config or merely a file beside `bindings.json`.
A replacement must verify that floor and, where activated, independent witness
anchors before readiness. Interrupted floor advancement stays closed until exact
migration reconciliation. Schema-1 binaries already reject the additional required
snapshot members; they MUST NOT be made to ignore or strip them. Removing new
fields, replaying an old snapshot/journal pair or lowering the floor is forbidden.
Owner recovery is separately authorized, never automatic downgrade.

A local schema tag cannot detect whole-store rollback with the old binary and
old policy. The deployment exclusion/floor is therefore an activation requirement,
not a claimed cryptographic property of mode A. Complete-state rollback detection
still requires independently retained Option C evidence; registry WC1 proof alone
does not cover the Keymaker allocator, native results or migration floor.

### 2.3 Capacity and history

Use the existing **256 MiB** active binding/result budget for all message state,
canonical params, certificates, publication proofs, migration/recovery history,
intent/candidate artifacts and simultaneous staging copies. Count actual encoded
bytes, including base64 expansion, before allocation. At most **65536** retained
native requests total across methods (the existing limit); additionally at most
**65536** total certification transaction rows, **65536** association rows, and one
certificate and one publication record per certification transaction. One pending
transaction per association; admitted work remains inside base §10 concurrency and
rate limits. Counts do not promise that the byte budget can accommodate them.

Reserve the full worst-case transition/staging space before intent, including
publication evidence and audit headroom. Each attestation, entry, checkpoint and
snapshot is at most **8192 bytes**, depth 16, with inherited string/array limits.
A journal-verifier call admits at most **64 entries**, **2 checkpoints**, and
**540672 bytes** total for those inputs. Witness proof pages and total artifacts
also consume reserved state bytes; transport-specific caps cannot enlarge them.
Capacity or history overflow refuses `state_capacity_exceeded` before a new
transition, leaves existing evidence intact and supplies no message success.
A pending transition whose reserved proof space proves insufficient stays fenced;
never truncate evidence or substitute a shorter unverified suffix.

Audit retains the existing **64 MiB** segment, **1 GiB** online and **16 MiB**
reserved control/refusal budgets. No renewal, count exhaustion or expiry permits
reclaiming certificates, IDs, tombstones, publication acknowledgements or recovery
evidence. No automatic eviction. Only a separately qualified durable archive and
retrieval/restore protocol can remove required online state; this slice defines
none for message state. Audit archive removal still requires the existing verified
durable acknowledgement. Finite capacity deliberately applies backpressure.

## 3. Transaction and trusted reconciliation

All transitions serialize against binding changes, message signing/retry release
and other certification work. Recheck authoritative binding and generation under
`with_active` for issuance and activation. Never keep that generation release lock
across registry/witness I/O: commit the fence, release locks, collect evidence,
then reacquire and revalidate before activation. No network-dependent unbounded
queue or extension of the native response deadline is introduced.

| Step | Durable transition and permitted next action |
| --- | --- |
| 0 reserve | Validate binding/policy/time/budgets, choose internal transaction ID and lifetime, stage exact intent. No signing/publication yet. Before an intent commit there is no new current ID. |
| 1 intent | Commit `pending=id`, exact intent/base references and fence audit. Existing current is evidence only. Issuance/renewal may now prepare exactly one candidate; no message signing/disclosure passes. |
| 2 prepared | Construct and sign the fixed purpose-5 attestation once; durably stage its exact envelope/T and candidate artifacts, then commit `prepared`. Do not expose unpublished bytes. A crash before preparation is durably evidenced never authorizes reconstruction by reconciliation. |
| 3 issued | Commit the exact retained certificate and `issued` outcome with internal issuance/renewal audit. This is candidate commitment, not current-T activation. |
| 4 published | Registry accepts the exact retained envelope and returns §4 proof. Validate and durably commit original proof plus acknowledgement as `published`; do not clear pending. A lost registry reply is resolved by exact-ID lookup of original evidence, not another issuance or invented receipt. |
| 5 active | Revalidate same binding, certification time, publication and fresh authority evidence; atomically set current to candidate, clear pending and commit `active` with activation audit. This is the only successful T2 promotion. Retirement/revoke winning ordering prevents promotion. |

Every committed row uses the existing `binding_commit` durable transaction with
an extended full-state digest. Intermediate artifact sync is not a commit;
a success audit record alone is not a matched snapshot. Exact commit evidence
requires journal sequence/hash/version/digest plus the exact candidate bytes and
qualified snapshot/rename/directory durability. A journal-ahead candidate is not
silently discarded by normal startup.

**Recovery authority:** the proposed trusted offline operation
`message-state reconcile` is a service-administration operation, not a native
method. It requires operator-controlled invocation, protected expected transaction
ID/base/candidate digests, exclusive state lock, no serving old instance and closed
message admission. Invocation authorization is not proof of an outcome. It runs
the same closed validation and journal replay as startup and records its decision
using §5. It has no purpose-4/5 signer access and MUST NOT issue, reissue, publish,
change lifetime or manufacture a message result.

1. Inventory original intent, base snapshot, every candidate/artifact, journal
   continuation, result rows and publication/WC1 evidence. Verify all hashes,
   bounds, references and current protected schema floor. An unmatched commit,
   missing bytes, conflicting candidate or uncertain instance exclusion stays
   closed. A digest-only audit entry cannot reconstruct an attestation/result.
2. A **proven abort** requires the exact retained intent and validated complete
   journal tail proving no issuance commit, no publication or unresolved external
   acceptance, and the exact base/candidate staging inventory. Prepared-but-never-
   committed bytes may be sealed as aborted, never reused. Durably commit the
   abort decision before clearing pending. Only then may the previous T1 serve,
   and only if still valid with qualified publication and current authority.
   Missing evidence is unknown, not a no-commit proof.
3. A **proven commit** installs only the exact retained matching candidate bytes
   whose audit/durability evidence establishes that commit; never compute a new
   certificate/signature. For `issued` without proof, preserve pending and
   `key_not_enrolled`. For a proven publication, restore its exact acknowledged
   proof. Only a fully proven activation with current binding/time/publication
   checks can restore current T2 and clear pending. Never reactivate T1 after
   issuance commit. If activation cannot be proven, leave the fence; the normal
   internal lifecycle may later activate the retained candidate after independent
   recovery has established its outcome, without reissuing it.
4. Unknown outcomes retain the original evidence and fence across every restart.
   There is no timeout-based abort, force-clear, empty-bootstrap or caller choice.
   A committed but now-expired candidate remains evidence and closed; a subsequent
   independently admitted lifecycle transaction can supersede it after resolution.
   For that case only, reconciliation may commit terminal `closed` after proving
   the issued candidate's exact outcome and present expiry/withdrawal: retain all
   bytes, set current and pending to null, and audit the closure decision. This
   removes the unresolved-transaction fence but grants no authority (still
   `key_not_enrolled`); it never restores T1. A new lifecycle transaction uses a
   fresh internal ID, without pretending reconciliation renewed the certificate.

Normal startup validates/replays matched committed state but does not make a new
recovery decision from partial files. Reconciliation may restore exact message
results only from retained bytes; disclosure still requires normal live admission.
No recovery path calls the signer. Lost acknowledgements never delete commits.

## 4. Publication record and restart

Publication is to the trust-node owner's registry. Until that registry and WC1
integration exist and are qualified, nothing is published and message signing
stays closed. Service egress remains denied: a separately authorized local
publisher/transport boundary must supply original evidence; this slice grants
no network access and accepts no client-selected URL, root or witness stream.

| Publication member | Retained bytes/facts and required verification |
| --- | --- |
| `transaction,content_id` | Exact committed certification transaction and T; match envelope body content ID, purpose-5 signature, policy, key and full binding independently. |
| `entry,suffix` | Original unsigned `journal-entry/1` envelope `{version,body,id}`, with `op:add`, `record_type:attestation/1`, `record:T`, exact protected registry/owner, seq/prev/time. Retain the complete bounded contiguous suffix that establishes inclusion. An entry alone or Git commit is not proof. |
| `checkpoint,conflict,snapshot` | Original registry-root-signed `checkpoint/1` and its exact referenced signed complete revocation snapshot; optional original second checkpoint for fork detection. Checkpoint seq equals the attestation entry or is the nearest subsequent checkpoint covering it, with verified ancestry to that exact entry. Registry/owner/root role, author signature, ids, seq/head/snapshot and time all verify under S3. Purpose 5 never signs checkpoints/snapshots. |
| `validation` | Exact original verified anchor projection, protected root/policy revision, decision-time context (including durable W), verifier plan and input manifest/digests. S3's six-field projection is exactly `{registry_id,owner,registry_seq,registry_head,checkpoint_id,previous_checkpoint_id}`; do not add timestamps or trust caller-created facts. |
| `witness` | WC1 stream/policy pins, original registry intent and matching committed resolution bytes, both original receipts, checkpoint/candidate association, independently authenticated head/control anchor and continuity evidence. Verify checkpoint time verbatim in WC1 evidence. A mere intent receipt, cached head, registry writer's claim or another consumer's stream cannot confirm publication. |

Store the covering checkpoint **at publication time**. `VerifyJournal` accepts at
most 64 entries and two checkpoints per call, so fetching a recent head after an
arbitrarily long history cannot replace the original inclusion proof. If the
nearest covering checkpoint cannot be proven within those bounds, fail closed;
never skip a middle entry. Advancing a witness anchor uses separately verified
bounded continuity steps, persisting each accepted anchor; no call silently
truncates a suffix or treats a partial prefix as inclusion.

At original acceptance use the real qualified time/W, current signed snapshot
and already independently verified witness projection. S3 checks freshness
(max_age <=60 seconds), genesis/ancestry and fork/rollback as specified. Its
returned plan is not publication or a witness-update permit; atomically retain
exact proof and required watermark before authority use, and separately satisfy
WC1. Never feed an old captured time sample to obtain a *current* verifier verdict.

On restart retain the exact publication acknowledgement and inclusion bytes.
Recheck their hashes, signatures, binding and durable transaction association;
historical validation context explains the original decision only. An aged
covering checkpoint remains historical inclusion evidence, not a fresh S3
checkpoint verdict. Obtain fresh challenge-bound WC1 head/control/continuity
confirmation and live active status/scoped revocation evidence (max age <=60 s)
before reopening, under final serialized authority checks. Missing/stale or
conflicting evidence keeps messages closed; restart does not turn `published`
into `active`, forget a fence or erase a stored acknowledgement.

D38 chooses **B**, a separate `freshness/1` profile for snapshot freshness.
That profile is not required to establish this historical publication inclusion
proof, and is not implemented or invented here. Live-status/snapshot freshness
and its eventual transport remain distinct activation gates; do not implement
D38-A snapshot reissue or rewrite a historical checkpoint to make it fresh.
Fresh witness observation proves retained history/continuity, not issuer honesty,
a future lease, complete upstream publication or permission to ignore revocation.

## 5. Audit mapping and explicit base deltas

Use the existing closed [base §11](keymaker.md#11-audit-and-fail-closed-recovery)
record, with no new members. Internal transition rows have `surface:control`,
`domain:control`, service-generated `request_id:msg:<transaction>:<phase>` (not
an attributable client attempt), resolved peer_uid/generation/path/master_epoch
from the protected binding, and SHA-256 `payload_digest` of the exact canonical
transition artifact. Unknown attribution stays null. The digest contains all
selected IDs and evidence references without exposing their original payloads.

| `operation` value | Meaning and durable partner |
| --- | --- |
| `message_certification_fence` | Internal issue/renew intent wins ordering; paired with the snapshot commit containing pending/intent. Kind is in the digested artifact, not an extra audit member. |
| `message_attestation_issue` | First certificate candidate committed, not yet current; exact envelope/binding manifest digest. |
| `message_attestation_renew` | Renewal candidate committed with prior T retained; same digest/transaction rule, no purpose-4 key change. |
| `message_publication` | Qualified exact publication evidence durably retained; not a `sign_message` event. |
| `message_certification_activate` | Current-T promotion and fence removal in one snapshot commit. |
| `message_certification_abort` | Proven no-issuance-commit abort and fence removal; prior authority still needs normal checks. |
| `message_certification_reconcile` | Trusted exact-outcome recovery decision/evidence digest; no cryptographic issuance or result invention. |
| `message_state_migrate` | Validated schema-1 to schema-2 transition/floor evidence digest. |
| `binding_commit` (existing) | Every phase, including prepared/artifact-only state advancement: `surface:control,domain:control,request_id:binding:<version>`, full candidate state-body digest, seq/hash referenced by installed snapshot. |
| `sign_message` (separate S3 signing slice) | One attributable request-attempt record on surface B, `domain:swarma-msg`, exact accepted preimage digest and native ID. Retained committed selection/result is its durable partner. An exact retry may audit its own attempt but cannot create a second issuance or successful-result commit. |

Internal phase success is durable only when its event rows and `binding_commit`
are synced and the exact snapshot commit is established. The candidate manifest
binds their operation/request IDs and digests; snapshot audit linkage points to
its commit record, avoiding circular hashes. An interrupted event append without
its paired commit is an attempted/unknown outcome, not completed issuance.
A refusal uses its existing stable code and `result:refused`; uncertain time or
outcome uses existing `unknown` rules and closes admission. No internal event is
labelled as a message signature success. No certificate, original publication
proof, signature, payload or free-form phase diagnostic enters audit. Existing
custody-cause rules, hash chaining, archive and failure closure remain unchanged.

**Explicit proposed §11 deltas:** admit the eight new internal operation literals
above, internal request-ID grammar and their event/commit pairing; extend the
`binding_commit` content digest and schema-aware replay to the complete inventory;
add the already proposed `sign_message` operation/`swarma-msg` domain and retained
selection/result transaction. There are **no new audit members**, enum result
values, revocation domains, checkpoint-signing domains or implicit optional fields.
State migration is required; historical audit bytes/hashes are never rewritten.

## 6. Paired negative text vectors

These are required future executable scenarios, **not passing runtime tests**.
Run each crash row for both initial issuance (previous current null) and renewal
(previous valid T1), checking disk/audit state, no message output and no extra
signature calls during recovery. Controls require exact expected outcomes, not
merely any error. Bound examples satisfy all other limits.

| Vector | Forbidden outcome / required rejection and retained state | Nearby positive control |
| --- | --- | --- |
| MS-S01 crash before intent | Interrupt step 0; no new current/result/publication; incomplete staging cannot authorize signing or reconstruction. | Complete reservation and exact intent commit establishes pending, still no signing. |
| MS-S02 crash after fence | Interrupt step 1; pending survives restart, T1 unusable. Unknown tail stays closed. | Exact intent/base plus complete no-commit/no-publication evidence permits audited abort; only still-valid T1 can resume (initial issue stays unenrolled). |
| MS-S03 crash during preparation | Interrupt step 2 before/after envelope sync and before prepared commit; never sign another certificate in reconcile or use partial bytes. | Matching complete prepared bytes are retained; proven pre-issuance abort seals them without reuse, or normal lifecycle uses the exact durable prepared candidate after outcome resolution. |
| MS-S04 crash during issuance commit | Interrupt step 3 before/after journal sync, snapshot sync, rename and directory sync separately; unmatched/unknown evidence fences, no T1 fallback. | Exact retained candidate and proven commit restore issued T2 candidate without signing; still `key_not_enrolled` until proof/activation. |
| MS-S05 crash around publication | Interrupt before registry acceptance, after acceptance/lost reply, after proof sync and during published commit separately; never infer success from transport acknowledgement alone or republish/reissue in reconcile. | Recover original entry/checkpoint/WC1 proof for exact T; persist once; no duplicate issuance, pending stays until activation. |
| MS-S06 crash during activation | Interrupt step 5 at event append, commit append/sync, snapshot write/sync, rename and directory sync separately; unknown state retains fence. | Proven complete activation with fresh authority restores only T2; exact retained native results remain unchanged. |
| MS-S07 unmatched commit | Supply journal-ahead commit with missing/different candidate, or candidate version/digest/binding mismatch; startup and reconcile refuse, no deletion/guess/reissue. | Exact retained candidate plus complete matching durability evidence permits restoring that one outcome; issued-only still fenced. |
| MS-S08 downgrade | Present schema 2 to old reader; strip tag/messages; restore old schema-1 pair under floor 2; or lower floor/serve old binary: refuse readiness, preserve artifacts. Whole-store/policy rollback outside independent floor has the mode-A limitation, not a false local detection claim. | Authorized locked migration preserves all old rows/results and raises protected floor; schema-2 reader validates exact upgraded state. |
| MS-S09 history capacity | Attempt transaction/association/native-ID 65537, 256 MiB+1 actual staging bytes, 65-entry/3-checkpoint/540673-byte verification input, or deletion of required old evidence: refuse growth, retain existing state; pending insufficiency stays fenced. | Within count AND byte limits, a complete <=64-entry/<=2-checkpoint/<=540672-byte proof and reserved state can commit; no promise each maximum coexists with all others. |
| MS-S10 missing/stale publication | Remove entry, checkpoint, snapshot, original receipt or committed WC1 resolution; use an unverified projection or stale live confirmation; `key_not_enrolled`, no output/current-T promotion, original acknowledgement preserved if present. | Exact covering proof accepted at publication plus fresh live witness/status evidence permits activation/restart; historical checkpoint age alone does not erase inclusion. |
| MS-S11 fallback T1 | After fence or issued T2 without proof, try new signing and exact retained T1-result retry: `key_not_enrolled`; caller cannot choose old/new T. | After fully qualified T2 activation, fresh T2 request proceeds; old T1 request/exact retry refuses `signer_identity_mismatch` while retaining its result. Only proven pre-issuance abort may reopen valid T1. |
| MS-S12 proof substitution/fork | Wrong T/owner/root/stream, skipped middle entry, later unrelated checkpoint, equal-seq different signed head/checkpoint or intent-only receipt never qualifies; fence and retain fork evidence, no partial plan use. | Original exact entry, contiguous ancestry to nearest covering checkpoint, independently verified WC1 committed pairing and matching six-field projection qualify inclusion. |

## 7. Remaining gates

State layout, proven-outcome reconciliation and issuance audit are specified here;
runtime schema codecs, atomic durability, migration/floor deployment, bounded
publisher integration and all paired executable/fault evidence remain review gates.
WC1 service acceptance/transport and independent observer/custodian qualification
remain required; no colocated or writer-controlled fake witness qualifies.

**Deferred until PR #22 lands:** durable watermark bootstrap/advancement and
continuity (including conservative Now/W mapping), and time-provider collection
latency/uncertainty under admission and actual-release deadlines. Do not decide
these by copying provider logic, sampling the wall clock, setting W=Now, holding a
generation barrier across provider I/O or relaxing deadlines. Activation must wait
for reviewed integration of that landed provider and the watermark transaction.

No surface table accompanied this brief (coverage-map brief gap). No requested
spec row is excluded. Runtime code/tests/mutants, deployment, public publisher
API and D38 freshness wire implementation are outside this spec-only slice.
