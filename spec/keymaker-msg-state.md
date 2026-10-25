# Message certification: durable state, recovery and issuance audit

Status: normative candidate; **production activation unavailable**. This answers the state-schema,
reconciliation and issuance-audit questions for K3 S2. It extends the
[message contract](keymaker-msg.md), not the shipped daemon or native methods.
The internal S2 implementation covers issuance and closed durable state; see the
[runtime inventory](../README.md#internal-certification-state) for its limits.
S1 supplies the internal purpose-4 key. Nothing here enables message signing,
a publisher transport, a public purpose-5 capability or an administration command.

The adopted spec contracts are pinned to waggle S4+S5
[`5f4e743`](https://github.com/relux-works/waggle/blob/5f4e7435d75697385ff6ce15a7501ac6f31c8ea5/spec/swarm-envelope-2.md):
[D39 journal §2.7](https://github.com/relux-works/waggle/blob/5f4e7435d75697385ff6ce15a7501ac6f31c8ea5/spec/swarm-envelope-2.md#27-identity-journal-and-checkpoints),
[D38 B freshness §2.9](https://github.com/relux-works/waggle/blob/5f4e7435d75697385ff6ce15a7501ac6f31c8ea5/spec/swarm-envelope-2.md#29-signed-snapshot-freshness-d38-b),
and [S5 receipts §2.10](https://github.com/relux-works/waggle/blob/5f4e7435d75697385ff6ce15a7501ac6f31c8ea5/spec/swarm-envelope-2.md#210-process-local-freshness-receipts-d41-composition).
This is spec adoption, not a module upgrade: the internal runtime remains on its
published S3 pin, refuses populated publication state and supplies no S4/S5
adapter or receiver. It does not replace the message supplement's S0 profile.
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
| `messages.publications` | Existing schema-2 logical publication records `{transaction,content_id,entry,suffix,checkpoint,conflict,snapshot,validation,witness}` per §4. Original signed/unsigned record bytes are retained, not a URL, Boolean or an inferred acknowledgement. `conflict` is null unless a second checkpoint was supplied. |
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

### 2.1.1 S4/S5 state-format boundary

The current schema-2 codec remains closed and rejects populated publication
state. This adoption does not append fields to that schema, reinterpret its
body hash, add a free-form sidecar, or relax startup inventory checks. Before
implementation, specify an explicit successor codec/version and protected
reader-floor/migration for the retained prior checkpoint, fresh-state inventory
and artifacts in §§4–5. Preserve all schema-2 certificates, native IDs/results,
phase fences, artifacts and recovery copies. Compose that version/preimage
with PC2's separately reviewed combined root; neither subsystem gains a second
commit authority or another 256 MiB budget. No receipt is a persisted member.

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
**540672 bytes** total for those inputs. Freshness is a separate limit: at most **64 publications**, **1 checkpoint**,
**532480 bytes** total, at most8192 bytes/depth16 per signed input. The protected
prior checkpoint is at most8192 bytes and accounted separately from the journal
explicit-argument aggregate, never hidden in its optional conflict slot. Exact
snapshot, publication/freshness endpoints, cumulative-policy evidence, witness
proof pages and total artifacts also consume reserved state bytes; transport-specific caps cannot enlarge them.

The registry service's [pinned transport contract](https://github.com/relux-works/swarma-owner-registry/blob/fa6e3d95dc2af90e3acfe1aa090cea60b5cde736/design/owner-registry.md#3-accept-api-and-verification-boundary)
adds independent outer byte gates: **512 KiB (524288 bytes) total intake/evidence**
and a **separate 2 MiB (2097152 bytes) aggregate received full proof bundle**.
Use the separate full-proof route for publication proofs; count all context,
protected C(n-1), current snapshot, witness/control evidence and transport
encoding in its aggregate. Neither route enlarges the S3 journal64/2/540672
or S4 freshness64/1/532480 raw verifier limits or the shared state budget.
The **8192-byte WC1 window, including the LF**, is another independent gate
on the whole encoded checkpoint wrapper. The 2 MiB route does not promise that
any maximal proof fits the WC1 window. Preflight every applicable route and
the complete real-head WC1 wrapper, including prior bytes, **before intent**;
an overflow refuses before the intent, with no truncation, skipped evidence
or ad hoc splitting/pagination. Existing state, sequences and anchors remain
unchanged; bounded refusal telemetry is permitted. Exact byte boundaries pass
only their respective size gate, subject to every other validity and capacity
check; they do not establish publication or activate K3.

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
| `entry,suffix` | Retain the original unsigned target `journal-entry/1` envelope `{version,body,id}` with `op:add`, `record_type:attestation/1`, `record:T`, and exact protected registry/owner/seq/prev/time. Retain the complete oldest-first contiguous inclusion suffix, including the authenticated raw anchor required by the owner-registry adapter. Other suffix entries retain their own exact supported types and record IDs: a snapshot reissue contributes `op:add,record_type:revocation/1,record:<new snapshot ID>`. Verify every entry ID/link/time and the target entry's exact T independently. An entry alone or Git commit is not proof. |
| `checkpoint,conflict,snapshot` | Original registry-root-signed `checkpoint/1` and its exact referenced signed complete revocation snapshot; optional original second checkpoint for fork detection. Checkpoint seq equals the attestation entry or is the nearest subsequent checkpoint covering it, with verified ancestry to that exact entry. Registry/owner/root role, author signature, ids, seq/head/snapshot and time all verify under the adopted D39 profile. Purpose 5 never signs checkpoints/snapshots. |
| `validation` | Exact original verified anchor projection, protected root/policy revision, decision-time context (including durable W), verifier plan and input manifest/digests. The exact six-field projection is exactly `{registry_id,owner,registry_seq,registry_head,checkpoint_id,previous_checkpoint_id}`; do not add timestamps or trust caller-created facts. |
| `witness` | WC1 stream/policy pins, original registry intent and matching committed resolution bytes, both original receipts, checkpoint/candidate association, independently authenticated head/control anchor and continuity evidence. Verify checkpoint time verbatim in WC1 evidence. A mere intent receipt, cached head, registry writer's claim or another consumer's stream cannot confirm publication. |

For every advancing journal proof, retain the original signed **C(n-1)** at
`IDJournal[witness.checkpoint_id]` with `IDJournalAvailable=true`. Authenticate
its content ID, registry/owner, signature, sequence and head against the protected
six-field witness. Include that exact prior in the input manifest and retain it
atomically with the accepted anchor and W. A digest or reconstructed checkpoint
is insufficient. `conflict` is never the prior: it remains independently admitted
second current fork evidence. An exact non-advancing checkpoint retransmission
needs no separate prior. Historical prior age is not current authority; candidate
checkpoint time MUST be >= authenticated prior time: **equal time passes**;
backward time refuses `journal_rollback`. Missing prior refuses
`journal_unavailable`; malformed or wrong signed prior refuses `checkpoint_invalid`.
Keep originals at restart and preserve older publication/recovery history even
when the next invocation needs only the last prior checkpoint.

Store the covering checkpoint at publication time. For an attestation entry E_n,
retain C_n or the nearest subsequent qualifying covering checkpoint with every
linking entry. If the registry appends a fresh snapshot reissue as E_(n+1),
retain E_(n+1), C_(n+1) and the exact new snapshot referenced by C_(n+1); never
rewrite C_n. With the owner-registry bundle's raw anchor at n-1, the anchor, E_n
and E_(n+1) occupy three of the journal's 64 total entry slots. An anchor leaves at most
63 new entries, including any reissue. Supply one candidate checkpoint; the
optional second is fully admitted fork evidence, never a previous/next
checkpoint slot. Keep the per-record, 540672-byte journal aggregate and separate
532480-byte freshness aggregate independent of the registry's 512 KiB intake
and separate 2 MiB full-proof received-bundle caps. The full bundle includes
context, C(n-1), snapshot, witness/control evidence and transport encoding;
its 2 MiB cap does not promise that any maximal proof fits the separate
8192-byte WC1 window, including the LF. Preflight the complete encoded
real-head wrapper before intent. If complete inclusion or continuity exceeds
an applicable cap, refuse before the intent, with no truncation or skipped
entry; do not split away completeness. Advance
anchors only through separately verified current bounded steps, persisting each
accepted anchor; expired intermediate checkpoints require another qualified
path, not an old time sample.

At original acceptance use the real qualified time/W, current signed snapshot
and already independently verified witness projection. VerifyJournal checks freshness
(max_age <=60 seconds), genesis/ancestry and fork/rollback as specified. Its
returned plan is not publication or a witness-update permit; atomically retain
exact proof and required watermark before authority use, and separately satisfy
WC1. Never feed an old captured time sample to obtain a *current* verifier verdict.

On restart retain the exact publication acknowledgement and inclusion bytes.
Recheck their hashes, signatures, binding and durable transaction association;
historical validation context explains the original decision only. An aged
covering checkpoint remains historical inclusion evidence, not a fresh VerifyJournal
checkpoint verdict. Obtain fresh challenge-bound WC1 head/control/continuity
confirmation and live active status/scoped revocation evidence (max age <=60 s)
before reopening, under final serialized authority checks. Missing/stale or
conflicting evidence keeps messages closed; restart does not turn `published`
into `active`, forget a fence or erase a stored acknowledgement.

D38=B separates ongoing snapshot freshness from retained publication inclusion.
At initial publication, **VerifyJournal is outside receipt mode**: its candidate
checkpoint and exact referenced snapshot must be current under real qualified
Now/W and protected max_age<=60s. A receipt cannot waive that snapshot's own-age.
The registry-authorized head-change reissue path supplies current evidence:
retain cumulative entries, advance snapshot issued_at strictly, append the
add/revocation/1 entry and retain its descendant checkpoint/exact snapshot.
The three-entry proof and exact prior are captured by the byte-imported
[P-JRN-publish-reissue family](../vectors/waggle-s4/README.md).
An aged unchanged initial base still refuses; freshness/receipt composition
cannot convert it into a journal accept. Retain pending, `key_not_enrolled`,
no T2 activation and no T1 fallback until a valid publication proof exists.
Never lower Now/W or replace a snapshot beneath an existing checkpoint.

### 4.1 B live status: full freshness admission

After publication, current registry-domain status uses the complete
`verifier.New(context).VerifyFreshness(chain, checkpoint, ids, keys)` contract,
not a Boolean assertion or a receipt invented by the adapter. The exact inputs
are protected independently of transport and bound to the original proof:

| Input | Authoritative value and custody |
| --- | --- |
| `AgentRevocationRoot`, `RegistryOwner` | Protected exact registry-revocation key/purpose/attestation_root and owner; enforce the inherited distinct-role catalog and scope before evidence. Never select these from received assertions. |
| `FreshnessAnchor` | Exactly `{registry_id,owner,publication_seq,freshness_id,issued_at,snapshot,registry_seq,checkpoint_id}` from the last durable accepted publication. Sequences are safe integers, registry_seq positive; IDs/timestamps use the pinned canonical types. Explicit authorized genesis has publication_seq0 and null freshness_id/issued_at, but still a positive authenticated registry checkpoint/snapshot. Missing/lost state never bootstraps. |
| `JournalWitness`, `WitnessReadAt` | Independently authenticated six-field registry/owner/sequence/head/checkpoint/previous-checkpoint projection above, plus the protected time of its fresh read. Read time is >=tip.issued_at, <=min(Now,W), and at most max_age<=60s old. Never copy read time from received assertions. Resolve WC1 intent/resolution/control/continuity, not a cached head. |
| `chain`, `checkpoint` | Original oldest-first signed freshness/1 records, exact signed checkpoint, protected root/owner/scope pins. Verify every global publication position, strict time, same-head prev and head-change null-prev rule. Normal proof has <=64 publications/one checkpoint/532480 bytes; independent journal bounds remain. |
| `SignedSnapshots` | Exact original registry-root signed complete revocation/1, snapshot ID equal to both tip.snapshot and checkpoint.snapshot, protected max_age<=60, and independently qualified cumulative `rollback_safe`. Signature/schema/all entries and future-effective matching still verify, even when the base snapshot itself is old. |
| `Time`, `Now`, `WatermarkAvailable`, `Watermark` | The real qualified shared timeconf decision and independently continuous durable W, not wall clock, receipt timestamps or guessed W=Now. Keep provider uncertainty/hold/continuity and existing operation/release budgets. |
| `ids`, `keys` | At most64 exact queried record IDs (including T and applicable attestations) and at most64 key IDs for the dependent admission. Query coverage is not inferred from an empty array or a previous accept. Active generation/binding, certificate validity and WC1 remain separate mandatory checks. |

`rollback_safe` comes only from qualified cumulative-publication evidence:
retain every effective and future-effective entry without postponing from,
strict issuance, same-time byte identity, justified ancestry and restore
continuity. Never infer rollback_safe from a re-anchor, complete=true or a higher seq.
An authenticated head alone does not prove unseen issuer honesty or cumulative
publication. Unavailable evidence refuses; it is not an empty revocation set.

Before dependent use, atomically retain exact signed inputs, both protected
endpoint references, accepted new anchor and Plan.Watermark, cumulative-policy
provenance and authenticated read/witness evidence in the single recoverable
state/audit transaction (§5). Retain previous originals for recovery; no eviction.
No receipt/plan grants Commit or an effect permit. Repeat current authority and
fresh head checks at the serialized release boundary; no RPC or provider refresh
under generation/store locks, no new egress and no renewed deadline.

### 4.2 S5 process-local receipt composition

Only full successful VerifyFreshness or VerifyFreshnessReanchor returns
`Result.FreshnessReceipt`; every refusal has zero Plan and nil receipt. Commit
its accepted anchor/W/evidence transaction first; then supply the original
opaque pointer in Context with the **admitted new anchor**, real current facts
and the **same immutable SignedSnapshots Evidence** for its entire lifetime.
One Evidence per receipt lifetime is mandatory. Rebuilding it byte-identically
invalidates the receipt. Snapshot bytes, root/owner/witness/anchor/read bindings,
cumulative/rollback-safe premise or process change requires fresh full F
verification, including after a change that later returns to the same values.
After restart, revalidate retained inputs and perform a new VerifyFreshness;
never deserialize/recreate the old receipt, use Present to admit it, or persist
private fields/a verified=true surrogate. A re-anchor must mint its own fresh
receipt after full successful recovery verification, never reuse the old one.

Keymaker adopts registry-root own-age composition only for receiver/agent
VerifyAttestation, VerifyMessage and its standalone registry CheckRevocation
path. It creates no Authorize/VerifyEnvelope capability. For completeness the
pinned §2.10 classification covers **all 17 exported callables** (VerifyAttestation
has two path classes, counted once):

| Class | Exported calls | Rule |
| --- | --- | --- |
| May waive only bound registry snapshot own-age | VerifyAttestation(agent), VerifyMessage, CheckRevocation; library Authorize and VerifyEnvelope where applicable | Validate R1–R3 and all other checks. CheckRevocation's explicit root must match. Keymaker adopts only the three named receiver/status paths. |
| Validate-only | VerifyAttestation(device=true), VerifyOperator, VerifyServiceAttestation | Supplied receipts validate R1–R3 but cannot waive operator-root/grant-root own-age. No new operator or service policy is activated. |
| Outside receipt mode | VerifyJournal, VerifyFreshness, VerifyFreshnessReanchor | Ignore FreshnessReceipt, RequireFreshnessReceipt and FreshnessMarginSeconds even if invalid; independently run complete journal/F contracts. |
| Context storage only | New | Does not verify a receipt or grant admission; the later method chooses the class. |
| Context-free evidence | Present, Evidence.IsAvailable | No receipt-consuming admission; Present still rejects receipt construction. |
| Context-free code mapping | OperatorRecordCode | No receipt-consuming admission or freshness authority. |
| Origin metadata only | FreshnessReceipt.Audit | Authentic-origin bool and detached Audit() identifiers only, never currency or authority. |
| Unsupported persistence | FreshnessReceipt.MarshalJSON, FreshnessReceipt.UnmarshalJSON | Refuse receipt JSON encoding/decoding; no accepted wire or persistence format. |

For consumers/validate-only calls, `RequireFreshnessReceipt=true` rejects absence;
optional nil/false retains legacy own-age behavior. **Any supplied invalid receipt
refuses even when own-age would pass; no legacy fallback.** R follows the
existing trusted-time gate and precedes validity continuation. Preserve exact
freshness_receipt_unavailable, freshness_receipt_invalid,
freshness_receipt_binding_mismatch and freshness_receipt_expired decisions locally
and the existing outer native outcomes. An old base can pass only its bound
registry own-age replacement: signatures, completeness, all effective/future
revocation matches, active status and current authorization are never waived.

Expiry is fixed at mint: `E=min(tip.issued_at+A, issuing WitnessReadAt+A)`, A<=60s.
Use requires `max(Now,W) < E - FreshnessMarginSeconds`. The nonnegative integer
margin0..60 comes conservatively from the qualified timeconf uncertainty/decision
bounds, not a caller option; refuse if a safe supported margin cannot be mapped.
It only tightens admission, never extends E, changes Now/W or replaces the
provider's own gates. Newer witness reads cannot extend expiry; the read must
remain non-future and no earlier than the mint read. An inclusive-age F accept
at E may mint a receipt already unusable by consumers. Future from may become
effective before expiry and MUST still revoke.

Audit derives receipt metadata only through `Audit()` identifiers: registry,
owner, snapshot/checkpoint/freshness IDs, reanchored status and old endpoint IDs.
Its bool proves origin only. No opaque pointer/private fields or original
proof bytes enter a base audit row; §5 binds retained typed artifacts by digest.
Registry S5 never extends operator-root device/act evidence: Q7 persistent revoke
remains closed until its independent sources/durable gates and D42 policy exist.
Current registry freshness neither refreshes stale operator evidence nor revokes
otherwise current independent operator evidence merely because registry B is idle.

### 4.3 Explicit re-anchor and owner recovery runbook

Normal catch-up admits at most64 publications (about21m20s at20s cadence or64m
at60s, fewer if the anchor is resent; byte/head bounds can fail sooner). This is
a proof-count limitation, not an availability guarantee or retention interval.
Do not truncate, skip positions or use historical clocks to pass it. Preserve
full registry history and independently witnessed/off-node heads.

Re-anchor is an explicitly selected owner-approved recovery path using
`VerifyFreshnessReanchor(tip, checkpoint, ids, keys)`, never automatic fallback
from a failed normal proof. It requires a real positive retained old publication,
fresh authenticated current witness/read, exact signed tip/checkpoint/snapshot,
qualified cumulative rollback_safe and real Now/W. Tip publication_seq and
issued_at must strictly advance. SAME registry head is allowed only at equal
registry_seq with identical checkpoint ID/head and snapshot; lower sequence or
equal-position conflict refuses. A head advance needs its validated new binding.
No re-anchor establishes missing genesis, cumulative truth or hidden ancestry.

Owner runbook, no new command or installed recovery implementation:

1. Stop dependent message admission, retain pending/fences, original anchor,
   raw endpoint publications/checkpoints, W, policies and all gap/fork evidence.
   Classify normal bounded catch-up versus explicit recovery; normal failure is
   not authority to choose recovery. Obtain protected owner approval for this
   exact registry/installation/endpoints and the skipped-fork detection cost.
2. Obtain independent authenticated current WC1 head/control/continuity, protected
   read time, exact signed tip/checkpoint/snapshot, real timeconf/W, and qualified
   cumulative/restore provenance outside locks. No source or premise: remain
   closed. Missing current evidence is not repaired by a historical receipt.
3. Pure-verify the explicit sibling. On refusal keep all old anchors/evidence;
   no truncated normal proof or partial Plan use. On accept independently check
   Plan.Reanchor's flag/count and both endpoint IDs against retained originals.
4. Reserve real encoded bytes for the full recovery transaction and copies;
   durably retain §5's typed artifact and endpoint evidence. Atomically commit
   new anchor, W, artifact references and event/binding audit. Unknown append,
   sync/rename/cleanup outcome fences; qualified exact-outcome recovery only,
   with no fabricated re-anchor or receipt. PC2/C obligations remain separate.
5. After commit, use the newly minted receipt with its one immutable Evidence
   only while R and every current release predicate still pass. Reopen only
   after all §7 gates, not merely because an endpoint audit digest exists.

Cost accepted only by that explicit recovery approval: **skipped freshness-fork
detection is lost** for intervening publication positions. Endpoint rollback/fork,
current witness and effective revocation checks remain, but cannot prove the
skipped chain was consistent. Qualified cumulative publication independently
preserves no-hidden-revocation; re-anchor, complete and higher seq do not prove it.
Retained full history, endpoint bytes/audit and off-node heads enable later
cross-check, not a claim of universal fork detection.

## 5. Audit mapping and explicit base deltas

Use the existing closed [base §11](keymaker.md#11-audit-and-fail-closed-recovery)
record, with no new members from this message slice. The Q7 operator-only members
MUST be absent on issuance, transition and `sign_message` records. Internal
transition rows have `surface:control`,
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
| `message_freshness_commit` (S4/S5 adoption) | Normal freshness or explicit re-anchor anchor/W/evidence commit, phase `freshness` or `reanchor`; §5.1 artifact, never a message signature or generic reconcile. |
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

**Explicit proposed §11 deltas:** admit the nine listed internal operation literals
above, internal request-ID grammar and their event/commit pairing; extend the
`binding_commit` content digest and schema-aware replay to the complete inventory;
add the already proposed `sign_message` operation/`swarma-msg` domain and retained
selection/result transaction. There are **no new audit members**, enum result
values, revocation domains, checkpoint-signing domains or implicit optional fields.
State migration is required; historical audit bytes/hashes are never rewritten.

### 5.1 Retained freshness and re-anchor artifact

The new operation is an explicit §11 operation-literal delta only: no audit
member, result enum or hash algorithm is added. It uses surface/control domain
and `request_id:msg:<transaction>:freshness` or `:reanchor`, with a unique retained
service transaction ID. `payload_digest` hashes the exact canonical artifact,
not a receipt pointer, log string or the snapshot containing its own audit link.

The proposed versioned artifact has exactly
`{kind,transaction,mode,policy,old_anchor,new_anchor,watermark_before,watermark_after,
 witness,witness_read_at,proof,checkpoint,snapshot,endpoints,receipt_audit,reanchor}`.
`kind` is `message-freshness/1`; mode is `normal` or `reanchor`. Anchors have the
exact eight fields in §4.1; witness is the six-field authenticated projection.
Policy is an immutable reference binding protected root/scope, cumulative/restore
qualification and time policy. Proof is the bounded ordered array of original
signed publication references; checkpoint/snapshot are references to exact
signed bytes. Every artifact reference is `{hash,bytes}` with the established
SHA-256/encoded-byte bounds, resolving to already synced retained immutable
objects. No self-reference/circular hash or unresolved URL is permitted.

`endpoints` is exactly `{old,new}`; each is `{freshness,checkpoint}`, references
to the corresponding original signed publication/checkpoint bytes (old freshness
null only for authorized normal genesis, never re-anchor). `receipt_audit` is
null if no authentic producer receipt exists, otherwise a detached typed copy
of Audit() identifiers only per §4.2, never authority. An accepted producer
commit requires authentic Audit origin; null is only unsuccessful-attempt evidence
and cannot advance anchor/W. For normal mode reanchor is null; for reanchor it is exactly
`{reanchored:true,skipped_publications,old_freshness_id,new_freshness_id,
 old_checkpoint_id,new_checkpoint_id}` from Plan.Reanchor. The nonnegative exact
count is **new publication_seq - old publication_seq - 1**, including zero.
Endpoint IDs MUST recompute from referenced originals and match both anchors;
checkpoint references bind both full endpoint registry heads. A digest without
retained resolvable endpoint evidence is insufficient.

Reserve artifacts, predecessor/successor bodies, recovery/staging copies and
audit headroom under the shared state budget before writes. File/directory sync
and exact artifact hashes precede commit references. Publish accepted new anchor,
Plan.Watermark and these references in one serialized recoverable snapshot/
audit transaction, pairing message_freshness_commit with binding_commit and
existing rename/directory-sync barriers (and PC2 common-root/cleanup if enabled).
No use/release before proven durability; preserve exact uncertain candidate,
old/new bodies and holds on any unknown outcome. Recovery must resolve the
recorded outcome, never re-mint a receipt or recalculate a skip waiver. A fresh
F decision after restart remains mandatory. Artifacts/histories are retained;
this defines no eviction or on-disk schema-2 bypass. The explicit successor
codec/migration/floor and recovery qualification in §2.1.1 are activation gates.

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
| MS-S12 proof substitution/fork | Wrong T/owner/root/stream, skipped middle entry, later unrelated checkpoint, equal-seq different signed head/checkpoint or intent-only receipt never qualifies; fence and retain fork evidence, no partial plan use. For a same-content snapshot reissue, substituting the previous snapshot under the new checkpoint refuses; rewriting the old checkpoint at the same sequence without the reissue entry is a fork. | Original exact target entry, complete ancestry, independently verified WC1 committed pairing and matching projection qualify inclusion. Also cover a registry-authorized reissue: raw anchor E_(n-1), attestation E_n, add/revocation E_(n+1), descendant C_(n+1), and its exact fresh snapshot qualify within all bounds; activation still requires live authority. |

The imported byte-only S4 family maps P-JRN-publish-reissue to MS-S12's
three-entry control. Its old-snapshot/missing-reissue/missing-record negatives
map to MS-S12 with exact checkpoint_snapshot_invalid/journal_chain_broken/
journal_chain_broken and empty plans. The remaining three map below. All new
rows are **PENDING consumer execution**; imported expected codes are upstream
fixture expectations, not a claim that Keymaker executes this verifier today.

| Vector | Forbidden outcome / exact rejection or invariant | Nearby positive control |
| --- | --- | --- |
| MS-S13 missing prior | N-JRN-publish-reissue-missing-prior: exact prior unavailable despite complete suffix -> journal_unavailable/empty plan, anchors unchanged. | P-JRN-publish-reissue retains C(n-1) at the protected IDJournal key and IDJournalAvailable=true. |
| MS-S14 wrong prior | N-JRN-publish-reissue-wrong-prior: wrong genuinely signed prior bytes at that key -> checkpoint_invalid/empty plan; conflict slot cannot substitute. | Same positive with exact authenticated prior content ID/registry/owner/seq/head. |
| MS-S15 prior time | N-JRN-publish-reissue-backward-time: candidate time before prior -> journal_rollback/empty plan, even if candidate/snapshot otherwise current. | Same positive's forward time; a separate equal candidate/prior time control accepts with every other predicate valid. |
| MS-S16 separate bounds | 65 freshness publications, 2 freshness checkpoints or532481 bytes refuses without anchor/W advance; journal65/3/540673 remains a distinct refusal. Over8192-byte protected prior or unreserved expanded state refuses. | Complete <=64/1/532480 freshness proof and <=64/2/540672 journal proof each meet their own bounds, separately reserved prior/evidence and shared256MiB; maxima need not coexist. Independent 512 KiB intake, 2 MiB full-proof bundle and 8192-byte WC1-including-LF boundaries are paired in MS-S23–MS-S25; overflow refuses before intent. |
| MS-S17 full F facts | Missing/malformed eight-field anchor, unauthenticated/future/stale read or head, gapped/forked publications, mismatched snapshot, uncovered queried ID/key or unqualified rollback_safe refuses, no authority advance. | Full F with exact six-field head, real Now/W, signed complete chain/snapshot, authenticated read and independently qualified cumulative evidence accepts a candidate; future-effective entries still revoke when effective. |
| MS-S18 receipt premises | Rebuild identical Evidence, copy/serialize/forge receipt, change root/owner/anchor/witness/read/snapshot or cumulative premise (even change-and-return), or reuse after restart -> refuse/fence; no legacy fallback. | Original opaque pointer with one immutable Evidence, admitted new anchor and fresh current facts passes only after atomic producer commit; restart runs full F anew. |
| MS-S19 expiry/margin | At max(Now,W)>=E-margin, negative/unsupported margin, missing timeconf mapping or newer read used to extend E -> refuse; inclusive F boundary is not consumer acceptance. | Real qualified margin0..60, max(Now,W)<E-margin and non-future/read-not-before-mint pass; increasing margin can only reduce admission. |
| MS-S20 API scope | Supplied invalid receipt refuses in every consumer/validate-only path even with current own-age; required absence refuses. Receipt cannot refresh operator/grant evidence or current-generation authority. | Valid bound aged registry snapshot works only in applicable receiver/status paths. Optional absence uses current own-age; VerifyJournal/F independently ignore receipt fields and require full proofs; device/operator remain own-age bound. |
| MS-S21 re-anchor selection | Automatic normal-error fallback, zero/missing old publication, backward tip time/sequence, lower registry head or equal-seq different checkpoint/snapshot -> refuse with unchanged state. | Explicit approved sibling with positive old anchor, strictly newer publication/time, exact fresh evidence and qualified cumulative premise accepts SAME identical registry head or a valid advance. |
| MS-S22 audited skip | Missing flag, wrong skipped count/endpoints, unresolved original bytes, new audit members or uncertain sync -> fence/no release, retain exact evidence and unknown transaction. | Exact count including zero, reanchored=true, both endpoint freshness/checkpoint IDs and retained bytes, atomic artifact/new-anchor/W/audit commit preserve evidence; approved skipped-fork-detection loss remains explicit. |
| MS-S23 intake boundary | 524289 bytes (512 KiB+1) total intake/evidence refuses before the intent; no truncation or change to records, sequences, anchors or W. | Exactly 524288 bytes (512 KiB) passes the intake size gate with all per-record, encoding, state and other applicable limits valid; this is not the separate full-proof route. |
| MS-S24 full-proof boundary | 2097153 bytes (2 MiB+1) aggregate received full proof bundle, including context, C(n-1), snapshot, witness/control evidence and encoding, refuses before the intent; no truncation, splitting away completeness or authority change. | Exactly 2097152 bytes (2 MiB), including the same complete inventory, passes only the full-proof size gate with all J/F, per-record and state limits valid and the complete WC1 wrapper independently fitting its 8192-byte window including LF; no promise that any maximal proof fits WC1. |
| MS-S25 WC1 boundary | Complete encoded real-head checkpoint wrapper of 8193 bytes including LF refuses before the intent even if the bundle fits 2 MiB; no truncation, pagination, intent, sequence or anchor/W advance. | Exactly 8192 bytes including LF passes the WC1 window size gate with otherwise valid complete prior/head/control evidence and every other applicable limit satisfied; passing a larger outer route alone never satisfies this gate. |

## 7. Remaining gates

**K3 activation stays closed.** The following conjunctive gates, not a library
accept or this spec adoption alone, permit enabling it:

| Gate | Required integration/qualification before activation |
| --- | --- |
| K3-G1 exact adapter/version | Reviewed S4/S5 dependency upgrade and receiver/live-status adapters, explicit successor state/artifact codecs, protected floor and quiesced migration/recovery retaining every S2 history/result/fence; current production still rejects populated publication state. PC2 combined-root/preimage/restore acceptance remains required wherever PC2 participates; no second commit point or implicit C switch. |
| K3-G2 actual authority | Qualified protected root/owner/lineage/epoch policy, purpose-5 scope and <=24h lifetime, exact active-generation/binding/T/current-status checks and qualified-T1 renewal; native signing/retry/actual-release implementation. Existing kernel/generation/enrollment deadlines and gates remain. |
| K3-G3 publication custody | Real owner-registry publisher boundary, D39 raw anchor and exact prior IDJournal custody, current head-change reissue/inclusion proof, complete signed records/retention and independent WC1 committed pairing/head/control/transport/custodian. No client URL, extra egress or fake witness. |
| K3-G4 time and cumulative premises | Qualified timeconf collection/uncertainty/hold/continuity and safe margin mapping within existing deadlines, durable W bootstrap/advancement/restore continuity, real authenticated witness read and independently qualified cumulative rollback_safe. No W=Now, old-clock or complete=true substitutes. |
| K3-G5 receipt and live B | Atomic retained F proof/new-anchor/W before use; original in-memory pointer/one Evidence lifetime, full current queries and R checks at release/restart, no old-base initial publication via receipt, no operator-root extension. |
| K3-G6 bounded recovery/audit | Reviewed explicit owner re-anchor policy/runbook, retained endpoint/skip artifact and atomic audit/root transaction, independent no-hidden-revocation premise and declared skipped-fork-detection cost; exact unknown-outcome handling, capacity/archive and old-instance exclusion. Without re-anchor approval only bounded normal catch-up is usable and over-bound outage stays closed. |
| K3-G7 executable evidence | Execute paired MS-S01–MS-S25 and imported positive/six negatives, actual crash/sync/restart/restore/replay/receipt/margin/expiry and negative-control evidence, live multi-UID/native release and real storage/provider/publisher/WC1/capacity qualification. Text rows and upstream byte equality are not these passes. |

Q7 persistent revoke remains independently closed pending its sources, durable
integration and D42 offline-root policy; S5 registry composition neither opens
nor substitutes that operator-domain gate. All base root-custody/generation and
owner recovery requirements remain. No supplied formal catalog surface table
(brief gap); no requested spec row is excluded. Runtime code/tests, pin changes,
deployment, publisher/receiver transport and real authority qualification are
outside this spec-only slice and remain PENDING, not implementation claims.
