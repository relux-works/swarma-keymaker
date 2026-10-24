# State-witness service protocol and server

Status: proposed normative contract, **spec only; not implemented, deployed or
qualified**. Implementation ownership is unassigned. Option A remains in force
until the relevant option C consumer and service gates are accepted and qualified.
MUST and MUST NOT describe the proposed service. This document opens no listener,
changes no consumer record format and grants no key a new signing language.

Public contracts checked for this proposal:

- [Keymaker consumer](keymaker-witness.md), especially §§3.1–3.3, 4, 5 and 8;
  [Keymaker audit](keymaker.md#11-audit-and-fail-closed-recovery).
- [The registrar §4.5](https://github.com/relux-works/swarma-registrar/blob/2219f70358fb7b5c7d66f229c80a8ba4a1fe0230/spec/registrar.md#45-external-high-water-witness-option-c-normative-draft),
  [§9](https://github.com/relux-works/swarma-registrar/blob/2219f70358fb7b5c7d66f229c80a8ba4a1fe0230/spec/registrar.md#9-audit-and-failure-ordering-normative)
  and [Appendix C.3](https://github.com/relux-works/swarma-registrar/blob/2219f70358fb7b5c7d66f229c80a8ba4a1fe0230/spec/registrar.md#c3-external-witness-rulings-and-activation-dependencies-informative).
- [Waggle S0 §2.6](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#26-root-signed-attestations-and-shared-revocation)
  and [§7](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#7-consumer-gates-and-remaining-risks): distinct root roles,
  trust-node isolation, independent checkpoints and future registry-journal gate.

- [Owner-registry service design draft](https://github.com/relux-works/swarma-owner-registry/blob/1cc08a6b4fd1cd5a123a5b38e4c3f17114f32496/design/owner-registry.md),
  especially §§2, 4–7 and Q2/Q9/Q10/Q12. Independently reviewed, **not yet
  content-accepted**; its unpublished content formats remain separate gates.

## 1. Scope and trust boundary

The service provides append-only, **linearizable per-stream order**, one exact
record at each position, durable retention before acknowledgement, and a fresh
challenge-bound latest head. Its order includes unresolved consumer intents.
A hash or signature authenticates bytes; latestness also requires honest
serialized service execution and independent retention. Wall-clock freshness,
TLS authentication and cached receipts alone do not establish it.

The decided placement is a separately administered trust node outside the
platform's administrative domain, shared with the owner registry in separate
accounts and processes, with the trusted checkpoint kept off that node. The
registry writer has no witness append or administration permission. Co-location
is one host failure/compromise domain, despite process and key separation.
No agent or platform administrator gains administrative access there.

The witness does not reconstruct consumer state, validate enrollment/grant
contents, decide whether local durability occurred, authorize a signature or
prove human intent. It stores opaque commitments with the minimal framing,
authentication and chain checks in §3. A valid consumer record is not proof that
a compromised consumer followed its protocol. Single serving-instance exclusion
remains a consumer responsibility; append CAS is **not a distributed signing
lock**. Witness serving instances also require qualified exclusion on restart.

Observed forks/regressions fence, but signatures cannot prove a compromised
witness or registry honest. An undetectable joint rollback with no independent
surviving evidence remains outside the guarantee. The strict restore profile
requires §8's independent checkpoint barrier; it is a proposed dependency, not
an available platform capability. No fallback weakens that requirement silently.

## 2. Stream identity, provisioning and roles

`service` is a stable protected witness-installation identifier. Every `stream`
and service identifier matches `[a-z0-9][a-z0-9._-]{0,127}`: 1–128 ASCII bytes,
case sensitive, no aliases or normalization. A stream ID is never inferred
from a UID, hostname, supplied URL or missing local state.

A protected binding has exactly `{service,stream,consumer,identity,lineage,
profile,writer_epoch,writer_id,record_key,transport_pins,readers}`. `consumer`
is exactly `keymaker`, `registrar` or `owner-registry`. The binding fixes:

| Type | Protected identity and record profile |
| --- | --- |
| `keymaker` | One station and registry lineage; identity is exactly the existing `{product,project,agent}` station tuple. Purpose-3 signed profile from Keymaker §3.2. No shared station stream. |
| `registrar` | One explicitly provisioned registrar consumer/lineage; identity is its protected opaque stable identifier. Exact flat record from registrar §4.5.1, authenticated by its separately pinned transport writer. |
| `owner-registry` | One registry-root/owner scope; identity binds that root and owner. Checkpoint intent/resolution inclusion profile in §6, submitted only by the independent witness-side bridge. |

For owner-registry, identity is exactly `{registry_id,owner}`, with independently
pinned root ID and exact owner. `lineage`, `profile`, identity strings and each identifier are nonempty UTF-8
<=255 bytes, with the station object's exact registered names. Writer policy epochs
are positive safe integers, distinct from record-signing key epochs; `writer_id` is a protected principal identifier,
not a caller selector. `record_key` is the purpose-3 public key/epoch/purpose
binding for Keymaker, or null for registrar/owner-registry; the checkpoint profile pins
the registry root independently of its submitting principal. Transport pins
are exact certificate public-key pins, separate from record-signing keys.
Provisioning bounds these closed nested values and ACL lists under §9; unknown
members and overlapping forbidden roles refuse.

The administrative chain is service-wide. Before provisioning, every bound reader
must have explicit owner authorization to read its complete control metadata,
including other bindings and administrative expected-head commitments; that
disclosure is part of this proposed profile. It grants no other stream record
or latest/proof operation access. Consumers requiring private control metadata
cannot share this profile without a separately reviewed isolation design. No
unauthorized lookup may disclose a foreign record/head or control page.

Only signed, independently authorized administration (§7) may provision an
unused stream or rotate its writer. Provisioning binds the exact first-record
hash and independent consumer bootstrap authorization to the initial binding.
It does not append a consumer record or reconcile local consumer state. The
first append consumes that one-use bootstrap grant atomically. An empty stream
without it is `bootstrap_required`; an authorized but still-empty stream returns
`stream_empty` to latest reads, never a successful zero-record head. No restart,
repair, restore, master rotation or outage creates a new empty stream or
implicitly selects option A. A provisioned stream is never deleted/reused.

The witness signing key is Ed25519, separately provisioned from every consumer
key, registry root, grant/operator root, administrator signing key and transport
key. Public key IDs are `sha256:` plus lowercase SHA-256 hex of raw32; signatures
are canonical unpadded base64url raw64 with strict Ed25519 verification. Protected
pins establish the role; a claimed purpose or successful signature cannot
promote a key. In particular purpose 3 signs only the existing Keymaker record
domain, never a TLS transcript, receipt or arbitrary request.

The registry signing/publishing principal is **not** the checkpoint observer
(the separate witness-side consumer/bridge in the registry draft).
It cannot call append on any witness stream, including the checkpoint stream,
provision streams, rotate keys, modify witness storage or administer the
independent checkpoint custodian. The observer has its own credential and only
its provisioned checkpoint stream. Giving the registry writer that credential
would violate the chosen trust boundary, not implement this protocol. The
registry content root signs scoped revocations, snapshots and checkpoints only;
a distinct maintainer role signs Git commits. Neither is a witness writer or
witness signer. No existing key-service purpose is assigned to the bridge.

## 3. Bytes and minimal server validation

All protocol objects use registrar CCJ-1: duplicate-aware UTF-8 parsing,
scalar-sorted keys, shortest safe-integer tokens, canonical escaping, no BOM,
normalization, unknown members, duplicate decoded names, floats or trailing data.
Received JSON MUST equal its CCJ-1 encoding. `N = 9007199254740991` is the
maximum safe integer. All encodings called base64url are strict, unpadded and
canonical, including unused bits. No layer silently repairs supplied bytes.

A consumer record is its exact canonical UTF-8 envelope followed by **one LF**.
`record_hash = lowercase_hex(SHA-256(complete_record_including_LF))`; it has
64 hex digits without a prefix. An expected/previous record hash uses that same
form; 64 zeroes is only the provisioned genesis predecessor. Stream record
sequences are integers 1 through N, exactly +1. Zero occurs only in a request's
explicit authorized genesis anchor, never as a stored record. Exhaustion fences
without wrap, truncation, renumbering or implicit new stream. Intent-based
consumers require room for both records before beginning an intent. The server
refuses a recognized intent at seq=N as `sequence_exhausted` before storage.

The server checks the following, and no application state beyond it:

| Profile | Checked outer fields/projection |
| --- | --- |
| Keymaker | Exactly `{body,signature}` plus LF; body has exactly the fields enumerated in consumer §3.2: v,type,consumer,stream,station,seq,state_epoch,kind,commit_class,base_state_digest,state_digest,prev_hash,intent_hash,key_epoch,key_id. Check canonical types/bounds/enums, configured consumer/station/stream, purpose-3 writer epoch/key, strict signature under `keymaker-witness-record/1` + NUL + CCJ-1(body), seq/prev_hash. Extract acknowledgement fields verbatim. Do not parse a state inventory or treat state_digest as proven local state. |
| Registrar | Exactly the existing flat v,stream,seq,kind,revision,digest,prev_hash,intent_hash object plus LF; check profile types, v=1, stream/chain, digest/hash forms and the configured full revision-object-ID grammar. No record signature or new record member is required. Authentication comes from the pinned writer transport identity. |
| Checkpoint inclusion | Only the closed witness wrapper/projection and independently verified public checkpoint binding specified in §6; the registry's inner journal, signed attestations and grants are not interpreted as witness authority. |

All profiles check LF-inclusive hash equality, expected head, authorized current
writer and binding, bounded strings/arrays/depth, and exact signed receipt
construction. Keymaker/registrar semantic intent/committed pairing, candidate
revision/state digest, state-epoch meaning and whether a commit actually occurred
remain consumer checks. Registry wrapper pairing has the additional mechanical
checks in §6; it does not establish local durability or application semantics. The witness never synthesizes a resolution, cancels an intent or treats
an equal application digest as permission to resume. A malicious writer can
poison its own stream; the consumer must then fence rather than infer authority.

## 4. Transport and operations

Recommend a dedicated HTTPS endpoint using mutually authenticated
[TLS 1.3 (RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446.html), with pinned
server and client certificate public keys. Disable early data/0-RTT and session
resumption for this profile. Authenticate both peers before application data;
no public-Web-PKI-only fallback, HTTP redirect, cookie, bearer token or caller
identity header. Certificate validity and pin rotation need qualified clock and
operator policy. TLS credentials are distinct from every record-signing key.

Each POST to `/witness/v1` contains exactly one bounded CCJ-1 request object:
`{v:1,request_id,timeout_ms,method,params}`. request_id is 32 lowercase hex
characters for response correlation, not effect deduplication or authority.
timeout_ms is integer 1–5000, narrowed by the caller's remaining total budget.
Responses are exactly `{v:1,request_id,result}` or
`{v:1,request_id,error:{code,retryable}}`. HTTP 200 carries either framed outcome;
authentication/framing failures may close without an application response.
No caller-controlled URL or key selector reaches a lookup or signer.

| Method | Exact params | Authorization / result |
| --- | --- | --- |
| `append` | `{stream,expected_seq,expected_hash,record}`; record is base64url of exact line bytes | Current bound writer only. Returns original signed receipt as base64url. Checkpoint stream requires its independent observer. |
| `latest` | `{stream,challenge,anchor,control_anchor}` | Bound reader; challenge decodes to exactly 32 unpredictable client bytes. Each anchor is exactly `{seq,hash}` from protected surviving evidence. Returns signed head as base64url. |
| `proof_page` | `{stream,page_hash}` | Bound reader; returns base64url canonical proof page committed by the head's proof manifest. It is historical evidence, never a latest-head substitute. |
| `admin` | `{action}`; action is base64url of the exact signed admin line including LF | Separately pinned administrative transport plus signed action in §7; never a consumer or registry credential. Returns signed control receipt. |

### 4.1 Compare-and-append and exact retries

Authenticate and authorize the stream before disclosing its existence/head.
Bound and validate the supplied line, then serialize against that stream's
append/latest order. For a new record, expected_seq/hash MUST equal the exact
current durable head and record seq/prev_hash MUST equal expected_seq+1/hash.
Genesis additionally needs the exact protected bootstrap grant. A different
record at an occupied position refuses `position_conflict`, even if signed by
a valid writer; a gap/wrong predecessor refuses `head_conflict`.

For an already occupied position, **byte-for-byte identical complete record**
and its original predecessor pair return the original receipt, without a
second append, receipt re-signing or consumer-state effect. This check may use
an authorized current writer after key rotation, verifying the original
historically authorized record; an inactive old credential gains no access.
A digest match alone is not exact equality. Request IDs never override this rule.
A prepared or outcome-unknown transaction is not yet an acknowledged occupied
position: exact retry must reconcile and complete every durability/custodian/head
barrier before releasing its stored receipt. Never expose a prepared signature
as success before those barriers.
For checkpoint records, validated same-registry-position fork detection in §6
precedes a generic position-conflict result; unauthenticated data cannot raise
a signed-fork alarm.
A repeat at an older position is not proof that position is the latest.

New append ordering is: precharge storage; persist exact record, original
receipt and audit/transaction intent; sync files and containing directories;
obtain §8's independent durable checkpoint confirmation; atomically publish
and sync the head/resolution marker; then acknowledge. Per-stream ordering is
held through this boundary. Never acknowledge a queue, replica cache or
unconfirmed checkpoint. Unknown outcome is `outcome_unknown`: retain all
evidence, fence this stream and reconcile its exact transaction before new
writes/latest success. A lost reply may have committed; only exact retry or
fresh verified head/proof can resolve it, not a new record or compensating erase.

### 4.2 Latest head and bounded continuity

Reads and appends share one linearizable order. A latest operation samples the
actual durable head, including an unresolved intent, and cross-checks §8's
independent checkpoint. It signs the complete head record, required receipt
fields, exact challenge and complete proof manifest in §5. Its linearization
point lies within that request. No cached signed reply, historic lookup, stale
replica or old resolved head behind an intent may answer it. A concurrent append
may linearize after the read; this is no lease through a consumer's later effect.

The consumer independently verifies signature/domain/service/stream/profile,
challenge once, post-restore entropy, writer history, complete chain from its
trusted anchor and exact local-state reconciliation. A lower sequence, different
hash at equal sequence or disconnected ancestry fences. A restored local floor
is not an independent checkpoint. Include the intent immediately preceding a
committed head even if the chain anchor is already that committed record; that
extra evidence must hash-match its referenced intent. Empty/missing evidence
never establishes first use. The read appends no consumer record.

Each proof page contains at most two exact records and original receipts, in
sequence order. Complete history is retained from **any trusted checkpoint**;
online reconciliation may nevertheless exceed §9's finite caps/deadline. Then
return `proof_limit` and fence consumer readiness; never label a truncated prefix
complete. Larger gaps require separately authorized bounded offline continuity
verification, preserving the old anchor and history; no new genesis or automatic
checkpoint jump. Proof pages and reconnects share the original attempt budget.
A verified intermediate checkpoint may be retained as evidence, but not used to
claim reconciliation before a fresh complete-to-head check succeeds.

## 5. Signed receipts, heads and proof pages

Signature envelopes are exactly `{body,signature}`. The signature preimage is
ASCII(domain) + one NUL + CCJ-1(body), without LF. Signature/body bytes are
retained exactly; receipt hash is `sha256:` plus lowercase SHA-256 of its exact
canonical envelope, without LF. Authentication and these signatures have
separate roles. Select the expected domain from the **protected stream type**,
never from received body claims:

| Type | Append acknowledgement | Latest head |
| --- | --- | --- |
| Keymaker | `keymaker-witness-ack/1` | `keymaker-witness-head/1` |
| Registrar / checkpoint inclusion | `state-witness-ack/1` | `state-witness-head/1` |

The Keymaker append body is exactly
`{v,consumer,stream,station,seq,state_epoch,kind,base_state_digest,state_digest,
record_hash,key_epoch,key_id,witness,control_hash}`. All pre-existing consumer
§3.3 fields are present, taken from the exact admitted line. Added `witness` is
exactly `{service,key_epoch,key_id}` for the witness signer; control_hash is the
64-hex hash of the applicable administrative control head. No digest identifies
a different record, and the writer fields are not replaced by witness fields.

The consumer-neutral append body is exactly
`{v,consumer,stream,seq,record_hash,writer,projection,witness,control_hash}`.
Here v=1, writer is exactly `{epoch,id}` from the protected admitting principal;
projection is `{kind,revision,digest}` for the registrar or the exact checkpoint
projection in §6. These are copies of commitments, not validation of underlying
state. Epoch/id identify the original writer, including on an exact retry.

A latest-head body contains exactly its append-body fields plus
`record`, `receipt`, `challenge`, `proof`. receipt is base64url of the exact
original append receipt, including when the anchor already equals the head.
record is base64url of the complete head line
including LF. challenge is the exact canonical client challenge. The witness
key/control_hash identify the key/policy used for **this fresh reply**; other
fields still describe the admitted head, not a newly appended record. Verify
both the original head receipt and this fresh reply under their authorized
historical/current keys; do not overwrite a historical receipt on rotation.

`proof` is exactly `{records,controls,intent}`. records and controls are each
a manifest exactly `{anchor_seq,anchor_hash,head_seq,head_hash,count,pages}`.
count is the number of chain entries; pages is an ordered array of exact
`{index,first_seq,last_seq,page_hash}` descriptors, contiguous from index0.
Entries cover exactly anchor_seq+1 through head_seq, never an omitted suffix.
A zero-length chain has count0 and pages[] only when anchor equals head.

For any committed consumer head, including the registry resolution, intent is exactly
`{seq,record_hash,page_hash}` for its immediate preceding intent, even when
that position is at/before the chain anchor. Its separate one-entry page uses
chain `intent`, index0, and the committed head as its anchor and target context.
The consumer verifies its record hash against the committed record's prev_hash
and intent_hash, plus all pairing fields. This is referenced-record evidence,
not an alternative chain anchor. Other heads use intent:null. It counts against
the same page/entry caps and is covered by the fresh head signature.

A page is CCJ-1 of exactly `{v,consumer,stream,chain,anchor_seq,anchor_hash,
head_seq,head_hash,index,entries}` without LF. chain is `records`, `controls` or the one-entry `intent` evidence;
entries is an ordered array of exact `{record,receipt}` objects, both canonical
base64url encodings of original bytes. For controls these are the signed admin
line and original control receipt. page_hash is `sha256:` plus lowercase
SHA-256 of these complete page bytes. A head's signed manifest binds every
page hash, count and target head. Pages need no independent signing domain;
cached immutable pages are permitted only against that freshly signed manifest.
Missing/reordered/duplicate pages, wrong chain labels, boundary or hash mismatch
refuse. No opaque continuation token can change the signed target mid-proof.

Writer-key history is authenticated by the controls manifest and independently
pinned administrative authority. Verify it before accepting affected signatures.
Witness key rotation cannot make an untrusted key self-authorizing. Lost keys,
missing transition history or more history than the proof cap fence, not TOFU.

## 6. Owner-registry checkpoint confirmation and equivocation

Recommend **inclusion in a dedicated typed witness stream**, not a standalone
countersignature. A countersignature alone binds bytes but supplies neither
stream ordering nor a fresh latest head. Inclusion reuses CAS, retained receipts,
LF-inclusive record hashing, continuity and challenged reads. It does not
modify or re-sign the registry's underlying attestations, grants or enrollment.

The public owner-registry **design draft** cited above proposes journal fields
`type,registry,owner,seq,prev,at,op,record_type,record` and signed checkpoint
fields `type,registry,owner,seq,head,at,snapshot`. Journal entries themselves are
unsigned; the original registry-root checkpoint authenticates their head.
These draft shapes are not registered by S0. This service assigns no content
tag, signature preimage or replacement checkpoint format. A reviewed registry
adapter and accepted signed checkpoint/hash-linked journal profile remain
prerequisites. Until available, admission refuses `profile_unavailable`; no
mock verifier or supplied valid flag may replace them.

Recommend one checkpoint per accepted registry journal entry, including each
snapshot reissue as a new entry, following draft §6/Q9. Registry journal sequence
and witness sequence are distinct: one registry transition consumes an intent
and a committed witness position. No v0 owner-root-change operation is introduced.
The registry writer never receives a witness credential, even for this stream.

The separate witness-side bridge verifies the exact prepared checkpoint under
the pinned registry root/owner, full journal ancestry and complete candidate
transaction before submitting intent. That candidate includes exact records,
journal/checkpoint bytes, publication dependencies, retained request/id outcomes
and watermark, not merely the content head. Its digest commits an independently
validated recoverable inventory; a writer-supplied digest is insufficient. The
inventory encoding, access/exclusion protocol and independent validation are
consumer-owned qualification gates, not an assertion that this witness can
reconstruct state. No caller-selected network fetch is allowed. Journal proof
intake obeys §9; a gap beyond its bound fences.

The witness-side wrapper is exactly `{v,stream,seq,prev_hash,writer_epoch,kind,
intent_hash,checkpoint,registry_proof,projection}` plus LF. v=1;
writer_epoch equals the current protected bridge policy epoch.
kind is `intent` or `committed`; intent_hash is null for intent or the exact
LF-inclusive intent hash for committed. checkpoint and registry_proof are
base64url original bytes. projection is exactly `{registry_id,owner,registry_seq,
registry_head,checkpoint_id,checkpoint_time,candidate_digest,previous_checkpoint_id}`.
registry_seq is positive safe integer; content IDs and candidate_digest are
canonical sha256 IDs; registry_id/owner match protected pins. checkpoint_time
copies the verified checkpoint's `at` exactly. The accepted adapter must fix
its single canonical UTC representation before activation; this proposal does
not guess a type/coercion for an unpublished format. previous_checkpoint_id is
null only for explicitly authorized registry genesis, otherwise the last resolved
checkpoint ID. The adapter derives source fields from verified originals, not
agreement with submitted values. This wrapper is a service proposal, not the
registry's signed body schema. Neither wrapper needs a new content signature;
its separate bridge is authenticated by transport and witness receipts bind it.

Required ordering matches registry draft §6: quiesce publication and exclude
old instances; validate the candidate; obtain acknowledged external intent;
durably commit that exact local candidate; obtain acknowledged matching committed
resolution; revalidate bytes/time/authority; then publish and acknowledge. The
bridge independently validates local commit evidence before resolution. A digest
alone is not such evidence. Failure or uncertainty at intent fences old authority;
there is no auto-cancel. The witness checks wrapper/chain/projection equality
and the adapter's signature/header/ancestry facts; it cannot prove that local
commit, semantic completeness or exclusion actually occurred. Consumers must
not treat a signed intent as confirmation of publication.

The first checkpoint requires explicit scope/bootstrap authorization. A new
intent must extend the last resolved registry journal head with verified ancestry.
The committed record immediately follows its exact intent: same checkpoint,
proof, projection and writer epoch; prev_hash and intent_hash identify that
intent. The bridge cannot start another transition while one is unresolved.
Retain an index of each registry position's exact checkpoint and candidate,
intent position and resolution position. Only that matching resolution may
repeat the checkpoint at a new witness position. An exact original wrapper and
predecessor retry returns its original receipt; a second intent/repackaging of
an already reserved or resolved checkpoint refuses `position_conflict`.

Decreasing registry sequence refuses. Two independently valid checkpoints with
the same registry sequence but different heads are `checkpoint_fork`, even if
generic witness CAS would also conflict. Different checkpoint bytes at equal
registry sequence also refuse/fence; retain both signed originals and alarm.
Changing the reserved candidate digest or resolution pairing refuses
`evidence_invalid`, preserving the intent and old evidence. Fork detection uses
verified original signatures/scope, never untrusted claimed projections.

Neutral receipts bind stream, checkpoint head/sequence/time, complete candidate
digest and exact wrapper hash. Confirmation evidence consists of original
checkpoint, exact intent and resolution lines, both original receipts, and fresh
head/continuity including any later unresolved intent. An intent receipt alone
is not a committed checkpoint. The two-position inclusion proves recorded claims
and order, not honest publication of every event or correct revocation semantics.
A malicious issuer can withhold a first publication.

Consumers durably retain the last accepted registry head/checkpoint and witness
head/control anchor. Never regress or accept a different head at equal sequence;
require verified ancestry on advance. Compare against the independently retained
off-node checkpoint after restore; a rolled-back local last-seen file is no
freshness proof. Optional exchange of signed heads/checkpoints between authorized
consumers can expose inconsistent views: verify evidence, fence and alarm, but
never vote, overwrite a local anchor or pick the larger counter without ancestry.
No exchange is permission to disclose private records. This is consumer head
comparison, not the paused registry-to-registry exchange or a new distribution API.

The max(S+A,from) revocation-distribution claim is conditional on a qualified
publication history that is complete and presents no split views. A new signature
and timestamp cannot show that the publisher withheld no event or constrain a
dishonest issuer. The bound starts with issuance of the first containing snapshot;
there is no deadline on withdrawal before that publication. Co-host compromise can still
split views or omit records unless independent evidence/exchange exposes it;
this witness is not a claim of Byzantine consensus.

## 7. Administrative operations and key rotation

Administration uses an independently pinned off-node authorization key and a
separate transport principal. It is unavailable to consumer/registry accounts.
The signed admin envelope `{body,signature}` uses domain
`state-witness-admin/1` + NUL + CCJ-1(body), then LF for storage/hash chaining.
The closed body is `{v,service,seq,prev_hash,action_id,operation,stream,
expected_binding_hash,new_binding,expected_head,bootstrap_hash,key_epoch,key_id}`.
seq is the positive administrative safe-integer sequence, separate from consumer
streams; prev_hash is the LF-inclusive prior control hash, 64 zeroes only for
the explicitly authorized first action. action_id is a one-use 32-lowercase-hex identifier. expected_head is
exactly `{seq,hash}`; for a service-wide key change it is null and the barrier
covers all provisioned streams. Hashes cover complete original bytes; null is
allowed only where explicitly defined below.

| operation | Preconditions and exact effect |
| --- | --- |
| `provision` | stream unused; expected_binding_hash null, expected_head {0,zero-hash}; new_binding is the complete §2 binding; bootstrap_hash is the exact authorized first line's hash. Preserve independently evidenced consumer consent. |
| `rotate_writer` | Exact old binding hash/head, authorized old/new principal/key evidence and bounded complete new binding; same stream/identity/lineage/profile, writer_epoch exactly+1. bootstrap_hash null. Disable old append credential at the barrier; never alter old records/receipts. |
| `rotate_witness` | stream null; new_binding is exactly {service,key_epoch,key_id,public_key,proof}; epoch exactly+1, distinct key and proof of possession under `state-witness-key-transition/1` + NUL + CCJ-1 of that object without proof. expected_binding_hash is old service-key-policy hash; expected_head/bootstrap_hash null. Quiesce service-wide appends/reads and preserve every stream/control head. |

These are the only admin operations in v1. Reader/transport ACL replacement
uses rotate_writer with complete reauthorization and increasing policy epoch;
no hidden mutable ACL file may bypass control history. Deletion, stream rename,
lineage changes, root recovery or retention truncation are not accepted actions.
Loss of an old key or migration outside these preconditions requires a separately
reviewed recovery decision, not an empty-stream reset.

Serialize admin operations against affected append/read admission. Check the
current control predecessor and exact expected policy/head; retain signed action,
one-use ID, old/new pins, original control receipt and audit; apply §8's independent
checkpoint barrier before activation/ack. A repeated exact action returns its
original receipt; another action reusing its ID refuses `position_conflict`. Old public epochs remain
available for all historical verification. Unknown outcome fences affected streams.

Control receipts use `state-witness-control-ack/1` + NUL + CCJ-1(body), with
body exactly `{v,service,seq,control_hash,action_id,operation,stream,witness}`.
A witness-key transition's receipt is prepared under the old witness key; only
subsequent fresh replies/new receipts use the new key. The admin signature and
new-key proof authorize that transition; an old receipt alone is not a root pin.
Administrative sequence/key-epoch exhaustion fences; no wrap/reuse.
A binding/policy hash is `sha256:` plus lowercase SHA-256 of its complete CCJ-1
object without LF; a control_hash instead is lowercase64-hex SHA-256 of its
complete signed administrative line including LF. Changing only reader/transport
ACLs advances writer policy epoch without changing the record-signing key epoch.
An actual record-key rotation additionally advances that key's epoch by one and
requires a distinct new key. Neither action re-derives historical signatures.

## 8. Durability, independent checkpoints and restore

Record/receipt/control/audit bytes MUST survive power loss before acknowledgement.
Persist full writes, file synchronization, checked closes, atomic publication
and directory synchronization as one recoverable transaction; no success depends
on volatile cache. Retain acknowledged records, exact receipts, key/control history
and cumulative fork evidence indefinitely or in a verified immutable archive.
Archive retrieval remains part of proof availability. Capacity exhaustion is
backpressure, not permission to discard old positions or tombstones.

**Strict restore profile:** before each append/control acknowledgement, a
separately administered off-node checkpoint custodian MUST durably confirm the
exact monotonic tuple `{service,chain,stream,seq,record_hash,receipt_hash,control_hash}`.
chain is `records` with the exact consumer stream, or `controls` with stream:null
and administrative seq/record_hash (the signed control-line hash). receipt_hash
binds the corresponding original receipt; control_hash binds applicable policy. It must compare the previous tuple,
reject same-position differences and supply fresh challenge-bound authoritative
reads. This custodian is outside the shared registry/witness host's restore and
administrative failure domain. Its nonrollback retention/latestness is an
explicit trusted dependency requiring independent qualification, not a property
proved recursively by witness signatures. No such provider is claimed to exist.

The local exact record/receipt transaction is durable before custodian confirmation;
publication/ack follows that confirmation and local head sync. A custodian that
is ahead of published local state means a pending or lost transaction, never
permission to return an older head. A fresh latest read must compare to that
custodian under the stream's serialization; uncertainty fences. A custodian
behind an acknowledged local head, missing evidence or an equal-sequence hash
conflict also fences. Compare record tuples to their original receipt/policy
values, and check the current administrative head separately; a fresh reply's
new control_hash must not be mistaken for a rewrite of an old record tuple. Store its receipts and keep the trusted checkpoint off
this host; an on-host copy is only a cache. All added round trips count in §9.

On every witness restart/restore, quiesce serving, exclude older instances,
validate archives/local chains/control pins, obtain fresh custodian evidence
with qualified post-restore entropy and reconcile every possibly pending
transaction before reads or appends. Only the exact previously durable candidate
may complete an interrupted publication; no regenerated receipt or new record.
If needed bytes are missing, independently restore those exact bytes or remain
fenced. Restoring backups never lowers the custodian anchor, resets a stream or
authorizes a new witness key. This server recovery proves storage state only;
consumer startup still follows its own intent/committed reconciliation rules.

A periodic/offline checkpoint alone leaves an unanchored acknowledgement window
and does **not** satisfy this strict profile. It is an alternative with weaker
bounds requiring separate acceptance, not an implementation shortcut. Consumer
last-seen anchors and signed-head exchange detect regressions only where newer
evidence survives. Losing the host loses both co-located services; consumers
fail closed and any option A recovery must preserve/resolve outstanding evidence.
Loss/rollback/compromise of the custodian together with all other evidence is
outside the guarantee. A compromised signer need not obey this protocol.

## 9. Limits, deadlines and storage growth

These are proposed admission bounds, **not measured capacity or availability**.
Charge before allocation/irreversible work. Per-operation default is **5000 ms**,
never greater than the caller's remaining budget; all retries, proof pages,
checkpoint confirmation, handshakes and reconnects in one reconciliation attempt
share that bound. Keymaker's existing two-second native budget is unchanged.
No asynchronous continuation permits an already timed-out authority release.

| Resource | Proposed limit / behavior |
| --- | --- |
| HTTP body / decoded frame | 65536 bytes; oversized Content-Length refuses before body allocation; streaming body stops at cap+1; no compression |
| Exact consumer/admin line | 8192 bytes including LF; signature envelope receipt <=4096 bytes; include the entire record, never a prefix |
| JSON | Depth16 root=1; arrays64 entries; ordinary strings <=8192 decoded UTF-8 bytes. Explicit binary-carrier fields record/receipt/checkpoint/registry_proof/action may be <=16384 ASCII bytes; outer result may carry <=60075 ASCII bytes. All remain frame-bounded; no general string exception. |
| Proof page | <=2 entries and <=45056 canonical bytes; each raw line <=8192 and receipt <=4096, or reject. Two base64 carriers total <=32770 bytes plus bounded syntax/header; do not rely solely on entry count. |
| Proof attempt | <=64 pages and <=128 entries across record/control chains and required intent evidence; manifest<=16384 bytes; signed head envelope<=32768 raw bytes. Over-cap is proof_limit, not partial reconciliation. |
| Streams / ACLs | 1024 provisioned streams; <=8 writer transport pins and <=32 reader principals per stream; no dynamic caller-named allocation |
| Concurrency | 128 connections, 16 active operations global, 1 active request/connection, 1 stream serialization slot; no unbounded queue |
| Rate | Per principal 20/s burst40; append/admin 2/s burst4; global200/s burst256; charge malformed/refused/retry traffic, independent bounded pre-auth bucket |
| Memory / records | 256 MiB working-memory target, streaming bounded archive reads; 100 GiB retained-history budget and 1 GiB audit budget, no automatic deletion; reserve16 MiB health/control evidence |

A checkpoint plus required registry proof must fit its record/frame/page limits;
otherwise profile intake fails closed until separately reviewed bounded adapter
pagination is specified. Do not omit ancestry, truncate a snapshot, weaken
completeness or split one checkpoint into unrelated success claims to fit.
The outer JSON metadata budget, excluding a single binary result carrier, is
4096 bytes. A maximum 45056-byte proof page encodes to 60075 base64url bytes;
with that metadata the response is at most 64171 bytes, below 65536. Enforce
both raw and encoded bounds; a 49152-byte raw page would already encode to
65536 before its wrapper and is forbidden. Head/receipt carriers are smaller.

Long-lived consumer traffic, audit-per-operation costs, offline proof retrieval,
archive growth and independent-checkpoint round trips require capacity planning.
At most these bounds may be narrowed by protected policy without review; raising
them changes the protocol qualification identity. No throughput SLA is claimed.

## 10. Closed errors and witness audit

Only the following application error codes are admitted. retryable describes
bounded transport retry potential, **not permission to clear a consumer fence**.
Every witness failure/timeout prevents consumer authority use: Keymaker maps
witness failures to its state_witness_unavailable fence (existing precise local
entropy/deadline codes remain); the registrar uses registry_unavailable. Existing
client errors and consumer audit semantics are not replaced by witness codes.

| Code | retryable | Meaning / side effects |
| --- | --- | --- |
| `request_malformed` | false | Closed schema/CCJ/base64/type failure; no record append |
| `limit_exceeded` | false | Frame/record/field cap; no partial append |
| `not_authorized` | false | Wrong peer/role/stream; disclose no foreign head |
| `stream_unavailable` | false | Missing binding/history or protected-policy failure |
| `bootstrap_required` | false | No exact first-line authorization; no allocation |
| `stream_empty` | false | Provisioned but no admitted record; no startup success |
| `head_conflict` | false | Expected sequence/predecessor mismatch; no losing append |
| `position_conflict` | false | Occupied position with different bytes; retain original |
| `checkpoint_fork` | false | Conflicting registry checkpoint; retain fork evidence/alarm |
| `sequence_exhausted` | false | No room for next record/pair/control epoch; no wrap |
| `profile_unavailable` | false | Accepted verifier/profile/rotation evidence missing |
| `proof_limit` | false | Complete proof exceeds attempt bounds; never partial success |
| `evidence_invalid` | false | Signature/domain/hash/chain/pin/continuity failure; fence affected scope |
| `storage_unavailable` | false | Local/custodian/audit durability or integrity unavailable; preserve evidence/fence |
| `outcome_unknown` | false | Append/control may be durable; reconcile exact pending transaction |
| `deadline_exceeded` | false | No late success; unknown work also leaves scope fenced |
| `rate_limited` | true | Precharged bound, no append; retry shares original budget |
| `busy` | true | Bounded admission unavailable, no append; no queued authority |

If failure occurs after irreversible work with unknown outcome, outcome_unknown
wins over a pre-work storage/rate code; on an already-expired transport close
without success and retain the unknown fence. Invalid replies, challenge mismatch
and wrong domains are consumer evidence_invalid diagnostics, never success even
if the server sent no application error. Do not echo records, digests, keys or
foreign-policy detail in errors. Restricted audit carries the typed cause.

Witness audit is a separate append-only typed channel, not a consumer record
or registrar issued/refused event. Closed entries contain
`{v,seq,at,instance,principal,stream,operation,request_id,record_hash,control_hash,
result,code,prev_hash}` plus LF. Unknown/unverified fields are null; no arbitrary
text. seq is a positive safe integer; at is qualified UTC or null with result
unknown; instance is a fresh16-byte base64url server identifier. result is
success/refused/unknown; code is null on success or from the closed table.
Hashes commit exact bytes; prev_hash is the LF-inclusive previous audit-line
hash. No secrets, signatures, raw records, certificates, tokens, raw challenges,
URLs or local paths enter this channel. Store exact proof evidence separately
with restricted access, referenced by hash.

Append/control success requires audit durability in the same retained transaction.
Fresh latest/proof replies require durable audit before release but do not append
consumer records. Exact append repeats still audit the lookup without generating
a new receipt. Replicate/archive audit independently; audit/control reserve loss
closes service admission. Logging must not recursively call witness append or
create an unwitnessed normal success; failed failure-audit uses bounded separate
health telemetry and readiness failure only. Fork alarms never erase either view.

## 11. Negative text vectors and positive controls

These are requirements for future implementation tests, **not executable server
or lifecycle evidence**. Fixture W is a provisioned healthy stream with sole
writer, valid independent checkpoint and complete original history/receipts.
All refusals release no new success and preserve acknowledged evidence. Where
an append may have committed, retain its exact transaction and fence rather
than assert no-write. Each row includes its nearby valid control.

| ID | Negative and required outcome | Positive control |
| --- | --- | --- |
| WS01 | Append gap/wrong expected head/prev_hash: head_conflict; no losing record | W appends next exact seq/hash once |
| WS02 | Different bytes at occupied position, even with a valid signature: position_conflict; original unchanged | Exact complete repeat/predecessor returns original byte-identical receipt, no second append |
| WS03 | Cached signed receipt/old resolved head used as latest while an intent/newer head exists: consumer rejects/fences | Fresh serialized reply includes actual latest, including intent |
| WS04 | Correctly signed head with another challenge or replay of consumed challenge: consumer rejects; no reconciliation | Fresh qualified32-byte challenge matches once within total budget |
| WS05 | Ack/head/record cross-domain or neutral reply substituted for Keymaker: reject | Correct independently pinned key and protected-type domain verify |
| WS06 | Writer/reader of one stream requests another stream: not_authorized; no ungranted record/head disclosure (authorized service-wide control metadata is explicit in §2) | Same credential acts only within its bound stream/ACL |
| WS07 | Registry publishing principal attempts any witness append/admin, including checkpoint stream: not_authorized | Independent observer admits a valid original checkpoint only to its own stream |
| WS08 | Missing/empty stream interpreted as first use: stream_unavailable/bootstrap_required/stream_empty as applicable; no reconciliation | Exact independently authorized provision+first-line grant permits one bootstrap append, not startup-only creation |
| WS09 | Exhaust seq, writer/control epoch, or leave only one slot before intent: sequence_exhausted; no wrap/new stream | Next complete pair within safe-integer range succeeds |
| WS10 | Restore witness below off-node checkpoint, including same-host registry restore: storage_unavailable; no old-head serving | Recover exact independently confirmed bytes/control history before readiness |
| WS11 | Two valid registry checkpoints at same registry_seq with different registry_head: checkpoint_fork; retain both/alarm | Exact intent/resolution retries return original receipts; matching resolution and verified descendant advance |
| WS12 | Missing/reordered/wrong-hash proof page, omitted committed-head intent or truncated proof presented complete: reject; proof_limit on over-cap | Complete bounded record/control proof and exact referenced intent verify from protected anchor |
| WS13 | Ack before local sync/custodian confirmation, or lose reply after durable commit: no early success; unknown outcome fences | Exact stored transaction/receipt survives and exact retry or fresh proof resolves without duplicate append |
| WS14 | Unauthenticated key rotation, lost history, old writer new append or purpose3 used for TLS: reject, no new authority | Authorized same-stream epoch+1 barrier preserves history; new writer may retrieve exact old receipt, not alter it |
| WS15 | Reset deadline on reconnect/page, release after timeout, or exceed record/frame/rate/storage cap: refuse/fence as applicable | Whole attempt within remaining consumer budget, properly charged bounded valid record/proof succeeds |
| WS16 | Checkpoint adapter unavailable, claimed valid flag, foreign scope or disconnected journal head: profile_unavailable/evidence_invalid; no inclusion | Qualified verifier derives projection from exact original bytes and complete ancestry |
| WS17 | Audit failure triggers recursive witnessed logging or ordinary unaudited reply: storage_unavailable, admission closed | Independent bounded audit transaction durable before reply; nonrecursive health path grants no authority |
| WS18 | Replace signatures with freshness/completeness assertion or use equal counters without ancestry: reject/fence | Valid chain, fresh head, protected last-seen/off-node anchors checked; optional signed-head exchange exposes a real conflict |

| WS19 | Registry publishes after intent alone, resolves a different candidate, or treats a writer digest as commit evidence: consumer/bridge refuses and fences; server rejects mismatched pairing; retain intent | Independently validated exact candidate follows intent→local durable commit→matching resolution→revalidation→publication |

Future qualification must exercise power loss, same-boot restore, archive loss,
checkpoint lag/ahead/conflict, concurrent append/latest/admin barriers, cross-role
credentials, source-compatible consumer codecs and bounded load. Narrowing plants
must remove the exact required fence/comparison and fail a named test while the
paired valid control succeeds. Text controls here do not qualify durable storage,
TLS, independent retention, consumer integration or instance exclusion.

## 12. Consumer deltas and activation decisions

Keymaker's existing §3 record bytes, purpose3, ack/head domains, separate station
stream, intent→local commit→resolution ordering and actual-release fences remain
unchanged. The only edit to that supplement is a link to this candidate. The
following **proposed wire refinements require explicit consumer acceptance**:
closed receipt/head bodies with witness-key/control metadata; binary transport
carrier; signed manifests/pages and referenced-intent inclusion; service-wide
control-metadata read scope and disclosure consent; TLS pin policy;
server caps and independent-checkpoint barrier/cost. This document must not be
used to claim §3.3 already implemented those encodings or accepted new egress.

For the registrar, recommend replacing the strict transport reuse rule in
§4.5.3 and the corresponding C.3/WC2 rows with: a separately typed witness RPC
using the same authenticated off-host durability trust boundary, over the
qualified TLS1.3 endpoint above; it need not be the existing §9 audit-delivery
wire endpoint. Preserve §9's closed event schema, sequence, exact-byte durable
ack, issuance-before-release and refusal-spool rules. Preserve all §4.5 consumer
record/digest, fresh-head, failure and operator-recovery requirements. The
registrar must explicitly accept the neutral signed receipt/head/proof mapping,
transport pin/admin/provisioning profile and limits. **No registrar repository
edit or acceptance is claimed.** Alternative: extend its audit-channel sink
with these exact typed operations and equivalent isolation/limits, then review
that adapter; ordinary audit shipping is insufficient.

Recommend typed registry intent/resolution inclusion over bare countersignature, dedicated mTLS
RPC over implicit audit reuse, and synchronous off-node checkpoint confirmation
over periodic checkpoints. Each alternative's lost property is stated above;
none is a deployed decision merely because recommended here.

The public registry draft and this proposal still need joint acceptance of the
wrapper/receipt/time types, candidate-inventory/commit-validation and exclusion
protocol, per-entry checkpoint load, and limits. Its Q10 names bridge versus
witness-owned coordination without an implemented API; no observation proxy is
claimed here. Its off-node checkpoint discussion does not mandate this document's
stronger synchronous per-ack custodian barrier: cost/provider acceptance remains
open. Its Q2 records a purpose-5 domain mismatch in its older Keymaker pin; this
service grants no new purpose or alias and leaves alignment to those owners.

Open gates remain: service implementation owner; registry adapter/profile and
checkpoint observer ownership; registrar transport/consumer-wire acceptance;
Keymaker wire/egress/purpose3 integration acceptance; host/key/clock/entropy and
exclusive-instance qualification; off-node checkpoint provider and joint-loss
runbook; archive/online-proof recovery; measured storage/rate/deadline capacity.
Implementation, deployment and qualification must close these before C activation.
