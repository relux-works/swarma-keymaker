# Option C: external state witness

Status: normative proposal for content review, **not implemented or activated**.
This supplement proposes the changes listed in
[section 9](#9-normative-changes-to-existing-sections). The existing specification
and option A remain the shipped contract until separately reviewed implementation
and qualification land. No new command, network permission or key purpose is
enabled by publishing this document.

The required guarantee follows the public
[registrar specification, section 4.5](https://github.com/relux-works/swarma-registrar/blob/5f44ebf3f78829144aa7864ca2e4ad62bea43eb5/spec/registrar.md#45-external-high-water-witness-option-c-normative-draft):
acknowledged external intent, durable local commit, acknowledged external
resolution, then authority use; fresh challenge-bound latest-head verification
at startup. Keymaker has its own mechanism and **separate consumer stream**
(WC3). Registrar receipts cannot reconcile Keymaker state. The placement
direction is decided (WC1); deployment/qualification remain open, and the
existing honest mode A holds until those gates close.

## 1. Guarantee and trust boundary

An honest, independently retained witness MUST preserve every acknowledged
record outside Keymaker's restore/failure domain. A local snapshot restore
MUST NOT restore the witness, its trusted key binding or its independent
continuity evidence. The witness stores commitments, not enrollment authority,
private keys, proofs or a backup from which local state can be reconstructed.

Option C MUST fence **both surfaces** until startup reconciliation succeeds.
During a state transition it MUST prevent dependent releases, including from
old cached authority. Exactly one writer/serving instance may use a consumer
stream. Deployment MUST exclude older instances before replacement and for
the entire serving lifetime. A local lock alone cannot exclude a restored
clone on another machine; compare-head append is not a distributed signing
lock. Uncertain exclusion fences the replacement. Its mechanism is an
activation gate, not an assumed witness feature.

The claim covers rollback of Keymaker-owned state and accepted external
authority anchors. It does not make a compromised signer obey checks, detect
an unobserved upstream generation-journal rollback, revoke already released
signatures, prove operator intent, or detect a jointly rolled-back or malicious
witness when no independent newer evidence survives. Existing generation,
enrollment, custody, operator and actual-write checks remain mandatory.

## 2. Protected state and state epoch

### 2.1 Complete state inventory

Every resolved state MUST commit to all the following components. Empty and
absent are distinct; omission is invalid. An implementation MUST publish the
closed artifact inventory for each component before activation, including
temporary files whose presence currently fences startup. Unknown artifacts,
partial writes and missing required artifacts MUST fence rather than be
silently excluded from hashing.

| Component | Required protected contents |
| --- | --- |
| `bindings` | Complete bindings snapshot: all active/predecessor/revoked/unbound records, master epochs, registration-number allocator, Store version and audit linkage; complete retained native request IDs, canonical arguments, status and results, including retained registration envelopes. Hash results locally; never send them to the witness. Pending binding snapshots are attempt evidence, not an older-state fallback. |
| `audit` | Exact journal bytes, latest sequence/digest, active and sealed segment linkage, seal bounds and archive/retention acknowledgements. Archived segments remain committed through a verified archive index and hash chain. Removing a segment requires the existing verified durable archive acknowledgement and a witnessed retention transition; it never resets the head. |
| `enrollment` | Full high-water revision, host sequence/ID/history/tombstones and permanent key/name ownership; acceptance/bootstrap marker and attempt evidence; complete consumed-approval ledger, including its random ledger identity and all consumed IDs. Ledger truncation, replacement or pruning is not recovery. |
| `reconciliation` | Exact approval receipt or its explicit absence, approval and ledger identities, consuming evidence, pending/orphan publication evidence and the protected publication fence. Receipt digests bind the full pin and protected configuration-path identity. Receipt publication, invalidation, consumption and cleanup are state changes. |
| `authority` | PC2 authoritative root/revisions/digests, global withdrawal counter, durable incarnation and published boot/process instance; exact local intents and retained cross-owner activation attempts, holds and recovery open/resolution/release-prepared/released history. Complete schema-2 message artifacts/phase fences, migration decisions/floors and original results are included, with an explicitly reviewed combined inventory. Protected policy and pin digests, complete append-only name/index registry and tombstones, station/consumer/registry-lineage bindings, admitted UID generations and accepted generation-source head/continuity anchor. An independently advanced source must still be checked at release; recording an anchor does not replace the source's freshness contract. |
| `custody` | Master public epoch/identity and verification anchors; witness signer public key, derivation tuple, key epoch and authorized rotation history. Secret seed/key bytes and chain codes are excluded. Custody protections and correct public derivation are independently checked, so a different restored seed cannot be authorized by excluding its bytes. |

The daemon, stopped-service operator tools and recovery tools MUST share this
inventory and serialize transitions over it, preserving existing privilege
boundaries. No direct file edit or old operator binary may bypass witnessing
while C is selected. Root-owned fences remain root-owned; this proposal does
not grant the daemon permission to remove them. Cross-privilege transaction
coordination is an implementation activation gate.

### 2.2 Canonical commitment

The local state header MUST contain version 1, the last committed `state_epoch`
and a manifest. The digest preimage is CCJ-1 of exactly:

```text
{v:1, consumer:"keymaker", stream, station, state_epoch,
 manifest:{bindings, audit, enrollment, reconciliation, authority, custody}}
```

These are member names, not literal non-JSON wire bytes. Each manifest value
is `sha256:` plus lowercase SHA-256 hex of its canonical artifact inventory.
Each inventory is an array of exact `{id,present,size,sha256}` objects, ordered
by ASCII logical artifact ID. IDs are unique, version-defined and independent
of directory enumeration order. Present entries hash **all exact file bytes**
and carry their nonnegative byte size; absent entries have `present:false`,
`size:0`, `sha256:null`. Empty files have a real empty-byte hash. Required
semantic anchors without a file use a version-defined CCJ-1 artifact whose
exact members are part of that closed inventory. Alias IDs, omitted entries,
duplicates and unknown fields are invalid. Size/counter integers obey CCJ-1's
safe-integer bound; oversized state fences, never hashes a truncated prefix.

The complete state digest is `sha256:` plus lowercase SHA-256 of those
canonical preimage bytes, **without LF**. Permissions, inode numbers and lock
ownership do not enter the preimage; their protection checks remain required.
Caches and process-local challenges are excluded. The header itself, witness
receipts and witness protocol diagnostics are excluded to avoid self-reference.
An altered header still fails the recomputed digest/epoch comparison. Witness
records carry only the complete digest, not the inventory or its contents.

`state_epoch` is a positive monotonic safe integer, independent of master
epoch, enrollment sequence, audit sequence and witness record sequence. Each
logical durable transaction advances from n to n+1 **even when application
bytes would otherwise be unchanged**. Epoch 1 requires explicit independently
authorized stream enrollment/bootstrap. A restart, repair, restore or migration
MUST NOT reset it or select a fresh stream. Exhaustion fences before writing
an intent; it never wraps. The local epoch and complete candidate inventory
are part of the intended durable commit. Partial multi-file persistence is
not claimed to be atomic and remains fenced under section 4.

## 3. Consumer stream, keys and witness interface

### 3.1 Protected identity and purpose separation

Protected provisioning MUST bind a stable ASCII stream ID matching
`[a-z0-9][a-z0-9._-]{0,127}`, consumer `keymaker`, the station's immutable
registered identity tuple and registry lineage to the authorized writer public
key and witness verifier key. `station` is the canonical object
`{product,project,agent}` with the exact registered names from section 4.2 of
the base specification. Neither a caller UID nor a hostname chooses a stream.
There is one Keymaker stream per protected station consumer, distinct from
the registrar and every other station. Station renaming/migration and master
rotation require explicit continuity-preserving authorization; they cannot
create empty-stream first use.

This proposal reserves SLIP-0010 purpose **`state-witness = 3`**, with the
four-component path `m/3'/product'/project'/agent'` resolved through the existing
explicit registry. This is a curator-reviewed extension to the two-purpose
rule, not current derivation support. The key MUST be Ed25519, available only
to the internal witness writer, and MUST NOT be registered as a binding,
selected by a caller, exposed through surface A or used for `registration/1`.
Purpose-1 and purpose-2 keys MUST NOT authenticate witness records. A shared
master does not make those purposes interchangeable. The witness MUST pin the
authorized purpose-3 public key and authenticated provisioning of its tuple;
a claimed purpose field alone cannot prove how an arbitrary key was derived.

Witness receipt/head signatures use the witness's **separately provisioned**
verification key, never the Keymaker writer key. Rotation of either key MUST
preserve the stream, old continuity evidence and explicitly authorized public
key epochs. No automatic trust-on-first-use or old-seed reset is allowed.
Custody/provider, enrollment and rotation procedures remain activation gates.

### 3.2 Exact records and signatures

A record is CCJ-1 of exactly `{body,signature}` followed by LF. `body` contains
exactly these fields:

| Field | Value |
| --- | --- |
| `v`, `type`, `consumer` | Integer 1, `keymaker-state-witness/1`, `keymaker` |
| `stream`, `station` | Exact protected bindings from section 3.1 |
| `seq` | Positive safe integer; exactly previous sequence + 1 |
| `state_epoch` | Candidate epoch n+1, identical for its intent and resolution |
| `kind` | `intent` or `committed` |
| `commit_class` | One class from section 4.1; identical for the pair |
| `base_state_digest`, `state_digest` | Exact previous resolved state digest and intended candidate digest; initial base is null only under explicit bootstrap |
| `prev_hash` | Lowercase SHA-256 hex of the complete previous record including LF; 64 zeroes only for authorized first intent |
| `intent_hash` | Null for intent; complete intent-record hash for committed resolution |
| `key_epoch`, `key_id` | Positive authorized writer-key epoch and `sha256:` digest of its raw 32-byte public key |

The signature preimage is UTF-8 `keymaker-witness-record/1`, one NUL byte,
then CCJ-1 of `body` without LF. `signature` is the strict canonical unpadded
base64url encoding of its 64-byte Ed25519 signature. Unknown/duplicate members,
invalid CCJ-1 scalars and noncanonical encodings MUST be rejected. A record
hash covers the complete canonical envelope **including LF**, not just body.
This domain is distinct from SSHSIG, `registration/1`, witness acknowledgements
and witness head replies. There is no general witness-signing socket method.

An intent compares the last resolved head and advances the state epoch once.
Its matching committed record MUST immediately follow, repeat every candidate
binding and have both `prev_hash` and `intent_hash` equal to that exact intent's
hash. No new intent bypasses an unresolved one. Room for both sequences is
required before accepting an intent. A repeated exact record MAY return its
original receipt; a different record at that position MUST fail.

### 3.3 Required operations

The separate [witness-service candidate](witness-service.md) proposes the shared
server, concrete wire encodings, transport and qualification gates. Its
[consumer-delta list](witness-service.md#12-consumer-deltas-and-activation-decisions)
requires explicit acceptance; the existing consumer contract below is unchanged.

The placement-independent interface MUST provide:

1. **Compare-and-append** of a signed record against the exact expected previous
   sequence/hash, atomically per stream. An acknowledgement follows independent
   durable retention, never just queueing or local caching.
2. **Fresh latest-head read** from the authoritative serialized stream, binding
   a client-generated 32-byte unpredictable challenge to the actual latest
   record, including an unresolved intent. A historical lookup, stale replica
   or cached signed receipt cannot answer it. Reads and appends share one
   linearizable order.
3. **Continuity evidence** from any surviving trusted checkpoint to the latest
   head, including the intent resolved by a committed head. The witness retains
   acknowledged records, signatures, predecessor hashes, authorized writer-key
   epochs and exact receipts; it MUST NOT truncate, replace or renumber them.
   Any archival proof must preserve verification, not discard that obligation.

An append receipt's signed body MUST bind `v`, `consumer`, `stream`, `station`,
`seq`, `state_epoch`, `kind`, `base_state_digest`, `state_digest`, `record_hash`
and the exact writer `key_epoch`/`key_id`. A head reply MUST bind those values,
the complete head record, its continuity proof and the exact read challenge.
Use separate signature domains `keymaker-witness-ack/1` and
`keymaker-witness-head/1`, each followed by NUL and CCJ-1 of its signed body.
Both signatures are verified against the pinned witness key. Authentication
alone does not prove latestness; durable retention and serialized latest reads
are requirements of the trusted service. No private material, approval body,
retained envelope or client payload is transmitted.

Each operation MUST have a finite deadline, default at most five seconds,
further bounded by the caller's remaining budget. Retries, proof pages and
transport reconnects share that bound; no unbounded background retry permits
release. Existing two-second native/signing budgets are not increased.
Frame sizes, continuity-proof pagination/caps, authentication, authorization,
transport and independent checkpoint retention need qualification before
activation. Keymaker cannot silently inherit registrar audit transport or
open general network egress to satisfy this interface.

## 4. Write protocol and crash resolution

### 4.1 Durable commit classes and release cost

The same protocol applies to each class below. These are logical transactions,
not permission to acknowledge individual file writes early.

| `commit_class` | Required use |
| --- | --- |
| `binding-result` | Register, revoke, unbind, retirement persistence, registration-proof retention and every other retained native result/ID change, with its audit linkage. Exact retries still witness their new audit records, but never create another effect or nonce. |
| `enrollment` | Every high-water commit, including an equal-state reload, and accepted pin/generation-admission changes. Verification failure fences as before and cannot install partial authority. |
| `reconciliation` | Bootstrap, approval/ledger creation, receipt publication, invalidation rename, consumed-ID append, evidence removal and privileged recovery. Each intermediate separately durable boundary either has its own pair or is inside one fenced transaction whose exact final inventory is precommitted. |
| `audit` | Every ordinary durable audit append, including hello, public lookup, signature success, refusal and bounded aggregate counter flush. Audit-only state is protected state. |
| `retention` | Journal rotation/sealing, archive acknowledgement/index and permitted online-segment removal. |
| `policy-custody` | Explicit registry/pin/configuration changes, accepted external authority anchors, master public epoch and authorized witness-key rotation/migration. |

**Surface A requires the witness for every signature release**, because its
mandatory durable success audit changes the witnessed journal head. It does
not require a registrar proof or purpose-2 signature. Registration on B requires
witnessed retention and final success audit before releasing the proof. Binding
changes require witnessing even when no signature is returned. Hello, pubkey
and ordinary refusals also change audit state and require witnessing in normal
operation. Read-only startup verification itself appends nothing.

A logical transaction MAY include a precomputed bounded group of audit/state
writes if its exact final digest is known before intent and **all** dependent
responses wait for resolution. This does not waive audit-before-release,
generation → Store → enrollment → terminal F ordering where PC2 applies,
actual-write rechecks, rollback
fences or the native request budget. No signature can ride on a cached receipt
for a previous equal state. Witness traffic MUST NOT recursively append to the
protected audit journal; bounded typed service-health diagnostics are separate,
grant no authority and cannot become an unwitnessed normal result.

There are at least two sequential witness durability round trips per logical
commit, plus local fsyncs. A separately committed final success audit costs
another pair; the draft does not claim a one-pair implementation. Startup adds
a fresh read/continuity check. Throughput, witness storage (including A traffic)
and the existing two-second budget require measurement. Outage or excessive
latency sacrifices availability of **both** surfaces; this is intentional.

### 4.2 Ordered transition

1. Serialize the complete protected state. Close new release admission and
   drain existing actual-write barriers before irreversible transition; retain
   generation → Store → enrollment ordering. Validate authority and prepare
   exact candidate bytes/epoch/digest without publishing them. For PC2 include
   its root, all participant/attempt/hold state and the exact S2 phase. Establish
   coordinator quiescence, then release **all** journal/Store/enrollment/F locks
   before witness I/O; no witness lock may introduce a reverse acquisition.
   Apply the [two-boundary rule](keymaker-pc2.md#11-short-critical-sections-and-continuous-exclusion-leases):
   witness network I/O and notifications remain outside all maintenance locks;
   durable closed-admission/hold state persists across the external phases.
   Never drop a required continuous exclusion lease to make the call. If the
   coordinator cannot preserve exclusion and the unlocked network boundary,
   refuse with admission closed. Fixed local lease operations require reviewed
   authenticated targets, bounded time and transitive no-back-edge graphs; none
   is an exception inside the journal/C/F critical section. Qualification parents
   release D before launching/waiting for children; children own D independently.
   Qualifying that cross-owner unlocked coordinator remains WC5, not a shipped API.
2. Outside all locks, compare-and-append intent for epoch n+1 against the exact
   resolved head.
   Validate its exact durable acknowledgement. **Before this succeeds, no
   local durable commit is allowed**, including a receipt invalidation rename.
3. Reacquire the local forward journal → C → F order, revalidate the exact
   candidate/authority and both owners' holds, and commit locally, using the
   required full-write, file-sync,
   checked-close, rename and directory-sync boundaries. Persist its epoch/header.
   Preserve every existing local fail-closed check. A multi-file error is
   indeterminate durability, never permission to restore the earlier state.
   Release all local locks while retaining quiesced admission before resolution.
4. Only after successful local durability, append the matching committed
   resolution **outside all locks** and verify its exact durable acknowledgement.
   Reenter the forward local order for final validation/release. Recompute local
   state and recheck protected policy, current authority, request deadline and
   actual-write fences. Only then reopen admission/release. If another mandatory
   audit append occurs, witness that transaction before its dependent release.

| Failure/crash point | Required state and recovery |
| --- | --- |
| Before intent, or intent rejected with provably no append | No candidate commit. The failed transition fences old and new admission. A fresh latest-head proof and otherwise valid reconciliation are needed; old local bytes alone cannot reopen it. |
| Intent append outcome/receipt unknown | No local commit; an intent may already be durable. Fence and read fresh head. An actual unresolved intent requires privileged recovery even if local state equals the previous committed state. |
| Intent acknowledged, before/during local commit | External intent survives whole-local-state restoration. Keep all candidate/partial evidence, fence and require privileged exact-candidate recovery. A local commit error MUST NOT append a resolution. |
| Local commit successful, resolution absent/failed | Keep new local state; external intent remains unresolved. No response or old-state fallback. Privileged recovery required. |
| Resolution outcome/receipt unknown | Fence. A fresh authoritative latest read proving the exact matching committed record MAY replace the lost receipt after complete validation. If latest is still intent, privileged recovery is required. |
| Resolution durable, response lost | Restart may reconcile that exact latest committed state; retained native ID rules still govern retry. No duplicate append, effect, nonce or ledger consumption. |

Cancellation/deadline before irreversible work returns the existing deadline
code where applicable. After uncertain intent/commit it also leaves the service
witness-fenced; it never rolls back durable evidence to make cancellation look
side-effect free. Refusal delivery MUST contain no success/result/signature.
If witness failure prevents a normal durable refusal audit, close admission and
use bounded separate health telemetry, as with an unauditable failure in base
section 11; do not execute or recursively attempt witnessed refusal logging.

## 5. Startup, restoration and privileged recovery

Before serving either socket, establish single-instance exclusion and protected
stream/key/policy bindings, then validate local artifacts and recompute their
complete state digest. Generate a new unpredictable challenge using qualified
post-restore entropy; a snapshotted PRNG counter is insufficient. Request a
fresh latest head and verify its witness signature, domain, challenge, stream,
station, writer signature/purpose binding, sequence and continuity.

A latest **committed** record permits reconciliation only if its exact intent
is proved, local epoch/digest and all candidate bindings match, and all existing
local validation succeeds. A lower head than a surviving trusted checkpoint,
different record at an equal sequence, broken chain, missing local artifact,
empty/missing stream, old digest or invalid response MUST fence. A restored
local checkpoint is not independent freshness evidence. No local mutation or
witness append is part of this comparison; subsequent startup audit or policy
commits use section 4 before readiness/release.

A latest **intent** always fences normal startup, even when its intended digest
or the prior committed digest equals local bytes. Locally remembered pending
metadata, equal application bytes and the absence of a receipt cannot decide
whether a commit occurred. There is no automatic resolution, cancellation,
roll-forward or rollback. This includes unchanged-state commits: the newer
external epoch/intent survives restoration of every local pending marker.

Privileged recovery MUST stop/exclude all serving instances; obtain the fresh
exact intent/head; independently authenticate the intended complete state and
retained history from surviving evidence outside the restored failure domain;
and authorize the exact stream, station, epoch, intent hash, digest and policy.
Only then may it recover and durably commit that **exact** candidate, or verify
its independently reconciled successful commit, and acknowledge its matching
resolution. Final full validation precedes serving. A witness digest alone
cannot reconstruct missing bytes or prove that restoring old bytes is safe.
If the exact candidate cannot be recovered/approved, remain fenced. Cancellation,
replacement, stream repair and loss-of-evidence procedures need separate review;
no existing reconcile flag implements them.

This closes the local restore window: after a newer completed commit, restored
state has an older epoch/digest than the fresh witnessed commit; after an intent
but before resolution, even an entirely restored old host sees the unresolved
external obligation. Same-boot restoration and reboot inside an approval TTL
receive no exemption. The guarantee depends on witness independence, honest
latest reads, qualified challenge entropy and old-instance exclusion.

## 6. Refusals and option A interaction

Proposed stable code **`state_witness_unavailable`**, `retryable:false`, means
that current external state evidence is absent, untrusted, inconsistent,
unresolved or unavailable. It is one fail-closed service condition, with typed
restricted diagnostics distinguishing causes. No new signed registrar verdict
is introduced. On surface A map it to `SSH_AGENT_FAILURE`; on B use the existing
error wrapper; before listeners exist emit only a bounded startup diagnostic.
It blocks both surfaces and requires fresh proof or privileged reconciliation,
not a client retry that silently clears the fence. Existing parameter, entropy,
clock and deadline refusals retain their meanings; an invalid witness reply is
not a registrar enrollment parse error.

Option A remains the interim policy until C is implemented and activated.
Its boot identity, ten-minute TTL, trusted UTC/boot-elapsed checks, strict
post-lock invalidation, ledger and explicit confirmation stay required whenever
an A approval is used. This proposal does not reinterpret their present format
or assert that they prevent whole-state restoration.

In fully selected C, a fresh matching latest-head check replaces the **per-start
A freshness approval**, so boot/TTL checks are redundant for that normal path
and no A receipt is consumed automatically. Old receipt/consumed/fence evidence
remains in the protected inventory; an outstanding approval or consuming/pending
fence is not authority and needs the qualified operator workflow. Boot/TTL
still constrain any explicitly authorized A-based bootstrap/recovery consent;
they never replace fresh witness evidence. Consumed IDs and historical receipt
evidence are not discarded just because C is enabled.

For a C-enabled workflow that does consume or publish a receipt, external intent
MUST precede the first local invalidation/publication action. This is a proposed
change to the local option A consumption ordering **for C only**: C's quiesced
reconciliation phase must establish the candidate under witness coordination
before that rename. No pre-invalidation reading exception is added to the
shipped A policy. Its existing command and injected test policies cannot be
relabeled C without a reviewed implementation of this protocol.

Selecting C, switching back to A, rebinding a stream and returning to C require
explicit privileged, independently evidenced reconciliation and preserved
history. Outage MUST NOT automatically downgrade to A or accept a local receipt.
An explicit A fallback cannot erase a pending external intent, overwrite a
newer head or later re-enter C without resolving that evidence. Bootstrap of an
empty stream is an explicit authorized act, never inference from missing files.

## 7. Negative lifecycle vectors and positive controls

These are **text-only implementation requirements**, not executed vectors.
Existing `vectors/` files test derivation/byte formats and paired refusal inputs;
they have no natural witness lifecycle format and are unchanged. `KW` IDs are
local to this supplement. Unless stated otherwise every row starts from valid
resolved state L, sole-instance exclusion and independently trusted bindings.
Every negative is explicitly classified below. Both classes return no success
signature/proof/result or authority for the rejected operation and preserve the
specified durable evidence. Their distinct postconditions are:

- **service fence:** a witness, integrity or uncertain-transition failure blocks
  admission/release on both surfaces until the fresh proof or privileged
  reconciliation required by sections 4–6 succeeds. If that failure prevents a
  normal witnessed refusal audit, only bounded separate health telemetry is
  permitted; it cannot substitute for an ordinary refusal audit.
- **client refusal:** an ordinary invalid request, or a deadline with no
  uncertain transition, retains its existing refusal code and normal durable
  witnessed refusal audit. Once that audit transaction resolves, admission
  remains open or reopens on the same healthy instance; the next valid request
  succeeds without restart or privileged recovery. The client error alone
  never creates a persistent service fence. If witnessing that audit itself
  fails, the separate witness failure follows the service-fence rules above.

The expected code is the Keymaker startup/operation verdict, with surface A's
existing wire mapping. These classes restate sections 4–6, not new error or
recovery rules. Each negative must be paired with its listed control.

| ID | Scenario | Class | Expected code and state | Control |
| --- | --- | --- | --- | --- |
| KW01 | Restore complete older L after witnessed M, including bindings and audit to a mutually consistent pair | service fence | `state_witness_unavailable`; no admission or local/witness reset | KWP1 |
| KW02 | Restore receipt plus old consumed ledger within TTL or across reboot | service fence | `state_witness_unavailable`; no renewed consent or duplicate consumption | KWP1 |
| KW03 | Restore only consumed IDs, high-water, receipt/consuming fence or retained request results | service fence | `state_witness_unavailable`; inventory mismatch, no nonce/effect replay | KWP1 |
| KW04 | Forge witness head signature, alter digest or omit the challenged binding | service fence | `state_witness_unavailable`; no local mutation | KWP1 |
| KW05 | Replay authentic historical head/receipt with a new challenge while a newer commit or intent exists | service fence | `state_witness_unavailable`; stale signatures do not reconcile | KWP1 |
| KW06 | Latest head is acknowledged intent; local commit never ran, is partial, or completed without resolution | service fence | `state_witness_unavailable`; retain exact intent and local evidence; privileged recovery only | KWP3 |
| KW07 | Local bytes equal intended/previous bytes after an unchanged-state intent; restore erased local pending identity | service fence | `state_witness_unavailable`; epoch/intent still fences, no automatic resolution | KWP3 |
| KW08 | Witness unavailable or operation deadline exceeded at startup | service fence | `state_witness_unavailable`; neither socket serves | KWP1 |
| KW09 | Intent append/ack fails, including lost ack after durable intent | service fence | `state_witness_unavailable`; zero local candidate commits, old authority fenced | KWP2 |
| KW10 | Local commit errors after acknowledged intent, including error after rename/directory sync | service fence | `state_witness_unavailable`; no resolution or compensating rollback; preserve indeterminate state | KWP3 |
| KW11 | Resolution unavailable after successful local commit | service fence | `state_witness_unavailable`; new state retained but unusable | KWP4 |
| KW12 | Replay another stream/station/consumer record or registrar receipt | service fence | `state_witness_unavailable`; no cross-consumer reconciliation | KWP1 |
| KW13 | Purpose-1/2 key signs correct witness-domain bytes, or purpose-3 signature uses SSHSIG/registration domain | service fence | `state_witness_unavailable`; wrong key/domain never verifies | KWP2 |
| KW14 | Surface A selects the witness public key; B tries to register purpose 3 | client refusal | A: `sign_key_mismatch`; B: `purpose_unknown`; no key use/binding change | KWP5 and KWP8: after each witnessed refusal, a valid purpose-1 A request or purpose-2 B helper request succeeds on the same healthy instance, without restart/recovery |
| KW15 | Witness is behind surviving independent head, changes record at equal sequence or supplies broken continuity | service fence | `state_witness_unavailable`; never adopt regression/equivocation | KWP1 |
| KW16 | Missing local artifact or empty stream is interpreted as bootstrap | service fence | `state_witness_unavailable`; no implicit state/stream creation | KWP6 |
| KW17 | Two different intents compare the same head, or new intent bypasses unresolved intent | service fence | `state_witness_unavailable` for loser; no losing commit/release or duplicate sequence | KWP2 |
| KW18 | Replacement cannot exclude old serving instance | service fence | `state_witness_unavailable`; no commit or readiness; CAS is insufficient | KWP1 |
| KW19 | Exhaust state epoch or leave room for only one witness record | service fence | `state_witness_unavailable`; no intent/local write, no wrap/new stream | KWP2 |
| KW20 | Skip witnessing an A success audit, helper retention/final audit, binding change or refusal audit | service fence | `state_witness_unavailable`; no dependent release; unwitnessed tail cannot reconcile | KWP5 |
| KW21 | Restore old name-index/pin/master-public-epoch policy or remove audit segment without approved archive transition | service fence | `state_witness_unavailable`; no revived path, authority or truncated evidence | KWP1 |
| KW22 | Outage automatically selects A or consumes restored approval | service fence | `state_witness_unavailable`; selected mode and pending witness evidence preserved | KWP7 |
| KW23 | Resolve pending intent solely from restored local equality or choose different candidate under operator recovery | service fence | `state_witness_unavailable`; exact external intent retained | KWP3 |
| KW24 | Read challenge entropy unavailable | service fence | `entropy_unavailable`; no latest-read acceptance or readiness | KWP1 |
| KW25 | Request deadline expires with an uncertain intent/commit outcome | service fence | `request_deadline_exceeded`; no release; preserve ambiguous intent/commit evidence and leave subsequent operations `state_witness_unavailable` | KWP3 |
| KW26 | Request deadline expires before irreversible work or after a fully resolved transition, with no uncertain witness/local outcome | client refusal | `request_deadline_exceeded`; no late release; normal witnessed refusal audit, no persistent fence from the deadline alone | KWP8 |

| ID | Positive control and required observation |
| --- | --- |
| KWP1 | Fresh correctly signed challenge-bound latest committed head equals complete local epoch/digest; continuity and all ordinary checks pass; startup comparison appends nothing. |
| KWP2 | Intent acknowledged, exact local commit succeeds, exact resolution acknowledged; only then release. Identical application bytes still advance epoch and use a new pair. Exact record retries never append twice. |
| KWP3 | Quiesced privileged recovery independently approves exact intent/candidate/history, completes/verifies local durability, resolves it and revalidates before serving. |
| KWP4 | Resolution was durable but receipt lost; a fresh latest read proves that exact resolution, with no duplicate append. |
| KWP5 | Valid purpose-1 A signature and purpose-2 helper proof independently verify after all applicable witness/audit/release steps; internal purpose-3 record verifies only at the witness. |
| KWP6 | Explicit independent bootstrap authorization enrolls exact nonsecret identity/policy and complete initial state at epoch 1; service startup alone cannot bootstrap. |
| KWP7 | Explicit evidenced fallback preserves pending C history; re-entry requires exact reconciliation/resolution. A boot/TTL and one-use rules remain enforced. |
| KWP8 | On the same healthy instance, KW14 wrong-key/purpose requests and KW26 resolved deadline refusals each retain their ordinary witnessed refusal audit; after its resolution, the next valid in-budget request succeeds without restart or privileged recovery. Exercise both A and B and verify no rejected key use, binding effect or late release. |

Implementation qualification MUST demonstrate narrowing controls that remove
pre-commit intent, accept stale challenge replies, bypass pending-intent fencing,
omit each protected component and skip witness-before-release on each surface.
Each must fail a named lifecycle test at the intended assertion while its
positive control passes. A parser crash, skipped plant or unrelated setup error
does not establish coverage. No such tests or mutants are claimed in this slice.

## 8. Open activation questions

- **WC1 — placement and independent retention:** the decided placement is
  a separately administered trust node outside the platform's administrative
  domain, shared with the owner registry, in separate accounts and processes,
  with the trusted checkpoint kept off that node. Until deployed and qualified,
  the existing honest mode A holds and WC1 stays open for activation. Qualify
  independent restore, off-node checkpoint retention and joint-loss limits;
  this placement decision is not deployment or qualification evidence.
- **WC2 — protocol, clock and freshness:** close transport/authentication,
  signed response framing, proof size/paging bounds, durable-ack/linearizable-read
  evidence and restart-safe challenge entropy. A challenge proves response
  binding, not honesty/latestness. Wall-clock timestamps/TTL alone cannot prove
  freshness; monotonic operation budgets and trusted time for existing A/helper
  checks must be qualified after restore/suspend. No implicit clock-skew grace.
- **WC3 — stream provisioning:** separate Keymaker consumer streams are the
  accepted direction; qualify exact station/lineage enrollment, ACLs, closed
  state inventory, full manifest/header storage and continuity-preserving migration.
- **Witness key custody:** approve purpose 3, writer custody/provider and
  independently provisioned witness key, purpose attestation/provisioning,
  rotation/revocation and lost-master recovery without stream/epoch reset.
- **WC4 — exclusion:** qualify old-instance exclusion across snapshots/clones
  for the complete serving lifetime; local flock or CAS does not supply it.
- **WC5 — lifecycle/recovery:** close quiesced operator/daemon coordination,
  inventory schemas, bootstrap, C-specific receipt ordering, exact-candidate
  recovery authorization, explicit A fallback and re-entry, cancellation/repair
  and total loss of independent evidence. Qualify latency/storage for audit of
  every operation, especially A, without relaxing resource budgets.

PC2 additionally requires independently current per-transaction root/counter/
incarnation/journal and unresolved-obligation retention outside the restored
failure domain. Startup-only/lagging anchors and a restored local floor cannot
supply it. Complete-state Keymaker evidence is separate from registry WC1
publication proof; no local F, checksum or message-state schema floor activates C.

All remain open for implementation/activation. A published spec and passing
unchanged-code tests close none of them.

## 9. Normative changes to existing sections

These are C-only proposals for review. The separate PC2 base amendments do not
activate them, select a witness mode or discharge WC1–WC5. Section references
below are to `keymaker.md`.

| Existing rule | Proposed C-only change |
| --- | --- |
| Sections 3.2 and 4.2: durable binding/allocator and name-index history | Commit complete records, retained effects and policy/history under the monotonic witnessed state epoch; recovery cannot reset any of them. |
| Section 4.1: only purpose 1 and 2 accepted | Add internal-only purpose 3, `state-witness`; keep A, binding registration and registrar proof restrictions unchanged. |
| Section 8 and local enrollment consumption contract | Add witnessed high-water/consumed-ledger/receipt transitions; fresh C startup replaces per-start A approval. For C receipt workflows only, acknowledged intent precedes local invalidation/publication, requiring a separately implemented quiesced ordering. Shipped A's first-action rename and refusal/retry windows remain unchanged. |
| Section 9: domain separation table | Add internal purpose-3 witness record domain and independently keyed acknowledgement/head domains; expose no extra public signing operation. |
| Section 10: unready helper may coexist with A; all egress denied | A witness fence closes both surfaces. Qualify an explicit narrow witness communication mechanism without general service egress; no mechanism or exception is activated here. Existing request budgets stay unchanged. |
| Section 11: local durable audit before release and local hash continuity | Require witnessed complete audit state before every dependent A/B release, including public responses/refusals, and witnessed retention. Keep closed audit schema; witness records/health diagnostics are separate to avoid recursive commits. |
| Section 12: privileged handoff/recovery | Require reviewed witness provisioning, independence/exclusion and cross-privilege recovery/mode-change runbooks before C use. Existing commands do not install or activate C. |
| Section 13: qualification and vectors | Add section 7 lifecycle negatives, controls and narrowing plants as future required implementation evidence; existing byte vectors are unchanged. |
| Section 14 and unresolved questions | Add open witness activation gates; residual restore risk remains open until implementation, qualification and activation. |
| Section 15: stable local codes | Propose `state_witness_unavailable` (`retryable:false`) as a cross-surface witness fence, with existing SSH failure/native wrappers and deadline/entropy mappings. |
