# Combined authority-root format (G4 draft)

Status: **draft for architect co-authorship, reviewer acceptance and curator
content approval, in that order; no runtime implementation or activation**.
The architect is a mandatory acceptor of every byte, primitive and limit the
user-manager consumes under F. Golden vectors check a proposed format, not an
implemented reader, append guard, custody provider or recovery coordinator.
PC2 S1 code starts only after those content gates. The three joint PC2 gates
remain OPEN. This separate file keeps the format/read-set review bounded;
[PC2](keymaker-pc2.md) retains the safety/ordering contract.

## 1. Versions, grammar and limits

The proposed combined snapshot schema and minimum reader/authority floor are
**3**. Its logical root is **keymaker-authority/2**: version 1's closed inventory
cannot silently acquire participant/reservation/provenance references. This is
an explicit proposed delta to PC2 §2 and user-manager activation-order §6.2,
requiring the architect's acceptance; neither version is an implemented PC2
codec. S2 schema 2 and all historical audit bytes/hashes remain unchanged.

Use the integer-only CCJ-1 bytes from [base §7](keymaker.md#7-surface-b-native-control):
UTF-8 without BOM/trailing newline/whitespace, sorted scalar-value keys, no
normalization, shortest specified string escapes, safe decimal integers only.
Reject invalid UTF-8/scalars, negative zero, fractions/exponents, extra documents,
unknown or duplicate **decoded** members, case/spelling aliases and noncanonical
bytes. Check raw byte limits before allocation, recursion depth <=16, then the
complete exact member set and types. Unordered JSON input is not canonicalized
into acceptance. Names such as RootDigest, rootDigest and root_digest are not
aliases. All listed members are required unless an explicit union says otherwise.

| Primitive | Exact bound |
| --- | --- |
| N / Z | N: 1..9007199254740991; Z: 0..9007199254740991, JSON integer; no wrap/reset/reuse of monotone fields |
| UID | Integer 0..4294967295; downstream profiles may refuse their reserved UIDs |
| Token / ID | Token: nonzero 32 lowercase hex; request/process/manager IDs: exactly 32 lowercase hex; no coercion |
| D / H | D: `sha256:` plus 64 lowercase hex; H: exactly 64 lowercase hex for unchanged binding/audit/journal interfaces |
| V | `fsverity-sha256:` plus 64 lowercase hex; a different algorithm or plain SHA substituted here refuses |
| Boot | Canonical lowercase UUID, 36 ASCII bytes |
| Text | 1..255 UTF-8 bytes, no NUL/control scalars; no truncation or normalization |
| Object/name role | Closed enums below, never paths or free-form labels |
| Arrays | Bounds below apply together with encoded-byte limits; empty is [], never null |
| Null | Only fields explicitly marked nullable; absent and null never interchange |

The logical root is <=1048576 bytes and <=4096 retained reservation entries.
These are simultaneous caps: 4096 rows of maximum-size fields need not fit.
All retained metadata/history, attempts, artifacts, recovery/staging and both
owners' reservations share **268435456 bytes (256 MiB)**. Smaller per-file/read
limits below do not create another budget. Exhaustion closes/refuses without
eviction. Individual maxima are not promises of jointly achievable allocations.

## 2. Exact combined inventory and participant references

Closed combined installed snapshot:

```text
{schema_version:3,authority:Root,payload:Ref,audit_seq:N,audit_hash:H}
```

The snapshot's payload equals authority.payload byte-for-byte; its audit pair
equals authority.binding_commit's pair. The sole authority point is complete
final Root publication with all transaction/cleanup obligations satisfied, not
installation of this snapshot, payload, a provenance file or a readable mirror.
Root bytes in the snapshot and final root must match exactly.

Closed private payload (immutable mandatory participant, **not** an independent
serving format or optional authority sidecar):

```text
{version:"keymaker-private/3",next_registration_number:N,records:[Binding],
 requests:[RetainedRequest],transaction_revision:N,messages:Messages2,
 message_dispatch:[{transaction:ID,codec:MessageCodec}]}
```

Binding, RetainedRequest and Messages2 retain the complete closed structures
in [S2](keymaker-msg-state.md#21-versioned-protected-inventory) and its
[artifact reference](../docs/message-state-codec.md). Retain every allocator,
original caller/ID/method/canonical-argument/result byte, ordinary binding,
tombstone, certificate, association, transaction, publication and pending fence.
Records <=65536, requests <=65536, each S2 history array <=65536; actual total
bytes may constrain them earlier. Native argument/result encodings <=65536 bytes
each, existing request/member schemas unchanged; no new result namespace.
Binding association text <=255 bytes, canonical generation/path/principal and
existing lifetime/status enums remain required. The provision extension's
provisioned status is permitted only in the new PC2 reservation path. Payload
<=256 MiB subject to the aggregate peak; depth <=16. It contains no master seed,
child private key, chain code or raw signed operator document.

Ref is exactly:

```text
{role:Role,codec:Codec,digest:D,bytes:N,verity_digest:V,
 device:{major:Z,minor:Z},inode:Hex16,uid:UID,mode:Mode}
```

bytes <=256 MiB and equal st_size. Device components <=4294967295; inode is
16 lowercase hex (not a lossy JSON integer), nonzero. Mode is exactly "0600"
(service state) or "0640" (root-owned shared recovery metadata), with required
owner/group/directory protection from PC2 §1/§4. A participant is a regular
single-link file: verify this separately; no symlink, writable mapping, alias,
path substitution or hardlink. Paths derive from role and digest under protected
configured directory descriptors, never from a supplied path. pin_policy,
manager_inventory and recovery_history require uid=0, mode="0640" and root-owned
0750 parents. Other Ref roles require the independently configured service UID,
mode="0600" and service-owned 0700 parents. A Ref cannot redefine its expected
owner. Full preparation verifies protected original-provider ownership before
sealing service-private retained copies. No participant may alias F_auth or F_pkg.
Role is exactly
payload, pin_policy, enrollment_snapshot, high_water, approval_history,
message_inventory, native_inventory, migration_history, manager_inventory or
recovery_history. At most one Ref per role; payload, pin_policy,
enrollment_snapshot, high_water, approval_history, message_inventory,
native_inventory, migration_history, manager_inventory and recovery_history are
all required, even for empty histories. No omission means empty.

Codec dispatch is exact: payload=keymaker-private/3; pin_policy=pin-config/1;
enrollment_snapshot=registrar-snapshot/1; high_water=registry-high-water/1;
approval_history=keymaker-approval-history/1;
message_inventory=keymaker-message-inventory/3;
native_inventory=keymaker-native-inventory/3;
migration_history=keymaker-migration-history/1;
manager_inventory=pc2-manager-inventory/1;
recovery_history=pc2-recovery-history/1. The existing pin/snapshot/high-water
source schemas remain owned by their current providers; these dispatch names
identify exact retained provider bytes, not permission to broaden their readers.
The following new sealed inventories have exact closed wrappers (G5 must accept
implementation/lifecycle and provider bindings, not invent optional members):

| Codec | Exact additional structure / cap |
| --- | --- |
| keymaker-approval-history/1, keymaker-migration-history/1, pc2-recovery-history/1 | {version:matching literal,entries:[HistoryRef]}; <=65536 entries, <=256 MiB under aggregate |
| keymaker-message-inventory/3 | {version:matching literal,entries:[HistoryRef]}; includes every S2/combined artifact and recovery copy, <=1048576 entries, <=256 MiB |
| keymaker-native-inventory/3 | {version:matching literal,entries:[{caller:{uid:UID,generation:Token},request_id:ID,method:Text,arguments_digest:D,result_digest:D,status:"pending"|"committed"}]}; <=65536 rows, <=256 MiB; must match complete retained namespace, not a replacement cache |

HistoryRef is exactly {kind:HistoryKind,id:Text,digest:D,bytes:N}. HistoryKind is
legacy_snapshot, s2_snapshot, combined_payload, message2, message3, approval,
policy, migration, attempt, hold or recovery; bytes <=256 MiB, IDs unique within
kind, sorted by (kind,id). The role/ID selects a protected owner-defined retained
object, not a manager-supplied path. Full preparation resolves and validates every
original object under its exact codec; all copies contribute to capacity. Old
S2 artifact SHA256 bits are preserved (the inventory's D prefix does not rehash
or rewrite original H-bearing bytes). These inventories confer no authority
independently of the common root. Manager inventory is defined in §4.

All ten immutable participant files are enabled for fs-verity before reference
publication. The writer fully validates exact bytes and cross-references outside
short critical locks, records both plain digest and fs-verity digest, and under
C/F rechecks installed identity/measurements and exact prepared candidate before
commit. The manager does not accept a previously computed admitted flag alone.
fs-verity measurement is distinct from plain SHA-256; Linux documents constant
size-independent measurement and enforced immutable file contents, with corrupted
reads failing. It supplies no freshness or writer authentication by itself.
See the [kernel interface](https://docs.kernel.org/filesystems/fsverity.html#fs-ioc-measure-verity).
Enabling verity can be expensive and belongs outside the critical section.

**Proposed platform dependency, not a shipped capability:** this draft chooses
fs-verity plus fully validated provenance as its exact bounded-read primitive.
The format/platform owners must accept and qualify its algorithms, inode lifetime,
permissions and latency. No inode-only, writable-file, cached validation bit or
full-256-MiB-scan fallback exists. If unsupported or not composable with all root
installers and immutable histories, PC2 stays closed; a different primitive needs
an explicitly revised format, not an optional unverified branch.

## 3. Logical root, provenance and acyclic hashes

Root is exactly the following (all members required):

```text
{version:"keymaker-authority/2",minimum_reader_schema:3,
 transaction_revision:N,previous_root_digest:D|null,root_digest:D,
 binding_commit:{version:N,digest:H,audit_seq:N,audit_hash:H},
 authority_incarnation:Token,instance_id:ID,boot_id:Boot,master_epoch:Text,
 pin_policy_digest:D,registry_digest:D,custody_ready:boolean,
 withdrawal_counter:N,journal:{seq:N,hash:H},recovery:"clear",entries:[Entry],
 payload:Ref,participants:MetaRef,provenance:MetaRef,reservation:MetaRef,
 manager_baseline:{revision:N,digest:D}}
Entry = {uid:UID,generation:Token,predecessor_generation:Token,
 registration_number:N,master_epoch:Text,owner:Text,
 provision_effect:{caller_uid:UID,caller_generation:Token,request_id:ID},
 provision_pin_digest:D,pin_policy_digest:D,admitted:boolean,
 binding_status:"provisioned"|"active"|"unbound"|"revoked"}
MetaRef = {codec:MetaCodec,digest:D,bytes:N}
```

MetaCodec is exactly keymaker-participants/1, keymaker-provenance/1 or
keymaker-reservation/1 in its matching field; bytes <=65536. MetaRefs locate
immutable same-named-role objects by digest in protected metadata directories.
Root's payload Ref equals the participants' payload. Sorted entries by strictly
increasing registration number retain complete PC2 history and unique live
tuple/path associations. An absent target never means an ordinary binding or an
empty history. Previous root is null only at independently authorized genesis;
otherwise it is the exact previous **final** root digest, never a staging root.
The pin-policy digest is over exact protected current pin bytes, not reencoded
map values. Root revision and binding_commit.version agree with the candidate.

Closed participants object:
`{version:"keymaker-participants/1",files:[Ref]}`; exactly the ten roles above,
lexically sorted. <=65536 bytes, no duplicate role/physical inode, maximum ten
Refs. Its hashes and fs-verity measurements bind the fully validated private
snapshot, policy, histories and the complete aggregate inventories.

Closed provenance:
`{version:"keymaker-provenance/1",base_root_digest:D|null,facts_digest:D,
participants_digest:D,journal:{seq:N,hash:H}}`, <=4096 bytes.
Facts are the exact Root members authority_incarnation, instance_id, boot_id,
master_epoch, pin_policy_digest, registry_digest, custody_ready,
withdrawal_counter, journal and entries, with version
`keymaker-authority-facts/1`. The facts preimage excludes future references and
commit hashes. Their digest binds the same exact tuples/pins/owners/effects and
both eligibility facts validated against complete participants. It cannot be a
post-commit async projection. Base root, journal ancestry and independently
current continuity must be proved; a self-consistent digest is not authority.

For all recipes CCJ means complete canonical bytes, no newline. Every literal
version/type below is checked **before** hashing; substituting a tag refuses.
D(x) means sha256: plus SHA256(x); H(x) is the same hash without that prefix.
Domain separation is in the required version/type member, not a hidden prefix.

| Digest / tag | Exact preimage |
| --- | --- |
| Payload | CCJ(payload), including version keymaker-private/3 |
| Participants / provenance / reservation / manager inventory / guard | CCJ(object including its exact version); reservation's own digest is not a member of itself |
| Authority facts | CCJ(facts above including version keymaker-authority-facts/1) |
| Binding body | CCJ({type:"keymaker-combined-body/3",schema_version:3,authority:A,payload:Ref}); A is Root with **only binding_commit and root_digest removed** |
| Candidate root | CCJ({type:"keymaker-authority-candidate/1",body_digest:D(binding-body-preimage)}) |
| Authority transaction | CCJ({type:"keymaker-authority-tx/1",base_root_digest:D|null,next_revision:N,candidate_root_digest:D}); same required PC2 identity recipe |
| Final root | CCJ(Root with **only root_digest removed**); includes keymaker-authority/2 and binding_commit; no outer wrapper is silently added |
| Activation attempt | CCJ(exact attempt below with only attempt_id, disposition and evidence_digest removed), including pc2-activation-attempt/1; unchanged A2 identity recipe |
| Hold | CCJ({type:"pc2-hold/1",kind:"activation"|"authority",origin_id:D}); unchanged A2 recipe |
| Logical root link | CCJ({type:"keymaker-authority-link/1",root_digest:D,transaction_revision:N,authority_incarnation:Token,withdrawal_counter:N,journal:{seq:N,hash:H},guard_digest:D,minimum_reader_schema:3,floor_epoch:N}) |

The binding body's H is binding_commit.digest. Prepare exact audit frames/tail
under audit serialization **before F**, with provider evidence obtained before
short locks. Binding_commit carries the reserved audit pair; its audit record
uses the existing allowed payload_digest and operation binding_commit. No new
audit field, operation literal or hash recipe: Q7's closed-optional rule in
[base §11](keymaker.md#11-audit-and-fail-closed-recovery) remains unchanged.
Audit frames cannot contain their own hash or the future final root hash.

Dependency DAG: immutable payload/inventories -> participant refs + facts ->
provenance/reservation -> A -> binding body -> candidate -> transaction ID ->
prepared audit hashes -> binding_commit -> final Root -> logical root link.
The link is retained by independent custody **after** root completion and before
dependent release; it is never inserted into its own root/body/reservation.
Reservation tickets use bounded future slots rather than future root hashes.
Exact authority intent binds old/new final roots and participants only after all
preimages are fixed. Never feed that intent ID/hash back into its own candidate.
Only exact retained bytes may recover an unknown transaction.

## 4. Aggregate reservation and manager obligation inventory

Closed reservation, <=65536 bytes:

```text
{version:"keymaker-reservation/1",base_root_digest:D|null,limit_bytes:268435456,
 groups:[{owner:"keymaker"|"manager",kind:Group,inventory_digest:D,
          materialized_bytes:Z,integrity_bytes:Z,reserved_bytes:Z,objects:Z}],
 total_bytes:Z,audit_records_reserved:8,manager_slots:Slots}
Slots = {slots:1,attempt_bytes:4096,hold_bytes:4096,guard_bytes:65536,
         recovery_bytes:65536}
```

There is exactly one sorted row for each of these (owner,kind) pairs, including
zero rows: keymaker installed, artifacts, recovery, staging, pending_proofs,
policy_history, root_history, migration_history, reservation_metadata;
manager attempts, holds, recovery, inventory, staging. No other pair is legal.
Each numeric byte/object value <=268435456; checked sums never exceed the safe
integer bound. total_bytes equals the sum of materialized_bytes+integrity_bytes+reserved_bytes
across **all fourteen rows**, <=268435456. Inventories bind the complete retained
files/counts/actual encoded bytes and separately charged verity-tree/descriptor bytes for that class, not just this transaction or
one owner. Root objects, metadata, attempts/holds/ledgers and duplicated old/new,
installed/staged, native intent/effect and migration copies all belong to one
of these rows. No file/copy belongs to two classes; no physical alias is used
to undercount distinct reserved simultaneous copies. No unlisted class is free.

For every new transition reserve actual installed size, each simultaneous new
recovery/staging copy, all existing artifacts and unmaterialized proof tickets
**before intent or live mutation**. In particular, the installed bound cannot
be reused as the proposed snapshot bound; reserve both native intent and effect
snapshots. Existing pending proof reservation is 4194304 bytes per association;
S2's current conservative copy/audit reservations are minimum obligations, never
replaced by a smaller PC2 estimate. Keep unused ticket bytes charged until their
owning protocol durably resolves/releases them. Audit bytes retain their separate
existing headroom protocol; eight max-size audit records cannot be double-spent.

A class inventory has exact codec
`{version:"keymaker-capacity-inventory/1",owner:"keymaker"|"manager",kind:Group,
objects:[{id:Text,bytes:N,integrity_bytes:Z}]}`, <=1048576 sorted unique IDs and
<=256 MiB under the aggregate. Its digest is the row inventory_digest; object
count, sum(bytes) and sum(integrity_bytes) equal that row. Empty classes still
have an explicit empty inventory digest. Integrity bytes charge the retained
verity tree/descriptor with a qualified conservative bound before enablement;
metadata overhead cannot be free space outside the budget. Future slots charge
all encoding and integrity growth. Actual filesystem allocation accounting and
all ownership/classification are G5 qualification, not facts from a cached sum.

Future slots have conservative upper bounds fixed before encoding, not their
own future hashes/actual final lengths; charge metadata's own worst-case size
as a prospective slot too. Thus reservation -> root is acyclic. Existing bytes
are actual protected stat/verified inventory values. New copy bounds include
maximal audit linkage and encoding expansion. Encoded object size must remain
within its ticket before writing; insufficient ticket stays held/refused.

The one manager slot is credit in this **same** aggregate, not a manager budget.
It reserves one attempt/hold and bounded guard/recovery staging before a manager
may consume it under F. Root-owned manager inventory accounts for all retained
attempt/hold/ledger history as materialized bytes; future history growth first
needs a new aggregate reservation/root transaction. A second pending activation
or exhausted slot refuses; no on-demand uncharged manager write. Root commit
cannot reclaim credit from an unresolved attempt. G5 must provide the reviewed
cross-owner reservation-consumption API, permissions and common transaction.

Manager inventory, <=65536 bytes:
`{version:"pc2-manager-inventory/1",revision:N,previous_digest:D|null,
 attempts_digest:D,holds_digest:D,recovery_digest:D,materialized_bytes:Z,
 objects:Z,slot_reservation:D}`. The three inventory digests bind the complete
append-only retained histories (not only live entries); slot_reservation refers
to an already committed reservation. Its later checkpoint may appear in a root;
it never refers to the future root that first carries it. Initial genesis uses
an explicitly authorized empty-history digest and no invented past identity.

## 5. Attempts, holds and root-owned recovery guard

Exact activation attempt, <=4096 bytes, is the unchanged A2 closed record:

```text
{version:"pc2-activation-attempt/1",attempt_id:D,manager_id:ID,effect_digest:D,
 target:{uid:UID,generation:Token,registration_number:N,master_epoch:Text,
         predecessor_generation:Token},owner:Text,
 provision_effect:{caller_uid:UID,caller_generation:Token,request_id:ID},ordinal:N,
 source:{transaction_revision:N,root_digest:D,authority_incarnation:Token,
         withdrawal_counter:N},prepared_tail:{seq:N,hash:H},active_record_hash:H,
 boot_id:Boot,instance_id:ID,disposition:"pending"|"absent"|"durable",
 evidence_digest:D|null}
```

Evidence is null exactly for pending. Manager ID, effect, ordinal, tuple, source,
tail and exact proposed active-record hash are immutable; source instance is
not a new attempt identity. New ordinal only after conclusive resolution of the
previous attempt, never another generation or OS mutation. Hold is exactly
`{type:"pc2-hold/1",kind:"activation"|"authority",origin_id:D}`; its digest is
stable through death/recovery. Disposition updates append linked retained records,
not a changed immutable identity. Boot/RPC instance/durable incarnation differ.

The root-owned **guard is an authoritative veto/consumption endpoint**, not an
eligibility projection or independent grant. Snapshot file guard.json is exactly:

```text
{version:"pc2-recovery-guard/1",revision:N,previous_digest:D|null,
 inventory:MetaRef,phase:"clear"|"open"|"resolved"|"release-prepared"|"released",
 holds:[{kind:"activation"|"authority",origin_id:D,hold_id:D}],
 attempt:MetaRef|null,resolution:MetaRef|null,release_prepared:MetaRef|null,
 released:MetaRef|null,source_root_digest:D}
```

Here MetaRef dispatch additionally admits pc2-manager-inventory/1,
pc2-activation-attempt/1 and pc2-recovery-record/1 in the named fields, with
<=65536/4096/8192 bytes respectively. At most one hold/attempt in this initial
profile; histories remain fully retained and charged. No active hold is omitted
because its original process died. Unknown unattributable markers stay closed;
never fabricate origin IDs. Inventory/guard ancestry from the independently
retained accepted baseline must be checked outside F; under F require that exact
prepared guard or the caller's one exact normal attempt extension. Any other
change forces fresh unlocked preparation. No unbounded history walk under F.

Recovery record, <=8192 bytes:
`{version:"pc2-recovery-record/1",recovery_id:ID,previous_digest:D|null,
 phase:"open"|"resolved"|"release-prepared"|"released",holds:[D],
 root_digest:D,journal:{seq:N,hash:H},outcome:"unknown"|"absent"|"durable",
 evidence_digest:D|null}`. One exact hold; unknown iff evidence null. Full
continuity/proof artifacts remain in sealed retained recovery_history. open
closes admission; exact resolution does not reopen it. Only full linked
release-prepared, owner cleanup+parent sync and released+last-directory sync
permit a released guard. Root recovery alone clears uncertainty. The guard's
atomic replacement and file/directory durability are part of that protocol;
a reader cannot infer release from readable bytes or missing marker/guard.
For clear, holds=[], all four attempt/resolution/release references are null.
For open, holds has one row, attempt is required iff kind=activation, and all
resolution/release references are null. Resolved adds resolution; release-prepared
adds release_prepared; released adds released, retaining the same hold and earlier
references. No phase may omit or null a required earlier link.
Initial clear is allowed only at independently authorized genesis with complete
empty histories; it is never a recovery transition or restart shortcut.

The original manager's own pending attempt is the one normal expected marker
while it holds F; its exact phase=open guard is permitted only with the original
live writer's unchanged normal-flight ownership and no prior error. Every other
pending/intent/recovery condition vetoes append. A clean original writer may
finish only that exact proven normal attempt through the linked durable finish
sequence; any error transfers uncertain cleanup to root recovery. A restarted
process cannot claim normal-flight ownership from matching IDs or bytes. G5
must accept/qualify these normal-finish and recovery transitions together.
After any possible write, keep unknown write vs known durable append/uncertain
cleanup distinct. Expiry, death, lost reply or marker unlink never means abort.
Before durable consumption disconnect/restart invalidates observation; completion
of the same consumed attempt after source death remains subject to the OPEN
joint absorption/correlation decision, not granted by these encodings.

## 6. Exact manager read set under F

F_auth is the stable protected authority lock, **different from F_pkg** native
package exclusion. Manager acquires effects -> exclusive gate -> exclusive data
-> F_auth; Keymaker source gate/data -> C_Store -> C_enrollment -> audit ->
F_auth. Terminal F has no C, Store, enrollment, audit, implicit file/database
lock, RPC, provider, inventory/account tool or service/operator wait. Parent
releases D before qualifier launch/wait; child acquires independent D under
continuous F_pkg/B_pkg/W/root-writer exclusion. These formats do not relax A3c's
two boundaries or allow network work while a required lease is held.

All directory descriptors, F identity and independent prepared continuity have
already been authenticated outside the short window. The following exact set
is the **only** metadata byte read set; at most 24 regular files, at most
2097152 bytes of file contents, plus ten fixed-size verity measurements and
bounded fstat results. Files have their per-object caps as well as the total.
Any extra reference/file, open-ended directory scan or over-cap length refuses
before unbounded allocation/read. Read cap+1 to distinguish oversize from EOF;
no truncation into acceptance. F itself is not a metadata payload.

| Read | Maximum bytes / number | Required final check |
| --- | --- | --- |
| Final authority.json Root | 1048576 / 1 | Exact closed root/digest, prepared T/owner/effect, admitted+provisioned, complete facts, counter/incarnation/epoch/instance and root ancestry; no prior-root fallback |
| participants, provenance, reservation | 65536 each / 3 | Exact MetaRef bytes/digests/types; ten required roles; facts/participant linkage; complete fourteen-row aggregate; root/current installed identities agree |
| Root-owned guard.json and manager inventory | 65536 each / 2 | Current protected guard and inventory match independently prepared head/baseline, all vetoes/credits; no missing-file means clear |
| Current attempt and linked resolution/release-prepared/released records | 4096 for attempt; 8192 each for up to 3 recovery records / <=4 | Exact IDs/linkage/hold/outcome, writer ownership and full release sequence; cap and phase unions even for null references |
| Protected floor/continuity anchor and authority intent endpoint | 8192 each / 2 | Floor 3, exact independently current root/link/guard and no unknown intent. Root-owned intent endpoint has an explicit clear record, never missing=clear |
| Ten participant files, opened/checked but not scanned | zero content bytes / 10 | fstat exact role/size/owner/mode/device/inode/single-link; FS_IOC_MEASURE_VERITY SHA256/32-byte digest equals Ref; never substitute ordinary digest or enabled flag |

This sums to <=1421312 content bytes (strictly below the 2 MiB total) and at most
22 content/participant files; 24 is a fixed defensive open-file ceiling, not
permission for two additional schemas. The manager reconstructs the combined
binding preimage from Root minus C/root_digest and its payload Ref, verifying
binding_commit.digest without scanning payload. Complete payload/history/policy
semantic validation was prepared against the exact measured immutable files;
changed root/guard/participant/independent anchor demands fresh unlocked
preparation, never reuse of an admitted cache. Unrelated revision growth is not
itself withdrawal, but may be conservatively refused for fresh preparation.

Under F establish the qualified local file/directory sync-consumption barrier
for the full linked recovery release before trusting released; no C or daemon
RPC. Opening/measuring an inode does not prove all disk blocks healthy or latest:
verity reads detect corrupted content when used; independent custody/exclusion
and full preparation remain mandatory. Integrity errors stay closed. Existing
reader <=250 ms, writer 1000 ms, send-start+2000 ms observation and native 2 s
budgets are original deadlines, never renewed. Qualify permissions and worst-case
latency of direct metadata/measurement/sync or keep PC2 closed. Cooperative
clocks cannot interrupt a stuck fsync; possible-write expiry retains real outcome.

Closed floor/continuity anchor, <=8192 bytes:
`{version:"keymaker-authority-floor/1",minimum_reader_schema:3,epoch:N,
 root_digest:D,logical_link_digest:D,guard_digest:D,authority_incarnation:Token,
 transaction_revision:N,withdrawal_counter:N,journal:{seq:N,hash:H}}`.
Its ownership/failure domain/currentness come from the independent custody
protocol, not this self-described file. Its logical link uses §3 exactly; the
link contains the fixed floor number/epoch,
not the future digest of this anchor containing that link. No floor/link cycle.

Closed intent endpoint, <=8192 bytes, is a discriminated union:
`{version:"keymaker-authority-intent/1",state:"clear",last_transaction:D}` or
`{version:"keymaker-authority-intent/1",state:"pending",transaction_id:D,
 base_root_digest:D|null,candidate_root_digest:D,new_root_digest:D,
 next_revision:N,participants_digest:D,reservation_digest:D}`.
Clear is durable exact cleanup of the last transaction, not fabricated on
startup. Original live writer may finish only its exact own intent under PC2;
no other holder bypasses pending because its hashes match.

## 7. Artifact dispatch and pending predicates

MessageCodec is exactly keymaker-msg-state/2 or keymaker-message-artifact/3.
message_dispatch has one sorted row per retained transaction, no missing,
duplicate or unrelated ID. Codec 2 dispatches **original** S2 bytes and hash
recipes, including original snapshot/migration decision, with no rewrapping or
recomputed historical references. Codec 3 artifacts are exactly
`{version:"keymaker-message-artifact/3",kind:"intent"|"candidate"|"resolution",
 body:Body}`; Body has the matching exact S2 member set, but base digest/version
refer to the combined binding-body domain. Artifacts <=256 MiB under aggregate
and existing tighter envelope/proof bounds; new wrapper is hashed in full.
Unknown codec/kind/version, a codec-2 hash interpreted as 3, corrupt/unresolved
reference or contradictory phase refuses. Candidate/resolution references keep
their recorded byte length/hash; no signing/reissue/result invention in recovery.

S2's pending certification predicate and PC2's global intent/attempt/recovery
hold are **distinct**, both retained and enforced. The new format does not
turn issued into active, clear pending, enable publication or permit T1 fallback.
A message-only offline reconciler cannot release a global hold. No bool/null
shortcut turns unknown into an empty inventory. Existing implementation only
accepts its S2 subset; future phases need their separate content/runtime gates.

## 8. One migration graph and atomic crash walk

The S1/S2 migration ordering is implemented only after content review:
validated legacy (untagged conceptual 1) -> exact closed schema 2 -> combined 3.
Existing valid schema 2 joins the same edge. One offline coordinator, one parent
intent and raised protected floor own the graph; no direct 1->3 skip, independent
second migration or intermediate authority. Preserve exact old/intermediate/new
bodies, decisions, message artifacts/results/pins/high-water/floors/obligations.
Unknown prior commits reconcile under their original protocol first. All audit
readers/recovery must support Q7's exact closed-optional schemas before serving;
floor 3 is not a reason to skip unknown audit members or rewrite old records. Stable
pending certification is retained through explicit dispatch, not silently aborted.

Migration state, <=8192 bytes, is exactly
`{version:"keymaker-migration/1",migration_id:ID,input_schema:1|2,
 phase:"legacy_validated"|"s2_staged"|"s2_committed"|"combined_staged"|
 "combined_committed"|"released",minimum_reader_schema:3,
 base_digest:D,s2_digest:H,combined_candidate_digest:D|null,
 parent_intent_digest:D}`. Combined digest is null before combined_staged only;
all other members are required. s2_digest identifies the exact planned
intermediate body, computed before any write, not inferred from staging later.
Existing-S2 starts at s2_committed with an exact base decision. Each state has a
paired vector; it is a valid **closed migration record**, never serving authority.

Before any live migration mutation, exclude serving/old/restored writers, reserve
all copies and durably record parent intent. Raise independent minimum floor 3
before any serving; a raised floor with legacy/intermediate bytes stays closed.
The authorized exact coordinator may resume its retained graph under that floor;
no normal floor-2 opener, floor rollback or old final root may restore service.
The current continuity anchor pins root/link/incarnation/counter/journal/guard;
equal readable root bytes do not defeat that independent floor. Floor 2 alone is
never PC2. Unknown format/preimage/floor versions refuse without mutation.

| Crash/error boundary | Exact required disposition |
| --- | --- |
| Before durable parent intent/no live writes | Prove stopped writers/no in-flight sync and old complete consistency; absence alone is not proof |
| Intent write/fsync/close/parent sync | Partial/unknown stays held; do not install live participants before proven durable intent |
| Floor raise, legacy->2 stage/install | Ordinary readers refuse old/intermediate bytes under floor 3; same coordinator resumes, never lower floor |
| Participant/audit/body write, sync, close, rename or directory sync | Preserve all exact old/new/reserved copies; no standalone snapshot commit or old-root fallback |
| Final root rename before directory sync | Root is not eligible; exact participant/audit/root durability must resolve first |
| Root durable, intent cleanup/unlink before parent sync | Known commit may have unknown cleanup; same hold/result retained, no repeated effect |
| Manager active write before fsync / durable append before receipt/marker-final sync | Distinguish unknown write from known append/uncertain cleanup; no duplicate attempt/effect or completed withdrawal |
| Recovery partial cleanup/released readable before final sync | Same linked hold persists; qualified sync barrier + exact release resolves once, not another recovery origin |

All eight PC2 runtime cases and nine KR/KI/KP rows remain **PENDING / NOT RUN**.
Golden fixtures below prove byte/preimage/pair integrity, not real-process races,
fs-verity availability, sync semantics, independent restore or a no-back-edge graph.

## 9. Golden vectors, limits and acceptance

[vectors/authority-root.json](../vectors/authority-root.json) records domain
preimages, expected digest/length and adjacent negative/positive control groups.
The offline [vector tool](../tools/vectors/main.go) checks these through
`go run ./tools/vectors/main.go -check`. Claims are scoped to fixture integrity:
no daemon/manager reader exists here, and expected negative verdicts are future
consumer conformance obligations rather than passing runtime tests.

Controls include a minimal root, an exactly byte-maximal root, every closed
migration state and valid attempt/hold/reservation/provenance/link preimages.
Pairs cover unknown/duplicate/alias members, wrong domain, truncation, oversized
field and total, floor rollback, old-root replay, out-of-set provenance and
nonaggregate reservation. No malformed positive is used as a control.
The maximal root fills its 1 MiB cap; not every independent field/count maximum
can fit simultaneously. Its lossless gzip representation, decompressed length and SHA256 are published
so both consumers can reproduce its exact bytes without a platform installation.

OPEN: architect acceptance of version-2/root/member/domain/read-set and bounded
immutable primitive, guard/inventory schemas and migration; reviewer then curator
content approval; G5 cross-owner coordinator/API/all-writer accounting; platform
provisioning/latency; observer auth; observation absorption; independent restore
custody under honest A; indefinite withdrawal completion. See
[UNRESOLVED](../UNRESOLVED_QUESTIONS.md#pc2-combined-format-g4-draft).
This document adds no purpose, credential, native method, public code, audit
member, budget or runtime activation.
