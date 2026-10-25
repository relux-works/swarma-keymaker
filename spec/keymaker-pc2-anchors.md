# PC2 joint anchors: pre-A2 debit and carried spend lineage

Status: Keymaker-side proposal for joint manager review; **not an executable
credit, debit, recovery or replenishment protocol**. The existing G4 bytes can
commit a completed historical spend checkpoint. They do **not** currently
specify the live pre-A2 index-to-guard handoff or the atomic spent-to-fresh
replacement. Both remain integration blockers. No closed G4 member, new guard
phase, HistoryRef kind, extra final-window file or implementation is added here.

## 1. Baseline and decision

The [landed census][k-census] supplies the class/copy/ticket rules, CC-C01–CC-C18
and CC-V1–CC-V9. This document extends those identifiers. Sources are pinned to
Keymaker `4b9aebbaa74598b95ff0b071ae5218a7aa89c57c` and manager
`730370b38f3eb006311b7e3efcbf80f4d4d0518d` (fetched main). In the latter history,
Q2 codecs landed at `a148213`, protected-store work through `b8fa8c0`, and Q3
journal lifetime at `fe16b8c`. Their presence does not open production PC2.

The manager [storage contract][m-storage] and [production opener][m-open]
explicitly leave committed funding, pre-A2 debit and folding unavailable.
Its closed [owner transition][m-index-codec] supports genesis/associate/install,
not debit, bind-A2, retire or replace. Its fixture funding is not a production
Qn receipt. The journal's [lifetime][m-lifetime] publishes the native pending
marker before gate/data/F_auth; the future manager must commit the debit
**before entering that path**, not add funding inside its guard callback.
The journal performs no autonomous credit issuance, A2 or hold creation;
those require the manager's explicit prepared operation and prior debit.

**G4-sufficiency verdict:** historical commitment is expressible (§4.1);
end-to-end live spend lineage is **not established by the existing contract**.
This is not a claim that SHA-256 cannot commit these bytes. The missing edge is
an authoritative, current commitment to the *unfolded inventory-class index*
at every debit/retirement transition, reducible to the existing final anchors.
A bounded hash of a missing relation, a larger revision or a matching process
capability does not supply that edge. §5 gives the required joint decision.
No new closed G4 field has been proved unavoidable; inventing one here would
skip that decision.

## 2. Exact candidate debit representation

### 2.1 Owner, storage and bounds

Propose a versioned **manager owner-index metadata** protocol, replacing or
extending that owner's internal transition format after joint acceptance.
These are candidate CCJ-1 preimages, **not objects accepted by today's
pc2store or G4 dispatch**. They live only in the existing protected
`manager/inventory` metadata population; staging uses `manager/staging`.
The root manager/coordinator is the sole publisher. Keymaker verifies and
seals its authenticated census, never writes the manager's index or restores
credit from its local counter. The journal consumes only a prepared operation.

Use G4's D, ID, Token, Boot, Text, N and Z domains, canonical no-LF bytes,
closed required members and depth <=16. Proposed index records are <=65536
bytes, including all bindings; retain <=1024 transitions including genesis
and <=256 distinct copy allocations per admitted frontier. Reject either
count or byte overflow before creating an output. These conservative candidate
bounds follow the existing [store envelope][m-index-codec]; they do not enlarge
its funding or authorize automatic compaction/reset at exhaustion.

Define the following exact candidate nested records (all members required):

```text
Base = {root_digest:D,logical_link_digest:D,guard_digest:D,
        manager_revision:N,manager_digest:D,authority_incarnation:Token,
        withdrawal_counter:N,floor_epoch:N,index_sequence:Z,index_digest:D}
Ticket = {q:D,source_owner:"keymaker"|"manager",source_kind:Group,
          role:Group,ordinal:N,id:Text,bytes:N,integrity_bytes:Z}
Copy = {copy_id:ID,disposition_version:N,directory_role:Text,
        relative_name:Text,content_digest:D,bytes:N,integrity_bytes:Z}
Debit = {version:"pc2-pre-a2-debit-proposal/1",sequence:N,previous_digest:D,
         deployment_id:ID,manager_id:ID,base:Base,ticket:Ticket,
         effect_digest:D,activation_ordinal:N,
         target:{uid:UID,generation:Token,registration_number:N,
                 master_epoch:Text,predecessor_generation:Token},
         owner:Text,
         provision_effect:{caller_uid:UID,caller_generation:Token,request_id:ID},
         writer:{boot_id:Boot,instance_id:ID},copy:Copy}
```

`Group` and owner/group pairs are exactly the census/G4 fourteen-class catalog;
`source_kind` belongs to `source_owner`, `role` to manager for this proposal.
A debit for a native Keymaker-owned copy needs its owner's separately accepted
index producer, never the manager claiming that directory. The original
committed Qn digest is `ticket.q`; it is **never** the new checkpoint's digest.
`previous_digest` names the full preceding accepted metadata record. Sequence
increments exactly once, without forks/wrap. The original independently admitted
genesis supplies the first predecessor, not an empty/lost local directory.
`base` describes an already completed baseline, not the future root sealing
this record. Its index head precedes this record; neither points to itself.

`effect_digest` hashes the original canonical owner-authenticated immutable
intent/reservation bytes, not a mutable progress object. The target, provision
effect, owner and activation ordinal must equal those original bytes and the
retained per-effect history. Changing any binding is a different, unauthorized
request, not retry. Writer identity attributes the original use; it is not a
lease or permission to resume after restart. Deployment mapping and sole-writer
exclusion are external authenticated inputs, not facts granted by these strings.

`ticket.id` is the existing 70-byte identity:

```text
pc2t1: + H(CCJ(["pc2-ticket-id/1",ticket.q,ticket.source_owner,
                ticket.source_kind,ticket.role,ticket.ordinal]))
```

It must select a disjoint partition of an **already committed** aggregate
allocation. The unhashed source bound and destination remain available for
validation. An auxiliary metadata-to-manager transfer uses the census's exact
cross-owner source, not a second manager allocation. Fixed attempt/hold/guard/
recovery subtickets need the same jointly admitted partition; the fixture's
auxiliary-ticket constructor alone cannot authorize all of them. Ticket ordinal
and activation ordinal are distinct; neither is inferred from the other.

`copy` binds exact proposed native bytes and the checked prospective relative
location under admitted directory descriptors. Require Text bounds, no absolute,
empty, dot/dot-dot, backslash or symlink components. Pending-marker contents and
staging name must be fixed before debit; a later time/random name needs a new
explicit funded binding, not a wildcard. No inode is claimed before creation.
An install transition subsequently records actual device/inode/mount and
checks bytes, location and copy lineage against this debit. Same-inode rename
is one conversion; a second inode needs its own copy/ticket. An append to an
existing native file needs a separately accepted byte-range/growth binding;
this Copy schema covers new physical copies only, not arbitrary append effects.

Require `copy.bytes <= ticket.bytes` and
`copy.integrity_bytes <= ticket.integrity_bytes`, as well as the combined bound;
positive G4 content length
and the qualified filesystem envelope apply. Debit/index/head/guard versions,
parent allocation and simultaneous metadata outputs have their **own prior**
prospective bounds. A debit cannot pay for writing itself retroactively.
Until the joint producer can pre-bind the journal's marker contents/name,
its current internally generated marker is not an implementation of this Copy
contract. Changing that preparation boundary needs manager/journal review.

### 2.2 Debit, attribution and later A2

Define `d = D(CCJ(Debit))`; no `debit_id` member hashes itself. The immutable
spend identity is `(deployment_id, original Qn, ticket.id)`, with exact effect,
activation ordinal and copy binding. It survives every later Q/checkpoint.
Repeated identical bytes return the original debit after durability/currentness
checks; different bytes for that identity refuse, retaining the first debt.

A durable debit is an irreversible attribution of its ticket, **not** A2,
observation absorption, proof of a native write or permission to append active.
Ticket conservation, for bound `B = ticket.bytes + ticket.integrity_bytes`,
materialized content x and integrity i:

```text
before debit:               reserved = B; materialized = 0
attributed, no file yet:     reserved = B; materialized = 0; ticket unavailable
after one copy install:     reserved = B-x-i; materialized+integrity = x+i
                            B = (B-x-i) + x + i, with B-x-i >= 0
```

No second destination charge is added on transfer. The census examples remain
`30240 = 10240+16384+3616` and `69632 = 53248+16384`. Residual remains charged;
debit/cancellation alone releases nothing. Copy disappearance is not recredit.

Once the genuine prepared tail and proposed active-record hash exist, propose
an immutable **index relation**, with this exact preimage:

```text
{version:"pc2-debit-a2-binding-proposal/1",sequence:N,previous_digest:D,
 debit_digest:D,attempt_digest:D,attempt_id:D,hold_id:D}
```

Resolve and validate the full original Debit and A2 record outside F. Their
manager/effect/target/owner/provision-effect/activation-ordinal bindings agree;
A2 source is the independently current root of that preparation, with proven
ancestry from Debit.base, not necessarily the old source root byte-for-byte.
Verify its positive prepared tail and exact active hash, recompute unchanged
A2 identity and `pc2-hold/1` activation origin, then check the one normal
A2/hold/open-guard extension before active write. `attempt_digest` binds the
full immutable pending record, `attempt_id` its unchanged identity preimage.
Prepare this relation outside F; publish it retrospectively after the journal
lifetime, once the exact actual A2 consumption is proved, and seal it in a later
checkpoint. The relation alone never asserts successful consumption. Actual A2
consumption still occurs only under the original journal-owned F_auth lifetime.
No index lock, history scan or additional index read is added there. Requiring
this A2-source-root-bearing relation to be inside that very source root would
create a cycle and is forbidden. Neither this relation nor a Debit hash is an
A2/authority hold origin. Its retrospective publication/currentness semantics
remain part of the §5 decision, not a current owner-index operation.

### 2.3 Publication and pre-A2 recovery

Required future order, conditional on §5's missing anchor decision:

1. Outside short locks authenticate original committed Qn, accepted Base,
   finite metadata frontier, sole writer and exact ticket/copy/effect bindings.
   Serialize against all manager/root writers; prepare common transaction inputs
   outside F. The owner-index lock must never be acquired under terminal F.
2. Publish debit record and retained head by no-replace installation with
   write/file-sync/checked-close, source/destination parent sync and exact
   predecessor/identity recheck. Replace only the designated mutable head;
   sync/read back before reporting local persistence. Preserve every uncertain
   output. Follow the [existing publication discipline][m-publication], without
   claiming its associate/install implementation already supports Debit.
3. Establish the jointly accepted current anchor through root/guard/inventory
   (§§4–5), including custody acknowledgement and required barriers. **Local
   durable index head alone does not authorize marker/intent/copy creation.**
   A lost acknowledgement keeps this ticket occupied/unknown; exact reconciliation
   must prove the same debit, not allocate a replacement.
4. Only then may the original authorized manager execute the exact native
   preparation. The journal lifetime starts after that explicit prior debit;
   its marker publication is not a credit-producing callback. Before any
   active append, final-check and durably bind genuine A2/hold/open guard.

A crash before A2 can leave a debit and native marker without an activation
attempt. Authorized root reconciliation must stop the old/in-flight writer,
verify both owner indices, exact native journal/effect state and the original
debit, then retain a conclusively classified **pre-A2** outcome. Proposed exact
metadata outcome relation:

```text
{version:"pc2-pre-a2-outcome-proposal/1",sequence:N,previous_digest:D,
 debit_digest:D,outcome:"no-active-write",evidence_digest:D}
```

It is allowed only with affirmative evidence that active write never began;
missing A2/marker is insufficient. If active may have been written or attribution
is incomplete, refuse this relation, retain unknown debt and require the joint
recovery owner. Do not encode it as a G4 recovery record with an empty/made-up
hold. A real common authority repair transaction may use its own genuine
`keymaker-authority-tx/1` origin once its candidate is fixed; it does not
retroactively originate the Debit or turn it into A2. Cleanup, native evidence,
parent barriers and subsequent common fold retain that debt/history. Only §4.3's
joint retirement can replace credit. No currently available API performs this
pre-A2 reconciliation; until accepted, remain unavailable with retained debt.

## 3. Exact baseline and carried state

Prepare old baseline `B_old = (R_old, L_old, G_old, M_old, Q_old, P_old, F_old)`:
exact final root, logical link, guard, manager head, reservation, ten-role
participant set and independent floor. Include the independently accepted
index sequence/digest and full ticket partitions used by §2. Underlying values
are exact canonical bytes or exact Ref/MetaRef bindings, not revision numbers
alone. Prove genesis-to-current ancestry, journal floors, native outcomes,
complete physical closure and old-writer exclusion outside F.

For each original allocation replay the entire accepted transition chain. A
checkpoint's new reservation digest changes the *container*, never the original
allocation identity. Candidate fold relation inside manager inventory metadata:

```text
{version:"pc2-spend-fold-proposal/1",sequence:N,previous_digest:D,
 old_base:Base,original_q:D,ticket_id:Text,debit_digest:D,
 consumed_bytes:Z,residual_bytes:Z,integrity_bytes:Z,
 disposition:"carried"|"retire-prepared",
 evidence_digest:D}
```

Each relation covers one original ticket; original Debit supplies B and copy.
`consumed_bytes` is charged content, `integrity_bytes` charged integrity and
`residual_bytes` the still-reserved balance: their checked sum equals the original
ticket bound. Metadata copies use separate tickets, never these bytes again.
`carried` preserves occupied/spent state even when conclusive native release is
not yet available; it is not serving authority. `retire-prepared` additionally
requires conclusive outcome, all cleanup/release barriers and all-writer
exclusion, but grants **zero fresh credit**. An omitted original allocation,
duplicate ticket or conflicting outcome makes the entire fold unavailable.
There is no field naming the future Q, root or final receipt in this preimage.

## 4. Acyclic commitments, retirement and final checks

### 4.1 What existing G4 can seal

For a **completed prior** index cut, K is its terminal full accepted record
(Debit, binding, outcome or fold), not an invented compacted summary. Replay
all exact predecessors to the admitted genesis; retain every record and head
copy, with no omission or history truncation. Format migration from existing
associate/install records needs joint acceptance of that retained domain chain;
none of these candidate tags is accepted by the current store. Let `sid(K)` be the
census's existing `pc2o1:` storage-ID recipe, with `content_digest=D(CCJ(K))`,
manager/inventory role, admitted location/copy/version and exact measured size.
The unhashed tuple is retained in the owner index; no digest-only alias proof.
Let I be an existing G4 `keymaker-capacity-inventory/1` of manager/inventory
containing `{id:sid(K),bytes:len(CCJ(K)),integrity_bytes:qualified_cost}` among
**all** retained physical metadata entries at that census cut. Then:

```text
old committed Q + old accepted index head + original effect/copy
  -> Debit / bind-A2 / outcome / fold history -> completed checkpoint K
  -> sid(K) with K's content digest -> complete class inventory I
  -> Q_next.groups[manager,inventory].inventory_digest = D(CCJ(I))
  -> R_next.reservation MetaRef -> combined binding body -> candidate
  -> authority transaction ID -> prepared audit C -> final R_next
  -> logical link L_next binding R_next and exact G_next -> floor F_next
```

Other class inventories bind the physical native copies; `participants` binds
the ten measured roles, including the sealed manager head and recovery wrapper.
`manager_baseline` identifies that exact head revision/digest; it is not itself
an index commitment. Q_next.base_root_digest and R_next.previous_root_digest
both bind R_old. Every pointer above has an already fixed preimage. Prepared
audit C precedes final R_next; L_next is retained afterwards and never fed into
R_next/Q_next. A post-commit receipt may name R_next, but cannot be inserted into
that same root's inputs. Thus topological order proves no self/future-root cycle.

I and Q_next do not list their **own future digests**, current-head output or
future receipt as measured input. Those new physical copies consume disjoint
prospective metadata slots, exactly as the [census self-accounting rule][k-lag]
and [manager frontier][m-frontier] require. Prior completed versions remain
listed and charged. Complete current funded-delta evidence is still needed for
these prospective outputs; a lagged checkpoint alone is not a live commitment.
K cannot include I/Q_next/R_next in its own hash, and I cannot include sid(I).

For carry, each ticket's accounted B is identical across old/new census:
`B = consumed_content + charged_integrity + reserved_residual`. All other retained
metadata/native versions are added by their own prior tickets. Fold applies the
old delta once, without adding B again or freeing its residual. A new Q digest
with `manager_slots.slots=1` cannot make that carried ticket unspent. Budget and
slot ownership are separate checks; neither can be inferred from the other.

### 4.2 The edge that is missing today

The historical chain above does not prove a current unfurled index suffix.
[Manager inventory][k-manager] has exactly its nine members. `attempts_digest`,
`holds_digest`, `recovery_digest` bind those complete three class histories under
the census proposal; the spend index belongs to **inventory**, excluded from
those head summary counters. `slot_reservation` names an already committed Q;
`previous_digest` links heads, not arbitrary new index bytes. [Guard][k-guard]
contains only that head reference, actual holds/attempt and release records.
Before genuine A2 there is no activation hold/attempt to put there. Clear is
not an occupancy proof or a permitted restart/recovery state. Non-clear phases
require one genuine hold and the specified link union.

Counterexample: keep R_old, Q_old and its lagged inventory-class checkpoint,
then write two different pre-A2 suffixes allocating the same ticket to different
native copies. Without a specified live anchor transition, the fixed G4 files
can remain identical. A generic reader cannot distinguish the suffixes from
those files. Honest sole-writer exclusion prevents concurrent legitimate
publication but does not define which suffix is current after a lost reply or
coherent restore; independent custody needs an accepted binding, not a local
index supplied by the claimant. The required property is not implied by a
self-consistent hash graph.

Changing `attempts_digest` to mean the index, embedding Debit in a HistoryRef
ID, using an authority hold for the Debit hash, or quietly admitting an index-only
normal extension changes an existing semantic contract. None is proposed as an
implementation shortcut. Only the original live writer's **one exact A2 normal
extension** is admitted today. The two unused defensive file slots are not
permission to read the index under F. No guard member or phase is added here.

### 4.3 Old-to-new baseline and atomic retire/replace

Required future replacement, conditional on the decision in §5:

1. Establish B_old and original spend ancestry outside F, retain every old
   allocation and consume actual recovery release barriers. Exclude old/restored
   writers, including in-flight sync, before declaring retire-prepared. Pre-A2
   evidence uses §2.3, never an invented released activation hold.
2. Prepare a common transaction with K and the exact conserved old debt,
   complete class inventories, prospective metadata and new-slot bounds.
   A retire-prepared relation names **old** Q and grants nothing. This is the
   separate occupied resolve/fold path, not the fresh calculator with a false
   zero count: [occupied preflight still refuses][k-calculator].
3. The sole common transaction must make old-credit retirement and admission
   of exactly one explicitly new allocation inseparable at its qualified final
   authority point. Existing root intent binds old/new final roots, participants
   and reservation; the floor/link must become independently current, and all
   cleanup/guard release obligations must hold before service. Partial root,
   guard, inventory, intent or floor publication grants **neither** old nor new
   credit. Multi-file atomicity is a transaction/recovery property, not a claim
   that one rename updates all these files. Current G4 names the endpoints but
   does not specify the live spend switch that proves this step.
4. B_new is the exact R_next/L_next/G_next/M_next/Q_next/participants/floor plus
   the accepted index cutoff/current funded delta. Prove `previous` ancestry and
   original spend preserved; after commit, old ticket is permanently retired,
   retained physical bytes remain charged, and only the explicitly committed
   replacement is unspent. No unrelated Q/hash change is a replacement event.
5. Lost acknowledgement: retain old/new candidate bytes and the same transaction
   ID; neither owner recredits from its local result. Obtain independently
   current exact-head evidence and replay required barriers outside serving
   admission. If incomplete, remain closed. If committed, return that original
   replacement result once, never mint a second slot on retry.
6. An old writer fails current root/guard/inventory/floor comparisons and cannot
   use old credit. A restored writer additionally fails independently retained
   currentness/exclusion even if its entire local tree hashes consistently.
   Matching IDs do not restore normal-flight ownership. If an old privileged
   writer can still publish, replacement remains forbidden; advisory flock and
   local high-water alone cannot meet this condition.

Retirement releases only the resolved original residual under the accepted
common transaction. New reservation includes every retained byte, integrity
cost and new prospective bound under 268435456; it does not evict history or
borrow an exhausted recovery envelope. Until the missing switch is specified,
these are acceptance conditions, not an available retire/replace API.

### 4.4 Outside F versus inside F

Outside F_auth: full bounded history/ancestry and byte validation, both owner
indices, native outcomes, physical aliases, ticket arithmetic, Q commitment,
K/I proofs, prepared audit/provider evidence, independent currentness, deployment
mapping, installer rights, old-writer exclusion and original observation
correlation. Any suffix/head change invalidates preparation. Keep process-local
single-use preparations bound to the exact root/guard/heads and writer lifetime;
pointer aliases share one use, while value clones must refuse.

Inside F_auth: only the [existing exact set][k-read-set], with authenticated
descriptors prepared outside F: Root; participants/provenance/reservation;
guard and manager head; attempt plus at most three recovery records;
floor and intent; ten participant fstat/verity checks, with zero participant
content scanning. Match exact prepared bytes/digests/refs, root/link/floor,
all vetoes, ticket ownership and only the one allowed original A2 delta. Apply
direct qualified release-sync consumption. Any mixed, stale, unknown or changed
anchor refuses and requires fresh unlocked preparation. A missing index-binding
edge cannot be repaired inside this window.

Maximum file count is `1+3+2+4+2+10 = 22`. Maximum content bytes are
`1048576 + 3*65536 + 2*65536 + 4096 + 3*8192 + 2*8192 = 1421312`, below
24 files / 2097152 bytes. There is no index file, RPC, sidecar authority,
provider, owner-index lock or history walk under F. F_auth remains distinct
from F_pkg; original 250 ms / 1000 ms / send-start+2000 ms and native 2 s
budgets are not restarted. A privileged sync/latency profile still needs
qualification; this proposal does not run it.

## 5. Joint contract decision before code

Both owners must accept the exact index protocol, anchored cutoff/current-delta
semantics, authority point and recovery proof, then publish matching contract
amendments and vectors. Options are:

| Option | What must be decided | Assessment / safe default |
|---|---|---|
| A — serialize through common roots, preserve G4 bytes | Seal each attributed debit/checkpoint through the historical chain before native creation; define a finite prospective metadata delta, how its exact currentness is anchored, the occupied carry protocol and an all-or-nothing retirement/replacement rooted in existing intent/floor/guard. Prove this still obeys the single A2 normal-extension rule and recovery unions. | Preferred first design to evaluate because it reuses existing commitments. **Not accepted or demonstrated here**: repeating a root transaction without proving its post-root metadata suffix does not close the edge. Refuse if a finite acyclic cut cannot cover it. |
| B — explicitly version the joint format | If A cannot express a current spend cut, jointly revise the closed manager/root/guard commitment contract to authenticate it, with new version/floor, bounded byte accounting, migration and the same final read set. Select exact location/preimage only in that joint decision. | Required alternative before code; no member name, optional addition, overloaded digest or extra file is invented here. Existing readers must refuse the new version. |
| C — local index or additional under-F proof | Trust a sidecar/new RPC, walk history, read an additional index file, reset the slot on finish or reinterpret a folded Q as fresh. | Reject: violates the fixed final set, currentness or once-only credit contract. |

Recommendation: jointly resolve A with an exact finite cut and independent
currentness proof; if either owner cannot demonstrate it, select B explicitly.
Until then neither pre-A2 native creation nor carried-credit replenishment is
admitted by this proposal. End-to-end **G4 sufficiency remains negative at the
present contract**, even though its historical hashing capacity is adequate.

## 6. Named crash cuts extending the census

Each cut includes before/after write, file sync, checked close, rename, each
source/destination/ancestor directory sync and readback, as applicable. These
are future acceptance cases, not executed power-loss evidence.

| Cut | Required retained state and refusal |
|---|---|
| CC-C19: debit validation, before first metadata output | Proven no new output: no native creation; original committed bounds remain reserved. No interpretation as a successful debit. |
| CC-C20: debit record/head partial, immutable install or mutable-head replacement | Retain actual bytes and original frontier/ticket; unknown suffix closes admission. Never select highest sequence or overwrite an immutable branch. |
| CC-C21: local debit durable, anchor transition absent/partial | Ticket occupied/unknown; no marker/intent/copy. Local durable head is not committed spend authority. |
| CC-C22: exact anchored debit, acknowledgement lost, native creation not begun | Reconcile same d and current baseline/barriers; no second debit, allocation or A2. No native work on unproven acknowledgement. |
| CC-C23: native temporary/marker/intent/copy created, A2 absent | Retain attributed debt/native bytes; stop original writer. Prove no-active-write outside F or stay unknown. No synthetic hold/recovery record. |
| CC-C24: real A2/hold/open guard partial, or later index relation incomplete | Same original ticket and A2 identity retained; veto active until full exact normal extension is durable. Original writer only; otherwise root recovery. |
| CC-C25: pre-A2 outcome proven, cleanup or parent barrier incomplete | No-active proof alone does not release credit. Retain debt; retry original cleanup under authorized exclusion. |
| CC-C26: K/I/Q_next staged or root intent pending before final authority | Old credit stays spent/occupied; replacement unavailable. No omission of prospective metadata or assumed root completion. |
| CC-C27: final root visible, floor/link/guard/cleanup incomplete or custody reply lost | Both credit admissions closed. Recover exact transaction and consume missing barriers; no rollback/retry-mint from visibility. |
| CC-C28: retirement/replacement committed, success reply lost | Return original exact committed replacement only after independent currentness and sync proof. One new allocation, old permanently retired. |
| CC-C29: old writer or coherent restored old owner tree resumes after fold | Reject stale baseline and normal-flight ownership; prevent publication using qualified exclusion. Local matching hashes/IDs never recredit. |
| CC-C30: any debit/fold/recovery metadata frontier or aggregate exhausted | Retain all actual/uncertain debt, no output beyond funded envelope, no force cleanup/top-up, no borrowed future root or fresh calculator bypass. |

## 7. Future vector pairs and side responsibilities

All CC-V10–CC-V17 below are **PENDING**, not named existing tests, passing gates
or killed mutants. They extend CC-V1–CC-V9. Each negative asserts the specific
refusal and retained accounting/no duplicate effect; a nearby positive must
succeed with genuine accepted authority. Repeat each publication case across
CC-C19–CC-C30 as applicable in isolated qualified fixtures.

| Pair | Negative / forbidden effect | Positive control | Keymaker supplies / manager supplies |
|---|---|---|---|
| CC-V10 DebitBindings | Change Qn, ticket source/ordinal, effect, activation ordinal, target, copy ID/location/bytes or original intent; reject before native output, retain original allocation. | One exact prior committed allocation and canonical Debit, conservation of B. | Common-Q/partition and original-root fixtures / original intent, proposed debit/copy/index fixtures and actual native-output trace. |
| CC-V11 PreA2Publication | Partial/lost-ack index or unanchored suffix used to create marker/intent; reject, preserve all partial bytes/debt, no active. | Same durable/current anchored d permits only its exact original native preparation. | Root/intent/floor/custody cuts / record/head/file/parent cuts and pre-entry journal instrumentation. |
| CC-V12 NoInventedOrigin | Missing A2, forged Debit-origin activation/authority hold or made-up tail; reject attempted G4 recovery, no release. | Proven pre-A2 no-active outcome retained without A2; separate real authority repair TX uses unchanged origin recipe. | Genuine candidate/TX/hold and wrong-domain fixtures / native no-write evidence, stopped-writer proof and later genuine A2 linkage. |
| CC-V13 CarryConservation | Folded Q treated as fresh, erased original ticket, double-counted destination or lost residual; reject and leave admission closed. | Original B conserved through exact K/I/Q_next ancestry, once-only conversion with all retained copies charged. | Fourteen-row reservations/root DAG and arithmetic / complete five-class/index/copy history and materialization traces. |
| CC-V14 FiniteAcyclicCut | K references its future Q/root, I includes sid(I), audit names future final root, or lagged checkpoint omits current delta; refuse preparation. | Fixed old-Q K -> I -> Q_next -> body -> candidate -> TX -> audit C -> R -> L -> floor, with separately funded current delta. | Exact canonical hash/preimage fixtures / index frontier and complete delta/physical-closure proof; both independently compute expected hashes. |
| CC-V15 AtomicReplace | Partial final authority or lost reply permits old/new consumption together or two fresh grants; refuse both until exact current commit established. | One original retire/replace transaction recovers idempotently to one replacement and retained old history. | Root/intent/guard/floor and independent receipt cuts / sole index writer, original allocation/replay and native release traces. |
| CC-V16 OldRestoredWriter | Old process, co-restored index/root or fork tries to publish/consume; reject with retained debt, no refreshed observation or resumed normal ownership. | Fresh authorized reconciliation proves latest chain and excludes old/in-flight writers before same-transaction recovery. | Current independent floor/link/custody evidence / cross-process publication and writer-exclusion/restore fixtures. |
| CC-V17 FinalSetAndBudget | Add index read/RPC/history walk, wrong lock order, reset deadline, exhausted metadata or false zero occupied count; refuse without native write/new credit. | Accepted preparation matches exact 22-file anchors, original budgets and funded frontier; original A2 extension only. | Final root/reference and capacity cases / syscall/lock/time traces, journal all-exit outcomes and direct release consumption. |

Future narrowing mutations: remove respectively one immutable binding (V10),
the anchored-debit-before-native check (V11), origin-domain validation (V12),
original-ticket carry check (V13), DAG/current-delta check (V14), common commit
switch (V15), independent currentness/exclusion check (V16) or final-set/budget
check (V17). Each needs its own named failing executable test when implemented;
none is claimed killed by this spec review. Two codecs agreeing is not an oracle:
expected bytes and verdicts must derive independently from accepted contracts.

## 8. Owner decisions and review limits

| Owner item | Required decision/evidence | Safe default |
|---|---|---|
| O-A Joint format/lifecycle authority | Both capacity owners and contract curator select §5 A or B, accept exact debit/index preimages, current cut, retirement switch and any required floor/migration. | Both anchors remain blocked; no silent G4 member or normal-extension change. |
| O-B Deployment and recovery owner | Designate sole publisher/installer and authenticated coordinator, protected role-to-directory mapping, stop/start privileges and exclusion of old/restored/in-flight writers. | No new native work or replenishment; advisory exclusion alone is insufficient. |
| O-C Independent custody owner | Admit failure domain, per-transaction latestness, exact root/link/guard/index-cut receipt and lost-ack recovery, including existing C0 authority. | Coherent restore is unqualified; hashes, fixture baseline and local backup do not authorize credit. |
| O-D Storage and qualification owner | Accept finite metadata/recovery envelope, filesystem/verity/allocation accounting, zero-length interrupted outputs, sync privileges and original latency bounds on an isolated target. | Retain unknown/exhausted debt indefinitely; no padding, eviction, budget increase, emergency file or full-host destructive experiment. |

O-B–O-D require deployment-owner decisions; O-A first needs a joint technical
contract, escalating format/admission tradeoffs to the owner if necessary.
These preserve the census's O1–O7 defaults, including unresolved source-death
observation absorption; no fresh authority is inferred from finishing old work.

This is a docs-only proposal. Runtime property suites, native crash/restore and
privilege/latency qualification, production debit/credit APIs and all vectors
remain unrun/PENDING. The brief has no attack-surface table; that is a handoff
brief gap, not a claim of executable surface coverage. Review scope is the two
anchors, candidate preimages, arithmetic, counterexamples and source linkage.
Out of scope by the spec-only acceptance boundary: implementation of a producer,
new G4 dispatch/floor, C0 custody, observation-correlation decisions and qualified
native fault injection. No existing reviewer test or runtime file is changed.

[k-census]: https://github.com/relux-works/swarma-keymaker/blob/4b9aebbaa74598b95ff0b071ae5218a7aa89c57c/spec/keymaker-pc2-census.md#L381
[k-lag]: https://github.com/relux-works/swarma-keymaker/blob/4b9aebbaa74598b95ff0b071ae5218a7aa89c57c/spec/keymaker-pc2-census.md#L218
[k-manager]: https://github.com/relux-works/swarma-keymaker/blob/4b9aebbaa74598b95ff0b071ae5218a7aa89c57c/spec/keymaker-authority-root.md#L341
[k-guard]: https://github.com/relux-works/swarma-keymaker/blob/4b9aebbaa74598b95ff0b071ae5218a7aa89c57c/spec/keymaker-authority-root.md#L432
[k-read-set]: https://github.com/relux-works/swarma-keymaker/blob/4b9aebbaa74598b95ff0b071ae5218a7aa89c57c/spec/keymaker-authority-root.md#L486
[k-calculator]: https://github.com/relux-works/swarma-keymaker/blob/4b9aebbaa74598b95ff0b071ae5218a7aa89c57c/internal/keymaker/authority_capacity.go#L46
[m-storage]: https://github.com/relux-works/swarma-user-manager/blob/730370b38f3eb006311b7e3efcbf80f4d4d0518d/spec/pc2-manager-state.md#L156
[m-open]: https://github.com/relux-works/swarma-user-manager/blob/730370b38f3eb006311b7e3efcbf80f4d4d0518d/internal/pc2store/secure_linux.go#L35
[m-index-codec]: https://github.com/relux-works/swarma-user-manager/blob/730370b38f3eb006311b7e3efcbf80f4d4d0518d/spec/pc2-manager-state.md#L223
[m-publication]: https://github.com/relux-works/swarma-user-manager/blob/730370b38f3eb006311b7e3efcbf80f4d4d0518d/spec/pc2-manager-state.md#L276
[m-frontier]: https://github.com/relux-works/swarma-user-manager/blob/730370b38f3eb006311b7e3efcbf80f4d4d0518d/spec/pc2-manager-state.md#L355
[m-lifetime]: https://github.com/relux-works/swarma-user-manager/blob/730370b38f3eb006311b7e3efcbf80f4d4d0518d/tools/genjournal/lifetime_writer_linux.go#L242
