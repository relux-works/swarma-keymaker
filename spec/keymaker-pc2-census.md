# PC2 joint capacity census: Keymaker answers

Status: **design proposal; MC-Q2 / G5-B remains open**. No runtime code, credit
issuer, occupied-slot transaction, new G4 field or production qualification is
introduced. A valid codec or pure size calculation is not a committed census.
The seven answers distinguish existing requirements/code from proposed joint
operations and operator decisions. All proposed APIs, vectors and crash tests
below are **PENDING / NOT RUN**.

The exact public baselines are:

| Alias | Repository and immutable commit |
|---|---|
| KM | `swarma-keymaker@28b1c8839fa59cbd1ac7409510716c7929c77e2e` |
| UM | `swarma-user-manager@b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9` |

Every source anchor below is `repository@commit:path:line`; abbreviated commits
resolve to these exact objects. Current public G4 preimages take precedence over
earlier planning proposals. This document changes none of G4's
closed codecs, fourteen classes, participant roles, identities or read limits.

## 1. Object ownership and canonical copy IDs

**Keymaker answer / already decided.** Every retained physical copy has one
capacity class, regardless of its logical event, process liveness or owning UID.
The fourteen rows are fixed, including explicit empty rows. The class codec
checks unique sorted IDs **within a class**; it does not prove cross-class
uniqueness, filesystem completeness, custody or currency. The manager owns its
five class populations and Keymaker its nine; root-owned files can still be
charged to a Keymaker class. Row ownership is budget responsibility, not a grant
of filesystem write privileges. Anchors:
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:291][k-groups],
[swarma-keymaker@28b1c88:internal/keymaker/authority_codec.go:972][k-class-codec],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:154][m-classes].

**Joint proposal: fixed role classifier.** Apply the following to the complete
PC2 read/write/retention closure, including whole native journal/effect files
that carry those obligations; do not count only a PC2 substring of a retained
file. Unrelated files outside that closure are not silently brought into this
budget. Explicit audit segments retain their separate existing budget. A role
and copy phase select exactly one row; descriptive filenames do not select it.

| Fixed class | Complete role population; precedence for copies |
|---|---|
| `keymaker/installed` | Currently installed private binding/native-result/message payload. A retained old installed image moves to recovery or migration history by its declared retention role, never stays counted as a second current installation. |
| `keymaker/artifacts` | Immutable certification, publication, freshness, signed-input and other retained message artifacts; recovery and staging copies use the dedicated rows instead. |
| `keymaker/recovery` | Retained private native intent/effect **snapshot bodies**, exact old/new repair images and private recovery evidence; not the root-owned manager recovery ledger. |
| `keymaker/staging` | Keymaker temporary installation copies of root, payload, native intent/effect snapshots, participants and policy until publication; each simultaneous inode is a separate copy. |
| `keymaker/pending_proofs` | Unspent proof obligations; materialized proof artifacts move to artifacts/recovery by role, with the ticket-to-copy relation retained. |
| `keymaker/policy_history` | Retained original policy, pin, enrollment, approval/high-water and provider evidence copies; the published role and protected installer remain owner-authenticated. |
| `keymaker/root_history` | Current and retained logical authority roots and their distinct installed/archive copies. |
| `keymaker/migration_history` | Original legacy/S2 migration inputs, retained phase/decision records, C0 and original bootstrap authorization; retained Q0 itself is reservation metadata. |
| `keymaker/reservation_metadata` | Materialized Qn reservations, participants/provenance, Keymaker class/owner indices, private history/native/message inventory wrappers, root intent/floor/link metadata and their retained versions; it also funds future auxiliary metadata tickets whose materialized destination may belong to the manager (§2). |
| `manager/attempts` | Every immutable A2 attempt/disposition version and attempt-specific evidence; pending, absent and durable versions all retained. |
| `manager/holds` | Every activation/authority hold and immutable hold-disposition version, even after death or resolution. |
| `manager/recovery` | Complete native journal/effects/intent/marker/evidence/ledger files in the PC2 closure, root recovery open/resolved/release-prepared/released records, proof copies and native recovery snapshots; attempt/hold-specific versions above take precedence. |
| `manager/inventory` | Installed/retained manager and five manager class inventories, manager-side owner/copy index, committed-credit spend/fold index, guard/head metadata, package-fence publication and their retained versions. A manager-owned sealed recovery-history wrapper is metadata here; its referenced recovery records remain recovery. |
| `manager/staging` | Every manager temporary/staged copy before installation, including native snapshots and the prospective guard. Following an atomic rename, transfer the same copy's classification to its declared installed destination, rather than count it again. |

The schema/participant role does not determine budget ownership alone. For
example, the root-owned `recovery_history` participant is a wrapper in
`manager/inventory`; its body objects are `manager/recovery`. A service-private
copy of manager evidence, if actually retained, is a **different physical copy**
in `keymaker/recovery`. No logical reference creates an additional materialized
copy. Fixed exclusion inodes/directories are deployment infrastructure; their
qualified allocation overhead still needs the storage profile in §2, not an
unlisted data-object class. Unsupported scope or object types close the census.

Propose capacity IDs as `pc2o1:` plus 64 lowercase SHA-256 hex digits of CCJ-1
of this exact ordered array (no LF):
`["pc2-copy-id/1",deployment_id,authority_incarnation,owner,role,directory_role,relative_name,copy_id,disposition_version,content_digest]`.
Use the admitted deployment ID/incarnation and fixed role/directory catalogs;
`owner` is `keymaker` or `manager`; `relative_name` is the checked UTF-8 relative
location with no empty, dot, dot-dot or symlink component; `copy_id` is a retained
32-lowercase-hex copy-lineage ID, `disposition_version` a positive safe integer,
and `content_digest` the original bytes' D. All string inputs are bounded by the
owner profile before hashing. This is a **proposed index preimage**, not an added
G4 field or a published ledger codec.
It fits existing `Text` (1–255 bytes). Preserve the unhashed tuple, actual anchored
location, inode identity, length and content digest in the authenticated owner
index for collision/substitution checks. A2 attempt IDs retain their existing
recipe; two disposition/copy versions with the same A2 ID need different storage
IDs. Never identify storage by content hash alone. Rename is an indexed transition
between old/new location identities for the **same** copy lineage, not two copies
or fresh credit. Distinct physical copies of equal bytes remain distinct charges.
An append-only native file's retained historical prefixes are charged within its
full current length, not as fictitious additional full-file copies. Separately
retained old images and immutable disposition records are additional real copies;
old index references alone are not materialized file versions.

Joint preparation must compare both owner indices globally, reject hardlinks,
symlinks, cross-class aliases and unknown roles, and reconcile every named staging
entry with a ticket. An orphan with measurable bytes remains retained and charged
in its authenticated owner's staging/recovery row, without inventing an attempt
origin. Unknown owner/size/copy provenance means **unavailable census**; no new
admission until authorized reconciliation identifies it. A scan finding nothing
does not prove no deleted history. New index/staging growth is pre-funded too.

**Operator question O1 / safe default.** Which protected deployment-to-directory
mapping, sole publishers and old/restored-writer exclusion authority are admitted
for these two owner indices and shared recovery installation? Until selected and
qualified, no independently current census or cross-owner write capability.

## 2. Exact bounds, ticket destinations and once-only conversion

**Keymaker answer / already decided.** The calculator sums actual validated
class rows and independently measured installed size, plus conservative future
bounds. It cannot measure bytes, enable verity or authenticate inventory maps.
It charges future auxiliary metadata to `keymaker/reservation_metadata`, and the
fixed manager guard ticket to `manager/staging`. The manager's installed census
and guard belong to `manager/inventory`. These are source/destination stages,
not permission to charge the same materialized object twice. Anchors:
[swarma-keymaker@28b1c88:internal/keymaker/authority_capacity.go:5][k-cap-input],
[swarma-keymaker@28b1c88:internal/keymaker/authority_capacity.go:125][k-cap-metadata],
[swarma-keymaker@28b1c88:internal/keymaker/authority_capacity.go:145][k-cap-tickets],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:209][m-convert].

**Joint proposal: measurement responsibility.** Each physical writer measures
exact encoded content using the correct codec, current protected file length and
retained descriptor, and supplies per-copy qualified verity-tree/descriptor and
filesystem allocation overhead. The census owner verifies those measurements and
index linkage; the common transaction validates all fourteen rows and installed
identity. The platform/qualification owner supplies filesystem-specific bounds
for rounding, directory/index growth, xattrs, verity and recovery allocation.
No sparse/compressed-file discount or `stat`/checksum alone proves that bound.
Keep `bytes` as actual content length; charge additional per-object allocation
cost in `integrity_bytes` under a jointly approved conservative interpretation of
G4's integrity/metadata-overhead rule. Directory/fixed-object costs require an
explicit attribution profile; if the closed format cannot represent a cost
faithfully, stop rather than redefine `bytes` or add a field.

The same writer must calculate all old+new simultaneous copies and worst-case
encoding growth before writing: revision/size digit expansion, maximal audit
linkage, base64 and inventory entries, retained index/spend evidence, metadata's
own output and repeated recovery phases. One 8192-byte recovery record cap does
not cover four records plus proofs. Bound tickets before future hashes exist.
At materialization, independently check encoded length plus integrity/allocation
cost against the ticket; an overrun stays held/refused, not borrowed headroom.

For the **unchanged calculator**, let E be the sum of input materialized,
integrity and already reserved bytes in all fourteen rows; R the root bound
including integrity; N the larger of native-intent/native-effect bounds including
integrity; M the metadata bound including integrity; Ii the four supplied manager
integrity bounds; P the required pending-proof bound including proof integrity;
and Rp the input proof-row reservation. Its exact peak is:

```text
E + 2R + 4N + M + 139264 + sum(Ii) + max(0, P - Rp) <= 268435456
139264 = 4096 + 4096 + 65536 + 65536
M.content >= 65536 + 65536 + 4096 = 135168
P = PendingProofs * 4194304 + ProofIntegrityBytes
```

The metadata minimum is only a floor; it is not a bound for fourteen rewritten
class inventories or all owner-index growth. Extra copies/growth require explicit
input reservations without duplicating automatically added tickets. Existing
unused proof credit cannot be reclaimed by recomputing a smaller P. Eight audit
records retain their **separate existing** headroom protocol; they are not eight
free state-budget records or a second spendable audit reserve. The calculator's
output is immutable sizing evidence; no row total itself commits a ticket.

**Joint proposal: exact ticket-to-destination map.** For every instance, assign a
unique ticket identity `pc2t1:` plus SHA-256 hex of CCJ-1 of the exact ordered array
`["pc2-ticket-id/1",D(Qn),source_owner,source_kind,role,copy_ordinal]` (no LF),
using a positive safe-integer ordinal fixed in the pre-funded partition. The
debit relation must name exactly one destination and
copy lineage. A compound bound must be partitioned into individually bounded
subtickets **before any write**. This partition belongs to the proposed protected
owner index, not new members in Qn. Never fund a copy from two overlapping tickets.

| Ticket / charged source in unchanged preflight | Materialized destination / conversion rule |
|---|---|
| Root retained-image R / `keymaker/root_history` | `keymaker/root_history`, distinct retained/archive root copy. |
| Root installation R / `keymaker/staging` | `keymaker/staging` while temporary, then `keymaker/root_history` for that same installed copy after rename; no second debit on rename. The archive ticket above funds a different copy or remains unused and charged. |
| Native intent recovery N and native effect recovery N / `keymaker/recovery`, separately | `keymaker/recovery`, two separately retained snapshot bodies; never one ticket for both. |
| Native intent installation N and native effect installation N / `keymaker/staging`, separately | `keymaker/staging` while temporary, then `keymaker/installed` at the private payload endpoint. On supersession, the retained same copy moves to `keymaker/recovery` without another debit. A distinct repair inode needs a separate recovery ticket. No role transition recredits a retained old copy. |
| Fixed attempt 4096+I0 / `manager/attempts` | `manager/attempts`, exact A2 copy/version; additional disposition versions need their own pre-funded growth, not overwrite of the first version. |
| Fixed hold 4096+I1 / `manager/holds` | `manager/holds`, exact derived hold copy. |
| Fixed guard 65536+I2 / `manager/staging` | `manager/staging` while temporary, then `manager/inventory` for the installed guard, preserving the original debit. Old guards/history remain separately charged. |
| Fixed recovery 65536+I3 / `manager/recovery` | `manager/recovery`, partitioned records/proofs of the exact original flight; excess phases/copies need additional pre-funded bounds. |
| Auxiliary M: Qn/participants/provenance, Keymaker indices/class/private inventory wrappers, intent/floor/link copies / `keymaker/reservation_metadata` | `keymaker/reservation_metadata` after publication; temporary copies are `keymaker/staging` with their own subticket. |
| Auxiliary M: manager inventory head, all five manager class inventory files, sealed recovery-history wrapper, package-fence publication, manager index/spend records / `keymaker/reservation_metadata` | `manager/inventory` after publication; temporary copies are `manager/staging` with separate subtickets. This is the explicit cross-owner transfer, not a second manager reservation. |
| Auxiliary M: retained new guard versions beyond the fixed guard / `keymaker/reservation_metadata` | `manager/inventory` after publication, temporary copy in `manager/staging`; never overlap the fixed guard's copy. |
| Auxiliary M: C0 original authorization/commit and migration metadata copies / `keymaker/reservation_metadata` | `keymaker/migration_history`; Q0 stays `keymaker/reservation_metadata`. Original C0 authorization custody/commit remains separately gated. |
| Pending proof / `keymaker/pending_proofs` | `keymaker/artifacts` for published proof, `keymaker/recovery` for separately retained recovery proof; each simultaneous installation copy is staged and separately funded. Unused remainder stays reserved. |
| Other future owner/policy/native/index/migration copies / explicit `Classes.ReservedBytes` input | Exactly the destination in §1 for the fixed role/phase, captured before encoding. No uncategorized catch-all subticket, implicit new method or shared free-space pool. |

Let a ticket have remaining B, and its new copy consume b content plus i overhead.
The effective accounting transition is atomic in the spend relation:

```text
source.reserved -= b+i
destination.materialized += b
destination.integrity += i
destination.objects += 1
ticket.remaining = B-(b+i) >= 0
```

Physical rename changes location/class attribution without changing the consumed
total; source object count decreases when destination count increases. Historical
indices remain evidence of that move, not two materialized current copies. A new
retained old/new copy always has a separate ID and charge. Unused remainder is
**still reserved**, not immediately returned free space. Thus conversion changes
no aggregate total. It does not edit immutable Qn; the exact owned extension
explains effective counters until a later root folds the same delta (§§4–6).

Example: an old manager inventory costs 8192+2048=10240 bytes. An auxiliary
metadata subticket of 20000 in `keymaker/reservation_metadata` produces a new
manager inventory of 12288 content +4096 overhead. After conversion the old
10240 and new 16384 are materialized under `manager/inventory`; 3616 remains
reserved at the original source. Total remains **30240**, not 50240 or 10240.
If a temporary and final inode coexist, two subtickets are required; a rename
of the same inode consumes once. Likewise fixed guard 65536+4096=69632 converted
to 49152+4096 leaves **16384 reserved**; its destination is manager/inventory,
not an extra 69632 allocation there. Only qualified durable resolution can
retire residual credit, and retained history is never freed by that retirement.

The newly encoded Qn, class inventories and spend-index checkpoints must not
include their **own future content digest** in their own measured input. They
remain covered by prospectively funded metadata slots/owned extension until the
next census seals those already materialized versions. Every generation funds
its replacement metadata too; a lagged checkpoint is safe only with complete
current funded-delta evidence and an independent baseline, not a stale total.

**Operator question O2 / safe default.** Which filesystem/verity/allocation
profile and measured storage envelope are accepted, including non-file overhead
and zero-length staging/orphan objects? G4 object `bytes` is positive and cannot
directly represent an empty retained file. Do not pad actual lengths, omit its
allocation or alter G4: unsupported objects/costs keep census and PC2 unavailable
until a faithful reviewed profile or separately authorized owner resolution exists.

## 3. Complete histories and summary semantics

**Keymaker answer / already decided.** Attempts/holds/recovery bind complete
append-only retained history, not merely current pending items. Disposition is
excluded from A2 identity, but every linked disposition version and its bytes
remain retained. `pc2-manager-inventory/1` has exactly its existing nine members;
neither codec nor calculator supplies the owner history index or the population
meaning of its two summary counters. Anchors:
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:341][k-manager-summary],
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:420][k-attempt-history],
[swarma-keymaker@28b1c88:internal/keymaker/authority_identity.go:106][k-attempt-id],
[swarma-keymaker@28b1c88:internal/keymaker/authority_codec.go:946][k-manager-codec],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:170][m-prepare].

**Joint proposal.** Define A, H and R as all retained physical copy/version
entries in the manager attempts, holds and recovery class inventories in §1.
Propose `attempts_digest`, `holds_digest`, `recovery_digest` as D(CCJ-1) of those
three exact existing `keymaker-capacity-inventory/1` objects, respectively. The
storage ID binds each entry's content digest, location, copy and disposition
version; full preparation resolves those original bytes and validates semantic
links. This gives an exact recipe using existing G4 records, not just an
untyped "history hash". Empty digests use explicit canonical empty inventories.
This population/recipe is a **joint proposal**, not a stronger property claimed
from the current generic codec.

Propose the manager head's `materialized_bytes = sum(bytes in A union H union R)`
and `objects = |A|+|H|+|R|`. Integrity remains separately in the class rows.
Manager inventory/staging metadata are **excluded from these two head summary
counters**, but always included in their own reservation rows and effective
funded extensions. This prevents an inventory counting/hashing its own future
encoding. Both owners must accept this exact summary scope; if they require a
different scope, resolve it before implementation, without changing closed fields.

The five class rows summarize their own full materialized populations; the
fourteen-row reservation summarizes **all** populations plus retained credit.
Logical `HistoryRef` entries are references, not extra file copies. Their
wrapper bytes are separate metadata; referenced physical bytes are charged
once in the role row. All predecessor inventory/guard/spend-index versions remain
charged and linked to the accepted baseline. Old indices never disappear because
the newest root references only a later head.

Each owner needs a protected, complete allocation/location/version/tombstone
index; manager publishes its index, Keymaker its own. Reconcile on-disk names
against the index and index against actual protected objects in both directions.
Independent per-transaction accepted baseline, continuity custody and old-writer
exclusion must detect coherently restored/deleted suffixes. Directory scans,
hash-consistent empty inventories, local high-water alone or a co-restored index
cannot prove completeness. New checkpoint records must be funded before creation.
No new index codec, trust anchor or extra under-F read is allocated here.

**Operator question O3 / safe default.** Which independent custody owner and
failure domain supply per-transaction latestness of both owner indices, Qn/spend
history, root/link/guard/floors and unresolved obligations, with old-instance
exclusion? Until published and qualified, coherent-restore completeness remains
unproved and census authority closed; no startup-only backup or implicit option C.

## 4. Committed-credit API and the sealed baseline

**Keymaker answer / already decided.** `authorityCapacityPreflight` returns only
immutable encoded Qn sizing evidence. `authorityDigest`, root sealing and audit
preparation likewise do not commit credit. G4 requires a committed reservation
before manager consumption; a future root hash or map of free bytes is not one.
Anchors:
[swarma-keymaker@28b1c88:internal/keymaker/authority_capacity.go:27][k-cap-ticket],
[swarma-keymaker@28b1c88:internal/keymaker/authority_identity.go:5][k-identity-limit],
[swarma-keymaker@28b1c88:internal/keymaker/authority_audit_prep.go:55][k-audit-limit],
[swarma-keymaker@28b1c88:spec/keymaker-pc2.md:197][k-common-commit],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:191][m-census-capability].

**Joint proposal: semantic API, not shipped signatures.** Keymaker's common
authority transaction owner commits Qn through the exact Rn transaction with
authenticated owner-prepared participants/installers, durable audit, final
root/floor/guard/intent cleanup and independent current custody. The manager
cannot commit it by writing its own census. Bootstrap uses independently admitted
Q0/C0 before M0/Q1/R0 and grants no slot use until eligible R0. A later reservation
transaction itself consumes its predecessor's pre-funded metadata/copy headroom;
it cannot fund its own first mutation from an uncommitted candidate.

1. `PrepareManagerCensus` and Keymaker preparation authenticate complete immutable
   histories and current accepted baseline outside short locks. Prepare the exact
   fourteen rows and every copy/encoding/integrity bound.
2. A proposed `CommitCommonReservation` operation binds the prepared census and
   subticket partition to the common transaction. Only proven eligible durable
   Rn with committed Qn yields credit. Lost acknowledgement means unknown until
   the original transaction is conclusively observed/recovered; never issue Qn+1
   as a retry substitute.
3. A proposed `PrepareCommittedCredit` yields an opaque process-local, noncopyable,
   single-use capability from that independently current commit. Bind deployment/
   incarnation/boot and process, manager installation ID, Qn digest and slot
   lineage, baseline root/link/guard/inventory revisions/digests, immutable effect,
   ordinal, full target T/owner/provision effect, source counter/root, prepared
   journal tail and exact active-record hash/A2 attempt ID. A public struct or
   content hash cannot manufacture it. Prepare evidence unlocked; final direct
   comparison under F_auth must match or refuse for fresh unlocked preparation.
4. The journal-owned lifetime alone consumes this capability into the exact
   A2/hold/open-guard/inventory extension before active write. Native marker/intent
   creation earlier in the journal already draws from the committed allocation
   (durable pre-obligation debit in §6), even though it is not A2 observation
   absorption. Copied/reused/foreign capability refuses; an exact retry observes
   the retained original outcome, never consumes the slot again.

Preserve the sealed baseline participant. G4 allows only the original live
writer's one exact pre-funded normal extension; it changes the guard's bounded
inventory/attempt references, not the immutable root or participant. Fully validate
ancestry and the spend relation unlocked; under F_auth compare only the fixed
prepared metadata/verity set. Any unrelated, later-open, restarted or partial
extension vetoes normal append. Root recovery is a separately authorized repair,
not an additional normal exception. No extra spend-ledger open, census scan,
callback, provider/RPC or C acquisition is added under F_auth. The capability
must reduce its prepared spend proof to existing guard/inventory/root comparisons;
if that cannot be demonstrated, keep the API unavailable rather than enlarge G4.

**Operator question O4 / safe default.** Who is authorized to commit common
reservations and C0, install each owner's exact participants, and publish the
independent commit/currentness proof, with what recovery API for a lost commit
acknowledgement? No assumed root privilege, fabricated receipt, credit API or
C0 reset until those authorities and failure handling are accepted.

## 5. Occupied slot, recovery, root folding and replenishment

**Keymaker answer / already decided.** The calculator refuses **every nonzero**
`ManagerSlotsInUse` and unconditionally adds one fixed future slot (139264 bytes
plus supplied integrity) on successful fresh preflight. It is not an occupied-
slot recovery/folding calculator. No reviewed executable transaction at these
baselines handles an occupied or partly consumed slot. G4/UM describe requirements
for one, not an available API. Anchors:
[swarma-keymaker@28b1c88:internal/keymaker/authority_capacity.go:46][k-slot-refusal],
[swarma-keymaker@28b1c88:internal/keymaker/authority_capacity.go:166][k-slot-future],
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:332][k-slot-contract],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:238][m-occupied].

**Joint proposal: separate resolve/fold transaction, never relaxed preflight.**
A proposed `ResolveAndFoldOccupied` transaction belongs to the authorized root
recovery/common-transaction owners. It must:

- Authenticate the **same** Qn slot lineage, every native pre-obligation debit,
  original A2/hold and cumulative consumed/unspent bounds. Missing marker or
  stopped PID is not evidence of free credit. Partly published consumption is
  occupied/unknown; use the original coordinator/recovery identity.
- Use only the original pre-funded remaining recovery/guard/index/staging/audit
  tickets. Charge all retained old and new copies. If they cannot cover the
  required repair, stop held; no emergency uncharged file, second slot or forced
  on-demand top-up. Reserving a different recovery envelope requires a separately
  reviewed authority/custody transaction, which does not exist here.
- Resolve actual journal outcome and linked cleanup, consume release durability
  directly, and prepare the complete changed census unlocked. Fold its exact
  materialization delta into a common root with no second debit or allocation.
  Any occupied-state checkpoint is non-serving and needs the same unresolved
  hold; it cannot publish eligible `recovery:"clear"` while uncertainty persists.
- Preserve the original slot's spend lineage even if a checkpoint has a different
  Q digest. `manager_slots.slots=1` describes one bounded slot, not evidence it is
  unspent. The proposed spent/fold index records that it is carried, not minted.
  No new G4 `occupied`/`spent` member is added.
- Replenish only after exact outcome, all linked release/cleanup and independent
  currentness are durably established, no old/in-flight writer can consume, all
  retained bytes are still charged, and old credit is durably retired exactly
  once. A **new committed common reservation/root transaction** may then replace
  that retired credit with one future slot, including all new transaction copies.
  Credit is unavailable until that commit's durability/currency is proven.

Do not call `authorityCapacityPreflight` with a fabricated zero count, subtract
its fixed slot after the fact or treat a resolved-but-spent old allocation as
unspent. The new transaction must define the authenticated bridge from spent
old credit to a genuinely admissible fresh-slot preflight and atomic replacement.
If existing proposed census semantics cannot express that bridge, joint API review
is required before implementation; this response does not invent a successful
call sequence. A rejected occupied preflight remains a correct rejection.
Successful normal append does not by itself replenish; its retained history and
spend record survive. No second pending activation or independent owner recredit.

**Operator question O5 / safe default.** Accept that exhausted/uncertain occupied
recovery can block issuance and withdrawal completion indefinitely, and designate
the authorized recovery/fold/replenishment owner with its finite pre-funded
storage envelope? Default is retained hold/no new credit, not TTL, forced cleanup,
larger aggregate budget or relaxing the calculator.

## 6. Durable order, crash cuts and spend ownership

**Keymaker answer / already decided.** Reservation precedes **any obligation**,
not only active append. A2 consumption precedes active write; actual outcome and
linked release precede credit retirement/fold/replenishment. Possible write versus
proven append with uncertain cleanup remain different outcomes. The existing
code defines no durable cross-owner spend ledger. Anchors:
[swarma-keymaker@28b1c88:spec/keymaker-pc2.md:187][k-before-intent],
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:472][k-live-flight],
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:803][k-crash-walk],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:264][m-lifetime],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:393][m-release].

**Joint proposal: one spend authority, two enforcing consumers.** The root
manager/coordinator persists the append-only slot/subticket debit and transfer
relation in its protected owner/spend index, budgeted under `manager/inventory`.
It links committed Qn, original deployment/manager/effect/ordinal, copy/ticket,
consumed/residual bound, exact attempt/hold when known, original outcome/recovery
and subsequent fold/retirement evidence. The Keymaker common transaction seals
the authenticated prepared spend history via existing class/participant/guard
references and independent custody. It cannot retire debt from its own local
counter; the manager cannot recredit on local finish or a lost root acknowledgement.
Index codec/ancestry and commit semantics need joint publication; these concepts
are not new G4 members, authority from an opaque sidecar or a new under-F read.
Never hash a future root/Qn into its own reservation/index preimage: spend names
an **already committed** Qn; a later fold receipt binds the later root without
feeding that receipt back into that root's own candidate.

The proposed exact order is:

```text
eligible committed reservation Qn + subticket partition + current baseline
 -> durable debit for native obligations (before each marker/intent/copy)
 -> native marker/effect preparation under its existing protocol
 -> journal-owned effects -> exclusive gate -> exclusive data -> F_auth
 -> final check; durable A2 + hold + open guard/inventory consumption
 -> single active write + journal/file/directory sync + full-chain verification
 -> exact retained outcome + normal finish or same-origin root recovery
 -> linked resolved -> release-prepared -> owner cleanup -> released barriers
 -> direct manager release consumption, retaining spent debt/history
 -> common root fold of that exact delta; proven old-credit retirement
 -> separately committed fresh reservation/replenishment (only when §5 permits)
```

Before native obligation creation, persist an attributed pre-obligation debit
bound to the committed allocation and existing immutable effect/ordinal; do not
fabricate an A2 origin before its exact prepared tail/active hash exists. This
debit is **not** observation absorption or an active-append authorization. Failed
preparation can leave a charged native marker with no A2; it requires attributed
recovery, not a made-up attempt. Persist original attempt consumption before
active write. A capability prepared in RAM is never the spend record.

The pre-A2 debit's durable representation and its binding to the sealed baseline
are an **unclosed joint publication**: neither existing codec nor calculator
provides that spend index or proves it can be consumed through G4's fixed final
read set. The same is true of a carried spent-slot lineage across root folding.
Publish and review those exact index/continuity transitions before code; no extra
guard phase, optional member or second normal-extension exception is implied.
Until then the stated order is a requirement for the future transaction, not a
claim that an executable safe sequence already exists.

Every publication below includes checked full write, file sync, checked close,
rename where applicable, parent sync and identity/readback. A failure at **any**
substep leaves the listed conservative state; directory durability is not inferred
from an acknowledgement. Retained index writes and their staging copies require
prior credit too. Before starting, fully bound their worst-case count/growth so
the spending protocol cannot recursively create uncharged spending records.

| Cross-process cut; partial publication or lost acknowledgement | Durable owner action / required survivor state |
|---|---|
| CC-C01: Reservation candidate/preflight only; before reservation intent | No credit. Prove old consistency/no writer in flight; no native obligation or A2. |
| CC-C02: Common reservation intent write/file sync/close/parent sync | Common owner retains same transaction and paid copies; partial/unknown closes both owners. No native obligation may begin. |
| CC-C03: Qn/participants/audit/root/floor/link installation at each write/sync/close/rename/parent sync | Same common transaction and hold; no independently committed Qn from readable bytes, old-root fallback or another reservation attempt. |
| CC-C04: Root durable but intent clear/cleanup/parent sync or independent custody incomplete; commit acknowledgement lost | Determine exact original commit and all barriers before offering credit. Known root with unknown cleanup stays closed. No duplicate Q or extra slot from retry. |
| CC-C05: Debit/index staging, debit durable but native marker not created, or debit acknowledgement lost | Root manager retains that original ticket occupied; unused physical bytes do not imply the debit never happened. Observe same debit; no second consume. |
| CC-C06: Native pending marker/effect/intent file, rename or parent sync before A2; acknowledgement lost | Retain pre-funded native obligation and attributed debit; no fabricated A2/hold. Stop old writer/in-flight sync and use authorized reconciliation. |
| CC-C07: Prepared observation/capability lost before durable absorption | No cached completion authority. Retain any native debt; fresh unlocked observation required, within original correlation rules. |
| CC-C08: A2 write/sync/close/parent sync, then hold, manager inventory and open guard at every substep | Any partial publication vetoes; one slot occupied/unknown even if only a subset is visible. Root manager preserves same origin/copy debit; never expose write authority until all required links/barriers complete. |
| CC-C09: Complete durable consumption; before active write; consumption acknowledgement lost | Same A2/hold and spent relation. No active append yet only if stopped writer/no in-flight I/O and native evidence prove it; do not infer absence from reply loss. Source-death completion remains the separate joint correlation decision. |
| CC-C10: Active write started/short write; journal file/directory sync or full-chain verification incomplete | Unknown write, no clean abort, duplicate append or recredit. Retain exact attempt, original bytes, all copies and hold. |
| CC-C11: Active append proven durable; outcome/receipt/finish/marker unlink/parent sync or acknowledgement fails | Known append with uncertain cleanup; retain same active result and hold. Matching retry cannot create another active record or claim absence. |
| CC-C12: Exact outcome/normal finish publication partial | Original live no-error flight alone may finish its exact protocol. Restarted/errored/dead flight transfers to root recovery; no normal-flight ownership inferred from IDs. |
| CC-C13: Recovery open/resolved/release-prepared at every file/parent publication or lost acknowledgement | Resume same retained recovery ID/hold and spend lineage; resolution alone does not release. No new origin, cleanup before release-prepared, or deletion of histories. |
| CC-C14: Owning marker/intent cleanup/unlink or any parent sync partial | Hold/spend debt survives even after names vanish. Preserve release-prepared and exact cleanup ownership; no free slot. |
| CC-C15: Released record readable/file-synced but linked guard/other parents/last ledger directory incomplete; reply lost | Direct under-F qualified sync-consumption and full exact linkage/current guard required. Another process's success or phase text is insufficient; same release completes once. |
| CC-C16: Release consumed, but common fold candidate/intent/participants/audit/root/cleanup/custody partial | Spent relation and all retained bytes remain; no new credit. Exact fold finishes once, counting the same materialization delta, not spending the ticket twice. |
| CC-C17: Fold durable, old-credit retirement or fresh-reservation installation/acknowledgement partial | Default no usable replenishment; resolve original joint replacement. Neither owner publishes local unspent credit; old residual and prospective replacement charges cannot vanish between commits. |
| CC-C18: C0/Q0 or floor-genesis commit/acknowledgement unknown | Separate admitted bootstrap recovery establishes that same commit, never reinitialize. C0 is not a PC2 authority-hold origin or permission for M0/slot use. |

Keymaker common transactions use source gate/data -> C_Store -> C_enrollment ->
audit -> F_auth; manager append uses effects -> gate -> data -> F_auth, with no
C/audit underneath F_auth. Recovery establishes serving/old-writer exclusion and
offline lifetime exclusion **before** effects/gate/data/C/audit/F_auth. Release
F_auth before data/gate/effects. All provider/network/history work stays outside
the relevant short locks; network work is outside all locks. These operations
must fit the original 250 ms reader, 1000 ms writer and send-start+2000 ms
observation bounds; no guard-entry restart, extra file or covert helper wait.
The exact forward order and permitted final reads are constrained by
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:486][k-read-set] and
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:395][m-recovery-order].

**Operator question O6 / safe default.** Approve the root manager/coordinator as
spend-index writer, common-owner fold/retirement authority, exact installer/sync
privileges and independent per-transaction custody; how are pre-A2 debit and
carried spent lineage anchored without expanding the closed guard/read set; and
may the same durably consumed observation complete after source disconnect/death? Until
joint publication/acceptance, no spend/replenishment API; retain unknown debt and
existing observation-correlation refusal, with no invented abort/completion.

## 7. Shared acceptance vectors and evidence

**Keymaker answer / already decided.** Existing codec, identity, arithmetic and
audit-preparation tests do not qualify a live census, commit/spend API, native
durability, independence after restore or occupied-slot recovery. G4 runtime
qualification remains pending. Anchors:
[swarma-keymaker@28b1c88:internal/keymaker/authority_capacity_test.go:79][k-cap-tests],
[swarma-keymaker@28b1c88:spec/keymaker-authority-root.md:814][k-runtime-pending],
[swarma-user-manager@b6f6fbe:spec/pc2-manager-contracts.md:20][m-negatives].

**Joint proposal: one canonical fixture package, independent oracles.** Publish
immutable CCJ-1 bytes and expected SHA-256, all fourteen exact inventories, Qn,
subticket partition, before/after effective row arithmetic, original A2/hold,
sealed baseline, owned extension and retained spend/fold evidence. Use synthetic
deployment identities and objects. Each implementation must consume the same
bytes and independently reach the expected verdict/total; agreement between two
copies of one encoder is not an oracle. No new G4 member is accepted in a vector.

These named future vectors state specific claims; every negative checks the
named refusal/invariant, unchanged forbidden mutation/release and retained debt,
with permitted bounded refusal audit distinguished from forbidden effects. Every
positive actually performs its allowed operation. None has been executed here.

| Vector / intended negative witness | Negative and required observation | Adjacent positive / independent oracle | Future narrowing control; status |
|---|---|---|---|
| CC-V1 CopyExactlyOnce | Alias, duplicate cross-class ID, omitted orphan/history/native copy: census unavailable, no reservation/native write | Complete fourteen rows and equal-content distinct copies have exact independently listed counts/bytes | Drop one copy/class/global alias check; intended CC-V1 failure; PENDING |
| CC-V2 TicketDestination | Metadata-to-manager-inventory or guard transfer double-charged/unfunded, negative remainder or oversized copy: reject before write, retain source credit | §2 numeric examples total 30240 and 69632 exactly; same-inode rename once, separate inodes twice | Remove one source debit/destination charge/bound; intended CC-V2 failure; PENDING |
| CC-V3 MetadataSelfGrowth | Omit reservation/class/spend-index own prospective growth or add self/future-root hash: reject without intent | Acyclic funded current metadata and retained predecessor metadata fit exact peak; next generation funds its own output | Omit self-growth or accept cyclic reference; intended CC-V3 failure; PENDING |
| CC-V4 HistoryComplete | Live-only dispositions, missing intermediate absent/durable version, co-restored empty index or mixed baseline: unavailable, no slot | Complete original A2 ID with distinct retained version/copy IDs and independently current A/H/R digests/summaries | Ignore one version/baseline or substitute directory scan; intended CC-V4 failure; PENDING |
| CC-V5 CommitBeforeObligation | Calculator bytes, prepared capability or lost-ack unproven Qn used for marker/debit/append: no operation | Proven eligible committed Qn funds each native obligation then exact A2 consumption | Treat preflight/hash/ack as committed; intended CC-V5 failure; PENDING |
| CC-V6 SlotOccupied | Nonzero ManagerSlotsInUse, partly consumed slot, second activation or replay recredit: original refusal, no new slot | Existing exact-fit fresh calculator case succeeds; independently authorized same-origin occupied recovery consumes only remaining old tickets, with no new credit | Pass fake zero or subtract fixed slot; intended CC-V6 failure; PENDING |
| CC-V7 SpendCrashCuts | Every §6 partial/lost-ack cut: no duplicate append/conversion/fold, no independent recredit, exact original debt/hold retained | Separate owner processes resume original effect/transaction once; exact byte/counter totals before and after recovery match fixture | Forget one durable debit/phase/parent sync; corresponding CC-V7 cut fails; PENDING |
| CC-V8 FoldThenReplenish | Successful append/readable released phase or one owner's fold resets slot: no fresh credit | Proven linked release, exact fold/retirement and eligible common replacement fund only one future slot while retaining all histories | Replenish on finish/reply/timeout or drop old debt; intended CC-V8 failure; PENDING |
| CC-V9 NativeBounds | Extra F-time file, RPC/lock back edge, wrong sync privilege, deadline reset, unsupported empty-object accounting or invalid C0 origin: path unavailable | Exact 22-file/1421312-content-byte read set within 24/2097152 cap, ten measured participants; original deadlines and admitted C0 DAG | Add extra read/helper/reset or invent origin; intended CC-V9 failure; PENDING |

For CC-V7 run separate actual manager/journal, Keymaker transaction, installer,
recovery coordinator and reopen/reader processes. Put deterministic barriers on
**both sides of every** write/sync/close/rename/unlink/parent-sync in §6, inject
short write, errno, process death and lost replies independently. Also race two
consumers of one ticket, fold versus consumption, withdrawal versus actual
release, old/restored writer versus replacement and retry versus recovery.
Inspect actual receiving bytes, native journal chain, physical copy inventory,
unchanged original result, owner indices, slot lineage and independently current
anchors. Source death before/after absorption needs the jointly accepted positive
as well as refusal controls. Process kills are not power-loss proof.

| Evidence supplier | Required G5-B acceptance evidence |
|---|---|
| Keymaker capacity/common-transaction owner | Exact source/test/config identities; pure calculator/golden identities plus real census/provider/commit/fold code when it exists; independently measured installed/native copies and metadata bounds; source/destination arithmetic; actual audit/root/intent/release crash outcomes; original named reviewer tests retained. |
| Manager/journal/root coordinator owner | Complete authenticated five-class histories/owner index; actual marker/debit/A2/hold/guard/spend and recovery records; journal-owned lifetime/all-exit reverse release; actual outcome partition; direct release consumption; no independent recredit; exact cross-process traces. |
| Joint format reviewers | One accepted canonical fixture head with independently derived expected hashes/counts/peaks/transactions, both valid controls and known-invalid cases; no closed G4 drift or opaque authority escape. |
| Platform/qualification and custody owners | Real UID/permission/descriptor/verity/filesystem allocation and fsync/parent durability evidence, native package/authority-fence distinction, all-writer exclusion, bounded no-back-edge graph and worst-case original-window latency; independently current restore/C0/floor custody. State storage/power-loss assumptions and unverified limits explicitly. |

A G5-B verdict must identify exact accepted implementations and environment,
commands, full logs/exit codes, each intended failing witness and passing control,
every cross-process cut's surviving state and shared fixture digest. Missing,
truncated, setup-failed or unsupported evidence remains unverified. A surviving
narrowing control must report its exact coverage bound; no runtime mutant is
claimed killed by this design document. G5-B acceptance does not close the
separate participant privileges, observation correlation, independent custody,
message-provider or platform gates by implication.

**Operator question O7 / safe default.** Which isolated native target, principals,
filesystem/power-loss model and independent reviewers may qualify the joint
fixture head and exact storage/deadline envelope, and which remaining gates are
explicitly accepted? Default is design review only, G5-B/runtime PC2 unavailable;
no deployments, privileged tests or heavier workload authorized by this response.

## 8. Decision boundary and delivery limits

Joint decisions requested: accept §1's role/copy index and canonical identity
proposal; §2's per-ticket destinations, arithmetic and overhead profile; §3's
three-history digest/summary scope; §4's committed-credit capability boundary;
§5's separate occupied resolve/fold/replenishment transaction; §6's sole spend
writer and full crash order; and §7's shared fixtures/native acceptance package.
These decisions allocate no new field in a closed G4 record. Any encoding or
privilege gap is a blocker before code, not permission for a hidden ledger API.

Operator questions O1–O7 above each carry a safe default. In particular, this
proposal selects no independent custody provider, genesis authority, privileged
installer or longer timeout; it never reuses a co-restored local head as current.
No implementation acceptance surface table was supplied for this design-only
assignment; the future code brief needs a coverage map and actual narrowing
evidence. Existing test code is unchanged, and all runtime vectors here are unrun.
Only this document is changed. Documentation diff, hygiene and link checks do not
prove census completeness, once-only spending or crash durability.

[k-groups]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L291
[k-class-codec]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_codec.go#L972
[m-classes]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L154
[k-cap-input]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_capacity.go#L5
[k-cap-metadata]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_capacity.go#L125
[k-cap-tickets]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_capacity.go#L145
[m-convert]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L209
[k-manager-summary]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L341
[k-attempt-history]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L420
[k-attempt-id]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_identity.go#L106
[k-manager-codec]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_codec.go#L946
[m-prepare]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L170
[k-cap-ticket]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_capacity.go#L27
[k-identity-limit]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_identity.go#L5
[k-audit-limit]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_audit_prep.go#L55
[k-common-commit]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-pc2.md#L197
[m-census-capability]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L191
[k-slot-refusal]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_capacity.go#L46
[k-slot-future]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_capacity.go#L166
[k-slot-contract]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L332
[m-occupied]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L238
[k-before-intent]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-pc2.md#L187
[k-live-flight]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L472
[k-crash-walk]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L803
[m-lifetime]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L264
[m-release]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L393
[k-read-set]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L486
[m-recovery-order]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L395
[k-cap-tests]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/internal/keymaker/authority_capacity_test.go#L79
[k-runtime-pending]: https://github.com/relux-works/swarma-keymaker/blob/28b1c8839fa59cbd1ac7409510716c7929c77e2e/spec/keymaker-authority-root.md#L814
[m-negatives]: https://github.com/relux-works/swarma-user-manager/blob/b6f6fbe7baf2c9ff039c6d3fb17ed7ce54a5f1f9/spec/pc2-manager-contracts.md#L20
