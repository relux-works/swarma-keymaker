# PC2: authoritative admission through activation

Status: **normative candidate requirements; not implemented or qualified**.
This applies the Keymaker commitments in the accepted conditional
[activation-order design §6](https://github.com/relux-works/swarma-user-manager/blob/549b4aa89184c974331d1be1af151cec9768658e/spec/activation-order.md#6-keymaker-sections--pending-keymaker).
It changes no native method/result, generation-journal member, public refusal,
signing purpose or credential. Production bump remains
`bump_key_admission_unconfirmed` before journal/backend work. Normal create stays
register-after-active; independent create/retire gates remain unchanged.

These requirements bind a future PC2 implementation, including every supported
authority writer. They do not claim that today's binding/audit pair, confirmation
RPC or the internal message-state implementation supplies this authority.
The [composition conflicts](../UNRESOLVED_QUESTIONS.md#pc2-and-message-state-composition)
must close before selecting a combined persisted format or enabling PC2. The
[message-state contract](keymaker-msg-state.md) is preserved, not silently
extended. Its attestation ID T is distinct from the activation tuple below.

## 1. Stable fence and forward order

Let T be exactly `(uid,generation,registration_number,master_epoch,
predecessor_generation)` for the immutable provision effect. Both current
admission and the provisioned binding for that exact T MUST remain true through
the manager's durable active append. Later withdrawal still prevents unreleased
and subsequent Keymaker results; already released bytes cannot be recalled.

F MUST be a pre-provisioned root-owned regular single-link `authority.lock` in
a root-owned protected directory: directory mode 0750, file 0640, dedicated
service group, no station membership or service permission to replace entries.
The configured path and device/inode identities are protected for the authority
incarnation. Both owners use anchored directory descriptors, no-follow,
close-on-exec read-only opens, verify type/ownership/mode/link/device/inode and
take exclusive nonblocking Linux flock on a **distinct open file description**
per transaction. A dup/inherited descriptor is not independent exclusion; no
descriptor is passed to an exec/helper. Never create F on demand. Missing,
linked, aliased or changed objects close authority; replacement requires
quiesced recovery and fresh publication. Qualify read-only-descriptor exclusive
flock on the actual filesystem; a pathname is not proof of a common lock.

Keymaker order is journal gate -> data -> C -> F, where C is Store then enrollment
commit serialization, with required audit serialization arranged **before F**.
Keep the journal reader's early shared-gate release and no-upgrade rule. Manager
order is effects -> exclusive gate -> exclusive data -> F; it never takes C.
Release in reverse order, F before data/gate/effects. F is terminal: no holder
may acquire C, audit, effects, gate, data or implicit file/database locks, perform
RPC, inventory/account tools, wait for a service/operator or obtain external
evidence. In particular, an F reader cannot wait for the C held by a daemon
waiting for F. No locking Store/enrollment API may hide beneath that reader.

Preparation releases the short critical-section locks defined below. Network
proof acquisition and notifications run outside all locks; retaining a continuous
exclusion lease for fixed local preparation requires the separate §1.1 checks.
A separate local preparation read may take F alone and release it before querying
or other external work. Under terminal F,
the manager uses only bounded direct openat/fstat/read, closed metadata decoding
and the qualified local durability-consumption barrier. Final F acquisition,
root validation, local transaction/audit and actual handoff fit the original
**<=250 ms** reader data window; manager attempt/append/finish fits its original
**1000 ms** writer budget and **send-start + 2000 ms** observation bound. The
native two-second deadline is not enlarged. Retry/reconnect never renews any
budget. Cooperative clocks cannot interrupt a stuck sync: qualify latency or
refuse the path. An expired possible write retains its real outcome and hold.

### 1.1 Short critical sections and continuous exclusion leases

PC2 adopts the two-boundary requirement recorded in the landed
[A3c Q1 text](https://github.com/relux-works/swarma-user-manager/blob/a71d15a030b0e23ac3bf7d9a26ecad6efa1bea0c/spec/qualification-maintenance-journal.md#91-q1-recommendation--pending-curator-decision).
That pinned text still labels its recommendation pending; it supplies no runtime
qualification or waiver. The requirements here do not authorize an integration.

**Short critical sections:** no external, provider or service-manager calls under
manager effects/core, generation gate/data, recorder R or journal-append locks.
The final Keymaker C/F commit/append/release window is such a section: only
bounded local checks and local durable operations are permitted. No relay/helper
makes a synchronous wait unlocked. Terminal F's no-back-edge rule above remains
strict, including for root tools and recovery.

**Continuous exclusion leases:** native F/B, W, root-writer exclusion, closed
admission and qualification D form a separately enumerated boundary. Retain each
required lease continuously across both qualifier runs. Only explicitly reviewed
fixed local operations may run under a lease: each needs a fixed authenticated
target, bounded completion/failure time, and a transitive call/dependency graph
that never acquires or waits for a caller-owned exclusion lock. Provider and unit
observations require that same explicit review; no general provider/RPC allowance
is inferred. Any inner effects/core/gate/data/R/journal locks must be released
before such an operation. Lease permission never permits a call inside the final
C/F window. The platform F/B lease notation does not broaden terminal PC2 F.

The qualification parent MUST release D before launching or waiting for the
qualifier. The child acquires its own exclusive D; no held descriptor is inherited.
This is a qualification boundary, not a new Keymaker method or D interface.
A reservation snapshot may use the separately published D -> effects -> gate ->
data edge, with R and journal append excluded; no F/B/W/D/R acquisition from
inside lifecycle locks. It grants no reverse edge in the PC2 order.

Network proof acquisition and notification delivery remain outside **all locks**,
including maintenance leases. Dropping a required continuous lease to perform a
call is forbidden. If the required exclusion cannot compose with an unlocked
external phase, keep the path closed until its coordinator is reviewed and
qualified. Unknown continuity or callee dependency, or an exceeded deadline,
refuses with admission closed; neither an exception nor an extended budget is
permitted. A durable closed-admission/hold state is not a lock held across a call.

## 2. One authoritative transaction root

PC2 MUST replace independently authoritative binding/audit and admission/pin
publication with one recoverable root transaction. A refreshed receipt, status
sidecar or readable mirror is insufficient. Both services MUST use final root
publication as the authority point, never use a candidate early or fall back to
an old root while an intent/recovery obligation is outstanding. The committed
root binds actual protected policy/snapshot bytes; admission checks their
installed identity/digests, not just an `admitted` bit.

The required closed **logical PC2 metadata inventory** is:

```text
{version:"keymaker-authority/1",transaction_revision,previous_root_digest,
 root_digest,binding_commit:{version,digest,audit_seq,audit_hash},
 authority_incarnation,instance_id,boot_id,master_epoch,pin_policy_digest,
 registry_digest,custody_ready,withdrawal_counter,
 journal:{seq,hash},recovery:"clear",entries:[E]}
E = {uid,generation,predecessor_generation,registration_number,master_epoch,
 owner,provision_effect:{caller_uid,caller_generation,request_id},
 provision_pin_digest,pin_policy_digest,admitted,binding_status}
```

Every member is required and typed; reject duplicates, unknown members, coercion
and null except `previous_root_digest:null` at independently authorized genesis.
UIDs are uint32; generation tokens and durable incarnation are nonzero 32 lower
hex; request/process IDs retain their 32 lower-hex encoding; boot ID is canonical
UUID. Owner/epoch retain protected bounded strings. Revisions/counters are
positive JSON safe integers with explicit bootstrap, no reset/wrap/reuse.
Digests use `sha256:` plus 64 lower hex, except existing binding/audit/journal
digests keep their 64-hex encoding. `custody_ready` and `admitted` are booleans;
binding status is exactly provisioned, active, unbound or revoked. Entries are
complete retained bump reservation history sorted by unique registration number,
with live tuple/path uniqueness; ordinary bindings remain in the complete private
snapshot. Historical provision pin and current policy pin are distinct fields.

The root cap is **1 MiB and 4096 entries**, checked before allocation/publication,
charged with all histories/staging to the **single existing 256 MiB** budget.
No eviction of tombstones, native IDs, counters or recovery evidence. Root is
service-owned 0600 in service-owned 0700 state; only the trusted root manager
reads private metadata. Root-owned policy and attempt stores retain their owners;
there is no station/unprivileged observer filesystem export. No seeds, private
keys, chain codes, raw pins, operator documents or returned envelopes enter it.

The source design requires the candidate preimage to bind authority metadata,
excluding `binding_commit` and `root_digest` to avoid circularity; root digest
hashes CCJ-1 of the root without `root_digest`. S2 instead fixes its schema-2
body hash excluding only its own audit references. These are **not interchangeable
hash recipes**. The combined codec, artifact references, preimage and migration
are an explicit unresolved composition gate, not permission to add fields to
schema 2, weaken its closed reader or implement the logical inventory verbatim
under an existing schema tag. Preserve complete `messages`, original native-ID
namespace/results and S2's retained artifacts in the eventual combined model.

Advance transaction revision on every root commit. Advance the global withdrawal
counter on **every eligibility-affecting event**, including equal reload,
withdraw/re-add and restart publication: equal bytes cannot create an ABA match.
Audit-only/floor-only growth need not advance that counter unless eligibility
changes, but requires exact committed continuity. The manager prepares permitted
policy/counter/epoch/incarnation/instance and T outside its final lock window;
under final F it rereads the complete committed root/recovery barriers and requires
`admitted=true` and `binding_status=provisioned` for that same T/owner/effect.
Changed eligibility counter needs fresh unlocked preparation, even for equal
application bytes. Verify journal hash/ancestry, not sequence alone.

## 3. Participating writers and durable ordering

Every authority commit **and actual result release**, including exact replay,
MUST take the applicable forward C/F order and honor both owners' holds. This
includes provision/promotion/removal, register/revoke/unbind/retirement, registry,
epoch/custody/config changes, current-T certification phases and retained results,
audit/floor publication, migration/recovery and process-instance publication.
All policy installers participate: root pin install/edit/remove/reload/re-admit,
trust-anchor replacement, generation maps, UID/name/audience/executable policy,
signed enrollment high-water, approvals and consumption history. Stage and verify
external evidence outside the short critical sections and apply §1.1 to any
continuous lease; network evidence remains outside all locks. Live policy
installation occurs under F in the same root transaction. No replace-first/notify-later installer is permitted.

Reserve the complete worst-case bytes and audit headroom **before intent**.
S2 reserve -> intent/pending fence -> prepared -> issued -> published -> active
ordering and no-T1-fallback remain requirements; each durable phase must compose
with the same authority root, not a second independent commit point. No issuance
while creating; no certification intent promotes a binding or a current T.
Qualifying publication/evidence follows §1.1's two boundaries, followed by
fresh bounded local final validation. Shared budget accounting includes roots,
both owners' retained attempts/holds, message history, simultaneous snapshots and recovery copies.
S2's internal reserve alone is not proof this larger transaction fits.

For each authority transaction under its C/F window:

1. Check the manager writer/attempt/recovery ledger and local intent. Unresolved
   obligations close conflicting authority. The original live manager alone may
   make its one exact pre-write attempt after all final checks, with its own
   required pending marker; restart/retry must reconcile first.
2. O_EXCL-create the exact intent binding transaction ID, old/new root
   digests/revisions/counter and every participant digest. Checked full write,
   file fsync, checked close and parent fsync precede **any live artifact change**.
3. Durably append the audit commit and install exact private/policy candidates:
   full checked writes, file fsync/close, same-filesystem rename and parent fsync
   for each participant. Retain partial/prior evidence. Multi-file error is
   unknown, never permission to simulate old-state rollback.
4. Write/fsync/close the exact new root; rename into its authoritative slot and
   fsync its directory. Validate linked snapshot/audit/policy and all guards.
   Only then clear intent and fsync that directory. Only complete durability may
   open authority/report success; readable root bytes are insufficient.

The transaction identity is SHA-256 of CCJ-1 of
`{type:"keymaker-authority-tx/1",base_root_digest,next_revision,candidate_root_digest}`,
prefixed `sha256:` and fixed before live writes. Review acyclic candidate/root/
audit preimages with the combined format; no hash authenticates its own future
commit. Exact dedup stays `(caller_uid,caller_generation,request_id)`, with original
canonical arguments, registration, result and audit; never a second result cache.

Migration MUST be one explicitly reviewed, quiesced upgrade path for legacy and
already schema-2 stores, preserving full message histories, allocator/native IDs,
pins/high-water, audit, floors, reservations and every outstanding obligation.
Unknown/partial transactions are not clean migration inputs. Retain exact old/new
bodies and decision; exclude older/restored writers and advance the independently
protected minimum-reader/authority floor before serving. Floor 2 alone is not PC2
readiness. Do not reset counters/epochs or strip fields to downgrade. Pending
format/preimage/migration conflicts keep PC2 disabled rather than choosing either
independent migration as if it implemented both contracts.

## 4. Durable attempts, recovery and withdrawal

An authenticated confirmation is preparation, not an activation lease. Under F,
with pending correlation still valid, final validation and the manager's durable
activation-attempt record consume it once into the **exact local append attempt**.
The closed attempt inventory, immutable attempt ID/ordinal and hold derivation are
the accepted design's [K4/A2](https://github.com/relux-works/swarma-user-manager/blob/549b4aa89184c974331d1be1af151cec9768658e/spec/activation-order.md#attempt-and-hold-identities-a2),
not new gen-journal or RPC fields. It binds T/owner/effect, source root/counter/
incarnation, prepared tail, intended active hash, boot/instance and retained
pending/absent/durable outcomes. Write/file-sync/parent-sync it **before** journal
write. Hold F through append, journal and directory sync, exact chain verification
and writer-finish durability, releasing F before the journal pair.

Before consumption, disconnect/reconnect, service restart or uncertain correlation
invalidates the observation: a fresh unlocked query/challenge/ID is required.
After consumption, process death never proves abort: the exact attempt may finish
once using unchanged durable facts within the original budgets, or remain held
for exact resolution. Restart publication waits for F and obligation resolution.
F cannot prove continuous socket/process liveness through fsync; if that is a
required interpretation, refuse until the joint handoff decision closes.

Manager attempt evidence is root-owned, service-group-readable 0640 in a protected
root-owned 0750 directory, never daemon-clearable. Retain stable immutable hold
identity derived from the original activation/authority transaction, not PID,
flock ownership, pathname or a new recovery process. Process death, absent marker,
lost reply and elapsed TTL are not absence/abort/release proofs. A durable active
append with uncertain finish/cleanup is **known append, uncertain cleanup**;
without proven durability it is **unknown outcome**. Both retain any joint hold;
neither authorizes a duplicate active append or deleting the reservation.

Only the authorized root recovery coordinator may release an uncertain hold.
Exclude serving/old writers. Prepare network evidence outside all locks;
fixed local recovery observations under continuous exclusion require §1.1 review.
Open the offline Store/enrollment lifetime exclusion before taking effects ->
gate -> data -> C where repair requires it -> F. No RPC to a running daemon.
Retain and sync the root-owned append-only recovery ledger in this order:

1. `open`: bind recovery ID, original holds/intents, expected roots and resolution;
   file and directory fsync before repair. A successor resumes the same session.
2. Prove exact absent/durable outcome from full journal/Store/policy continuity,
   stopped writers/no in-flight sync and independent floors; repair only exact
   retained bytes and sync every participant/directory. Persist exact resolution.
3. `release-prepared`: bind hold set, resolution digests, post-repair roots/counters/
   incarnations and journal floor; sync. Only then perform each owning protocol's
   permitted marker cleanup and parent sync; retain all attempts/outcomes.
4. Revalidate complete artifacts/continuity/no flights under F; append linked
   `released` and sync its directory **last**. A partial record, wrong hold set,
   later open session or uncertain final durability leaves the same hold closed.

Readers under F must establish the qualified local file/directory sync barrier
and linked artifacts before trusting readable `released` bytes. Qualify read-only
descriptor sync permissions/latency for both principals; inability stays closed.
No reader takes C/RPC to consume this ledger. S2 offline message reconciliation
cannot independently release an authority/manager hold, re-sign, regenerate a
result, or clear its separate pending-certification fence.

Withdrawal may be requested while held, but MUST NOT report completion until
append absence/durability and its own durable tombstone/root/audit are proved.
Append winning orders first; withdrawal winning prevents append/promotion/release.
Affected issuance and cached-result disclosure remain closed through uncertainty.
Crash/storage recovery may block withdrawal completion **indefinitely**. Normal
budgets bound clean contention, not crash recovery or end-to-end revocation.

## 5. Incarnation, restore and independent custody

Boot ID, random RPC instance and durable authority incarnation are distinct.
Routine restart reconciles holds, independent floors and old-instance exclusion,
then publishes a fresh instance and counter under F. Restore/re-enrollment/epoch
or continuity loss additionally requires independently authorized incarnation
continuity, never a reset or a new empty root. A local inode/hash/random instance
does not prove latestness.

Before dependent use, independent custody outside the restored failure domain
MUST retain every authority root revision/digest/incarnation/counter, accepted
journal seq/hash and unresolved obligation. Verify independently current
continuity plus old-instance exclusion; startup-only or lagging backup anchors,
or an anchor restored with its root, are insufficient. Without this evidence
there is **no eligible F authority**: leave PC2 closed.

Honest mode A remains in force and cannot detect coherent whole-state rollback,
even in the same boot/TTL with restored consumed approvals. PC2 supplies no local
fix for that residual. Future option C still needs WC1–WC5, separate complete-state
consumer stream, off-node trusted checkpoint, exclusion and qualified recovery.
Registry publication WC1 evidence is not a complete Keymaker-state witness.
Include root/counter/incarnation, exact intents, message artifacts and cross-owner
attempt/hold/recovery histories in its versioned inventory. No implicit C switch
or automatic A fallback is permitted.

All witness/network preparation and recovery evidence work occur outside **all
locks**. A future coordinator quiesces dependent admission across external intent,
local root commit and matching external resolution; intent precedes local change,
resolution precedes release. It must compose with F/C and both owners' holds,
not call a witness under them. Retain the durable closed-admission/hold state;
§1.1 forbids dropping a required continuous exclusion lease to make a call. If
these boundaries cannot compose, WC5 stays closed rather than relaxing either.
Qualified custody/protocol/latency remains open.

## 6. Paired qualification and narrowing plants

All rows and the eight named upstream cases remain **PENDING / NOT RUN**. Real
separate reader/manager/invalidation/recovery processes and deterministic barriers
at validation/write/fsync/release are required. Goroutine/mock-only runs, parser
crashes, unapplied plants or unrelated setup failures prove none of these claims.
Each plant must fail the named row/case at its intended postcondition while the
control passes; report any survivor as uncovered. Isolated fault fixtures do not
qualify actual power loss, privileged exclusion or filesystem sync semantics.

| Row / path | Forbidden outcome / required negative postcondition | Nearby positive control | Upstream named cases | Narrowing plant |
| --- | --- | --- | --- | --- |
| KR1 reader/authority | Wrong T/predecessor/owner/effect/pin, stale mirror or only one true fact admits; no active append | Exact complete committed two-fact view and durable floor admits once | PC2AuthorityNotProjection; PC2WithdrawalWins | P-KR1_PROJECTION: substitute cached projection for root |
| KR2 reader/incarnation | Old inode/instance/anchor or death-cleared hold admits; retained root/attempt unchanged | Reconciled fresh instance and independently current root passes | PC2IncarnationRestore; PC2FenceDeathUnknown | P-KR2_DROP_HOLD: treat marker absence/death as release |
| KR3 reader/order/budgets | Shared OFD, reverse edge/RPC, early F release or deadline renewal succeeds; no forbidden call/write | Distinct OFDs and forward order complete in original window; clean contention yields busy | PC2NoRPCOrReverseOrder; PC2BudgetsNotRenewed | P-KR3_RELEASE_EARLY: unlock F before journal fsync |
| KI1 issuance/release | Withdrawal winning release emits key/proof/signature; no output or retained-result disclosure | Release winning first verifies; later requests refuse without erasing active history | PC2WithdrawalWins; PC2AppendWins | P-KI1_SKIP_RELEASE_F: omit F in actual transport handoff |
| KI2 issuance/replay | Changed counter/generation/epoch bypassed by retained ID or old challenge refreshes time; original result preserved | Unchanged live authority returns only original same-ID result in its original window | PC2CorrelationNotReplay; PC2AuthorityNotProjection | P-KI2_REPLAY_BYPASS: return cache before live authority check |
| KI3 issuance/unknown | Partial root/audit/append/recovery releases anything or death implies abort; same hold retained | Exact durable reconciliation permits a fresh valid operation once, no invented result | PC2FenceDeathUnknown; PC2IncarnationRestore | P-KI3_READABLE_RELEASE: trust unsynced released bytes |
| KP1 promotion/authority | Creating/revoked/unadmitted target promotes; reservation remains inert | Exact active T, resolved attempt and current two facts promote durably before use | PC2AuthorityNotProjection; PC2WithdrawalWins | P-KP1_PROMOTE_CREATING: accept creating as active |
| KP2 promotion/race | Promotion overwrites prior withdrawal; no promotion or release | Append/promotion wins then later withdrawal fences all subsequent release | PC2AppendWins | P-KP2_SKIP_COUNTER: ignore withdrawal-counter ABA |
| KP3 promotion/recovery | Death/restore/replay creates second registration/active/effect; retain exact histories | Exact outcome resolves once with fresh correlation; consumed attempt may finish once in original budgets | PC2FenceDeathUnknown; PC2IncarnationRestore; PC2CorrelationNotReplay | P-KP3_RETRY_NEW_ID: retry uncertain append under a new identity |

Under PC2NoRPCOrReverseOrder, pair a reviewed fixed local lease operation that
retains exclusion and releases inner critical locks with rejection controls for
an external/provider/unit call inside the C/F window, an unauthenticated target,
unknown transitive dependency, continuity loss and an expired lease-operation
budget. Rejection retains closed admission and performs no active append/release.
P-KR3_LEASE_BYPASS permits an unreviewed lease call; the test must catch the
forbidden call even if it returns successfully. Pair independent parent/child D
handoff under continuous F/B/W/root-writer exclusion with P-KR3_INHERIT_D, which
passes a held D to the qualifier; require no child launch under inherited D and
retain admission closed. These are future qualification controls, not runs here.

Each real policy writer, including root pin installers, needs an F-omission plant
under KR1/KI1; also plant skipped audit/participant/directory sync, old incarnation,
observation reuse and reset budgets under KR2/KR3/KI2/KI3. Test process death on
both sides of observation consumption while the manager owns F: before it,
observed disconnect/unknown correlation refuses with no attempt/active; after it,
preserve the consumed attempt and hold, with a valid once-only completion control
despite Keymaker death. Kill manager/recovery after marker unlink and before
final directory sync: absence never clears the hold. Paired controls prove
absent/stopped-writer recovery and known-durable cleanup without duplicate append.

## 7. Refusals and remaining gates

No PC2 public code is added. Clean local contention uses `busy`; clean deadline
expiry uses `request_deadline_exceeded`; uncertain local audit/root commit uses
`audit_unavailable`. Preserve precise generation/enrollment/custody/revoke/capacity
codes. Restore-closed source remains `generation_source_unavailable` (with existing
latched `generation_source_fenced` semantics where applicable); selected future C
uses its proposed `state_witness_unavailable`. Manager pre-write currency/correlation
failure is `bump_key_admission_unconfirmed`; retain native journal errors after
possible write and distinguish unknown durability from known append/uncertain
cleanup. Refusals disclose no success or signing material. No normal retry clears
a hold, unsets pending or creates a new effect.

Three joint gates remain: observation absorption versus RPC correlation (no
continuous-liveness claim), independently current restore custody under honest A,
and acceptance/qualification of possibly indefinite withdrawal-completion blocking.
The four S2 composition conflicts, all-writer/root-tool exclusion, combined closed
codecs/migration, append-lifetime journal guard, bounded metadata/sync and latency,
cross-owner coordinator and real process/platform evidence also remain open.
PC1 observer/bootstrap, existing time-provider/watermark gates and WC1–WC5 remain;
this specification closes none by prose or unchanged-code build results.
