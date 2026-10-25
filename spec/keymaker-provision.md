# Pre-active binding provision and confirmation

Status: **spec only; not implemented or activated**. Requirements below are a
candidate extension to [base §§3, 5, 7–8, 11 and 15](keymaker.md), not new daemon
capabilities. Ordinary `register` still requires an active target. No endpoint,
key purpose, signed document or enrollment wire member is enabled here.

The account lifecycle owner is the user-manager repository, pinned here to
**`2fba23868045b37143ef0156c0e88d1d340d9cc3`**:

- [spec/stations-v0.md §6.2](https://github.com/relux-works/swarma-user-manager/blob/2fba23868045b37143ef0156c0e88d1d340d9cc3/spec/stations-v0.md#62-keymaker-handoff-and-activation-order)
  requires old removed → reviewed re-admission → new binding → new active.
- [spec/generation-journal.md §4](https://github.com/relux-works/swarma-user-manager/blob/2fba23868045b37143ef0156c0e88d1d340d9cc3/spec/generation-journal.md#4-lifecycle-and-generation-bump)
  owns states, fresh tokens, retained history and non-overlap;
  [§6.1](https://github.com/relux-works/swarma-user-manager/blob/2fba23868045b37143ef0156c0e88d1d340d9cc3/spec/generation-journal.md#61-reader--with_active)
  owns the final reader ordering.
- [docs/station-core.md](https://github.com/relux-works/swarma-user-manager/blob/2fba23868045b37143ef0156c0e88d1d340d9cc3/docs/station-core.md)
  keeps production bump closed as `bump_key_admission_unconfirmed` pending this
  joint contract and backend qualification. Create and retire are independent.

The conditional [PC2 authority contract](keymaker-pc2.md) is now a Keymaker
requirement for the activation path: stable F, one root/intent transaction and
exact-attempt recovery. Its closed persisted format must compose with S2, not
extend schema 2 silently. The three joint gates and composition conflicts remain
[open](../UNRESOLVED_QUESTIONS.md#pc2-and-message-state-composition); production
bump stays refused. No native hello/result field changes follow from PC2.

## 1. Binding states and fresh identity

Add `provisioned` to the binding statuses, distinct from journal `creating`.
A provisioned binding reserves one exact `(uid,generation)` and identity path
but grants **no key issuance or use**. It retains base §3.2's owner, lifetime,
registration number, master epoch and registry revision. A protected provision
extension records the predecessor generation, original registrant/effect ID,
the admission pin digest and verified creating journal checkpoint. This
extension is durable service metadata, never a new generation-journal member.

Uniqueness covers **active and provisioned together**, per `(uid,generation)`
and `(master_epoch,path)`; they cannot coexist as separate reservations for
either key. The registration counter and all historical path/token evidence
survive restart. Existing unbound records and revoke tombstones are retained.

| From | To | Exact condition |
| --- | --- | --- |
| No binding | `provisioned` | Authorized §2 transaction; exact target creating, predecessor removed, policy re-admitted |
| `provisioned` | `active` | Exact target observed active under `with_active`, qualified activation ordering and unchanged binding/policy; durable promotion before any issuance |
| `provisioned` | `unbound` | Verified target removed before activation; preserve its registration, effect result and path history |
| `provisioned` | `revoked` | Existing authorized revoke, same lifetime/operator-act gates, tombstone and release ordering |

`retiring`, unknown evidence or a local timeout never promotes a binding.
A previously active incarnation follows existing retirement/revoke rules;
this adds no journal edge. If a restart sees target removed after an uncertain
interval, replay the full retained history: an intervening active state must
not be misreported as a never-active rollback. Unknown history stays fenced.

**Bump must not carry over old keys or bindings.** The new token is generated
by user-manager's CSPRNG/collision check, never Keymaker. For this bump-only
operation the operator must select an explicitly approved, **previously unused
purpose-1 identity path in this master epoch**, including no prior active,
unbound or failed-provision reservation. The protected append-only registry allocates a fresh name/index
before the RPC; requests never allocate names. Old persistent same-path
re-registration in base §3.2 would reproduce the old key and is therefore not
this bump operation. A missing fresh approved identity fails closed, not to
same-path reuse, generation hashing or a fifth path component. K3's same-path
stable-key decision is unchanged: the bump selects a different identity path.
No account key, home cache, token or old connection supplies successor authority.
Any required account/login token must be obtained fresh through its owning
service after activation; this contract neither issues it nor claims to recall
an already released old token.

## 2. Operator-only provision operation

**Recommend a separate `provision` method on surface B.** Its params are exactly
`{target_uid,target_generation,predecessor_generation,owner,names,lifetime}`.
Names/lifetime/owner and purpose-1 resolution use base §§4–5. UID follows the
protected enrollment-pin UID range; generation strings are nonzero 32 lowercase
hex digits. Target and predecessor tokens must differ. Predecessor is required:
this method is for same-account bump, not ordinary create.

Only the configured operator UID/generation may call it. The **caller remains
active** under base §3.1, including hello; the special target is creating. No
station, dispatcher or observer may provision, even itself. Ordinary `register`
gets no provisioning flag and keeps its active-and-unbound target requirement.

Admission order after the native frame/peer/active-caller/method checks:

1. After schema/caller/role validation, compare any retained caller-scoped ID
   with the complete method/params; changed arguments refuse request_conflict
   before target-state checks or effects. Exact recovery still revalidates below.
2. Verify complete authoritative journal/floor, exact target token in creating,
   and its immediately preceding incarnation for this UID in removed. Invalid
   overlap/history fences the source; never treat an unchecked pair as evidence.
3. Verify current operator-reviewed local enrollment pins admit this exact
   target token (§4); capture the pin digest before preparing the binding.
4. Resolve approved names and fresh path, owner, lifetime, epoch, uniqueness,
   replay identity and capacity. Fresh-path checks apply to new mutations; an
   exact replay validates its own original reservation instead of demanding
   that reserved path be unused again. No derived key or public key is returned.
5. Under the final journal/read guard and local commit lock, recheck caller
   active, target creating, predecessor removed, current pin and all binding
   conditions. Atomically commit registration, provision metadata, successful
   audit and retained result before response release. Pin reloads, binding
   revoke and epoch changes use that same local commit ordering.

Result is exactly `{target_uid,target_generation,registration_number,
master_epoch,status:"provisioned",provision_effect}`. `provision_effect` is
`{caller_uid,caller_generation,request_id}` of this mutation; it is correlation,
not a credential. It contains no public/private key, signature or login token.
The operator supplies this authenticated metadata to user-manager's protected
pending handoff intent, outside journal locks. A station cannot supply it.

Use base §5's durable deduplication key `(caller_uid,caller_generation,request_id)`
and complete canonical method/params comparison. Exact retries return the
original committed result with the same registration; changed args/method
refuse `request_conflict` without another effect. Fresh caller/target/policy
checks still apply. Once target is no longer creating, even an exact provision
retry refuses `provision_state_invalid`; the original result stays retained.
It is not reinterpreted as a fresh confirmation or a second provision.
A nonmatching predecessor token in otherwise valid history is
`generation_mismatch`; omitted/malformed arguments are `request_malformed`.

**Alternative:** explicit `register` provisioning mode could reuse more intake,
but changes the familiar active-target predicate and requires an additional
closed schema/result branch. Separate methods keep that exception reviewable
and prevent a missing/default mode from accidentally granting pre-active use.

## 3. No issuance before active and lock ordering

While the journal target is creating, `sign` on A, `pubkey` on either surface,
`sign_registration` and the proposed K3 `sign_message` all refuse. Fresh or
previously open target connections receive base `generation_inactive` (native
typed refusal or SSH failure); no method, key listing or cached result bypasses
it. An internal path reaching an unpromoted provisioned binding refuses
`binding_provisioned` before use. Observer metadata in §5 is not key lookup.
Provision itself reserves metadata; actual child derivation is deferred until
qualified active use. No pre-active certificate/helper proof/message signature
or public-key response is issued under the reserved binding.

Promotion is observed only under **`with_active`**, revalidating exact current
binding, policy, epoch, revocation and connection pin, plus conclusively
resolved activation attempt and the admitted root/counter/incarnation under C/F.
A legitimate intervening transaction/restart may advance the counter; require
proved nonregression and all current facts, not historical counter equality.
Durably promote before
first use; an unknown promotion commit fences all issuance. A timer, response
receipt, status cache or account's existence cannot promote it. Activation
never makes an old connection adopt the new token; connect and authenticate
anew. Every issuance and retry retains the final release fence.

Provision/confirmation require a distinct **metadata-only creating guard**.
It uses the published reader protocol, re-reading the same verified history
and floor, but requires target creating instead of granting active authority.
It must also validate the operator/observer caller active in that snapshot.
This is a proposed semantic extension, **not a claim that the existing
`with_active` adapter accepts creating or that a new journal API is shipped**.
It permits only bounded metadata commit/audit/response, never a signing callback.

The pinned journal [§5 WithEvidence contract](https://github.com/relux-works/swarma-user-manager/blob/2fba23868045b37143ef0156c0e88d1d340d9cc3/spec/generation-journal.md#5-reader-algorithm-durable-high-water-and-refusals)
provides a verified, data-locked multi-tuple window. `WithEvidence` itself does
not admit identity pairs: the consumer checks the caller with `View.Active`
and target/predecessor lifecycle with `View.Generation` in that same window.
A creating target is never admitted as active; `WithActive` retains its active
predicate. Neither primitive alone qualifies the Keymaker adapter.

Use journal gate → data → C → terminal F for PC2; gate/data acquisition is
nonblocking, no lock upgrade, and the shared data window including validation,
floor persistence, local transaction/audit and response handoff is **<=250 ms**.
Honor writer.pending, retirement reserve and all source fences. Remote work
finishes first. No Keymaker state/journal lock is held while waiting for
user-manager or an operator. User-manager persists handoff intent, releases
**all its journal/effect locks**, and queries outside them. Afterward it
reacquires its own locks and revalidates the same pending effect, reservation,
exact identities, fences and fresh inventories. Cross-process local ordering
must be qualified; a callback name does not establish it (§5.3). PC2's manager
order is effects -> exclusive gate -> exclusive data -> F, released in reverse.
Its bounded direct root read takes no C, audit/Store/enrollment mutex or implicit
file lock. F-only local preparation reads release F before any query. Every
authority commit/release, including root pin installers, participates. Qualify
F's protected stable inode, distinct OFDs and all-writer exclusion first.

## 4. Reviewed enrollment re-admission before provision

The required order is old removed → fresh creating reservation → operator
review/install of new local generation admission → provision → verified
confirmation and renewed inventories → new active. No temporary active entry
is allowed to obtain the binding or confirmations.

`PinConfig.generations` is actually a **map**, not a list of tokens:
`{"<canonical decimal UID>":"<one nonzero 32-hex generation>"}` in protected
local pin config ([implementation shape](../internal/enrollment/config.go)).
Replace that UID's old token with the reviewed new token; it cannot admit both.
No new registrar enrollment/1 member, host key, registry revision or signed
registrar document is required solely for a generation change. Changes to
host key, uid_map names or registrar trust retain their ordinary review flow.
The registrar `revision` field must not be repurposed as a local policy counter.

Both provision and confirm validate the protected current policy, including
its verified enrollment snapshot/uid_map and any unsupported exe qualification.
Absent/mismatched UID generation entry is `generation_mismatch`. Missing trust
files return `enrollment_unavailable`; invalid/rollback evidence returns
`enrollment_unverified`; uid/name/exe restrictions retain their base §8 codes.
No binding is committed without re-admission, and no confirmation substitutes
for the missing policy fact. The operator-controlled config is the trust
boundary for review; an RPC assertion of human review is not evidence.

Store `pin_digest = "sha256:" || lowercase_hex(SHA256(CCJ-1(parsed_pin_config)))`
of the complete validated protected JSON document used at provision. Confirm
returns this historical digest and the current validated document digest;
these are local policy provenance, not signatures. Current policy must still
admit the exact tuple. A later unrelated config change need not rebind if it
continues to admit it; a historical matching digest alone never authorizes it.
Issuance following promotion must also recheck this generation admission;
removing it closes this provisioned binding's authority even if journal active.

## 5. Authenticated local confirmation

### 5.1 Query and principal

**Recommend `confirm_provision` on the existing surface B**, a metadata query.
Protect the socket directory and verify server ownership and kernel peer UID
against the installed Keymaker principal. Server authenticates caller with
SO_PEERCRED and the current active generation; no executable-name, claimed
UID, root exemption or bearer-field fallback. Permit only the configured
operator or an explicitly configured **read-only observer principal**, scoped
to this owner/target set. That observer cannot provision, revoke, sign, list
keys or mutate pins. User-manager's adapter must actually use this qualified
active caller principal; its current execution UID is not silently exempted
from base generation checks. Until the adapter/principal is qualified, refuse
the bump; this slice installs neither.

Params are exactly `{target_uid,target_generation,registration_number,
master_epoch,challenge}`. The first four must match the protected pending
handoff metadata from the operator. Challenge is a fresh independent CSPRNG
128-bit value encoded as 32 lowercase hex; top-level request_id remains a
separate base §7 ID. No caller-supplied "valid" or "admitted" flag is accepted.

Successful result is exactly the following metadata (schema notation):

```text
{version:"keymaker-provision-confirm/1",challenge,
 target_uid,target_generation,predecessor_generation,owner,
 registration_number,master_epoch,binding_status:"provisioned",provision_effect,
 admission:{uid,generation,provision_pin_digest,current_pin_digest},
 journal:{seq,hash},instance_id,boot_id,observed_boottime_ms}
```

All object members above are required and closed, including nested objects.
Tuple fields use §2 encodings; registration_number is a positive JSON safe
integer; owner/master_epoch are the exact protected nonempty strings, bounded
by the native frame. Provision effect uses uint32 caller_uid, its exact
32-hex generation and 32-hex request_id. Pin digests are `sha256:` plus 64
lowercase hex, journal seq is a positive safe integer, hash is 64 lowercase
hex. Boot ID is the canonical lowercase UUID from the local kernel;
observed_boottime_ms is a nonnegative safe integer. Unknown/missing fields,
wrong types, invalid encodings and mismatched identity values cannot compare
equal by coercion. Challenge and instance_id each have exactly 32 lowercase
hex digits. Response version is the literal shown, not a signing domain.

The observer receives **two separately verified facts** in one consistent
read window: admission's exact UID/generation currently permitted by pins,
and the exact durable provisioned binding/effect/registration/epoch made after
admission. One fact never supplies the other. The complete source checkpoint
is its safe-integer seq and lowercase 64-hex chain hash. Instance ID is a fresh
32-hex CSPRNG service-start identifier; boot ID and CLOCK_BOOTTIME milliseconds
come from the trusted local host, not station data. Confirm validates custody
readiness for this epoch without deriving or releasing keys, and refuses
unknown transactions, missing predecessor evidence or untrusted service state.

### 5.2 Freshness, retries and consumer verification

User-manager records local boot ID and CLOCK_BOOTTIME **before sending** a
query. It verifies authenticated endpoint, echoed native ID and challenge,
version and closed schema/types, both facts against the pending exact tuple,
registration/epoch/owner/provision_effect, and **predecessor_generation against
the predecessor generation of the consumer's protected pending effect**.
For `journal:{seq,hash}`, independently verify the journal's complete chain:
the checkpoint's exact hash must occur at its stated sequence, and the
consumer's preserved checkpoint must be an ancestor at its exact hash.
A checkpoint later than the preserved floor must extend that verified chain;
`seq >= floor` alone is insufficient. Unknown ancestry or an equal-sequence
hash mismatch refuses confirmation. All target/status facts must remain
creating/provisioned. Observed boot must equal its own current boot; observed
time must lie between local start and receipt. The receipt may be used once
for this pending effect, only before **start + 2000 ms**, with continuity of
boot/time/reservation and fresh inventories. This bound includes transport
and intervening work; the observer must query again if it cannot reach the
activation check in time. A future observation, reused challenge or changed
service instance during pending correlation refuses. Persist pending correlation
and its exact durable consumption. Before consumption, consumer/service restart,
boot change, lost response or uncertain correlation requires a **new query**,
never importing old receipt bytes. Once a durable attempt may have consumed it,
reconcile that exact obligation first; a new query never proves it absent or
authorizes a second append. Unknown consumption remains recovery-held.

**Recommend pinning the service instance from the confirmation result only.**
Native `hello` continues to return only `{version:1}`; do not expect or add an
instance field there. On a newly authenticated connection, the consumer pins
`instance_id` only after fully validating the first fresh confirmation result,
including its challenge, tuple, predecessor and checkpoint. Persist that pin
with the protected pending correlation, bound to this connection and query;
subsequent correlated responses must match it exactly. It is not a durable
cross-connection trust pin. Before durable consumption, any disconnect/reconnect
invalidates that pending correlation even if the next result claims the same instance ID. A service
restart or changed instance ID also invalidates it. Retain the effect intent,
but discard the observation and obtain a new request ID/challenge and fully
verified result on the new authenticated connection before pinning anew.
A retained old result cannot re-establish the pin. After the qualified durable
handoff below, these invalidation rules do not abort an already consumed append
attempt; no old bytes may create a different attempt or refresh its budgets.
PC1 must qualify the real
observer and protected operator-to-manager handoff, not station-supplied
expectations. Instance equality, including an unchanged instance on a live
connection, **does not prove currency through the active write (PC2)**.

A confirmation query has no binding effect but retains its result/arguments
with audit under the caller's ID for bounded exact retry semantics. Same ID
and same args can only recover the **same observation**, never a refreshed
clock/challenge; changed method/args is `request_conflict`. Replay disclosure
still needs current caller/target/pin/binding authority and the original
freshness window, otherwise `request_expired` or the precise authority code.
Service replay additionally requires the stored boot/instance to match the
current service boot/instance, otherwise request_expired. Retained-ID conflict
comparison precedes target checks here too, after schema/caller/role admission.
For service replay disclosure the cap is observed_boottime_ms + 2000; the
consumer's start-based bound is stricter and must still be checked.
No automatic ID reclamation is added. A new observation needs a new ID and
challenge. Rates/capacity include queries, retries and refusals.

A wrong target token is `generation_mismatch`; wrong expected registration
or epoch is `binding_conflict`. Consumer-received wrong challenge, tuple,
registration, epoch or provision_effect, stale or replayed evidence is not success:
user-manager returns its own `bump_key_admission_unconfirmed`, without active
append. It must not adopt values from a mismatched response as new expectations.

### 5.3 Observation is not an activation lease

**A fresh authenticated query is an observation, not a lease or an atomic
cross-service transaction.** Challenge, local boot/time and a short TTL limit
replay; they do not prevent a policy withdrawal, revoke or epoch change after
the reply and before active append. User-manager's published §6.2 requires
confirmation validity through activation and revocation ordering. The joint
adapter **must serialize or otherwise prove currency of both facts through
the final active append**, without holding its locks across a Keymaker RPC.
Neither a cached response nor an extra last query proves this property.

The [PC2 contract](keymaker-pc2.md) selects the conditional stable local F and
authoritative root/intent ordering; implementation and qualification remain
absent. User-manager prepares a fresh correlated observation outside all locks,
then under final F rereads both exact committed facts, counter/epoch/incarnation/
instance, policy, ancestry, guards and original budgets. Its durable activation
attempt consumes that observation once **before** journal write and keeps F
through append, file/directory sync, verification and normal finish. No RPC occurs
under effects/gate/data/C/F. The existing check-only AppendPrepared callback or
a caller defer releasing F after journal unlock is not an append-lifetime guard.

Before consumption, observed disconnect/restart/uncertain correlation refuses and
requires fresh unlocked preparation. After it, unchanged durable facts support
only that exact attempt within original budgets: Keymaker death cannot prove
abort, refresh a pin, reset a deadline or release a hold. Restart publication
waits for F and obligation reconciliation. Continuous process/socket liveness
through fsync cannot be inferred from F or a PID. Joint acceptance/qualification
of this observation-absorption boundary remains open; if continuous liveness
is instead required, preserve refusal rather than weaken it. Until all gates
close,
**`user.bump` remains closed as `bump_key_admission_unconfirmed`**. Independent
create/retire flows remain available subject to their existing gates. Even if
a journal active append races later withdrawal, Keymaker must still release
no key operation after current policy/revoke/epoch checks fail. That fail-closed
issuance limit does not retroactively make the activation confirmation current.

**Alternative:** a signed confirmation could cross process boundaries without
trusting a live socket, but still needs challenge/currency/replay and activation
ordering. Purpose 2 is registrar-built proofs only; purpose 5 is message-key
attestations only; neither is widened. No authorized confirmation signer or
new purpose has been selected, so signed receipts are not this contract.
Local authentication suffices for the recommended same-host observation.

## 6. Failure, recovery and create

| Interruption / refusal | Required state and recovery |
| --- | --- |
| Before old removed; overlap or stale token | No successor provision/activation. Valid non-creating target: `provision_state_invalid`; wrong token: `generation_mismatch`; malformed/overlapping journal: `generation_source_unavailable`. Old generation is never implicitly retired by Keymaker. |
| Old removed, before pin install | Old stays dead; new creating stays fenced. Operator may explicitly re-admit; no automatic UID inheritance. |
| Pins installed, before provision commit | No binding or issuance; same provision ID/args may retry under current evidence. Pin membership alone grants no key. |
| Provision commit outcome unknown / acknowledgement lost | Fence affected state, reconcile actual durable outcome. Keep any committed binding/result and recover exactly under same ID/args without another registration; a proven uncommitted outcome has no binding. Never delete an uncertain committed effect or retry under a new identity. |
| Bound, before confirmation or active | Restart preserves provisioned reservation, original registration/effect and policy provenance. Re-read full journal; while creating, no issuance and a new confirm query is required. |
| Unconsumed receipt lost/stale or caller crashes | No activation from cached bytes; new challenge/query outside locks after resolving any uncertain consumption. Same-effect recovery never allocates another successor token. |
| Consumed attempt; process death, response loss or append/finish error | Preserve exact attempt/hold. Unknown without proven durability and known durable append with uncertain cleanup are distinct; neither permits automatic abort or duplicate append. Resolve once under the root coordinator, retaining original outcome/effect. |
| Timeout while creating | Timeout withdraws confirmation usability, **not** generation state. Keep reservation inert and request bounded reconciliation; no timer promotion, inferred removed or silent history deletion. User-manager verifies rollback, writes creating→removed, then Keymaker durably marks unbound. |
| Creating→removed or explicit revoke wins | Never activate; retain unbound record or authorized revoke tombstone and all effect IDs. Revocation cannot be undone by later journal activity. |
| Crash after active append before Keymaker promotion | Verify exact active journal and qualified ordering and resolved attempt/current root under with_active/C/F; durably promote the same record once before issuance. Unknown/rolled-back source, pins or commit remain fenced. Never copy the old binding. |
| Crash after promotion/result commit | Replay the actual durable state; original IDs/results remain exact. Recheck current authority at every release; a timeout cannot undo a committed effect. |

Each reconciliation/promotion/withdrawal transition is durably audited with
its protected state outcome; restart does not skip audit or invent success.
Reconciliation never generates a substitute key, token, receipt or successful
result to fill missing evidence. No old generation resurrection or automatic
second successor follows failure. Operator reconciliation and ordinary
retirement fallback belong to their existing owners. The PC2 root coordinator
uses durable open -> resolution -> release-prepared -> owning marker cleanup/
parent sync -> released/final directory sync. Missing markers or readable
unsynced release bytes never discharge a hold. Withdrawal completion may block
indefinitely while append/cleanup remains unresolved, with affected issuance
suppressed. No caller retry or message-only reconcile clears joint uncertainty.
Honest A does not supply independently current restore custody; without that
custody and old-instance exclusion this path stays closed.

**Recommend leaving normal create as register-after-active.** This contract
fixes bump's explicit pre-active handoff only; it does not make create depend
on confirmation availability. An active but unbound new account cannot obtain
keys before authorized register. Alternative: migrate create to provision too
for a uniform handshake, but that broadens rollout and would require a nullable
predecessor schema and corresponding account-side review. That is unselected.

## 7. Codes, audit and budgets

Reuse base §15 for parsing, caller/generation/role, missing/conflicting/revoked
binding, enrollment, custody, capacity, audit and deadlines. Missing binding
is `binding_not_found`; stale pin generation is `generation_mismatch`; a used
path, wrong expected registration/epoch or competing binding is
`binding_conflict`. State is checked before a new effect; repeated original
mutation with changed args is always `request_conflict` before any new effect.

| New code | Exact meaning | retryable |
| --- | --- | --- |
| `provision_state_invalid` | Exact target journal token exists but is active, retiring or removed rather than creating for provision/confirm; an identical provision retry after activation does not restore the earlier admission condition | `false` |
| `binding_provisioned` | A key-use/public-key path reaches a reserved binding without a qualified, durable active promotion; no key is issued | `false` |

No new retryable class. Existing native retryable allowlist in base §7 is
unchanged. Fixing administrative state requires an explicit authorized action;
a nonretryable code does not authorize silently changing request arguments.
Consumer `bump_key_admission_unconfirmed` is user-manager-owned, not a new
Keymaker response code.

One ordinary base §11 audit record per attributable `provision`,
`confirm_provision`, exact retry or refusal: operation as named, domain control,
authenticated caller UID/generation, target resolved path/epoch when known,
request ID, result/refusal and digest of complete canonical params. The audit's
generation remains the caller's; do not mislabel it as the target generation.
The separate protected result/provision metadata correlates the exact target.
Never log raw params, receipt, challenge, token, pin document, keys, public-key
response, seed or chain code. Audit/result state is not a public registry.
Mutation and successful audit/result are one recoverable durable transaction;
confirm audit/result precedes metadata release. Audit failure suppresses output,
not deletion of an uncertain or committed result. Unknown outcome stays fenced.

All operations use base native 65536-byte frame/depth16, request/hello budgets,
rate/state/audit bounds; the final journal read window is the stricter 250 ms.
No unbounded query cache, polling queue or per-target allocation bypass.
Capacity exhaustion preserves tombstones and effect IDs. If option C is later
activated, provision state, provenance and retained query/mutation results must
enter its complete authority inventory; no witness exemption is added.

## 8. Negative text vectors and positive controls

These are future contract requirements, **not executable implementation or
host qualification evidence**. Fixture: active configured operator/observer,
authenticated B, valid trusted journal with UID's old g0 removed and fresh g1
creating, reviewed pin g1, approved unused path, healthy custody/audit, bounded
local guard. The protected pending handoff knows the operator's exact provision
effect, new registration and epoch. For pre-commit refusals, no key output,
binding mutation or new successful result; refusal audit/budget effects only.
Indeterminate commits use §6's keep/reconcile/recover rule, not that blanket.

| ID / claim | Negative and exact expectation | Nearby positive control |
| --- | --- | --- |
| PC-V01 target creating only | Provision separately at active, retiring, removed: `provision_state_invalid`, no new binding | Exact fresh creating token after removed predecessor provisions once |
| PC-V02 no pre-active issuance | Creating target's sign/pubkey/helper/K3 requests: `generation_inactive`, no key/proof/signature/result disclosure; internal unpromoted binding-use control: `binding_provisioned` | After qualified active append and durable with_active promotion, fresh own-generation connection can use its new binding |
| PC-V03 confirmation exact tuple | Wrong target generation: `generation_mismatch`; wrong expected registration or epoch: `binding_conflict`. Consumer given a mismatched response, including predecessor or checkpoint with unknown ancestry/wrong hash, refuses bump_key_admission_unconfirmed without active append | Exact tuple/predecessor/reg/epoch/effect, both facts and verified checkpoint ancestry/hash match pending intent |
| PC-V04 old receipt replay | Before durable consumption, replay g0 confirmation into g1, reuse challenge, expired2000ms observation, boot/instance mismatch, reconnect even with equal instance ID, or post-restart cached bytes: consumer bump_key_admission_unconfirmed, no activation | New live challenge, matching boot/instance/tuple and current observation for the same pending effect within age bound |
| PC-V05 predecessor removal | Malformed overlapping journal introducing g1 before g0 removed: source fenced, `generation_source_unavailable`, no provision; user-manager must not append active or create overlap | Full history proves g0 removed before fresh g1 creating and binding |
| PC-V06 binding/active crash | Crash after durable provision but before active: restart cannot issue, replace binding or allocate another registration; creating remains fenced for key use | Same-ID/args recovers committed provision; new confirm then qualified active/promotion uses that same registration |
| PC-V07 changed retry | Same operator ID with different target, predecessor, owner, names, lifetime or method: `request_conflict`, original record/result unchanged | Exact ID/args under still-creating/current authority returns byte-identical original result |
| PC-V08 pin ordering | Missing/wrong new admitted generation: `generation_mismatch`, no provision/confirm; old token or numeric UID alone insufficient | Reviewed current generations[UID]=g1 checked before binding and again at confirm/release |
| PC-V09 uniqueness and no carryover | Reuse old or otherwise historically issued path, including unbound persistent path; or second live/provisioned reservation: `binding_conflict` | New approved never-issued path and one g1 reservation; old evidence retained |
| PC-V10 timeout/rollback/revoke | Expire receipt while g1 creating: consumer rejects, binding remains inert; verified removed before activation transitions to unbound; authorized revoke tombstone never promotes | New timely query while still creating can observe same reservation; legitimate rollback preserves registration/history without granting issuance |
| PC-V11 audit and unknown commit | Known pre-commit audit failure: audit_unavailable, no effect/output. Unknown durability: fence, no success until actual outcome reconciled, never delete a committed record | Confirmed committed result retained and recovered without new registration; confirmed uncommitted has no successful result; healthy audit releases once |
| PC-V12 authority and locks | Station/observer provision: role_not_permitted; unconfigured observer query: role_not_permitted. Busy/pending journal guard refuses under existing adapter mappings; no remote wait under held locks | Active configured operator provisions; scoped active observer queries with nonblocking gate→data→C→terminal F order inside250ms for PC2 |
| PC-V13 confirmation currency | Withdraw admission or revoke/change epoch between reply and active append: a TTL-only implementation cannot satisfy PC2; bump stays unconfirmed, no claimed qualified activation | Jointly qualified ordering proves both facts current through append; later withdrawal still fences every Keymaker release |

## 9. Open gates and normative amendments

[PC1–PC4](../UNRESOLVED_QUESTIONS.md#provision-and-confirmation-gates) track joint
acceptance, actual observer authentication, conditional PC2 final currency,
creating-guard/recovery qualification and rollout. No surface table was supplied
(brief gap); every requested specification part is addressed. No required text
vector is out of contract. Runtime implementation and production tests are
outside this spec-only slice; do not mark these requirements green from prose.

The base now incorporates PC2 authority/migration/release/qualification
requirements; this is not activation or joint implementation acceptance. The
remaining provision method/schema changes require separately qualified
implementation. On acceptance/implementation amend base §3.1 for the **target-only,
metadata-only** creating guard, §3.2 for provisioned state/provenance/uniqueness,
§5 for separate provision and scoped confirmation authority, §7 for exact
schemas/retries, §8 for ordered pin checks, §11 for durable audit/results and
§15 for the two nonretryable codes. Active caller/issuance checks and ordinary
register are preserved. The linked candidate alone makes none of these changes
operational and does not close existing root/backend/restore qualification gates.
