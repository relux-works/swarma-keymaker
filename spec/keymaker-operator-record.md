# Persistent-revoke operator-record verification

Status: **spec only; not implemented or activated**. This proposes the Q7
adapter for native `revoke` in `mode:"operator"`. Persistent revoke continues
to refuse `operator_record_unavailable`; the landed verifier alone does not
supply its facts or commit an effect. No dependency or runtime code changes
are made here. Ephemeral mode, register and operator-principal intake retain
[Keymaker §5](keymaker.md#5-operations-and-authority).

Sources: [waggle S1 verifier API](https://github.com/relux-works/waggle/blob/98c9cfd26cfc57a7ee82176cd599e92af03e69bb/verifier/types.go),
[context schemas](https://github.com/relux-works/waggle/blob/98c9cfd26cfc57a7ee82176cd599e92af03e69bb/verifier/README.md),
[operator pipeline](https://github.com/relux-works/waggle/blob/98c9cfd26cfc57a7ee82176cd599e92af03e69bb/verifier/verify.go),
[record package](https://github.com/relux-works/waggle/blob/98c9cfd26cfc57a7ee82176cd599e92af03e69bb/record/README.md)
and [S0 §§2.6, 4.2, 6–7](https://github.com/relux-works/waggle/blob/98c9cfd26cfc57a7ee82176cd599e92af03e69bb/spec/swarm-envelope-2.md).
These immutable public sources define the bytes, authority and refusal order;
this adapter must not implement another record parser or signature verifier.

## 1. Exact request and verifier call

`operator_record` remains the entire canonical `swarm-envelope/2` object,
not a wrapper or base64 string. Preserve its embedded received bytes exactly,
without LF; enforce the 8192-byte/depth16 act limits and existing native frame
limits. Re-marshalling may be used only with an exact byte-equality check;
never repair, pretty-print or add signatures. Operator-device signatures are
P-256 low-S over the registered raw preimage, not WebAuthn assertion wrappers.

For a fresh request, resolve the target from the protected Store, not from
signed claims. Its binding must match this concrete `ActBinding`:

| Input | Exact value / source |
| --- | --- |
| operation | `"revoke"`, fixed by the handler; no widening profile |
| target | `{kind:"registration",id:registration_number}`; positive safe JSON integer from the validated request, matching Store `Binding.Number` |
| owner | Exact Store `Binding.Owner`, agreeing with protected operator-owner policy; never a request override |
| epoch | Exact Store `Binding.Epoch` (`master_epoch`), a string; no numeric conversion or current-epoch substitution for another binding |
| arguments | Exactly `{registration_number: request.registration_number,mode:"operator"}`; its digest is `record.Digest(argumentBytes)`, where argumentBytes is the successfully encoded `record.Canonical(arguments)` result, without LF |
| action_id | Signed body's canonical base64url encoding of 16 random bytes, a single-use ID, returned as `Plan.ActionID`; distinct from the native 32-hex-digit request ID and nonce |
| audience / nonce / interval | Protected installation audience; signed 16-byte nonce; signed whole-second iat/exp, lifetime<=120s. No caller time override |

`ActBinding` has exactly `{operation,target,owner,epoch,arguments}`. There is
**no action_id member in ActBinding**; S1 validates the signed action ID and
checks `UsedActions`. The full native dedup arguments separately include
`operator_record`; do not hash that self-containing object as act arguments.

After constructing every available snapshot with `verifier.Present(value)`
and checking its error, make this exact in-process call:

```go
result := verifier.New(context).VerifyOperator(rawAct)
publicCode := verifier.OperatorRecordCode(result.Code)
```

Here context is `verifier.Context` from §2, rawAct is the preserved byte slice,
and `result.Code == "accept"` supplies only a candidate `Plan`, never an effect
permit. Acceptance must have the expected single act content ID, exact action
ID and candidate watermark; persist its ID-to-original-bytes binding yourself.
`VerifyEnvelope`, raw signature success or a fixture verdict cannot replace
`VerifyOperator`. Its ordered E/T, O1–O5 and Commit-conflict semantics remain
those of S1. `confirmed=false` is allowed for narrowing; no A3 or user-presence
claim follows. No unsigned persistent-revoke fallback exists.

## 2. Every Context fact and its v0 owner

All values are protected in-process snapshots, not new request fields. S1
`Evidence{}` means unavailable; an available empty map/array is explicit, never
null. Use `map[string]any`, `[]any`, `int64`, booleans, strings and raw `[]byte`
as S1 requires. `Present` errors or unsupported/bounded-out input must refuse,
not silently produce an available empty collection. Each Present snapshot is
bounded by S1's depth32/1MiB budget; the act still has depth16/8192-byte limits.
Budget exhaustion closes admission; never truncate retained history to fit.

| Context field | Available value and authoritative source |
| --- | --- |
| `Audience` | Exact consuming installation string in protected local configuration; not hostname/request discovery |
| `RequiredRoles` | Handler policy `[]any{"approver"}`; S1 requires one approver signature for acts |
| `OperatorRoot` | Canonical root key identifier with protected operator purpose, provisioned out of band for this owner; neither device attestation nor transport chooses a root |
| `OperatorOwner` | Protected configured owner string, matching target binding owner; no normalization |
| `DeviceAttestations` | Map device key ID -> original signed `attestation/1` bytes. External operator-root issuer supplies them; candidate v0 delivery is a protected local evidence bundle, independently verified by S1. A device-key pin alone is insufficient |
| `SignedSnapshots` | Map exact OperatorRoot -> `{availability:"available",max_age:int64(A),rollback_safe:true,snapshot:rawBytes}` only after §3's checks. External operator root signs; protected delivery and locally retained continuity supply bytes/history. No deployed source exists yet |
| `SignerFacts` | `{current:bool}` from protected owner/device authorization policy current at the effect boundary. Missing source stays unavailable; false is invalid. Attestation validity, possession, `confirmed` and nonrevocation alone do not establish current owner authorization. Its provider/update boundary remains open; presence facts are not required by narrowing |
| `Time` | `{trusted,fresh,authority_until}` from the qualified shared provider under Keymaker §8; includes its start/hold/continuity/uncertainty decision, not a configured true flag |
| `Now` | Exact sampled whole-second UTC string from that same qualified provider, not `time.Now`, a signed iat or caller timestamp. Provider integration is separate work, not assumed present here |
| `WatermarkAvailable` | `true` only after loading and validating the local durable watermark and its restore continuity; otherwise unavailable |
| `Watermark` | Exact local durable timestamp W. Initialization and qualified advancement need review; no in-memory replacement with Now just to accept an act |
| `IDJournalAvailable` | `true` only for complete, reconciled local exact-byte act-ID history |
| `IDJournal` | Map accepted content ID -> original raw act bytes in the protected Store transaction domain, including retained historical entries; same ID with different bytes must remain detectable |
| `ReplayAvailable` | `true` only with complete, reconciled durable action history; unreadable/missing/pending state never becomes an empty history |
| `UsedActions` | Explicit array of consumed action IDs from the installation-wide protected ledger, not merely this caller's request IDs. Retain across caller generations/restarts; reserve atomically at commit |
| `ActBinding` | Exact protected request/binding projection in §1, reread and compared at commit |
| `ServiceRoot` | Every configured purpose5 role pin as `{key,purpose:int64(5)}` from the protected role catalog; no fabricated pin when unrelated role is genuinely unconfigured |
| `AgentRevocationRoot` | Every configured registry-revocation role pin as `{key,purpose:"registry-revocation",attestation_root}` from that same catalog |
| `GrantRoot` | Every configured grant-owner root key ID from that catalog |
| `AdmittedKeys`, `Attestations`, `AgentAttestationIDs`, `CurrentGenerations`, `Assurance`, `Delivery` | Unused by this narrowing operator pipeline; leave unavailable, not fabricated agent/device facts. Existing caller generation checks remain independent and mandatory |

Present D30 root-role pins must be pairwise distinct. Do not omit a known pin
to bypass that comparison. The operator root legitimately signs both its device
attestations and operator-domain snapshots; this is one role. The registry's
key cannot substitute for it. D31 supplies no v0 root-recovery record; this
adapter cannot replace/recover a root or infer a new root from received bytes.

The existing retained-request store does **not** already implement the three
S1 journals, continuity proofs or these configuration sources. Extend its
protected recoverable transaction domain for act bytes/IDs, used actions,
watermark and source-continuity anchors; do not add an independent best-effort
side file. Concrete schema/migration/bootstrap and restore qualification are
gates. Never advertise an empty journal after loss or restore.

## 3. Snapshot source recommendation and freshness

**Recommend (a): retain `operator_record_unavailable` until the fact sources
and durable integration are accepted and qualified.** S1 landing alone does
not open persistent revoke. There is no deployed owner-registry/trust-node
snapshot service to call. This path is not an emergency-stop mechanism.

Candidate (b), if accepted later: an operator-delivered protected local bundle
of original operator-root-signed device attestations/snapshots plus separately
protected current-owner policy. It requires checked owner/mode/no-link paths,
bounded immutable reads, atomic replacement and serialization with admission;
no daemon signing key, station-writable path, native upload or automatic fetch.
Keep previously accepted issuance/content/cumulative entries durably. A newer
snapshot must retain all entries, including future entries, without postponing
`from`; equal issued_at requires byte-identical evidence. Missing, unproved gaps,
regression, conflicting same-time evidence or lost restore continuity must fence.
`revocation/1` has no previous-snapshot hash member; do not add one locally.
Local last-seen comparisons cannot prove an unseen issuer fork absent or supply
independent continuity after joint restore. A restored local floor is not
independent proof: preserve option A's explicit
operator reconciliation and external restore evidence; do not claim option C.

S1 must verify the original signature, issuer, complete=true, every entry and
scope. For configured `0 < A <=60` seconds, require
`issued_at <= min(Now,W)` and `max(Now,W)-issued_at <= A`; current revocation
matches from `from <= max(Now,W)` for the device key, its attestation ID and
act ID. Missing/stale/future/incomplete/continuity-unavailable evidence refuses
unavailable; bad signature/issuer/shape and revoked authority refuse invalid.
No unsigned empty snapshot, removal of retained entries, stale grace period,
local re-signing or switching to a registry-key signature is permitted.

A newly copied old file gains no age. Candidate (b) works only while its
qualified evidence remains fresh; manual delivery supplies no availability
promise. Respect the 64-entry/8192-byte profile: capacity cannot justify dropping
revocations. The bound `max(S + A, from)` assumes complete, cumulative,
non-equivocating issuance and continuity; S is first-containing issuance, not
submission. No pre-publication or end-to-end completion deadline is claimed.

Alternative (c): a future reviewed trust-node source can distribute originals
and independently retained continuity; it still needs operator-root signatures,
current-owner facts and the same freshness rule. No listener, RPC or deployment
is authorized here. For effects classified critical by protected consumer
policy, S0 §6's authority-owner online check additionally applies; the sender
cannot classify the effect. Its exact source and serialization must be decided
before activation, not replaced with a cached boolean.

S1 uses `min(Now,W)` for starts and `max(Now,W)` for expiry. Thus an act whose
iat is newer than durable W refuses `not_yet_valid` even if Now is later.
Qualified initialization/advancement of W and the provider-to-S1 time mapping
are explicit review questions, not permission to alter S1 or invent a fresh W.

## 4. Ordering, atomic commit and retries

The current [native verifier hook](../internal/keymaker/native.go) returns a
code only; an adapter must carry S1's plan into this transaction, not discard it
after a successful check. The direct [Store revoke gate](../internal/keymaker/binding.go)
also keeps persistent revoke closed. Neither entry point may bypass the same
verified-plan/commit invariant when implementation is separately authorized.

1. Apply existing kernel caller/generation, configured operator, framing,
   method/argument and capacity gates. Under the existing Store serialization,
   check retained `(caller_uid,caller_generation,request_id)` first: changed
   method or full canonical arguments -> `request_conflict`; exact committed
   retry returns its original durable result under current disclosure authority.
   This is retained evidence, not a fresh act/effect, and need not reconsume an
   action or accept an expired act. It grants no authority or source-fence reset.
2. For a fresh ID, prepare bounded external/configuration/evidence reads and any
   RPC **outside all locks**. Construct an immutable candidate context and run
   the pure verifier before any tombstone transaction. No acceptance on missing
   verifier, `Present` failure or unresolved fact source.
3. At the serialized effect boundary, repeat retained-result selection, exact
   target/owner/epoch comparison, current caller/operator authority, protected
   policy/evidence versions, time/revocation and action/id availability. Use a
   fresh context and rerun pure verification against current facts; an earlier
   accept is only a hint. Final checks may use only qualified bounded local
   reads/computation. If an RPC-dependent final/critical-effect check cannot be
   ordered without RPC under locks, keep unavailable pending a reviewed
   coordinator/exclusion contract; no cached-current shortcut.
4. Atomically reserve `Plan.ActionID`, bind every Plan ID to exact act bytes,
   persist nonregressing Plan.Watermark, verified act/canonical native arguments,
   tombstone, original result and audit linkage in one recoverable Store
   transaction. Precharge its full retained budget before any intent. Recheck
   original deadlines/current evidence at the actual effect/release boundary;
   the native two-second budget is not extended. Refusal before commit leaves
   these authority indexes and the binding unchanged; bounded refusal audit is
   permitted. Do not expose pure accept as success before durable commit/audit.
5. A new request ID reusing a consumed action -> `act_replay`, mapped invalid;
   this is installation-wide, not caller-scoped. Concurrent new requests can
   reserve it only once. A committed or unresolved reserved action ID never
   becomes unused through restart, restore, generation change or cleanup.
   Unknown write/sync outcome preserves the exact pending transaction and fences
   affected authority until qualified recovery; no duplicate tombstone effect,
   new-ID escape, dropped act bytes or regenerated success. Follow §11's audit
   failure fence and existing actual-release barriers on both surfaces.

## 5. Public codes and audit delta

Use S1 `OperatorRecordCode` for verifier results, including the following exact
unavailable set. Both public refusal codes have **retryable=false**.

| S1 result / adapter condition | Native outcome |
| --- | --- |
| `accept` | Candidate plan only; native success only after §4 commit/revalidation |
| empty code, `operator_record_unavailable`, `signer_unavailable`, `key_binding_unavailable`, `time_unavailable`, `watermark_unavailable`, `revocation_unavailable`, `id_journal_unavailable`, `replay_unavailable`, `state_unavailable` | `operator_record_unavailable`, retryable=false |
| Every other definite S1 refusal, including binding/audience/owner/epoch errors, revoked, stale act, bad signature, `envelope_conflict`, `act_replay` | `operator_record_invalid`, retryable=false |

Unavailable verifier/plan-commit inputs must be supplied as `state_unavailable`
or an explicit unavailable result, never default accept. Native framing,
`request_conflict`, caller/generation, capacity, deadline and fatal audit/storage
handling retain their existing outer codes/fences; do not blanket-map unrelated
native errors. A failed/uncertain commit cannot yield success even if verification
was accept. Preserve the original fine S1 reason locally, never on the wire.

Proposed explicit delta to [§11's closed audit schema](keymaker.md#11-audit-and-fail-closed-recovery):
for this path `payload_digest` is `record.Digest(rawAct)` when bounded act bytes
are available (null when no such bytes are known), and add optional typed
`operator_action_id` and `operator_reason`. The former is null until a bounded
canonical action ID is known; the latter is the exact S1 stable decision code
(or `state_unavailable` for adapter unavailability), drawn from the pinned
verifier's code inventory, never an error string. `refusal_code` keeps the coarse
native outcome. These fields are absent on unrelated records; old journal
bytes/hashes stay intact and recovery must not synthesize metadata. Audit-schema
acceptance and historical recovery tests are required before implementation.

Operator evidence in audit is **digest and action ID only**, plus the typed
fine verdict and existing attribution/result metadata. Never log act/attestation/
snapshot bytes, device/public keys, signatures, nonce or free-form errors. Keep
verified act bytes only in separate protected result/ID storage bound to the
transaction; audit is neither a replay ledger nor a result cache. Audit failure
prevents release and cannot recursively log itself into apparent success.

## 6. Paired negative text vectors

Future tests, **NOT RUN**; these do not qualify the missing sources or commit
adapter. Control V has a current configured operator caller, protected matching
binding, valid P-256 device act/attestation, independently current owner policy,
fresh complete continuous snapshot, qualified time with W=Now, unused action
and healthy durable storage. Every refusal has no new tombstone/action commit;
an indeterminate transaction instead preserves evidence and fences.

| ID | Negative / required outcome | Positive control |
| --- | --- | --- |
| OR01 | Wrong operation/target, owner or epoch -> act_operation_unknown/act_binding_mismatch, mapped invalid | V matches exact protected request and target binding |
| OR02 | Current snapshot revokes device, attestation or act -> revoked/invalid; no old-iat bypass | Same valid complete snapshot with no matching effective entry permits V |
| OR03 | Snapshot age>A (including A=60 boundary), missing/stale/future/incomplete or unproved continuity -> unavailable | Valid signed continuous snapshot age exactly A is admitted if all other checks pass |
| OR04 | New native ID reuses consumed action -> act_replay/invalid, including another caller generation/restart; racing IDs cannot both commit | Exact same native ID/arguments returns original result with current disclosure authority, no second effect |
| OR05 | Expired/future act -> expired/not_yet_valid, invalid | V lies inside half-open validity and<=120s lifetime |
| OR06 | Non-operator/agent key, wrong root, invalid P-256 signature or WebAuthn wrapper -> invalid | Original raw-preimage P-256 low-S device signature under pinned operator attestation verifies |
| OR07 | Verifier, current-owner source, time, watermark or replay/ID journal unavailable -> unavailable, empty plan/no effect | Fully supplied V returns candidate IDs/action/watermark, committed once before success |
| OR08 | Same native ID changes evidence/arguments -> request_conflict; same act content ID changes bytes -> envelope_conflict/invalid | Exact bytes and original arguments retain their original binding |
| OR09 | Snapshot drops an old/future entry, postpones from, same-time fork, restore clears used actions, or commit/audit sync is uncertain -> refuse/fence, retain evidence | Qualified monotonic evidence and exact transaction recovery preserve histories and original result |

Implementation and qualification must exercise the real adapter, concurrent
reservation, actual-release boundary, restart/restore and faulted durability.
The [Q7 questions](../UNRESOLVED_QUESTIONS.md#q7-operator-record-integration-sources)
remain content-review gates; this text supplies no deployed issuer or emergency
stop, no root recovery, no unsigned path and no runtime acceptance.
