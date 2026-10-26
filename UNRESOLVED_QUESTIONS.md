# Decisions and unresolved questions

The authoritative decision list and safe defaults are in
[`spec/keymaker.md`, section 14](spec/keymaker.md#14-open-questions-and-activation-gates).

- Q1 and Q4: helper ownership split and module naming — decided.
- Q2 and Q3: decrypt out of v0 (`operation_unsupported`) and configured
  operator-only register/revoke intake — decided. Persistent revoke refuses
  until the signed-act adapter and its fact sources are qualified; Q7 remains
  its activation gate.
- Q6: decided — the authoritative `gen-journal/1` format belongs to
  `swarma-user-manager`. The production read-only adapter uses its protected
  release window. Qualification on a real root-owned journal remains an
  activation gate; retirement recorded late is not fenced (section 3.1).
- Q7: `operator-act/1` record format and exact Keymaker mapping are published
  in [waggle S0 §4.2](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#42-keymaker-operator_record-exact-mapping).
  [Waggle S1](https://github.com/relux-works/waggle/tree/98c9cfd26cfc57a7ee82176cd599e92af03e69bb/verifier) has landed. The
  [integration proposal](spec/keymaker-operator-record.md) is spec only; source
  decisions and durable integration/qualification remain activation gates.
  Persistent revoke stays `operator_record_unavailable`.
- Q8: explicit, append-only, scoped name-to-index registry — decided.
- Q9–Q11: control-group provisioning, external root attestation/rotation and
  the reusable Linux test window — qualification gates.
- Q12: decided — executable-qualified enrollment is valid data but not an available v0
  enforcement capability. All matched rows with `exe` refuse locally, including
  matching procfs snapshots. No UID-only fallback is allowed.

## Station-caller purpose proposal

The [station-caller supplement](spec/keymaker-station-caller.md) records the
owner decision (2026-10-25): SC-Q1 approves `station-caller = 6`, both signing
domains/scopes and only "grant narrowing by the requester"; approval does not
allocate the purpose or activate a method. SC-Q3 selects (a) protected dispatcher
association for now, with (b) registry publication later at federation. SC-Q5
allows enabling only fully qualified combinations, with macOS only after native
qualification. The [SC-Q1–SC-Q6 decision table](spec/keymaker-station-caller.md#8-owner-questions-and-safe-defaults)
keeps SC-Q2, SC-Q4 and SC-Q6 open and unchanged. Every implementation, activation
and qualification gate remains closed. Every dependent station caller path,
including
operator-enrolled bootstrap and recursive delegation, remains disabled until
qualified. Readable keys, interim Git signing and arbitrary-bytes substitutes
are forbidden; the protected operator service root retains its own authority.

The [M0 operator bootstrap transaction](spec/keymaker-station-caller.md#41-m0-operator-bootstrap-transaction)
proposes create -> active -> operator register-after-active, then qualified
operator-only public staging, inert dispatcher association/currentness, exact
caller association and executor worker UID/generation pins in dispatcher M0 policy,
an explicit protected caller-to-worker mapping and full activation. These are
separate roles even if policy explicitly selects the same account. The operator's
broker v0 worker-UID allowlist setup and qualified worker-UID positive control
precede B0, with admission
closed and no active lease; policy Replace invalidates every old-generation lease.
It is not a first-create provision/confirm path, a station-facing bootstrap exception or an
implementation. Purpose 6 remains unallocated. SC-Q2, SC-Q4 and SC-Q6 remain open:
Keymaker's closed bounded intent/result/audit attribution and the proposed original
120-second installation budget, dispatcher's owned association/policy formats and idempotent
install/acknowledgement, broker setup evidence and its currentness through activation,
joint invalidation/restore/old-writer exclusion and final local rechecks need
publication, implementation and native qualification. An equal key, installed
allowlist or saved acknowledgement cannot open readiness. Recreate needs new
association/policy installation and separately verified broker setup; any required
allowlist replacement remains outside B0–B5 and forbidden while leases are active.
All [bootstrap tests](spec/keymaker-station-caller.md#71-m0-bootstrap-paired-qualification-requirements)
are PENDING / NOT RUN; macOS, bootstrap completion and station output remain
closed. No new dispatcher field, station method, signing domain or audit member
is allocated by this proposal.

The [installation budget proposal](spec/keymaker-station-caller.md#original-installation-budget-and-complete-endpoint)
keeps one original B0 entry start through the complete B5 durable outcome/audit
and final openings. Human think-time, retries and reconciliation consume the same
120-second ceiling and fixed step cutoffs; no late activation is permitted. The
per-step 8 MiB/16-call Keymaker installer caps do not establish remote service or
nested-work bounds. All of B4's 40 seconds is proposed for dispatcher policy
installation/currentness, with zero broker share. Broker/operator setup has its
own finite budget, not assigned here. Its selected positive control is peer-scoped
`status` from the exact executor worker UID, returning the expected new `policy_generation`
and required account; the foreign-UID negative control, including the caller UID
when distinct from the worker UID, gets empty or denied. Caller allowlist/status
evidence cannot substitute for worker evidence.
A reload without error is insufficient, and `lease.request` probing is forbidden
because release cannot revoke a delivered token. Control qualification remains a
gate. The full joint envelope remains incomplete and unqualified.

| ID / owner | Required input and safe default |
|---|---|
| SC-BT1 / operator, Keymaker and platform qualification | Accept or revise the proposed 120-second B0–B5 ceiling, 10/10/20/20/40/20-second phase caps and charged local 8 MiB/16-call per-step workload, including human time; B4's 40 seconds is entirely dispatcher policy/currentness, with no broker operation. Require accepted pre-B0 setup evidence from the selected qualified exact executor worker-UID `status` and foreign-UID negative controls, including the caller UID when distinct. Retain both identities and the explicit selected protected-policy mapping, even for the same account. Publish original occurrence/start/deadline and exact act/use/outcome recovery encoding, capacity and independently current custody. Missing acceptance or actual post-read endpoint enforcement keeps Linux/macOS closed; no context/timer or post-write refusal substitute. |
| SC-BT2 / dispatcher with Keymaker | Confirm bounded install/ack/status/retry/currentness/activation delivery and byte/call totals, including nested work and every original cutoff. Supply the exact predecessor/occurrence binding, unknown-outcome holds and effect-enforcing late-activation exclusion. Publish and qualify M0 policy pins for the purpose-6 caller association and exact executor worker UID/generation, their explicit selected mapping (including same-account selection), and independent currentness checks at install/prepare/start; no field names or equality are inferred. Confirm policy installation/currentness within the proposed entire 40-second B4 cap and setup-evidence validity through activation. All dispatcher numbers remain joint inputs; the installer caps assign no dispatcher SLA or wire fields. Unset limits keep the joint profile closed. |
| SC-BT3 / broker and operator with dispatcher/Keymaker | Publish the separate finite one-time setup budget before B0 (time/human work, bytes/calls/retries, unknown-outcome reconciliation), with admission closed and no active lease. Its bootstrap-clock share is zero. Qualify the selected peer-scoped `status` from the exact executor worker UID: expected new `policy_generation`, required account in its allowed list and no lease payload; pair with a foreign UID's empty or denied result, including the caller UID when it differs. The allowlist entry is for the worker UID; caller-UID allowlist/status evidence is insufficient and never implies the worker identity. Confirm evidence currentness through activation; absence of reload error is insufficient. `lease.request` is forbidden as a precondition probe because release cannot revoke a delivered vendor token. Both controls fit this separate unassigned setup budget, not B0–B5. Any policy replacement while leases are active is forbidden because Replace invalidates every old-generation lease. No broker installation/confirmation API, disabled entry, new fields or setup numbers are assigned. Missing evidence/bounds keeps the tuple closed. |

## Q7: operator-record integration sources

The [Q7 supplement](spec/keymaker-operator-record.md) recommends retaining the
unavailable gate until these decisions and qualification close. A protected local
evidence file is a candidate, not an activated source or a freshness exemption.

| Open question | Recommendation / acceptance needed |
| --- | --- |
| Operator pins and owner/device currency | Choose owner-scoped protected root/role catalog, exact owner and an independently current device-authorization provider/update boundary. A device signature, valid attestation or nonrevocation alone cannot manufacture SignerFacts.current. D30 distinct present role pins and D31's closed v0 recovery remain mandatory. |
| Signed snapshot delivery and continuity | Recommend no activation yet. Candidate: protected operator-delivered originals with A<=60s, cumulative last-seen state and independently justified restore continuity; qualify safe replacement/admission serialization. Future registry distribution retains the operator-root signature. No deployed source, grace period or unsigned empty set. |
| Time and watermark | Use the separately integrated qualified shared provider, never copy its rules. Decide conservative S1 Time/Now mapping and independent durable W bootstrap/advancement: min(Now,W) blocks acts issued after W. Do not substitute a guessed fresh W or bypass provider uncertainty/holds. |
| Durable action/ID/result transaction | Accept schema/migration/explicit bootstrap for installation-wide used actions, original act-byte ID bindings, watermark/source anchors and recoverable tombstone/result/audit transaction. Current retained native IDs are not this ledger. Keep permanent evidence and qualify capacity under Store and S1 Present bounds. |
| Critical-effect owner check | Protected consumer policy must classify this effect and, if critical, supply S0's exact-request authority-owner check at the serialized boundary. Decide its real source/exclusion protocol; no RPC under locks or cached-current substitute. |
| Audit schema / recovery qualification | Specified in base §11: [closed optional operator members](spec/keymaker.md#111-operator-record-audit-extension), exact act-digest meaning, typed action ID/pinned S1 reason, coarse wire outcome, old-reader refusal and unchanged historical bytes/hashes. Q7-A01–Q7-A09 remain PENDING implementation/execution, including old/new/mixed recovery, no synthesis and no raw evidence. This spec delta does not close runtime/source/restore gates. |
| Qualification | Execute paired invalidity, unavailable source, exact retry/replay, concurrent reservation, changed evidence, actual effect/release, sync loss and restart/restore tests before runtime activation; text vectors are not execution evidence. |

## Q5: registrar draft alignment and explicit differences

Reference: [swarma-registrar spec/registrar.md (draft)](https://github.com/relux-works/swarma-registrar/blob/f81020a685b8d33c4fc61d835192d4fc87739398/spec/registrar.md),
sections 2–5. Its constants remain under review; a changed revision requires
explicit consumer updates and re-qualification before activation.

| Conflict or dependency | Disposition / remaining gate |
| --- | --- |
| Earlier Keymaker fixtures represented uid_map as a UID-keyed object; registrar requires an array of integer-UID rows with names and optional exe | Corrected to the registrar schema; existing vector IDs retained. Array-valued mutations remain one changed field. |
| Earlier localpart proposal allowed slash and ignored the configured-audience mxid bound | Withdrawn; use registrar structured/explicit-legacy rules and its 255-byte mxid bound. Negative slash and length-bound cases added. |
| Earlier encoding details were assumptions | Body construction, Ed25519 encoding, envelope/signature/nonce, time and half-open key windows now reference the draft owner sections instead of duplicating their schema. |
| Shared trusted-time provider dependency | Consumed: the public `swarma-credential-broker/timeconf` provider at exact `8cdea829b261e97908623376fe6857e9960fe877`, with its protected policy schema and fresh start/decision/release samples. Numeric/evidence rules remain owned by the shared provider. Missing/off policy refuses `clock_untrusted`, non-retryable. PENDING: real host evidence/collector/latency qualification and durable previous-decision-bound/hold continuity across process replacement, per the normative [platform time policy](https://github.com/relux-works/swarma-credential-broker/blob/8cdea829b261e97908623376fe6857e9960fe877/docs/time-policy.md). This adapter does not qualify or implement that external continuity store. |
| Native helper requires canonical frame bytes; registrar HTTP accepts noncanonical JSON wire spellings | Intentional transport distinction. The same semantic body uses the same CCJ-1 scalar-order codec and canonical signature preimage. Do not relax native frames or reject registrar HTTP whitespace by analogy. |
| E1: shared enrollment authority and snapshot verification | Decided: the owner holds the offline Ed25519 enrollment-publisher key; both services verify the pinned signed registry commit and phase-0 envelope signature using the same out-of-band pins in root-owned config, per registrar section 4.3. Snapshot phase ordering, historical legacy-name ownership and rollback/reload rules follow section 4.4 without a Keymaker variant. |
| A retained native helper response may contain a nonce already consumed by registrar HTTP admission | Same-ID helper retry retrieves evidence, not another HTTP success. A fresh admission uses a new native ID and independent nonce; joint retry tests remain a gate. |
| Registrar accepts syntactically valid executable-qualified rows; v0 cannot attest per-operation executable identity | Explicit local capability refusal `enrollment_unsupported`, not a registrar format change. Wrong, unavailable and matching executable snapshots all refuse. v0 refusal is decided in Q12; future enablement requires a separate design. |
| Enrollment maps UIDs, while local custody also needs binding/generation evidence | Active station binding and protected per-UID generation admission remain additional local checks; no extra enrollment wire member is invented. Joint revocation/re-admission tests remain required. |

The helper's wrapper and local refusal codes remain Keymaker-owned; registrar
loader diagnostics are not silently renamed into signed-format rules. The
helper is Ed25519-only in v0 although the registrar also supports P-256.
No unresolved interface may be replaced with an allow-all production stub.

## Option C external witness: specification and activation gates

The [witness supplement](spec/keymaker-witness.md) proposes Keymaker's own
complete-state commitment and separate consumer stream, following the accepted
external-intent direction in the
[registrar specification, section 4.5](https://github.com/relux-works/swarma-registrar/blob/5f44ebf3f78829144aa7864ca2e4ad62bea43eb5/spec/registrar.md#45-external-high-water-witness-option-c-normative-draft).
Its [normative change list](spec/keymaker-witness.md#9-normative-changes-to-existing-sections)
is for curator review; no implementation, qualification or activation is claimed.
The enrollment restore residual below remains **open** until those steps land.
An unconsumed approval restored with old consumed-ID/state evidence, including
a snapshot restored inside its TTL, has no independent freshness proof under A.
C would detect a restored older epoch or unresolved external intent; local
receipt equality and boot/TTL checks cannot provide that guarantee.

| Question | Direction / remaining decision and evidence |
| --- | --- |
| WC1: placement | Decided: a separately administered trust node outside the platform's administrative domain, shared with the owner registry, in separate accounts and processes, with the trusted checkpoint kept off that node. Until deployed and qualified, the existing honest mode A holds and WC1 stays open for activation. Qualify independent restore, off-node checkpoint retention and joint-loss limits; undetectable joint rollback remains outside the guarantee. |
| WC2: clock and freshness | Qualify authoritative serialized latest reads, challenge-bound signed replies, post-restore unpredictable entropy, transport/authentication, bounded framing/proofs and operation deadlines. Wall-clock freshness/TTL alone is insufficient; existing trusted-time checks remain. |
| WC3: Keymaker consumer stream | Separate Keymaker/station stream is the accepted direction. Qualify protected station/lineage enrollment, ACLs, exact artifact inventory/manifest and continuity-preserving migration. Registrar receipts cannot reconcile this consumer. |
| Witness key custody | Curator must approve internal SLIP-0010 purpose 3 and qualify writer custody, independent witness verifier-key provisioning, purpose binding, rotation/revocation and lost-master recovery without resetting the stream/epoch. No socket gains a witness-key operation. |
| WC4: single active instance | Qualify exclusion of an older serving instance throughout authority use, including restored clones. Local flock or witness compare-head writes alone do not fence its signatures. |
| WC5: lifecycle and cost | Publish cross-privilege commit coordination, C-specific receipt ordering, bootstrap, exact-candidate privileged recovery, explicit A fallback/re-entry and loss-of-evidence handling. Qualify two witness durability round trips per logical commit, including all A success audits, within existing budgets. Cancellation/replacement of an unresolved intent is not inferred from local bytes. |

Boot identity, ten-minute TTL and one-use consumption remain required whenever
an A approval is used. A fresh equal C head would replace per-start A approval
only in activated C; historical consumed IDs and pending evidence remain
protected. An outage never automatically switches modes. Every item above
remains open for activation; unchanged-code checks cannot close it.

### Shared witness-service proposal

[Witness-service protocol and server](spec/witness-service.md) specifies a
candidate contract; it does not close WC1–WC5 or activate option C.

| Open service question | Required acceptance / evidence |
| --- | --- |
| Implementation owner | Assign the service implementation and joint consumer qualification owners. No implementation is assigned or supplied here. |
| Host and independent retention | Qualify the decided trust-node/account/process/key isolation, exclusive serving instances, off-node checkpoint custodian, synchronous durability barrier, restart entropy, backup/archive recovery and joint-loss bounds. A periodic checkpoint does not meet the proposed strict profile. |
| Registrar transport and consumer wire | Registrar owners must accept the proposed dedicated mutual-TLS1.3 RPC instead of mandatory §9-channel wire reuse, update §4.5.3/C.3/WC2 explicitly, and accept neutral receipts/head/proofs. Existing audit semantics stay mandatory; no registrar edit/acceptance claimed. |
| Keymaker wire and egress | Explicitly accept proposed receipt/head metadata, proof encoding, service-wide control-metadata disclosure scope, caps and added durability cost; qualify a narrow witness path without general egress or budget increases. Existing consumer §3.3 changes only by a candidate link. |
| Registry checkpoint profile | Align with the [public registry design draft](https://github.com/relux-works/swarma-owner-registry/blob/1cc08a6b4fd1cd5a123a5b38e4c3f17114f32496/design/owner-registry.md), independently reviewed but not content-accepted. Accept its journal/checkpoint schema and adapter, exact candidate inventory/commit validation, checkpoint-time representation, intent/resolution coordination and old-instance exclusion; the registry writer has no witness credential. Distinct maintainer signing remains separate. No registry content tag is assigned here. |
| Joint draft differences | Registry Q10 leaves coordinator/API qualification open; accept the proposed paired inclusion wrapper and receipts jointly. Its off-node checkpoint discussion does not require this proposal's per-ack custodian barrier: explicitly accept provider/cost and qualify per-entry signing/sync load. Registry Q2's purpose-5 domain mismatch in its older Keymaker pin remains with those format owners; no witness alias or purpose expansion. |
| Capacity and proof recovery | Measure proposed frame/record/page/rate/storage numbers, archival growth and off-node round trips against all consumer deadlines. Specify bounded offline continuity recovery for over-cap gaps; never truncate evidence. |

## Swarm Signer message specification gates

The [message supplement](spec/keymaker-msg.md) is spec only. Purpose 4,
`sign_message`, and the decided purpose-5 issuer are not implemented or
activated. No portable certified identity chain or current-use verification
is claimed until runtime implementation and base Q10 qualification gates are satisfied.
MSG1 format alignment is satisfied; MSG2 and MSG3 are decided, not open alternatives.

| Format alignment | Status and remaining evidence |
| --- | --- |
| MSG1: waggle S0 format — aligned | Aligned to accepted main `67df75bec015ea463f685e4daf4975ecda18816a`, [S0 §§2.2–2.6, 4.2 and 6](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md). Exact nine labels, full signed record, separate body content ID, raw-key `ed25519:` ID and 24576-byte/depth12 language are pinned. X01 binds body.author_attestation to the exact current record; X25/D30 give snapshots a separate registry-owner root and leave purpose 5 attestation-only. Both earlier gaps are resolved; [alignment ledger](spec/keymaker-msg.md#44-landed-s0-alignment-and-qualification-gates) records mappings and remaining qualification. Native signing unimplemented; internal S1 key and S2 issuer/state code has package tests. Publication/fresh-status/root continuity remain Q10 gates. |

### Decided message contracts

| Decision | Contract and remaining qualification |
| --- | --- |
| MSG2 — decided: stable key, fresh generation authority | One purpose-4 key per persistent path within an epoch. Every generation and registration gets a fresh authority attestation bound to that generation/registration. A verifier rejects a signature whose attested generation is not active or whose attestation expired, even if an active generation uses identical key bytes. Fresh per-generation paths were not selected. Signed body.author_attestation binds the exact current generation/registration attestation; signer and receiver perform the distinct checks in §3.2/§4.3. Another generation's certificate for the same stable key refuses. Active-status proof and deployment still need qualification. |
| MSG3 — decided: internal purpose 5 | `root-attestation = 5` at a protected installation tuple, pinned by the owner. It signs only service-built agent attestation/1 and never revocation/1; the separately pinned registry-owner revocation root distributes binding withdrawal. Pairwise distinct root roles and exact revoker scope are mandatory; purposes 1–4 never attest and purpose 5 never signs other domains. Validity is a nonempty window of at most 86400 seconds (24 hours); issuer and verifier enforce the ceiling. The independently held issuer alternative was not selected. Exact format, root continuity/revocation, publication and independently fresh status evidence remain base Q10 qualification gates, not another issuer-purpose decision. |
| K3 S2 state/recovery/audit — internal code for review | [Certification state contract](spec/keymaker-msg-state.md) defines schema 2, protected downgrade floor, exact retained candidate reconciliation, internal audit pairing and publication-backed current-T activation. Issuance/renewal is internal at binding/by expiry to the trust-node owner registry. Entry for T plus nearest covering signed checkpoint and WC1 confirmation survive restart; without qualified publication, key_not_enrolled and no T1 fallback. Adopted S4/S5 requires exact protected prior checkpoint bytes, separate journal64/2/540672 and freshness64/1/532480 limits, atomic bytes/anchor/W, one-Evidence process-local receipts and explicitly audited re-anchor with skipped-fork detection loss. Internal schema/issuer/recovery code exists on its S3 pin; [K3-G1–K3-G7](spec/keymaker-msg-state.md#7-remaining-gates) retain successor-codec/floor, provider/cumulative premises, real publisher/WC1/receiver/signing, re-anchor recovery and all execution/activation gates. No silent schema-2/pin upgrade. |
| K3 S4/S5 consumer adoption — spec only | [§4](spec/keymaker-msg-state.md#4-publication-record-and-restart) and [§5.1](spec/keymaker-msg-state.md#51-retained-freshness-and-re-anchor-artifact) fix D39 prior custody/equal-time rule, full B inputs/qualified rollback_safe, S5 receiver/status scope and atomic endpoint audit. [MS-S13–MS-S22](spec/keymaker-msg-state.md#6-paired-negative-text-vectors) and the pinned seven-fixture family are paired requirements, not executed consumer evidence. Qualify normal64-publication catch-up or explicit owner-approved re-anchor, its exact skip artifact, independent cumulative/restore premise and admitted fork-detection cost. Q7/operator D42 remains independently closed. |
| K3 time/W — remaining activation gates | Shared time-provider consumption has landed. Durable watermark bootstrap/advancement/continuity and conservative provider mapping, plus collection latency/uncertainty under admission/release deadlines, still require reviewed integration and qualification. Do not substitute wall clock, W=Now, copied provider rules or relaxed deadlines. |
| Signing language and bounds — decided | Landed-S0-aligned exact `swarma-msg/2` + LF + canonical signed record: complete-preimage limit 24576, depth12, string8192/array64; non-retryable `message_too_large`. Three exact paths: `key` and `body.author` equal the own active binding's attested purpose-4 `ed25519:` ID, and `body.author_attestation` equals its service-resolved current attestation content ID, under with_active through release and on retries. No envelope assembly or other semantic interpretation. Missing/invalid protected resolution: `signer_identity_unavailable`; missing/wrong-type paths: `signer_identity_malformed`; unequal strings: `signer_identity_mismatch`, all non-retryable. Duplicate members remain `ccj_noncanonical`; native params errors remain `request_malformed`. Runtime implementation and base qualification remain gates; accepted-head format alignment is satisfied. |

Base generation ordering, operator-record verification for persistent revoke,
socket-group provisioning and owner recovery gates remain in force. No
message feature grants helper enrollment or interprets waggle's semantics.

## Enrollment adapter activation gates

Enrollment approval replay residual: the ten-minute, same-boot approval and
append-only consumed-approvals record cannot detect restoration that also rolls
back the consumed record, including a whole-host restore within the same boot
and TTL, or deliberate file surgery by root. Restoring an approval alone or
rolling state back to its approved digest does not constitute new confirmation.
Option C, an external witness outside the restored host, is required to close
this residual; it is not implemented by the interim local policy.

Consumption begins when the default startup policy acquires the exclusive
Store lock. Its first action renames the receipt to consuming evidence and
fsyncs the directory, before reading or validating consent or retained state.
Every later error leaves consuming evidence or a durable consumed ID; recovery
requires privileged cleanup and a new confirmation. Exactly two retry windows
remain: an atomic rename failure with no filesystem effect, and a refusal on
the exhaustive pre-lock list in the
[consumption contract](internal/enrollment/README.md#startup-consumption-contract)
(lifetime/target guard, protected config location, protected directory/lifecycle
lease, existing Store lock acquisition, or cancellation/deadline before lock).
Those pre-lock gates read no consent or retained-state contents and grant
nothing. In either window a later start within the TTL may consume the unchanged
approval at most once. No post-rename validation failure is a retry window.

The registrar dependency pin and bump rule are in [README.md](README.md#registrar-dependency).
The local adapter and its explicit bounds are in [internal/enrollment/README.md](internal/enrollment/README.md).

- A missing station `uid_map` is a registrar schema failure that fences the whole
  snapshot. The helper returns `enrollment_unverified`; `uid_map_required` was
  removed. No alternate parser or group fallback is provided.
- The shared interim normal-restart policy requires an explicit operator
  reconciliation after every start. Local readability alone cannot establish
  freshness. The shipped `OperatorReconciler` requires a root-protected approval
  for a fresh startup challenge and exact state digest. An external-witness
  policy requires a future design decision and is not shipped.
- The pinned registrar Store contract now states that a Commit error leaves
  durable state indeterminate. The adapter returns neither old nor new authority
  and fences until a new start with operator reconciliation; this is aligned.
- The published enrollment-1 suite (114 negative/25 positive) runs through the
  local adapter's conformance test. All published rows are supported. Later
  unpublished rows need an explicit dependency bump and are not claimed.
- Native helper integration now enforces binding, generation and current
  enrollment through actual response release. The
  [registration builder](internal/registration/README.md) constructs and checks
  proofs; enrollment alone still grants no binding or release authority.
  Production generation evidence and live multi-UID qualification remain gates.
- Curator-approved `custody_unavailable` (`retryable=false`) covers closed, unloaded
  or protection-failed local signing custody on both surfaces. Responses do not
  distinguish causes; only local audit records the closed cause enumeration.
  Other existing refusal meanings are unchanged.
  Registrar self-check failures retain their typed spellings and return no proof.


## Offline packaging activation gates

- Section 12.1 creates the master seed parent but not the dedicated child
  state_dir expected by the custody loader. The owner must reconcile this
  provisioning gap before activation. Packaging records the dependency without
  adding another root procedure or changing the normative runbook.

## Provision and confirmation gates

The [provision/confirm supplement](spec/keymaker-provision.md) aligns its
account-side inputs to user-manager `2fba23868045b37143ef0156c0e88d1d340d9cc3`,
`spec/stations-v0.md` §6.2, `spec/generation-journal.md` §§4/6.1 and
`docs/station-core.md`. It is spec only; production bump remains
`bump_key_admission_unconfirmed` until joint acceptance and qualification.
Existing create/retire gates are independent. Normal create keeps
register-after-active; no key-purpose or signed-receipt authority is added.

| Gate | Remaining decision / evidence |
| --- | --- |
| PC1: joint interface and observer authentication | Accept the separate operator-only provision and scoped read-only confirm schemas on both sides. Qualify the real observer/user-manager adapter and protected operator-to-manager handoff/pending-intent correlation, active observer UID/generation, socket/server authentication and owner/target scope. Pin service instance only from the first fully verified confirmation result on the authenticated connection; reconnect/restart invalidates pending unconsumed correlation, not the effect intent or an already consumed attempt. A root caller is not exempt from Keymaker generation checks. Signed confirmation would need a separate authorized signer/purpose decision; purposes 2/5 are not widened. |
| PC2: currency through activation | The conditional local F/root/intent ordering is now a [Keymaker requirement](spec/keymaker-pc2.md), derived from the accepted user-manager design at 549b4aa89184c974331d1be1af151cec9768658e. Implementation, combined state/migration, durable observation handoff, independent custody, failure/blocking acceptance and cross-process qualification remain open below. No nonce/2000ms observation, equal instance, current callback or cached receipt closes these gates; production bump remains refused. |
| PC3: creating guard, durability and restore | Qualify metadata-only creating target guard with active caller, journal gate→data→C→terminal F order and <=250ms local window. Cover exact replay, audit/root/commit uncertainty, attempt/hold recovery, restart/promotion/removal history, protected policy-digest provenance and independently current epoch/journal/root floors. No timer activation or deleting committed evidence; include combined state in option C inventory if activated. |
| PC4: identity allocation and rollout | Operator preallocates a never-used purpose-1 identity for bump: ordinary persistent same-path reuse would reproduce the old key and is not this operation. Confirm this account-to-identity mapping, local generation-pin review/install flow, resource budgets and actual fresh account-token acquisition through its owning service. Keep normal create register-after-active unless separately reviewed. Runtime/root/backend and joint negative-vector qualification remain open. |

## PC2 and message-state composition

The [PC2 contract](spec/keymaker-pc2.md) is normative candidate text, not a new
runtime capability. It consumes the accepted conditional user-manager
[design §6.7](https://github.com/relux-works/swarma-user-manager/blob/549b4aa89184c974331d1be1af151cec9768658e/spec/activation-order.md#67-proposed-keymaker-spec-deltas-and-joint-acceptance-limits),
without editing that owner's sections or claiming joint qualification. The
three joint gates remain **OPEN**:

1. **Observation absorption versus RPC correlation:** jointly accept/qualify
   the exact durable consumption boundary under F. Before it disconnect/restart
   invalidates correlation; after it only the same consumed attempt may complete
   once or remain held, within original budgets. F cannot establish continuous
   process/socket liveness through fsync; if that is required, keep refusal.
2. **Independent restore custody under honest A:** retain every root revision/
   digest/incarnation/counter, accepted journal floor and unresolved obligation
   outside the restored failure domain, with independently current continuity
   and old-instance exclusion. A coherent root/approval/anchor restore can pass
   local hashes/boot/TTL. Qualify this custody or disable the PC2 path; no implicit
   option C selection and no registry-publication proof as complete-state witness.
3. **Potentially indefinite withdrawal-completion block:** uncertain append or
   cleanup/recovery retains the joint hold and suppresses issuance. Requested
   withdrawal cannot report completed until append outcome and its own root/
   tombstone/audit durability are established. Accept/qualify this failure policy;
   no finite crash-recovery/end-to-end revocation latency or timeout-abort claim.

Comparison includes the read-only S2 implementation candidate
`266c3ef9bc27531a2e8efe34671adb80b850df3c`; it does not change that candidate.
The following are exact conflicts/integration gaps, **not silently resolved**.
Proposals require contract review and a single accepted composition before PC2
implementation/activation; S2's existing codecs/fixtures are not redefined here.

| ID | Exact mismatch / scenario | Proposed resolution, not an accepted codec or capability |
| --- | --- | --- |
| PC2-S2-1 schema and preimage | S2 [§2.1](spec/keymaker-msg-state.md#21-versioned-protected-inventory) closes schema 2 to six legacy members plus schema_version/messages and hashes the full body excluding only audit_seq/audit_hash. PC2 K2 requires authority metadata in its candidate preimage excluding binding_commit/root_digest and a final root digest. Appending root/provision members to schema 2 or reusing its version/hash would violate its exact reader and recovery copies. | Specify a new explicit combined format/preimage/floor, retaining the complete schema-2 messages inventory, artifacts and original native-ID/result namespace. Review an acyclic dependency graph for authority metadata, snapshot body, binding_commit and final root, with distinct versioned digest semantics. No optional-field merge, opaque authority sidecar or circular hash. |
| PC2-S2-2 authority and recovery ordering | S2 [§3](spec/keymaker-msg-state.md#3-transaction-and-trusted-reconciliation) and candidate persistMessagesContext establish a phase through binding_commit then bindings.next rename/directory sync. PC2 K4 permits authority only after all participants and final root/intent cleanup; a message-only offline reconcile cannot decide or clear a manager/authority hold. Two independently serving commit points can disagree. | Compose each S2 reserve/intent-fence/prepared/issued/publication/activation phase inside the common root transaction and forward C/F ordering, reserving audit before F. One cross-owner coordinator resolves exact outcomes; S2 pending certification and PC2 global holds remain separately retained predicates. Preserve no T1 fallback, no signing/reissue/result invention in recovery, and no external calls inside short critical sections; apply PC2 §1.1 separately to continuous exclusion leases. |
| PC2-S2-3 migration and restore | S2 [§2.2](spec/keymaker-msg-state.md#22-migration-and-downgrade) has clean schema-1→2 migration and floor 2. PC2 additionally commits admission/pins/high-water, incarnation/counter and cross-owner attempts, with independently current per-transaction anchors. Floor 2 and a matched old snapshot/journal alone cannot authorize PC2; existing schema-2 stores also need a path. | One reviewed quiesced upgrade graph accepts validated legacy and existing schema-2 states, retains exact prior/new bodies, histories, decisions and all unresolved obligations, excludes old/restored writers and raises the combined reader/authority floor. Unknown transactions reconcile first. No reset, schema stripping, second independent migration or claimed honest-A rollback protection. |
| PC2-S2-4 bounded read and capacity | S2 [§2.3](spec/keymaker-msg-state.md#23-capacity-and-history) and candidate codec reserve message artifacts/recovery copies (including a 4 MiB proof reservation), not all PC2 root/attempt/hold copies. A <=1 MiB root/4096-entry read does not itself validate a possible 256 MiB private message snapshot in the final window; acquiring C/implicit Store locks under F would deadlock the stated order. | Review one aggregate 256 MiB reservation and exact bounded direct metadata read-set/immutable participant references with complete validated provenance; qualify rechecks and filesystem sync inside the original windows. Do not add another state budget, trust an asynchronous projection, truncate history or introduce F→C. If the required check cannot fit, leave PC2 closed. |

The adopted [two-boundary rule](spec/keymaker-pc2.md#11-short-critical-sections-and-continuous-exclusion-leases)
keeps final journal/C/F sections local-only. Fixed local operations under required
continuous exclusion leases need authenticated targets, bounded completion and
transitive no-back-edge qualification; parents release D before qualifier launch.
Network/notifications stay outside all locks without dropping required leases;
unknown continuity/deadline keeps admission closed. This refines the call rule,
not the three joint decisions above or any format. The pinned A3c source still
labels its Q1 recommendation pending; no implementation/qualification is inferred.

All eight upstream PC2 cases and every KR/KI/KP row are **PENDING / NOT RUN**.
All-writer/root installer participation, combined closed artifact/ledger codecs,
append-lifetime journal guard, read-only sync permissions/latency, root coordinator
and real separate-process/platform evidence remain qualification gates. Existing
PC1 observer/bootstrap, shared provider/watermark and WC1–WC5 gates remain; no
purpose, credential, public error or capability is enabled by this document.

## PC2 combined format G4 draft

The [separate G4 draft](spec/keymaker-authority-root.md) and
[golden fixture manifest](vectors/authority-root.json) propose combined schema
and protected reader/authority floor 3, logical root keymaker-authority/2,
versioned preimages, one migration graph and an exact bounded manager read set.
They **do not close** PC2-S2-1..4 or enable PC2 S1 code. Content gates are ordered:
author draft -> architect co-authorship and mandatory acceptance of everything
read under F -> reviewer acceptance -> curator content approval -> S1 code.
No architect co-authorship/acceptance is claimed by the producer draft.

| Open item | Required decision/evidence |
| --- | --- |
| G4-A: closed codecs and domains | Architect accepts logical version 2 as an explicit delta to the closed version-1 proposal; combined schema/floor 3, payload partition, complete root/member unions, digest tags, acyclic body/audit/root/link ordering, immutable participant/reference dispatch and every migration state. Existing S2 and Q7 closed-optional audit semantics remain unchanged. |
| G4-B: bounded provenance primitive | The draft specifically proposes fs-verity-backed fully validated immutable participants, distinct plain/verity digests and no inode-only/cache/full-scan fallback. Architect/platform owners must accept it and qualify actual filesystem, verity metadata/staging capacity, inode lifecycle, permissions and bounded measure/open/sync. The coauthor's probe on the review host (kernel 7.0, ext4) reports both FS_IOC_MEASURE_VERITY and FS_IOC_ENABLE_VERITY returning EOPNOTSUPP; this spec rework did not rerun those probes. That host is not qualified for this mechanism and PC2 stays closed. No fallback primitive or deployment change is introduced. |
| G4-C: manager read set and recovery | Architect accepts every root/provenance/reservation/guard/attempt/recovery/floor/intent byte: exact 1,421,312 content bytes and 22 content/participant files within the outer 2 MiB and 24 regular-file ceilings, ten immutable measurements, exact phase/null unions, prepared full-validation provenance and bounded current guard ancestry. No C/Store/enrollment/audit/RPC or second 256 MiB budget; F_pkg differs from F_auth. Golden checks are byte/pair integrity only; reader verdicts and all real-process PC2 cases remain PENDING. |
| G4-D: S4/S5 retained inventory | The message-adoption contract on landed main b045dd6 is incorporated into the same required combined payload: anchors/W, exact independent prior checkpoint, original signed inputs/endpoints, typed normal/reanchor artifacts and detached audit metadata. Architect/reviewer/curator must accept these exact members/domains/bounds, including the explicit proposed message_freshness_commit operation. No persisted receipt/Evidence object, extra manager read, serving format, budget or migration graph. This composition does not upgrade the runtime module. |
| G5-A: upstream/lifetime and coordinator | Owner supplies a reviewed journal-owned append-lifetime API (the current prewrite callback is insufficient), root recovery coordinator and old-serving/restored-writer exclusion. The original attempt identity and recovery ledger survive all marker-cleanup/directory-sync boundaries. No message-only reconciler may clear global uncertainty. |
| G5-B: all-writer and aggregate ownership | Owners accept complete per-class retained inventory codecs, root-policy/pin installers and fully validated provider-byte identities, cross-owner reservation/credit consumption and materialized history accounting. The proposed one-manager-slot cap and immutable inventory lifecycle require review. All installed/old/new/staging/recovery/native-intent/effect copies and verity metadata use the same 256 MiB peak; current installed bounds cannot size future copies. |
| G5-C: methods and platform | Real operator/observer authentication and metadata-only creating target guard, root/service permissions, qualified read-only EX flock/sync, full callgraph/no-back-edge proof and unchanged original deadlines remain implementation/qualification prerequisites. |
| G5-D: message authority providers | The exact on-disk wrappers/references are placed in G4 §§7.1–7.2. Independently protected cumulative/restore/time/scope/WC1 provider evidence inner codecs, whole-wrapper limits and continuity/privilege interfaces are still owner-owned inputs, not supplied by G4. Authentic genesis/reanchor approval and one continuous shared W must be qualified; no local boolean, synthesized prior or guessed watermark substitutes. Runtime receipt/Evidence identity cannot be placed on disk by design; restart requires new full verification. |
| G5-E: first capacity commit | G4 §4.1 names independently admitted non-serving C0 over initial reservation Q0, before M0/Q1/R0. Owners must accept its exact authorization/currentness/durability/exclusion API, once-only ticket conversion and retained C0/Q0 custody under the same 256 MiB. C0 alone never serves or permits slot consumption; no future-M0 hash in Q0 or uncommitted-Q1 reference in M0. Unknown C0 stays closed, never fabricated from lost state. C0-specific recovery semantics remain an owner gate; C0 is not an authority transaction or a pc2-hold/1 origin. An authority hold always uses the A2 transaction_id, including zero-journal R0. |
| G6: filesystem qualification | The reported kernel-7.0/ext4 EOPNOTSUPP for both verity ENABLE and MEASURE is a concrete qualification failure for the proposed primitive, not proof of a fallback. PC2 remains closed on that host. Owners must qualify a supported platform or approve a separately reviewed revised mechanism; this slice implements neither. Direct-read/sync latency and all existing G6/A3c gates also remain open. |

The three joint gates remain OPEN: observation absorption versus RPC correlation,
independently current every-transaction restore custody outside the restored
failure domain under honest A, and potentially indefinite withdrawal-completion
blocking. A self-consistent root/verity digest/local anchor supplies no rollback
protection. No automatic option C or A fallback; WC1–WC5 remain separate.

### S2b authenticated runtime prerequisites

The S1 codecs and isolated S2a fence/capacity primitives do not supply the owner
inputs needed by a common transaction. At repository base `655f30f`, and with
user-manager pinned to `505fb9f55a6d` in [go.mod](go.mod), the following runtime
contracts are absent. This is an implementation dependency finding, not closure
of any G5 gate or filesystem qualification.

| Required source | Current boundary and missing owner contract |
| --- | --- |
| Independently authenticated package-fence identity | [authority_fence_linux.go](internal/keymaker/authority_fence_linux.go) verifies an explicitly supplied F_pkg device/inode pin, but does not authenticate its origin. No package-fence identity provider or protected publication schema is exposed by this repository or its pinned dependency. The package owner must supply its protected location/identity, incarnation, replacement/exclusion rules and a reviewed consumption API. Opening an arbitrary second lock file would not establish F_auth != the actual F_pkg. |
| Complete cross-owner capacity census and credit lifecycle | [authority_capacity.go](internal/keymaker/authority_capacity.go) accepts complete inventories, carried reservations and qualified bounds. Neither it nor the pinned manager implements the protected census of all manager attempts, holds, recovery, inventory and staging, or the once-only reservation-to-materialized conversion. G4 section 4 requires the G5-B owner API for those inputs. Caller maps, a new directory layout or a locally invented empty manager history cannot establish completeness or credit ownership. |
| Protected participants and common writer/recovery ownership | [enrollment.Authority](internal/enrollment/authority.go) exposes admission/reload, while its existing high-water Store publishes its own transaction. It has no common-transaction preparation/installation capability covering policy installers, all ten immutable participant roles and manager recovery. Owners must define which participant each writer may prepare/install, durable intent/guard consumption and old/restored-writer exclusion, with terminal F having no hidden lock or provider call. The closed G4 codecs authenticate neither provider ownership nor currentness. |
| Independently admitted first capacity commit and floor transition | [G4 section 4.1](spec/keymaker-authority-root.md#41-first-independent-capacity-commit) explicitly leaves the C0 authorization/currentness/durability/exclusion API to G2/G5-E. [message_reconcile.go](internal/keymaker/message_reconcile.go) supports the existing protected floor-2 message protocol, not the independent combined floor/continuity provider. Legacy and closed-S2 inputs cannot create M0/R0 or resume a combined migration by inferring bootstrap authority from local files. Unknown C0 recovery remains owner-defined. |

A local audit preparation refactor can address exact bytes and serialization,
but cannot supply these missing owner authorities. The pinned journal's
`AppendPrepared(..., guard func() error)` also remains a prewrite validation
callback, not the journal-owned append-lifetime contract required by G5-A;
a caller's defer cannot establish the required unlock ordering.

The review split is transaction/crash-walk first (S2b-1), migration second
(S2b-2). Both remain blocked at the authenticated input boundary. No transaction
or migration implementation, serving integration, floor raise, substitute
provenance provider or positive crash-walk/migration qualification is claimed.
The eight requested omitted-sync/migration/lock-alias plants remain PENDING;
without the actual engine, an unapplied plant or rejecting stub is not a kill.

To unblock, the Keymaker, manager and root-policy owners must provide reviewed
provider/consumption contracts and the accepted implementation revisions for the
sources above, including privilege, continuity, bounded-call and recovery
semantics. Alternatively, they may scope an independent audit-preparation change
while those contracts are developed; it would not deliver S2b-1. G6 participant
immutability, actual filesystem/durability and latency qualification remains a
separate prerequisite and has not been rerun here.

## Generation-journal adapter integration gates

The pinned vector source is the public user-manager
[`gen-journal/1` vectors at `33d0b94`](https://github.com/relux-works/swarma-user-manager/blob/33d0b941dcd4a7ee6d2b5b4ee03c4357056034df/spec/generation-journal.md).
Its 67-case manifest and exact raw files are copied under
`internal/keymaker/testdata/gen-journal/`, with per-file source paths and SHA256
in `provenance.json`. Drift controls check those bytes; they do not establish
adapter conformance. The adapter now pins the signed landed user-manager
`505fb9f55a6d4f3f71db49e5037cd863679a3e41`. Production delegates directly to
its public `WithEvidence`; no private path, marker or lock validator is copied
and no release uses `Checkpoint`. The tagged `NewTestHandle` and exact-gap hook
exist only in fixture builds; normal binary metadata and dependencies are
checked separately. The 67 adapter verdicts and real-flock/no-create contracts
are executable in `generation_fixture_linux_test.go`.
Semantic byte-backed anchor and watcher fixtures use an explicit 5s test-only
window in ordinary and race runs. Tagged source fixtures use the source owner's
per-handle `WithReaderHold(5s)` option, including all 67 vectors. Real 300ms Sync
regressions pair both semantic paths with explicit 250ms refusal controls.
Dedicated deadline tests keep the two-argument 250ms real-clock window;
the normal source API exposes no reader-duration option. Invalid duration and
nil-option tests require refusal before callbacks or source/local persistence.

- Qualification against a real root-owned journal remains PENDING. Nonroot
  tagged fixtures do not qualify production custody, ACLs, storage latency or
  restore procedures. Cooperative deadlines cannot cancel an already-started
  durable sync; expired authority suppresses response emission.
- The owner-approved pristine enrollment rule uses the protected initial floor
  only with no anchor and no binding ever issued. Audit-indexed enrollment
  detects an absent/corrupt established anchor and interrupted publication;
  incident fencing survives restart without automatic recovery. WC1 remains
  an unactivated separate witness proposal as stated in section 3.1; no dummy
  restore-success callback is present. Local continuity cannot detect complete
  joint restoration of the old anchor and audit pair.
- Go MVS selects registrar `264660e5dabb` and x/sys0.38.0. The exact conformance
  pin and explicit HTTP-only exclusions are updated. CCJ, registration,
  enrollment and envelope are unchanged by this repin; registry now requires
  a protected `object_format` of exactly `sha1` or `sha256`. Local enrollment
  config, Git verification, state reads and Loader calls enforce that pin.
  No module replacement directive is used.

## Qualified-time adapter activation

The [slice plan](spec/keymaker-time-adapter.md) records the external provider
continuity/witness, native operation profile, durable enrollment issue-bound,
pre-window audit handoff and K3 receipt inputs. The rollback CAS backend and
restore exclusions remain owner decisions. Current audit collection under
Store/generation/journal locks and point-only persisted enrollment issuance
remain known contract gaps; slice A does not activate them or change codecs.

### M0 enrollment E-I/E-C budgets and final admission

The [enrollment profiles](spec/keymaker-qt2c-profile.md#enrollment-e-i-approval-issue-and-publication)
propose **owner budget decisions**, not qualified or active endpoints:

| Row | Proposal / decision and evidence still required |
| --- | --- |
| E-I whole command | Decide <=60 seconds from original command entry before configuration, locking, inspection, human confirmation or output, through complete durable approval/ledger/bootstrap publication, fence cleanup with parent sync and committed issue-use outcome. Both existing 10-second inspections consume the same allowance; ten-minute approval TTL is independent. Implement/qualify the deadline-enforced endpoint, conservative L_issue encoding and durable original occurrence/use state. Current code has neither the command deadline nor that transaction. |
| E-C reload through swap | Decide <=10 seconds from original Reload entry before reloadMu/pause, or initial authority-open entry before load, through validation, consumed-ID/high-water/use durability, final gated candidate swap and admission opening. The existing 10-second load subdeadline and shorter caller deadline only shorten it. Review the exact prepare-to-Store/barrier handover and owning use/epoch transaction; today load and later swap have no common enforced endpoint. |
| Once-only recovery and qualification | Review formats/migration, capacity, exact issuer/consumer visibility, original/witness custody and independent old/restored-instance exclusion. Preserve durable invalidation on every refusal; unknown issue/consumption/use/swap outcomes remain held, never re-issue or re-open from a new Run/H/Epoch. The profiles list paired timely/late, post-read pause, second-read, unknown-retry and handover controls as PENDING / NOT RUN. No code or wire member is added; native Linux/macOS activation and custody/time qualification stay closed. |
