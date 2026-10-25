# Station-caller signing purpose proposal

Status: **owner decisions recorded; disabled until qualified**. No purpose
allocation, native method, registry method, audit schema or deployment is
activated here. The decisions in §8 leave every implementation, activation and
qualification gate closed. Private keys,
seeds and chain codes remain inside Keymaker; there is no readable key file,
export operation, interim Git key or arbitrary-bytes signing fallback.

The integration requirement is [CIP-0025][eic] at
`dea17185c0317892c13dda823baaeded684f6352`, especially EIC-8-08 and EQ-35.
CIP-0025 owns execution isolation and integration requirements, not signing
grammar. Its §5, §11 and Q-EIC-02 leave boundary, qualification and revocation
carrier types/domains open. This proposal does **not** assign those carriers to
the caller key. It uses the public module-owned formats cited below; remaining
grammar/currentness gaps keep their profiles closed.

## 1. Purpose identity and separation

The owner decision (2026-10-25), SC-Q1, approves **`station-caller = 6`**, the
two signing domains in [§2.1](#21-closed-native-requests-and-signed-bytes), and the
narrow exception "grant narrowing by the requester". This approval does not
allocate the purpose or activate any method. The reservation inventory across
the existing specifications is:

| Index | Name | Source and scope |
|---|---|---|
| 1 | `agent-identity` | [Base §4.1](keymaker.md#41-master-and-slip-0010); peer-bound Git SSHSIG |
| 2 | `host-registration` | Base §4.1; configured registrar helper |
| 3 | `state-witness` | [Witness §3.1](keymaker-witness.md#31-protected-identity-and-purpose-separation); reserved internal witness signer |
| 4 | `swarma-msg` | [Message §1](keymaker-msg.md#1-purpose-registry-and-domain-separation); author message sibling |
| 5 | `root-attestation` | Message §1 and §4.1; internal attestation root, not a caller key |
| 6 | `station-caller` | owner decision (2026-10-25): assignment approved; no registry allocation yet |

No other purpose index is reserved by the current spec set. Index 0 remains
reserved in the name-index registry. Actual allocation must still recheck the
complete inventory against the then-current base before allocating 6.

Use Ed25519 SLIP-0010 at exactly `m/6'/product'/project'/agent'`, with the
same master epoch and protected name-index registry as the active purpose-1
binding. The caller never selects a path, epoch, principal or purpose. Keymaker
resolves the sibling itself; four hardened components and all existing naming,
retirement and custody rules apply. A different tuple is unnecessary because this
key identifies that station, while protected association records bind its use to
the current account generation and execution/profile. Recreating an account does
not itself rotate a persistent derived key or reactivate a previous association.

The distinct purpose ancestor separates this key from purposes 1–5. Exact domain
and closed-body checks below supply a second boundary. Surface A cannot list/use
6, `register` still binds only 1, and `sign_registration` still uses only 2.
The purpose-4 message signer and purpose-5 issuer cannot use 6, and the station
caller cannot sign messages, attestations, witness records or registration proofs.
Verifiers must pin the expected role/key association as well as verify signatures.
A signature is neither authority to execute its contents nor proof of a boundary.

## 2. Exact signing surface and refusals

### 2.1 Closed native requests and signed bytes

Propose two surface-B methods using the existing hello, CCJ-1 frame, native ID,
2-second budget and typed error rules in [base §7](keymaker.md#7-surface-b-native-control):

| Proposed method | Exact params | Exact successful result |
|---|---|---|
| `station_caller_pubkey` | `{}` | `{key,path,registration_number,master_epoch}`; `key` is `ed25519:` plus unpadded canonical base64url of the 32 raw public bytes; other members retain base binding meanings, with `path` the resolved purpose-6 sibling |
| `sign_station_caller` | `{profile,plan_id}` | `{key,sig}`; same key encoding, `sig` canonical unpadded base64url of the 64-byte Ed25519 signature |

`profile` is exactly `dispatcher-request/1` or `caller-delegation/1`.
`plan_id` is exactly `sha256:` plus 64 lowercase hex digits identifying an
immutable **protected typed plan**, not a path, URL, supplied digest to sign,
arbitrary JSON body or opaque payload. The protected plan catalog/provenance and
its complete schema are an external publication gate (SC-Q2). The caller cannot
write that catalog. Keymaker must independently validate the complete resolved
plan against the pinned closed schema, its digest, authenticated origin, current
peer/generation association, intended receiver and operation scope. A trusted
writer or matching digest alone cannot validate an arbitrary body.

Keymaker constructs the signed body from validated typed values and resolves its
own key; it never accepts a namespace, preimage, encoded bytes, private key,
identity selector or unknown member. No recursive extension map, free-form
"extra" member or opaque signable payload is permitted. Full nested schemas and
finite bounds must be published before activation; missing grammar refuses rather
than treating the unpublished part as opaque. The two permitted preimages are:

| Profile | Exact preimage and construction; owner |
|---|---|
| `dispatcher-request/1` | `ASCII("swarma-dispatcher request/1") || 0x0a || CCJ-1(R)`; R is the exact closed `dispatch-op/1` request **without `auth`**, under [dispatcher §3.3 and §8.1][dispatcher]. The adapter inserts `{key,sig}` as `auth` afterward, without changing R. Only ordinary station-caller operations in the approved per-profile allowlist may be constructed. Unknown/gated operations and incomplete nested grammars cannot sign. |
| `caller-delegation/1` | `ASCII("swarma-credential-broker grant/1") || 0x0a || CCJ-1(B)`; B is exactly the closed `grant/1` **body**, under [broker §6.1–§6.2][broker]. Keymaker selects `issuer` as its purpose-6 key; `subject` is an independently registered descendant caller key, never an `agent:` credential leaf; `parent` is the current caller-chain leaf ID, never null. The service constructs only an independently validated attenuation of that chain (actions, accounts, harnesses, profiles, validity and strictly decreasing depth), within the four-envelope bound. The adapter computes the broker-defined ID from the same preimage and assembles `{body,id,sig}`. |

There is no terminating LF after the CCJ-1 object and no caller-chosen prefix.
Use the common CCJ-1 scalar codec; do not sign the JSON spelling of a native
frame, base64 text, a hash in place of the body, or an SSHSIG wrapper.
The complete preimage must fit a proposed **24576-byte** bound, independent of
the inherited 65536-byte native frame cap; oversized resolved plans cannot sign.

These domains are existing **external** formats, not new domains created by
CIP-0025. Broker `broker/1` is peer-authenticated transport and defines no broker
request-signature domain. Purpose 6 cannot sign `revocation/1`, root grants,
dispatcher-issued agent credential leaves, operator acts, `team/1`, boundary
receipts, qualification records or arbitrary broker requests. The owner decision
(2026-10-25), SC-Q1, approves only the narrow exception "grant narrowing by the
requester" to base §1's grant ban; it gives Keymaker no policy-issuer or dispatcher
role. The corresponding base amendment and typed authority transaction remain
subject to [§5](#5-disabled-until-qualified); delegation stays shut. Approval
alone supplies no signing implementation or activation.

### 2.2 Freshness, retries and refusal order

Native IDs and receiver IDs are distinct. The protected plan must bind the full
active association (including execution/profile and intended receiver), the
receiver request/delegation identity, authority validity, policy revision and
current replay evidence. These bindings must be carried and checked by versioned
adapters, not added silently to an existing signed body. Dispatcher generation-
bound key association, durable replay evidence and fresh authority checks remain
mandatory even when stable public bytes are unchanged. An exact same-ID retry may
return only its original result **after all current gates pass**; altered arguments
refuse `request_conflict`. Retired/revoked association or expired plan cannot
recover a usable signature from a cache. Unknown effects retain their original
evidence/fences, never create a replacement plan automatically.

Neither published signing domain specifies a caller challenge/nonce. This proposal
adds none. Dispatcher pre-key proof of possession, rotation and grant replay
transactions remain unpublished. They require exact domains, identity/freshness
bindings, safe retry semantics and storage before they can become a third profile;
no generic challenge signer or existing registration proof substitutes for them.

Apply base §5 admission order: bounded parsing, kernel peer/current generation,
method/role, readiness and own binding/policy, plan validation/capacity, final
generation/revocation/fence check, durable result/audit, actual release. In a
healthy authenticated fixture, an incomplete qualification gate refuses before
resolving a signing plan or disclosing the sibling public key. Existing earlier
parse/peer/generation failures retain their precise codes.

| Exact code | Candidate use |
|---|---|
| `request_malformed`, `ccj_noncanonical`, `frame_too_large` | Unknown fields/profile, malformed plan ID or invalid native syntax; inherited framing codes cover other frame errors |
| `operation_unsupported` | Native generic `sign`, undefined methods or any unapproved signing profile/operation; unknown profile spelling itself is `request_malformed` |
| `purpose_unknown` | Attempt to register/select purpose 6 through a base purpose-1 binding API; no derivation through that route |
| `peer_identity_unavailable`, `role_not_permitted`, `peer_binding_mismatch`, `binding_not_found` | Missing kernel credentials, no station-caller role/profile, foreign plan association or absent own binding respectively |
| `generation_inactive`, `generation_mismatch`, `generation_source_unavailable`, `generation_source_fenced`, `identity_revoked`, `binding_provisioned` | Existing precise generation, terminal identity and pre-active authority failures; never mapped to successful replay |
| `custody_unavailable`, `clock_untrusted`, `rate_limited`, `busy`, `state_capacity_exceeded`, `audit_unavailable`, `request_deadline_exceeded`, `request_conflict`, `request_expired` | Inherited custody, time, budget, evidence, deadline, changed-ID and expired-result failures with their existing meanings |
| **`station_caller_unqualified` (new proposal)** | Purpose/adapters/policy/tuple are disabled, missing, changed, revoked or not independently qualified; no caller key disclosure/signature |
| **`station_caller_plan_unavailable` (new proposal)** | Protected typed plan, its current authority/replay evidence or qualified provenance cannot be obtained completely |
| **`station_caller_plan_invalid` (new proposal)** | Resolved plan has invalid digest/schema, forbidden domain/operation, invalid attenuation, expired validity or complete preimage over 24576 bytes |

All three proposed codes have `retryable=false`; readiness or authority must be
re-established, not guessed by transparent retries. Existing retryability is
unchanged. Errors remain exactly `{code,retryable}`, with no body echo or new
free-form diagnostics. External dispatcher/broker verification codes retain their
owners' spelling and are not additional Keymaker error members.

## 3. Endpoint and peer/profile binding

Use **surface B**, `/run/swarma-keymaker/control.sock`; no SSH agent extension,
new socket, forwarding bridge or file-based signer. This is a proposed extra row
beside the [base §9 surfaces table](keymaker.md#9-domain-separation), not a change
to the current allowlist. A Unix socket's reachability grants no operation scope.
Surface A continues accepting only purpose-1 Git SSHSIG, and fails a purpose-6
key with `sign_key_mismatch` or a non-Git namespace with its existing refusal.

The caller is the kernel peer UID (`SO_PEERCRED` on Linux), its independently
active user-manager generation and its own current Keymaker binding. Retain
`with_active` through final audit/result/release, including retries. Protected
policy must additionally admit this binding's station-caller role and exact
execution/profile/receiver/operation scope. A supplied UID, claimed executable,
profile label, guest UID or shared messaging-account UID cannot select another
station. No public proxy delegation is implied. Cross-service evidence acquisition
occurs outside short state locks; publication must define final exclusion/recheck
ordering against invalidation, without conflicting cross-service waits (SC-Q4).

Linux transport evidence does not qualify macOS. A native macOS key-service port,
peer credentials, login dependency and complete service-purpose confinement are
separate prerequisites; Keychain availability supplies none of these. Optional VM
or pool paths require distinct reviewed adapters/tuples and cannot borrow a host
peer UID. None is activated by this proposal.

## 4. Enrollment, publication and external dependencies

Resolve the public purpose-6 sibling only for the qualified own active binding.
No private value leaves custody during enrollment, proof or rotation. Proposed
`station_caller_pubkey` exposes public metadata, not a registrar registration or
caller grant. Its protected publication must bind the public key to the full
current station association, Keymaker registration/epoch, approved purpose,
receiver and policy; transport of a public key alone supplies no such authority.

Dispatcher-owned `register_key` is the destination for caller-key association,
with registration separate from caller-authority activation. It is an **existing
specified method**, not an implemented/qualified integration claimed here. Its
pre-key proof/replay and rotation grammar remain open. Operator-installed public
associations may be specified first, but **operator-enrolled station bootstrap is
also disabled until purpose and adapters qualify**, overriding the historical
home-generated-key initial slice in the cited dispatcher/broker revisions.
Recursive delegation requires requester C, not dispatcher D, to sign O's attenuated
caller grant after O's public association is durably registered. An unavailable C
or invalid delegation keeps O pending with no spawn authority.

The registrar's `registration/1` helper remains purpose 2 and its existing
enrollment snapshot has no authority to enroll station-caller keys. No existing
registrar/registry publication method has been established for purpose 6; this
proposal allocates **none**. The owner decision (2026-10-25), SC-Q3, selects
option (a), a protected association at the dispatcher, for now. Option (b),
publication in the registry, is deferred until federation; it does not overload
Matrix registration or message attestation. Such publication still requires a
separately reviewed association record/API, revocation/currentness and restore
protocol. The existing registration, proof/rotation and disabled-bootstrap
constraints above remain in force.
Do not call a hypothetical method or accept an unsigned registry row as evidence.

| Dependency | Owning module/decision authority | Required publication or evidence |
|---|---|---|
| Purpose allocation, custody, methods and public metadata | Keymaker specification owner and operator | owner decision (2026-10-25): assignment 6, both §2.1 signing domains and only requester grant narrowing approved; actual allocation, custody, methods, closed schemas and migration remain gated by §5; no private export |
| Active UID/generation and retirement ordering | User-manager | Existing protected generation source and release exclusion; real native qualification |
| Protected typed plan catalog and caller registration/replay | Dispatcher adapter owner with Keymaker | Complete versioned schemas, policy/provenance, exact key association, receiver IDs, bootstrap/rotation and durable recovery |
| Caller-chain attenuation, revocation and final issue/renewal | Credential-broker adapter owner with dispatcher | Existing grant verifier semantics plus qualified versioned integration; no new broker request-signature format inferred |
| Optional external public association | Registry/registrar owners with dispatcher | owner decision (2026-10-25): protected dispatcher association now (a); registry publication later, at federation (b), still requiring a separately published schema/API; existing registration is insufficient |
| Qualification/activation, protected profile and stop/revocation | Independent qualification authority, operator and launcher/session-host owners | Exact tuple acceptance, joint activation, immediate fences and bounded confirmed disposition |
| Authority time/currentness | Shared time-policy owner and each consumer | Qualified current evidence and continuity; no caller wall-clock or receipt-only substitute |

## 5. Disabled until qualified

Define the proposed protected gate **`station_caller_ready`**, initially and on
every missing/unknown component **false**. It is a derived conjunction, not a
caller-supplied boolean or a standalone enable flag:

1. The purpose/method/closed-plan/audit contracts and both versioned adapters are
   independently reviewed and published at immutable compatible revisions.
2. The complete native entry, custody, protected public association/currentness,
   generation exclusion, plan validation, replay/results, audit and recovery are
   implemented and qualified for the exact platform/profile/receiver tuple.
3. Every required station/EIC capability and support record is independently
   current; approved qualification binds the full EIC-10-01 tuple and the precise
   source/test/configuration identities. Boundary publication, dispatcher binding
   and broker issue **and renewal** gates are active together.
4. The operator explicitly activates only that accepted tuple/scope; no hold,
   emergency stop, revoked key/association/tuple, stale epoch or integrity fault
   applies. Live per-request authority still passes §§2–3.

The owner decision (2026-10-25), SC-Q5, permits enabling only fully qualified
combinations; macOS only after native qualification. No combination is qualified
or activated by this decision record. The stricter exact-tuple requirements above
and native macOS prerequisites below remain in force.

The operator decides activation using independent qualification acceptance;
Keymaker/adapters enforce it. Documentation, fixture success, a support label or
operator enrollment alone cannot open the gate. All questions in §8 affecting a
profile must close first. Public-key enrollment, operator-enrolled bootstrap and
recursive delegation remain closed while their integration is unqualified.
The separate protected **operator service root stays independently usable** under
its own authority and recovery prerequisites; it is never restored into a station.

Relevant tuple/profile/policy/key changes invalidate readiness before another
signature release or dependent effect. No revoked rollback, receipt-only migration,
standalone credential-refresher conformance claim or silent weaker fallback.
macOS `keys.station` remains absent until a native port and login dependency
qualify; missing proof on any platform remains `PENDING-VERIFY`, not activated.

## 6. Audit, emergency stop and revocation

Reuse the [base §11 audit frame](keymaker.md#11-audit-and-fail-closed-recovery),
surface `control`, existing sequence/digest chain, custody-cause rules and
audit-before-release durability. **No new JSON audit member or result enum** is
proposed. The proposed operation literals are `station_caller_pubkey` and
`sign_station_caller`. Public metadata uses existing domain `control`; signing
uses exactly `swarma-dispatcher request/1` or `swarma-credential-broker grant/1`.
Admitting those operation/domain combinations is an explicit closed-schema
extension requiring writer/reader validation and old/new/mixed recovery evidence;
an old reader must refuse/fence unfamiliar records, never strip or rewrite them.

Attribute the kernel peer, current generation, service-resolved purpose-6 path and
master epoch in existing fields. `payload_digest` is SHA-256 of the accepted
canonical native request (or null before parsing), never raw plan content. Keep
the plan/preimage digest, immutable profile/policy association and original result
in separate protected, bounded transaction evidence, not invented audit fields.
The durable result/replay format and aggregate accounting need publication before
activation; an audit record alone does not make an effect recoverable/current.
No raw plan, native frame, nonce, grant body, signature, credential or private key
belongs in audit or diagnostics. Retained result storage has separate authority
and finite budgets. Audit failure discards an unreleased signature and fences;
unknown writes preserve exact attempt evidence rather than claiming abort.

Retirement closes the generation; terminal purpose-1 identity revocation closes
its purpose-6 sibling. Purpose-6 association/key or tuple revocation immediately
closes affected signing/public disclosure and dependent new starts/releases,
including cached results and in-flight asynchronous work. A previously issued
signature cannot be recalled: dispatcher/broker readers must independently check
current association, chains, epochs and revocation at their actual effect/final
release boundaries. Keymaker signatures are not boundary receipts or leases.

Emergency stop closes station-caller readiness until explicitly authorized
recovery and all ordinary gates pass. Neither an intact cache nor a stale
completion can reopen it. Preserve legitimate status/list/observe/reconcile and
authorized stop under their own intact prerequisites; no signing bypass is a
recovery path. The launcher/dispatcher, not Keymaker, own process disposition.
For station security revocation, EIC-10-05 requires immediate start/release fences
and confirmed whole-account stop including quiet period, or confirmed qualified
non-revoked narrowing, within **300 seconds of detection or a shorter profile
bound**. Retries/restarts never reset it; unknown/fenced state alone does not
satisfy completion. Broken state retains fences even if this deadline is missed.

## 7. Future paired vectors

All rows are **unrun future qualification requirements**, not executable evidence
or a claim of runtime support. Each negative checks the named refusal, no returned
signature/private material, no enrollment/authority mutation and no onward effect;
bounded permitted refusal audit is allowed. Positives must actually perform the
permitted operation through the same qualified production entry, not just parse.
The last column names a future independent narrowing control and its witness;
none has been executed here.

| Case and claim | Negative / intended refusal | Nearby positive | Narrowing control / intended failing witness |
|---|---|---|---|
| SC-V1 wrong purpose | Register 6 through purpose-1 API: `purpose_unknown`; verify purpose-1/2/3/4/5 signatures cannot authenticate caller 6 | Active own 6 public metadata and permitted request signature verify only as the registered caller | Allow cross-purpose association; SC-V1 WrongPurposeDenied |
| SC-V2 arbitrary bytes | Add `bytes`, `namespace`, body or identity selector to native params: `request_malformed`; plant opaque/unknown plan member: `station_caller_plan_invalid` | Same admitted complete typed plan constructs the exact domain + LF + CCJ-1 bytes and signature verifies | Accept opaque payload or ignore nested unknown field; SC-V2 ArbitraryBytesDenied |
| SC-V3 wrong peer | A second real UID references the first station's valid plan: `peer_binding_mismatch`; guest-provided UID supplies no authority | Same endpoint, own active UID/generation/profile plan signs and reaches only its permitted receiver operation | Remove only peer/association comparison; SC-V3 WrongPeerDenied |
| SC-V4 disabled gate | Independently missing purpose, either adapter, qualification or activation: `station_caller_unqualified`, for public key, bootstrap and delegation separately | Exact accepted tuple activates and each path actually obtains only its allowed output; protected operator service root remains usable while station gate is closed | Bypass one readiness term; SC-V4 StationCallerPurposeDenied / DW-30 |
| SC-V5 replay/freshness | Changed same native ID: `request_conflict`; retired generation: `generation_inactive`; expired retained result: `request_expired`. No nonce format exists to replay yet | Same ID/arguments with current authority returns original result, receiver deduplicates original effect; fresh plan uses its own receiver identity | Skip generation check before cache or receiver replay binding; SC-V5 StationCallerGenerationDenied / ReplayDenied |
| SC-V6 Git namespace | SSHSIG bytes/`git` namespace injected on B: `request_malformed` or resolved-plan `station_caller_plan_invalid`; 6 on A: `sign_key_mismatch` | Ordinary purpose-1 Git succeeds on A, purpose-6 typed request succeeds on B; neither cross-verifies | Add interim Git/arbitrary signer fallback; SC-V6 StationCallerFallbackDenied |
| SC-V7 delegation attenuation | Root/null parent, credential `agent:` leaf, widened scope or unrelated registered subject: `station_caller_plan_invalid` | Registered descendant key gets a strictly attenuated current requester-signed delegation; dispatcher never substitutes itself as issuer | Drop one attenuation/subject check; SC-V7 DelegationScopeDenied |
| SC-V8 invalidation and recovery | Revocation/stop wins final ordering: `station_caller_unqualified`; audit failure: `audit_unavailable`; no late signature or onward release | Healthy audit/release succeeds; authorized recovery/status/stop progresses with intact state, and fresh qualified reactivation works | Reopen from stale completion or release before durable audit; SC-V8 ReleaseFenceDenied / AuditBeforeReleaseDenied |
| SC-V9 diagnostics and bounds | Synthetic sensitive body copied to any diagnostic, or bound exceeded, fails qualification; oversized signed body: `station_caller_plan_invalid` | Bounded structured codes/digests suffice for recovery; exact in-bound typed request succeeds | Remove one channel exclusion/size bound; SC-V9 SensitiveDiagnosticDenied |

SC-V3 also requires EIC EQ-20 **ServicePurposeDeniedSamePeer**: hold peer and
endpoint valid, request an unauthorized signing operation/profile and observe
zero content/effects; pair it with actual permitted service output. Removing
only purpose scope must fail that witness, independently of peer checks.
SC-V5 must separately exercise same stable key with a stale generation association
and stale execution/profile; those variants cannot be hidden by missing readiness.
If challenge-based bootstrap is later published, add reused/expired/wrong-subject
challenge negatives and a consumed-once valid positive before activating it.

## 8. Owner questions and safe defaults

| ID; decision owner | Exact question / recorded owner decision | Safe default until answered and qualified |
|---|---|---|
| SC-Q1; Keymaker specification owner/operator | owner decision (2026-10-25): approved `station-caller = 6`, both §2.1 signing domains/scopes, and only the narrow exception "grant narrowing by the requester". This approval does not allocate the purpose or activate a method; implementation/publication and qualification remain gated by §§1–2 and §5. | No allocation, public method or delegation signing; preserve existing allowlists |
| SC-Q2; dispatcher/broker adapter owners with Keymaker | Which immutable complete closed plan schemas, per-operation allowlists, finite bounds, catalog writer/provenance, receiver binding and replay/result transaction implement these two exact domains? | Both profiles closed; no opaque nested body or arbitrary-bytes substitute |
| SC-Q3; dispatcher registration and registry/registrar owners | owner decision (2026-10-25): option (a), a protected association at the dispatcher, for now; option (b), registry publication, later at federation. Exact proof-of-possession, registration/rotation/restore grammar and authority-install transaction remain publication/qualification dependencies under §4 and §5. | No implicit registry method, overloaded registration proof or activated bootstrap/rotation; recursive delegation pending |
| SC-Q4; user-manager/dispatcher/broker/Keymaker owners | Which production evidence source and acyclic exclusion/recheck protocol order execution/profile/receiver currency, emergency stop and revocation against signing, replay and onward effects? | Missing/unconfirmed currency closes release; no RPC under short locks or cached-current fallback |
| SC-Q5; independent qualification authority/operator | owner decision (2026-10-25): enable only fully qualified combinations; macOS only after native qualification. Exact tuple/adapters/policy/association, joint receipt/issue/renewal and operator activation still require the existing §5 acceptance and gates; this record activates none. | `station_caller_ready=false`; bootstrap/delegation disabled, macOS port and optional backends unavailable |
| SC-Q6; Keymaker storage/audit and adapter owners | Approve operation/domain additions, old-reader fencing, protected retained-plan/result schema, crash/restore/replay evidence and finite aggregate budgets? | No new audit combinations or signing; no historical rewrite, lost unknown effect or unaudited output |

There are exactly **three newly proposed refusal members** (§2.2), **two new
native methods/operation literals** (§2.1, §6), **two typed plan profile names**
and **one derived readiness gate**. These are proposals, not registry changes.
No new audit field, signing domain, challenge, broker request method or
registrar/registry method is allocated. Plan/storage/activation schemas remain
explicit external publication questions, not hidden extension points.

## 9. CIP-0025 mapping and limits

This slice addresses caller signing dependencies, not the complete execution
isolation contract. Each mapped clause below retains its original owner and full
meaning; the table does not claim runtime qualification or discharge unrelated
launcher, network, resource or data obligations.

| CIP-0025 clause / qualification obligation | Proposal section |
|---|---|
| §1 ownership and no UID-only station activation | §§1, 3–5 |
| EIC-2-01, EIC-2-02, EIC-2-06 (protected profile, unknown proof closed, no waiver) | §§2.1, 3, 5 |
| EIC-3-01, EIC-3-03, EIC-3-05, EIC-3-06 (binding versions, station rules, no guest UID, retained fences) | §§1–4, 6 |
| EIC-4-02 (closed typed plans; module grammar) | §2.1 |
| EIC-5-03, EIC-5-04, EIC-5-05, EIC-5-06, EIC-5-08 (independent final currentness, joint activation, invalidation/restore) | §§2.2–6 |
| EIC-6-01, EIC-6-02, EIC-6-03 (native gates and requalification) | §§3, 5 |
| EIC-7-03, EIC-7-04 (macOS key-service absence and per-cell qualification) | §§3, 5 |
| EIC-8-03 (minimal explicit service binding) | §§2.1, 3, 7 |
| EIC-8-04, EIC-8-05, EIC-8-07 (broker issue/renewal, joint path and acyclic final recheck) | §§3–6 |
| **EIC-8-08** (separate purpose; all dependent paths disabled; no readable/Git/arbitrary fallback; operator root retained) | **§§1–8**, especially §§2, 4–5 |
| EIC-8-09 (bounded secret-free diagnostics) | §§2.2, 6–7 |
| EIC-10-01, EIC-10-02, EIC-10-03, EIC-10-04 (exact tuple/production entry, paired controls, invalidation) | §§5, 7–8 |
| EIC-10-05, EIC-10-06 (immediate fence, original stop deadline, permitted recovery) | §§5–7 |
| EIC-11-01, §11 rollout (distinct support/qualification/activation, optional tuples) | §§3, 5 |
| Compatibility/migration; Specification changes item 3; Implementation plan leaves 2–3 | §§2, 4–5, 8 |
| EQ-20 / PO-20 ServicePurpose; EQ-35 / PO-35 and additional bootstrap/delegation/generation subcases | §7 SC-V1–SC-V8 and following paragraphs |
| EQ-36 / PO-36 diagnostics; TO-25 evidence; TO-27/28/29 invalidation/disposition/recovery; TO-30 / DW-30 / DM-30 rollout | §§5–7 |
| Q-EIC-02 carriers, Q-EIC-03 joint activation, Q-EIC-06 recovery authority | §§2, 5–6, 8 SC-Q3–SC-Q6 |

The implementation brief must provide an acceptance surface table and coverage
map before code work; none was supplied for this docs-only assignment. All
vectors above are pending. Qualification cannot be inferred from link checks or
spec review. No command here modifies another module or installs a service.

[eic]: https://github.com/relux-works/curator-spec/blob/dea17185c0317892c13dda823baaeded684f6352/cips/CIP-0025-execution-isolation-contract.md
[dispatcher]: https://github.com/relux-works/swarma-dispatcher/blob/b719e2307f5f4d6284abbd1ba60c42330f2d6ae8/spec/dispatcher.md
[broker]: https://github.com/relux-works/swarma-credential-broker/blob/f2c01f52477b5885aefd5b6bd04d09a6a22813b2/spec/broker.md
