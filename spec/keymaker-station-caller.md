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

The station-facing public method resolves the purpose-6 sibling only for the
qualified own active binding. The proposed protected operator installation in
[§4.1](#41-m0-operator-bootstrap-transaction) returns no public metadata to a station.
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

### 4.1 M0 operator bootstrap transaction

Status: **proposed transaction; not implemented, qualified or activated**.
M0 uses ordering A: once before dispatch, the operator performs ordinary
`user.create` -> durable `active` -> authorized purpose-1 `register`, then this
purpose-6 installation and the protected M0 launch policy pinned to that existing
UID/generation. The broker v0 allowlist is a separately verified operator setup
precondition before B0, not a step in this installation. Dispatch starts only that
existing active generation. Ordinary create remains
[register-after-active](keymaker-provision.md#6-failure-recovery-and-create);
this is not bump's `provision`/`confirm_provision`, an early-active workaround,
a PC2 credit exemption or registrar purpose-2 enrollment. The broker v0 lease
supplies no caller grant. The proposed M0 scope is only `dispatcher-request/1`,
with `dispatch`
and owned-run `cancel`; requester delegation and federation remain later work.
The dispatcher must publish the matching minimal authority/request contract;
the Keymaker request signature authenticates a caller and never supplies launch
authority.

**Admission and staging boundary.** An exact active purpose-1 binding, current
protected generation/admission policy, approved name-index registry, master epoch
and healthy custody are prerequisites. Purpose 6 must have been explicitly
allocated following §1; this text does not allocate it. Installation additionally
requires independent acceptance of the exact Linux operator-bootstrap entry,
its storage/recovery, both versioned adapters and their invalidation protocol,
and explicit operator authorization of that qualified installation scope.
The operator entry enforces method/role and active caller generation; root UID
by itself is no exemption from those checks.
Missing implementation, acceptance, authority or evidence refuses before
production derivation or public staging. Native macOS bootstrap remains closed.

The operator workflow is a protected service/installer transaction, **not** a
third station native method, a call to the station's `station_caller_pubkey` while
unready, or a new challenge/signing profile. It may stage only public metadata
inside the qualified protected installation path; it returns no key to a station.
This resolves the installation dependency without treating the not-yet-installed
association or launch policy as authority for their own creation. The separately
qualified operator entry and its authorization are independent inputs, never
purpose-6 signatures or broker credentials. Its concrete entry/closed storage
format and joint interfaces still require review before implementation. No
operator service root or private material is installed in a station.

**Broker v0 setup precondition — outside B0–B5.** Before B0, the operator
installs the allowlist entry for the **exact station UID** during one-time setup,
with admission closed and **no active lease on that broker**. The operator
atomically replaces the protected policy file with a new monotonic policy
generation and the station UID added, then signals reload. The daemon validates
and runs `Manager.Replace`; on refusal it reports `configuration_reload_refused`
and retains the old policy. A successful Replace closes all connections and
**invalidates every lease of the old generation**. Installing the allowlist while
other leases are active is therefore forbidden; this is an operator precondition,
not a claim that the daemon rejects every such reload. There is no broker
allowlist-installation or confirmation API.

The selected **exact station-UID positive control** is broker v0's existing
peer-scoped `status` call from that station UID: it must return the expected new
`policy_generation` and the required account in its allowed-account list, with
no lease payload. Pair it with a **foreign-UID negative control** that returns an
empty or denied result. Absence of a reload error alone is not positive evidence;
a wrong generation/account or failed negative control cannot satisfy setup.
`lease.request` is **forbidden as a precondition probe**: it delivers a real vendor
token that lease release cannot revoke. The selected `status` control still needs
qualification; unknown verification or missing qualification keeps admission
closed. Both controls run within the setup's own unassigned budget below, never
inside B0–B5.
The evidence's validity/currentness through activation must be accepted jointly;
a policy change invalidates it and cannot be silently adopted by B0–B5.

Broker setup and its positive-control evidence have their **own one-time setup
budget**, outside t_B/D_B and with **no share of the bootstrap clock**. Its finite
time, human work, bytes/calls, retries and control/evidence bounds remain
joint inputs to be confirmed by broker/operator owners, not invented numbers or
borrowed B4 allowance. This separation does not make setup or its controls
unbounded or authority to activate. Missing accepted setup evidence closes
B0 admission.

**Original occurrence and retention.** Before deriving, the owning Keymaker
transaction reserves one operator-scoped occurrence, using the base request-ID
domain and full canonical argument comparison. Retain the original authenticated
operator UID/generation and ID, exact target UID/generation, purpose-1 registration,
master epoch, resolved purpose-6 path/public key, intended dispatcher and scope,
immutable adapter/qualification/policy identities, predecessor versions, completed
steps and their durable evidence. These are required protected transaction
properties, not dispatcher field names or new native params. Reserve the next
closed, versioned transaction/result format and all staging/history within the
single existing 256 MiB state budget (§6); no implicit side journal, pruning or
second allowance. Missing format/capacity closes admission before work.
Same ID with different arguments is `request_conflict`. Recovery references the
original occurrence, even under a separately authorized recovery operator; it
cannot change the original identity or mint a replacement occurrence to clear debt.

| Step | Operator-only action and durable order | Crash / unknown outcome |
|---|---|---|
| B0 — reserve closed installation | Authenticate the operator and exact active target; capture approved full tuple, current revisions and original deadline. Durably reserve the original intent/result capacity before derivation. Keep station disclosure/signing and new dispatch for this scope closed. | No reservation before a proven no-effect refusal; possible reservation retains the exact occurrence and hold. Missing local evidence never means pristine state. |
| B1 — derive and stage | Keymaker resolves the purpose-6 sibling from the existing master/name-index, derives only inside custody, and stages its public key, purpose-6 path, purpose-1 registration number and master epoch bound to the target generation and intended dispatcher. Commit protected stage/result and successful audit before any public metadata leaves Keymaker for installation. Discard transient private child material; no station file/export. | Recover only the original committed public stage after current checks. Partial stage/audit is held and reconciled; never generate another key, registration or epoch, or silently repeat derivation to replace unknown evidence. |
| B2 — install inert dispatcher association | The authenticated operator installs exactly B1's public metadata and full target/scope provenance at the dispatcher. Dispatcher owns its protected format, predecessor checks, durable idempotent install and acknowledgement. Association installation is separate from authority activation and grants no launch. Retain its exact committed identity/version in Keymaker's original transaction. | Lost acknowledgement requires authenticated lookup/reconciliation of that same install. Same bytes with unknown history are not proof; no reassociation, overwriting another predecessor or blind retry as a new install. |
| B3 — establish joint currentness and audit | Both owners verify that their protected current records identify the same installed public key/path/registration/epoch, target UID/generation, receiver/scope and immutable installation occurrence. Bind exact current revisions, not key equality alone. Durably retain the verified association and audit checkpoint before proceeding. | Missing, mismatched, stale or unknown evidence leaves the scope held. A late acknowledgement cannot reopen it. Resume only the original step after proving the actual outcome and current authority. |
| B4 — install dispatcher M0 policy | Install only dispatcher-owned limited M0 policy bound to that association, exact UID/generation, allowed plan/operations, expiry and currency rule, then establish its currentness. The pre-installed and verified broker allowlist remains a precondition; no broker policy replacement occurs here. Keep dependent new issue/start/release authority closed through installation using the jointly accepted admission protocol; an installed policy alone is not activation. | Retain partial policy installation and original evidence; no launch or compensating grant/key/policy. Missing dispatcher closure or currentness leaves this tuple unqualified; do not invent a broker field, confirmation API or disabled-entry feature. |
| B5 — verify and activate accepted scope | Revalidate B0–B4, the retained broker setup precondition and all §5 terms, durably audit/checkpoint the original installation outcome and exact operator activation, then admit only the accepted request scope. Keymaker and dispatcher independently consume current installation/activation facts; dispatcher rechecks its M0 policy at prepare and start. Broker retains its own current issue/renewal gates. | Unknown completion or one-sided activation stays closed for affected signing/new effects. Recover the original outcome and reconcile all owners before reopening; a readable success marker is insufficient. No atomic cross-service commit is claimed. |

**Joint currentness and exclusion.** Keymaker owns custody, derivation, local
intent/result retention, audit and its final release check. Dispatcher owns its
association/policy storage and encoding, install/replay transaction and actual
prepare/start authorization. Broker owns its separate v0 setup and ordinary lease
admission; B0–B5 consumes qualified setup evidence and performs no broker reload,
confirmation call or activation operation. Propose a close -> install -> verify
-> activate protocol for Keymaker and dispatcher. Every participating writer
first durably closes its affected scope under its own final release/effect
exclusion, drains or contains earlier admitted work and acknowledges that original
occurrence. Collect all required closure acknowledgements outside locks **before**
changing a live association, generation-policy link or activation decision. No
writer bypasses this barrier, including installer, revoke, restore and recovery.
Generation changes additionally retain user-manager's authoritative final fence.
For every Keymaker stage/result disclosure, including recovery, the final bounded
verified generation window checks both operator and target active; target binding,
policy and custody checks, owning state/audit and actual handoff remain ordered
against retirement. An operator-only generation check is insufficient. Dispatcher
likewise rechecks the target generation at its actual install/start boundary.
Then install only against the retained exact predecessor, verify the same complete
committed association at both owners, and durably publish the operator's activation
decision bound to that occurrence and the accepted tuple. Each service consumes
that same protected decision plus its own matching current records under local
exclusion; it must not require another service's open bit to open its own scope.
The next mutation repeats the closure barrier before replacing those records.

Joint publication must bind authenticated delivery/acknowledgement, exact current
record identities and nonregressing versions to this protocol, specify competing
installer serialization and restore/old-writer exclusion, and qualify each final
local check. The concrete dispatcher storage/encoding remains dispatcher-owned;
no acknowledgement schema or field is assigned here. A saved acknowledgement,
polling interval, matching key or time-to-live alone cannot supply currentness.
Missing closure participation or unknown currency keeps admission closed. External
delivery/queries run outside short state/generation locks; re-enter local exclusion
and revalidate the same attempt before commit/release.
No Keymaker lock is held waiting for the dispatcher or any external dependency.
The proposed original installation budget below is independent of enrollment issue/consumption, native
two-second calls and approval lifetime. Its time/custody, workload and joint
consumer qualification remain required; the proposal keeps the entry closed.

#### Original installation budget and complete endpoint

**Owner budget decision — proposal: whole B0–B5 installation <=120 seconds.**
Name the original installation start **t_B**: entry to B0 reservation, before
configuration/provider lookup, locks, closure acknowledgements, operator
confirmation, reservation or derivation. It is not successful reservation time.
Capture the original exclusive ceiling **D_B=t_B+120 s**, using checked qualified
suspend-aware elapsed arithmetic, and intersect every shorter original caller,
authority and component deadline. These are semantic timing properties for the
next owning transaction, not new request/acknowledgement members. Retain the
original occurrence, start/deadline, exact predecessors and step outcomes through
restart; unavailable boot/deadline continuity holds, never starts another timer.

The following are **proposed installer scheduling caps**, not measured bounds or
confirmed dispatcher service numbers. Broker setup has no phase in this table.
Each step starts once; its deadline is the earlier of that first step entry plus its allowance, its cumulative
cutoff from t_B, and the original effective D_B. Exact retries, lookups and
reconciliation retain that same step deadline. No unused allowance transfers to
a later step or permits work after a cutoff; equality refuses.

| Step | Owning participants | Installer allowance | Cumulative exclusive cutoff from t_B | Included work / joint confirmation |
|---|---|---|---|---|
| B0 | Keymaker; operator authorizes; each owner closes its scope | 10 s | 10 s | Entry, bounded inputs, operator/target checks, closure and intent/capacity reservation. Dispatcher closure calls/bounds remain joint inputs; retained broker setup evidence must already qualify. |
| B1 | Keymaker | 10 s | 20 s | Resolve/derive once in custody; full protected stage/result/audit durability and required custody confirmation before disclosure. |
| B2 | Dispatcher; operator installs; Keymaker retains evidence | 20 s | 40 s | Inert association install, acknowledgement, permitted exact retry/status lookup and local retention. Dispatcher service/workload numbers remain joint inputs to be confirmed. |
| B3 | Keymaker and dispatcher | 20 s | 60 s | Exact current association/revision verification, any same-occurrence reconciliation and durable checkpoint/audit. Dispatcher currentness/lookup bounds remain joint inputs. |
| B4 | Dispatcher; operator authorizes; Keymaker retains evidence | 40 s | 100 s | Dispatcher M0 policy installation and currentness, acknowledgements/lookups and partial-outcome retention only. All 40 s is the proposed dispatcher installer cap; service/workload bounds remain joint inputs to be confirmed. Broker share: zero. |
| B5 | Keymaker and dispatcher under operator activation | 20 s | 120 s | Final current checks, retained setup-evidence validation, exact durable B5 outcome/audit/custody and each applicable final activation/opening. Dispatcher activation/currency bounds remain joint inputs; no broker operation is scheduled. |

The allowances sum to **120 s = 10+10+20+20+40+20 s**: 20 s for local
reservation/staging, 80 s for dispatcher installation/currentness and 20 s reserved
for full finalization. The former broker/dispatcher B4 envelope is reassigned
entirely to dispatcher policy installation and currentness; broker time in B0–B5
is **zero**. This preserves the ceiling and fixed cutoffs, not a transferable
setup allowance. It is a finite owner proposal with explicit finalization
headroom, not a claim that remote calls, storage or a person meet it. All
dispatcher service/workload numbers remain joint inputs to be confirmed; these
installer caps assign no service promise. Owners must confirm feasibility or
propose a reviewed revision before implementation/activation; unknown component
bounds close the tuple.

**Human steps count inside the same ceiling**, including think-time, prompts,
review and explicit operator actions. The intent is one bounded installation,
without indefinitely retaining nearly-ready authority between human steps.
Read-only preparation of a candidate decision before t_B grants no installation
authority; B0 independently revalidates it under the original deadline. A slow
confirmation refuses/holds the original occurrence as applicable. A prompt,
manual handover or supplied confirmation cannot restart t_B or borrow the
approval TTL. No automatic fresh occurrence is authorized by this refusal.

**Complete enforced endpoint.** Before the effective D_B and B5 cutoff, commit
the exact original B5 installation outcome, all required owning state and audit,
independent custody/acknowledgement evidence and checked file/namespace barriers;
then complete each required final activation/admission opening under its current
local exclusion within those same bounds. No required authority durability may
follow opening. Every owner must enforce its part against delayed or restored
executors, including previously prepared activation responses. A caller timeout
or cancellation alone cannot stop a remote writer. A late acknowledgement,
readable success marker, durable outcome alone or post-expiry response refusal
cannot authorize a later opening. No atomic cross-service commit is claimed.
Only a subsequent notification reports the already-complete original outcome;
notification loss cannot refund it or cause a second activation. A scope already
fully activated on time continues only under its ordinary current policy,
qualification and runtime limits; 120 s is not its policy lifetime.

After each sole qualified final read, the enforced positive post-read bound
must cover that owner's entire remaining act/use/outcome/opening endpoint,
including pauses, storage stalls and custody/release ordering. All external
preparation remains outside final locks, with exact revalidation before entry;
no remote call, refreshed receipt, second clock read or new use admission repairs
an expired final window. Intersect any applicable native/generation/time window
without enlarging its allowance. No such installation endpoint/fence is qualified
on Linux or macOS; both remain closed. Original elapsed bounds and independently
qualified time/currentness are separate requirements, not a polling interval.

**Retry and reconciliation cutoffs.** No installation/status/retry call may
start unless its accepted complete bound fits strictly inside the original step
cutoff and remaining D_B. Every retry uses the original occurrence and canonical
arguments; no duplicate key, registration, association, policy or activation.
B2 ends before t_B+40 s, B3 before t_B+60 s and all B4 work before t_B+100 s;
B5's last 20 s is not another install/retry allowance. An unknown outcome at any
cutoff, especially D_B, retains actual pending/held evidence with affected
signing/start/issue authority closed, never a claim of no effect. Late or duplicate
acknowledgements may be retained for investigation but cannot reopen the scope.
After expiry, a separately authorized, finitely bounded recovery may establish
only the exact old outcome and contain effects; it cannot finish or reactivate
the expired installation. Any later installation needs a distinct explicit
operator decision only after the predecessor's effects/holds are conclusively
resolved under the owners' accepted recovery protocol. Changing IDs, Run, epoch,
process, connection or host is not that resolution and never clears the debt.

**Maximum admitted load — proposal and remaining joint inputs.** One occurrence
addresses one active target generation, one purpose-1 binding, one purpose-6
stage and one dispatcher/scope; B4 installs one dispatcher policy and verifies
its currentness. Broker setup load is separate and unconfirmed; it is not charged
as a B4 installation or hidden in another phase. No batch install, additional
target or arbitrary inventory scan is admitted. Propose a **Keymaker-controlled 8 MiB aggregate byte-work cap per
step** (48 MiB across six steps): charge all bytes Keymaker reads, validates,
writes or sends, including repeated work, retained originals, stage/result/audit
and custody evidence. Count each access/transfer again, not only distinct bytes.
Also propose **at most 16 Keymaker-initiated dependency calls per step**
(96 across the installation), charging each initial request, retry, status lookup,
reconnect and time/generation/custody/audit invocation; a retry cannot reset the
counter. These installer caps deliberately bound a small M0 qualification workload;
they are not component owners' internal call counts, a frame-size change, a cache
exemption, another storage allowance or a promise of throughput.
All retained bytes still fit the existing single 256 MiB state budget and audit
budgets; reserve the full actual inventory before work. Oversize or unknown
complete workload refuses before effects, never truncates needed history.

| Step | Local logical work cap for the same occurrence | Bytes and delegated-call bounds still required before admission |
|---|---|---|
| B0 | One original reservation/closure transaction, no target batch | Keymaker <=8 MiB / <=16 dependency calls; dispatcher closure, retained setup-evidence validation, generation/time/custody and audit dependency bytes/call counts need accepted joint limits. |
| B1 | One derivation and one owning public-stage transaction; no second derivation to replace unknown evidence | Keymaker <=8 MiB / <=16 dependency calls; complete custody/audit/time-original closure and nested calls require qualified limits. |
| B2 | One association installation identity; repeated calls cannot mean another install | Keymaker <=8 MiB / <=16 dependency calls; dispatcher install/ack/lookup/retry bytes and total calls are **joint inputs to be confirmed**. |
| B3 | One exact association/currentness checkpoint transaction | Keymaker <=8 MiB / <=16 dependency calls; dispatcher verification/reconciliation bytes and total calls are **joint inputs to be confirmed**. |
| B4 | One dispatcher policy identity and its currentness; no broker operation | Keymaker <=8 MiB / <=16 dependency calls; dispatcher input/output, install/currentness/lookup/retry bytes and total calls are **joint inputs to be confirmed**, including all internal delegated work. Broker setup bytes/calls belong to its separate precondition budget. |
| B5 | One original completion/activation outcome; exact recovery never repeats activation | Keymaker <=8 MiB / <=16 dependency calls; dispatcher activation/status, retained setup-evidence validation and custody/audit/time dependency bytes and total calls are **joint inputs to be confirmed**. |

No remote service guarantee, internal RPC/retry count, acknowledgement grammar
or broker feature is inferred from those local installer caps. Each owner must publish
finite aggregate bytes/calls for the initial call, every status lookup, retry,
reconnect, reconciliation and nested custody operation under its phase cap.
Unset is **unqualified**, never zero, unlimited or “one logical call”. Until
those inputs and actual persistence workload are accepted, this is an
incomplete joint admission envelope and no bootstrap is admitted. Changing a
bound invalidates qualification for that tuple. There is no new wire field,
public method, refusal code, side ledger or implementation in this proposal.

The acyclic installation dependencies are independent operator/qualification
inputs plus pre-installed/verified broker setup -> active purpose-1 binding ->
B0/B1 protected public stage -> B2/B3 inert current association -> B4 dispatcher
M0 policy/currentness -> B5 full activation. No step needs a station signature, launch or lease produced by a later step. The
mechanism maintaining closure during partial installation is a joint acceptance
gate, not an assertion that present v0 services implement it. Inert staged records
cannot satisfy §5's runtime readiness conjunction by themselves. All normal
station public-key/signing calls still require the complete conjunction.

**Audit and refusal.** Use §6's proposed `station_caller_pubkey` operation and
`control` domain for the operator's public-metadata stage/installation outcome,
with actual authenticated operator attribution in existing UID/generation fields;
the target's full association and step/outcome correlation belong in protected
transaction evidence linked to the audit sequence/hash. Never attribute the
operator as the target peer or invent a canonical native frame for an internal
step: `payload_digest` is null when no canonical native request was accepted.
This use needs the explicit writer/reader/attribution review under SC-Q6; no new
audit member, operation literal, public method or dispatcher field is allocated.
Audit success alone neither proves dispatcher installation nor opens authority.
Every outward successful bootstrap result requires durable owning state/audit;
audit failure is `audit_unavailable` and retains any possible remote effects.

Preserve earlier precise base refusals (§2.2). Missing allocation, qualified
operator entry/adapter/tuple/activation scope is `station_caller_unqualified`.
Unavailable complete protected stage/association/current-authority evidence uses
`station_caller_plan_unavailable`; complete but inconsistent target, predecessor,
association, policy source or scope uses `station_caller_plan_invalid`. Here the
existing proposed plan codes also describe protected bootstrap evidence; neither
admits a new station-supplied plan/body. They remain `retryable=false`: operator
reconciliation of the same occurrence is not a transparent retry. Unknown writes
retain a hold and actual evidence, never a claim of no effect. No new code is
needed. No signing challenge or purpose-2 proof substitutes for operator authority.

**Invalidation.** A generation change/retirement, purpose-1 or caller-key
revocation, epoch/association change, stop or qualification-tuple change closes
affected readiness before a new signature/public disclosure or dependent
start/release, cancel included, including retained results and asynchronous
completions (§6). M0 policy expiry or revocation immediately closes new `dispatch`
signing; it preserves only the exact admitted run's reduce-only `cancel` consent
under §6, without renewing dispatch authority. Other policy changes invalidate
the affected operation scope before its next release.
Recreate requires a new association installation, new M0 policy and explicit
operator verification of the broker setup precondition for the exact target UID
before B0; retained identical public bytes never reactivate the old association.
A UID-only v0 entry does not attest a generation: the owners must invalidate old
admission, with explicit new-generation installation and generation binding
enforced by the protected M0 policy and joint currentness protocol. Any required
allowlist replacement remains a separate operator setup before B0, while admission
is closed and no lease is active on that broker. No implicit UID reuse, bump or
rotation is enabled.
Authorized stop/recovery retains its own prerequisites and original stop deadline.

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
Section 4.1 distinguishes independently qualified, operator-authorized inert
staging from completed bootstrap/runtime activation. Staging is not station
readiness, and no part of the conjunction is waived for station output.
The separate protected **operator service root stays independently usable** under
its own authority and recovery prerequisites; it is never restored into a station.

Relevant tuple/profile/key changes invalidate readiness before another
signature release or dependent effect. Policy changes, expiry and revocation
close the affected operation authority; only §6's retained reduce-only cancel
consent survives expiry/revocation of M0 launch policy, with all other readiness
terms still required. It cannot reopen dispatch. No revoked rollback, receipt-only
migration, standalone credential-refresher conformance claim or silent weaker fallback.
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

M0 launch-policy expiry or revocation immediately closes new `dispatch` signing.
Reduce-only owned-run `cancel` stays signable under **retained consent** only
for the exact run durably admitted under that policy and not yet confirmed
stopped, while the caller association, purpose-1 binding/generation and caller
key remain current and not revoked. The protected typed cancel plan must prove
that original admission, ownership and current stop state; it grants no new
authority, extension or re-dispatch. All remaining qualification, custody,
audit/replay, current-plan validity and original request deadlines still apply;
retained consent renews no expired plan or deadline. Dispatcher independently
checks that same reduce-only scope at the cancel effect boundary. A non-admitted,
foreign or confirmed-stopped run refuses `station_caller_plan_invalid`; missing
complete protected evidence is `station_caller_plan_unavailable`. Terminal stop
also prevents a cached signature from being disclosed on retry. Missing live
cancel qualification/association refuses `station_caller_unqualified`, preserving
earlier precise base key/generation refusals. Association, key or generation
revocation closes cancel signing too; retained consent never authorizes a
compromised or obsolete signer.

The dispatcher's automatic P7 stop does **not depend on any Keymaker signature**,
including when association/key/generation revocation prevents requester cancel.
It uses retained stop consent under its own authority and the original deadline:
at most 300 seconds from detection, or the shorter profile bound, without renewal.
Confirmed account-wide absence and quiet period remain required (the stop rule below).

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
| SC-V4 disabled gate | Independently missing purpose, either adapter, qualification or activation: `station_caller_unqualified`, for public key, bootstrap completion and delegation separately | Exact accepted tuple activates and each path actually obtains only its allowed output; protected operator service root remains usable while station gate is closed | Bypass one readiness term; SC-V4 StationCallerPurposeDenied / DW-30 |
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

### 7.1 M0 bootstrap paired qualification requirements

All rows are **PENDING / NOT RUN**, including native Linux and macOS. Each
claim applies to the protected operator entry and affected production receiver,
not just codec fixtures. After possible effects, retain the actual attempt/hold;
only clean pre-effect refusals assert no mutation. Test permitted audit separately
from forbidden disclosure, association replacement, issue or start. SC-V4 still
requires independently qualified/authorized staging and full activation before
station output; its bootstrap-completion case cannot make B2 depend on B5.

| Named test / claim | Negative and required state | Nearby positive | Narrowing control / intended failing test |
|---|---|---|---|
| `SCBootstrapAdmissionClosed` | Missing allocation, qualified operator entry or either adapter refuses `station_caller_unqualified` before derivation/staging; no station output. | Independently accepted/authorized installation scope may stage inert public metadata while station readiness remains false. | Bypass staging qualification; `SCBootstrapAdmissionClosed`. |
| `SCBootstrapExactBinding` | Inactive operator, wrong/retired target, foreign registration/epoch/path or lost custody refuses the precise base code or `station_caller_plan_invalid`; no substituted binding/key. | Exact active purpose-1 target derives/stages only its purpose-6 sibling. | Drop target/generation comparison; `SCBootstrapExactBinding`. |
| `SCBootstrapAuditBeforeExposure` | Fail/unknown stage or audit sync: `audit_unavailable`, retained hold, no public metadata forwarded or station result. | Durable owning stage/audit precedes first protected delivery and later successful completion. | Forward before sync; `SCBootstrapAuditBeforeExposure`. |
| `SCBootstrapInstallIdentity` | Stale predecessor, wrong dispatcher or changed same-ID arguments cannot overwrite/associate; changed args give `request_conflict`. | Authenticated same-ID/current exact install recovers the original durable association identity. | Accept different predecessor under same ID; `SCBootstrapInstallIdentity`. |
| `SCBootstrapCurrentnessABA` | Change an association without closing both owners, withdraw/re-add equal bytes, stale generation/version or late acknowledgement cannot restore admission; mismatch/unknown uses the specified invalid/unavailable refusal and retains closure. | Current nonregressing same installation passes both owners' final checks. | Omit one owner from the closure barrier or compare public key only; `SCBootstrapCurrentnessABA`. |
| `SCBootstrapCrashCuts` | Inject death/unknown outcome before/after every B0–B5 local write/sync, remote install/ack and activation; retain original debt, no duplicate registration/install/activation or replacement occurrence. | Verified same-occurrence recovery reaches only the original outcome after current checks. | Treat absent acknowledgement as no effect; `SCBootstrapCrashCuts`. |
| `SCBootstrapInstallOrder` | Missing association/allowlist/policy, unsupported scoped closure or one-sided activation never enables station output/new issue/start; missing qualification uses `station_caller_unqualified`. | Fully accepted B0–B5 order reaches only dispatch and owned-run cancel under current M0 policy. | Let an installed allowlist or marker imply readiness; `SCBootstrapInstallOrder`. |
| `SCBootstrapRecreateFences` | Change generation, revoke, stop or change tuple between stage and release: no cached/late output/start, no silent policy/allowlist adoption. | Explicit new association/policy installation for the new accepted generation, with separately verified current broker setup and any required replacement only while no lease is active, can activate. | Reuse equal-key old association; `SCBootstrapRecreateFences`. |
| `SCBootstrapRetentionAndReaders` | Exhaust reserved capacity, downgrade to an old reader or restore unknown history: precise capacity/audit/source refusal, retained original evidence, no reset/prune/reissue. | Qualified supported reader recovers bounded exact state/audit without altering historical bytes. | Reset unknown occurrence to pristine; `SCBootstrapRetentionAndReaders`. |
| `SCBootstrapCancelAfterPolicyExpiry` | After policy expiry/revocation, new dispatch refuses `station_caller_unqualified`; revoked association refuses cancel with that code (earlier precise key/generation refusals still apply). Cancel for a non-admitted, foreign or confirmed-stopped run, including cached replay after stop, refuses `station_caller_plan_invalid`, with no signature/onward effect or renewed authority. | With policy expired or revoked, the same qualified current caller signs only reduce-only cancel for its exact admitted, not-confirmed-stopped run; dispatcher may stop it under retained consent. Automatic P7 stop still progresses when signer revocation closes cancel. | Blanket-deny expired policy must fail the positive cancel assertion; admit dispatch on retained consent, skip signer revocation, or omit run admission/stop checks must fail the corresponding denial in `SCBootstrapCancelAfterPolicyExpiry`. |
| `SCBootstrapAllowlistActiveLeases` | Attempt allowlist replacement while any lease is active: operator setup forbids the operation, so it is not performed; B0 cannot use the attempted setup as evidence. Do not assert daemon rejection: successful Replace would invalidate every old-generation lease. | With admission closed and no active lease, operator replacement and qualified exact-UID `status` establish the separately bounded precondition before B0. | Permit setup with active leases; `SCBootstrapAllowlistActiveLeases`. |
| `SCBootstrapAllowlistPositiveEvidence` | Reload with no error, `status` with a stale/wrong `policy_generation` or missing required account, wrong peer UID, or a foreign-UID negative control returning allowed accounts cannot satisfy setup or admit B0. Any `lease.request` precondition probe is forbidden; no token/lease is issued by these controls, and failed qualification keeps admission closed. | Qualified peer-scoped `status` from the exact station UID returns the expected new `policy_generation` and required account, with no lease payload; the paired foreign UID gets empty or denied. Both fit the separate setup budget before B0. | Accept wrong generation/account, skip foreign-UID control, treat no reload error as evidence or permit `lease.request` probing; `SCBootstrapAllowlistPositiveEvidence`. |
| `SCBootstrapBudgetTimelyLate` | Exhaust B0 entry-to-completion time, any step cutoff or shorter caller bound; B5 outcome/audit/opening at equality or later cannot activate. | Same workload completes every step, full durability and all final openings strictly within the original bounds; subsequent notification may be lost without repeating activation. | Reset t_B at reservation/step entry, transfer unused allowance, or omit final opening; `SCBootstrapBudgetTimelyLate`. |
| `SCBootstrapBudgetUnknownCeiling` | Lose install/activation acknowledgement or custody/audit durability at a cutoff/D_B: retain exact held evidence and closed authority, no assumed rollback or no-effect result; a late ack cannot reopen. | Within the original bound, authenticated exact-outcome reconciliation proves complete durability/currentness before the same occurrence's sole activation. | Treat missing ack as no effect or accept late ack as activation; `SCBootstrapBudgetUnknownCeiling`. |
| `SCBootstrapBudgetRetryCeiling` | Retry, lookup or recovery after the original phase cutoff/D_B, including a new ID/Run/epoch or fresh receipt: no renewed install/activation or refunded debt. | An accepted bounded exact retry/status lookup fits the same original cutoff and returns only its original proven outcome, without another effect. | Give reconnect/reconciliation a fresh timer or occurrence; `SCBootstrapBudgetRetryCeiling`. |
| `SCBootstrapBudgetHumanPause` | Human pause, suspend or delayed confirmation consumes the original allowance and cannot reopen expired installation; unknown prior effects stay held. | The same independently authorized operator confirmation arrives and all endpoints complete within the original ceiling. | Start timer after confirmation or exclude think-time; `SCBootstrapBudgetHumanPause`. |
| `SCBootstrapBudgetLoad` | Missing joint byte/call limits, a second target, exceeding charged repeated byte-work/call caps or unbounded nested work refuses before new effects; preserve any earlier evidence. | One target's complete original workload fits accepted local and joint caps, including all retries/originals and reserved durable evidence. | Treat unset calls as unlimited or count repeated bytes once; `SCBootstrapBudgetLoad`. |
| `SCBootstrapBudgetPostReadPause` | Pause after a final read, during outcome/audit/barrier or between durable B5 outcome and opening: enforced original bound prevents late activation; preserve exact unknown/burned outcome. | The same fully admitted native endpoint durably commits and opens on time, with no second read or RPC under final locks. | Replace actual endpoint enforcement with a timer/post-write error; `SCBootstrapBudgetPostReadPause`. |

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
