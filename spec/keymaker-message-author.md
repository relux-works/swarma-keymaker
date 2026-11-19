# BIP-340 message author: fixture source contract

Status: **fixture-only, not live**. Numeric purpose 9 / `message-author` is
allocated in the [authoritative catalog](keymaker-purposes.md). Public
`messageauthor` supplies inert typed values/framing; the private key capability
has no production constructor, loader, initializer, dispatcher or state owner.
These method names do not register RPCs. Existing runtime/config/startup/native,
legacy purpose allowlists, request history and J7 gates remain unchanged.

## Exact upstream profile

Pin [swarma-envelope](https://github.com/relux-works/swarma-envelope/tree/065e25f69da8b28cdf3ea35d9fcd7fc4aacc4d5e)
commit `065e25f69da8b28cdf3ea35d9fcd7fc4aacc4d5e`, module
`v0.0.0-20261114153213-065e25f69da8`, sum
`h1:Dlnt/FeaU6ysDHyE1x11mk1qeKtXNa5NDmwyO3139aM=` and go.mod sum
`h1:KRYIv6a94YcuR4jNhQlbyMtS1oMRSyt7qTnlO0hp6/Q=`. The receiver must use the
same verifier version. This does not opt into registry currency /2 or provide
currentness authority. Historical /1 fixtures remain explicitly historical.

```text
K = "bip340:" || base64url_no_pad(raw_x_only_32)
R = {body:BODY,key:K,role:"author",version:"swarm-envelope/2"}
P = ASCII("swarma-msg/2") || LF || CCJ-1(R)  # original bytes, no final LF
H = SHA256(P)                             # exactly once
S = BIP340.Sign(selected purpose9 key,H,fresh_aux32)
```

The envelope content ID instead hashes the domain/LF/canonical **body**, not R.
There is no digest selector or generic hash signing API. BIP-340 internal tagged
hashes stay inside BIP-340. Signatures are raw64, original r<p/s<n, high-s valid;
keys are strict x-only32/lift_x, canonical unpadded URL base64. No parity bytes,
DER/ECDSA/low-S conversion, alternate outer tag or Ed25519 relabeling.

Provider admission uses exact upstream `record.AdmitSigner` with mandatory
`MultiAgent=true`, `Check=true`: decoded P<=24576, first-LF tag1–96 printable
ASCII and exact `swarma-msg/2`, canonical CCJ-1 with depth12/string8192/array64,
then independently resolved own K equals both top `key` and `body.author`, and
fixture-current T equals `body.author_attestation`. The original bytes are
copied privately; signing reselects the exact Store binding, rechecks admission,
hashes P internally, obtains aux32 and self-verifies before returning bytes.

This is deliberately the upstream **opaque byte provider**, not an author-only
inner record dialect. Canonical role/type/version/action claims can pass byte
admission when all three protected identity paths match. Full receivers still
reject forbidden claims. Math cannot grant approver, service, grant, device,
operator or root authority. Full matched `VerifyMessage` checks the closed
message/1 schema, signature roles/profile, independently pinned purpose5-issued
BIP-340 agent subject, current binding/time/revocation evidence and exact
room/recipient/delivered UTF-8 text hash. Message validity is at most120s;
attestation validity at most86400s. Wire attestation purpose is `swarma-msg`,
not numeric9; subject.algorithm is `BIP-340`, roles `[author]`, actions
`[message.sign]`. Purpose9 cannot issue its own certificate or a revocation.

## Independent custody and selection

The private capability owns distinct seed/role/instance/epoch/registry pins,
mutex, entropy source and closed state. Only explicitly public test roots
construct it. It reuses the hardened SLIP-0010 secp arithmetic protocol, never a
legacy Ed25519 node or J7 key/root/role/withPath capability. The logical epoch
must equal the selected purpose1 binding's epoch; equality is not root sharing.
An exact active binding includes UID, generation, path, owner, registration
number, lifetime/status, epoch and registry revision. Wrong/missing/retired
selection, failed Store, invalid custody/role/instance or entropy failure yields
no signature. Returned bytes are detached; diagnostics redact and JSON/text
serialization refuses. Go erasure is best effort, not hardware non-extraction.
An operator copying seeds cannot be detected by a source fixture.

Within an independent root/epoch a persistent path has stable K. Registration
or GEN changes require a new T even if K remains equal. No new protected root
file/config/lifecycle format is introduced, and no rotation under the same pins
is authorized. Purpose1 registration, legacy Resolve/Public/Sign and Surface A
remain closed to9. See [caller API](../messageauthor/README.md) for exact
request/result/error grammar, frame caps and outstanding-request correlation.

## Live prerequisites, explicitly absent

A separate live coordinator must own all of the following before real traffic:

1. Actual accepted kernel principal/current GEN, independent holder's qualified
   authoritative binding feed, withdrawal ordering and per-connection pins.
2. Qualified purpose5 certificate issuance/publication/current-T selection,
   trusted time/revocation/witness proof and pending-renewal fences. Existing
   `messageCurrent` remains `key_not_enrolled`; no fixture map or readable
   certificate becomes a live provider.
3. Separately reviewed role/config/root/state participant and finite capacity,
   exact caller+request ID+method+canonical params/P+binding/root/K/T retained
   identity. No numeric store schema/floor is assigned by this source unit.
4. Durable intent before crypto, exact randomized result and audit before wire,
   same-ID conflicts, one signing invocation for concurrent equal retries,
   restart/pending/unknown-outcome and zero/partial-write recovery. Retry reuses
   the identical retained signature, never fresh signing.
5. Real GEN -> binding/current-certificate/state -> custody exclusion through
   actual response write and every retry; withdrawal/renewal/expiry before
   release suppresses success. No indefinite metadata lock across socket reads,
   unbounded proof fetch under a barrier or fake currentness Boolean.
6. Independent reviewed source, CI, separately provisioned holder/custody and
   privileged operator/native qualification. Real keys remain gated on J7.

The public codec and private fixture results establish none of these. No
bootstrap, enrollment, filesystem initializer or deployment instruction is
provided here. M2 can develop the pinned client; live signing remains closed.

## Consumer ownership

M2 authenticates its holder route, verifies sender-carried A under the approved
per-host purpose5 pin and its own binding, then uses the K/T/A identity response.
For signing it supplies exactly P, checks correlated K/S against that verified
identity, independently verifies S over P, assembles E once and publishes/retries
identical E bytes. Expiry requires a new nonce/iat/exp and native request ID;
T renewal requires a new P/ID. A retry bit or lost reply proves no lack of commit.

M3's consumer/format belongs to the carrier: verify sender-carried A against an
owner-approved per-host purpose5 pin and a host-owned pinned UID/registration to
carrier-sender projection. There is no fleet export or public Store.Snapshot
endpoint. Multi-recipient encoding/255-byte overflow and action-specific
kind/topic/re binding belong to the carrier, not this Keymaker profile.

## Fixture validation and limits

New public test roots/vectors live only in
`internal/keymaker/testdata/message-author-v1`; wire literals in
`messageauthor/testdata/wire-v1`. Their manifests bind payload SHA256 and exact
upstream identity without self/commit hash cycles. No historical seed/vector is
rewritten. Tests pair valid controls with exact refusal codes/nil results,
binding/custody/entropy faults, canonical bounds, provider/receiver asymmetry,
full certificate/delivery negatives, official BIP fixed32 vectors and the pinned
stdlib public-math oracle. Existing real-Unix legacy rejection and startup gates
are regression witnesses only. They do not qualify native or current authority.

Run bounded checks with the pinned Go toolchain/private caches as described in
[the codec README](../messageauthor/README.md); the `message-author` mutation
group plants only changed source gates. MVS/build/vet and independent review
remain required for adoption. No producer full-suite result is implied.


## Live participant (A7a-2)

Status: **live source contract; production signing remains closed**. The preceding
fixture-only sections describe existing source and remain intact. This section defines
the separately reviewed live participant, not a claim that it is implemented, installed
or qualified. The production current-T provider MUST refuse `message_author_unqualified`
for both identity and sign until the separately reviewed issuer-side integration is
available. A source commit, healthy configuration, enrollment or a fixture certificate
cannot open it. Code implementation requires owner acceptance of this exact spec
revision.

The [Exact upstream profile](#exact-upstream-profile) remains frozen to envelope
`v0.0.0-20261114153213-065e25f69da8`. K is canonical `bip340:` plus strict
x-only32/lift_x; R is `{body:BODY,key:K,role:"author",version:"swarm-envelope/2"}`; P is
`ASCII("swarma-msg/2") || LF || CCJ-1(R)` without a final LF. H is SHA256(P) exactly
once, and S is raw64 BIP-340 with fresh aux32 and valid high-s preserved. T is A's
lowercase `sha256:` content ID from the pinned envelope content-ID function, never a
local replacement. The selected own K equals both record key and body.author; current T
equals body.author_attestation. A has a BIP-340 subject, role author and action
message.sign, with validity at most 86400 s. Message validity at most 120 s belongs to
the sender. Holder byte admission interprets no other BODY claim and grants no claim
authority.

Purposes 1, 2, 4, 7 and 8, their allowlists, legacy Resolve/Public/Sign, registration,
request history and J7 gates retain their existing meaning. Purpose 9 gains no legacy
surface. PC2 remains conditional and inactive. Within this section, numbered clauses 2-8
and their tables are local to this live contract; references to base sections identify
the base specification.

### 2. Role, files, store and operator source contracts

#### 2.1 Separate participant and packaging source

| Surface | Single required form |
| --- | --- |
| Role selection | New `service_role:"message-author"`, selected from protected config in the same role-selection pattern as `j7-request`. |
| Example config source | `packaging/message-author.example.json`. |
| Config installation contract | `/etc/swarma-keymaker-ma/config.json`, root-owned mode 0640; specify it in source, do not install it in this unit. |
| Unit source | `packaging/swarma-keymaker-message-author.service`; User/Group `swarma-keymaker-ma`, `NoNewPrivileges`, empty capability sets, using the J7 unit form. |
| Socket | `<socket.dir>/control.sock`, mode 0660, group exactly `socket.group` from installer config; example directory `/run/swarma-keymaker-ma`. |
| State | Own state directory, example `/var/lib/swarma-keymaker-ma/state`, with its own `audit/` and `generation.anchor`. No shared legacy/J7 state. |
| Implementation | `internal/keymaker/message_author_live*.go`: participant, handler, release and recovery, with adjacent tests. |

Directory, UID/GID and group choices on an installed host come from protected installer
configuration, not a producer-selected principal or request parameter. Packaging files
describe the contract only; neither service installation nor service startup with live
custody is an acceptance step.

Use the existing `messageauthor` typed codec/framing and existing hardened purpose-9
arithmetic/custody building blocks. Bounded wiring into existing config, role startup,
CLI, Store/snapshot, request-id and audit integration points is allowed only to support
this participant and its named commands; list each such existing-file delta in the
handoff. No new issuer package, issuer config or issuer lifecycle is authorized.

Keep `TestMessageAuthorRuntimeStaysClosed` as the legacy real-socket rejection witness
for **both** methods. Method names stay out of `internal/keymaker/native.go` and
`internal/control/server.go`. `config_linux.go` may contain exactly the new role string,
not those method names; retain a negative test proving every other service role still
refuses the message-author methods. Update any source-isolation allowlist narrowly for
the explicitly reviewed live files, not by dropping its prohibition. Existing capability
isolation and J7 behavior remain guarded.

#### 2.2 Schema and explicit operator commands

The new Store participant is
`message_author:{format:"keymaker-message-author-state/1",...}` at **schema 7**. The
message-author reader floor is **exactly 7**. Schema 3 remains reserved for the
authority root; schema 6 remains delegation. Never repurpose either number or accept a
weaker reader floor.

The floor is carried in a root-installed J7-form head pin,
`{"expected_version":V,"expected_digest":"D"}` followed by LF, mode 0640, outside the
service-writable rollback/backup domain. V/D are the protected expected-head values, not
placeholders that authorize accepting whatever head was read. Reuse the reviewed J7
head-pin semantics; do not invent an installer pin path or confuse this pin with the
unresolved purpose-5 issuer pin.

The audited operator command source contracts are:

- `keymaker message-author init`: the **only** creation of a fresh store; explicit
  operator intent, never implicit initialization during serving or a retry. It does not
  generate/provision a live key as a side effect.
- `keymaker message-author enroll`: enroll the participant's own exact binding record.
- `keymaker message-author retire`: retire that record and preserve its tombstone.

No legacy or J7 migration creates this store. Test initialization/enrollment/retirement
only in isolated, test-owned state. These source contracts do not authorize operating
the commands against installed state or define a provisioning runbook.

### 3. Authority, current-T boundary and custody

#### 3.1 Kernel principal, generation and own binding

Use the user-manager **`gen-journal/1` adapter** and require `generation_journal` in
config. Missing configuration refuses startup with `generation_source_unavailable`, as
J7 does. Preserve the adapter's protected floor/anchor checks; healthy mocks are not
proof that its real root-owned journal is qualified.

At accept, record `(peer_uid,generation_at_accept)` from kernel peer credentials and the
generation source, never from request fields. Revalidate per operation and at release. A
connection cannot move to another generation; invalidate and close it on
mismatch/retirement. Only active generation authorizes work. Processes sharing a UID are
not distinguishable here; do not claim process-level identity isolation.

Bindings are **this participant's own** records in the shape defined by Independent
custody and selection above: UID, generation, path, owner, registration number,
lifetime/status, epoch and registry revision. Enroll/retire are audited. At most one
binding is active per `(uid,generation)` and per `(epoch,path)`. Tombstones survive
restart; a retired path is not resurrected under its epoch. There is no legacy daemon
feed or ongoing J7 synchronization in v1. Retirement/withdrawal is serialized by the
participant's `WithActive`, including already accepted connections. In v1 the revocation
source is these own retire records, not an external witness service.

#### 3.2 Frozen current-T interface and production default

For the **exact selected binding**, the provider returns **one current `(K,T,A)` or one
refusal standing**. Re-derive that answer at admission and again inside **every** final
barrier, including identity replies and retained-result disclosure. It must be scoped to
the complete selected binding, not just K or a path. Never read issuer internals, select
a certificate by file readability, reuse a stale answer from connection 1, or infer T
from an intent.

The production provider in this unit is a **refusing provider**:
`message_author_unqualified`. It supplies no identity and authorizes no signing until
A7a-1 lands and the separately reviewed issuer-side integration is available. Landing
this holder, a healthy generation journal, successful enrollment, a fixture certificate
or a loadable key does not change that default. No hidden configuration switch selects
the fake provider in production.

Tests inject a **fake current-T source behind precisely this interface**, using public
test material and controllable current/renewed/refused standings. It may advance from T1
to T2 to exercise consumer races, but it is not an implementation of issuance,
publication, renewal or registry authority. The barrier must re-read it for the exact
binding; an always-true currentness flag is not an acceptable fake interface. Schedule
fake standing changes through the same holder-local exclusion when testing
withdrawal/renewal ordering; this proves consumer behavior, not an independent issuer
publication protocol.

#### 3.3 Independent custody

The holder owns a distinct purpose-9 seed/root, role, instance, logical epoch, registry
pins, mutex, entropy source and closed custody state. Its logical epoch equals the
selected purpose-1 binding epoch without root sharing. In v1, `keymaker message-author
enroll` takes that purpose-1 epoch and registration identity as explicit, audited
operator input and stores them in the binding record. At every admission and release the
holder MUST enforce that its logical epoch equals that recorded epoch. Enrollment with a
different epoch MUST refuse; an equal-epoch valid control MUST succeed when its other
gates pass. Equality with the LIVE purpose-1 binding is asserted by this audited
operator act, not verified against a live feed. No such feed exists in v1. Reuse
hardened SLIP-0010 secp arithmetic, never a legacy Ed25519 node, a purpose-7/8 root or
their `withPath` capability. Purpose 9 issues **no certificate and no revocation**.

Wrong/missing/retired selection, stored-binding failure, wrong role/instance,
closed/unloaded/unprotected custody or entropy failure produces no signature. No fixed
or zero aux fallback. At signing, reselect the exact stored binding, re-admit the
private copy of P, hash once internally, obtain aux32, sign once and self-verify before
release. No generic byte/digest-signing selector or key-export operation exists.
Returned public/signature bytes are detached. Capability JSON/text serialization
refuses; diagnostics redact private material. Erasure is best effort, not a
hardware-custody claim. All custody used in this unit's tests is test-only; no live
material is created or loaded.

This separation MUST NOT preclude a later purpose-5 issuer key for BIP-340 subjects
inside this same participant as a separate-purpose key, with its own derivation or
custody, internal issuance only and owner pins. That is a later reviewed extension, not
an issuer built by A7a-2. The frozen current-T interface remains the only holder
boundary. Issuer state would require its own later format revision of
`keymaker-message-author-state` and its own review. No purpose-9 path may ever sign an
attestation; purpose 9 also issues no revocation. Issuer placement, issuance,
publication, renewal, pin provisioning and real-key activation remain outside this
contract's implementation unit.

### 4. Wire contract, codes and trusted time

#### 4.1 Existing grammar, unchanged

[The existing wire grammar](../messageauthor/README.md), lines 32-97 at source revision
`c85429462831e4c74f9f791abd62e2dd33508b3f`, is normative **verbatim**. This contract
changes no wire grammar. Use the codec's spellings; do not translate them to the
purpose-4 provider-to-native mappings. The following are cross-checks, not a replacement
wire format:

- BE32 frame length 1..65536, canonical CCJ-1, depth at most 16, no trailing bytes. One
  outstanding request per connection; no pipelining or unsolicited replies.
- After native version-1 hello, requests have exactly `method`, `params`, `request_id`,
  `timeout_ms`. Methods are `message_author_identity` with `{}` and
  `sign_message_author` with `{preimage:base64url_no_pad(P)}`. No caller, key, path or
  digest selectors.
- IDs are 32 lowercase hex digits. Only hello uses its fixed id. Identity/sign use fresh
  random ids, except an exact sign retry reuses its original id and P on a new
  connection.
- Decoded P is at most 24576 bytes; enforce encoded length at most 32768 before decode.
  Its first-LF tag is exactly printable-ASCII `swarma-msg/2`. Run pinned upstream
  `AdmitSigner` with `MultiAgent=true`, `Check=true`, canonical depth 12, string 8192
  and array 64 limits. Own K must match **both** record key and author; current T must
  match author_attestation.
- Identity success is
  `{request_id:ID,result:{key_id:K,author_attestation:T,attestation:base64url(A)}}`;
  sign success is `{request_id:ID,result:{key_id:K,signature:base64url(S)}}`. A is
  1..8192 raw bytes, S exactly 64. Refusal is
  `{request_id:ID_or_null,error:{code:CODE,retryable:BOOL}}`, with exactly one result or
  error, no echoed P or free-form diagnostic.
- The first four framing-code cases in the pinned README require null id. Preserve its
  complete closed code set and retryable bits; never treat an unknown code as success.

The scripted sender exchange is: connection 1 hello + identity; build P outside holder
locks; connection 2 hello + **fresh identity** + sign immediately with no other work
between. Each request uses `timeout_ms=1500` in the sender exchange; the sender's read
budget is 2 s from before writing. The holder accepts timeout 1..2000 ms from frame
completion, bounds framing/next-frame wait to 2 s, and carries that request deadline
through handoff. No late reply after close; a timeout cannot undo a committed effect.

Deferral of verification of A under the purpose-5 pin is **receiver-scoped**. The
sender's step-2 verification of A under that pin remains mandatory **once the pin
exists**; neither implementing that sender check nor choosing/provisioning the pin
belongs here. A content-id equality check is not issuer qualification.

#### 4.2 Explicit contract update and single refusal meanings

The A7a-2 contract update adds **exactly** these eight accepted codes to [the base
section 15 table](keymaker.md#15-stable-local-refusal-codes). The subsequent
implementation must add the same eight entries to `control.validCode` in
`internal/control/protocol.go`; this spec-only change does not change that code. Each is
`retryable=false`:

| New accepted code | Meaning for this participant |
| --- | --- |
| `signer_preimage_too_large` | The preimage exceeds the pinned encoded/decoded bound. |
| `signer_tag_malformed` | The preimage's tag is malformed under the upstream admission contract. |
| `signer_domain_refused` | A well-formed tag is outside the admitted domain. |
| `signer_payload_invalid` | Payload admission fails the pinned canonical/profile rules. |
| `signer_identity_unavailable` | The pinned admission/codec identity-unavailable standing. |
| `signer_identity_malformed` | The pinned admission/codec identity-malformed standing. |
| `signer_identity_mismatch` | K/author/record-key/current-T equality fails; specifically includes a retry referencing a T that is no longer current. |
| `message_author_unqualified` | No qualified signing exists for this caller and request: no exact active binding, no current `(K,T,A)`, a fenced state, issuer not live, or this attempt terminally dead. Applies to identity and sign. |

For `message_author_unqualified`, the sender re-prepares with new P/new id or remains
unqualified; it is not invited to retry the same dead attempt. These eight additions do
not register methods on the legacy server or alter retryability of other roles' existing
codes.

Keep these distinct decisions; do not collapse stale-T refusal into a generic dead
response:

| Classified condition | Single outcome |
| --- | --- |
| Same caller/id, caller changes method or canonical arguments/P | `request_conflict`, non-retryable; no retained result disclosed. |
| Exact retained retry, current source establishes T1 is no longer current | `signer_identity_mismatch`, non-retryable; preserve evidence and terminally suppress this attempt. |
| Otherwise eligible method, no qualified identity, fenced holder, or terminal dead attempt without the preceding old-T classification | `message_author_unqualified`, non-retryable; no public result/signature. |
| Temporary unavailable generation evidence | `generation_source_unavailable`, per-request refusal; no new fence. |
| Untrusted time confidence | `clock_untrusted`, non-retryable per-request refusal; no new fence. |
| Known audit append/sync failure | `audit_unavailable` if a refusal can be emitted; close admission and release no unaudited result. |
| New-work retained/state capacity exhausted | `state_capacity_exceeded`, non-retryable; no intent, eviction or invocation. |
| Connection/request slot exhausted | `busy` under the existing codec contract. |
| Rate exhausted | `rate_limited` under the existing codec contract. |

Framing/grammar and kernel-principal checks precede retained dispatch. For a valid
correlated request, detect changed caller-supplied method/arguments against the retained
record before taking a retry path. A **source** binding/K/T change is authority loss,
not a caller argument conflict. Then distinguish a proven old T from other unqualified
states; when there is no current identity, do not invent one to decide mismatch.
Temporary generation/time failures refuse that delivery without changing a proven
retained status. An already latched fence is never cleared by a healthy sample. Each
test isolates the named classification; simultaneous failures follow the reviewed spec's
ordered checks, not a producer-chosen error race.

#### 4.3 Trusted time

Use J7's broker `timeconf` provider and **inline `time_policy`**, not a second policy
file: sync age at most **2048 s**, uncertainty at most **1.5 s**, using the existing
policy and adapter semantics. Sign release is **START class at both Lower and Upper
bounds**, the R-U2-4 form. Use conservative attestation/lifetime admission, not a single
wall-clock point. Apply fresh time evidence at the final barrier, including retained
disclosure; do not invent additional numeric windows.

`clock_untrusted` and `generation_source_unavailable` are per-request refusals, not
automatic fences. Actual uncertain durability/continuity fences clear **only by
RESOLVE**, audited operator reconciliation proving one exact state. A restarted process,
a newly healthy clock/source, or readable bytes alone do not clear them. Existing
time-adapter continuity/receipt and real-journal qualification gaps remain declared;
this unit does not claim they have been closed.

The holder does **not** decide message `exp` inside P. The sender stops retrying after
message expiry and builds new nonce/iat/exp/P/id; the holder's release standing depends
on current binding, own K and current unexpired T, not interpretation of message expiry.

### 5. Durable attempt identity, statuses and retention

Lookup is by caller `(uid,generation)` and request id; the retained equality record
includes **method**, complete canonical params and exact P, selected binding identity,
custody root/instance, K and T. Method is part of equality, not a way to allocate
another attempt with the same caller/id and escape `request_conflict`. Never reinterpret
a retained record under a newly selected binding/root/K/T.

Reserve/charge capacity before allocation or mutation. Sync complete intent before any
signing invocation. Sync `invoking` immediately before the **one** BIP-340 call. Equal
concurrent requests join that attempt, never a second call. Persist exact randomized S
and prove success audit durable before entering `result`. Persist `handoff_unknown`
before entering the actual socket callback; only a completed callback can record
`released`.

| On-disk status | Single invariant |
| --- | --- |
| `intent` | Full equality record synced; no `invoking` evidence exists; non-invocation is provable. |
| `invoking` | Invocation marker synced; crypto may have run; no second invocation is permissible. |
| `result` | Exact signature/result and its success audit are proven durable; no handoff committed in this state. |
| `handoff_unknown` | Exact result/audit remain durable; handoff marker synced before callback; client receipt is not assumed. |
| `released` | At least one complete response callback committed; exact retained result remains. |
| `dead` | Terminal suppression for this attempt; retain evidence, never invoke or disclose again except the specific old-T refusal classification. |

Absence is no row, not a seventh status. **FENCED is a participant/uncertainty overlay,
not an invented attempt status**; preserve the underlying durable row/evidence. Unsigned
intent and possible invocation are concretely distinct as `intent` and `invoking`. The
separate handoff marker makes uncertain delivery different from uncertain result/audit
durability.

No horizon, eviction or automatic reclamation exists in v1, as in [Message certification
state, finite capacity](keymaker-msg-state.md). Retain at most the attempt-row limit in section 8;
at capacity refuse new work and keep results, dead rows and tombstones. Replays still
require their ordinary budgets, durable audit and fresh authority; audit exhaustion is
not waived for a retained result. The audit journal is never the result cache.

A retained S is disclosed only while its exact binding is active, own K unchanged and T
current and unexpired. T1 -> T2 makes the old attempt undisclosable with
`signer_identity_mismatch`, even when K is unchanged; new P/new id is a fresh attempt.
Do not re-present S under another attestation. A different kernel principal never gets
the original caller's retained result.

### 6. Final release barrier and audit

Every first/repeated identity or signature success is under holder-local `WithActive`,
J7 style, in this exact order:

**generation -> binding and current `(K,T,A)` -> Store -> custody -> audit -> actual
socket callback.**

Keep that exclusion through the callback, including durable handoff admission, and
re-derive all current authority inside it. Withdrawal uses the same barrier. No
cached-currentness shortcut, indefinite metadata lock across socket reads, or unbounded
remote proof fetch under locks. The request's timeout, at most 2000 ms, remains the
deadline through handoff. PC2 is **not activated**; do not add its root transaction,
terminal-F activation claim, or numeric windows.

If withdrawal wins, suppress unreleased success, invalidate the connection and retain
evidence. If a complete response callback wins first, the released signature cannot be
recalled; withdrawal suppresses every later disclosure. A deadline suppresses that
delivery, not the durable attempt. A started durable write must complete its commit
protocol without a late response. A partial frame is a lost reply, not evidence of
absence or permission to sign again.

The participant owns a [base section-11](keymaker.md#11-audit-and-fail-closed-recovery)
closed audit journal in its own `audit/`. Preserve the closed record shape, chaining,
durability, rotation and content prohibitions. Participant validation and replay MUST
enforce the following operation/domain contract; do not borrow purpose-4 operation
literals.

| Operation | `surface` | `domain` | Payload treatment |
| --- | --- | --- | --- |
| `message_author_identity` | `control` | `control` | Existing section-11 no-payload representation; no identity blob or A bytes. |
| `sign_message_author` | `control` | `swarma-msg` | SHA-256 digest of **complete decoded P**, as `sign_message`; never P or S. |
| `message_author_init` | `control` | `control` | Closed section-11 control record; no raw operator input or custody material. |
| `message_author_enroll` | `control` | `control` | Closed section-11 control record; no raw operator input or custody material. |
| `message_author_retire` | `control` | `control` | Closed section-11 control record; no raw operator input or custody material. |
| `message_author_release` | `control` | `control` | Closed section-11 control record; no retained result/signature bytes. |
| `message_author_fence` | `control` | `control` | Closed section-11 control record; no free-form diagnostic payload. |
| `message_author_reconcile` | `control` | `control` | Closed section-11 control record; no raw reconciliation documents. |

No seeds, private keys, chain codes, raw payloads, native frames, returned
envelopes/signatures/tokens or free-form client errors enter logs/audit. Payload content
is digest-only. Durable success audit precedes public response release. Known audit
failure discards unreleased computed bytes, closes admission, and cannot leave an
unproven attempt in `result`; unknown audit durability fences pending RESOLVE. Audit
unavailability never falls back to unaudited serving.

### 7. Deterministic state, handoff and recovery tables

Each cell below names one action. Events are serialized at the holder; after an action
the next event is judged in the resulting state. "Unreachable" is a definitional
assertion needing a cited argument/test, never a fallback branch. State-changing actions
require the section-5 durability protocol; a write whose outcome is unknown is
classified by table 7.3, not treated as successful.

#### 7.1 Request/event table

`ADMIT` means fresh admission passed before intent; `RETRY` means identical retained
inputs and freshly proven current authority; `OLD-T` means the current source proves the
submitted T is no longer current, including a retained retry; `CONFLICT` means changed
caller-supplied method/params; `DUP` means an equal request to the running attempt.
`LOSS` is proven terminal loss of binding/generation/custody identity, distinct from
OLD-T and temporary source/time refusal. `WAIT` joins the existing attempt; any
subsequent disclosure takes its own barrier. `BARRIER` enters table 7.2 with retained
bytes only. `INVOKE` performs the single durable `invoking` boundary after revalidation
and pre-crypto checks, never on recovery alone.

| State | ADMIT new id | RETRY | OLD-T | CONFLICT | DUP | LOSS |
| --- | --- | --- | --- | --- | --- | --- |
| Absent | Sync `intent`; immediately continue with the `intent` RETRY action in this same request | Unreachable: unseen id is ADMIT | Refuse `signer_identity_mismatch`; remain absent | Unreachable: no retained identity | Unreachable: first admission owns this row | Refuse `message_author_unqualified`; remain absent |
| `intent` | Unreachable: occupied id | INVOKE once | Sync `dead`; refuse `signer_identity_mismatch` | Refuse `request_conflict`; keep `intent` | WAIT | Sync `dead`; refuse `message_author_unqualified` |
| `invoking` | Unreachable: occupied id | WAIT | Suppress computed bytes; sync `dead`; refuse `signer_identity_mismatch` | Refuse `request_conflict`; keep `invoking` | WAIT | Suppress computed bytes; sync `dead`; refuse `message_author_unqualified` |
| `result` | Unreachable: occupied id | BARRIER | Sync `dead`; refuse `signer_identity_mismatch` | Refuse `request_conflict`; keep `result` | BARRIER | Sync `dead`; refuse `message_author_unqualified` |
| `handoff_unknown` | Unreachable: occupied id | BARRIER | Sync `dead`; refuse `signer_identity_mismatch` | Refuse `request_conflict`; keep `handoff_unknown` | WAIT | Sync `dead`; refuse `message_author_unqualified` |
| `released` | Unreachable: occupied id | BARRIER | Sync `dead`; refuse `signer_identity_mismatch` | Refuse `request_conflict`; keep `released` | BARRIER | Sync `dead`; refuse `message_author_unqualified`; no recall |
| `dead` | Unreachable: occupied id | Refuse `message_author_unqualified`; keep `dead` | Refuse `signer_identity_mismatch`; keep `dead` | Refuse `request_conflict`; keep `dead` | Refuse `message_author_unqualified`; keep `dead` | Keep `dead`; no disclosure |

After ADMIT syncs `intent`, the admitting request itself immediately continues with the
`intent` row's RETRY action, INVOKE once, through `result` and the delivery barrier in
7.2 within its own deadline. This is neither another event nor a second admission. It
MUST NOT stop at `intent` except on a deadline or clean pre-crypto failure before
`invoking`; either leaves provably unsigned `intent`.

`invoking` in this table is the **running** attempt. On restart a proven `invoking`
without `result` becomes `dead` immediately under 7.3; it is never a resumable
cryptographic operation. For recovered `handoff_unknown`, RETRY can enter BARRIER; a
simultaneous duplicate waits for the currently running handoff. No callback may overlap
another release of this attempt.

Before invocation, a clean pre-crypto custody/entropy failure refuses without a crypto
call or result, leaving provably unsigned intent for an otherwise permitted exact retry;
set no `invoking` marker until those preparations have succeeded. A self-verification
failure after invocation discards bytes and terminally records `dead`. A proven result
transition occurs only after **both** exact result and success audit are durable.
Failure/uncertainty during these writes is handled by 7.3 and section 6, not by running
crypto again.

#### 7.2 Delivery/barrier table

These events apply to one selected delivery; they never make a second attempt. A
per-request temporary refusal preserves the last proven durable attempt state. The fence
overlay blocks admission/success independently of an underlying state.

| Classified barrier/delivery event | Single outcome |
| --- | --- |
| Full fresh authority/audit/deadline check passes for `result`, `handoff_unknown` or `released` | Sync `handoff_unknown` before the callback; hand off the identical retained bytes under the lock chain. |
| Socket callback completes a full success frame within the deadline | Record `released`; preserve exact result. |
| Callback fails or client receipt is unknown after its durable handoff marker | Keep `handoff_unknown`; close this delivery, retain identical bytes for a qualified exact retry. |
| Deadline expires before callback begins | Suppress the delivery, keep its proven retained state, emit no late frame. |
| Deadline is discovered after a durable operation began | Complete that operation's commit protocol, suppress this delivery, retain its proven state. |
| Current source proves old T | Sync `dead`; refuse `signer_identity_mismatch`, no success callback. |
| Proven terminal authority loss other than old T | Sync `dead`; refuse `message_author_unqualified`, no success callback. |
| Current provider refuses qualification | Refuse `message_author_unqualified`; no success callback or invented identity. |
| Temporary generation evidence unavailable | Refuse `generation_source_unavailable` for this delivery; do not latch or clear a fence. |
| Time confidence untrusted | Refuse `clock_untrusted` for this delivery; do not latch or clear a fence. |
| Audit append/sync known to fail | Close admission with `audit_unavailable` standing; release no unaudited bytes. |
| Evidence is uncertain or holder already fenced | Refuse `message_author_unqualified`; keep the fence until RESOLVE. |

Identity replies have no signature-attempt status: use the same
fresh-authority/audit/deadline exclusion and the unchanged identity grammar. Production
current-T refusal therefore releases neither K/T/A nor S even if the rest of the role is
healthy.

#### 7.3 Recovery and RESOLVE: evidence first, no crypto

Recovery never invokes signing, reconstructs a signature, invents T or switches to a
fixture provider. The rows below classify **durable evidence**, not file readability or
a client's belief about receipt. Missing, truncated, zero-length or contradictory
evidence cannot prove absence on its own.

| Durable evidence established after restart | Single recovered outcome |
| --- | --- |
| Authoritative continuity proves no intent ever committed | Absent; no signature/result exists. |
| Complete `intent`, with continuity proving no `invoking` committed | Recover `intent`; only a later admitted exact retry may invoke once. |
| Complete `invoking`, with authoritative continuity proving no `result` committed | Record `dead`; never re-sign, even if the call may not have started. |
| Exact `result` and its success audit both proven durable | Recover `result`; eligible disclosure still needs a new final barrier. |
| Durable `handoff_unknown` with exact result and success audit proven | Recover `handoff_unknown`; retry only identical bytes under current authority. |
| Durable `released` with its supporting result/audit proven | Recover `released`; retry only identical bytes under current authority. |
| Durable `dead` | Recover `dead`; no crypto or success disclosure. |
| Result bytes present but success-audit commit unproven | FENCED overlay; no result disclosure or re-signing. |
| Any remaining zero/partial/missing/conflicting record or head/continuity evidence | FENCED overlay; neither absence nor completion is inferred. |

RESOLVE is audited operator reconciliation, not automatic source recovery. If its
evidence proves exactly one of the first seven rows, clear the overlay to that row's
single outcome; if not, retain the fence. Proof of possible invocation without durable
result resolves only to `dead`. A single readback of result bytes is insufficient proof
of committed audit or continuity. Reconciliation never issues A, chooses a new T or
signs. Unknown client receipt with **proven** `handoff_unknown` is not an
audit-uncertainty fence; this distinction permits safe identical-byte retry without
pretending the client received anything.

### 8. Finite capacity, per participant

Charge before allocation/effect and on duplicate traffic too. No borrowing from a
legacy/J7/PC2 root budget, hidden unlimited queue, or eviction to make room.

| Bound | Exact value |
| --- | --- |
| Connections, global | 32 |
| Connections, per UID | 4 |
| Active requests, global | 16 |
| Active requests, per connection | 1 |
| Requests per UID+generation | 20/s, burst 40 |
| `sign_message_author` per UID+generation | 2/s, burst 4 |
| Global request rate | 200/s, burst 256 |
| Attempt rows | 3072, no horizon or eviction |
| State | 15 MiB, including concurrent old/staging/new snapshots and 8192 bytes of generation anchors |
| Audit segment | 64 MiB |
| Online audit | 1 GiB |
| Audit reserve | 16 MiB |

Retain the existing section-11 rotation/reserve rules; reserve does not authorize
unbounded signing after audit capacity is exhausted. Keep codec
frame/preimage/attestation bounds from section 4, not the older legacy connection count
or a PC2 numeric window.


#### Runtime memory policy

Message-author role startup calls `debug.SetMemoryLimit` with the named constant
`maLiveMemoryLimit = 192 MiB` before loading retained state. The dedicated role
sets the policy itself, so it does not depend on a missing or larger inherited
`GOMEMLIMIT`. Other roles and package initialization do not set this limit.
The unit's `MemoryMax=256M` remains unchanged: the 64 MiB gap leaves space for
memory outside Go's runtime accounting. This is a soft GC budget, not a hard RSS
limit; capacity evidence must independently check the participant process's own
peak RSS (`VmHWM` from `/proc/self/status`) below 240 MiB after the fresh sign
and after replay (16 MiB below the unit ceiling), and sampled heap below 128 MiB.
Linux `ru_maxrss` can inherit the launching parent's high-water mark across exec;
it is logged as a possibly inherited diagnostic and never used as an assertion.
`TestMALiveRSSAccounting` pairs a trivial measuring child with and without a
touched 208 MiB parent allocation: the child's `VmHWM` must remain small, while
any inherited `ru_maxrss` is reported separately. A kernel that does not expose
that inheritance is reported as such; it does not change the `VmHWM` gate.

`TestMALiveCapacityLatency` uses this same startup helper before fixture setup,
then exercises the persisted/reopened near-bound state in separate one-CPU and
`runtime.NumCPU()` children. Five repeated runs use race instrumentation off.
An otherwise identical child without the limit retains all assertions as a
negative diagnostic; local survival does not establish that the policy is
unnecessary. Earlier hosted `ru_maxrss` failures alone do not establish the
participant's own RSS or a unit memory-limit violation.
`TestMALiveRuntimeMemoryLimit` independently checks actual role startup before
state loading, beside an unselected-role control, so an omitted limit is detected
even when one machine's uncontrolled GC happens to stay below the RSS ceiling.

#### O13 capacity amendment and matching acceptance rows

The owner-approved O13 amendment lowers only this participant's capacity. The
whole-snapshot CCJ1 layout, journal-first commitment, retained evidence and
refusal semantics stay unchanged. Full validation runs at load; each durable
transition validates its changed rows and touched uniqueness/reservation
invariants. The encoded snapshot ceiling is `(15 MiB - 8192) / 3` bytes.

| Acceptance row | Required positive and negative evidence |
| --- | --- |
| N2-19 `TestMALiveRetentionNoEviction` | At 3072 rows, fresh work refuses before intent/invocation; results, dead rows and tombstones remain. Exact replay at the same retained bound still requires audit, rate budget and current authority. |
| N2-19 capacity companion `TestMALiveCapacityLatency` | Persist and reopen history at 3071 rows near the encoded byte ceiling; admit one final 24576-byte P, then durably replay at 3072 rows. Each operation is below 1000 ms and measured peak heap below 128 MiB (and process RSS below the unchanged 256 MiB unit ceiling), giving at least 2x margin against the 2000 ms deadline and unit MemoryMax=256 MiB. No shrinking/eviction is a valid fixture. |
| N2-19 load companion `TestMALiveIncrementalPersistence` | Reject a corrupt unchanged retained row on load, beside a valid canonical snapshot. Reject an invalid changed row or duplicate caller/id before journal mutation. |

These are source-fixture measurements, not native runtime qualification. Higher
capacities require a new measured owner decision; no journal/per-row-file design
or retention horizon is introduced by this amendment.


**Activation gate G-A7A2-RETENTION-SCALING is closed.** With no eviction in v1,
this participant refuses new work with `state_capacity_exceeded` before intent
or crypto after at most about **3072 lifetime attempts**, possibly earlier when
its state budget binds. This finite lifetime is acceptable only because A7a-2
is closed by default. Live purpose-9 signing MUST NOT be activated until a
separately reviewed retention-scaling change provides a persistence layout
whose per-transition cost does not grow with retained rows, and/or a compaction
rule preserving permanent request-id rejection. This amendment names that gate;
it does not design or satisfy it. The unit's `MemoryMax=256M` remains unchanged.
