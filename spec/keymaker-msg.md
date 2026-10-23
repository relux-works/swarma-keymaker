# Swarm Signer: agent message signatures

Status: normative candidate for content review, **spec only; not implemented or
activated**. The shipped native method set and purpose allowlist do not change.
This supplement enumerates the changes in [section 9](#9-normative-change-inventory).
MUST and MUST NOT below describe the proposed contract after approval, not a
claim that the daemon supports it. There is no new socket or deployment step.
The stable-key lifecycle (MSG2), purpose-5 issuer and 24-hour ceiling (MSG3),
and bounded signing language with caller identity/key checks are decided.
The exact envelope-field/label alignment (MSG1) and qualification remain gates.

The owner of `swarm-envelope/2` is
[the waggle repository](https://github.com/relux-works/waggle). Its S0 draft branch
`spec/s0-envelope-grants` was not published when this proposal was prepared.
The supplied shape is `domain label || LF || CCJ-1(body)`, with
`id = sha256(preimage)` and signatures outside the body. **`MSG_LABEL` is a
named parameter pending waggle's accepted S0 definition, not literal bytes
and not an invented `swarma-msg` prefix.** Publication and review of a pinned,
independently accepted S0 head remain an activation gate (MSG1). An unreviewed
local draft is not an alignment authority. Keymaker MUST NOT silently adapt
to another label or invent an envelope dialect. Operator device keys remain
P-256; these agent keys are Ed25519. Neither substitutes for the other's
authority. Agent message keys sign only the **author** role: human approver
and delegate-session signatures have separate waggle authority contracts.

## 1. Purpose registry and domain separation

Propose the registry extension **`swarma-msg = 4`**, following the
[purpose-3 witness reservation](keymaker-witness.md#31-protected-identity-and-purpose-separation).
Purpose 4 MUST NOT be accepted as a station binding's purpose: the bound
identity remains purpose 1. Its message key is a service-selected sibling,
never a path chosen by a client. Purpose 4 is reserved, not currently enabled.

| Purpose | Authority and permitted signed bytes |
| --- | --- |
| 1, `agent-identity` | Surface A's peer-bound Git SSHSIG preimage only |
| 2, `host-registration` | Configured helper's registrar-built registration preimage only |
| 3, `state-witness` (proposal) | Internal witness records under `keymaker-witness-record/1` plus NUL only; no socket key access |
| 4, `swarma-msg` (this proposal) | Active peer's derived message key; an accepted author `MSG_LABEL` plus LF and canonical object only |
| 5, `root-attestation` (decided, MSG3) | Internal service-built message-key attestations under `keymaker-msg-key/1` plus NUL only |

The distinct SLIP-0010 purpose ancestors supply distinct keys. Prefixes and
framing supply non-overlapping preimages. Both are mandatory in **both
directions**: A, the helper and the internal witness writer MUST NOT sign a
message preimage or use purpose 4; `sign_message` MUST NOT sign SSHSIG,
registration or witness preimages or use purposes 1, 2 or 3. Purpose 5 MUST
NOT sign messages, and purpose 4 MUST NOT certify keys. Verifiers MUST pin
the expected purpose and its authorized key, not trust a claimed purpose
number. A shared master is still one compromise domain.

waggle owns the closed list of platform labels and the allowed algorithm,
role and envelope-type combinations. Each label MUST be an exact ASCII
string without LF or any control byte (including DEL); all labels MUST be
pairwise distinct. Compare all bytes up to the first LF, without normalization,
trimming, case folding or prefix matching. Prefix-freedom is **not** a
security requirement: if one distinct label prefixes another, the shorter
one's following LF differs from the longer one's next non-control byte.
Acceptance of one exact label never accepts its longer or shorter neighbor.

Protected configuration pins only S0 entries permitting purpose-4 Ed25519
agent **author** signatures for the applicable envelope types. `MSG_LABEL`
denotes the exact expected label for one such entry; if S0 defines several,
use that closed allowlist, never a client-selected role/type/key parameter.
Approver/delegate labels MUST NOT be admitted. Verifiers select the expected
label from S0's role/type contract and reject relabeling an author signature
as another role or type. S0 must make that context cryptographically bound
and checkable; an ambiguous role/type mapping blocks alignment. Keymaker
does not inspect body semantics to compensate for an ambiguous label design.

## 2. Derivation, generation authority and continuity

### 2.1 Selected path and decided stable identity

Given the active binding's resolved identity path
`m/1'/product'/project'/agent'`, the message key uses exactly
`m/4'/product'/project'/agent'` under the same master epoch and registry
revision. All indices, hardening, bounds, allocation and tombstone rules are
those of base sections 4.1–4.2. No UID, generation hash, implicit allocation,
extra component, client-supplied path or runtime purpose override is allowed.
Ed25519 public keys and signatures are 32 and 64 raw bytes, respectively.

**Decided (MSG2): stable key for a persistent identity.** Within one
master epoch, explicit authorized re-registration of the same non-revoked
persistent path recovers the same purpose-4 public key. Retirement withdraws
access; it does not revoke that path. Re-registration gets a new registration
number and a fresh authority attestation bound to that exact generation and
registration, preserving predecessor evidence. Every generation/registration
requires its own attestation even when the purpose-4 key bytes are unchanged.
Ephemeral paths are never reused, so each new ephemeral execution already
has a distinct message key. A revoked identity path and its purpose-4 sibling
cannot be resurrected in the same epoch. Rotation requires the base's external
owner continuity/recovery procedure, not another child of a stolen seed.

Here, **"per its generation" means an authority lease**, not fresh key bytes:
only the active `(uid,generation)` bound to that identity may issue or recover
a signature. An old connection never adopts a replacement registration.
Stable-key verification proves the persistent key signed the bytes. It does
**not** prove when, or in which generation, the signature was created. A new
generation's attestation MUST NOT be presented as proof that an older signature
was made by that generation. Generation attribution needs a registration or
attestation reference covered by waggle's signed body and checked against the
attestation. Keymaker does not insert that reference; the only body checks
are the signer identity and key ID specified in section 3.2 (MSG1).
For current-use verification, a verifier MUST reject a signature whose
attested generation is not active, or whose attestation has expired, **even
if the public-key bytes are identical to an active generation's key**.
An unverifiable generation-to-attestation association MUST refuse; it cannot
fall back to persistent-key authenticity as current generation authority.
Even a caller-chosen signed generation/registration reference does not prove
which generation created the signature. It binds claimed context, not an
independently observed creation event; stable keys cannot establish the
generation at creation time.

### 2.2 Unselected alternative: fresh message key per generation

The alternative is a fresh message identity for every generation. It reduces
cross-generation linkability and prevents reuse of an old generation's key
as the new generation's signing identity. It increases publication and
rotation work and requires owner-certified continuity for a persistent agent.
With the existing four-component registry, it requires an explicitly allocated
fresh agent identity/path per generation, with the persistent logical identity
and predecessor link certified externally. That changes today's persistent
same-path reuse model and needs a separate allocation/continuity decision.
Hashing a generation into 31 bits or appending a fifth component is forbidden.
No automatic key churn is specified as a shortcut. This alternative was not
selected: MSG2 is decided in favor of section 2.1, not an open choice.

### 2.3 Admission and release

Issuance, attestation generation and retained-result disclosure MUST check the
kernel peer, current generation and active binding on every operation and
through actual response release under `GenerationSource.with_active` (base
section 3.1). The binding's registration number, owner, path, epoch, status
and current connection pin MUST still match. First self use pins the
registration just as `pubkey` does; later requests cannot switch bindings.
Retirement/revocation winning the release ordering suppresses success,
discards any unreleased signature and invalidates the connection.

Retired state refuses `generation_inactive`; a changed incarnation refuses
`generation_mismatch`; missing/untrusted generation evidence refuses
`generation_source_unavailable`. A missing binding refuses `binding_not_found`,
a foreign binding `peer_binding_mismatch`, and a revoked binding
`identity_revoked`, including on a fresh connection. Accept-time refusals
follow the base's bounded, audited first-frame typed-refusal contract.
No message request registers, rebinds or revokes an identity.

## 3. Surface B signing contract

### 3.1 Exact request and result

Propose `sign_message` on the existing control socket only, after native
version-1 hello. Use base section 7's canonical framing, peer authentication,
request deadline and one-in-flight rule. Group access grants connection
capability only. No new enrollment `uid_map` permission is inferred or needed:
the authority here is the caller's active own binding, not helper admission.
Surface A MUST NOT list this key, accept this method or offer an extension
that reaches it. Native `sign` remains unsupported.

The request has exactly `{method,params,request_id,timeout_ms}` with
`method:"sign_message"` and params exactly `{preimage}`. `preimage` is the
strict canonical **unpadded base64url** encoding of all preimage bytes; reject
padding, alternate alphabets and nonzero unused bits. This explicit binary
encoding is a proposed native method schema, not an inherited encoding guess.
There is no key, path, owner, UID, generation, algorithm or envelope selector.
The single ID is the native top-level 32-lowercase-hex `request_id`; it is not
duplicated in params. `timeout_ms` retains its base meaning.

Request schema example (the placeholder is **not** literal wire bytes):

```text
{method:"sign_message",params:{preimage:base64url(MSG_LABEL || 0x0a || CCJ-1(BOUND_BODY))},
 request_id:"00000000000000000000000000000004",timeout_ms:2000}
```

`BOUND_BODY` contains the required signer/key fields defined symbolically
below. Serialize that native object with CCJ-1 after the accepted S0 label,
field paths and value encodings are known. An empty body MUST refuse because
it lacks both fields; no literal application envelope is invented here.
Success is exactly `{request_id,result:{key_id,signature}}`, where `key_id`
is `sha256:` followed by the lowercase SHA-256 hex of the raw message public
key and `signature` is strict unpadded base64url of its 64-byte Ed25519
signature over the **exact complete decoded preimage**. No prehash, outer
frame, request ID, newline suffix or extra envelope is signed. The caller
computes waggle's envelope `id = sha256(preimage)` and places the returned
signature outside the body per S0. That content digest is distinct from the
native request ID and the public-key identifier.

### 3.2 Validation and the byte-signing boundary

After bounded native parsing and current authority checks, compare the bytes
before the first LF to an exact accepted author `MSG_LABEL` entry. Require
one LF separator and one CCJ-1 canonical JSON **object** after it. The signer
checks the label before body-field resolution. The tail uses all of base
section 7's scalar, ordering, escaping, Unicode,
safe-integer and depth rules. Parse it and require byte equality with its
canonical encoding. Do not normalize or repair it before signing. A BOM,
extra LF, trailing bytes, another JSON document, duplicate members, scalar
top level, or noncanonical JSON refuses before field checks.

The accepted bounded language additionally requires **exactly two body-field
checks**, in this order after canonical validation:

1. Resolve `SIGNER_FIELD` and require its value to equal `BOUND_SIGNER(binding)`,
   the envelope-format public identity associated with the authenticated
   caller's active binding.
2. Resolve `KEY_ID_FIELD` and require its value to equal the key ID of that
   binding's service-derived purpose-4 public key, as returned in section 3.1.

`SIGNER_FIELD` and `KEY_ID_FIELD` are named parameters, **not literal field
names**. Their exact names, paths, canonical value encodings and the mapping
from the protected binding to `BOUND_SIGNER(binding)` MUST come from reviewed
alignment with the accepted waggle specification (MSG1). They are not request
selectors. Until that alignment is available, message signing stays closed.
Each pinned path MUST resolve exactly once to one value of the agreed type;
no recursive search, wildcard/multiple matches, aliases, first/last-wins
selection, string coercion or normalization may supply authority.

A missing field, wrong type or ambiguous/multiple-valued representation
refuses `request_malformed`. Duplicate JSON members, including either field,
already refuse `ccj_noncanonical`; there is no CCJ-1 canonical object with
duplicate members. A well-formed, uniquely resolved value naming another
identity or key refuses proposed `message_binding_mismatch` (section 6).
These checks MUST use the same current binding/derived key as admission and
the final `with_active` release fence; a field comparison cannot pin stale
authority. Refusals produce no signature or successful retained result.

Only those two fields are interpreted. Other canonical body members remain
opaque; unknown members outside the pinned authority paths grant no authority
and are not alternate identity sources. Keymaker MUST NOT assemble or repair
the envelope, apply other envelope-member allowlists, or interpret roles,
grants, content, recipients, timestamps or operator intent. waggle checks
those semantics. Keymaker MUST NOT rewrite either field to make it match.

Decided: **`MAX_MSG_PREIMAGE_BYTES = 48000`**, counting the full decoded label,
LF and canonical body, not just the body. Its unpadded base64url is at most
64000 bytes. With this exact request schema, a 32-character ID and the longest
permitted timeout spelling, the native payload is at most 64116 bytes,
leaving 1420 bytes below the 65536-byte frame-payload ceiling. The four-byte
length header is outside that ceiling. S0 must align to this limit or negotiate
an explicit reviewed replacement (MSG1), not assume a 65536-byte preimage fits.
Exact label comparison, the LF delimiter and CCJ-1 canonicality are also
decided; MSG1 supplies the actual label bytes and field schema, not permission
to relax these rules.

An over-cap frame header refuses before allocation/body read. A valid frame
whose decoded preimage is 48001 bytes refuses `message_too_large`, even if
its label/body are otherwise valid. Check the decoded bound before signing,
and bound decoding allocations by it; never truncate or sign a prefix to fit.
The decoded object also obeys depth 16. Section 7 supplies both exact decoded
boundary controls and an independent frame-header overflow vector.

This deliberately relaxes the base's absolute "no method accepting arbitrary
signing bytes" wording. The proposed replacement is: **no unrestricted
byte-signing method; each signing method has a fixed purpose/key and a
non-overlapping, validated preimage language**. `sign_message` admits
caller-chosen canonical objects only under the closed author-label set. It
cannot sign arbitrary raw bytes or another protocol's preimage, but it can sign
arbitrary application content encoded in that language. Canonicality supplies
unambiguous bytes, not semantic approval or task authorization. This
bounded-language exception is accepted subject to the two caller-bound field
checks above. It MUST NOT be claimed to preserve a stronger ban on all
caller-supplied content, nor to provide other envelope-semantic validation.
This is a chosen-message signing oracle inside a bounded, fixed-purpose
canonical language, narrowed further by the signer/key checks. Distinct
keys and exact non-overlapping preimages prevent transfer to the listed
other domains under their required verifier contracts.

### 3.3 Durable retry and bounded effects

Deduplication uses `(caller_uid,caller_generation,request_id)`, storing the
method, exact canonical params, selected registration/key and original result
in the protected retained-result store. `timeout_ms` is a transport budget,
not a signed argument. Same ID and same preimage returns the retained bytes,
never signs again or chooses a new key. Another method or different canonical
params under a retained ID refuses `request_conflict`; never overwrite it.
Exact argument comparison must not rely on a digest alone. Retained params
may contain message content and remain private service state, never audit
payload. There is no unbounded cache or automatic ID reclamation.

Every retry rechecks current authority, both caller-bound body fields,
current key attestation validity and release ordering. Retirement, revocation or attestation expiry can therefore
deny disclosure of an earlier success. A fresh binding cannot retrieve its
predecessor's retained signature by reusing the ID. Result, successful audit
and selection of registration are one recoverable durable transaction before
release, under the base's final fence. Unknown commit state fences admission;
reconcile the actual durable outcome before reopening it. If committed,
keep the exact committed result and recover it on same-ID/same-bytes retry
without signing again, subject to current authority and validity. Never
discard a committed result merely because acknowledgement was lost. If
reconciliation establishes no commit, there is no successful result to
recover; preserve attempt evidence and return no success. Reconciliation
itself MUST NOT sign or invent a result. Unresolved outcome remains fenced.
A timeout after commit cannot undo it. A dropped reply is recovered with the
same ID/bytes while authority still permits, with no late or second response.
Base workload, rate, state-capacity and audit budgets include retries/refusals.

## 4. Public key certification and revocation

### 4.1 Decided root signer and purpose restriction

**Decided (MSG3): reserve `root-attestation = 5`** for an internal
Ed25519 certification key, derived as `m/5'/product'/project'/agent'` at one
installation tuple selected in protected provisioning. It is Keymaker's
certification root for this format, **not** the SLIP master node. Those
indices use the existing registry, with no automatic allocations. The owner
pins its public key, key ID, tuple, purpose and master epoch out of band.
Root continuity is certified by the owner's separate long-lived authority;
the master cannot certify recovery from its own compromise.

Only internal code may use this key to sign the service-built body below,
from the authoritative binding and protected policy under `with_active`.
There is no root-signing RPC, caller-supplied attestation body or arbitrary
root signing hook. Purposes 1–4 cannot attest keys and purpose 5 cannot be
registered, listed on A or selected on B. A key's advertised purpose/path is
not a cryptographic proof of derivation; trusted root provisioning establishes
that association. **Purpose 5 MUST never sign anything except service-built
attestations** in this fixed domain. In particular it MUST NOT sign Git,
registration, witness or message preimages. Keys of purposes 1–4 MUST NOT
be accepted as attestation signers, even if an input claims issuer purpose 5.

The independently held owner-issuer alternative was not selected. MSG3's
issuer purpose and lifetime ceiling are decided; base Q10 still requires
qualification of the exact format, provisioning, publication, fresh status
proof, root continuity and revocation. A decision is not deployment evidence.
Reusing purposes 1–4 or the SLIP master node is forbidden.

### 4.2 Proposed attestation bytes and publication

Under this decision, publish a CCJ-1 object exactly `{body,signature}`.
The signature preimage is ASCII `keymaker-msg-key/1`, one NUL, then CCJ-1
of `body`, without LF. The signature uses purpose 5 and strict unpadded
base64url. Body contains exactly the following members (sets below are schema
notation, not literal wire order; wire objects use CCJ-1 order):

| Member | Meaning |
| --- | --- |
| `type` | Literal `keymaker-msg-key/1` |
| `owner` | Exact configured binding owner identifier |
| `identity_path`, `path` | Bound purpose-1 path and its exact purpose-4 sibling, each four hardened indices in the base's path representation |
| `uid`, `generation`, `registration_number` | Exact current binding tuple and monotonic registration number; no client claims |
| `master_epoch`, `registry_revision` | Exact binding epoch and registry revision |
| `purpose`, `algorithm` | Integer 4 and literal `Ed25519` |
| `role` | Literal `author`; does not certify approver or delegate-session authority |
| `public_key`, `key_id` | Strict unpadded base64url of 32 raw message-key bytes and their `sha256:` key ID |
| `issuer_key_id`, `issuer_path`, `issuer_purpose` | Out-of-band pinned root's key ID, four-component purpose-5 path and integer 5 |
| `not_before`, `not_after` | Whole-second UTC safe integers; a nonempty half-open validity window |

All path fields are canonical strings `m/purpose'/product'/project'/agent'`,
using unpadded decimal indices in `[0,2147483647]` before hardening, as in
section 2.1. The issuer fields MUST equal the independently pinned issuer
tuple/key/purpose; the certified epoch MUST equal that root's pinned epoch.
Unknown members, malformed paths and noncanonical body bytes are invalid.

Issue only with trustworthy time, from the active binding; require
`not_before <= now < not_after` on issuance and every message release/retry.
The decided maximum lifetime is **86400 seconds (24 hours)**:
`0 < not_after - not_before <= 86400`. Issuers MUST enforce that ceiling;
verifiers MUST reject a longer window, even if currently inside it. Protected
policy may narrow it, with no skew extending authority. Refresh never widens a revoked binding's
authority. A refresh builds another attestation, not another message key.
Attestations are public metadata; private keys/chain codes are never published.

The operator publishes the attestation alongside the independently pinned
root and a current, authenticated binding-status view in the owner's public
identity registry. No new Keymaker lookup/list method or network listener is
proposed. A caller obtains its certificate through that registry by key ID
and registration number, not by querying another UID on B. The concrete
publication transport and fresh status proof remain base Q10 gates; an
unsigned file or a historical signed certificate is insufficient. Message
signing MUST remain closed until publication and fresh-status verification
are qualified. Local validity/custody checks do not assert remote freshness.

### 4.3 Verifier checks and withdrawn authority

A verifier MUST establish the owner/root/epoch binding from independent pins,
verify the attestation's purpose-5 signature over the exact certified body,
strict encodings, validity window, expected owner, registry lineage, exact
purpose/path relationship, public-key digest and expected registration. Then
check independently fresh binding status and root/epoch revocation evidence.
The attested `(uid,generation,registration_number)` MUST be currently active.
A retired generation or expired attestation MUST cause current-use rejection
regardless of equality with a new generation's purpose-4 public key; a new
certificate cannot make the old generation's attestation current again.
It MUST require purpose 4 and Ed25519, reconstruct the exact waggle preimage,
check the envelope content ID, and verify the message signature using that
certified public key. Require the certified `author` role and S0's exact
algorithm/role/type/label combination; another role or type must not verify
by reusing these bytes. waggle's verifier additionally checks the envelope
schema, semantic authority and any signed generation/registration reference;
a valid Keymaker signature supplies none of those decisions.
If certified key bytes, key-ID derivation, message purpose, validity,
generation binding or revocation status cannot be established, the verifier
MUST refuse. No key-ID-only, certificate-only or role-agnostic fallback exists.

Existing authorized binding revoke is the sole local revocation action;
it tombstones the identity path and withdraws its message sibling, with the
same operator-record gates, permanent history and release fence. No separate
message-only revoke or shortcut around persistent-revoke authority is added.
Retirement/unbinding withdraws a registration's authority without revoking
the persistent path. Publication MUST retain predecessor and revocation
tombstones and expose the withdrawn status for the old registration; a later
registration MUST NOT make that old attestation current again.

After revocation, verifiers see a withdrawn registration/key authorization
through the authenticated status view and MUST reject it for current use,
even if its certificate has not expired. Missing, stale or unreachable status
evidence fails closed; offline certificate-only verification cannot claim
current authority. Already released signatures remain mathematically valid
and cannot be recalled. Historical validity needs independently preserved
time/status evidence and an explicit relying-party policy; a body timestamp
alone cannot prove pre-revocation issuance. Keymaker provides no automatic
grandfathering or retrospective creation-time guarantee.

## 5. Audit and failure behavior

One ordinary base-section-11 record per attributable `sign_message` attempt,
including exact retries and refusals, with operation `sign_message`, surface
B, logical domain **`swarma-msg`**, and SHA-256 of the **complete decoded
preimage** as `payload_digest`, never its bytes or just its canonical tail.
When bounded decoding has not established the preimage, digest is null;
over-cap/unframeable input follows the existing bounded transport/aggregate
rules. Never invent a digest or binding for an unparsed request. Validly
decoded wrong-domain/noncanonical inputs may be digested before refusal.

Record the authenticated UID/generation and selected path/epoch only when
known. No native frame, content, signature, certificate, private key, chain
code or free-form parse error enters audit. Durable audit precedes release;
failure discards unreleased output, returns `audit_unavailable` if possible
and closes admission as in the base. Suppressing response output does not
authorize deleting a result whose commit is uncertain or durable; reconcile
and retain it under section 3.3. There is no double audit for fresh signing
plus result retention. An exact retry has its own attempt record
but returns the original result. No audit record serves as the retry cache.
Base custody cause handling and recovery invariants remain mandatory.
If option C is activated later, message results and certification/status
state must enter its complete inventory and witnessed transactions; there
is no message-signing exemption from that proposal's authority fence.

## 6. Refusal-code reuse

Decided: **`message_too_large`**, with `retryable=false`, covers a complete
decoded preimage over 48000 bytes despite fitting a native frame. The existing
`frame_too_large` remains the transport-length-header refusal.

This contract proposes one additional non-retryable code,
**`message_binding_mismatch`**, for a well-formed, uniquely resolved signer
identity or key ID that differs from the calling UID's active binding and
purpose-4 key. `peer_binding_mismatch` describes the authenticated peer versus
a stored binding; `sign_key_mismatch` is the SSH requested-key check. Neither
exactly describes these native body-field claims; those existing meanings
remain unchanged. Missing/wrong-type/multiple-valued fields already fit
`request_malformed`, while duplicate JSON members fit `ccj_noncanonical`.
No aliases or per-field error spellings are added. Error responses disclose
neither the expected field values nor the supplied ones.

Other typed errors retain section 7's `retryable` allowlist. Validation and
permanent authority denials are not retryable; transient generation-source,
resource/deadline and audit classes keep their exact base retryability.

| Condition | Code and proposed application |
| --- | --- |
| Wrong or missing message label, including another protocol's prefix | `namespace_not_permitted`; extend its namespace meaning to the fixed message domain |
| Decoded tail violates CCJ-1/object canonicality | `ccj_noncanonical`; applies to this nested canonical byte document too |
| Invalid base64url, unknown/missing params or selector fields; missing, wrong-type or ambiguous signer/key body fields | `request_malformed` |
| Well-formed signer identity or key ID differs from the active caller binding/purpose-4 key | Proposed `message_binding_mismatch`, `retryable=false` |
| Whole frame over 65536 / truncated / malformed | `frame_too_large` / `frame_truncated` / `frame_malformed` at the existing framing phase |
| Complete decoded preimage exceeds 48000, within a valid frame | Decided `message_too_large`, no truncation or signing |
| Inactive/mismatched/missing generation or binding; revoked identity | Exact codes in section 2.3 and base section 15; no message-specific aliases |
| Changed method/params for retained ID | `request_conflict` |
| Missing required published certification / outside certified key window | `key_not_enrolled` / `key_not_valid_now`; proposed extension of these currently host-key meanings to message certification |
| Trusted time or custody unavailable | `clock_untrusted` / `custody_unavailable` |
| Capacity, deadline or audit unavailable | Existing resource/deadline/audit codes, without extending retryability |

Cross-purpose signature verification failure is a verifier rejection, not a
new native code: a caller cannot select a key. An attempted key selector on
B is `request_malformed`; internal selection of a non-purpose-4 key must
fail before use as `purpose_unknown`, never silently substitute it. Base
methods remain unsupported for purpose 4 until implementation is activated.

## 7. Text vectors and positive controls

These are **requirements for future tests**, not executable service evidence.
They add no rows to the existing vector generator. Common fixture M: active
bound peer at `(uid=1001,generation="g1")`, persistent purpose-1 path
`m/1'/1'/1'/1'`, epoch `example-epoch-1`, registration 1, valid purpose-4
attestation and independently fresh active status, healthy time/custody/audit,
hello negotiated. `BOUND_BODY` resolves `SIGNER_FIELD` exactly once to M's
bound public identity and `KEY_ID_FIELD` exactly once to M's purpose-4 key ID,
using the accepted S0 paths/types. Preimage P is
`MSG_LABEL || LF || CCJ-1(BOUND_BODY)` (no suffix), using the accepted S0 author
label, not the literal parameter names. P2 is P with one otherwise opaque,
disjoint member changed, while both authority fields stay correct. Encode as
in section 3.1; use fresh valid IDs except the retry pair. These are custody
fixtures, not a claim of complete application-envelope validity.

For **pre-commit service refusals**, require no returned signature/private
material, no binding mutation and no new successful retained result; only
specified bounded refusal audit/budget writes are permitted. Existing retained
results remain unchanged. This no-new-result rule does not apply to an
indeterminate commit in MSG-V14: fence admission, reconcile the actual durable
outcome, **keep any committed result**, and recover it exactly on retry without
signing again, subject to current authority. A confirmed uncommitted outcome
has no successful result to recover. While unresolved, release no success
and admit no new signing attempt; reconciliation never signs or invents a
result. Private material is never disclosed in either case. Each positive
signs/verifies P with the certified purpose-4 key or states its narrower control.

| ID / claim | Negative input and exact expected outcome | Nearby positive control |
| --- | --- | --- |
| MSG-V01 exact label | Replace `MSG_LABEL` with a label outside the closed author list (including appended-byte or case-change variants chosen outside it), or omit LF: `namespace_not_permitted`; prefix matching never admits it | M signs exact P; distinct platform labels sharing a prefix still compare as distinct because of the LF boundary |
| MSG-V02 registration separation | Feed either exact ASCII `swarma-registrar registration/1` + LF + canonical body or `swarma-registrar enrollment/1` + LF + canonical body to B: `namespace_not_permitted`; sending P to `sign_registration` as an extra bytes member is `request_malformed` | M signs P; helper separately constructs a valid enrolled registration proof with purpose 2 |
| MSG-V03 SSHSIG separation | Feed valid Git SSHSIG preimage to B: `namespace_not_permitted`; P in A SIGN_REQUEST is `sign_data_not_sshsig` | M signs P; A signs valid Git SSHSIG with purpose 1 |
| MSG-V04 witness separation | Feed `keymaker-witness-record/1` plus NUL and a valid witness body to B: `namespace_not_permitted`; P is not a witness-record preimage | M signs P; qualified internal purpose-3 writer/verifier accepts its valid record, conditional on option C activation |
| MSG-V05 canonical tail | After the correct label + LF use `{ }`, duplicate-key `{"a":1,"a":1}`, `{"a":9007199254740992}`, the bytes `7b2261223a22ff227d` (invalid UTF-8 in a string), `[]`, or `{}` plus LF: `ccj_noncanonical` | Exact P and canonical P2 sign as distinct bytes; canonicality refusals precede missing-field checks |
| MSG-V06 decoded and framing bounds | Complete otherwise-valid preimage of 48001 bytes in a valid native frame: `message_too_large`; independently a header declaring 65537 bytes: `frame_too_large` before body read, even when body absent | A complete 48000-byte preimage under the accepted label signs; its request payload is 64116 bytes at timeout 2000, excluding the header |
| MSG-V07 generation fence | Retire g1 before final release: `generation_inactive`; change journal to active g2 while connection pins g1: `generation_mismatch`; no late success | Same M without retirement signs; explicitly re-registered g2 needs fresh connection/attestation and succeeds |
| MSG-V08 revoke fence | Revoke registration 1 before release or use a fresh connection afterward: `identity_revoked` | Unrevoked M signs; no resurrection control uses a tombstoned path |
| MSG-V09 key-purpose verification | Verify M's P signature with purpose-1, -2, -3 or -5 public key: cryptographic verification fails; replace certificate purpose/key with those siblings: certificate/policy verification rejects, even if otherwise validly issuer-signed | Same signature and unchanged purpose-4 certificate verify; purpose-5 certificate signature verifies only under the pinned issuer |
| MSG-V10 retained-ID conflict | First sign P with ID R; retry R with canonical P2: `request_conflict`, original result unchanged | Retry R with exact P returns byte-identical original key ID/signature across reconnect/restart under still-current authority; only one retained success |
| MSG-V11 unbound/foreign authority | M with no binding: `binding_not_found`; a foreign stored binding cannot be adopted (`peer_binding_mismatch`); key/path selector in params: `request_malformed` | M's own binding, no selectors, signs |
| MSG-V12 current certification | Expired local key attestation: `key_not_valid_now`; verifier with stale/missing status or a current revoked tombstone rejects current-use authentication despite a valid message signature | Valid window plus fresh active status and expected registration verifies |
| MSG-V13 wire encoding | Pad P's base64url or set unused bits to nonzero: `request_malformed`; decoded bytes must not be silently repaired | Exact unpadded encoding in section 3.1 signs |
| MSG-V14 audit/recovery boundary | Known pre-commit audit refusal: `audit_unavailable`, no output, mutation or new successful result. Separately interrupt a commit with unknown durability/acknowledgement: fence admission, release no success, reconcile actual durable outcome and keep any committed result; no signing during reconciliation | Healthy audit releases one retained result. If reconciliation finds a committed result after lost acknowledgement, same-ID/bytes retry recovers it exactly without signing again under current authority; if it proves no commit, no successful result exists; unresolved outcome stays fenced |
| MSG-V15 role/type separation | Give B S0's human-approver or delegate-session label: `namespace_not_permitted`; verify a valid author signature as approver, delegate or a different envelope type: verifier rejects the wrong S0 combination/preimage | Agent Ed25519 author signature under its exact type-specific label verifies; independently authorized human P-256 approver and delegate-session controls follow S0, never the agent key |
| MSG-V16 stable key, inactive attestation | Keep the same purpose-4 key for persistent path g1→g2; present a cryptographically valid g1 signature and unexpired g1 attestation after g1 retires: verifier rejects because its attested generation is not active, even though g2 uses identical key bytes | Signature with the fresh g2/registration-2 attestation, current generation association and active status verifies; expired g2 attestation still rejects |
| MSG-V17 purpose-5 outbound isolation | A SIGN_REQUEST selecting the purpose-5 key: `sign_key_mismatch`; helper or `sign_message` params selecting it: `request_malformed`; bounded internal wrong-key plants feeding purpose 5 into helper (2), witness (3) or message (4) signers: `purpose_unknown` before signing | A signs with purpose 1, helper with 2, qualified witness with 3, message with 4; internal attestation builder alone signs its fixed attestation with 5; witness control is conditional on option C activation |
| MSG-V18 attestation issuer isolation | For each purpose 1, 2, 3 and 4, replace the attestation signature/issuer with that sibling while keeping the true purpose-5 root independently pinned: verifier rejects the unpinned/wrong-purpose signer; claiming issuer purpose 5 cannot authorize it | Service-built attestation signed with the pinned purpose-5 issuer verifies, within a nonempty window of at most 86400 seconds; a 86401-second window rejects even with a valid issuer signature |
| MSG-V19 signer identity binding | Change only the uniquely resolved `SIGNER_FIELD` to another well-formed public identity: `message_binding_mismatch`, `retryable=false`, no signature or new successful retained result | M's exact bound signer identity and correct key field sign without rewriting either field |
| MSG-V20 key-ID binding | Change only `KEY_ID_FIELD` to another well-formed key ID: `message_binding_mismatch`, `retryable=false`, no signature or new successful retained result | M's service-derived purpose-4 key ID and correct signer field sign |
| MSG-V21 mandatory fields | Remove `SIGNER_FIELD`, remove `KEY_ID_FIELD`, or remove both (including canonical `{}`): `request_malformed` after canonical validation | Correct BOUND_BODY containing each pinned authority field once signs |
| MSG-V22 unique field resolution | Duplicate either authority member in raw JSON: `ccj_noncanonical` (canonical duplicates are impossible); at either pinned path, use a canonical multi-value/ambiguous representation instead of its agreed single-value type: `request_malformed`; no first/last/alias choice | Canonical BOUND_BODY resolves each exact field path to one correct value and signs; disjoint opaque members do not supply alternate authority |

Construct MSG-V06 from a correct bound body containing an additional opaque
ASCII string, disjoint from both authority paths. Let B be that canonical
body's byte length when the extra string is empty, and L the accepted label
length. Set the ASCII padding length to `48000 - L - 1 - B`; S0 must confirm
the required fields and label leave room. One more padding byte yields the
48001-byte negative without changing either authority field. Encode and
check the whole native request for both: 64116/64118 bytes at timeout 2000,
still inside the frame limit. No exact field names, labels or application-valid
body are invented by these parametric vectors.
MSG-V07 and V08 require separate races where retirement/revocation wins the
release barrier; released-first controls show the stated recall limit.
MSG-V09's internal-purpose guard additionally needs a bounded faulty-selector
plant before implementation handoff. No killed mutants or passing runtime
message tests are claimed by this text-only slice.

## 8. Open dependencies and scope bounds

[MSG1](../UNRESOLVED_QUESTIONS.md#swarm-signer-message-specification-gates)
remains open for waggle's exact label/role/type and generation-reference
semantics, plus `SIGNER_FIELD`/`KEY_ID_FIELD` names, paths, canonical encodings
and binding-to-public-identity mapping. MSG2 (stable key with fresh active-
generation authority), MSG3 (owner-pinned purpose 5 and maximum 24 hours),
and the bounded language/48000-byte limit/refusal are decided. Publication
and fresh-status proof still need qualification under base Q10.
Base Q6, Q7, Q9 and Q10 continue to gate generation ordering, persistent
revocation, socket access and portable certification. No new signed format
can replace an unpublished authority interface with an allow-all stub. These design decisions alone do not
qualify any of those dependencies.

No surface table was supplied with this assignment (brief gap). All eight
requested specification parts are covered; no required row is treated as
out of contract. Implementation, executable vectors/mutants, publication
service and production qualification are outside this spec-only slice.

## 9. Normative change inventory

On separate approval and implementation, the following base rules need
explicit amendments; publishing this proposal does not amend them silently:

| Base section | Proposed amendment |
| --- | --- |
| 3 | Message sibling lifecycle follows binding/tombstone and actual-release fences; generation-specific certificates do not imply generation-specific key bytes |
| 4.1–4.3 | Reserve purpose 4 and decided internal purpose 5; preserve four hardened components and purpose-1-only binding registration; publish root certification/continuity before claiming it |
| 5 | Add self-only `sign_message` without caller selectors, with signer/key body checks and durable retained-result authority |
| 7 | Add exact method/binary schema and validated-domain exception to the unrestricted-byte ban; include signatures in durable same-ID recovery |
| 8 | Replace "only signing method on B" with the two method-specific signing authorities; helper bytes, enrollment and purpose 2 remain unchanged |
| 9 | Add the proposed purpose-3/4/5 separation rows, including reverse-direction checks; ordinary metadata/mutations still perform no key signing |
| 10 | Count message encoding, canonicalization, signing, retries and results inside existing limits; qualify group provisioning without implying helper permission |
| 11 | Add `swarma-msg` logical domain, exact preimage digest/null rules and result audit transaction; preserve custody extension and failure closure |
| 13–14 | Implement paired vectors, fault/race controls and acceptance coverage; resolve MSG1 and qualify decided MSG2/MSG3 before activation |
| 15 | Add decided non-retryable `message_too_large` and proposed non-retryable `message_binding_mismatch`; reuse existing codes for malformed/missing/duplicate field cases and section 6 applications |
