# Swarm Signer: agent message signatures

Status: normative candidate for content review, **spec only; not implemented or
activated**. The shipped native method set and purpose allowlist do not change.
This supplement enumerates the changes in [section 9](#9-normative-change-inventory).
MUST and MUST NOT below describe the proposed contract after approval, not a
claim that the daemon supports it. There is no new socket or deployment step.
The stable-key lifecycle (MSG2), purpose-5 issuer and 24-hour ceiling (MSG3),
and bounded signing language with caller identity/key checks are decided.
Landed S0 alignment (MSG1) is recorded; implementation and qualification
remain gates.

The owner of `swarm-envelope/2` is
[the waggle repository](https://github.com/relux-works/waggle).
This candidate aligns to the accepted main commit
**`67df75bec015ea463f685e4daf4975ecda18816a`**,
`spec/swarm-envelope-2.md` §§2.2–2.6, 4.2 and 6. All waggle citations below
pin that landed S0 head. MSG1 format alignment is satisfied; it does not
activate this unimplemented runtime. Keymaker MUST NOT silently adapt to a
changed head or invent an envelope dialect. The resolved mappings and remaining
qualification gates are recorded in
[section 4.4](#44-landed-s0-alignment-and-qualification-gates).
Operator device keys remain P-256; agent keys are Ed25519. Agent message keys
supply only author authority. The byte signer does not interpret a record's
claimed role/type; waggle receivers enforce that authority boundary (§3.2).

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
| 4, `swarma-msg` (this proposal) | Active peer's derived message key; exact `swarma-msg/2` plus LF and a canonical signed record with caller-bound key paths |
| 5, `root-attestation` (decided, MSG3) | Internal service-built message-key attestations under `swarma-attestation attestation/1` plus LF only; never revocation snapshots (§4.3) |

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

The complete nine-literal registry is copied from
[waggle §2.4](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#24-exact-domain-registry-and-key-profiles):

| Exact ASCII label | Assignment | `sign_message` |
| --- | --- | --- |
| `swarma-msg/2` | Message signed record | Accept exact domain only, subject to §3.2 |
| `swarma-waggle grant/1` | General grant | Refuse |
| `swarma-waggle operator-act/1` | Operator act | Refuse |
| `swarma-attestation attestation/1` | Root-issued key attestation | Refuse |
| `swarma-attestation revocation/1` | Registry-owner/operator/grant-root revocation snapshot | Refuse |
| `swarma-registrar registration/1` | Registrar registration | Refuse |
| `swarma-registrar enrollment/1` | Registrar enrollment | Refuse |
| `swarma-credential-broker grant/1` | Broker grant | Refuse |
| `swarma-credential-broker revocation/1` | Broker revocation | Refuse |

Labels are 1–96 ASCII bytes in 0x20–0x7e. The witness placeholder in waggle
is not a tenth literal; our separate NUL-framed witness domain stays refused.
No caller or protected configuration may add an alias to this closed table.
There is one message label for every message role. The signed record binds
`version`, `role`, `key` and the complete `body`, including `body.type`.
Receivers admit only message/1 author Ed25519 agent signatures with current
purpose-4 certification; optional approvers require separately attested P-256
operator devices. Delegate is reserved with no admitted v0 profile.
A shared message tag does not grant the byte signer semantic role authority.
Grants/operator acts use different tags; no method here signs those domains.
Agent keys do not issue grants in v0: they are subjects/leaves only. Operator
P-256 low-S signatures here are ordinary signatures over the exact act/message
preimage; FIDO/WebAuthn assertion constructions are outside v0, with no
translation or assertion-wrapper fallback ([waggle §2.4](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#24-exact-domain-registry-and-key-profiles)).

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
The signed `body.author_attestation` binds the exact attestation content ID.
Keymaker checks that it is the caller's current purpose-5-issued attestation
for the active binding, not another generation's certificate for the same key
(§3.2). Receivers fetch exactly that referenced attestation, fully verify it and
its active binding, and finally compare the author/key and attestation ID
([waggle §2.6](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#26-root-signed-attestations-and-shared-revocation)).
This resolves the earlier generation-association gap without inventing a field
or accepting a newer attestation as a substitute. A retired generation or
expired attestation MUST refuse even if the public-key bytes are identical to
an active generation's key. Stable-key signatures still do not provide an
independently observed creation-time event; the signed reference binds the
verified authority context. Keymaker supplies no historical creation-time proof.

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
{method:"sign_message",params:{preimage:base64url(ASCII("swarma-msg/2") || 0x0a || CCJ-1(BOUND_RECORD))},
 request_id:"00000000000000000000000000000004",timeout_ms:2000}
```

Per [waggle §2.2](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#22-ccj-1-and-preimages),
`BOUND_RECORD` is `{body:BODY,key:K,role:"author",version:"swarm-envelope/2"}`
for a conforming author; `BODY.author` equals K and `BODY.author_attestation`
equals the current attestation content ID T. This is schema notation;
CCJ-1 determines member order. Keymaker signs the original supplied bytes.
Success is exactly `{request_id,result:{key_id,signature}}`, where `key_id`
is `ed25519:` plus canonical unpadded base64url of the 32 raw purpose-4 public
key bytes ([waggle §2.3](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#23-cryptography)),
and `signature` is strict unpadded base64url of the 64-byte ordinary Ed25519
signature over the **exact complete decoded preimage**. This message-specific
key ID replaces the former draft's digest ID, not existing native methods' IDs.
No prehash, outer frame, request ID, newline suffix or extra envelope is signed.

The caller separately computes `content_preimage = ASCII("swarma-msg/2") ||
LF || CCJ-1(BODY)` and `id = "sha256:" || lowercase_hex(SHA-256(content_preimage))`.
It assembles `{version,body,id,signatures}`, placing `{role,key,sig}` entries
outside the body. **The content ID does not hash the signed record.** It is
distinct from the native request ID, message key ID and audit preimage digest.

### 3.2 Validation and the byte-signing boundary

After bounded native parsing and current authority checks, use the ordered
[waggle §2.5 admission](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#25-message-signer-provider-opaque-canonical-bytes):

1. Check the complete decoded preimage length before allocation/signing:
   **`MAX_MSG_PREIMAGE_BYTES = 24576`**.
2. Require a first LF; before it require 1–96 bytes in ASCII 0x20–0x7e.
3. Compare that entire label exactly to `swarma-msg/2`.
4. Require the complete remainder to be CCJ-1 canonical JSON bytes:
   parse/re-encode equality, depth **12** (root container = 1), strings at most
   **8192 bytes**, arrays at most **64 entries**, and every registrar CCJ-1
   scalar/order/escaping/Unicode/safe-integer rule. A BOM, trailing bytes,
   extra LF, multiple documents, duplicate decoded members (including escaped
   aliases) or noncanonical encoding refuses before identity
   resolution. Never normalize or repair the bytes.

Keymaker is a multi-agent provider, so §2.5's identity narrowing is mandatory.
Resolve the caller's attested purpose-4 key ID from the **own active binding**
and current generation, not request data. Resolve its **current attestation
content ID** T from the exact service-built `attestation/1` issued by Keymaker
under the pinned purpose-5 root for this active `(uid,generation)` and its
registration/epoch/owner/path. T is `sha256:` plus 64 lowercase hex digits,
computed by §4.2 from that attestation body. A current attestation is a protected
service fact, not any valid certificate for the same stable key; renewal may
change T within one generation. Missing/invalid service-resolved key, current
attestation or identity policy refuses `signer_identity_unavailable`. Existing precise
peer/binding/generation/certification failures retain their base codes (§2.3,
§6); this code covers inability to resolve a usable signer identity after those
checks, not an alias that hides a known revoke or retirement.

Then extract **exactly three identity paths**, each exactly once:

| Exact path | Comparison |
| --- | --- |
| `key` | Top-level signed-record string equals the caller's resolved attested purpose-4 key ID |
| `body.author` | String in the `body` object equals that same caller-resolved key ID |
| `body.author_attestation` | String in the `body` object equals T, the caller's service-resolved current attestation content ID |

A missing path, non-object signed record or path container, wrong type or multi-valued
representation refuses `signer_identity_malformed`. Duplicate JSON members
already refuse `ccj_noncanonical`; canonical duplicate members are impossible.
Any unequal string refuses `signer_identity_mismatch`, including two
mutually equal foreign strings. Comparisons are byte-for-byte: no recursive
search, aliases, first/last-member choice, coercion or normalization. These are
checks of resolved ID equality, not extra syntax validation of foreign claims.
The protected key ID itself must have the §3.1 Ed25519 encoding and T the
§4.2 canonical content-ID form.
All three identity codes have `retryable=false`, disclose no values, and
replace the former draft's `message_binding_mismatch` proposal.

All three checks MUST run under `with_active` and use the same current
binding/derived key/current attestation as admission and final release,
including retries. A different-generation attestation for the same stable key
MUST refuse `signer_identity_mismatch`, not pass on key equality. A comparison cannot pin stale
authority. Pre-commit refusals release no signature or new successful result.

Only these three paths are interpreted. Other canonical record/body members
remain opaque. In particular `room`, `to` and `body_sha256` are signed inside
the complete body, but Keymaker does not interpret or reconstruct them.
[waggle §2.1](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#21-closed-schemas-and-limits)
requires receivers to compare the actual delivery room/recipient and hash the
actual delivered UTF-8 text. Keymaker does not enforce other member allowlists,
role/type/version semantics, audience, timestamps, action, grants or operator
intent. A canonical record claiming `approver`, a reserved delegate or another
body type can pass these byte/identity checks; its agent signature supplies
no such authority and the receiver MUST reject the wrong profile/tag/type.
This explicit §2.5 boundary replaces the former draft's role-specific labels.
Keymaker MUST NOT assemble, repair or rewrite the record or any checked path.

At 24576 decoded bytes, unpadded base64url is exactly **32768 bytes**. This
method's exact schema with a 32-character ID and timeout 2000 has **116 bytes**
of other JSON syntax/fields: maximum native payload **32884 bytes**, headroom
**32652 bytes** below the 65536-byte payload ceiling. The four-byte header is
outside that ceiling: total frame 32888 bytes, 32648 below even a total-frame
65536 ceiling. The enforced 116-byte metadata budget is narrower than waggle's
4096-byte allowance (36864-byte payload / 36868-byte total); it is not an
unbounded metadata assumption. Unknown params refuse; arbitrary escaping of
raw bytes is not the carrier. Outer native JSON keeps depth 16; the decoded
signed-record depth is independently 12.

A valid frame with a 24577-byte decoded preimage refuses `message_too_large`,
without truncation; its 32770-byte encoding plus wrapper still fits (32886).
An over-cap frame header separately refuses `frame_too_large` before body read.
The depth-13 signed record refuses `ccj_noncanonical`. These specialize the
native error vocabulary, mapped explicitly to waggle's provider codes in §6.
Boundary references are waggle S21/S22 (24577/depth13 refusals) and PS2/PS3
(24576/depth12 codec-only controls; PS3 is a top-level array); they do not prove caller
identity or complete receiver-schema validity. §7 pairs equivalent limits
with a correct caller-bound record.

The accepted replacement for the base's absolute byte-signing ban is:
**no unrestricted byte-signing method; each signing method has a fixed
purpose/key and a non-overlapping, validated preimage language**.
This is a chosen-message signing oracle inside a bounded, fixed-purpose
canonical language, narrowed further by all three identity paths. Canonicality
supplies unambiguous bytes, not semantic approval or task authorization.
Distinct keys and exact domain/LF framing prevent cross-domain transfer under
the required verifier contracts. This does not preserve a stronger ban on all
caller-supplied content or provide other envelope-semantic validation.

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

Every retry rechecks current authority, all three caller-bound identity paths,
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
registration, witness, message or `revocation/1` preimages. Keys of purposes 1–4 MUST NOT
be accepted as attestation signers, even if an input claims issuer purpose 5.

The independently held owner-issuer alternative was not selected. MSG3's
issuer purpose and lifetime ceiling are decided; base Q10 still requires
qualification of the exact format, provisioning, publication, fresh status
proof, root continuity and revocation. A decision is not deployment evidence.
Reusing purposes 1–4 or the SLIP master node is forbidden.

### 4.2 Landed-S0 attestation bytes and publication

Use exactly the four-member `swarm-envelope/2` envelope, closed bodies and
[waggle §2.6](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#26-root-signed-attestations-and-shared-revocation)
attestation/1 profile. There is no private Keymaker certificate dialect.
Content ID uses `ASCII("swarma-attestation attestation/1") || LF || CCJ-1(body)`.
The purpose-5 root signs `ASCII("swarma-attestation attestation/1") || LF ||
CCJ-1({body:body,key:issuer,role:"author",version:"swarm-envelope/2"})`.
Exactly one author signature uses body.issuer, the independently pinned root.
Signatures are strict unpadded base64url 64-byte Ed25519; raw root/public keys
and signature verification meet waggle §2.3, including point/subgroup checks.
No NUL prefix, bare-body signature or `{body,signature}` wrapper is accepted.

| Required body member | Agent certificate meaning and protected source |
| --- | --- |
| `type`, `issuer` | `attestation/1`, independently pinned purpose-5 root key ID |
| `subject` | Exactly `{algorithm:"Ed25519",key_id:K,public_bytes:base64url(raw32)}`; K is `ed25519:` plus that same canonical encoding |
| `key_class`, `purpose` | Exactly `agent`, `swarma-msg`; purpose string maps to our numeric derivation purpose 4, not issuer purpose 5 |
| `roles`, `actions` | Exactly `["author"]`, `["message.sign"]`; no concrete action/target authorization |
| `iat`, `exp` | Exact `YYYY-MM-DDTHH:MM:SSZ`, years 1970–9999, real dates; start-inclusive/end-exclusive |
| `binding.uid` | Exact binding UID as JSON integer in [0,4294967294] |
| `binding.generation` | Exact current generation, nonempty UTF-8 at most 255 bytes |
| `binding.registration_number` | Exact current registration JSON integer in [1,9007199254740991] |
| `binding.master_epoch` | Exact signing-service master epoch, nonempty UTF-8 at most 255 bytes |
| `binding.owner` | Exact protected owner, nonempty UTF-8 at most 255 bytes |
| `binding.path` | Exact purpose-4 path `m/4'/product'/project'/agent'`, nonempty UTF-8 at most 255 bytes; additionally enforce our four hardened components and identity-sibling relationship |

The binding object has exactly those six members. Compare independently typed
protected current-generation evidence with those fields plus boolean
`active:true`; no normalization or coercion and no absence-equals-absence.
Never silently rename epoch or substitute a reusable UID for a generation.
Issue only from the authoritative active binding under `with_active`, with
trusted time and `iat <= now < exp`. The decided lifetime is
**`0 < exp - iat <= 86400` seconds**, where subtraction uses parsed instants.
Both issuer and verifier MUST reject a longer window, even with a valid root
signature. Protected policy may narrow it; refresh never widens revoked
authority and creates an attestation, not a new message key.
Both sides enforce **8192 bytes for the entire evidence envelope**, depth 16,
strings 8192 and arrays 64, plus all CCJ-1/profile/time restrictions. Do not
confuse this evidence cap with the message preimage cap or the 120-second
message-body lifetime, which Keymaker does not interpret.

Publish certificates, independent root pins and authenticated current binding
status through the owner's identity registry; no new socket, lookup RPC or
network listener. Publication must preserve exact content-addressed attestation bytes and their
key/registration association; receivers select by the signed attestation ID.
Private material is never published. Publication/freshness/root continuity remain Q10
gates. Signing stays closed until runtime implementation and qualification.

### 4.3 Verifier checks and withdrawn authority

A verifier establishes pairwise distinct protected root pins for the purpose-5
signing service, registry-owner revocation, operator and grant owner roles,
plus their scope/purpose and epoch. Root-role overlap refuses before signed
evidence intake; successful cryptography cannot widen a root's language. It then
applies waggle §2.6's ordered envelope/header, content-ID/root-signature,
complete typed profile/current binding/time, and separately authorized signed
revocation-snapshot checks.
It additionally checks protected registry lineage, numeric purpose 4 and the
exact path relationship from §2.1. These protected facts are not invented
certificate members. Require Ed25519 subject/key-ID correspondence, author
profile, expected registration, active generation and a valid <=86400-second
window. A retired generation or expired attestation rejects even when a fresh
registration uses identical public-key bytes. Reconstruct the exact message
signed record and separate content ID, including the same 24576-byte
message-preimage/depth12 limits; enforce waggle's full receiver schema,
algorithm/role/type profile, action authority and delivery bindings. A valid
Keymaker signature supplies none of those semantic decisions.
For a message author, look up exact bytes by signed `body.author_attestation`,
never by key ID or fallback to a newer certificate. Fully verify that record,
its subject, current binding, validity and registry-owner snapshot; then verify
all approvers' evidence in signature-array order. Only after that evidence
succeeds compare subject key ID with `body.author` and verified attestation
content ID with `body.author_attestation`; either inequality refuses receiver
`author_attestation_mismatch` at the end of K1. Missing referenced bytes are
unavailable; earlier evidence refusals retain precedence. This receiver code
is distinct from the signer's `signer_identity_mismatch`.

Revocation distribution uses waggle **revocation/1**, not a Keymaker format:
body exactly `{type:"revocation/1",issuer,issued_at,complete:true,entries}`;
entries are at most 64 closed `{kind,id,from}` objects, kind `key` or `record`.
Use `swarma-attestation revocation/1` plus LF and the same separate content-ID
and signed-record constructions. Exactly one author signature must come from
the snapshot's directly pinned registry-owner revocation root for agent keys
and their attestations, with protected purpose `registry-revocation` and scope
bound to the exact purpose-5 attestation root. The registry root cannot sign
attestations, and the purpose-5 root cannot sign snapshots; either cross-signature,
wrong purpose/scope or overlapping root roles refuses `key_binding_invalid`.
Missing protected policy is unavailable. Operator-device snapshots keep their
operator root and grant snapshots their grant-owner root. Both issuer/verifier enforce the
8192-byte evidence cap and typed timestamps. Authenticated complete snapshots
need rollback continuity and protected positive maximum age <=60 seconds;
future-issued, stale, incomplete, missing or rolled-back evidence refuses.
Validate every entry before matching; key or attestation-record revocations
are cumulative, effective at `from <= max(now,W)` per waggle §2.6, where
W is the verifier's durable time watermark (§3.3 there). Root
withdrawal remains an independent protected owner-pin/recovery action.
For first containing snapshot issued at S, protected maximum age A (0 < A <=60 s)
and entry `from`, the distribution bound is **max(S + A, from)**; there is no
withdrawal guarantee before issuance S, no earlier effect than `from`, and no
end-to-end platform completion promise. Every later complete snapshot retains
entries (including future-effective ones), never moves `from` later, and has
strictly increasing `issued_at`; equal-time retransmission must be identical.
Consumers serialize snapshot currency with their effect gate. This closes
S0's D29 timing decision without granting Keymaker snapshot-signing authority.

Existing authorized binding revoke remains the sole local source of truth:
it tombstones the identity path and withdraws the purpose-4 sibling under the
same operator gates and release fence. Shared snapshots distribute that
withdrawal and cannot undo it. Retirement/unbinding withdraws a registration
without revoking the persistent key; use record-level withdrawal rather than
blanket key revocation for a retired generation when the stable key continues.
Retain predecessor evidence/tombstones; a new certificate never makes the old
generation current. Keymaker issues no revocation snapshots. Its authoritative binding withdrawal,
retained tombstones, generation/registration identity and exact attestation IDs
are the facts the registry must distribute; no new export, callback, RPC or
wire interface is specified by this slice. The exact live input transport,
publication and continuity process remains Q10.

S0 D32 locates the registry and rollback witness on a separately administered
trust node outside the platform's administrative domain ([waggle §1](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#1-scope-ownership-and-existing-waggle)).
The registry stores, orders and publishes original signed attestations without
re-signing them; registrar enrollment retains its offline publisher signature.
This deploys no node or witness: until qualified, mode A with pinned roots and
caller-supplied snapshots remains in use; [option C](keymaker-witness.md) stays gated.

Verifiers also need independently fresh active-generation status: an empty
revocation snapshot alone does not prove a registration active. Missing/stale
status fails closed; no key-ID-only, certificate-only or role-agnostic fallback.
Already released signatures remain mathematically valid and cannot be recalled.
Historical validity is outside waggle v0; a body timestamp alone cannot prove
pre-revocation issuance. Keymaker supplies no creation-time guarantee.

### 4.4 Landed S0 alignment and qualification gates

These mappings and historical changes were checked against accepted waggle
**67df75b**, §§2.2–2.6, 4.2 and 6. No format or authority mismatch remains;
implementation, publication and qualification remain gates.

| Difference | Treatment / remaining gate |
| --- | --- |
| Signing payload and content ID | Former body-only signing and `id=hash(preimage)` differ: sign the full `{body,key,role,version}` record; hash the separately tagged body for content ID (§3.1). This is a wire change, no compatibility alias. |
| Role/type separation | One message label replaces symbolic role-specific labels. The signer cannot reject an approver/type claim without extra interpretation forbidden by §2.5; receivers enforce author authority (§3.2, MSG-V15). Delegate has no admitted profile. |
| Key IDs and identity paths | Former `sha256:` public-key digest IDs and symbolic distinct signer identity become `ed25519:` raw-key encodings at `key` and `body.author`, plus the exact current attestation content ID at `body.author_attestation` (§3). Other methods keep their existing IDs. |
| Message limits and refusal vocabulary | 48000→24576 complete bytes; signed depth 16→12; add string 8192/array 64 caps. Native frame remains payload 65536/depth16. Source codec codes are mapped, not asserted identical (§6). |
| Canonical value versus record shape | waggle codec-only PS3 admits a depth-12 array. Our mandatory identity phase rejects a canonical non-object signed record as `signer_identity_malformed`, not `ccj_noncanonical`; the original object-only codec refusal is replaced. The required three paths still make every successful record an object. |
| Attestation wrapper, names and time | Former NUL-framed private body/wrapper replaced by LF-framed full envelope/signed record. Numeric subject purpose 4 maps to `purpose:"swarma-msg"`; singular role becomes roles/actions; `public_key` becomes subject.public_bytes; numeric not_before/not_after become strict iat/exp timestamps. Root purpose remains protected integer 5. |
| Fields absent from the new wire profile | `identity_path`, `registry_revision`, `issuer_path`, `issuer_purpose` are not attestation members. Enforce identity sibling/registry lineage/root tuple/purpose using independent protected evidence and pins; do not add unknown wire fields or claim the certificate signs these facts. These inputs need Q10 qualification. |
| Binding path semantics | waggle specifies an opaque protected `binding.path` string; this consumer requires it to be the purpose-4 subject path. Both producer and protected evidence must use that meaning; an identity-purpose path cannot be silently substituted. This is an explicit consumer mapping; live issuer/evidence conformance remains Q10 qualification. |
| Field ranges and evidence size | New binding strings <=255 bytes, UID excludes 4294967295 although native UIDs fit uint32, registration <=9007199254740991, timestamp years 1970–9999. Old certificate imposed no explicit whole-envelope cap; new evidence <=8192 bytes, depth16/string8192/array64. Issuer rejects nonrepresentable or oversized records; never truncate/coerce/omit binding fields. |
| Lifetimes and status | Agent 86400-second ceiling matches on both sides; message bodies instead have <=120-second lifetime at receivers. Snapshot <=60-second freshness/64-entry cap and rollback continuity are additional requirements. Overflow cannot drop tombstones or claim completeness; rollover/publication capacity needs Q10 qualification. Snapshot currency does not replace fresh generation status. |
| Purpose-5 revocation signing authority — resolved | Landed [§2.6](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#26-root-signed-attestations-and-shared-revocation) (X25/D30) restricts purpose 5 to agent attestation/1; the separately pinned registry-owner revocation root distributes binding withdrawal. Pairwise distinct roots and exact revoker scope are mandatory; cross-signatures refuse (§4.3). Keymaker provides no snapshot signer or new publication interface. |
| Stable-key generation association — resolved | Landed [§2.5](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#25-message-signer-provider-opaque-canonical-bytes) and [§2.6](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#26-root-signed-attestations-and-shared-revocation) (X01) bind the exact attestation ID in signed body.author_attestation. Signer checks the current active binding's T; receiver verifies precisely that referenced record before late author_attestation_mismatch. Another generation's attestation for the same stable key refuses (MSG-V25). No creation-time oracle is claimed. |
| Landed-head delta check | Compared with the previous draft: three paths replace two; purpose-5/snapshot authority and generation association are resolved; revocation bound is max(S + A, from), A <=60 seconds (D29). The 24576/12 limits, string8192/array64, all nine literal labels, raw-key ed25519 ID form, and every §4.2 attestation field/range are unchanged. Agent grant issuance and WebAuthn assertions remain outside v0. D32 records trust-node placement, not deployment. |

Every curator-required certificate fact is present or mapped explicitly in
§4.2: uid, generation, registration_number, master epoch, subject purpose
`swarma-msg`, Ed25519, author role, key bytes/key_id, owner, path and the
issuer/verifier-enforced <=86400-second window. The additional missing wire
facts and consumer mappings above require protected evidence, not invented
certificate fields. MSG1 is aligned to the accepted head; runtime remains
unimplemented and base Q10 qualification is still required.

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

Native errors retain the base retryability allowlist. The message-specific
identity codes below are proposed unimplemented additions to base §15, with
exact conditions from [waggle §6](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#6-future-verifier-contract-and-refusal-order).
No response echoes supplied or expected values. `message_too_large` remains
decided and non-retryable, now at the aligned 24576-byte limit.

| Condition, in provider order after native admission | Native code (`retryable=false` unless base says otherwise) | waggle provider code / mapping |
| --- | --- | --- |
| Complete decoded preimage >24576, inside a valid frame | `message_too_large` | `signer_preimage_too_large` (S21 vs PS2) |
| Missing LF, malformed tag alphabet/length | `namespace_not_permitted` | `signer_tag_malformed` |
| Well-formed label other than exact `swarma-msg/2` | `namespace_not_permitted` | `signer_domain_refused` |
| Tail violates canonical/depth12/string8192/array64 language | `ccj_noncanonical` | `signer_payload_invalid` (S22 vs PS3) |
| Missing/invalid service-resolved attested caller key, current attestation or identity policy after precise native authority checks | `signer_identity_unavailable` | Same; no caller field supplies the unavailable fact |
| Missing `key`, `body.author` or `body.author_attestation`, non-object record/container, wrong type or multi-value representation | `signer_identity_malformed` | Same; duplicate members already fail canonicality |
| Any extracted string differs from its service-resolved key ID or current attestation ID | `signer_identity_mismatch` | Same; equal foreign strings still fail |
| Invalid base64url, unknown/missing params, caller key/path/identity selectors | `request_malformed` | Native adapter schema, not a waggle identity-path error |
| Whole frame over 65536 / truncated / malformed | `frame_too_large` / `frame_truncated` / `frame_malformed` | Native framing phase before provider |
| Inactive/mismatched/missing generation or binding; revoked identity | Exact §2.3/base §15 codes | Existing authenticated-peer authority checks retained |
| Changed method/params under retained ID | `request_conflict` | Native durable retry contract |
| Missing required published certification / outside certified key window | `key_not_enrolled` / `key_not_valid_now` | Proposed message extension of existing host-key meanings |
| Trusted time or custody unavailable | `clock_untrusted` / `custody_unavailable` | Existing custody boundary |
| Capacity, deadline or audit unavailable | Existing resource/deadline/audit codes and exact base retryability | No new retryable identity class |

Mappings preserve rejection conditions, not provider-code spelling for existing
native codec/domain errors. waggle identity codes are adopted exactly; no
`message_binding_mismatch` alias is retained. Invalid identity resolution is
not retried automatically: restore protected state through its normal flow.

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
attestation with content ID T and independently fresh active status, healthy time/custody/audit,
hello negotiated. `BOUND_RECORD` has `key=K`, `body.author=K` and `body.author_attestation=T`, where K is
M's service-resolved attested `ed25519:` key ID, body is an object and the
other record fields are `role:"author",version:"swarm-envelope/2"`.
Preimage P is `ASCII("swarma-msg/2") || LF || CCJ-1(BOUND_RECORD)`, no suffix.
P2 changes one otherwise opaque body member while all three identity paths stay
correct. Encode as §3.1; fresh IDs except retries. These are custody fixtures,
not complete receiver-schema validity. waggle's S21/S22 and PS2/PS3 are
codec-only boundary references; PI1–PI5 and I01–I21 additionally exercise
identity narrowing in its landed S0 vector set, including I-attestation-* cases. Boundary files at the same commit:
[S21](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/vectors/swarm-envelope-2/0-negative/S21.json),
[S22](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/vectors/swarm-envelope-2/0-negative/S22.json),
[PS2](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/vectors/swarm-envelope-2/1-positive/PS2.json),
[PS3](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/vectors/swarm-envelope-2/1-positive/PS3.json).

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
| MSG-V01 exact label and closed registry | Replace `swarma-msg/2` with each of the eight non-message literals in §1: `swarma-waggle grant/1`, `swarma-waggle operator-act/1`, `swarma-attestation attestation/1`, `swarma-attestation revocation/1`, `swarma-registrar registration/1`, `swarma-registrar enrollment/1`, `swarma-credential-broker grant/1`, `swarma-credential-broker revocation/1`: `namespace_not_permitted` for every case. Also refuse `swarma-msg/20`, case changes, missing LF/control/overlong tags | Exact P signs; exact LF comparison separates distinct prefix-sharing labels |
| MSG-V02 registration separation | Feed either exact ASCII `swarma-registrar registration/1` + LF + canonical body or `swarma-registrar enrollment/1` + LF + canonical body to B: `namespace_not_permitted`; sending P to `sign_registration` as an extra bytes member is `request_malformed` | M signs P; helper separately constructs a valid enrolled registration proof with purpose 2 |
| MSG-V03 SSHSIG separation | Feed valid Git SSHSIG preimage to B: `namespace_not_permitted`; P in A SIGN_REQUEST is `sign_data_not_sshsig` | M signs P; A signs valid Git SSHSIG with purpose 1 |
| MSG-V04 witness separation | Feed `keymaker-witness-record/1` plus NUL and a valid witness body to B: `namespace_not_permitted`; P is not a witness-record preimage | M signs P; qualified internal purpose-3 writer/verifier accepts its valid record, conditional on option C activation |
| MSG-V05 canonical tail | After the correct label + LF use `{ }`, duplicate-key `{"a":1,"a":1}`, `{"a":9007199254740992}`, the bytes `7b2261223a22ff227d` (invalid UTF-8 in a string), or `{}` plus LF: `ccj_noncanonical` | Exact P and canonical P2 sign as distinct bytes; canonicality refusals precede missing-field checks |
| MSG-V06 decoded and framing bounds | Otherwise-valid caller-bound preimage of 24577 bytes: `message_too_large`; separately signed-record depth 13: `ccj_noncanonical`; independently header 65537: `frame_too_large` before body read | A complete 24576-byte record signs at payload 32884 bytes excluding header; depth12 signs. Source boundary pairs S21/PS2 and S22/PS3 are codec-only controls |
| MSG-V07 generation fence | Retire g1 before final release: `generation_inactive`; change journal to active g2 while connection pins g1: `generation_mismatch`; no late success | Same M without retirement signs; explicitly re-registered g2 needs fresh connection/attestation and succeeds |
| MSG-V08 revoke fence | Revoke registration 1 before release or use a fresh connection afterward: `identity_revoked` | Unrevoked M signs; no resurrection control uses a tombstoned path |
| MSG-V09 key-purpose verification | Verify M's P signature with purpose-1, -2, -3 or -5 public key: cryptographic verification fails; replace certificate purpose/key with those siblings: certificate/policy verification rejects, even if otherwise validly issuer-signed | Same signature and unchanged purpose-4 certificate verify; purpose-5 certificate signature verifies only under the pinned issuer |
| MSG-V10 retained-ID conflict | First sign P with ID R; retry R with canonical P2: `request_conflict`, original result unchanged | Retry R with exact P returns byte-identical original key ID/signature across reconnect/restart under still-current authority; only one retained success |
| MSG-V11 unbound/foreign authority | M with no binding: `binding_not_found`; a foreign stored binding cannot be adopted (`peer_binding_mismatch`); key/path selector in params: `request_malformed` | M's own binding, no selectors, signs |
| MSG-V12 current certification | Expired local key attestation: `key_not_valid_now`; verifier with stale/missing status or a current revoked tombstone rejects current-use authentication despite a valid message signature | Valid window plus fresh active status and expected registration verifies |
| MSG-V13 wire encoding | Pad P's base64url or set unused bits to nonzero: `request_malformed`; decoded bytes must not be silently repaired | Exact unpadded encoding in section 3.1 signs |
| MSG-V14 audit/recovery boundary | Known pre-commit audit refusal: `audit_unavailable`, no output, mutation or new successful result. Separately interrupt a commit with unknown durability/acknowledgement: fence admission, release no success, reconcile actual durable outcome and keep any committed result; no signing during reconciliation | Healthy audit releases one retained result. If reconciliation finds a committed result after lost acknowledgement, same-ID/bytes retry recovers it exactly without signing again under current authority; if it proves no commit, no successful result exists; unresolved outcome stays fenced |
| MSG-V15 receiver role/type separation | Under the same `swarma-msg/2` label, change a correct caller-bound record's role to approver/delegate or its body type: byte signer may sign it; receiver rejects the agent's wrong profile/type or reconstruction. Grant/act tags refuse at signer; no invented role-specific tags | Agent Ed25519 author message verifies; optional independently attested P-256 approver follows waggle; delegate has no admitted v0 control |
| MSG-V16 stable key, inactive attestation | Keep the same purpose-4 key for persistent path g1→g2; present a cryptographically valid g1 signature and unexpired g1 attestation after g1 retires: verifier rejects because its attested generation is not active, even though g2 uses identical key bytes | A fresh signature covering g2/registration-2 attestation ID T2, with that exact attestation and active status, verifies; expired g2 attestation still rejects |
| MSG-V17 purpose-5 outbound isolation | A SIGN_REQUEST selecting the purpose-5 key: `sign_key_mismatch`; helper or `sign_message` params selecting it: `request_malformed`; bounded internal wrong-key plants feeding purpose 5 into helper (2), witness (3) or message (4) signers: `purpose_unknown` before signing | A signs with purpose 1, helper with 2, qualified witness with 3, message with 4; internal attestation builder alone signs its fixed attestation with 5; witness control is conditional on option C activation |
| MSG-V18 attestation issuer isolation | For each purpose 1, 2, 3 and 4, replace the attestation signature/issuer with that sibling while keeping the true purpose-5 root independently pinned: verifier rejects the unpinned/wrong-purpose signer; claiming issuer purpose 5 cannot authorize it | Service-built attestation signed with the pinned purpose-5 issuer verifies, within a nonempty window of at most 86400 seconds; a 86401-second window rejects even with a valid issuer signature |
| MSG-V19 signer identity binding | Change only `body.author` to a foreign string: `signer_identity_mismatch`, `retryable=false`; also set both paths to the same foreign ID: same refusal, no new successful result | M's own active attested key ID at both key paths plus current T signs without rewriting |
| MSG-V20 signed-record key binding | Change only top-level `key` to a foreign string: `signer_identity_mismatch`, `retryable=false`; mutual agreement with a foreign author never supplies caller authority | M's service-derived purpose-4 key ID at both key paths plus current T signs; exact retries recheck all three |
| MSG-V21 mandatory identity and resolution | Remove any of `key`, `body.author`, `body.author_attestation` (including canonical `{}`), use a canonical top-level scalar/array, set body to a scalar or any identity field to a non-string: `signer_identity_malformed`. Separately remove/invalidate protected resolved key/current attestation/policy after valid native admission: `signer_identity_unavailable`. All non-retryable | Correct BOUND_RECORD and valid caller identity resolution sign; precise generation/revoke failures retain their native codes |
| MSG-V22 unique field resolution | Duplicate any of the three decoded authority members, including escaped aliases: `ccj_noncanonical` (canonical duplicates are impossible); use arrays/multi-value objects for any identity string: `signer_identity_malformed`; no first/last/alias choice | Exact `key` and `body.author` each resolve once to M's key ID and `body.author_attestation` to current T; disjoint opaque members cannot substitute |
| MSG-V23 attestation closed schema and bounds | Omit any required certificate or binding member: verifier `key_binding_unavailable`; wrong type/profile/key-id/root/purpose, inactive binding, 86401-second window, evidence >8192 bytes, depth17, UID 4294967295, registration 9007199254740992 or binding string 256 bytes: verifier `key_binding_invalid`. Issuer refuses these before signing; never omit/coerce to fit | Complete §4.2 purpose-5 certificate with exact active binding, valid <=86400 window and each applicable boundary within 8192-byte evidence verifies; exact 8192-byte evidence is a codec boundary control only if all other profile limits hold |
| MSG-V24 shared revocation and currency | Missing/stale/future/incomplete/rolled-back registry snapshot refuses current use as unavailable; malformed/signature-invalid or purpose-5-root-signed snapshot, registry-root-signed attestation, wrong scope/purpose or overlapping root roles refuse as invalid; effective key or attestation-record entry rejects even with old body.iat. Bound is max(S + A, from), A <=60 s | Complete authentic fresh continuous snapshot with no effective match plus independently active status allows the ordinary certificate/message checks; registry-owner revocation root, purpose and scope satisfy §4.3 |
| MSG-V25 exact current attestation binding | With active g2 and the same stable K as retired g1, supply g1's attestation ID T1 at body.author_attestation while key and body.author equal K: signer_identity_mismatch, retryable=false, no new successful result. An older noncurrent renewal ID within g2 also refuses. Missing/wrong-type author_attestation is signer_identity_malformed. At receiver, exact referenced evidence is fully verified; an inactive g1 record refuses earlier as key_binding_invalid, while otherwise valid evidence whose content ID disagrees with the reference refuses late author_attestation_mismatch; no newer-record substitution | Active g2's exact current purpose-5 attestation ID T2, with key=body.author=K, signs without rewriting under with_active. Receiver fetches T2 exactly and verifies all binding/profile/time/snapshot evidence before equality; the valid current g2 association verifies |

Construct MSG-V06 from a correct caller-bound record with opaque string
padding split across an array of at most 64 strings, each <=8192 bytes.
Count CCJ-1 syntax and the 12-byte `swarma-msg/2` label plus LF: adjust ASCII
padding to make the **complete** preimage exactly 24576; one additional byte
in a non-full string yields 24577 without changing any identity path.
Their base64url/native payload sizes are 32768/32884 and 32770/32886.
Separately nest an opaque body member so the complete signed-record container
depth is 12 (positive), then 13 (negative), counting root = 1. Strings/arrays
stay within their bounds. Independent negatives are an 8193-byte string and
65-entry array (`ccj_noncanonical`), paired with 8192-byte/64-entry valid
caller-bound controls inside the preimage limit. These controls assert custody
language only; a receiver may refuse an unregistered application payload.

MSG-V07 and V08 require separate races where retirement/revocation wins the
release barrier; released-first controls show the stated recall limit.
MSG-V09's internal-purpose guard additionally needs a bounded faulty-selector
plant before implementation handoff. No killed mutants or passing runtime
message tests are claimed by this text-only slice.

## 8. Open dependencies and scope bounds

[MSG1](../UNRESOLVED_QUESTIONS.md#swarm-signer-message-specification-gates)
is aligned to accepted waggle **67df75bec015ea463f685e4daf4975ecda18816a**.
§4.4 records the resolved X01/X25/D30 mappings and the retained field/range
constraints; no format/authority mismatch remains. MSG2 (stable key, fresh
active-generation attestation), MSG3 (purpose 5, maximum 24 hours), and the
bounded 24576-byte/depth12 language remain decided. Runtime signing, attestation
issuance and publication are not implemented by this document. Live
publication/fresh status/root continuity remain base Q10 qualification gates.

Base Q6, Q7, Q9 and Q10 continue to gate generation ordering, persistent
revocation, socket access and portable certification. No new signed format
can replace an unpublished authority interface with an allow-all stub. These design decisions alone do not
qualify any of those dependencies.

No surface table was supplied with this assignment (brief gap). All seven
requested alignment parts are covered; no required row is treated as
out of contract. Implementation, executable vectors/mutants, publication
service and production qualification are outside this spec-only slice.

## 9. Normative change inventory

On separate approval and implementation, the following base rules need
explicit amendments; publishing this proposal does not amend them silently:

| Base section | Proposed amendment |
| --- | --- |
| 3 | Message sibling lifecycle follows binding/tombstone and actual-release fences; generation-specific certificates do not imply generation-specific key bytes |
| 4.1–4.3 | Reserve purpose 4 and decided internal purpose 5; preserve four hardened components and purpose-1-only binding registration; publish root certification/continuity before claiming it |
| 5 | Add self-only `sign_message` without caller selectors, with signed-record key/author/current-attestation checks and durable retained-result authority |
| 7 | Add exact method/binary schema and validated-domain exception to the unrestricted-byte ban; include signatures in durable same-ID recovery |
| 8 | Replace "only signing method on B" with the two method-specific signing authorities; helper bytes, enrollment and purpose 2 remain unchanged |
| 9 | Add the proposed purpose-3/4/5 separation rows, including reverse-direction checks; ordinary metadata/mutations still perform no key signing |
| 10 | Count message encoding, canonicalization, signing, retries and results inside existing limits; qualify group provisioning without implying helper permission |
| 11 | Add `swarma-msg` logical domain, exact preimage digest/null rules and result audit transaction; preserve custody extension and failure closure |
| 13–14 | Implement paired vectors, fault/race controls and acceptance coverage; resolve MSG1 and qualify decided MSG2/MSG3 before activation |
| 15 | Add non-retryable `message_too_large` and the three `signer_identity_*` codes with §6 mappings; keep native schema/canonicality/domain errors separate |
