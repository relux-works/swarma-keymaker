# Keymaker candidate specification

Status: spec only; Linux v0 candidate. MUST and MUST NOT describe requirements,
not implemented or qualified capabilities. No service code is included.

The [option C external-witness supplement](keymaker-witness.md) proposes state
rollback protection, lifecycle vectors and explicitly enumerated normative
changes; it does not activate or change this specification's existing rules.

The [Swarm Signer message supplement](keymaker-msg.md) proposes purpose-4
agent message signatures, certification, lifecycle choices and paired text
vectors. Its registry/method changes are proposals; the existing purpose
allowlist and native methods remain unchanged until separately activated.

## 1. Scope and public references

Keymaker is a dedicated local key-custody service. It provides one bound
Ed25519 identity per active station account, Git-compatible SSH signatures,
public-key lookup, controlled binding registration and identity revocation.
It also supplies the host registration helper. It MUST NOT export private
keys, accept client-selected signing paths, mint grants, launch agents, manage
OS accounts, issue carrier login tokens or decide whether a signed action is
semantically correct. `decrypt` is out of v0 and MUST refuse as unsupported.

Public design references (drafts remain drafts):

- [CIP-0024, Agent stations (draft)](https://github.com/relux-works/curator-spec/blob/fb4e16abe1cf4aa2c87e01a87203134b4f06b6b9/cips/CIP-0024-agent-stations.md): one station per account and identity custody.
- [CIP-0019, Carrier admission (draft)](https://github.com/relux-works/curator-spec/blob/a77686c8112d60841236f2107d7e085e48361f6e/cips/CIP-0019-carrier-admission-by-public-key.md): helper and enrollment constraints.
- [CIP-0010, Credentials (draft)](https://github.com/relux-works/curator-spec/blob/a77686c8112d60841236f2107d7e085e48361f6e/cips/CIP-0010-credentials-setup-token-and-inherited-auth.md): identity keys and provider credentials have different authorities.
- [Credential broker specification, section 13.1](https://github.com/relux-works/swarma-credential-broker/blob/ec7fb3d0670449b074521d51f3e03b59f0142a69/spec/broker.md#131-transport): Unix framing, canonical objects and deadlines.
- [swarma-registrar spec/registrar.md (draft)](https://github.com/relux-works/swarma-registrar/blob/f81020a685b8d33c4fc61d835192d4fc87739398/spec/registrar.md): authority for `registration/1`, `enrollment/1`, signed envelopes and `uid_map` meaning. This candidate aligns to sections 2–5 at that draft revision; changing constants requires a reviewed alignment update, not a silent deployment change.
- [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md): Ed25519 hardened derivation and published test vectors 1 and 2.
- [SSH agent protocol, draft-miller-ssh-agent-17](https://www.ietf.org/archive/id/draft-miller-ssh-agent-17.txt): protocol subset below; a work in progress, not an RFC.
- [OpenSSH PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig), sections 2–3: detached signature format and signed preimage.

Keymaker owns its two socket endpoints, framing, method schemas, helper
responses/refusals, peer authentication and host-key custody. The registrar
owns the signed document formats. This ownership split is decided (Q1). A format conflict MUST close registration
admission until aligned;
Keymaker MUST NOT silently introduce a second registration document dialect.

## 2. Threat model and limits

The kernel, root-managed installation, generation journal, operator verification
and service process are trusted. An attacker may control all code and text in
one station, submit arbitrary socket bytes, reuse connections and race account
retirement. Usernames, request text and executable names are not credentials.

| Threat | Required boundary | Remaining limit |
| --- | --- | --- |
| Prompt injection reads an identity key | No private-key response or station-readable key file | The compromised station can request permitted signatures as itself |
| Station claims another identity | Kernel UID plus active generation selects one stored binding | Processes sharing a UID cannot be distinguished; one station per UID is required |
| Recycled UID accesses the previous account's key | Generation equality checked on every operation and before release | Journal integrity and retirement coordination are trusted |
| Generic signing used for carrier admission | Exact SSHSIG allowlist, separate host purpose and helper endpoint | A permitted Git signature can still authenticate harmful Git content |
| Unauthorised register/revoke or name minting | Operator authority and mandatory enrollment `uid_map` | Root or service compromise defeats the local boundary |
| Replayed or altered mutation | Caller-scoped durable request ID and exact arguments | Registrar owns registration nonce verification and login-token replay policy |
| Resource exhaustion | Bounded frames, work, concurrency and audit budgets | Local denial of service remains possible; no availability guarantee |
| False execution report, bad review, malicious task | No correctness claim from a signature | Independent review and external observation remain necessary |
| Kernel exploit, master compromise, cryptographic break | Outside local custody guarantee | All descendants share a master compromise domain; separate derived keys are not independent owners |

The service MUST NOT claim to protect provider-visible content, enforce task
scope, establish reviewer independence, provide consensus, prevent network
exfiltration by an already-authorised station, or make a compromised signer
truthful. File permissions protect against other UIDs; they do not protect
against root or the dedicated service's own compromise.

## 3. Principals, generations and bindings

### 3.1 Peer identity and generation source

`PeerCredentials(connection)` MUST obtain the UID from Linux `SO_PEERCRED`.
The macOS port MUST use `LOCAL_PEERCRED`/the native peer-credential equivalent,
and is not qualified in v0. Failure returns `peer_identity_unavailable`; there
is no environment-variable, request-UID, claimed executable or username fallback.
PID/GID may be audit metadata but MUST NOT replace UID authentication. Abstract
Unix sockets, TCP listeners and agent forwarding are outside v0.

The generation interface is a separate trusted dependency:

```
GenerationSource.lookup(uid) -> {uid, generation, state, revision, fenced}
GenerationSource.with_active(uid, generation, bounded_commit) -> result
```

The authoritative generation journal format belongs to `swarma-user-manager`
and its v0 specification; Keymaker MUST NOT define another journal format.
For each UID, Keymaker needs the generation token, lifecycle state, a revision
or ordering, and integrity/provenance evidence. Their encoding belongs to the
user-manager specification. The interface above is semantic, not a journal
schema; `fenced` is a local admission verdict. K1 implements the read-only
adapter against that published format. `lookup` MUST read the authoritative
journal through this verified adapter. Missing, ambiguous, unreadable,
restored-but-unreconciled or fenced evidence MUST refuse. Only `active` permits
admission. A cached success MUST NOT authorise later work.

`with_active` is a semantic interface requirement, not a claim that an RPC or
file-lock protocol has been published. It MUST serialize the final binding
check, durable result and response release against retirement. No Keymaker
state lock may be held while waiting on a remote service. A retirement that
wins this ordering MUST prevent subsequent release. A response released first
is already issued; later retirement cannot recall its signature. The concrete
ordering contract belongs to the user-manager journal format (Q6).

Without an explicitly configured and available verified journal, the production
source MUST return `generation_source_unavailable`. Until the user-manager
writer exists, the operator writes entries using a reviewed root-run procedure
in that same format. This is the real authoritative journal with a manual
writer and qualifies as the production generation source, not a static UID
table. Keymaker MUST NOT infer activity from `getpwuid` or the process table.
Root-protected synthetic journals remain isolated test fixtures, not production
authority; unit fixtures may inject the interface.

The `with_active` ordering requirement still applies to retirement recorded in
the journal. A manual entry alone does not establish cross-process serialization
of a concurrent update and release; the procedure and adapter must follow the
published journal's ordering contract. Keymaker revalidates at release. In this
interim, retirement fencing depends on the operator recording `retiring` or
`removed` before account removal. A retirement recorded late is not fenced;
manual writing provides no automatic coordination with OS account removal.

The optional protected configuration member `generation_journal` contains
`path` (an absolute, clean journal directory path) and `initial_floor`
(`{seq, hash}` in the journal format). It exposes no owner or fixture policy.
The configured initial floor MUST be used only for pristine local state: no
stored generation anchor and no binding ever issued. A durable enrollment
record MUST distinguish a lost anchor from pristine state even when no binding
has yet been issued. An absent, corrupt or incompletely committed established
anchor, or journal rollback/fork relative to it, MUST latch
`generation_source_fenced`, durably record one incident, and require operator
reconciliation. Keymaker MUST NOT initialize from the restored journal or
recover automatically. A verified window alone may advance the durable floor;
publication MUST be crash-safe and complete before an authorized release.
Local anchor continuity does not implement external restore authorization:
WC1 remains PENDING, with no dummy success callback or claim of restore safety.

The final callback MUST carry the journal's bounded deadline through durable
audit admission and actual transport handoff. A post-callback deadline check
cannot recall bytes already emitted. An already-started durable write/sync
completes its commit protocol, but an expired window MUST suppress handoff.

Each accepted connection records `(peer_uid, generation_at_accept)`. Each
operation and its release MUST revalidate this tuple. A live connection MUST
NOT change generations, adopt a new binding, or survive retirement by using
the UID's new incarnation. Close it on a mismatch. Binding revocation uses the same final-release fence
as generation retirement.
An in-flight signature whose release has not committed MUST be discarded when
revocation wins the ordering; already released results cannot be recalled.
A connection open at revocation MUST be invalidated and closed, returning a
typed refusal/failure for any pending next request where possible (otherwise
EOF). The audit verdict is `identity_revoked`; no next request can reuse an
old binding snapshot. Retirement similarly refuses `generation_inactive` or
`generation_mismatch` for an in-flight or next request. A connection MUST NOT
be transferred to a newly registered path or generation. Clients MUST verify the
server socket's protected directory, expected owner and kernel peer UID.

Surface B MUST report an accept-time generation refusal as one audited,
request-ID-bound typed error for the first well-formed frame within its
admission deadline, then close without admitting any method.

### 3.2 Binding record and lifecycle

The service-owned durable record has exactly these semantic members:

```
{uid, generation, path, owner, registration_number, lifetime,
 registrar_principal, status, master_epoch, registry_revision}
```

`lifetime` is `ephemeral` or `persistent`. `path` is the four-element resolved
hardened identity path, never a UID-derived path. `owner` is a configured
owner identifier; `registration_number` is a service-assigned monotonic
positive safe integer. `registrar_principal` records the authenticated
registrant, including its generation. `status` is `active`, `unbound` or
`revoked`. Tombstones and issued registration numbers MUST survive restart.

There MUST be at most one active identity binding per `(uid, generation)`
and per `(master_epoch, path)`. Lifetime, owner and path MUST NOT be changed
in place. A registration conflicting with either uniqueness constraint
refuses `binding_conflict`. Retirement closes access but MUST NOT revoke a
persistent identity. Explicit authorised re-registration of its existing
non-revoked path to a fresh account can restore the same public key; it gets a
new registration number and retains the predecessor record. A new UID owner
MUST NOT inherit a key automatically. A revoked path MUST NOT be resurrected
under the same master epoch (`identity_revoked`). Ephemeral paths are never
reassigned to a later execution.

## 4. Derivation and storage

### 4.1 Master and SLIP-0010

An installation has one 32-byte cryptographically random master seed per
epoch. Ed25519 uses SLIP-0010 exactly: HMAC-SHA512 with key `ed25519 seed` to
obtain the master node; child input is `0x00 || parent_seed || ser32(index)`
using the parent chain code as HMAC key. `ser32` is big endian. Every child
index MUST have bit 31 set. The left half becomes the Ed25519 seed; the right
half is the child chain code. Public keys are RFC 8032 32-byte encodings;
SLIP's published `00` prefix is serialization metadata, not a public-key byte.

All operational paths MUST have exactly four components:
`m/purpose'/product'/project'/agent'`. A prime means add `0x80000000` to an
index in `[0, 2147483647]`. Non-hardened, extra, missing or out-of-range
components MUST refuse `path_not_hardened` or `path_invalid` before deriving.
The two fixed purpose indices are `agent-identity = 1` and
`host-registration = 2`; all others refuse `purpose_unknown`. Surface A and
binding registration accept only purpose 1. Purpose 2 is configured once for
the host helper and MUST NOT be registered as a station key.

### 4.2 Exact name-to-index mapping

Unbounded names cannot be injected into 31 bits by truncating a hash without
collisions. v0 therefore requires a protected, append-only name-index registry,
distributed with the master recovery metadata. Mapping is deterministic given
the registry, not a stateless function of a display name.

Here, `product` is the colony, `project` is the swarm cell, and `agent` is the station.

- Names MUST match ASCII `[a-z][a-z0-9-]{0,62}` exactly. No case folding,
  Unicode normalization, aliases or whitespace trimming is performed.
- Products are scoped to the installation. Projects are scoped to the exact
  product index. Agents are scoped to the exact product/project indices.
  The registry contains arrays of `{name,index}` entries for each scope.
- In a scope the first approved allocation is index 1; each later allocation
  MUST use `max(all historical indices) + 1`. Index 0 is reserved. At
  exhaustion allocation refuses `index_exhausted`; it never wraps.
- Names and indices are unique within a scope. Entries cannot be renamed,
  deleted, reassigned or renumbered; retirement retains a tombstone. Conflict
  or duplicate evidence refuses `name_registry_invalid`. Unknown names refuse
  `name_unknown`; service requests MUST NOT allocate indices implicitly.
- Lookup is exact by purpose name, product name, project name within that
  product, then agent name within that project. Hardening those four indices
  yields the unique path. Two distinct registered name tuples cannot share a
  path. Sharing component indices in different scopes is safe because the
  ancestors differ. The registry revision is bound to each registration.
- Allocation is an operator-controlled configuration action, serialized and
  reviewed outside the service request path. Reproduction on another machine
  requires the same master epoch AND the same registry. Rebuilding the
  registry by sorting current names is forbidden.

`vectors/keymaker-paths.json` fixes an invented registry, a public test seed,
name tuples, paths and expected public keys, including two purposes and two
agents. Production secrets MUST NOT enter the vector generator.

### 4.3 Custody, root and recovery hooks

Linux v0 stores the seed as a regular 0600 file owned by the dedicated service
user in a 0700 directory. The service MUST refuse symlinks, wrong owner/mode,
extra hard links, incorrect length and unsafe parent permissions. It MUST NOT
print, export, journal or place seed/derived private material in station homes,
argv, environment, crash dumps or protocol responses. Child material has only
bounded in-process lifetime. v0 MUST disable core dumps and diagnostic memory
exports, clear temporary secret buffers after use, and request memory locking
(`mlock`) where the platform supports it. Readiness MUST report whether locking succeeds;
a failed lock MUST NOT be presented as swap protection. The operator must
exclude seed/state from ordinary unencrypted backups and either disable swap
or qualify encrypted swap. Root, backup operators, process memory disclosure,
swap and crash/hibernation images remain residual risks. Best-effort clearing
in a managed runtime is not a hardware non-extraction guarantee. TPM-backed
storage is a later provider.

Nothing returned by any operation MUST contain private seed/key bytes, chain
codes, extended private keys, derivation intermediates, or material enabling
reconstruction of a private key or derivation of siblings or parents. Public
keys, paths and signatures do not waive this rule. Private material MUST NEVER
be logged or printed, including startup failures. Offline public-test vector
chain codes are explicitly fixtures, never daemon outputs.

macOS is outside v0. A later storage adapter must qualify its daemon context
and recovery semantics; Secure Enclave P-256 registration support does not
magically supply hardened Ed25519 derivation. A service-owned 0600 software
fallback requires explicit platform qualification. It MUST NOT use a station's
login keychain. Hardware sealing of a master is distinct from never exposing
derived keys inside the signer process.

An epoch identifies a master and registry. The service MUST retain hooks for
`close_admission`, `describe_root`, `install_epoch` and `retire_epoch`. They are
not v0 wire methods. A root attestation binds each station public key to its
epoch and path; attestation format, external owner pin and verification are
unpublished (Q10), so v0 MUST NOT claim a portable certified identity chain.
The SLIP master public key is not an xpub from which Ed25519 children can be
derived. No master/root signing method is exposed to stations.

Planned rotation closes admission, installs a new seed and root, re-registers
all bindings, and uses the owner's separate long-lived authority to certify
continuity between roots. Compromise requires revoking the entire old root
and reissuing every descendant under a new root. Next keys derived from the
stolen seed are also compromised. An owner recovery key MUST remain external
to the compromised master; local UID isolation is not root recovery.
These workflows and external registry publication are deferred, not simulated
by incrementing a local rotation counter. A restored journal MUST stay fenced
until external revocations, epochs and generations are reconciled.

## 5. Operations and authority

Admission checks run in this order: bounded frame parsing; kernel peer and
active generation; method/role; target binding and policy; journal capacity;
final generation/fence check; durable result; response. Early malformed frames
may lack an attributable identity. Refusals MUST perform no key operation or
binding mutation; permitted audit/refusal-budget writes are the only effects.

| Operation | Inputs | Output | Authority |
| --- | --- | --- | --- |
| `sign` (surface A only) | SSH key blob, SSHSIG signed preimage, flags | SSH Ed25519 signature | Active peer's one bound identity; requested key must equal that key |
| `pubkey` | No identity selector | Public key, path, registration number, epoch | Active peer's own bound identity only |
| `register` | `target_uid`, `target_generation`, `owner`, `names`, `lifetime` | Public key, resolved path, new registration number, epoch | Configured operator UID/generation; target must be active and unbound |
| `revoke` | `registration_number`, `mode`, `operator_record` | Retained identity tombstone and registration number | Operator; future dispatcher only for its own ephemeral registration |
| `sign_registration` (native helper method only) | `name`, `aud` | Registrar envelope | Active peer with an active station binding whose kernel UID is explicitly allowed for the name in pinned enrollment |
| `decrypt` | None accepted | `operation_unsupported` | Nobody in v0 |

`names` has exactly `{purpose,product,project,agent}`; `purpose` must be
`agent-identity`. `target_uid` is a registration TARGET, never the caller's
credential. `target_generation` must match authoritative evidence. Ordinary
requests MUST NOT have `uid`, `generation`, `identity` or `path` selectors.

v0 register/revoke intake is limited to the configured operator principal
(Q3, decided). Operator UID possession does not stand in for
a human signature where required. `mode` is `operator` or `ephemeral`.
`operator_record` is the whole canonical `swarm-envelope/2` object for
`operator-act/1`, or null for `ephemeral`. The record format and exact
persistent-revoke mapping are published in
[waggle S0 §4.2](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#42-keymaker-operator_record-exact-mapping).
There is no extra wrapper or request member. It binds operation `revoke`,
registration target, protected owner and master epoch, action ID, audience,
nonce and canonical arguments digest; current P-256 operator-device authority,
trusted time, revocation and durable replay/effect checks are mandatory.
The waggle S1 verifier library and durable consumer integration remain pending
(Q7). Persistent revoke MUST return `operator_record_unavailable` until that
verifier is available; it MUST NOT accept an unsigned substitute. Invalid or
changed evidence refuses `operator_record_invalid`. Positive fixture verdicts
model the verifier interface and MUST NOT be mistaken for runtime availability.

An `ephemeral` revoke MUST require an ephemeral identity, its original
registrant principal and authoritative evidence of target retirement. A
configured operator may revoke that ephemeral identity in operator mode with
a verified act. Future dispatcher enablement also requires published grant
verification and a stored dispatcher registrant; absent that, its UID refuses
`role_not_permitted`. Persistent identities MUST refuse `ephemeral` mode even
when the requester originally registered them (`persistent_revoke_requires_operator`).
No operation can relabel a persistent identity as ephemeral. Account removal
and identity revocation are distinct transactions.

Mutation deduplication is keyed by `(caller_uid, caller_generation, request_id)`
and stores operation and complete canonical arguments (including signed
evidence) before effects. Exact retries return the original durable result;
different method/arguments refuse `request_conflict`. Fresh current authority
is still required to disclose a replay result. Audit and binding transition
are one recoverable transaction: committed tombstone/registration plus result,
or no mutation. Unresolved intent keeps the affected binding fenced and MUST
NOT be reported as absent or retried under a new identity. Durable mutation
results cannot be reclaimed without a rule permanently rejecting expired IDs;
v0 retains them and refuses admission at its budget.

### 5.1 Proposed pre-active provision and confirmation

The [provision/confirm supplement](keymaker-provision.md) proposes a separate
operator-only metadata transaction for a target in journal `creating`, plus
an authenticated scoped observer query. It defines `provisioned` binding
state, no issuance before active, ordered generation-pin re-admission and
exact-tuple confirmation. It is **spec only; not implemented or activated**.
The target-only metadata exception never relaxes active caller or signing
checks. Ordinary `register` above remains active-target-only. Confirmation
currency through the user-manager active append remains a joint qualification
gate; the supplemental query alone does not claim an activation lease. The
proposed instance correlation uses the confirmation result only; native hello
keeps its version-only result. Reconnect or service restart invalidates pending
correlation; instance equality cannot establish currency through activation.

## 6. Surface A: SSH agent subset

Endpoint: `/run/swarma-keymaker/agent.sock`. Each packet is `uint32be(length)`
then `byte(type) || body`. Length includes type, excludes header and MUST be
in `[1,65536]`. Strings are SSH `uint32be(length) || bytes`. Parse every length
with checked arithmetic and require complete consumption, with no trailing
data. The service MUST NOT accept native JSON on this socket.

| Request | Required reply |
| --- | --- |
| `SSH_AGENTC_REQUEST_IDENTITIES` (11), empty body | `SSH_AGENT_IDENTITIES_ANSWER` (12), count 1, own SSH key blob and fixed comment `keymaker`; never lists another key or host key |
| `SSH_AGENTC_SIGN_REQUEST` (13), `string key_blob`, `string data`, `uint32 flags` | `SSH_AGENT_SIGN_RESPONSE` (14), `string signature_blob` on success |
| Every other type, including add (17/25), remove (18), remove-all (19), lock/unlock (22/23), smartcard and extension messages | `SSH_AGENT_FAILURE` (5), no body |

The key blob is `string("ssh-ed25519") || string(public_key_32_bytes)`.
Signature blob is `string("ssh-ed25519") || string(signature_64_bytes)`.
Ed25519 flags MUST be zero (`sign_flags_unsupported`). A foreign key refuses
`sign_key_mismatch`. A missing/revoked binding refuses; it MUST NOT return an
empty identity list as if authentication succeeded. All semantic errors have
only the failure packet on this wire; stable detailed codes are in the audit.
Fatal framing errors close the connection; send failure only when framing is
sufficiently intact and doing so fits the deadline.

The `data` field MUST be the OpenSSH **signed-data preimage**, not an armored
signature and not the outer versioned SSHSIG blob:

```
ASCII("SSHSIG") || string(namespace) || string(reserved) ||
string(hash_algorithm) || string(message_digest)
```

No version or public key occurs inside this preimage. v0 requires namespace
exactly `git`, empty reserved, `hash_algorithm` exactly `sha256` (32-byte
digest) or `sha512` (64-byte digest), and no trailing bytes. Other namespaces
refuse `namespace_not_permitted`; malformed lengths/hash/reserved refuse
`sshsig_malformed`; absence of the SSHSIG preamble refuses
`sign_data_not_sshsig`. Raw text, a digest alone, a native envelope and SSH
userauth signed blobs MUST refuse. Their SSH response is failure. SSH userauth
is not an optional boolean switch in v0; enabling it later requires a separate
reviewed purpose/key and protocol contract, preserving domain separation.

The service signs these exact preimage bytes with the bound Ed25519 key.
It cannot inspect or approve the underlying Git message from its digest.
OpenSSH constructs the outer detached SSHSIG format. The following invocation
must work with an unmodified Git/OpenSSH client once a binding exists:

```sh
SSH_AUTH_SOCK=/run/swarma-keymaker/agent.sock \
git -c gpg.format=ssh -c user.signingkey='key::ssh-ed25519 <public-base64>' \
    commit -S -m 'Example change'
```

`<public-base64>` is the Base64 of the SSH key blob, not raw Ed25519 bytes.
Client verification uses an independently configured Git allowed-signers
file; successful signing does not install trust. Deployment MUST NOT install
agent forwarding or advertise forwarding support. A station that voluntarily
passes an authenticated descriptor or proxies requests delegates its own
permitted signing authority. v0 cannot detect every such proxy; this is part
of compromised-station misuse, not a claim to authenticate each later holder.
Kernel peer credentials authenticate the endpoint opener, not every process
that later receives its descriptor.

## 7. Surface B: native control

Endpoint: `/run/swarma-keymaker/control.sock`. Native control and the
registration-helper method in section 8 share this endpoint and framing;
method-specific authority remains mandatory.
Frames are a 4-byte BE length (excluding header) and exactly that many UTF-8
bytes, from 1 to 65536 inclusive. Over-cap headers refuse before allocation or
body read (`frame_too_large`). EOF partway through header/body is
`frame_truncated`. A read deadline is `request_deadline_exceeded`; it is not a
successful truncated-frame test. Zero length refuses `frame_malformed`.

Payload MUST be one CCJ-1 canonical JSON object. Integers are decimal safe
integers in `[-9007199254740991,9007199254740991]`; negative zero, fractions,
exponents, duplicate members, invalid UTF-8/Unicode, extra documents and
unknown schema members refuse. Object keys are sorted by Unicode scalar value
(equivalent to UTF-8 byte order for valid scalar sequences), with no insignificant whitespace. Strings use UTF-8 directly,
escape only quote/backslash and control characters (short `\b\t\n\f\r`
where available, otherwise lowercase `\u00xx`); do not escape slash. No Unicode
normalization is applied. This codec matches the registrar draft section 2.1.
Native socket frames deliberately require canonical bytes; the registrar HTTP
receiver instead accepts noncanonical wire JSON and canonicalizes its values.
This is an explicit transport distinction, not a different signed preimage
codec. The scope of that distinction is recorded in Q5.

First request (canonical bytes shown):

```json
{"method":"hello","request_id":"00000000000000000000000000000001","versions":[1]}
```

Success is `{"request_id":"...","result":{"version":1}}` with the actual
ID. Versions is a nonempty, unique array of positive safe integers; choose 1
if offered. If not, return `version_unsupported` and close. Any non-hello
before negotiation refuses `hello_required`. Hello has the same peer and
generation checks, but requires no identity binding. An unknown or repeated
method refuses `operation_unsupported` or `hello_already_negotiated`.

Every later request is exactly
`{method,params,request_id,timeout_ms}`. ID is 32 lowercase hexadecimal digits,
required and unique per caller generation; params is the method's object.
`timeout_ms` is an integer from 1 to 2000, relative to completion of the frame;
the service MUST also bound framing to 2 seconds. Hello deadline is 2 seconds.
One request is in flight per connection; no unsolicited replies or pipelining.
Response is exactly `{request_id,result}` or
`{request_id,error:{code,retryable}}`. The request ID MUST be echoed when a
valid ID was parsed; a framing/canonicalisation refusal uses null, then closes.
Errors contain no echoed payload or free-form diagnostic. `retryable` is
true only for `rate_limited`, `busy`, `generation_source_unavailable`,
`enrollment_unavailable`, `audit_unavailable` and `request_deadline_exceeded`;
mutation retries MUST retain the original ID and arguments.

`pubkey` params is `{}`. Register params and result are exactly the row in
section 5; `names` has the four named components, and all numeric UIDs fit
uint32. Revoke params are the three members in section 5; its result is
`{registration_number,status:"revoked"}`. Native `sign` MUST refuse; there is
no method accepting arbitrary signing bytes. A deadline after a durable
mutation cannot undo it; the retained result is recovered through the same-ID
retry. There MUST be no late response after closing or second mutation.

## 8. Registration helper method and registrar alignment

Endpoint: surface B, `/run/swarma-keymaker/control.sock`, using section 7's
frame/hello/ID/deadline rules. `sign_registration` is the only signing method
on B; it MUST NOT be accepted on A. Other B methods have their own section 5
authority. SSH packets MUST NOT be accepted on B. There are exactly two sockets,
not an additional helper socket.

The exact params object is `{name,aud}`. Success is
`{request_id,result:{envelope}}`, where `envelope` is the registrar-owned
registration envelope. Typed failures use section 7's error object. Keymaker
owns these helper method and result wrappers; the registrar owns the bytes
inside `envelope`. The signed document is built using **swarma-registrar
spec/registrar.md (draft)** sections 2–5 at the pinned reference in section 1;
Keymaker does not own or duplicate that document schema. The alignment choices
below are **to align with registrar spec** and must be rechecked if its draft
changes:

- The helper builds every registrar-defined body member itself: the fixed
  type, configured purpose-2 public key, permitted name, configured audience,
  independently generated 16-byte CSPRNG nonce, and whole-second UTC issue and
  expiry times. It chooses the draft's maximum 120-second proof lifetime.
  No caller-supplied key/body/nonce/time/TTL or signing bytes are accepted.
- Use the registrar section 2.2 canonical body preimage, ID and signature
  envelope, without a trailing newline. Ed25519 is v0's sole host algorithm;
  its 32-byte public key, 64-byte signature and 16-byte nonce use the draft's
  canonical unpadded base64url encodings. No P-256 or agent-key substitution.
  The generated key/signature must satisfy the draft's strict Ed25519 rules.
- Validate the requested name using the draft section 5 structured-name or
  exact explicit-legacy rules, including its configured-audience mxid byte
  bound, before audience comparison. The old permissive slash-containing
  localpart proposal is withdrawn. Name and audience remain literal,
  case-sensitive strings, with no normalization. A nonce is unrelated to the
  native transport request ID.
- Both issue time and release time must be inside the selected enrolled key's
  half-open validity window; no skew extends key authority. Clock rollback or
  unavailable trusted time refuses `clock_untrusted`; failed random generation
  refuses `entropy_unavailable`. Revalidate expiry after audit and before
  release, returning `request_expired` instead of an expired proof.
  "Trusted time" MUST satisfy the shared [platform time policy](https://github.com/relux-works/swarma-credential-broker/blob/191c0c35aa2f4e6a850246b26c05c0462ff96c41/docs/time-policy.md)
  in full: option A's protected NTS configuration, tracking evidence,
  clock-step/hold, uncertainty and process-start rules. `MaxSyncAge` is
  **2048 s** (sync must be strictly younger); `δ = |offset| + root distance`
  is the minimum uncertainty bound, not a replacement for the policy's
  conservative returned δ, whose inclusive cap is **1.5 s**. Check fresh time
  confidence at process start before any time decision and preserve the
  policy's continuity requirements; later decisions/releases still require
  confidence. Keymaker MAY be stricter, never looser.
  The provider package is **not yet consumed**. Keymaker will import a
  published public provider package once one exists; it MUST NOT copy the
  provider's rules into local logic. Until that dependency is published,
  consumed and qualified, production trusted time stays unavailable and the
  helper refuses `clock_untrusted`, **`retryable=false`**.
- A same-ID native retry returns the retained envelope only while all current
  binding/enrollment checks and proof expiry still permit it; it never mints
  another nonce for that ID. The registrar may already have consumed that
  nonce, so retry is not a guarantee of a second HTTP admission. A fresh
  admission attempt needs a new native ID. This receiver distinction remains
  an explicit Q5 integration test, not an exemption from registrar replay rules.

Before every helper signature and release, Keymaker MUST have the caller's
active station identity binding for the current generation. Absence refuses
`binding_not_found`; revocation refuses `identity_revoked`, including a fresh
connection from the same still-active UID/generation. Binding revocation
therefore also withdraws helper authority; uid_map alone never restores it.
The in-flight/next-request release fence in section 3 applies to the helper.
An already released proof cannot be recalled and remains subject to registrar
checks and expiry. Re-registration of an unrelated identity is not implicit
helper re-admission.

Keymaker MUST revalidate the exact local registry pin and snapshot using the
registrar draft sections 4.3–4.4 at the revision pinned in section 1. E1 is
decided: the owner holds the offline Ed25519 enrollment-publisher key, and
both services use the same out-of-band verification pins in root-owned
configuration. Both MUST verify the pinned signed registry commit and the
phase-0 enrollment envelope signature against those pins as specified in
registrar section 4.3; Keymaker adds no variant of its own. Snapshot verification
phase ordering, historical ownership of legacy names, atomic installation,
rollback evidence and reload/restore fencing follow registrar section 4.4,
without a separate Keymaker restatement of those rules.

The local helper maps missing/unreadable registry evidence to
`enrollment_unavailable`, unverifiable/invalid/rollback evidence to
`enrollment_unverified`, and a verified host tombstone to `host_revoked`.
Registrar loader diagnostics retain their registrar meanings; these mappings
are helper response codes, not renamed document formats. A missing station
uid_map is a schema violation that fails the entire registrar snapshot load;
the helper refuses `enrollment_unverified`. While any record is invalid, the
whole registry is unusable. No group-only fallback is available.

Consume uid_map as the draft section 4.2 **array of objects**, not an object
keyed by decimal UID strings. Resolve exactly one integer-UID row, then its
explicit names list; an absent row refuses `uid_not_permitted`, a different
name refuses `name_not_permitted`. Duplicate rows, cross-UID name ambiguity,
invalid types or other schema violations refuse `enrollment_unverified`.
The registrar owns the array/member bounds, optional `exe` syntax and name
membership rules; Keymaker MUST validate those exact rules before enforcing
peer authority. `aud` must match the configured server (`audience_mismatch`),
and the purpose-2 key must be enrolled/current (`key_not_enrolled` or
`key_not_valid_now`).

**Executable-qualified entries: unsupported in v0.** A path supplied in the
request is never executable evidence. On Linux, SO_PEERCRED's PID and a read
of `/proc/<pid>/exe` would at most give a process/path snapshot. The opener
may exit and its PID be reused; it may exec, fork or pass the connected file
descriptor before an operation. A pidfd can narrow PID-reuse ambiguity but
does not bind every later socket operation to an unchanged executable. A
readlink comparison has no atomic coupling to request release and does not
attest interpreter inputs or request proxies. No such race-safe attestation
contract is implemented or qualified here.

Consequently, if the matched UID row has `exe`, Keymaker MUST refuse
`enrollment_unsupported` before any signature, even when an observed path
matches. Wrong, undeterminable, inaccessible/deleted executable evidence and
matching snapshots all refuse; Keymaker MUST NOT silently drop `exe` or fall
back to UID-only authority. An unmatched row's optional exe does not grant
or change the caller's authority. The enrollment can be valid registrar data
while this local enforcement capability is unavailable. macOS executable
attestation is likewise unqualified and refuses; its peer-credential support
alone would not close this gap. Enabling executable-qualified rows requires
a separately reviewed per-operation attestation and delegation model (Q12).

The helper enforces account generations even though enrollment maps numeric
UIDs. Reusing a UID MUST NOT reactivate old helper permission implicitly: the
protected local enrollment-pin policy includes the admitted generation for
each UID. A new generation requires explicit reviewed re-admission alongside
its identity binding (`generation_mismatch` otherwise). This local guard is
not an added enrollment/1 wire member. This is a local narrowing rule to align with registrar spec; its shared
qualification is tracked in Q5, without changing the registrar uid_map schema.
Keymaker signs admission evidence; it never calls the homeserver, issues a
JWT, logs a token, or promises that already-issued carrier sessions are ended
by local revocation.

Local signing custody that is closed, unloaded or unable to maintain its required
protection refuses `custody_unavailable` with `retryable=false`; healthy generation,
enrollment and audit evidence do not substitute for custody. Recovery requires
restoring protected custody before a new admission attempt.

## 9. Domain separation

| Entry | Key | Bytes that may be signed |
| --- | --- | --- |
| Agent socket | Purpose 1, peer-bound path | Exact SSHSIG preimage in `git` namespace |
| Native control methods on B | No signing key operation | Binding mutations and public metadata only |
| Native registration helper on B | Configured purpose 2 | Registrar-built `registration/1` preimage only |
| Internal state witness (separate proposal) | Reserved purpose 3 | `keymaker-witness-record/1` + NUL + service-built CCJ-1 body only |
| Native `sign_message` on B (unimplemented candidate) | Purpose 4, active peer's author message sibling | Landed-S0-aligned exact `swarma-msg/2` + LF + canonical signed record: `key` and `body.author` equal that peer's active attested purpose-4 key ID; `body.author_attestation` equals its service-resolved current attestation content ID, under `with_active` through release and on retries |
| Internal message-key certification (decided, unimplemented) | Purpose 5, owner-pinned certification root | Only waggle `swarma-attestation attestation/1` + LF + service-built signed record for agent keys, with validity at most 24 hours; never `revocation/1`, whose agent-withdrawal snapshots use the separately pinned registry-owner revocation root |

The last three rows summarize unactivated proposals, not current signing
capabilities. See the [witness supplement](keymaker-witness.md#31-protected-identity-and-purpose-separation)
and [message supplement](keymaker-msg.md#1-purpose-registry-and-domain-separation).
The message candidate checks exactly three identity paths: `key`,
`body.author` and `body.author_attestation`. The first two equal the caller's
own active attested purpose-4 key ID; the third equals its service-resolved
current attestation content ID. Signing and retries reject a noncurrent
renewal or another generation's attestation even when the stable key is equal.
All three checks use the same active binding under `with_active` through
actual release. Other record fields remain opaque to the signer. This narrows
section 7's byte-signing ban and section 8's single-signing-method rule only
on activation; the [change inventory](keymaker-msg.md#9-normative-change-inventory)
lists the required amendments.

MSG1 format alignment to landed S0
`67df75bec015ea463f685e4daf4975ecda18816a` is satisfied. Purpose 5 signs only
agent attestations; a distinct scoped registry-owner revocation root signs
agent-withdrawal snapshots. These resolved mappings are recorded in the
[supplement's alignment ledger](keymaker-msg.md#44-landed-s0-alignment-and-qualification-gates).
Implementation, root/publication and live-authority qualification remain gates;
no message method, attestation issuer or snapshot publisher is activated here.

No request on one surface may yield a signature accepted in another domain.
This relies on both distinct purpose-derived keys and non-overlapping
preimages, not a caller's claimed operation. A Git payload containing a
registration document remains a Git digest inside SSHSIG and uses the agent
key; it is not a registration signature. Registration bytes sent through
SIGN_REQUEST fail before signing. Helper requests for SSHSIG bytes are schema
errors. Native `sign`, host-key lookup on A and identity-selector fields on B
refuse. Audit MUST record the logical domain on each operation. Cross-domain
verifiers MUST enforce their own expected key, namespace and envelope type.

## 10. Process, sockets and resource budgets

The daemon is one unprivileged service process under `swarma-keymaker`, not
root, with no network listener, plugins, shell-outs or inherited listening
descriptors from stations. Kernel peer checks occur immediately on accept.
State and secret directories are 0700. Configuration, binary and generation
evidence are root-owned and not writable by stations or the daemon.

| Path | Owner/group | Mode | Admission |
| --- | --- | --- | --- |
| `/run/swarma-keymaker` | service user/service group | 0755 | Protected traversable directory; no station writes |
| `agent.sock` | service user/service group | 0666 | World-connectable; peer generation and binding required |
| `control.sock` | service user/`swarma-registration` | 0660 | Group-restricted; self-only pubkey, operator mutations and mandatory mapped helper authority |

The helper group grants connection capability, not signing authority. Q9
tracks how provisioning supplies that narrow group access. Socket modes MUST
be set by the daemon before readiness; it MUST refuse unsafe pre-existing
non-socket entries, wrong ownership or directories writable by peers. It MUST
NOT unlink an arbitrary configured path or chmod a symlink. One daemon owns
the private state lock; a second instance refuses startup. Readiness requires
valid master, registry, replayed journal, generation source and enrollment for
helper admission. Unready helper admission need not block an independently
qualified agent socket; state corruption or audit failure closes all admission.

Proposed v0 hard bounds (configuration may narrow, never silently broaden):

| Resource | Limit |
| --- | --- |
| Connections | 128 global, 8 per peer UID; admission overflow closes with `busy` where framed |
| Active requests | 16 global, 1 per connection; no unbounded queues |
| Frame/body | 65536 bytes; nested JSON depth 16; string length at most frame bound |
| Framing/operation | 2 seconds each; deadline checked before irreversible work/release |
| Rate buckets | Per UID+generation: 20 operations/s, burst 40; mutations 2/s, burst 4; helper additionally 2/s per key and name, burst 4 |
| Global workload | 200 operations/s, burst 256; retry/rejection traffic consumes a bounded budget |
| Process | 256 MiB memory ceiling, 64 tasks, 512 file descriptors, one CPU quota |
| State | 256 MiB active binding/result budget; no automatic loss of tombstones or effect IDs |
| Audit | 64 MiB segments, 1 GiB online budget plus reserved 16 MiB for control/refusal evidence |

Limits MUST be charged before allocation or mutation. Rate exhaustion refuses
`rate_limited`; no delayed signing queue. Per-name buckets MUST be allocated
only for admitted names from the bounded enrollment, never arbitrary supplied
strings. UID-level connection bounds apply
before generation resolution. Duplicate requests do not evade accounting.
When durable state cannot safely grow, refuse `state_capacity_exceeded` while
retaining evidence. Operational values need qualification; they are explicit
candidate bounds, not performance measurements. Service network egress MUST
be denied; enrollment and journal reads are local.

## 11. Audit and fail-closed recovery

The exact record schema is `{seq,time,instance,surface,request_id,peer_uid,
generation,path,master_epoch,operation,domain,payload_digest,result,
refusal_code,[custody_cause],previous_digest,record_digest}` (`[custody_cause]`
denotes the optional extension below); other unknown optional values are null,
not omitted. `domain` is the SSHSIG namespace (`git`), registrar domain, or
`control`; result is `success`, `refused` or `unknown`. Time is whole-second UTC
or null with result `unknown` when trustworthy time cannot be established.

Both append APIs MUST require new `custody_unavailable` records to have result
`refused` and include `custody_cause`, exactly one of `closed`, `unloaded`, or
`protection_failed`. A nil Master or empty seed
maps to `unloaded`; an explicitly closed Master maps to `closed` even after its
seed is erased; any other non-32-byte seed maps to `protection_failed`. Capture
the cause during the failing custody operation. This member MUST be omitted on
other records, including successful operations, and MUST NOT appear in responses
on either surface, including helper responses. All three causes produce identical
response bytes for the same request. The member carries no key material or
free-form diagnostics. Recovery MUST accept otherwise valid historical records
without `custody_cause`, including `custody_unavailable` refusals. This exception
is recovery-only: both append APIs MUST reject a new custody refusal code without
a cause. Whenever a cause is present, both append APIs and recovery MUST validate
its enum and require `refusal_code` equal to `custody_unavailable` and result
`refused`; a cause with another or absent code, or on `success`, `unknown` or any
other result, MUST refuse. Recovery MUST NOT invent a cause, rewrite historical
bytes or recompute stored record hashes; canonical bytes and the existing hash
chain remain unchanged. After time qualification, a new custody record whose
result becomes `unknown` MUST refuse before any append. Ordinary cause-free
unknown-time records retain their existing behavior. No journal migration is
needed for this optional historical metadata.

Audit is an append-only sequence of CCJ-1 JSON lines owned by the service,
mode 0600, in a 0700 directory. Each operation, including hello, lookup and
refusal, records `seq`, UTC time (or null), instance,
socket surface, request ID if known, authenticated UID, generation, resolved
path and epoch if known, operation/domain, digest of accepted input, result,
stable refusal code or null, and preceding record digest. Unknown identity or
unparsed input uses null; never invent a generation/path for attribution.
The record hash is SHA-256 of the canonical record without its `record_digest` field.
This detects accidental breaks; it does not resist root or service tampering
without an independent off-host checkpoint.

The journal MUST NOT contain seeds, child private keys, chain codes, raw sign
payloads, native frames, signed operator documents, returned envelopes/tokens
or free-form client errors. Payload content is limited to a SHA-256 digest;
metadata needed for attribution is typed and bounded. The registration nonce
and payload are not audit fields. Retained result storage is separate,
protected, and subject to its own budget; audit is not an effect-result cache.

Before releasing a signature or public response, durable audit success MUST
be established (`fdatasync` or an equivalently qualified durable transaction).
Signatures computed before an audit write fails MUST be discarded without
release. If journal append or sync fails, return `audit_unavailable` if possible,
close admission and record a bounded service-health diagnostic without input
content. An inability to audit that very failure MUST NOT lead to recursive
logging or unaudited operation. Repeated unframeable connection attempts may
be represented by bounded aggregate refusal counters; never silently execute
an unauditable operation. A full reserve closes listeners until repaired.

Rotation seals the current segment with sequence/hash bounds, syncs it, then
creates a new O_EXCL 0600 segment linked to its predecessor. No truncation or
in-place rewrite. Old segments may be removed only after verified durable
archive acknowledgement outside online budgets; absence of acknowledgement
applies backpressure. Startup checks continuity and pending mutation intent.
Missing/corrupt evidence or uncertain restore fences service admission.

## 12. Privileged Linux step: operator handoff

These are proposed owner-run commands for reviewed v0 artifacts, not commands
executed for this specification. The infrastructure owner provisions the
service and a reusable test window once. Later integration runs are entirely
unprivileged and never create/delete OS accounts. The host must have working
local NSS, Bash, Python 3, sudo/visudo and the usual account-management tools.
No daemon or integration runner is supplied by this spec-only repository.

### 12.1 Explicit preflight and dynamic service IDs

Use a root Bash shell. Stage reviewed release files under
`/var/tmp/keymaker-release`, root-owned and not writable by stations. Every
name/path guard precedes the first mutation. Never renumber an existing entry.
The allocator selects system IDs; no fixed numeric service UID/GID is assumed.

```sh
set -euo pipefail
test "$(id -u)" = 0
# runbook-check:begin guards
require_absent() {
  local lookup_status
  if getent "$1" "$2" > /dev/null; then
    printf 'collision: %s %s\n' "$1" "$2" >&2
    exit 1
  else
    lookup_status=$?
    if [ "$lookup_status" -ne 2 ]; then
      printf 'lookup failed: %s %s (exit %s)\n' "$1" "$2" "$lookup_status" >&2
      exit 1
    fi
  fi
}
# runbook-check:end guards
# runbook-check:begin service-preflight
require_absent passwd swarma-keymaker
require_absent group swarma-keymaker
require_absent group swarma-registration
# runbook-check:end service-preflight
for service_path in /etc/swarma-keymaker /var/lib/swarma-keymaker \
  /var/log/swarma-keymaker /run/swarma-keymaker /usr/local/bin/keymaker \
  /etc/systemd/system/swarma-keymaker.service; do
  if [ -e "$service_path" ] || [ -L "$service_path" ]; then
    printf 'existing installation path: %s\n' "$service_path" >&2
    exit 1
  fi
done
# runbook-check:begin service-allocation
groupadd --system swarma-keymaker
groupadd --system swarma-registration
useradd --system --gid swarma-keymaker --no-create-home \
  --home-dir /var/lib/swarma-keymaker --shell /usr/sbin/nologin swarma-keymaker
# runbook-check:end service-allocation
SERVICE_UID=$(id -u swarma-keymaker)
SERVICE_GID=$(getent group swarma-keymaker | cut -d: -f3)
CONTROL_GID=$(getent group swarma-registration | cut -d: -f3)
install -d -o root -g swarma-keymaker -m 0750 /etc/swarma-keymaker
install -d -o swarma-keymaker -g swarma-keymaker -m 0700 /var/lib/swarma-keymaker
install -d -o swarma-keymaker -g swarma-keymaker -m 0700 /var/log/swarma-keymaker
install -d -o swarma-keymaker -g swarma-keymaker -m 0755 /run/swarma-keymaker
umask 077
( set -o noclobber; head -c 32 /dev/urandom > /var/lib/swarma-keymaker/master.seed )
chown swarma-keymaker:swarma-keymaker /var/lib/swarma-keymaker/master.seed
chmod 0600 /var/lib/swarma-keymaker/master.seed
install -o root -g root -m 0755 /var/tmp/keymaker-release/keymaker /usr/local/bin/keymaker
install -o root -g swarma-keymaker -m 0640 \
  /var/tmp/keymaker-release/config.json /etc/swarma-keymaker/config.json
python3 - "$SERVICE_UID" "$SERVICE_GID" "$CONTROL_GID" <<'PY'
import json, sys
path = '/etc/swarma-keymaker/config.json'
with open(path) as f:
    config = json.load(f)
config.update(service_uid=int(sys.argv[1]), service_gid=int(sys.argv[2]),
              control_gid=int(sys.argv[3]))
with open(path, 'w') as f:
    json.dump(config, f, sort_keys=True)
    f.write('\n')
PY
install -o root -g swarma-keymaker -m 0640 \
  /var/tmp/keymaker-release/name-indices.json /etc/swarma-keymaker/name-indices.json
install -o root -g swarma-keymaker -m 0640 \
  /var/tmp/keymaker-release/enrollment.json /etc/swarma-keymaker/enrollment.json
install -o root -g root -m 0644 \
  /var/tmp/keymaker-release/swarma-keymaker.service /etc/systemd/system/swarma-keymaker.service
systemctl daemon-reload
```

`getent` exit 2 is the sole permitted absence result; success is a collision,
and all other nonzero exits abort. The function accepts names or numeric keys;
numeric collision cases are checked offline even though installation leaves
ID selection to the system allocator. A partial provisioning failure requires
owner inspection of its exact resources before retry, not bypassing guards.
The config's `service_uid`, `service_gid` and `control_gid` are protected numeric
pins; the daemon MUST verify them against the configured account/groups before
readiness. Offline checker markers delimit actual runbook excerpts, not alternate
implementations of these guards.

The staged unit MUST contain these settings; the daemon owns socket creation:

```ini
[Unit]
Description=Local identity key custody
After=local-fs.target
[Service]
Type=simple
User=swarma-keymaker
Group=swarma-keymaker
SupplementaryGroups=swarma-registration
ExecStart=/usr/local/bin/keymaker serve --config /etc/swarma-keymaker/config.json
RuntimeDirectory=swarma-keymaker
RuntimeDirectoryMode=0755
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/swarma-keymaker /var/log/swarma-keymaker /run/swarma-keymaker
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
CapabilityBoundingSet=
AmbientCapabilities=
LimitCORE=0
LimitNOFILE=512
MemoryMax=256M
TasksMax=64
CPUQuota=100%
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

The service needs the control socket group to assign that group without root.
If group setup fails, startup MUST fail instead of making the socket 0666.
Production `systemctl enable --now swarma-keymaker` remains gated on the real
generation adapter, enrollment and operator-verifier qualifications.

### 12.2 Provision the reusable test window once

The owner provisions a shared platform test window with two empty system
accounts and one test group. The documented defaults are `platform-test-a`,
`platform-test-b` and `platform-test-reg`. Names come from runner configuration,
not compiled constants; if different names are configured, the owner uses those
same names when provisioning. `<runner>` denotes an existing unprivileged
runner account, never root. The neutral window may serve more than one service's
tests and is separate from the production service's control group.

Use the same root Bash shell and `require_absent` function from section 12.1.
Only `getent` exit 2 means absent: a collision (0) or any other lookup failure
aborts before allocation. This minimal provisioning writes no state file and
no runner configuration. It allocates system IDs without fixing or renumbering
them; primary-group selection follows the system's `useradd` policy.

```sh
set -euo pipefail
test "$(id -u)" = 0
: "${RUNNER_USER:?set the existing unprivileged <runner> account}"
TEST_A=${TEST_A:-platform-test-a}
TEST_B=${TEST_B:-platform-test-b}
TEST_GROUP=${TEST_GROUP:-platform-test-reg}
WINDOW_SUDOERS=/etc/sudoers.d/agent-platform-test
WINDOW_SUDOERS_NEW=/etc/sudoers.d/.agent-platform-test.new
for window_name in "$RUNNER_USER" "$TEST_A" "$TEST_B" "$TEST_GROUP"; do
  case "$window_name" in ''|*[!a-z0-9_-]*|-*|[0-9]*) exit 1 ;; esac
done
test "$TEST_A" != "$TEST_B"
test "$RUNNER_USER" != "$TEST_A"
test "$RUNNER_USER" != "$TEST_B"
RUNNER_UID=$(id -u -- "$RUNNER_USER")
test "$RUNNER_UID" -ne 0
# runbook-check:begin window-provision
# runbook-check:begin window-preflight
require_absent passwd "$TEST_A"
require_absent passwd "$TEST_B"
require_absent group "$TEST_A"
require_absent group "$TEST_B"
require_absent group "$TEST_GROUP"
for window_path in "$WINDOW_SUDOERS" "$WINDOW_SUDOERS_NEW"; do
  if [ -e "$window_path" ] || [ -L "$window_path" ]; then
    printf 'existing window path: %s\n' "$window_path" >&2
    exit 1
  fi
done
# runbook-check:end window-preflight
WINDOW_TMP=$(mktemp -d)
trap 'rm -rf -- "$WINDOW_TMP"' EXIT
# runbook-check:begin window-sudoers-content
printf '%s ALL=(%s,%s) NOPASSWD: ALL\n%s ALL=(%s:%s) NOPASSWD: ALL\n' \
  "$RUNNER_USER" "$TEST_A" "$TEST_B" \
  "$RUNNER_USER" "$RUNNER_USER" "$TEST_GROUP" > "$WINDOW_TMP/agent-platform-test"
# runbook-check:end window-sudoers-content
visudo -cf "$WINDOW_TMP/agent-platform-test"
# runbook-check:begin window-allocation
groupadd --system "$TEST_GROUP"
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin "$TEST_A"
useradd --system --no-create-home --home-dir /nonexistent \
  --shell /usr/sbin/nologin "$TEST_B"
# runbook-check:end window-allocation
usermod -a -G "$TEST_GROUP" "$TEST_A"
install -o root -g root -m 0440 "$WINDOW_TMP/agent-platform-test" "$WINDOW_SUDOERS_NEW"
mv -T -- "$WINDOW_SUDOERS_NEW" "$WINDOW_SUDOERS"
visudo -c
id "$TEST_A"
id "$TEST_B"
# runbook-check:end window-provision
```

Both accounts have no created home, a nologin shell and no assigned password;
`useradd` without a password leaves the account locked. Only A belongs to the
new test group. The sudoers drop-in permits arbitrary fixture commands only
as A, B, or the runner with that group. It has no root or wildcard Runas target
and does not add the runner to a privileged group. sudo-rs's `visudo` rejects
`requiretty`, so this window emits only the two constrained Runas rules.
The private temporary candidate is parsed before any account, group or installed
file change; unknown run-as accounts do not prevent that syntax validation.
Both destination paths must be absent, including dangling symlinks. The validated
file is installed as root:root 0440 under the dotted staging name (ignored by
sudo), then moved with `mv -T` to the final name. A full `visudo -c` checks the
resulting policy. A failed partial setup requires owner inspection before
retrying; no absent state file proves that an existing account or path is safe
to delete. No production secrets are involved.

### 12.3 Verify and run as the unprivileged runner

After provisioning, the runner supplies its own readable JSON configuration.
The minimal window needs neither a root-owned state file nor a root-owned
numeric-pinned configuration. A configuration using the documented defaults is:

```json
{
  "runner_user": "<runner>",
  "client_a": "platform-test-a",
  "client_b": "platform-test-b",
  "registration_group": "platform-test-reg",
  "scratch_dir": "/tmp"
}
```

Replace `<runner>` with the actual unprivileged account. Root-owned
configuration and `runner_uid`, `client_a_uid`, `client_b_uid`,
`registration_gid` pins are optional hardening, not artifacts produced by the
minimal setup. The runner MUST resolve the configured names, require distinct
nonzero runner/A/B UIDs, and require that its own UID equals the configured
runner's. Optional pins, when supplied, MUST match. These checks validate the
test window; they do not establish account-generation authority.

As the runner, verify the defaults (substitute configured names if changed):

```sh
RUNNER_USER='<runner>'
sudo -n -u platform-test-a -- /usr/bin/id -u
sudo -n -u platform-test-b -- /usr/bin/id -u
sudo -n -u "$RUNNER_USER" -g platform-test-reg -- /usr/bin/id -g
sudo -n -u platform-test-a -- /usr/bin/id -G
sudo -n -u platform-test-b -- /usr/bin/id -G
```

The first two outputs MUST equal the independently resolved client UIDs; the
third MUST equal the configured group's resolved GID. The group MUST be
nonroot; A's group list MUST contain that GID and B's MUST NOT. The runner MUST
refuse inconsistent identities or membership; it MUST NOT infer success from
account names alone. Missing window or sudo permission is PENDING, never a
skipped or passing multi-UID qualification.

The reviewed `keymaker-window` runner starts its own daemon fixture as itself.
Clients use `sudo -n -u <configured-account> -- <client>`. The runner-as-self
sudo rule with the test group remains available for group-restricted socket
fixtures; surface A alone needs no such socket. Use only a public test seed
and runner-owned state, never production service paths or the production user.
Synthetic generation fixtures do not qualify the production journal adapter.
A proposed invocation for the reviewed runner binary is:

```sh
: "${WINDOW_CONFIG:?set the runner-readable JSON configuration path}"
: "${RUNNER_SCRATCH:?set an existing absolute build scratch directory}"
"$RUNNER_SCRATCH/keymaker-window" -config "$WINDOW_CONFIG" -check
"$RUNNER_SCRATCH/keymaker-window" -config "$WINDOW_CONFIG"
```

The canonical compiled runner exits 0 for pass, 1 for execution/test failure,
2 for usage/configuration error and 3 for PENDING. With `-check`, 0 qualifies
only provisioning preflight. PENDING prints exactly
`PENDING: test window not provisioned` on stderr. A make convenience wrapper
may normalize nonzero exits to 2; it MUST print the underlying runner status,
and callers needing the distinction MUST call the runner directly.

The configured scratch parent must allow both clients to traverse to the run
binary and socket. The runner must not chmod private ancestor directories.
Only its run directory, client executable and socket subdirectory are exposed
for traversal; master/state directories stay 0700 with 0600 files. The runner
creates its own work tree and records its canonical path, UID, device/inode
and per-run random token. Cleanup MUST validate that manifest, wait for its
recorded child processes and persist a durable report outside the tree before
removing only its own tree. Any process termination MUST check the recorded
PID, UID, start identity and run token; no pattern killing or reused-PID
assumptions. Mismatched directory/process identity or failed report persistence
refuses cleanup. Interrupted trees remain for owner inspection; no standalone
cleanup command or ownership proof from a missing state file is assumed.
Runner cleanup MUST NOT remove OS accounts, groups, global sockets or another
run's files. No privileged provisioning or live qualification is claimed here.

### 12.4 Owner rollback of the one-time window

First finish fixture cleanup as the runner. Because this is a shared window,
the owner must confirm all consumers are idle and inspect the exact accounts,
group and sudoers drop-in before authorizing removal. Without a root state
file there is no automatic provenance comparison: names alone do not prove
ownership. Stop on changed or ambiguous resources; reconcile them manually.
Do not run rollback against an existing unrelated window.

After that inspection, use root Bash with the same configured names (defaults
below). Remove the sudoers permission first, then the two accounts and group:

```sh
set -euo pipefail
test "$(id -u)" = 0
TEST_A=${TEST_A:-platform-test-a}
TEST_B=${TEST_B:-platform-test-b}
TEST_GROUP=${TEST_GROUP:-platform-test-reg}
WINDOW_SUDOERS=/etc/sudoers.d/agent-platform-test
test ! -L "$WINDOW_SUDOERS"
test "$(stat -c '%u:%a' "$WINDOW_SUDOERS")" = 0:440
visudo -cf "$WINDOW_SUDOERS"
rm -- "$WINDOW_SUDOERS"
visudo -c
# No --remove: no homes were created; active accounts must not be forced away.
userdel -- "$TEST_A"
userdel -- "$TEST_B"
groupdel -- "$TEST_GROUP"
```

There is no state/configuration cleanup in this minimal window. Retain the
runner's configuration and external test reports. If account deletion reports
active processes, or any step fails, stop and inspect; do not force deletion,
kill by pattern, recursively delete directories or renumber UIDs. Account
primary-group leftovers, if any, require separate owner inspection rather
than guessed cleanup. Optional hardening artifacts have their own separately
reviewed teardown and are not required by this procedure.

## 13. Tests and vector evidence

Negative vectors are listed before positive controls. Every vector names a
stable ID, complete fixture input, exact refusal code, paired valid control
and a single changed input field. `peer_uid` and generation/journal/verifier
fields in fixtures are injected harness facts, NEVER wire credentials. For
malformed packets the changed field is the complete byte-string packet.
Each refusal asserts no signature returned, no private material disclosed,
and no binding/enrollment mutation; bounded audit writes are permitted.

Current offline checks verify SLIP's published seed/chain/public controls,
Keymaker path examples, fixture structure and one-field pairing. They do NOT
execute the candidate refusal semantics against a service. There is no daemon
and no claimed green service test. Future test harnesses MUST run negatives
first and controls second; a reject-all implementation MUST fail controls.

| Required test | Claim and limits | Current status |
| --- | --- | --- |
| `TestBindingPeerUID` | Wrong peer cannot select a bound key; own peer succeeds | Planned; fixture present |
| `TestGenerationRetirementAndReuse` | Retired/new incarnation and an old live connection cannot use old binding | Planned; fixture plus race test required |
| `TestRevocationOpenConnection` | Revocation/retirement wins before release and subsequent requests cannot use a cached binding | Planned; in-flight and next-request vectors present |
| `TestNoPrivateMaterialReturned` | Forbid seed/chain/extended-key/private diagnostic output; own public-key control succeeds | Planned; schema/output-invariant vectors present |
| `TestGenerationSourceUnavailable` | Missing/fenced evidence yields precise refusal, no cached authority | Planned; fixture present |
| `TestHardenedPurposeAndRegistry` | Reject non-hardened/unknown purposes, duplicates and implicit allocation; exact paths reproduce | Derivation and fixture checks available; daemon checks planned |
| `TestSSHSIGSubset` | Reject raw/userauth/other namespace/trailing/flags/host key; valid Git preimage signs | Planned; concrete packets present |
| `TestNativeFramingAndCanonicalBytes` | Oversize refused from header; EOF detected; noncanonical/unknown-version rejected | Planned; concrete packets present |
| `TestRegisterRevokeAuthority` | Wrong caller and persistent ephemeral-style revoke cannot mutate state; signed operator control succeeds | Planned; verifier is a publication gate |
| `TestHelperEnrollmentAndUIDMap` | Absent/unverified/revoked enrollment, missing map/UID, wrong name/aud cannot sign | Planned; registrar-array fixtures present |
| `TestHelperRevokedBindingFreshConnection` | A fresh helper connection cannot reuse uid_map after its identity is revoked | Planned; paired fixture present |
| `TestHelperExecutableQualifiedRefusal` | Wrong, unavailable and matching executable snapshots never activate an exe-qualified row in v0 | Planned; UID-only positive controls paired with three qualified-row refusals |
| `TestRunbookCollisionBeforeMutation` | Actual shell preflight stops name/ID collisions and lookup errors before stub mutations; absent lookups proceed | Offline checker available; no root or account writes |
| `TestDomainSeparation` | Registration bytes rejected on A and no B arbitrary-sign path | Planned; fixture present |
| `TestAuditFailureAndRecovery` | Failed append/sync returns no signature, mutation intent replays without duplicates | Planned; fixture plus fault injection required |
| `TestPeerCredentialsCurrentUID` | Real SO_PEERCRED reports current test UID and valid binding succeeds | PENDING v0 binary; needs no root, no cross-UID claim |
| `TestPeerCredentialsTwoUIDs` | Real foreign UID refused; permitted UID succeeds | PENDING privileged window in section 12; mandatory suite entry |
| `TestGenerationReuseRealPeers` | Same numerical UID with simulated fresh generation cannot inherit old fixture binding | PENDING privileged window; does not claim OS allocator qualification |
| `TestGitSigningUnmodified` | Git/OpenSSH signs and independently verifies with expected allowed signer | PENDING v0 binary; no wrapper or userauth substitution |

Peer credentials, generation source, clock, entropy, journal and signed-act
verification MUST be interfaces for bounded unit fault injection. The real
Linux peer path MUST also be exercised by the single-UID positive control;
mock-only evidence cannot qualify it. Multi-UID entries remain PENDING,
never silently skipped, removed or labelled passing; a qualification command
must return a distinct nonzero pending exit status if privileges are absent.

The service acceptance gate MUST demonstrate it detects a bounded known
violation: e.g. disabling UID equality must fail `TestBindingPeerUID`, and
allowing a missing uid_map must fail `TestHelperEnrollmentAndUIDMap` while
the positive controls remain green. Mutant evidence must identify the mutant,
the property narrowed, the named failing test, and the bound of any survivor.
Offline fixture integrity is a different gate; it cannot kill a daemon-policy
mutant. There are no reviewer tests or previously accepted implementation
tests in this initial repository. Future rework MUST retain them by name.

## 14. Open questions and activation gates

1. **Q1 — decided:** Keymaker owns the helper socket and key;
   registrar owns signed documents and uid_map semantics. This supersedes the
   earlier single-owner-helper assumption. Signed-format publication still gates
   production helper activation.
2. **Q2 — decided:** decrypt is out of v0 and refuses
   `operation_unsupported`; no decrypt or general byte-signing fallback.
3. **Q3 — decided:** v0 register/revoke intake is limited to the configured
   operator principal. Persistent revoke refuses until the signed operator-act
   verifier exists; Q7 remains its activation gate.
4. **Q4 — decided:** repository/module is `swarma-keymaker`,
   role is per-station key custody, lore name Keymaker; no module rename.
5. **Q5 — registrar draft alignment gate:** sections 2–5 of the cited draft
   now define the body/envelope, CCJ-1, names, uid_map arrays and snapshot pins.
   Remaining differences/dependencies are enumerated in UNRESOLVED_QUESTIONS.md;
   revised draft constants require explicit consumer re-qualification.
6. **Q6 — interim decision:** format publication by `swarma-user-manager`
   is the remaining gate. K1 implements its read-only adapter; until the writer
   exists, the operator uses a reviewed root-run procedure in that same real
   journal format. Until publication, production refuses
   `generation_source_unavailable`. Release revalidation fences recorded
   retirement; an operator update made late does not fence account removal.
   Section 3.1 retains `with_active` ordering and states the manual-writer limit.
7. **Q7 — signed-act gate:** the operator-act/1 format and exact mapping are
   published in [waggle S0 §4.2](https://github.com/relux-works/waggle/blob/67df75bec015ea463f685e4daf4975ecda18816a/spec/swarm-envelope-2.md#42-keymaker-operator_record-exact-mapping).
   The S1 verifier library, pins, replay/effect integration and qualification
   remain pending; persistent revoke refuses `operator_record_unavailable`.
   No unsigned substitute.
8. **Q8 — decided:** the explicit, append-only, scoped name-to-index registry
   is approved. Field names and path syntax stay as specified in section 4.2;
   a truncated hash cannot supply the required collision-free mapping.
9. **Q9 — provisioning gate:** qualify dedicated service user and narrowly
   managed helper-group membership for service/callers. Group access is never
   a replacement for required uid_map or active generation evidence.
10. **Q10 — later-format gate:** external owner root attestation, planned
    rotation and compromise/reissue records need publication and qualification;
    they are hooks only in v0. macOS/TPM are separate qualification work.
11. **Q11 — privileged evidence gate:** owner pre-provisions section 12's
    shared two-UID window and constrained non-root sudo. The minimal setup
    writes no state/configuration; the unprivileged runner supplies names and
    verifies distinct nonroot UIDs, sudo readbacks and A-only group membership.
    Live multi-UID evidence remains PENDING until that window is available;
    no privileged action or service deployment is part of this spec-only slice.
12. **Q12 — decided:** registrar-valid exe rows are
    refused locally in v0, including matching snapshots. A future design must
    qualify per-operation executable identity and descriptor delegation, not
    rely on a racy procfs path comparison.

No surface table was supplied with this specification assignment; a later
implementation brief must enumerate its acceptance surfaces and coverage map.
No listed required behavior is silently considered out of contract. Deferred
decrypt, hardware/macOS, operator-format publication, external identity-chain
certification and rotation implementation are explicitly outside v0; their
denial/default requirements remain inside the candidate contract.

## 15. Stable local refusal codes

SSH transports map these to `SSH_AGENT_FAILURE`; native transports use the
typed error object. Codes are stable identifiers, not arbitrary diagnostic
strings. Registrar-owned signed-document verdicts retain registrar spelling.

| Code | Meaning |
| --- | --- |
| `peer_identity_unavailable` | Kernel credentials could not be established |
| `binding_not_found`, `peer_binding_mismatch`, `binding_conflict` | Missing, foreign or conflicting binding |
| `generation_inactive`, `generation_mismatch`, `generation_source_unavailable` | Retired, different or unavailable account incarnation |
| `generation_source_fenced` | Generation journal rollback/fork, stale writer or capacity-reserve incident; operator reconciliation required; `retryable=false` |
| `role_not_permitted` | Authenticated peer has no operation authority |
| `provision_state_invalid` (unimplemented provision/confirm proposal) | Exact target journal token is active, retiring or removed rather than creating for provision/confirm; `retryable=false` |
| `binding_provisioned` (unimplemented provision/confirm proposal) | Key use or public-key disclosure reaches a reserved binding without qualified durable active promotion; `retryable=false` |
| `identity_revoked`, `persistent_revoke_requires_operator` | Terminal identity or forbidden revoke mode |
| `operator_record_unavailable`, `operator_record_invalid` | Missing verifier/evidence or invalid signed act |
| `path_not_hardened`, `path_invalid`, `purpose_unknown` | Invalid derivation contract |
| `name_invalid`, `name_unknown`, `name_registry_invalid`, `index_exhausted` | Naming/allocation failure |
| `sign_data_not_sshsig`, `sshsig_malformed`, `namespace_not_permitted` | Forbidden/malformed signature domain |
| `sign_key_mismatch`, `sign_flags_unsupported`, `agent_message_unsupported` | Wrong SSH key/flags or unsupported agent type |
| `operation_unsupported`, `request_malformed`, `request_conflict` | Unsupported method, invalid schema or conflicting effect ID |
| `frame_too_large`, `frame_truncated`, `frame_malformed`, `ccj_noncanonical` | Transport/canonical-byte failure |
| `message_too_large` (decided, unimplemented message contract) | Complete decoded message preimage >24576 bytes within a valid native frame; `retryable=false` |
| `signer_identity_unavailable` (unimplemented message contract) | Missing/invalid service-resolved attested caller key, current attestation or identity policy after precise native authority checks; `retryable=false` |
| `signer_identity_malformed` (unimplemented message contract) | Missing `key`, `body.author` or `body.author_attestation`, non-object record/path container or wrongly typed/multi-value identity field after canonical validation; `retryable=false` |
| `signer_identity_mismatch` (unimplemented message contract) | Any extracted string differs byte-for-byte from caller's own active attested purpose-4 key ID or current attestation content ID; equal foreign keys or another generation's attestation still refuse; `retryable=false` |
| `version_unsupported`, `hello_required`, `hello_already_negotiated` | Invalid negotiation state |
| `request_deadline_exceeded`, `request_expired` | Request budget or retained helper result lifetime ended |
| `enrollment_unavailable`, `enrollment_unverified`, `enrollment_unsupported`, `host_revoked` | Unavailable, untrusted, unsupported or revoked enrollment |
| `uid_not_permitted`, `name_not_permitted`, `audience_mismatch` | Mapped principal, name or audience check failed |
| `key_not_enrolled`, `key_not_valid_now` | Host purpose key absent or outside enrolled window |
| `custody_unavailable` | Local signing custody is closed, unloaded or its required protection failed; `retryable=false` on B, failure packet on A |
| `entropy_unavailable`, `clock_untrusted` | Cannot safely create fresh admission proof |
| `rate_limited`, `busy`, `state_capacity_exceeded`, `audit_unavailable` | Resource or durable-evidence admission closure |
