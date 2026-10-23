# Keymaker candidate specification

Status: spec only; Linux v0 candidate. MUST and MUST NOT describe requirements,
not implemented or qualified capabilities. No service code is included.

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
- [Registrar specification](https://github.com/relux-works/swarma-registrar/blob/main/spec/registrar.md): authority for `registration/1`, `enrollment/1`, signed envelopes and `uid_map` meaning. Its draft format-publication gaps gate integration.
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

`generation` is exactly 32 lowercase hexadecimal digits representing a random
128-bit account-incarnation token, not a counter. State is `creating`, `active`,
`retiring` or `removed`. `lookup` MUST read the authoritative user-manager
journal through a read-only verified adapter. Missing, ambiguous, unreadable,
restored-but-unreconciled or fenced evidence MUST refuse. Only `active` permits
admission. A cached success MUST NOT authorise later work.

`with_active` is a semantic interface requirement, not a claim that an RPC or
file-lock protocol has been published. It MUST serialize the final binding
check, durable result and response release against retirement. No Keymaker
state lock may be held while waiting on a remote service. A retirement that
wins this ordering MUST prevent subsequent release. A response released first
is already issued; later retirement cannot recall its signature. The concrete
user-manager adapter and ordering proof are an activation gate (Q6).

Until that adapter exists, the production implementation stub MUST return
`generation_source_unavailable`. It MUST NOT infer activity from `getpwuid`,
the process table or a static UID table. A root-protected synthetic journal is
allowed only in an explicitly isolated test instance; it does not qualify
production generation enforcement. Unit fixtures may inject the interface.

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
| `sign_registration` (native helper method only) | `name`, `aud` | Registrar envelope | Active peer whose kernel UID is explicitly allowed for the name in pinned enrollment |
| `decrypt` | None accepted | `operation_unsupported` | Nobody in v0 |

`names` has exactly `{purpose,product,project,agent}`; `purpose` must be
`agent-identity`. `target_uid` is a registration TARGET, never the caller's
credential. `target_generation` must match authoritative evidence. Ordinary
requests MUST NOT have `uid`, `generation`, `identity` or `path` selectors.

v0 register/revoke intake is limited to the configured operator principal
(Q3, pending curator ruling). Operator UID possession does not stand in for
a human signature where required. `mode` is `operator` or `ephemeral`.
`operator_record` is an opaque signed-record object for the future platform
verifier, or null for `ephemeral`. A verified operator record must bind this
exact operation, target registration, owner, epoch, action ID and canonical
arguments, with current authority and replay checks. Its bytes and verifier
are a publication gate (Q7). Persistent revoke MUST return
`operator_record_unavailable` until this verifier is available; it MUST NOT
accept an unsigned substitute. Invalid or changed evidence refuses
`operator_record_invalid`. Positive fixture verdicts model the verifier
interface and MUST NOT be mistaken for an available production wire format.

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
unknown schema members refuse. Object keys are lexicographically sorted by
UTF-8 bytes, with no insignificant whitespace. Strings use UTF-8 directly,
escape only quote/backslash and control characters (short `\b\t\n\f\r`
where available, otherwise lowercase `\u00xx`); do not escape slash. No Unicode
normalization is applied. These local canonical-byte assumptions MUST be
checked against the platform CCJ-1 owner before activation; a differing CCJ-1
definition gates both sockets rather than being silently accepted (Q5).

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
inside `envelope`. The following body assumptions are **to align with registrar
spec**, following the public CIP-0019 draft rather than publishing a competing
signed format:

- Keymaker constructs the `registration/1` body itself from configured host
  key, validated name/audience, CSPRNG 128-bit nonce and whole-second UTC
  `iat`/`exp`, with a 120-second lifetime. It uses the registrar's canonical
  envelope/preimage rules and returns the complete envelope. The client MUST
  NOT supply body, nonce, timestamps, key, signature input or TTL overrides.
- Public draft spelling is `swarma-registrar registration/1` plus newline and
  canonical body; this is the only helper signing domain. Ed25519 is v0's
  algorithm; the host key is the configured purpose-2 descendant in the
  enrollment's valid `keys[]`. No P-256 emulation or agent-key substitution.
- Pending registrar clarification, `sig` is unpadded base64url of the 64-byte
  signature, key uses its draft `ed25519:` encoding, and nonce uses unpadded
  base64url. Name grammar is lowercase `[a-z0-9][a-z0-9._=/-]{0,254}` without
  `@` or server suffix, maximum 255 ASCII bytes; enrollment membership remains
  mandatory even when this syntactic check passes. This bound/grammar is a
  provisional helper restriction, not a change to the carrier standard.
- Same-ID retry returns the same stored envelope while still valid and
  authorised; after expiry it returns `request_expired`. A new ID is needed
  for a fresh nonce. The nonce is distinct from the transport request ID.
  Nonce generation failure is `entropy_unavailable`; uncertain time or clock
  rollback is `clock_untrusted`. Do not mint an already-expired envelope.

Before every helper signature and release, Keymaker MUST load or revalidate
a pinned, verified `enrollment/1` revision from a configured local path. It
MUST NOT fetch the network or follow a mutable branch. Root-managed policy
pins the registry commit and verification trust anchors; an agent-writable
worktree or caller-supplied revision is invalid. Persist the greatest accepted
sequence and revocation tombstones. Missing path/unreadable evidence refuses
`enrollment_unavailable`; invalid signature/pin, rollback or unverified
revision refuses `enrollment_unverified`; revoked state refuses `host_revoked`.
Updates require explicit verified pin installation; removing a tombstone or
restarting with an older revision cannot reactivate an enrollment.

`uid_map` is REQUIRED for station hosts. Absence refuses `uid_map_required`;
an absent caller UID refuses `uid_not_permitted`; a name not mapped to the
kernel UID refuses `name_not_permitted`. Group membership never supplies a
fallback. Name must also be permitted by the enrollment's names policy.
`aud` MUST byte-equal the configured server name (`audience_mismatch`).
Unenrolled/wrong-purpose key refuses `key_not_enrolled`; validity-window
failure is `key_not_valid_now`. An optional executable pin in a future
uid_map contract MUST NOT be claimed enforceable from a request path string;
such entries refuse `enrollment_unsupported` until qualified.

The helper enforces account generations even though enrollment maps numeric
UIDs. Reusing a UID MUST NOT reactivate old helper permission implicitly: the
protected local enrollment-pin policy includes the admitted generation for
each UID. A new generation requires explicit reviewed re-admission alongside
its identity binding (`generation_mismatch` otherwise). This local guard is
not an added enrollment/1 wire member. Publication with the registrar is Q5.
Keymaker signs admission evidence; it never calls the homeserver, issues a
JWT, logs a token, or promises that already-issued carrier sessions are ended
by local revocation.

## 9. Domain separation

| Entry | Key | Bytes that may be signed |
| --- | --- | --- |
| Agent socket | Purpose 1, peer-bound path | Exact SSHSIG preimage in `git` namespace |
| Native control methods on B | No signing key operation | Binding mutations and public metadata only |
| Native registration helper on B | Configured purpose 2 | Registrar-built `registration/1` preimage only |

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
refusal_code,previous_digest,record_digest}`; unknown optional values are null,
not omitted. `domain` is the SSHSIG namespace (`git`), registrar domain, or
`control`; result is `success`, `refused` or `unknown`. Time is whole-second UTC
or null with result `unknown` when trustworthy time cannot be established.

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

This section is a proposed runbook for the infrastructure owner to execute
as root after a reviewed v0 binary, fixtures and config are delivered. It is
the privileged step handed to the keeper; **none of it was executed for this
specification**. Commands and CLI entry points below are candidate installation
requirements, not tools present today. Do not run them against an existing
installation or reuse a production master for the integration fixture.

The reserved IDs below are examples for a fresh isolated test host. The
guards MUST pass; collisions require selecting approved free service IDs,
not renumbering existing users. The reviewed files must first be staged under
`/var/tmp/keymaker-release`, owned by root, without station write access.

```sh
set -eu
test "$(id -u)" = 0
! getent passwd swarma-keymaker
! getent group swarma-keymaker
! getent group swarma-registration
! getent passwd 990
! getent group 990
! getent group 991
groupadd --system --gid 990 swarma-keymaker
groupadd --system --gid 991 swarma-registration
useradd --system --uid 990 --gid swarma-keymaker --no-create-home \
  --home-dir /var/lib/swarma-keymaker --shell /usr/sbin/nologin swarma-keymaker
install -d -o root -g swarma-keymaker -m 0750 /etc/swarma-keymaker
install -d -o swarma-keymaker -g swarma-keymaker -m 0700 /var/lib/swarma-keymaker
install -d -o swarma-keymaker -g swarma-keymaker -m 0700 /var/log/swarma-keymaker
install -d -o swarma-keymaker -g swarma-keymaker -m 0755 /run/swarma-keymaker
test ! -e /var/lib/swarma-keymaker/master.seed
test ! -L /var/lib/swarma-keymaker/master.seed
umask 077
head -c 32 /dev/urandom > /var/lib/swarma-keymaker/master.seed
chown swarma-keymaker:swarma-keymaker /var/lib/swarma-keymaker/master.seed
chmod 0600 /var/lib/swarma-keymaker/master.seed
install -o root -g root -m 0755 /var/tmp/keymaker-release/keymaker /usr/local/bin/keymaker
install -o root -g swarma-keymaker -m 0640 \
  /var/tmp/keymaker-release/config.json /etc/swarma-keymaker/config.json
install -o root -g swarma-keymaker -m 0640 \
  /var/tmp/keymaker-release/name-indices.json /etc/swarma-keymaker/name-indices.json
install -o root -g swarma-keymaker -m 0640 \
  /var/tmp/keymaker-release/enrollment.json /etc/swarma-keymaker/enrollment.json
install -o root -g root -m 0644 \
  /var/tmp/keymaker-release/swarma-keymaker.service /etc/systemd/system/swarma-keymaker.service
systemctl daemon-reload
```

The staged unit MUST have at least the following settings; the binary owns
creation/modes of both sockets, including helper group lookup:

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

Linux permits a socket's group to be changed only to an eligible group. The
service account therefore needs the helper group as well as callers. The
staged unit MUST add `SupplementaryGroups=swarma-registration`; root owns that
membership. It conveys no extra file read authority. Without that setting,
socket group setup MUST fail startup rather than fall back to 0666.

For the isolated multi-UID window, the future integration runner MUST accept
these fixed CLI options. It creates an isolated daemon/config/journal fixture,
uses a **public test seed** separate from the installation master, and drops
privileges for all client calls. It MUST NOT mutate live generation records.

```sh
! getent passwd keymaker-test-a
! getent passwd keymaker-test-b
useradd --create-home --shell /usr/sbin/nologin keymaker-test-a
useradd --create-home --shell /usr/sbin/nologin keymaker-test-b
usermod -a -G swarma-registration keymaker-test-a
usermod -a -G swarma-registration keymaker-test-b
install -d -o root -g root -m 0700 /var/tmp/keymaker-integration
/var/tmp/keymaker-release/keymaker-integration \
  --client-a-uid "$(id -u keymaker-test-a)" \
  --client-b-uid "$(id -u keymaker-test-b)" \
  --service-user swarma-keymaker \
  --work-dir /var/tmp/keymaker-integration \
  --report /var/tmp/keymaker-integration/report.json
```

The runner must emit each test's name, candidate/toolchain identity, actual
verdict and exit code. Owner cleanup is a separate explicit action after all
recorded daemon/client PIDs are stopped and the report is retained. No cleanup
command in this spec authorises deletion of an existing user or live data.
Production `systemctl enable --now swarma-keymaker` is permitted only after
the generation adapter, enrollment verification and signed-act gates are
qualified; synthetic test-source success cannot open that gate.

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
| `TestHelperEnrollmentAndUIDMap` | Absent/unverified/revoked enrollment, missing map/UID, wrong name/aud cannot sign | Planned; fixture present |
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
2. **Q2 — pending curator ruling:** decrypt is deferred. Default is typed
   unsupported refusal; no decrypt or general byte-signing fallback.
3. **Q3 — pending curator ruling:** configured operator-only register/revoke
   intake in v0, dispatcher later with published grants. Persistent revoke
   additionally needs a verified signed operator act; missing verifier refuses.
4. **Q4 — decided:** repository/module is `swarma-keymaker`,
   role is per-station key custody, lore name Keymaker; no module rename.
5. **Q5 — registrar/CCJ-1 publication gate:** agree exact signed body bytes,
   signature representation, name grammar/length, helper result nesting,
   retry/expiry, pin update/freshness and UID-generation re-admission guard.
   Local assumptions in sections 7–8 MUST be resolved against the owner.
6. **Q6 — generation-source gate:** publish authoritative journal adapter,
   operator-principal generations and retirement/release ordering. Production
   stub denies all dependent operations. An isolated fixture proves no live
   integration, restore freshness or cross-service atomicity.
7. **Q7 — signed-act gate:** publish operator-record verification, pins,
   replay and canonical argument binding. No unsigned persistent revoke.
8. **Q8 — index-registry decision:** approve explicit immutable scoped indices,
   approval workflow, registry recovery and epoch binding. A truncated hash
   cannot supply the required collision-free mapping.
9. **Q9 — provisioning gate:** qualify dedicated service user and narrowly
   managed helper-group membership for service/callers. Group access is never
   a replacement for required uid_map or active generation evidence.
10. **Q10 — later-format gate:** external owner root attestation, planned
    rotation and compromise/reissue records need publication and qualification;
    they are hooks only in v0. macOS/TPM are separate qualification work.
11. **Q11 — privileged evidence gate:** owner supplies section 12's isolated
    multi-UID window and reviewed v0 artifacts; no root action or service
    deployment is part of this spec-only slice.

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
| `role_not_permitted` | Authenticated peer has no operation authority |
| `identity_revoked`, `persistent_revoke_requires_operator` | Terminal identity or forbidden revoke mode |
| `operator_record_unavailable`, `operator_record_invalid` | Missing verifier/evidence or invalid signed act |
| `path_not_hardened`, `path_invalid`, `purpose_unknown` | Invalid derivation contract |
| `name_invalid`, `name_unknown`, `name_registry_invalid`, `index_exhausted` | Naming/allocation failure |
| `sign_data_not_sshsig`, `sshsig_malformed`, `namespace_not_permitted` | Forbidden/malformed signature domain |
| `sign_key_mismatch`, `sign_flags_unsupported`, `agent_message_unsupported` | Wrong SSH key/flags or unsupported agent type |
| `operation_unsupported`, `request_malformed`, `request_conflict` | Unsupported method, invalid schema or conflicting effect ID |
| `frame_too_large`, `frame_truncated`, `frame_malformed`, `ccj_noncanonical` | Transport/canonical-byte failure |
| `version_unsupported`, `hello_required`, `hello_already_negotiated` | Invalid negotiation state |
| `request_deadline_exceeded`, `request_expired` | Request budget or retained helper result lifetime ended |
| `enrollment_unavailable`, `enrollment_unverified`, `enrollment_unsupported`, `host_revoked` | Unavailable, untrusted, unsupported or revoked enrollment |
| `uid_map_required`, `uid_not_permitted`, `name_not_permitted`, `audience_mismatch` | Required map, mapped principal, name or audience check failed |
| `key_not_enrolled`, `key_not_valid_now` | Host purpose key absent or outside enrolled window |
| `entropy_unavailable`, `clock_untrusted` | Cannot safely create fresh admission proof |
| `rate_limited`, `busy`, `state_capacity_exceeded`, `audit_unavailable` | Resource or durable-evidence admission closure |
