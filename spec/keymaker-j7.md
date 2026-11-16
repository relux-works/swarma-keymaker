# Request and child-delegation key custody

Status: internal custody, protected lifecycle/policy and opt-in profile/1 typed
request signing, plus stopped-schema 6 profile/2 v3 requests. Production role startup remains closed. No installation,
external kind8185 interoperability, child service or enforcing activation.

## Purposes and selection

The allocated secp256k1 purposes are **j7-request = 7** and
**child-delegation = 8**. Reservations 3–6 and all existing Ed25519 purposes,
Master APIs, registry mappings and public vectors remain unchanged. Legacy
registration and Master.Public/Sign reject purposes 7/8. These algorithms use
separate roots; Ed25519 seed/node bytes are never converted into secp scalars.

Request custody derives exactly `m/7'/product'/project'/agent'` from the exact
current active identity binding's purpose-1 sibling. It reselects that entire
binding under the Store lock and compares its epoch and registry revision with
the immutable loaded pins. No arbitrary caller path or key selector is accepted.
The internal capability is not caller/run authentication: the internal request adapter holds
its generation/run and policy barriers through actual release.

Delegation custody uses **a separate instance and independently generated root**
at `m/8'/product'/project'/parent_slot'`. All four components are hardened;
name/slot indices are canonical positive integers through 2147483647. A protected
parent-slot source, separate from the request name registry, must allocate and
retain a fresh never-reused slot for every parent, including retired parents.
It provisions the public key before signing the parent, then binds that slot to
the exact authenticated parent containing the key. No truncated parent ID or
hash-derived index is used, avoiding a circular parent-ID dependency.

The internal source contract holds its exclusion barrier through use and binds
instance, epoch, registry revision and product/project/slot. Signing additionally
requires the exact bound parent. There is **no production slot source yet**:
missing source is unavailable; an integer or reference alone supplies nothing.
Fixture sources test namespace and pin checks, not durable allocation or parent
admission. Complete child validation, own-node history/closure checks, authority
separation and retained parent lifecycle must precede a child-only service.
Neither key may become a generic signing oracle. Request keys never sign grants;
delegation keys are reserved for children of their bound parent, never requests,
messages, consents, transactions or arbitrary caller digests.

## Cryptographic profile

Derivation follows [SLIP-0010](https://github.com/satoshilabs/slips/blob/a00312491693714d9bc1b6e4cb5b2e356e6c511e/slip-0010.md)
secp256k1 with the standard master/child retries, at the same child index.
Only hardened derivation is implemented. HMAC uses the standard library;
scalar/curve operations and BIP-340 nonce/signature arithmetic use pinned
`github.com/btcsuite/btcd/btcec/v2` **v2.5.1**, with its pinned secp dependency.

The [BIP-340](https://bips.dev/340/) primitive accepts a **32-byte application
digest**, emits x-only 32-byte public keys and strictly verifies 64-byte
signatures, including r/s bounds and even-Y reconstruction. It does not define
an application's digest/domain, signed object or wire encoding. Complete typed
objects and locally recomputed domains are mandatory for the request adapter;
there is no public raw-digest operation.

Signing supplies fresh 32-byte auxiliary entropy using the library's CustomNonce
option, refuses entropy failure, uses no FastSign option and explicitly
self-verifies before returning any internal result. The dependency's default
RFC6979 nonce path is not used. The [official corpus](https://github.com/bitcoin/bips/blob/200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb/bip-0340/test-vectors.csv)
is retained unchanged: indices 0–14 apply to this 32-byte message profile;
indices 15–18 are valid variable-message BIP-340 cases outside this backend
profile. No support for them is claimed. Public SLIP nodes anchor master/first
hardened child; synthetic four-level vectors cover both roles and parent slots.

## Explicit initialization and restart

`internal/keymaker.InitializeJ7Seed(path, uid, role, instance)` is a trusted,
explicit operator initialization boundary returning only an error. It generates
a fresh 32-byte root; it accepts no seed/key import and is not a socket method,
daemon startup action or deployment instruction. The operator must establish
that the target is independently authorized fresh custody. The function does
not prove freshness after joint deletion/restore of all external history.

The already existing immediate parent must be holder-owned 0700. The initializer
runs as that holder UID and never changes ownership implicitly. Descriptor
walking rejects symlinks; the seed record is regular holder-owned 0600 with
one link. The closed binary record is the bytes `keymaker-secp-root/1` plus LF,
exact role plus LF, exact instance ID plus LF, then exactly 32 root bytes.
Instance is a nonzero 32-character lowercase-hex provisioning identifier. The
record is protected storage only, not a private serialization/accessor API.
Wrong role/instance, a legacy raw seed, extra/truncated material or unsafe
ownership/mode/linking is refused.

Initialization obtains complete entropy, exclusively creates a same-directory
`.<filename>.next` staging file, writes and syncs the whole record, reopens and
checks its exact bytes/protection, then publishes with atomic no-replace rename
and syncs the directory. Existing target or prior staging evidence is never
overwritten. A returned partial-write or entropy failure publishes no loadable
partial target; cleanup only removes the staging inode created by that call.
Interruption may retain staging evidence and requires operator reconciliation.
A directory-sync error after rename can leave a complete but uncertain published
record: retain it, do not blindly initialize again or call failure an abort.

Restart is load-only: missing or malformed established material refuses and is
never automatically recreated. There is no automatic rollback/reset/recovery or
claim that local files exclude coordinated restore. Full recovery/continuity is
an independent integration obligation.

## Closed role configuration and runtime behavior

Omitted `service_role` retains the unchanged legacy schema; explicit `legacy`
uses that same schema. Legacy config cannot include new root/instance fields.
The two role variants share these required members:

```text
{service_role, j7_key_file, instance_id, service_uid, service_gid,
 master_epoch, registry_revision}
```

`service_role` is exactly `j7-request` or `delegation`; `j7_key_file` is an
absolute clean path; instance follows the rule above; epoch/registry pins are
nonempty strings; service IDs keep uint32 semantics. No legacy master, registry,
helper or legacy socket members are accepted in those variants.
The loaded record fixes role/instance, and the capability fixes epoch/revision.

The `j7-request` variant additionally accepts only:

- `time_policy`: the inline protected shared time policy; absence refuses
  `clock_untrusted` at startup, and a supplied backward tolerance must be at
  least one second.
- `generation_journal: {path, initial_floor: {seq, hash}}`: the protected
  generation journal and initial floor. Established state needs its carried
  generation anchor; startup never bootstraps a missing established anchor.
- `socket: {dir, group}`: the dedicated socket directory and numeric group.
- `static_gate: {approver_key_file, statement_file, signature_file, digest_file}`:
  four distinct protected input-file paths for the signed static gate.
- `j7_policy` with the protected table path, holder UID, schema, instance,
  identity registration number and exact launcher principal as defined below.
- `j7_state: {path, minimum_reader_schema, head_file}`: `path` is the Store
  directory. Reader floors remain exactly 4 or 5 in configuration; signing
  startup requires 5 and opens only schema 5. Inline expected-head members
  are refused in this variant.

Policy, state, socket, static-gate and generation stanzas are required for
readiness. Missing role stanzas refuse `j7_configuration_incomplete`; a missing
generation stanza refuses `generation_source_unavailable`. The launcher UID
must differ from the service UID. Key, state, policy and socket directories
must be distinct and nonoverlapping. Every path is absolute and clean.

`head_file` is a separate root-owned, single-link regular file, mode 0600 or
0640, under root-owned ancestors with no group/other write permission. It
contains exactly compact `{"expected_version":V,"expected_digest":"D"}` in
that member order, then exactly one LF: V is a canonical integer in
1..2^53-1 and D is 64 lowercase hexadecimal digits. Other whitespace, BOMs,
missing or extra LF, extra/missing/duplicate members, noncanonical integers,
uppercase hexadecimal and trailing data refuse. Its path is distinct from the
config file. It and the static-gate files must be outside all service-writable
directories. The stopped-operator tool exports those bytes read-only under the
state lock
after a reconciled stop; an independent operator installs the protected file.
Neither that service-user tool nor the running service writes the head file.
Static configuration
bytes therefore remain unchanged as served requests advance the state head.
Every restart in this first-run profile needs operator reconciliation and a
fresh independently retained export plus root installation. A root compromise
of the host defeats this pin. A crash during a run leaves HELD authority
and requires operator recovery; an unknown signing handoff blocks restart.

Startup is ordered: unprivileged process checks and hardening; protected config
parse; required-member and cross-field checks; service identity; trusted time;
the static gate with that trusted sample and the exact config-byte digest;
safe ancestors; protected head read (a missing or unsafe file refuses
`j7_head_pin_unavailable` before state opens); state directory and exclusive
state lock; exact-head schema-5 Store and instance/identity/binding/epoch checks; active launcher and station
generation evidence; protected policy directory and an existing protected
table; key load last and derived public-key equality with the gate's expected
request key; adapter composition; socket-directory lock and listener publication;
then exactly one `j7-request control ready` status line. No initializer or
migration runs in the service. A missing table refuses readiness; an existing
empty authority table grants nothing. An absent static-gate implementation
refuses `static_gate_unavailable`, before state, secret or socket access.

The first-run method scope is lifecycle (`hello`, bind, end, rebind),
`j7_pubkey` and `consent_v3`. No node is configured. Node-backed operations
cannot succeed and refuse `delegation_evidence_unavailable` when their preceding
schema, run and grant checks are satisfied; existing earlier refusals remain
in force, including schema-5 `delegation_request_v3` refusal. The service
provides no legacy SSH, master or registration-helper endpoint.

Store or audit failure latches admission closed. Shutdown stops acceptance,
closes and drains connections, unlinks only its matching socket inode, closes
the key, policy and Store, then releases the state lock. Socket admission is
128 connections globally and 8 per peer UID; lifecycle has its existing eight
slots. Rate buckets are not implemented on this dedicated socket in the
single-launcher profile. The socket group contains exactly the holder service
UID and the dispatcher's launcher UID. The holder membership is required for unprivileged
socket group assignment; the launcher is the only non-holder member. Startup
refuses `j7_socket_group_unavailable` if the holder process lacks the configured
group. After creation, socket owner, group and mode 0660 are verified. Group
membership enumeration belongs to a required root-owned S8 pre-start hook:
on every unit start it verifies `binary_sha256`, `config_sha256` and that
`getent group` lists exactly the holder and launcher, refusing otherwise.
The service does not enumerate other accounts. That hook remains an external
prerequisite; the example unit names it without implementing it. Group
membership is admission; kernel peer
credentials are authentication: the launcher checks the holder credential and
Keymaker checks the launcher credential per request. Root-owned configuration,
distinct-UID launcher interoperability and native qualification remain PENDING.

The `delegation` variant retains its existing closed configuration (including
optional policy and inline expected-head pins) and refuses
`operation_unsupported` before state, clock, generation or socket access.
Request and delegation services must use different OS users,
independent roots/state/policy/runtime directories and control access. Neither
holds owner, seal, funding or fee keys. Different public bytes alone cannot
prove different custodians or exclusive control; those are deployment duties.

## Limits and verification

Loaded roots use the existing mmap/mlock and dump-exclusion approach; unavailable
locking is not a claim of swap protection. Secret buffers/scalars are erased
best effort and closed mappings are unmapped. Go and dependency temporaries may
retain copies; the library documents variable-time aspects. This provides no
hardware non-extraction, side-channel qualification or protection against the
holder, root, backup operator or compromised host. Existing process-hardening
and platform qualification duties remain; none are performed by a unit fixture.

There are no seed/private/chain-code accessors or agent import/export operations.
Custody diagnostics are redacted and serialization refuses. Tests cover public
crypto vectors, retries, entropy, exact binding/role selection and isolated
filesystem failures. The fixture checker adds no production authority. Production
run ownership, custody/node integration, child admission, installation and real
multi-user qualification remain separate work; unrelated witness,
persistent-revoke and purpose-6 gates are not reopened or prerequisites here.

## Protected lifecycle and operator policy

A lifecycle-only internal native adapter implements `j7_run_bind`,
`j7_run_end` and `j7_run_rebind`. It has no Master or signing dependency. The
request service composes this landed adapter subject to the startup gate
above. Isolated Unix fixtures are not installed integration or qualification;
the delegation role remains closed.
Legacy Native rejects these methods and all J7 signing/public-key methods.

The transport creates a private connection scope exactly once from the accepted
`net.Conn`. Every operation uses that scope through ID admission, handling and
actual response-write fencing. A UID map, caller label, process ID or request
handle cannot create a scope. Kernel credentials and current authoritative
account-generation evidence authenticate the exact configured launcher principal;
control-group membership supplies no launcher role. There is one upstream
connection per run, retained by the trusted launcher/broker, not given to an
agent. Input must use a distinct active OS principal from the launcher and
station identity, and cannot share a UID with another retained live run.

The service generates a 16-byte random run ID. The retained record contains the
exact station Binding, launcher/input principals, immutable origin, parent and
`live`/`ended` state. Bind arguments are exactly:

```text
{identity_registration_number, input_principal:{uid,generation},
 origin, parent_run}
```

For an initial run, `parent_run` is empty and `origin` is a complete object with
all six members `{kind,event_id,grant_id,tip_hash,mode,command_id}`. Admission
uses `kind:"admission"`, exact lowercase 64-hex event/grant/tip hashes,
`mode:"enforcing"` and an empty command ID. An authenticated owner command is a
different variant: `kind:"owner_command"`, exact 64-hex command ID, with the
other four strings empty. These are local retained references, not new wire
bytes for any signed object or proof that admission actually happened.

Spawn uses `origin:null` and names a retained live parent in `parent_run`.
The service inherits its complete origin; a supplied replacement origin refuses.
End/rebind accept exactly `{run_id}` and remain privileged launcher operations.
A currently configured launcher can end stale history after an explicitly
approved launcher-incarnation change; it cannot adopt that old launcher's run,
change its origin or rewrite its original principal.
Rebind requires a fresh, never-assigned connection and a live retained record
with the same launcher. It changes neither origin nor identity. No reconnect
or retained bind-result retry on another connection adopts a run. An unknown
lost bind response remains held for operator inspection/reconciliation of the
retained record; the launcher must not expose input before successful binding. End is durable
and idempotent, invalidates the former connection before subsequent effects,
and cannot be undone by retry/rebind. Self-end preserves only a one-use internal
permit for its exact committed acknowledgement, then closes the connection.
Admission, mutation and release recheck channel lifetime; this permit grants no
new mutation and cannot survive EOF or later generation/binding retirement.
A fresh launcher channel may recover the retained end result. EOF discards the volatile association;
restart reconstructs none. Input/launcher/station retirement and station binding
withdrawal cancel the run context and close the actual connection. A canceled
connection never gains another run.

The launcher is responsible for the real per-run input, descriptor/process
isolation, origin admission and teardown. A supplied input principal does not
prove these facts. Same-UID handle/FD theft or shared broker access is not solved
by SO_PEERCRED, CLOEXEC or a local unit test. Such a deployment remains refused
until its own isolation and lifecycle evidence is qualified. Per-run input
accounts are not duplicate purpose-1 registrations: the record refers to the
one existing station binding and preserves its uniqueness.

### Policy format and protection

The holder-owned unsigned table has exactly
`{format,instance,identity_registration_number,version,rows}` with
`format:"keymaker-j7-policy/1"`. Instance/identity equal the protected pins;
version is an integer 1 through 9007199254740991. Each row has exactly
`{origin,use,delegate,consent,deny}`, all arrays present even when empty.
The row key is `{kind,event_id,grant_id}`: an exact admission pair or the distinct
owner-command key with both IDs empty. Tip/mode/command remain in the immutable
run record rather than widening this row key.

Deny affects Use; Delegate remains a separate permission. The same parent may
be listed in Delegate and Deny without giving it Use authority.

Use/delegate/deny members are exact lowercase 64-hex IDs. Consent entries have
exactly `{contract_sha256,booking_sha256,privacy_sha256,and_use}`: three exact
64-hex hashes and a Boolean. Unknown, missing, null, duplicate or mis-cased
members, duplicate keys/rows/permissions/triples, use+deny conflicts,
noncanonical/unsafe numeric values and wrong pins refuse. No TTL or authority
normalization is added. Limits are inclusive: 1 MiB raw bytes, 4096 rows and
16384 aggregate permission entries. These simultaneous limits can make a full
row/permission-count bound unreachable for a particular serialized table.

The table is regular 0600, single-link, in a holder-owned 0700 directory.
Descriptor walking refuses symlinks, group/other-writable or foreign-owned
ancestors, and access/default ACLs. The table uses O_NOFOLLOW, O_CLOEXEC,
O_NONBLOCK, fstat owner/type/mode/link checks, ACL rejection and bounded reading.
A strict pathname constructor is separate from fixtures that explicitly supply
an already-open protected directory inode. Such fixtures do not qualify the
production path walk or a real untrusted UID.

Root-owned protected role configuration may additionally supply:

```text
j7_policy:{path,holder_uid,schema,instance,identity_registration_number,
           launcher_principal:{uid,generation}}
j7_state:{path,minimum_reader_schema,head_file}  // request
j7_state:{path,minimum_reader_schema,expected_version,expected_digest}  // delegation
```

Policy schema is exactly `keymaker-j7-policy/1`, holder matches service UID,
instance matches the role and identity is positive/safe. `minimum_reader_schema`
is `4` for schema-4 lifecycle state and `5` for schema-5 request-signing state.
It must match the explicitly migrated participant and its independently retained
exact version/body head; `4` does not admit schema 5, and startup never migrates
state or substitutes empty signing history. Expected version/digest pins are
nonempty safe-integer/64-hex values. Both paths are absolute and clean. These
objects are rejected by legacy config; request readiness requires both. The
request head is read from its protected file as specified above; delegation
keeps inline pins. Parsing pins does not open a
store, publish policy, enable a profile or establish protection.

### Publication, withdrawal and the common fence

A trusted holder-only Go publication boundary, with no native update RPC, shares
one cancellable gate and directory-inode flock with every reader. Independently
opened publisher/reader descriptors use this same protocol. The protected
policy directory itself must not be replaced, and raw edits outside the protocol
are unsupported. Candidate parsing occurs outside Store's terminal lock; a
bounded exact-byte reread under the gate rejects a stale parse.

Publication durably records the new floor, raw-byte digest, explicit lists and
denials with `publication_pending:true` before file effects. It exclusively
creates `.<filename>.next`, writes/syncs complete bytes, renames and syncs the
directory, then commits pending=false before the version is usable. Unknown
staging or any uncertain phase fences; nothing deletes intent to retry blindly.
A newly observed operator table is synced and its version/withdrawals committed
under the same gate before a reader can use it.

Same version/same bytes is idempotent; a lower version or same-version changed
bytes is unreadable and cannot lower the floor. Missing, unsafe, corrupt,
wrong-instance or unreadable policy and missing rows are empty authority, never
a cached allow table or owner-row fallback. Permission checks return exactly
`GRANT_NOT_FOR_RUN` or `CONSENT_NOT_FOR_RUN`, without row content. Bounded local
audit causes distinguish policy rollback, equivocation and unavailability.

Removing an explicitly listed use grant records a durable origin/grant denial.
The explicit deny set can withdraw a grant admitted through later enrollment
without first listing it. Only a newer explicit operator use lifts a denial;
enrollment cannot. Absence from an otherwise unchanged explicit use list is
not itself withdrawal of an enrolled grant. Consent removal stops future consent
and does not remove existing enrolled grants. These retained denial transitions
are implemented; PR2 creates no consent event, enrollment or fabricated grant.
The separate schema-5 extension below records exact signed consent/enrollment history.

Lock order is authoritative generation evidence -> policy publication gate ->
Store/J7 -> private custody -> audit journal. There is no reverse
Store-to-generation acquisition or node RPC under these final locks. The typed
adapter below derives origin from the connection capability and holds this same
publication gate through its final recheck and actual socket-write callback.
The lifecycle-only adapter continues to expose no signing method.

### State participant and explicit migration

Schema 4 has the required `j7` participant, `format:"keymaker-j7-state/1"`:
instance/identity, original base schema, accepted policy version/digest/table,
pending publication, immutable run history and origin/grant denials. Reader 3
remains reserved for the separate authority-root format. Legacy schema-0/2 bytes
remain unchanged until an explicit stopped-operator migration. Base schema 2
retains its complete message inventory, artifacts and recovery-copy accounting;
base schema 0 has no fabricated message inventory.

Migration requires an existing reconciled binding/audit pair, an active station
identity and an independently retained exact version/body head. Restart likewise
requires that exact operator expectation. A changed legitimate descendant needs
operator reconciliation of the new expected head; the service never writes its
own independent pin. Missing floor, participant, snapshot or journal is never
initialization evidence. Schema-0/2 readers refuse the new state before opening
an audit writer. Preview/clone/body/native-request capacity and message-recovery
paths preserve the participant.

State space and audit budget are reserved before durable effects. Commits cover
the complete versioned body through the existing journal-first binding commit;
an ordinary lifecycle audit line cannot substitute. Complete snapshot write,
file sync, rename and directory sync follow the journal commitment. Uncertain
state fences with `j7_state_fenced`; unavailable audit reports
`audit_unavailable`. Interrupted pending publication cannot serve even if its
new file survived. Recovery retains evidence and requires operator reconciliation;
there is no automatic reset, downgrade, repair or replay of unknown effects.

A matched rollback of all local files is detectable only relative to an
independently retained later expectation. Joint loss/restore of that expectation
is outside local detection. Lost consent/enrollment continuity cannot become an
empty enrolled set with restored authority. The schema-5 participant below retains consent continuity; real broker/host
exclusion remains an independent duty.

### Verification boundaries

Default tests exercise actual Unix connections/kernel launcher peers and injected
account-generation evidence; they do not establish distinct-UID broker input
isolation. `TestMultiUIDJ7PolicyProtection` is a concrete tagged PENDING gate for
real agent policy-write/replace denial plus full protected-path/holder controls.
It needs an operator-reviewed existing window, protected scratch root and
readable tagged binary; absent inputs are not a passing or skipped qualification.
Crash witnesses cover retained process interruption, not host power loss.
Run and denial histories have inclusive 65536-entry retention bounds; byte and
retained-request budgets can refuse earlier. Dense-history native latency at
production deadlines is unqualified. Capacity preflight and durable-state tests
do not establish that transport performance.

The pinned BIP-340 library also has an exceptionally rare fail-closed availability
edge when its challenge hash is at least the curve order. No feasible natural
reproduction is claimed, and this lifecycle slice changes no crypto. The fixed
32-byte message profile, honest-holder/root boundary, optional locking and
best-effort erasure limits above remain in force. Full integration review,
launcher ownership/isolation, independent native custody
qualification and deployment/enforcing acceptance remain outside these fixtures.

## Profile/1 typed request adapter (internal, unactivated)

Only the internal request-custody constructor opts into `j7_sign`, `j7_pubkey`
and `j7_enroll`. It uses the actual isolated purpose-7 key, trusted clock,
generation source, exact current binding and protected launcher connection.
Legacy Native and the lifecycle-only adapter refuse these methods before effects.
No caller run/origin/UID/key/purpose/path/kind/event-ID/hash/nonce selector exists.
Purpose 8, child-grant signing, v4, transport signing, raw digests and batches
remain unavailable. Both production role startups still refuse.

The existing control protocol, hello, canonical wrapper, 65536-byte frame,
request deadlines and slot budgets apply. Params are exact closed objects:

| Method | Required params |
| --- | --- |
| `j7_pubkey` | `{}` |
| `j7_sign` | `{operation,object_b64,evidence_b64}` |
| `j7_enroll` | `{object_b64,evidence_b64}` |

Encoded fields are canonical **unpadded base64url**, never paths or references
to files. Objects are strict JSON with every named member present, no nulls,
unknown members or duplicate names. `object_b64` decodes to at most 32768 bytes.
The evidence bundle is exactly
`{format:"keymaker-j7-evidence/1",issuance_txid}` (at most 1024 decoded bytes).
Consent's issuance locator is the empty string; grant operations require a
lowercase 32-byte transaction ID. This bundle supplies only an untrusted locator,
never an asserted live verdict or trusted policy.

### Complete objects and signing bytes

`consent_v3` accepts exactly `{contract_b64}`. The complete contract is the
fixed-order eleven-member `swarma-trust-contract/1` from LIP-0013 §§2.1–2.5,
limited to 8192 bytes, printable ASCII, ordered unique actions/repos, explicit
budget/window/note and the bound request public key. No hash-only consent or
placeholder grant is accepted. Booking is SHA256(contract bytes || ASCII
`booking`); privacy is SHA256(ASCII `swarma-trust-privacy-v1`). The exact triple
must be listed in the immutable origin's consent entry. No separate booking or
privacy document is invented. Consent can precede the grant and NotBefore.

Keymaker builds kind8181, empty content and four ordered tags:
`t=swarma-rental-consent-v1`, `contract`, `booking`, `privacy`.
`envelope_v3` accepts exactly
`{contract_b64,grant_b64,instruction_b64,transport,to,action,room,mxid,repo,amount}`.
The instruction contains 1–8192 complete octets. Transport is `matrix`, `to` is
the contract's executor name, room/mxid are bounded Matrix identifiers. The
complete canonical signed v3 grant must bind the exact contract, grantee,
counterparties, window, scope, budget and signed consent triple.

| Action | Additional exact constraints and final ordered tag |
| --- | --- |
| `instruct`, `review` | `repo=""`, `amount=0`; no ninth tag |
| `land` | repo in contract's allowed repos, `amount=0`; ninth tag `repo` |
| `spend` | `repo=""`, positive amount <= contract budget; ninth tag `amount` as unsigned canonical decimal |

The kind8185 draft has empty content and ordered tags
`t=swarma-instruction-v1`, `to`, `grant`, `action`, `body`, `room`, `mxid`,
`nonce`, followed only by the action's ninth tag. Body is SHA256(instruction
octets). Keymaker draws the 32-byte nonce and trusted creation time itself.
For both events the ID is standard NIP-01
SHA256(JSON `[0,pubkey,created_at,kind,tags,content]`), with compact JSON and no
HTML escaping. There is **no J7 prefix or tagged-author preimage**. BIP-340 signs
that 32-byte ID; the signature is exactly 128 lowercase hex characters.

Signed success is exactly
`{profile,signed_object_b64,object_id,public_key}`. The complete event retains
`id,pubkey,created_at,kind,tags,content,sig` order. Profiles are
`swarma-rental-consent-v1` and `swarma-instruction-v1/draft`. Pubkey returns only
`{profile:"j7-request-public/1",public_key}`. Enrollment returns `{grant_id}`.
Refusals contain neither signed result nor permission/content from another
origin. `delegation_evidence_unavailable` is a closed nonretryable refusal;
existing run/state/consent/grant/conflict codes retain their spellings.

### Validator and live-evidence authority

The public import is
`github.com/relux-works/swarma-chain-lab/experiments/rental`
`v0.5.1-0.20261114210947-e70a35a41dec`, commit
`e70a35a41dec5948d5452f1f898f4d26977372d7`. `ParseSignedGrant` checks canonical
complete signed-grant bytes, the issuer signature and kind8181 consent.
The concrete internal authority additionally runs **actual `rental.Check`**
against its trusted Node and Policy pins: names, issuer, network/genesis,
issuance commitment, W transaction graph/signatures, seal, closure and durable
history. Caller-supplied liveness or policy is never sufficient. Missing,
uncertain or non-LIVE evidence refuses before disclosure.

Node work runs outside final locks, including a fresh repeated observation
before release. The final barrier rechecks run/generation/binding, policy,
durable denial and trusted time, with at most two seconds of local observation
age. That bound does not independently qualify node/header freshness, host time
or deployment. Chain observation is not atomic with a subsequent chain effect;
receivers must independently admit the complete grant and message. No production
node constructor is wired here.

Contract/8185 codecs follow the supplied LIP and independently checked public
`tools/trustcheck` source at link-spec commit
`45054797ee9ad3e38213e067051dfbd3eb2a21a1`. That tool is package main, not an
importable library. Own generic positive/negative
[`signing vectors`](../vectors/j7/signing.json) carry complete consent/grant and
all four draft envelope actions. Their synthetic grant has no issuance proof.
They prove offline bytes/signatures, **not external kind8185 interoperability**.

### Enrollment, retries and release continuity

Enrollment accepts exactly `{contract_b64,grant_b64}` plus the evidence bundle.
It never signs, edits policy or lifts a deny. The full validated grant must
contain the **exact event actually released** under this origin, identity,
consent entry/triple and `and_use`. Durable-but-unreleased consent does not count.
A current matching and-use entry is required for new enrollment. Removing consent
stops new consent and new enrollment, but does not revoke already enrolled use.
Standing and-use can admit a genuinely new consent/grant after an old grant was
withdrawn. Durable origin/grant denial wins until a newer explicit operator use.

The new outer schema is **5**, with required separate
`j7_signing:{format:"keymaker-j7-signing-state/1",records,enrollments}`.
Schema4 and its closed `keymaker-j7-state/1` participant are unchanged; schema 5
preserves that participant and every prior binding, native result, message
artifact and recovery commitment. Only an explicit stopped-operator **4->5**
migration with an independently retained exact version/body digest is admitted.
No startup/RPC migration or missing-means-empty history exists. Old readers
refuse schema 5 without authoritative writes. Schema3 remains separately reserved.

Each signing/public-key/enrollment record binds kernel peer/requestID, exact
protected run/binding/origin, canonical params/evidence and exact result digest.
Consent adds its complete event and entry/triple/and-use association. Enrollment
links exact released consent event/result hashes. Records, associations, results
and release states participate in the committed body and capacity accounting.
Changed input or run conflicts; exact retries recheck current authority and then
reuse original time/nonce/signature bytes. A prior signature never authorizes
retained-result disclosure after withdrawal.

Release states are `prepared` -> `handoff_unknown` -> `released`. The first
commit retains the exact signature. Unknown is durable **before** the actual
socket callback, including retries. Current generation/policy/Store/custody
barriers remain held through that callback. Released becomes durable only after
its success and a following commit. Enrollment is installed on that same gate;
withdrawal ordered first suppresses its effect and disclosure. Zero/partial
writes, a full write followed by failed final commit and process interruption
leave unknown/fenced continuity. They never become enrollment evidence or an
automatic retry. This deliberately trades availability for conservative safety.

Restart needs the independently reconciled exact current head and refuses
unknown handoff, lost/corrupt histories or an unmatched journal/snapshot. There
is no implemented unknown-handoff reconciliation endpoint: preserve all exact
records, socket-handoff evidence, policy versions and independent head for a
separately authorized stopped-operator decision. Never delete/reset unknown or
reinitialize to recover availability. Full-suite independent review, P17 concrete
Curator launcher/a2a Source hooks, distinct-UID/ambient-credential isolation,
real node/time/custody, crash/restore/exclusion and enforcing deployment remain
PENDING. Unit graph/Unix fixtures and compile-only evidence close none of them.

The plan's S7 rows retain the following precise limits; none is a production
qualification passed by these fixtures:

| Row | Source evidence and remaining boundary |
| --- | --- |
| S7-1 | Same-key cross-origin endpoint denial and valid owner/origin controls; real separate-run custody remains PENDING. |
| S7-2 | Schema5 stays closed to profile/2. Explicit schema 6 adds only the typed v3 request/root-consent prerequisite below; child/v4 and native delegation remain closed. |
| S7-3 | Caller selectors and borrowed channel/run IDs refuse in real Unix fixtures; stolen/inherited descriptor and actual broker isolation qualification is PENDING. |
| S7-4 | True first consent, full externally signed fixture grant, exact released-consent enrollment and envelope pass the actual adopted verifier; production issuer/node qualification is PENDING. |
| S7-5 | Retained full origin is immutable across spawn/rebind in lifecycle tests; concrete admission-source integration is PENDING. |
| S7-6 | EOF/rebind and connection/run checks are exercised with real launcher sockets and fixture generations; isolated launcher-created per-run channels are PENDING. |
| S7-7 | Exact-head restart, retained denial and required trusted rebind have source tests; independent restore/exclusion and deployed restart qualification are PENDING. |
| S7-8 | Independent offline byte/receiver checks do not prove ambient Git-token or wallet-RPC exclusion; actual ambient-credential and receiver deployment qualification is PENDING. |
| S7-9 | Policy publication serializes with first/retry/enrollment and actual response-write state; real distinct-UID withdrawal and crash/power-loss qualification are PENDING. |

### Profile/2 v3 request side and schema 6

The exact target is Draft LIP-0014 at link-spec
`d0b2dcc6465fc856e334ddeef7a22f3e1dceb81b`, sections 2–5 and adopted J1/J3.
There is one fifteen-member profile and one six-member delegate object. Old
seven-member delegate forms, bare notary names and future optional-notary or
recipient-class forms are not accepted. Pending J2/J4/J5 rules do not silently
change the active v3 rules. No equality rule for scope-text hashes is added.

Only the trusted Store's explicit **schema 6** enables the new request variant.
The native method remains `j7_sign`, with exact
`{operation:"delegation_request_v3",object_b64,evidence_b64}`. Decoded object is
exactly `{parent_contract_b64,parent_grant_b64,child_contract_b64}`: both COMPLETE
contracts at most 8192 bytes each and COMPLETE canonical signed parent at most
16384 bytes. The combined decoded object remains bounded by 32768 bytes; evidence
by 1024, event result by 16384 and native frame by 65536. Individual maxima are
ceilings and need not fit together under the aggregate cap. Canonical unpadded
base64url is required at every layer. No chunking, batch, asserted LIVE, supplied
hash/event/kind/key/origin/run/time/nonce or caller-selected reader floor exists.

The evidence is the existing complete `keymaker-j7-evidence/1` bundle with its
issuance transaction locator. Its locator confers no authority. The holder runs
actual pinned `rental.Check` on the complete signed parent and trusted own-node
policy before preparation and again before first or retained-result disclosure.
Contract hashes, full consent, derived scope/budget, subject and row fit are
computed locally. Genesis is pinned by the signed parent/network, not a new
contract field. Parent ID/depth precede live-parent observation; remaining
subject/ordinal/row/actions/repos/budget/window comparisons follow it. The
ordinal is bounds-checked before indexing. D12 forbids delegated spend, with
zero delegate budget/caps; counterfactual spend vectors never lift that rule.

The exact current origin's **Delegate** list must explicitly contain the actual
parent grant ID. Use and consent/enrollment `and_use` do not grant delegation.
Use denials remain use/enrollment denials; withdrawing Use leaves a separately
listed Delegate permission intact. Removing Delegate blocks first and retried
release even if Use remains. Policy rollback/equivocation/unavailability cannot
restore authority. There is no requester-side ordinal reservation or issuance
accounting: the landlord independently owns unused ordinal/nonce admission and
its durable reservation before it signs the child.

Purpose7 must equal **P.grantee_key**, not the child's recipient. Keymaker builds
kind 8186 with empty content and exactly five ordered two-string tags:
`t=swarma-delegation-request-v1`, `parent=P.ID()`, `contract=SHA256(child bytes)`,
`ordinal` as canonical decimal and `nonce` as 32 fresh random bytes/64 lowercase hex.
Creation time is inside P's window; a nested child may start in the future.
The exact construction timestamp is checked before secret signing and durable
preparation. Before every first or retry callback, the retained event's own
window is checked again, even if the clock has stepped backwards into the
window. Invalid retained bytes are preserved and fenced, never silently repaired
or disclosed. Consent may precede its contract start but must precede its end;
parent-bound envelope and delegation events require both bounds.
Standard NIP01 preimage and BIP340 apply without any new signed domain. The
four-field signed result uses the descriptive local profile
`swarma-delegation-request-v1/draft`, outside signed bytes. Kind8186 remains Draft,
not an external allocation or interoperability claim.

A narrowly bounded prerequisite allows schema 6 `consent_v3` for a canonical /2
ROOT only: empty parent,ordinal 0,delegate.depth 1. It uses the same complete
contract input, consent triple, current-origin entry, bound purpose7 key and
durable exact-event release. A canonical /2 child or nondelegable root stays
unsupported for this consent variant. After actual consent release the issuer
creates the full parent; only a later explicit operator Delegate listing admits
a request. Profile/2 `j7_enroll` and `envelope_v3` stay unavailable. Existing /1
routes and schema 5 parser/event wrappers retain their behavior.

Schema 6 preserves all required schema 5 participant fields/formats and every
retained signing/result/enrollment/run/origin/policy/denial, base0/2 binding,
message and recovery participant. Only a stopped explicit **5->6** migration
under the lifetime lock and independently retained exact version/body digest is
admitted. No startup/RPC upgrade, downgrade, missing-file bootstrap or mutable
service-owned floor is added. Actual unchanged reader 5 accepts its old state and
rejects even empty schema 6; it cannot drop unknown history and write authority.
Schema3 PC2 remains separate. Whole-store rollback detection still depends on
independent history and exclusion of old/restored serving instances.

The existing `prepared -> handoff_unknown -> released` transaction and final
**generation -> policy -> Store -> custody -> audit -> actual socket callback**
barriers apply. No RPC runs under those terminal locks. Unknown is committed
before every callback, including exact retries, and final durability follows the
write. Withdrawal may leave a private prepared signature but releases no success
bytes. A terminal fence refusal ends that connection; recovery requires a fresh
trusted launcher rebind. Retries retain exact nonce/time/signature and recheck
current authority. Concurrent runs sharing an ID retain at most one result;
imported verifier-journal contention may refuse evidence before the other run
reaches request_conflict. This is not a promise of one immediate successful
transport response. After contention, other-run or changed-body reuse conflicts.

The new operation exposes the frozen `CONTRACT_*`, `DELEGATE_NO_NOTARY`,
parent/depth/subject and `CHILD_*` codes in their ordered rules. Parent binding
uses `CONTRACT_HASH`, `CONTRACT_MISMATCH`, `SCOPE_MISMATCH`, `BUDGET_MISMATCH`,
`CONSENT_TAGS`. Existing malformed signed-parent and transport inputs remain
`request_malformed`; unavailable/unproved/non-LIVE own-node authority remains
`delegation_evidence_unavailable`, not a free-form dependency diagnostic. These
semantic/authority refusals are nonretryable. Historical /1 route errors do not
change. Retained-event integrity is not fresh live authority.

The exact 151+39 public contract/pair corpus and original /1 reference sources
remain privately hash-bound; no /2 checker was published at that pin. New
[generic complete fixtures](../vectors/j7/delegation-README.md) have different
bytes and use a separate test-only byte-grammar reference reader. They do not
prove J3 notary-name history, issuer J3.9 compliance, child attestation admission,
landlord reservation, native isolation or external interoperability. At child
admission, J3 checkpoint/name-history/writer checks precede attestation-key
comparison; this request endpoint has no child attestation and does not implement
that separate verifier. Purpose8 supplies nothing on v3. Child/v4 wire inputs,
own-node closures, P17, production origins, ambient credential exclusion,
distinct-UID and enforcing/native qualification stay separate gates.
