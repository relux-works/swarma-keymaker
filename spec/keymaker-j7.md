# Request and child-delegation key custody

Status: internal cryptographic custody and role configuration only. No new
native/SSH method, service, run admission, signing profile or activation.

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
The internal capability is not caller/run authentication: future admission must
hold its independently validated generation/run barrier through actual release.

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
objects and locally recomputed domains remain mandatory for future signers;
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
The two new variants require exactly:

```text
{service_role, j7_key_file, instance_id, service_uid, service_gid,
 master_epoch, registry_revision}
```

`service_role` is exactly `j7-request` or `delegation`; `j7_key_file` is an
absolute clean path; instance follows the rule above; epoch/registry pins are
nonempty strings; service IDs keep uint32 semantics. No legacy master, registry,
helper, socket or generation-config members are accepted in those variants.
The loaded record fixes role/instance, and the capability fixes epoch/revision.

**Both new runtime profiles currently refuse `operation_unsupported` before
legacy master/state, clock/generation readiness or socket initialization.**
Configuration support does not create a fake delegation service or silently
enable SSH/legacy sign routes. No startup path calls the new root loader or
initializer. Future request and delegation services must use different OS users,
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
filesystem failures. The fixture checker adds no production authority. Native
run binding, typed profiles/consent, durable J7 state, child admission, packaging
and real multi-user qualification remain separate work; unrelated witness,
persistent-revoke and purpose-6 gates are not reopened or prerequisites here.

## Protected lifecycle and operator policy

A lifecycle-only internal native adapter implements `j7_run_bind`,
`j7_run_end` and `j7_run_rebind`. It has no Master or signing dependency. The
normal daemon still refuses both new profiles: this adapter is exercised with
isolated Unix fixtures and is not installed broker integration or qualification.
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
and cannot be undone by retry/rebind. EOF discards the volatile association;
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
j7_state:{path,minimum_reader_schema,expected_version,expected_digest}
```

Policy schema is exactly `keymaker-j7-policy/1`, holder matches service UID,
instance matches the role, identity is positive/safe, reader minimum is 4, and
the expected version/head are nonempty safe/64-hex pins. Both paths are absolute
and clean. These optional objects are rejected by legacy config. Parsing pins
does not open a store, publish policy, enable a profile or establish protection.

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
Exact signed consent/enrollment history requires a later versioned extension.

Lock order is authoritative generation evidence -> policy publication gate ->
Store/J7 -> private custody (unused here) -> audit journal. There is no
Store-to-generation acquisition or node RPC. A future typed signing/release path
must derive origin from the connection capability and hold this same publication
gate through its final recheck and actual socket-write callback. PR2 supplies
no signature release and claims no such acceptance.

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
empty enrolled set with restored authority. The future consent participant and
real broker/host exclusion remain separate duties, without waiting for an
unrelated witness feature.

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
launcher ownership/isolation, typed consent/signing, independent native custody
qualification and deployment/enforcing acceptance remain outside these fixtures.
