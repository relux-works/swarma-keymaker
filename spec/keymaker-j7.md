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
