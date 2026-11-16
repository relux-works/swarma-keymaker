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
