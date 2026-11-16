# Message-author value codec

**Fixture-only, not live.** Import
`github.com/relux-works/swarma-keymaker/messageauthor` for byte conversion only.
It supplies no transport, signing, current certificate, identity lookup, secret
constructor or authority provider. Both constants name unregistered methods.
The [source contract](https://github.com/relux-works/swarma-keymaker/blob/main/spec/keymaker-message-author.md) pins exact upstream
BIP-340 semantics and separate live prerequisites.

## Module and version pin

This is an independently consumable nested Go module:
`github.com/relux-works/swarma-keymaker/messageauthor`, with a **Go 1.26.8**
minimum and no toolchain directive. The root service keeps its Go 1.26.10 floor.
The module requires only the existing pinned envelope module and its transitive
requirements; it does not depend on the root service module.

After a reviewed commit is published, set `REVIEWED_COMMIT` to its full commit
ID and pin it:

```sh
go get github.com/relux-works/swarma-keymaker/messageauthor@"$REVIEWED_COMMIT"
```

Go records the nested module's pseudo-version, for example
`v0.0.0-YYYYMMDDhhmmss-abcdefabcdef`, in the consumer's `go.mod`. Retain that exact
version and its `go.sum` entries. A local root `replace` is development wiring,
not a consumer version or a live-service qualification.

## Requests and frames

After externally owned native version1 hello, one outstanding request per
connection. A frame is BE32 body length followed by exactly one canonical CCJ-1
object; length1..65536, depth<=16, no trailing bytes. `FrameLength([4]byte)` checks
the header before the caller allocates a body. The codec cannot prevent the
caller's own allocations.

```text
{method,params,request_id,timeout_ms}
message_author_identity: params exactly {}
sign_message_author:     params exactly {preimage:base64url_no_pad(P)}
```

ID is32 lowercase hex characters; timeout1..2000ms. Decoded preimage<=24576
bytes, encoded<=32768 characters checked before base64 decode. P may be empty or
provider-invalid here: wire decoding is not signing admission. Identity requests
have no preimage. No selectors for key, algorithm, profile, purpose, digest,
path, UID, generation, owner, attestation or run; no import/export/list method.

```go
request := messageauthor.Request{
    ID: "0123456789abcdef0123456789abcdef",
    TimeoutMS: 2000, Method: messageauthor.IdentityMethod,
}
frame, err := messageauthor.EncodeRequestFrame(request)
```

`DecodeRequestFrame(frame)` returns detached values. `Preimage []byte` is sign
only; the encoder rejects an over-cap slice before base64 copying. Input P is
not normalized or rewritten. The holder, separately, must apply upstream exact
opaque-byte/three-protected-path admission before any signing.

## Responses and correlation

`EncodeResponseFrame(expected Request,response Response)` and
`DecodeResponseFrame(expected Request,frame []byte)` require the caller's
**own outstanding request**, never context inferred from a received reply.

```text
identity: {request_id:ID,result:{key_id:K,author_attestation:T,attestation:base64url(A)}}
sign:     {request_id:ID,result:{key_id:K,signature:base64url(S)}}
refusal:  {request_id:ID_or_null,error:{code:CODE,retryable:BOOL}}
```

Exactly one method-appropriate alternative, no extra members. Every nonnull ID
must equal expected.ID; success cannot have null ID. In Go, `Response` has
`Identity *IdentityResult`, `Signature *SignatureResult`, `Refusal *Refusal`.
Identity contains `KeyID`, `AuthorAttestation`, `Attestation []byte`; signature
contains `KeyID`, `Signature []byte`. `K` is canonical `bip340:` + strict
x-only32/lift_x; `T` is lowercase `sha256:` +64 hex; A is nonempty<=8192 raw bytes
encoded canonically; S is64 raw bytes. Neither A's parsed provenance/currentness
nor S's mathematical validity is established by this codec. No result includes a
root, private key, derivation path or fleet roster. Decoded slices are detached.

A decoded refusal can accompany a nil local Go error: inspect `Refusal` before
using any result. Empty Go ID represents wire null on refusals only, and remains
uncorrelated. Retryable does not mean no durable signing result exists.

Codec-local error vocabulary is closed; these names do not register control
server codes:

| Retryable | Exact codes |
| --- | --- |
| true | busy, rate_limited, generation_source_unavailable, audit_unavailable, request_deadline_exceeded |
| false | frame_too_large, frame_truncated, frame_malformed, ccj_noncanonical, request_malformed, request_conflict, version_unsupported, hello_required, hello_already_negotiated, operation_unsupported, peer_identity_unavailable, generation_source_fenced, generation_inactive, generation_mismatch, binding_not_found, peer_binding_mismatch, binding_conflict, identity_revoked, role_not_permitted, custody_unavailable, entropy_unavailable, clock_untrusted, key_not_enrolled, key_not_valid_now, sign_key_mismatch, state_capacity_exceeded, signer_preimage_too_large, signer_tag_malformed, signer_domain_refused, signer_payload_invalid, signer_identity_unavailable, signer_identity_malformed, signer_identity_mismatch, message_author_unqualified |

The first four false codes require null response ID. Unknown codes, wrong retry
bits, response variants or correlations produce local `ErrResponse`. Local
framing errors are `ErrFrameTooLarge`, `ErrFrameMalformed`, `ErrFrameTruncated`,
`ErrTrailingData`; canonical failures `ErrCanonical`; request schema failures
`ErrRequest`. Encoders fail with nil bytes, decoders with zero result, never a
partial alternative alongside an error. Local errors expose no received bytes.

## Consumer flow and limits

Authenticate the real holder/own principal before discovery. Verify A under the
approved per-host purpose5 pin and expected public binding, compare its exact
content ID to T and its BIP-340 subject to K. Actual currentness requires the
separate live coordinator; a codec roundtrip does not supply it.

M2 constructs exact original P and keeps the outstanding request, verifies
returned K equals its verified own K and S verifies SHA256(P) exactly once,
then assembles E once. Publish/retry identical E bytes. After message expiry
(<=120s), use new nonce/iat/exp/native ID. After T renewal, construct new P/ID;
never substitute a new certificate under an old signature. The receiver owns
role/type/version/action/delivery and sender-carried certificate authority.
There is no fleet export; carrier registration-to-sender projections are owned
outside this module. Root provisioning, GEN, retained results, audit, final-write
barriers, restart/ack-loss and real-key/native qualification remain separate.

## Tools and fixtures

Use Go 1.26.8 and isolated absolute HOME/TMPDIR/Go caches. From this
nested module directory:

```sh
go mod tidy -diff
go vet ./...
go test -count=1 ./...
```

From the repository root with Go 1.26.10, the module import-path pattern crosses
the nested-module boundary (the relative `./messageauthor/...` pattern does not):

```sh
go test -count=1 github.com/relux-works/swarma-keymaker/messageauthor/... ./internal/control/... ./internal/messageauthorcompat
```

`internal/frame` copies only the daemon's canonical value codec, without its
transport or server. Root-side equality tests execute the actual private copy
through a test-only subprocess probe, comparing exact canonical bytes, refusal
text and boundary verdicts against `internal/control`. Both sides also retain
independent negative/positive property tests. The root CI job runs the equality
test; a separate CI job vets and tests this module with Go 1.26.8.

`testdata/wire-v1` retains the literal request/reply verdicts and SHA256 manifest
unchanged. The root's `internal/keymaker/testdata/message-author-v1` keeps its
explicitly public fixture roots, signed bytes and historical /1 context. The
independent stdlib public-math oracle comes from exact envelope065 and is for
public verification only. All checks remain **fixture-only, not live** and activate no
service or native qualification.
