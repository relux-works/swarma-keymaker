# Message-author value codec

**Fixture-only, not live.** Import
`github.com/relux-works/swarma-keymaker/messageauthor` for byte conversion only.
It supplies no transport, signing, current certificate, identity lookup, secret
constructor or authority provider. Both constants name unregistered methods.
The [source contract](../spec/keymaker-message-author.md) pins exact upstream
BIP-340 semantics and separate live prerequisites.

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

Use the module-pinned Go toolchain and exact offline dependencies in private
HOME/TMPDIR/Go caches. From the module root:

```sh
go test -p=1 ./messageauthor -count=1
go test -p=1 -parallel=2 ./internal/keymaker -run '^TestMessageAuthor' -count=1
go build -p=1 ./messageauthor ./internal/keymaker
go vet -p=1 ./messageauthor ./internal/keymaker ./tools/mutations
go run ./tools/mutations -group message-author -scratch <private-directory>
```

`testdata/wire-v1` contains literal request/reply verdicts with a SHA256 manifest;
`internal/keymaker/testdata/message-author-v1` contains explicitly public fixture
roots, signed bytes and historical /1 receiver context. The independent stdlib
public-math oracle comes from exact envelope065; no secret math uses it.
The mutation tool stores overlays/logs/real child exit receipts in a new
`mutation-*` directory under the supplied private scratch. Go caches hold build
outputs; none of these commands activates a service or qualifies live traffic.
