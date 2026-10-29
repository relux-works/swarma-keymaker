# Station-caller wire codec

Import `github.com/relux-works/swarma-keymaker/stationcaller`.

This package encodes and decodes the two proposed native methods in
[station-caller §§1–3](../spec/keymaker-station-caller.md). It supplies pure
byte/typed-value conversion after the caller's externally owned base hello
negotiation. Production method/error allowlists and purpose allocation are
unchanged. [Qualification and activation remain closed](../spec/keymaker-station-caller.md#5-disabled-until-qualified).

## API

```go
request := stationcaller.Request{
    ID: "0123456789abcdef0123456789abcdef",
    TimeoutMS: 2000,
    Method: stationcaller.SignMethod,
    Profile: stationcaller.DispatcherRequest,
    PlanID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}
frame, err := stationcaller.EncodeRequestFrame(request)
```

`frame` includes the four-byte big-endian length. `DecodeRequestFrame(frame)`
returns the same typed request. `PubkeyMethod` requires empty `Profile` and
`PlanID`, producing exactly empty params. `SignMethod` requires either
`DispatcherRequest` or `CallerDelegation` and the exact lowercase plan ID.
Neither request accepts an identity, path, generation, epoch, body or extension map.

`EncodeResponseFrame(method, response)` and `DecodeResponseFrame(method, frame)`
use the outstanding request's method because the wire response contains none.
`Response` has exactly one alternative:

- `PublicKey *PublicKeyResult`: `Key`, `Path`, `RegistrationNumber`, `Epoch`.
- `Signature *SignatureResult`: `Key`, `Signature`.
- `Refusal *Refusal`: exact `Code` and `Retryable`.

An empty response `ID` means wire null, on refusals only. Framing/canonical-byte
refusals require null; otherwise the transport must echo a valid ID it parsed.
The caller must correlate every nonnull ID with its outstanding request and
reject an unexpected/missing correlation before using a result. A successfully
decoded `Refusal` has a nil Go error; a local codec error returns the zero
response and never a partial success. Local `ErrFrameTooLarge`,
`ErrFrameMalformed`, `ErrFrameTruncated`, `ErrTrailingData`, `ErrCanonical`,
`ErrRequest` and `ErrResponse` are error sentinels, not wire responses.

## Exact accepted values

The shared native CCJ-1 implementation enforces UTF-8, canonical scalar/escape
spelling, safe integer types, sorted unique members, container depth16 and the
65536-byte body cap. Each decoder takes exactly one complete frame and refuses
truncated or trailing bytes. Unknown/missing/duplicate members and unrelated
methods/results are rejected. Each failed encoder returns nil bytes.

Native request IDs are32 lowercase hex digits; timeout is an integer1–2000ms.
Keys are `ed25519:` plus canonical unpadded base64url of32 raw public bytes;
signatures are canonical unpadded base64url of64 raw bytes. Parsing does not
verify an Ed25519 point, signature, origin or authority.

The returned path is exactly `m/6'/product'/project'/agent'`, with canonical
decimal hardened components. Name indices are1–2147483647: base §4.2 reserves
zero in the registry, so it cannot be a resolved sibling name index. This
validation does not allocate or consult that registry. Registration numbers
retain the published positive safe integer range1–9007199254740991; the codec
does not impose the current Store allocator's stricter remaining capacity.
Epoch is an opaque nonempty UTF-8 string, bounded by the whole frame. No UUID,
ASCII-only syntax, normalization or separate short epoch limit is published
by the binding owner, so none is added. Canonically escaped controls and
distinct NFC/NFD spellings remain distinct accepted string values.

Refusals use the base closed native vocabulary and published base proposal
codes, plus the supplement's three full names: `station_caller_unqualified`,
`station_caller_plan_unavailable`, `station_caller_plan_invalid`. Those three
are nonretryable. Base retryability remains true only for `rate_limited`,
`busy`, `generation_source_unavailable`, `enrollment_unavailable`,
`audit_unavailable` and `request_deadline_exceeded`. Incorrect retryability
or foreign/free-form codes are rejected. This is a codec-local vocabulary;
it does not register those values with a production server.

## Remaining responsibilities and checks

Transport, hello negotiation, peer authentication, ID correlation, active
generation/binding, protected typed-plan installation/lookup/full-body schema,
association/currentness, signing custody, replay/audit/durable outcomes and
all native qualification remain external responsibilities. A plan digest is
not a plan validator, and these bytes provide no usable signer or effect permit.
This package builds no hash/preimage, opens no socket and accesses no keys.

Run `go test ./stationcaller -count=1` and `go build ./stationcaller` from the
repository root. Tests use inert public byte fixtures and cover exact wire
values, paired grammar/boundary refusals and zero-value failure behavior.
