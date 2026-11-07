---
name: swarma-keymaker
description: Use Swarma Keymaker's stationcaller Go wire codec and explain its Linux custody, generation-journal readiness and enrollment refusals. Use for this module's interfaces and qualification limits, not general SSH key management or service activation.
---

# Swarma Keymaker

Choose the implemented surface before giving commands:

- For station-caller byte conversion, use the public `github.com/relux-works/swarma-keymaker/stationcaller` package below. It supplies no transport or signer.
- For daemon configuration, generation incidents, enrollment reconciliation or persistent-revoke refusals, read [runtime boundaries](references/runtime-boundaries.md). These are internal/operator surfaces, not public import paths or agent enrollment steps.

Start with the [module README](../../../README.md) and [contract](../../../spec/keymaker.md). The module pins Go 1.26.10 and exact dependencies in [go.mod](../../../go.mod) and [go.sum](../../../go.sum); use those pins. Some older integration notes describe the pre-journal gate or deferred helper: check [current production wiring](../../../internal/keymaker/runtime_linux.go) before repeating those status claims.

## Public station-caller codec

Read the [package contract](../../../stationcaller/README.md) and [exported implementation](../../../stationcaller/codec.go). After externally owned base hello negotiation, `EncodeRequestFrame` / `DecodeRequestFrame` convert one typed request to/from a four-byte-length-prefixed CCJ-1 frame. For example, the inert [public example](../../../stationcaller/example_test.go) uses:

```go
request := stationcaller.Request{
    ID: "0123456789abcdef0123456789abcdef", TimeoutMS: 2000,
    Method: stationcaller.SignMethod, Profile: stationcaller.DispatcherRequest,
    PlanID: "sha256:" + strings.Repeat("a", 64),
}
frame, err := stationcaller.EncodeRequestFrame(request)
```

The example imports `strings` and `stationcaller`, checks errors and round-trips the frame; its output is `sign_station_caller (2000 ms)`. It performs no signing. IDs are exactly 32 lowercase hex digits; timeout is 1–2000 ms. `SignMethod` accepts only `DispatcherRequest` or `CallerDelegation` with a lowercase `sha256:` plan ID. `PubkeyMethod` requires empty profile/plan fields. No request accepts caller-selected identity, path, generation or body. A zero timeout refuses with `ErrRequest` and nil bytes; see the paired [schema/boundary cases](../../../stationcaller/codec_test.go).

`EncodeResponseFrame(method, response)` / `DecodeResponseFrame(method, frame)` need the outstanding request's method. A response has exactly one of `PublicKey`, `Signature` or `Refusal`. A decoded refusal can have a nil Go error: inspect `Refusal` before using a result. Correlate every nonnull response ID; an empty ID represents wire null on refusals only. Local decode errors return the zero response. Parsing a key/signature does not verify it or establish origin, authority, binding, plan validity or effect outcome.

Run from the repository root with Linux, the pinned Go toolchain and exact public dependencies already available:

```sh
go test ./stationcaller -count=1
go build ./stationcaller
```

These commands exercise inert byte fixtures and write build/test cache, not a daemon binary or service state. Use private absolute HOME, TMPDIR and Go caches for offline checks; keep the source read-only and exclude host keys and sockets. The [package tests](../../../stationcaller/codec_test.go) cover valid frames beside malformed/schema/boundary refusals; they do not qualify native execution.

Purpose 6 and both native station-caller methods remain disabled until the [published qualification gates](../../../spec/keymaker-station-caller.md#5-disabled-until-qualified) close. Codec constants and accepted refusal names do not register a production method. Do not replace the missing signer with readable keys, interim Git signing or arbitrary-byte signing; [the module's open decisions](../../../UNRESOLVED_QUESTIONS.md#station-caller-purpose-proposal) retain these boundaries.
