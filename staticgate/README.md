# Static gate verifier

Import `github.com/relux-works/swarma-keymaker/staticgate`.

This package applies the consumer rule of
[`swarma-s7 static-gate/1`](../spec/keymaker-static-gate.md) to one signed
statement. It is a pure function: it holds no signer and no private key, opens
no file or socket, reads no clock and hashes no binary. The caller supplies
every input. Nothing in this repository calls it yet; publishing it enables no
daemon mode, method or purpose.

## API

```go
statement, err := staticgate.Verify(raw, sig, staticgate.Inputs{
    ApproverKey:     pinnedKey,     // [32]byte, from the protected install
    StatementDigest: pinnedDigest,  // [32]byte, from the protected install
    MachineIDSHA256: machineDigest, // SHA-256 of the machine-id file content
    Now:             now,           // the host clock
    Class:           staticgate.ClassStart,
    Consumer:        staticgate.Keymaker,
    Section:         expectedSection,     // canonical bytes from protected config
})
```

- `raw` is the exact statement bytes, with no final LF.
- `sig` is the wire signature: exactly 128 lowercase hex characters. Raw 64
  bytes, uppercase hex and a trailing LF refuse.
- `Class` is `ClassStart` (bind, sign, dispatch, lease) or `ClassEnd` (run end,
  sweep, lease release, owned-run cancel). `ClassEnd` skips only comparing
  `Now` with the window bounds; a zero `Now` refuses for every class.
- `Consumer` is `Keymaker`, `Dispatcher`, `Source`, `BrokerTime` or `BrokerD5`.
  `Association` is required only for `Dispatcher`, and is compared for any
  consumer whenever `len(Association) > 0`. Keymaker needs no association
  input unless it chooses to compare one; omitted and empty are equivalent.
- `Digest(raw)` returns `SHA-256(tag || 0x0a || raw)`, the value that is signed
  and the value an installer pins. A consumer must pin the digest it was
  given, not recompute it from the statement it is about to check.

On success `Statement` carries `GateID`, the two labels, the window, the
digest, the consumer and the class, for audit only. On refusal it is the zero
value and the error is an `*Error`:

| Step | Check | Code | Sentinel |
| --- | --- | --- | --- |
| 1 | raw preimage digest equals the pinned digest, before any parse | `STATIC_GATE_PIN` | `ErrPin` |
| 1 | bounded parse: size, decoder rules, object | `STATIC_GATE_FORM` | `ErrForm` |
| 1 | `approver.key` equals the pinned key | `STATIC_GATE_KEY` | `ErrKey` |
| 2 | canonical bytes, depth, closed members, exact values, shapes | `STATIC_GATE_FORM` | `ErrForm` |
| 3 | BIP-340 signature under the pinned key | `STATIC_GATE_SIGNATURE` | `ErrSignature` |
| 4 | machine-id digest | `STATIC_GATE_HOST` | `ErrHost` |
| 5 | class, window width, non-zero `Now`, and for `start` the window-bound comparison | `STATIC_GATE_WINDOW` | `ErrWindow` |
| 6 | own section and association bytes | `STATIC_GATE_SCOPE_MISMATCH` | `ErrScopeMismatch` |

Match with `errors.Is(err, staticgate.ErrWindow)` or read `Error.Code`. The
text after the code names the failed check for an operator and is not a
contract.

## What it does not do

- It does not interpret a section. Sections are compared as canonical bytes,
  so an owner can freeze or change a section's members without a change here.
  The closed list of sections is one table (`members` in `gate.go`); adding or
  dropping a section is one row plus its vectors.
- It does not detect a superseded statement, a rollback or a clock set back.
  These are [stated limits](../spec/keymaker-static-gate.md#7-stated-limits)
  and the tests named `TestLimit…` keep them visible.
- It does not check that `caller_key` or the approver key is a usable curve
  point beyond what signature verification needs, and it authenticates no
  caller.
- It keeps no state between calls.

## Tests

```sh
go test ./staticgate/... -count=1
go vet ./staticgate/...
```

Every test carries a comment naming the claim it proves. `TestVectors` runs
[`vectors/staticgate/vectors.json`](../vectors/staticgate/README.md) through
the exported `Verify` and the strict engine, requiring identical returned
statements, refusal codes and check names. It also checks same-consumer
neighbours and single-field input-side mutations with identical bytes and
signatures (the invalid-consumer rows necessarily change the consumer).
`TestVectorFileIsGenerated` proves the committed file
is what the suite generates (`STATICGATE_WRITE_VECTORS=1` rewrites it).
`TestPlantedControls` removes the checks each negative names, through an
unexported switch that `Verify` never sets, and requires that the negative
then verifies and that each named check alone still refuses it.

The only scalars in the tests are CSV indices 1, 2 and 3 of the published
[BIP-340 test vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).
`TestPublishedKeys` checks both literal published columns, not just derivation.
They are public and must never approve anything real.
