# Static gate statement `swarma-s7 static-gate/1`

Status: **format and verifier for review; not activated**. This document
defines one signed statement, the rule a consumer applies to it and the
vectors that pin both. The [`staticgate`](../staticgate/README.md) package
implements the rule as a pure function. No daemon reads a statement yet: no
importer, native method, purpose allocation or deployment is enabled here, and
purpose 6 of the [station-caller proposal](keymaker-station-caller.md) stays
reserved and unallocated.

The key words MUST, MUST NOT and MAY are normative.

## 1. What the statement replaces, and what that costs

A first-run milestone, `G1.0`, runs on one host before the live import of
current state from an independent custodian exists. For that milestone only,
one statement **G**, signed once by the owner, stands in for two things:

- the live import for the importing scopes: each consumer reads its own static
  section of G instead;
- the installed caller association: the association is a member of G.

The cost is stated here so that nobody reads the gate as more than it is.

1. **Kept:** the grant check and the rule that the checked data holds no
   secret. **Lost:** independent live currentness. Inside G's window a
   rollback, a restored clone or an old instance on the same host is not
   detected. Trust narrows to the administrative domain of that host: its root
   can replace both G and the pinned approver key. No second machine is an
   independent witness in this cut.
2. **Bounded:** one host (machine-id binding), one window of at most 72 hours,
   exact equality of each consumer's own section, and refusal on any mismatch.

No local watermark, mock or journal restores the lost guarantee. A consumer
MAY journal `gate_id` for audit only.

## 2. Signer

- The approver key is a dedicated key held by the owner, generated for this
  purpose alone and used with user presence. It MUST NOT be a grant key or any
  key with another use, and it MUST NOT sign anything except this statement.
- Algorithm: BIP-340 over secp256k1 with a 32-byte x-only public key.
- Signature: 64 bytes, BIP-340 over `SHA-256(preimage)`.
- The signing tool is outside this repository. It is expected to show every
  member and to re-derive the digest before signing.

This repository holds no signer and no private key. The test statements are
signed with the published BIP-340 test-vector keys.

## 3. Exact preimage

```text
preimage = ASCII("swarma-s7 static-gate/1") || 0x0a || CCJ-1(G)
digest   = SHA-256(preimage)
sig      = BIP-340(approver key, digest)      ; 64 bytes, 128 lowercase hex on the wire
```

CCJ-1 is the encoding of the public
[registrar specification, section 2.1](https://github.com/relux-works/swarma-registrar/blob/5f44ebf3f78829144aa7864ca2e4ad62bea43eb5/spec/registrar.md):
names sorted by Unicode scalar value, no whitespace, shortest integers and its
prescribed escapes.

- Duplicate names at any depth, non-integer numbers and invalid UTF-8 refuse.
- Container depth above 8 refuses. The statement object itself is depth 1.
- The preimage is at most 8192 bytes, so G is at most 8168 bytes.
- There is no final LF and no wrapper, in the statement or in the signature.
- A consumer re-encodes the received G and refuses unless the result is
  byte-identical to the bytes it received.

## 4. Members of G

G is one object. The member set is closed: every member is required and an
unknown member refuses.

| Member | Value | Checked by the verifier as |
| --- | --- | --- |
| `v` | `1` | exact value |
| `kind` | `"swarma-s7 static-gate/1"` | exact value |
| `milestone` | `"G1.0"` | exact value |
| `gate_id` | 32 lowercase hex digits, random, for audit only | shape |
| `host` | `{"label":<non-empty string>,"machine_id_sha256":<64 lowercase hex>}`, for example label `host-a` | shape; the digest in step 4 |
| `not_before`, `not_after` | `YYYY-MM-DDTHH:MM:SSZ`: UTC, whole seconds, uppercase `T` and `Z`, a real calendar date | shape; the window in step 5 |
| `approver` | `{"alg":"bip340","key":<64 lowercase hex>,"label":<non-empty string>}` | shape; the key in step 1 |
| `association` | `{"caller_uid":<integer 0..4294967295>,"caller_generation":<non-empty string>,"caller_key":"ed25519:"+<canonical unpadded base64url of 32 bytes>}` | shape; bytes in step 6 |
| `keymaker` | `{"service_uid":int,"binary_sha256":hex,"config_sha256":hex,"j7_request_key":<64 hex x-only>}` | section: bytes in step 6 |
| `dispatcher` | `{"service_uid":int,"receiver":hex,"policy_sha256":hex,"config_sha256":hex,"worker":{"uid":int,"generation":string}}` | section: bytes in step 6 |
| `source` | `{"service_uid":int,"generation":string,"config_sha256":hex}`: the grant-check configuration | section: bytes in step 6 |
| `broker_time` | the static values the broker uses instead of imported settlement currentness; **open, frozen later by its owner** | section: bytes in step 6 |
| `broker_d5` | the static start fence replacing the imported head; **open, frozen later by its owner** | section: bytes in step 6 |

Rules for the table:

- **Sections.** The five sections are the rows of one table in the verifier
  (`keymaker`, `dispatcher`, `source`, `broker_time`, `broker_d5`). The
  verifier requires each to be a non-empty object and otherwise never
  interprets it: step 6 compares canonical bytes. The member lists above for
  `keymaker`, `dispatcher` and `source` are their owners' contract, enforced by
  equality with the owner's protected configuration and not by this format.
  Adding or dropping one section is one table row plus its vectors.
- **Separation.** Each section name is also the name of its only consumer. No
  section may stand in for another; in particular `broker_time` and
  `broker_d5` are two members and neither replaces the other.
- **Generations** are opaque non-empty UTF-8 strings, compared byte for byte
  and never normalised (no case folding, trimming or Unicode normalisation).
- **`caller_key`** is the public half of the caller's signing key in the
  spelling the caller check already uses. It MUST equal the association key
  of the dispatcher's protected policy. The 32 bytes are not checked as a
  curve point here.
- **`host.machine_id_sha256`** is SHA-256 of the exact content of the host's
  machine-id file, with nothing trimmed.
- In `dispatcher`, `policy_sha256` is SHA-256 of CCJ-1 of the installed
  protected policy body, and `config_sha256` is SHA-256 of the daemon's
  protected configuration file bytes.

## 5. Consumer rule

Each consumer (Keymaker, the dispatcher, the Source check, the broker for each
of its two sections) applies this rule at startup and again before each
dependent effect. It checks only its own section. The steps run in this order
and the first failure decides the refusal code.

0. **Readable bytes.** A statement whose preimage exceeds 8192 bytes, or that
   the CCJ-1 decoder refuses, or that is not an object, refuses with
   `STATIC_GATE_FORM`. This comes first only because step 1 must read
   `approver.key`; nothing else is examined before step 1.
1. **Pins.** The consumer reads the approver key and the SHA-256 of the
   preimage of the one G in use from its protected, root-owned install path,
   never from G.
   - Unless `approver.key` equals the pinned key: `STATIC_GATE_KEY`. A
     statement without a readable `approver.key` refuses here.
   - Then, unless the preimage digest equals the pinned digest:
     `STATIC_GATE_PIN`.

   The digest pin only stops an old signed G from being picked up by mistake.
   It sits in the same trust domain as G and restores no independence.
2. **Form.** Canonical re-encoding, depth, the closed member set, exact
   `v`/`kind`/`milestone` and the shapes of §4: `STATIC_GATE_FORM`.
3. **Signature.** BIP-340 over `SHA-256(preimage)` under the *pinned* key. The
   wire signature is exactly 128 lowercase hex digits: `STATIC_GATE_SIGNATURE`.
4. **Host.** `host.machine_id_sha256` equals SHA-256 of this host's machine-id
   content: `STATIC_GATE_HOST`.
5. **Window.** `not_before < not_after`, `not_after − not_before ≤ 72 h`, and
   for class `start` (§5.1) `not_before ≤ now < not_after` on the host clock:
   `STATIC_GATE_WINDOW`.
6. **Scope.** The consumer's own section, and `association` where the consumer
   consumes it, equal the expected canonical bytes from its protected
   configuration exactly: `STATIC_GATE_SCOPE_MISMATCH`.

The consumer compares bytes only. It never hashes its own binary: a process
cannot vouch for itself. Checking `binary_sha256` and `config_sha256` against
the installed files is the installer's root-owned pre-start check, at install
and again at every unit start.

Every refusal happens before secret load and before the listener (Keymaker),
before dispatch (dispatcher) and before lease (broker), and leaves no partial
state. All-zero pins, an all-zero machine-id digest, a zero clock reading, an
unknown consumer and an empty expected section refuse; nothing defaults open.

`association` is consumed by `keymaker` and `dispatcher`: both MUST supply its
expected bytes. Another consumer MAY supply them, and then they are compared
too.

### 5.1 Operation classes and the window end

| Class | Operations | Step 5 |
| --- | --- | --- |
| `start` | Keymaker run bind and sign, dispatcher dispatch, broker lease | the clock comparison is required: at or after `not_after`, `STATIC_GATE_WINDOW` |
| `end` | Keymaker run end, the startup sweep, broker lease release, dispatcher owned-run cancel | the clock comparison is skipped; steps 0–4 and 6 apply in full |

A run bound inside the window may end after `not_after`; it gets no new
signature or lease. Without this an expired gate would strand a run in
quarantine. The bounds on the window itself (`not_before < not_after`, at most
72 hours) are properties of G and are checked for both classes. Any class
other than `start` or `end` refuses with `STATIC_GATE_WINDOW`.

## 6. Caller authentication

The dispatcher's existing caller check is unchanged: the request's key equals
the protected association key, the Ed25519 signature verifies, and the kernel
peer equals the association UID at the generation read locally.

For this milestone the caller key is a local Ed25519 key created on the host
at install time, not a Keymaker purpose-6 key. Its public half is
`association.caller_key`, so the owner signs the key that is relied on.
Creating that key needs the owner's explicit approval.

What this does not give: Keymaker custody of the caller key. That arrives with
purpose 6 and the full live import, outside this document.

## 7. Stated limits

These are limits of the cut, kept as tests, and MUST NOT be described as
protection:

- **Superseding is not detected.** Two different statements, both signed by
  the approver inside their windows, both verify. The digest pin selects one,
  and whoever can write the pin can select the other.
- **The clock is the host's.** A host clock set back into an expired window is
  not detected.
- Everything in §1 item 1.

## 8. Vectors

[`vectors/staticgate/`](../vectors/staticgate/README.md) holds one genuine
statement and its signature, and `vectors.json` with every case below. Each
negative names its exact refusal code and the passing control it stands
beside. All statements are generated by the package tests with published
BIP-340 test-vector keys; the committed file is checked against the generator.

| Code | Negatives |
| --- | --- |
| `STATIC_GATE_KEY` | another key, and a key with another purpose, as signer; `approver.key` differing from the pin; zero pin; `approver` absent |
| `STATIC_GATE_PIN` | a validly signed statement that is not the pinned one; zero pin |
| `STATIC_GATE_FORM` | 8193-byte preimage; depth 9; duplicate names at the top and nested; non-integer number; whitespace, final LF, unsorted names, needless escapes; each member missing; unknown member; wrong `v`, `kind`, `milestone`; each shape of §4 |
| `STATIC_GATE_SIGNATURE` | signature over another tag, over no tag, over a final LF, by another key, for another statement; uppercase, short, empty, LF-terminated or altered signature text |
| `STATIC_GATE_HOST` | another machine-id; zero digest |
| `STATIC_GATE_WINDOW` | not yet valid; at `not_after`; expired `start` beside a passing `end`; unknown class; 72 h + 1 s, empty and inverted windows for both classes |
| `STATIC_GATE_SCOPE_MISMATCH` | every member of every section and of `association` (including `caller_key`) changed one at a time; member added or removed; `broker_time`/`broker_d5` swapped; `source`/`dispatcher` swapped; generations re-spelled (case, trailing space, look-alike letter, decomposed form); unknown consumer; missing or non-canonical expected bytes |

Positive controls include the genuine statement for all five consumers and the
exact boundaries: 8192 bytes, depth 8, `now = not_before`, the last nanosecond
before `not_after`, exactly 72 hours, and `end` after expiry.

The planted control in the package tests removes each check in turn and shows
that the negatives naming it then verify, so each refusal is attributed to the
check that causes it.

## 9. Example

The genuine vector (`vectors/staticgate/genuine.ccj`, 1449 bytes, placeholder
values, **not for signing**):

```text
{"approver":{"alg":"bip340","key":"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659","label":"static-gate-example"},"association":{"caller_generation":"g-example-1","caller_key":"ed25519:iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg","caller_uid":28601},"broker_d5":{"example_acknowledged_head":"8888888888888888888888888888888888888888888888888888888888888888"},"broker_time":{"example_hold_seconds":30,"example_in_flight":1},"dispatcher":{"config_sha256":"9999999999999999999999999999999999999999999999999999999999999999","policy_sha256":"7777777777777777777777777777777777777777777777777777777777777777","receiver":"66666666666666666666666666666666","service_uid":28602,"worker":{"generation":"w-example-1","uid":28603}},"gate_id":"00112233445566778899aabbccddeeff","host":{"label":"host-a","machine_id_sha256":"6ed6653dba3d6aee8110c6e23de37f15c609b8a6e29aa164d1acace604e5cb7e"},"keymaker":{"binary_sha256":"3333333333333333333333333333333333333333333333333333333333333333","config_sha256":"4444444444444444444444444444444444444444444444444444444444444444","j7_request_key":"5555555555555555555555555555555555555555555555555555555555555555","service_uid":28600},"kind":"swarma-s7 static-gate/1","milestone":"G1.0","not_after":"2026-11-19T00:00:00Z","not_before":"2026-11-17T00:00:00Z","source":{"config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":"s-example-1","service_uid":28604},"v":1}
```

The preimage (tag, LF, the bytes above) is 1473 bytes with SHA-256
`4b42a926b2b362ea233fd23f621515ca3c486c59a04b3e133d4ab26abd12e6bc`. The
approver key is row 1 of the published BIP-340 test vectors. The contents of
`broker_time` and `broker_d5` are invented placeholders.
