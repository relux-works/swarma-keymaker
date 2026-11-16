# Static gate statement `swarma-s7 static-gate/1`

Status: **format, verifier and Linux Keymaker importer; deployment prerequisites remain**. This document
defines one signed statement, the rule a consumer applies to it and the
vectors that pin both. The [`staticgate`](../staticgate/README.md) package
implements the rule as a pure function. The Linux request-role service consumes
it through the protected importer described below. This does not qualify a
deployment or allocate a purpose; purpose 6 of the
[station-caller proposal](keymaker-station-caller.md) stays reserved and unallocated.

The key words MUST, MUST NOT and MAY are normative.
The consumer-rule clarifications below amend the static-gate r2 format.

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
  member and to re-derive the digest before signing; it MUST enforce
  `not_before < not_after` and a window width of at most 72 hours.

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
  Consumers such as M0 apply their own stricter shape: its caller and worker
  generations are exactly 32 lowercase hex digits, as used in these examples;
  a non-hex Source-section positive vector proves the verifier stays opaque.
- **Example UIDs** (caller, worker and services) use the managed range
  30000..59999; the format itself remains range-neutral.
- **`caller_key`** is the public half of the caller's signing key in the
  spelling the caller check already uses. It MUST equal the association key
  of the dispatcher's protected policy. The 32 bytes are not checked as a
  curve point here.
- **`host.machine_id_sha256`** is SHA-256 of the exact content of the host's
  machine-id file, with nothing trimmed.
- In `dispatcher`, `policy_sha256` is SHA-256 of CCJ-1 of the installed
  protected policy body.
- The dispatcher's transport spec defines `dispatcher.config_sha256` as
  SHA-256 over CCJ-1 of `{"m0":<sha256 hex>,"server":<sha256 hex>}` over
  its two protected config files; the verifier compares bytes only.
- The host and approver labels are audit-only; authentication relies on the
  digest/key pins and machine-id digest, not on a label.

## 5. Consumer rule

Each consumer (Keymaker, the dispatcher, the Source check, the broker for each
of its two sections) applies this rule at startup and again before each
dependent effect. It checks only its own section. The steps run in this order
and the first failure decides the refusal code.

1. **Pins and bounded parse.** The consumer reads the approver key and the
   SHA-256 of the preimage of the one G in use from its protected, root-owned
   install path, never from G, and performs these checks in this exact order:
   - First, compute the digest of §3, formed from the raw, unparsed bytes
     (tag, LF, then those bytes), before any parse or size check, and refuse
     unless it equals the pinned digest:
     `STATIC_GATE_PIN`.
   - Then bound the parse: a preimage over 8192 bytes, a codec refusal
     (including the codec container-depth bound of 16), or a non-object value
     refuses with `STATIC_GATE_FORM`. The format's depth bound of 8 is checked
     only at step 2: with a correct pin, a wrong-key statement at depth 9–16
     therefore refuses `STATIC_GATE_KEY`, while depth 17 or more refuses FORM.
     Because the pure verifier hashes before its size check, the consumer's
     protected reader must independently bound how many bytes it reads.
   - Then require `approver.key` to equal the pinned key:
     `STATIC_GATE_KEY`; an unreadable approver key refuses here too.

   This PIN → bounded parse → KEY order is an r2 amendment. The digest pin
   only stops an old signed G from being picked up by mistake; it sits in the
   same trust domain as G and restores no independence.
2. **Form.** Canonical re-encoding, depth, the closed member set, exact
   `v`/`kind`/`milestone` and the shapes of §4: `STATIC_GATE_FORM`.
3. **Signature.** BIP-340 over `SHA-256(preimage)` under the *pinned* key. The
   wire signature is exactly 128 lowercase hex digits: `STATIC_GATE_SIGNATURE`.
4. **Host.** `host.machine_id_sha256` equals SHA-256 of this host's machine-id
   content: `STATIC_GATE_HOST`.
5. **Window.** `not_before < not_after`, `not_after − not_before ≤ 72 h`, a
   non-zero `Now` for every class, and for class `start` (§5.1)
   `not_before ≤ now < not_after` on the host clock: `STATIC_GATE_WINDOW`.
   Zero Now is refused here, after signature verification at step 3, not before
   public-key signature computation. Refusal returns no usable statement.
6. **Scope.** The consumer's own section, and `association` where the consumer
   consumes it, equal the expected canonical bytes from its protected
   configuration exactly: `STATIC_GATE_SCOPE_MISMATCH`.

The consumer compares bytes only. It never hashes its own binary: a process
cannot vouch for itself. Checking `binary_sha256` and `config_sha256` against
the installed files is the installer's root-owned pre-start check, at install
and again at every unit start.

Every startup refusal happens before secret load and before the listener (Keymaker),
before dispatch (dispatcher) and before lease (broker), and leaves no partial
state. All-zero pins, an all-zero machine-id digest, an unknown consumer and
an empty expected section refuse. A zero `Now` is an unfilled input and
refuses for EVERY operation class with `STATIC_GATE_WINDOW`, including `end`.
This amended R3 supersedes the earlier zero-Now exception for `end`: a
consumer ending work still supplies a real clock reading.

Only `dispatcher` MUST supply the expected `association` bytes. Every
consumer, including `keymaker`, compares them whenever supplied. Supplied
means `len(Association) > 0`: omitted and empty are indistinguishable, which
is acceptable for consumers that do not consume the association. A mutated
association can therefore pass Keymaker with no supplied association, but it
cannot authorize dispatch unless it also equals the dispatcher's protected
association.

The following producer choices are ratified as r2 clarifications:

- (a) A missing or unreadable `approver`/`approver.key` refuses with
  `STATIC_GATE_KEY`, rather than `STATIC_GATE_FORM`, after the bounded parse.
- (b) A malformed `approver.key`, including uppercase, non-hex or non-string,
  refuses with `STATIC_GATE_KEY` before the shape check.
- (c) An unknown operation class refuses with `STATIC_GATE_WINDOW`.
- (d) An unknown consumer or empty expected section refuses with
  `STATIC_GATE_SCOPE_MISMATCH`.
- (e) All-zero key pins, digest pins and machine digests refuse with
  `STATIC_GATE_KEY`, `STATIC_GATE_PIN` and `STATIC_GATE_HOST`, respectively,
  at their ordered checks.
- (f) Every section is a non-empty JSON object as in r2 §5; scalar and empty
  sections refuse with `STATIC_GATE_FORM`, while values within an object
  remain opaque, including arrays, booleans and null.

### Keymaker consumer note

The Linux request-role importer reads four root-owned, single-link regular
files of mode 0640 with the service's primary group, beneath protected
root-owned ancestors. Access/default ACLs are refused. The approver key and
digest files are exactly 64 lowercase hex characters plus one LF; the
signature file is exactly 128 lowercase hex characters plus one LF. The
statement is the exact CCJ-1 bytes with no LF. Reads are bounded before parsing.
File reads follow PIN (digest), FORM (statement), KEY (approver key), SIGNATURE,
then HOST (machine-id); a failed earlier read prevents later reads.
Unreadable, unsafe or malformed key, digest, statement and signature files
refuse `STATIC_GATE_KEY`, `STATIC_GATE_PIN`, `STATIC_GATE_FORM` and
`STATIC_GATE_SIGNATURE`, respectively. An unreadable or unsafe root-owned
regular `/etc/machine-id` refuses `STATIC_GATE_HOST`; its exact content is
hashed without trimming. A statement changed without updating its digest pin
refuses `STATIC_GATE_PIN` before its content is parsed.

The expected `keymaker` section is CCJ-1 of exactly
`{"binary_sha256":B,"config_sha256":C,"j7_request_key":K,"service_uid":U}`.
U is the checked service UID and C is SHA-256 of the exact protected config
bytes. B and K come from the signed statement's own section, and must each be
64 lowercase hex characters. The exact comparison pins U, C and the closed
member set. The service does not hash itself: the root-owned S8 pre-start
check must compare the installed binary with B. Only after every earlier
startup precondition passes does custody load the key and compare its derived
public key with K (`j7_request_key_mismatch` on disagreement). Keymaker does
not consume association and supplies no expected association bytes.

Startup verifies class `start` with the supplied trusted Now. The captured
statement, signature and pins are immutable for the process lifetime; every
bind, rebind, sign, consent and public-key effect verifies class `start`
again with a fresh trusted sample. Run end and response release use class
`end`. A request refusal is audited through the control observer and precedes
the wrapped effect. File replacement after startup does not update authority;
a reconciled restart is required. No host-clock fallback is used.

R-U2-1 (decided 2026-11-16): startup is a start-class effect, so a service whose
window has expired does not start. This profile has no startup sweep and needs
none: no claim outlives a stop; the launcher binds runs again after restart as
start class. Authority held from before a stop is ended only by stopped-operator
reconciliation, with the service stopped and outside the gate. Within one running
process, run end and release are end-class and pass after expiry; all other
checks remain required.

### 5.1 Operation classes and the window end

| Class | Operations | Step 5 |
| --- | --- | --- |
| `start` | Keymaker startup, run bind and sign, dispatcher dispatch, broker lease | the clock comparison is required: at or after `not_after`, `STATIC_GATE_WINDOW` |
| `end` | Keymaker run end and response release, broker lease release, dispatcher owned-run cancel | only the window-bound comparison is skipped; non-zero `Now`, window width, and steps 1–4 and 6 still apply |

A run bound inside the window may end after `not_after`; it gets no new
signature or lease. Without this an expired gate would strand a run in
quarantine. The bounds on the window itself (`not_before < not_after`, at most
72 hours) are properties of G and are checked for both classes with
`STATIC_GATE_WINDOW`; the signer applies the same width rule. This width
rule is an r2 amendment: `end` skips only comparing `Now` with the window
bounds, never the non-zero-`Now` requirement. The retained
`end-before-not-before` positive means only that window bounds are not compared;
it does not mean an end is exempt from all clock checks.
Any class other than `start` or `end` refuses with `STATIC_GATE_WINDOW`.

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
There are **180 rows: 21 passing controls/limits and 159 refusals**.

| Refusal code | Rows |
| --- | ---: |
| `STATIC_GATE_KEY` | 11 |
| `STATIC_GATE_PIN` | 4 |
| `STATIC_GATE_FORM` | 75 |
| `STATIC_GATE_SIGNATURE` | 15 |
| `STATIC_GATE_HOST` | 2 |
| `STATIC_GATE_WINDOW` | 13 |
| `STATIC_GATE_SCOPE_MISMATCH` | 39 |

| Code | Negatives |
| --- | --- |
| `STATIC_GATE_KEY` | another key, and a key with another purpose, as signer; `approver.key` differing from the pin; zero pin; `approver` absent or unreadable; malformed or uppercase `approver.key`; KEY before canonical form on parseable pinned bytes |
| `STATIC_GATE_PIN` | a validly signed statement that is not the pinned one; zero pin; wrong pin before size/codec refusal |
| `STATIC_GATE_FORM` | 8193-byte preimage; depth 9; duplicate names at the top and nested; non-integer number; whitespace, final LF, unsorted names, needless escapes; each member missing except `approver` (KEY); unknown member; wrong `v`, `kind`, `milestone`; remaining shapes of §4 (`approver.key` is KEY), including uppercase, 63-character, 65-character, non-hex, non-string and empty `host.machine_id_sha256` |
| `STATIC_GATE_SIGNATURE` | signature over another tag, over no tag, over a final LF, by another key, for another statement; uppercase, short, empty, LF-terminated or altered signature text; hand-encoded r ≥ p, s ≥ N, non-liftable R; unusable pinned key |
| `STATIC_GATE_HOST` | another machine-id; zero digest |
| `STATIC_GATE_WINDOW` | not yet valid; at `not_after`; expired `start` beside a passing `end`; zero `Now` for both classes; unknown class; 72 h + 1 s, empty and inverted windows for both classes |
| `STATIC_GATE_SCOPE_MISMATCH` | every scalar leaf of the example sections and of the dispatcher's `association` (including `caller_key`) changed one at a time; a nested array element changed; member added or removed; `broker_time`/`broker_d5` swapped; `source`/`dispatcher` swapped; generations re-spelled (case, trailing space, look-alike letter, decomposed form); unknown consumer; missing or non-canonical expected bytes |

Positive controls include the genuine statement for all five consumers and the
exact boundaries: 8192 bytes, depth 8, `now = not_before`, the last nanosecond
before `not_after`, exactly 72 hours for both classes, and `end` after expiry
with a non-zero `Now`. A section holding an array, true, false, null and a
nested array verifies when its expected bytes match.

Each negative uses a passing control of the same consumer, except the two
consumer-name misuse rows: an invalid consumer cannot have a passing row of
that same consumer, so only that input field differs from a genuine consumer.
Input-only negatives keep identical statement bytes and signature and change
exactly one field belonging to the named check; the suite checks this
mechanically. The precedence rows deliberately combine multiple faults and
are not input-only negatives. Statement mutations necessarily re-pin and
re-sign, and unusable-key rows also pin the unusable key to isolate signature
verification.

The planted control in the package tests removes each check in turn and shows
that the negatives naming it then verify, so each refusal is attributed to the
check that causes it.

## 9. Example

The genuine vector (`vectors/staticgate/genuine.ccj`, 1491 bytes, placeholder
values, **not for signing**):

```text
{"approver":{"alg":"bip340","key":"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659","label":"static-gate-example"},"association":{"caller_generation":"0123456789abcdef0123456789abcdef","caller_key":"ed25519:iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg","caller_uid":38601},"broker_d5":{"example_acknowledged_head":"8888888888888888888888888888888888888888888888888888888888888888"},"broker_time":{"example_hold_seconds":30,"example_in_flight":1},"dispatcher":{"config_sha256":"9999999999999999999999999999999999999999999999999999999999999999","policy_sha256":"7777777777777777777777777777777777777777777777777777777777777777","receiver":"66666666666666666666666666666666","service_uid":38602,"worker":{"generation":"fedcba9876543210fedcba9876543210","uid":38603}},"gate_id":"00112233445566778899aabbccddeeff","host":{"label":"host-a","machine_id_sha256":"6ed6653dba3d6aee8110c6e23de37f15c609b8a6e29aa164d1acace604e5cb7e"},"keymaker":{"binary_sha256":"3333333333333333333333333333333333333333333333333333333333333333","config_sha256":"4444444444444444444444444444444444444444444444444444444444444444","j7_request_key":"5555555555555555555555555555555555555555555555555555555555555555","service_uid":38600},"kind":"swarma-s7 static-gate/1","milestone":"G1.0","not_after":"2026-11-19T00:00:00Z","not_before":"2026-11-17T00:00:00Z","source":{"config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":"s-example-1","service_uid":38604},"v":1}
```

The preimage (tag, LF, the bytes above) is 1515 bytes with SHA-256
`a9112c6bc3bfbf86661f0a637c7ad820ecaff1f777be6cc48d2a23b3e27dda41`. The
approver key is CSV index 1 of the published BIP-340 test vectors. The contents
of `broker_time` and `broker_d5` are invented placeholders.
