# Lifecycle wire values

`github.com/relux-works/swarma-keymaker/j7lifecycle` converts the existing native
lifecycle protocol to and from inert Go values. It opens no socket, reads no
keys or state, and supplies no client, signer, peer authentication, generation
authority or launcher state machine. Normal nonlegacy daemon startup remains
refused; this package does not enable an operation or daemon mode.

## API and exact variants

`EncodeRequestFrame(Request)` and `DecodeRequestFrame([]byte)` handle one
complete four-byte big-endian length-prefixed CCJ-1 frame. Every request has an
explicit 32-lowercase-hex `ID` and `Method`:

| Method constant | Other fields |
| --- | --- |
| `HelloMethod` | Nonempty unique positive safe-integer `Versions`; zero `TimeoutMS`, nil `Bind`, empty `RunID`. An offer without version1 is syntactically valid; the server refuses it. |
| `BindMethod` | Explicit `TimeoutMS`1–2000, `Bind *BindParams`; no Versions or RunID. |
| `EndMethod`, `RebindMethod` | Explicit `TimeoutMS`1–2000 and `RunID`32 lowercase hex; no Versions or Bind. |

Bind params encode exactly `{identity_registration_number,input_principal,
origin,parent_run}`. Registration is1–9007199254740991; input contains a nonzero
uint32 UID and opaque nonempty UTF-8 generation. No UUID, ASCII, normalization
or short-token restriction is added. A root has empty parent and a complete
six-member origin. Admission uses `kind:"admission"`, three lowercase64hex
`event_id`, `grant_id`, `tip_hash`, `mode:"enforcing"` and empty `command_id`.
The existing `owner_command` grammar uses only a lowercase64hex command ID,
with those other four strings empty. Parsing it does not authenticate a command.
A child uses `Origin:nil` (explicit wire null) and `ParentRun`32 lowercase hex;
the holder inherits the origin from its retained live parent. Lifecycle child
binding supplies no child signing operation.

No request has an extension map, arbitrary method, raw digest, signer, query,
caller-selected run ID for bind, nonce or prepared-ID adoption route. The holder
generates the bind result's run ID. Current principal/binding/policy, trusted
parent selection, authentic Source origin and isolation remain external duties.

`EncodeResponseFrame(expected Request, Response)` and
`DecodeResponseFrame(expected Request, []byte)` require the consumer to supply ONLY its own outstanding request. The consumer
MUST NOT construct or select that context from the response.
A response has exactly one of `Version *int64`, `Run *RunResult`, or
`Refusal *Refusal`. Hello success is `{request_id,result:{version:1}}`;
bind/rebind result is `{run_id,state:"live"}`; end result is exactly the
requested run and state `ended`. Nonnull IDs must equal the outstanding ID;
rebind also requires the requested run ID. There is **no method echo** on wire.
Bind and rebind successes share a byte grammar; method context is local, never
an authenticated response field. Unexpected outer/result members refuse.

Refusals retain the closed native code/retryability pairs. `Retryable` is true
only for rate_limited, busy, generation_source_unavailable,
enrollment_unavailable, audit_unavailable and request_deadline_exceeded.
An empty response ID means wire null on refusals only. Such a refusal is
uncorrelated and cannot acknowledge a mutation. Framing/canonical refusals use
null. Even a correlated retryable error does not prove absence of a durable
commit. A decoded refusal returns nil Go error; inspect `Refusal` before using
any result. Local failures use `ErrFrameTooLarge`, `ErrFrameMalformed`,
`ErrFrameTruncated`, `ErrTrailingData`, `ErrCanonical`, `ErrRequest` or
`ErrResponse`, return no bytes/zero value, and are never new wire codes.

`FrameLength(header [4]byte) (int,error)` validates the advertised1–65536-byte
body length before the caller allocates body storage; invalid headers return0
and the specific frame-size/zero-length sentinel. It performs no read.

## Bounds and ownership

The body is1–65536 bytes, depth at most16, with canonical UTF-8, sorted unique
members, exact scalar/escape spellings and safe integers. One complete frame
is required: no trailing bytes or partial decoded values. Header cap checks
precede parsing/copying inside the API; the caller has already allocated its
input slice. Obviously over-cap generation strings/version lists are rejected
before constructing encoded copies. The existing internal canonical codec is
reused; there is no second production canonicalizer.

The concrete launcher client owns protected path/peer/current-generation checks,
real Unix I/O, hello, one outstanding request per connection, ID/method context,
finite framing/operation deadlines and durable local launch records. Hello's
version alone attests no role, generation or service identity. Keep one fresh
upstream connection per run, never given to an agent. Input is released only
after acknowledged bind and durable local `bound` state. An exact bind retry is
permitted only on the original live assigned channel. A lost/ambiguous channel
leaves the run HELD with input fenced; a fresh connection cannot recover/adopt
it by bind replay. End persists exact request ID/body for a permitted fresh
launcher connection to recover its retained exact acknowledgement. Local teardown
always runs; an unacknowledged end remains ending/fenced with retry intent.
EOF only drops volatile association, never durably ends a run.

The current server bounds every next frame read to two seconds, including
no-byte idle waiting after bind. This package changes neither that lifetime nor
hello/timeouts. It adds no heartbeat or reconnect workaround and does not qualify
long-idle operation. The existing holder rebind method is represented as data;
a launcher policy may forbid it, as the current v1 policy does.

## Vectors and checks

`testdata/wire-v1/manifest.json` hashes the synthetic literal `vectors.json`
payload and identifies the historical compatibility/current inspected source
pins. It does not hash itself or name its own eventual delivery commit. Consumers
pin the reviewed delivery commit/module version and corpus hashes externally;
changing the corpus requires a new pin. The test-only independent reference
reader/emitter and literal expectations do not use either production codec.
Real Unix holder fixtures use kernel opener credentials plus fixture generation
sources; they prove neither distinct-UID isolation nor installed native custody.

Run with the pinned Go1.26.10, private protected TMPDIR/caches, readonly module
intent, and the site's approved resource wrapper for heavy commands:

```sh
GOTOOLCHAIN=local GOMAXPROCS=2 go test -p=1 ./j7lifecycle -count=1
GOTOOLCHAIN=local GOMAXPROCS=2 go test -p=1 ./internal/control -run '^TestValidRefusal$' -count=1
GOTOOLCHAIN=local GOMAXPROCS=2 go test -p=1 ./internal/keymaker -run '^TestJ7Lifecycle' -count=1
GOTOOLCHAIN=local GOMAXPROCS=2 go test -race -p=1 -parallel=2 ./internal/keymaker -run '^TestJ7Lifecycle' -count=1
GOTOOLCHAIN=local go build ./j7lifecycle
GOTOOLCHAIN=local go run ./tools/mutations/main.go -group j7-lifecycle-wire -scratch "$SCRATCH"
```

Logs, compile-valid overlay plants and child receipts belong in caller-supplied
private scratch, never the public corpus. A kill requires the named intended
assertion and real test exit1; setup failures and survivors remain failures.
These checks do not run a service or qualify Source/launcher/deployment behavior.
