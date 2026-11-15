# Synthetic delegation request fixtures

`delegation.json` contains new generic complete parent contract, signed parent,
child terms, released-form consent and kind-8186 request bytes, plus literal
NIP-01 preimages. It follows Draft LIP-0014 sections 2–5 at public link-spec
commit `d0b2dcc6465fc856e334ddeef7a22f3e1dceb81b`. These bytes differ from the
upstream contract-only corpus. That exact 151-contract/39-pair corpus is kept
outside product source for independently reproducible private checks.

The synthetic scalar labels 23, 29, 31, 37 and 41 are public test data. Parent,
seal and issuance IDs are recomputed from complete synthetic bytes; no grant ID
is a placeholder accepted as authority. The funding source is synthetic, not an
active-chain claim. The notary pin/checkpoint are syntax fixtures, without a
registration/history/owner proof. No fixture establishes LIVE admission, issuer
J3.9 compliance, external interoperability, custody isolation or deployment.
Kind 8186 remains a draft allocation. Endpoint tests separately exercise full
`rental.Check` on a synthetic W-node graph; a receiver still checks its own node.

Two positive events and seventeen neighboring negatives cover exact tag order,
parent/contract/ordinal binding, key, kind, nonce spelling, time, content, event
ID and signature. Correctly signed wrong terms remain invalid requests. The
all-zero nonce spelling is structurally valid; a byte fixture cannot establish
freshness or the landlord's unused-nonce/ordinal reservation. Request retries
reuse exact bytes, and a new request may ask for the same ordinal. Only the
landlord owns its durable issuance reservation.

The product and a test-only byte-grammar reference reader check these fixtures.
The reference does not call product contract/binding/hash/event construction
helpers. Both are maintained by the same author and share cryptographic
libraries; independent review and actual endpoint evidence remain necessary.
D12 remains active: delegated spend is refused. Future-spend examples do not
establish an active endpoint budget-over path.

From the repository root with Go 1.26.10:

```sh
go test ./internal/keymaker -run '^TestJ7Delegation(RequestIndependentVectors|ReferenceContractControls)$' -count=1
go run ./tools/vectors/main.go -check
go run ./tools/vectors/main.go -write-j7-delegation
```

The explicit writer touches only `vectors/j7/delegation.json`. Historical
signing vectors, seeds, domains and their CLI remain unchanged. Checks write
only private Go build/test scratch; set private `HOME`, `TMPDIR` and Go caches.
