# gen-journal/1 vectors

The authoritative schema, byte hashing, refusal order and fixture semantics are
in [the format specification](../../spec/generation-journal.md). `manifest.json`
is the stable `gen-journal-vectors/1` index. Raw `.jsonl` files include deliberately
invalid bytes; do not format or normalize them. Every negative names its nearest
positive control. Ownership/mode/symlink/size fixtures are materialized by the
Go tests, so no root access or large committed file is required.

Run the content and path vectors plus the mandatory corrupt-link control:

```sh
go test ./tools/genjournal -run '^(TestVectors|TestBrokenChainPlant|TestReviewLateBrokenChain)$' -count=1
```

Run the release/retirement ordering harness and new-reader drain check:

```sh
go test ./tools/genjournal -run '^(TestReleaseWins|TestRetirementWins|TestWriterProgress|TestPendingGateWindow)$' -count=1
```

`TestReleaseWins` holds the data lock while a writer publishes intent, proves no
retirement append occurs during that release, then lets the writer commit.
`TestRetirementWins` computes a result before retirement and proves the final
active check prevents its later release. These are executable Linux lock tests,
not claims that a static file can prove ordering or that a production transport
has been qualified.


Marker fixtures follow `gen-journal-pending/1`: fresh valid evidence is retryable
but refuses admission; malformed bytes are preserved with
`journal_pending_malformed`; cross-boot, expired (1500 ms including margin) or
future-start evidence returns `journal_writer_stale`. Fixture timestamps are
materialized relative to the test boot clock, never committed as host metadata.
The journal byte ceiling is 1 MiB; marker size is at most 512 bytes. The normal
writer has one 1000 ms budget across all stages, distinct from retry advice.

`late-broken-chain.jsonl` corrupts only the third record's predecessor; the
nearest valid control is `retiring`. `TestPendingGateWindow` publishes intent
in the exact gap after the first check and before shared gate acquisition;
the unfenced neighbor releases. Private scheduling injection is unavailable
through the production CLI or exported reader entry points. Narrowing the
second check to cancelled contexts must fail this regression.

Run the maximum-size qualification once on the installation's local storage:

```sh
GEN_JOURNAL_MEASURE=1 go test ./tools/genjournal -run '^TestMaximumFenceDuration$' -count=1 -v
```

The fixture starts at 1048576 minus the 264-byte removal reserve with one
retiring generation, then appends its removal. The canonical sequence width
leaves a few bytes below the hard ceiling. This diagnostic test is
opt-in and is not rerun by the ordinary vector/order checks. It measures the
real runbook and checks the complete final history and removed marker; no
single timing observation proves performance on all storage or under faults.

Capacity fixtures materialize `capacity-reserve-valid` (529 bytes free and one
active generation), `capacity-reserve-deficit` (528 free), and
`capacity-exact-ceiling`. The latter two refuse `journal_capacity_reserve` on
protected release, even though raw diagnostic verification can succeed.
`TestCapacityReserveLifecycle` uses the real manual writer to refuse new
creating without mutation, reconcile the valid current reserve, and then
successfully append retiring and removed using the reserved space.
`TestReviewR2CapacityAdmission` retains exact-ceiling and failed-retirement then
reconciliation witnesses; reconciliation cannot erase their fence.

```sh
go test ./tools/genjournal -run '^(TestReviewR2CapacityAdmission|TestCapacityRecordBounds|TestCapacityReserveLifecycle|TestCapacityReserveDeficit)$' -count=1 -v
```
