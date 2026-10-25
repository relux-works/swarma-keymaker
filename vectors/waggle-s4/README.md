# Pinned S4 publication and reissue bytes

Source: public waggle [5f4e7435d75697385ff6ce15a7501ac6f31c8ea5](https://github.com/relux-works/waggle/tree/5f4e7435d75697385ff6ce15a7501ac6f31c8ea5/vectors/swarm-envelope-2).
All seven JSON files are byte-identical imports, including upstream formatting,
claims, signed bytes, context and expected plans. [manifest.json](manifest.json)
records exact source paths, byte counts, SHA256 and positive-control mapping.
No generator, test verifier or altered signed record is imported.

| Fixture ID (same filename plus .json) | Expected upstream decision | Keymaker row / positive control |
| --- | --- | --- |
| P-JRN-publish-reissue | accept; candidate plan only | MS-S12 three-entry publication/reissue control |
| N-JRN-publish-reissue-old-snapshot | checkpoint_snapshot_invalid; empty plan | MS-S12; P-JRN-publish-reissue |
| N-JRN-publish-reissue-missing-reissue | journal_chain_broken; empty plan | MS-S12; P-JRN-publish-reissue |
| N-JRN-publish-reissue-missing-record | journal_chain_broken; empty plan | MS-S12; P-JRN-publish-reissue |
| N-JRN-publish-reissue-missing-prior | journal_unavailable; empty plan | MS-S13; P-JRN-publish-reissue |
| N-JRN-publish-reissue-wrong-prior | checkpoint_invalid; empty plan | MS-S14; P-JRN-publish-reissue |
| N-JRN-publish-reissue-backward-time | journal_rollback; empty plan | MS-S15; P-JRN-publish-reissue plus separate equal-time control |

The positive retains raw anchor E_(n-1), attestation E_n, reissue E_(n+1), exact
signed descendant checkpoint/snapshot and protected C_(n-1) at the witnessed
IDJournal key. Candidate time is not before that authenticated prior; equality
also passes under D39. The wrong-prior case uses genuinely signed wrong bytes,
not merely invalid JSON. Do not substitute conflict for the prior.

These bytes and [paired MS-S rows](../../spec/keymaker-msg-state.md#6-paired-negative-text-vectors)
are conformance inputs, not passing Keymaker runtime tests. The existing
`go run ./tools/vectors/main.go -check` covers its original native/derivation
fixtures, not these imported verifier cases. Consumer execution, current
publication/freshness/receipt integration and all activation gates remain PENDING.
