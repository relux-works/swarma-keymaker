# Prepared certificate publication handoff

This internal component retains the existing transaction, encoded Envelope,
ContentID and exact decoded bytes of an already prepared message certificate.
It adds no issuer, daemon, signing RPC, key operation, transport or wire format.
The parent package validates the full retained certificate before preparing it.

`Retry` returns the same typed original request and outcome. A lost reply leaves
the outcome unknown; it cannot create another transaction or replace evidence.
One bounded opaque reply may be retained, and exact replay is idempotent.
Different original bytes or a conflicting reply refuse. Retention is in memory;
it does not replace the existing transaction store or provide restart custody.

`PublishedWire` always returns unavailable. A signature, local commit, retained
reply or injected test result cannot establish a published or current record.
No authenticated publishing principal, selected transport, admitted publication
view, or original-operation reconciliation mapping is supplied here. The source
owner must supply those inputs and the complete resolved record/journal/
checkpoint/witness proof before any successful publication route is possible.
Framing, error, proof-transfer, total-time, original-deadline, concurrency and
recovery limits also need an admitted connector contract. The 8192-byte reply
cap bounds local opaque retention only; it grants no transport or proof budget.

Composition must bind the exact prepared certificate to its retained original
durable transaction, reconcile that operation after lost replies or restart,
and atomically retain the validated original outcome through the existing store
and exclusion boundary. This component does not modify that store, the registry
reader, consumer ports, time confidence, assurance, or activation. The consumer's
existing r8.2 contract and accepted source component remain unchanged.

Tests use already formed public wire fixtures and never issue a certificate or
operate a key. Fixture validity establishes byte/signature handling only.
Independent exact-head review remains required before integration.

Rollback: omit the new package and parent helper from composition, or revert
the isolated commit. No runtime wiring, persisted schema, migration, deployment
or key state is introduced, so existing publication unavailability is retained.
