# Decisions and unresolved questions

The authoritative decision list and safe defaults are in
[`spec/keymaker.md`, section 14](spec/keymaker.md#14-open-questions-and-activation-gates).

- Q1 and Q4: helper ownership split and module naming — decided.
- Q2 and Q3: decrypt out of v0 (`operation_unsupported`) and configured
  operator-only register/revoke intake — decided. Persistent revoke refuses
  until the signed operator-act verifier exists; Q7 remains its activation gate.
- Q6: interim decision — the authoritative journal format belongs to
  `swarma-user-manager`; its publication is the remaining gate. K1 reads that
  format. A reviewed root-run manual writer is production authority until the
  module writer exists; retirement recorded late is not fenced (section 3.1).
- Q7: signed operator-record verification — activation gate.
- Q8: explicit, append-only, scoped name-to-index registry — decided.
- Q9–Q11: control-group provisioning, external root attestation/rotation and
  the reusable Linux test window — qualification gates.
- Q12: decided — executable-qualified enrollment is valid data but not an available v0
  enforcement capability. All matched rows with `exe` refuse locally, including
  matching procfs snapshots. No UID-only fallback is allowed.

## Q5: registrar draft alignment and explicit differences

Reference: [swarma-registrar spec/registrar.md (draft)](https://github.com/relux-works/swarma-registrar/blob/f81020a685b8d33c4fc61d835192d4fc87739398/spec/registrar.md),
sections 2–5. Its constants remain under review; a changed revision requires
explicit consumer updates and re-qualification before activation.

| Conflict or dependency | Disposition / remaining gate |
| --- | --- |
| Earlier Keymaker fixtures represented uid_map as a UID-keyed object; registrar requires an array of integer-UID rows with names and optional exe | Corrected to the registrar schema; existing vector IDs retained. Array-valued mutations remain one changed field. |
| Earlier localpart proposal allowed slash and ignored the configured-audience mxid bound | Withdrawn; use registrar structured/explicit-legacy rules and its 255-byte mxid bound. Negative slash and length-bound cases added. |
| Earlier encoding details were assumptions | Body construction, Ed25519 encoding, envelope/signature/nonce, time and half-open key windows now reference the draft owner sections instead of duplicating their schema. |
| Native helper requires canonical frame bytes; registrar HTTP accepts noncanonical JSON wire spellings | Intentional transport distinction. The same semantic body uses the same CCJ-1 scalar-order codec and canonical signature preimage. Do not relax native frames or reject registrar HTTP whitespace by analogy. |
| E1: shared enrollment authority and snapshot verification | Decided: the owner holds the offline Ed25519 enrollment-publisher key; both services verify the pinned signed registry commit and phase-0 envelope signature using the same out-of-band pins in root-owned config, per registrar section 4.3. Snapshot phase ordering, historical legacy-name ownership and rollback/reload rules follow section 4.4 without a Keymaker variant. |
| A retained native helper response may contain a nonce already consumed by registrar HTTP admission | Same-ID helper retry retrieves evidence, not another HTTP success. A fresh admission uses a new native ID and independent nonce; joint retry tests remain a gate. |
| Registrar accepts syntactically valid executable-qualified rows; v0 cannot attest per-operation executable identity | Explicit local capability refusal `enrollment_unsupported`, not a registrar format change. Wrong, unavailable and matching executable snapshots all refuse. v0 refusal is decided in Q12; future enablement requires a separate design. |
| Enrollment maps UIDs, while local custody also needs binding/generation evidence | Active station binding and protected per-UID generation admission remain additional local checks; no extra enrollment wire member is invented. Joint revocation/re-admission tests remain required. |

The helper's wrapper and local refusal codes remain Keymaker-owned; registrar
loader diagnostics are not silently renamed into signed-format rules. The
helper is Ed25519-only in v0 although the registrar also supports P-256.
No unresolved interface may be replaced with an allow-all production stub.

## Enrollment adapter activation gates

Enrollment approval replay residual: the ten-minute, same-boot approval and
append-only consumed-approvals record cannot detect restoration that also rolls
back the consumed record, including a whole-host restore within the same boot
and TTL, or deliberate file surgery by root. Restoring an approval alone or
rolling state back to its approved digest does not constitute new confirmation.
Option C, an external witness outside the restored host, is required to close
this residual; it is not implemented by the interim local policy.

Consumption begins when the default startup policy acquires the exclusive
Store lock. Its first action renames the receipt to consuming evidence and
fsyncs the directory, before reading or validating consent or retained state.
Every later error leaves consuming evidence or a durable consumed ID; recovery
requires privileged cleanup and a new confirmation. Exactly two retry windows
remain: an atomic rename failure with no filesystem effect, and a refusal on
the exhaustive pre-lock list in the
[consumption contract](internal/enrollment/README.md#startup-consumption-contract)
(lifetime/target guard, protected config location, protected directory/lifecycle
lease, existing Store lock acquisition, or cancellation/deadline before lock).
Those pre-lock gates read no consent or retained-state contents and grant
nothing. In either window a later start within the TTL may consume the unchanged
approval at most once. No post-rename validation failure is a retry window.

The registrar dependency pin and bump rule are in [README.md](README.md#registrar-dependency).
The local adapter and its explicit bounds are in [internal/enrollment/README.md](internal/enrollment/README.md).

- A missing station `uid_map` is a registrar schema failure that fences the whole
  snapshot. The helper returns `enrollment_unverified`; `uid_map_required` was
  removed. No alternate parser or group fallback is provided.
- The shared interim normal-restart policy requires an explicit operator
  reconciliation after every start. Local readability alone cannot establish
  freshness. The shipped `OperatorReconciler` requires a root-protected approval
  for a fresh startup challenge and exact state digest. An external-witness
  policy requires a future design decision and is not shipped.
- The pinned registrar Store contract now states that a Commit error leaves
  durable state indeterminate. The adapter returns neither old nor new authority
  and fences until a new start with operator reconciliation; this is aligned.
- The published enrollment-1 suite (114 negative/25 positive) runs through the
  local adapter's conformance test. All published rows are supported. Later
  unpublished rows need an explicit dependency bump and are not claimed.
- Native helper integration now enforces binding, generation and current
  enrollment through actual response release. The
  [registration builder](internal/registration/README.md) constructs and checks
  proofs; enrollment alone still grants no binding or release authority.
  Production generation evidence and live multi-UID qualification remain gates.
- Proposed `custody_unavailable` (`retryable=false`) covers closed, unloaded or
  protection-failed local signing custody on both surfaces. This proposal awaits
  curator content approval. Other existing refusal meanings are unchanged.
  Registrar self-check failures retain their typed spellings and return no proof.
