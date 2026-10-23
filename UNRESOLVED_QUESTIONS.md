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

## Option C external witness: specification and activation gates

The [witness supplement](spec/keymaker-witness.md) proposes Keymaker's own
complete-state commitment and separate consumer stream, following the accepted
external-intent direction in the
[registrar specification, section 4.5](https://github.com/relux-works/swarma-registrar/blob/5f44ebf3f78829144aa7864ca2e4ad62bea43eb5/spec/registrar.md#45-external-high-water-witness-option-c-normative-draft).
Its [normative change list](spec/keymaker-witness.md#9-normative-changes-to-existing-sections)
is for curator review; no implementation, qualification or activation is claimed.
The enrollment restore residual below remains **open** until those steps land.
An unconsumed approval restored with old consumed-ID/state evidence, including
a snapshot restored inside its TTL, has no independent freshness proof under A.
C would detect a restored older epoch or unresolved external intent; local
receipt equality and boot/TTL checks cannot provide that guarantee.

| Question | Direction / remaining decision and evidence |
| --- | --- |
| WC1: placement | Owner chooses an independently administered restore/failure boundary and independently surviving checkpoint. No location is selected here; joint host/witness loss or undetectable joint rollback remains outside the guarantee. |
| WC2: clock and freshness | Qualify authoritative serialized latest reads, challenge-bound signed replies, post-restore unpredictable entropy, transport/authentication, bounded framing/proofs and operation deadlines. Wall-clock freshness/TTL alone is insufficient; existing trusted-time checks remain. |
| WC3: Keymaker consumer stream | Separate Keymaker/station stream is the accepted direction. Qualify protected station/lineage enrollment, ACLs, exact artifact inventory/manifest and continuity-preserving migration. Registrar receipts cannot reconcile this consumer. |
| Witness key custody | Curator must approve internal SLIP-0010 purpose 3 and qualify writer custody, independent witness verifier-key provisioning, purpose binding, rotation/revocation and lost-master recovery without resetting the stream/epoch. No socket gains a witness-key operation. |
| WC4: single active instance | Qualify exclusion of an older serving instance throughout authority use, including restored clones. Local flock or witness compare-head writes alone do not fence its signatures. |
| WC5: lifecycle and cost | Publish cross-privilege commit coordination, C-specific receipt ordering, bootstrap, exact-candidate privileged recovery, explicit A fallback/re-entry and loss-of-evidence handling. Qualify two witness durability round trips per logical commit, including all A success audits, within existing budgets. Cancellation/replacement of an unresolved intent is not inferred from local bytes. |

Boot identity, ten-minute TTL and one-use consumption remain required whenever
an A approval is used. A fresh equal C head would replace per-start A approval
only in activated C; historical consumed IDs and pending evidence remain
protected. An outage never automatically switches modes. Every item above
remains open for activation; unchanged-code checks cannot close it.

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

## Offline packaging baseline gates

- The optional enrollment input refuses `enrollment validation unavailable at
  this revision`. The follow-up after PR #5 must integrate its validator/pins and
  qualify offline dependency inputs; no syntax-only substitute is shipped.
- The existing control_gid field has no native control-socket effect in this
  baseline. That effect and the later operator_uid field depend on PR #6.
- Section 12.1 creates the master seed parent but not the dedicated child
  state_dir expected by the custody loader. The owner must reconcile this
  provisioning gap before activation. Packaging records the dependency without
  adding another root procedure or changing the normative runbook.
