package keymaker

import (
	"encoding/json"
	"fmt"

	"github.com/relux-works/swarma-envelope/verifier"
)

// These adapters have no serving constructor, persistence dependency or effect
// permit. Their caller must supply independently authenticated protected facts
// and the complete evidence inventory. Real publisher/WC1/time custody and an
// atomic accepted-proof/anchor/W transaction remain K3 activation prerequisites.
type messageProofRoute uint8

const (
	messageIntakeProof messageProofRoute = iota
	messageFullProof
)

// Control contains original encoded control/transport evidence, not summaries.
// WitnessWrapper is the entire encoded WC1 real-head wrapper including its LF.
// JSON encoding below accounts for every field, including base64/escaping and
// the context's original prior checkpoint, snapshots and witness facts.
// Receipt is process-local and deliberately has no encoded representation.
type messageProofInput struct {
	Route          messageProofRoute
	Chain          [][]byte
	Checkpoint     []byte
	Conflict       []byte
	Envelope       []byte
	IDs            []string
	Keys           []string
	Key            string
	Reference      string
	Device         bool
	WitnessWrapper []byte
	Control        []string
	Receipt        *verifier.FreshnessReceipt `json:"-"`
	RequireReceipt bool
	MarginSeconds  int64
}

// One context retains one immutable Evidence lifetime. encoded is only the
// complete size-accounting image; it is never decoded to recreate Evidence or
// used as persistence authority. Neither map is exposed to a serving caller.
type messageProofContext struct {
	facts   verifier.Context
	encoded map[string]json.RawMessage
}

func newMessageProofContext(values map[string]any) (*messageProofContext, error) {
	return (&messageProofContext{}).updated(values)
}

// updated preserves every unchanged Evidence identity, especially snapshots.
// Replacing even byte-identical revocations starts a new lifetime; the library
// then rejects an old receipt. No timestamps or unavailable facts are inferred.
func (p *messageProofContext) updated(values map[string]any) (*messageProofContext, error) {
	n := &messageProofContext{facts: p.facts, encoded: make(map[string]json.RawMessage, len(p.encoded)+len(values))}
	for k, v := range p.encoded {
		n.encoded[k] = v
	}
	c := &n.facts
	slots := map[string]*verifier.Evidence{
		"freshness_anchor": &c.FreshnessAnchor, "witness_read_at": &c.WitnessReadAt,
		"service_authority": &c.ServiceAuthority, "service_attestations": &c.ServiceAttestations,
		"registry_owner": &c.RegistryOwner, "journal_witness": &c.JournalWitness,
		"commit_signing_key": &c.CommitSigningKey, "enrollment_publisher": &c.EnrollmentPublisher,
		"audience": &c.Audience, "required_roles": &c.RequiredRoles, "known_keys": &c.AdmittedKeys,
		"root": &c.GrantRoot, "service_root": &c.ServiceRoot, "agent_revocation_root": &c.AgentRevocationRoot,
		"operator_root": &c.OperatorRoot, "operator_owner": &c.OperatorOwner,
		"attestations": &c.Attestations, "agent_attestation_ids": &c.AgentAttestationIDs,
		"operator_attestations": &c.DeviceAttestations, "active_generations": &c.CurrentGenerations,
		"revocations": &c.SignedSnapshots, "time": &c.Time, "now": &c.Now,
		"watermark_available": &c.WatermarkAvailable, "watermark": &c.Watermark,
		"id_journal_available": &c.IDJournalAvailable, "seen": &c.IDJournal,
		"replay_available": &c.ReplayAvailable, "used_actions": &c.UsedActions,
		"signer_facts": &c.SignerFacts, "assurance": &c.Assurance,
		"delivery": &c.Delivery, "binding": &c.ActBinding,
	}
	for name, value := range values {
		slot, ok := slots[name]
		if !ok {
			return nil, fmt.Errorf("unsupported protected fact %q", name)
		}
		// Present rejects unsupported values, depth/cycles and oversized slots;
		// in particular it cannot reconstruct a receipt from protected input.
		e, err := verifier.Present(value)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		*slot, n.encoded[name] = e, raw
	}
	return n, nil
}

func (p *messageProofContext) proofSize(in messageProofInput) (int, error) {
	raw, err := json.Marshal(struct {
		Context map[string]json.RawMessage
		Input   messageProofInput
	}{p.encoded, in})
	return len(raw), err
}

// Outer limits are independent of the verifier's J/F count/per-record limits.
// Passing a gate neither authenticates a WC1 wrapper nor qualifies real facts.
func (p *messageProofContext) check(in messageProofInput) string {
	limit := 524288
	switch in.Route {
	case messageIntakeProof:
	case messageFullProof:
		limit = 2097152
	default:
		return "message_proof_invalid"
	}
	if len(in.WitnessWrapper) > 8192 {
		return "message_witness_too_large"
	}
	n, err := p.proofSize(in)
	if err != nil {
		return "message_proof_invalid"
	}
	if n > limit {
		return "message_proof_too_large"
	}
	return ""
}

func (p *messageProofContext) verifyJournal(in messageProofInput) verifier.Result {
	if code := p.check(in); code != "" {
		return verifier.Result{Code: code}
	}
	// Raw anchor stays in Chain; separately authenticated exact prior stays in
	// IDJournal. S4 performs signature/scope/head/time comparisons itself. A
	// conflict checkpoint is never substituted for the protected prior.
	return verifier.New(p.facts).VerifyJournal(in.Chain, in.Checkpoint, in.Conflict)
}

type messageFreshnessAudit struct {
	Origin                           verifier.FreshnessAudit
	SkippedPublications              int64
	OldFreshnessID, NewFreshnessID   string
	OldCheckpointID, NewCheckpointID string
}

type messageFreshnessResult struct {
	verifier.Result
	Audit *messageFreshnessAudit
}

// Even the containing admission result is deliberately not a durable artifact.
func (messageFreshnessResult) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("freshness admission is process-local")
}

func (p *messageProofContext) verifyFreshness(in messageProofInput, reanchor bool) messageFreshnessResult {
	if code := p.check(in); code != "" {
		return messageFreshnessResult{Result: verifier.Result{Code: code}}
	}
	var r verifier.Result
	if reanchor {
		// Explicit sibling operation; failed catch-up never selects this mode.
		if len(in.Chain) != 1 {
			return messageFreshnessResult{Result: verifier.Result{Code: "freshness_malformed"}}
		}
		r = verifier.New(p.facts).VerifyFreshnessReanchor(in.Chain[0], in.Checkpoint, in.IDs, in.Keys)
	} else {
		r = verifier.New(p.facts).VerifyFreshness(in.Chain, in.Checkpoint, in.IDs, in.Keys)
	}
	out := messageFreshnessResult{Result: r}
	if r.Code != "accept" {
		return out
	}
	origin, ok := r.FreshnessReceipt.Audit()
	if !ok {
		return messageFreshnessResult{Result: verifier.Result{Code: "freshness_receipt_invalid"}}
	}
	// Old endpoint IDs are audit-only projections of the same admitted anchor.
	// Exact endpoint bytes and atomic audit custody are still K3-G6 requirements.
	var old struct {
		FreshnessID  string `json:"freshness_id"`
		CheckpointID string `json:"checkpoint_id"`
	}
	if err := json.Unmarshal(p.encoded["freshness_anchor"], &old); err != nil {
		return messageFreshnessResult{Result: verifier.Result{Code: "freshness_state_invalid"}}
	}
	out.Audit = &messageFreshnessAudit{Origin: origin, OldFreshnessID: old.FreshnessID, OldCheckpointID: old.CheckpointID, NewFreshnessID: origin.FreshnessID, NewCheckpointID: origin.CheckpointID}
	if r.Plan.Reanchor != nil {
		out.Audit.SkippedPublications = r.Plan.Reanchor.SkippedPublications
	}
	return out
}

func (p *messageProofContext) consumer(in messageProofInput) verifier.Verifier {
	c := p.facts
	c.FreshnessReceipt = in.Receipt
	c.RequireFreshnessReceipt = in.RequireReceipt
	c.FreshnessMarginSeconds = in.MarginSeconds
	return verifier.New(c)
}

func (p *messageProofContext) verifyAttestation(in messageProofInput) (verifier.Attestation, string) {
	if code := p.check(in); code != "" {
		return verifier.Attestation{}, code
	}
	// S5 decides which bound registry age may be renewed. Device/operator
	// snapshots and nil-receipt legacy consumers retain their own age gates.
	a, err := p.consumer(in).VerifyAttestation(in.Key, in.Reference, in.Device)
	return a, messageEvidenceCode(err)
}

func (p *messageProofContext) verifyMessage(in messageProofInput) verifier.Result {
	if code := p.check(in); code != "" {
		return verifier.Result{Code: code}
	}
	return p.consumer(in).VerifyMessage(in.Envelope)
}
