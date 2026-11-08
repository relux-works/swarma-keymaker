// Package publicationhandoff retains one already prepared certificate and its
// original, unverified publication reply. It has no transport or publication
// authority. These process-local values have no wire or persistence format.
package publicationhandoff

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/relux-works/swarma-envelope/record"
)

const MaxWireBytes = 8192

// MaxReplyBytes bounds opaque diagnostic retention only. It is not a registry
// proof, framing, error-body or transport budget.
const MaxReplyBytes = 8192

var (
	ErrInvalid     = errors.New("invalid prepared publication handoff")
	ErrConflict    = errors.New("original publication outcome conflict")
	ErrUnavailable = errors.New("authenticated publication view unavailable")
)

// Request is the exact original transaction and certificate, not a new registry
// request format. Its zero value is invalid. Equal content IDs do not permit
// substituting different signature or envelope bytes.
type Request struct {
	transaction string
	contentID   string
	envelope    string
	wire        string
}

func (r Request) Transaction() string { return r.transaction }
func (r Request) ContentID() string   { return r.contentID }
func (r Request) Envelope() string    { return r.envelope }
func (r Request) Wire() []byte        { return []byte(r.wire) }

type ReplyState uint8

const (
	NoReply ReplyState = iota
	UnverifiedReply
)

// Outcome is bound to the exact original request. A retained reply is never a
// verified publication, acknowledgement, activation or currentness decision.
type Outcome struct {
	original Request
	state    ReplyState
	reply    string
}

func (o Outcome) Original() Request { return o.original }
func (o Outcome) State() ReplyState { return o.state }
func (o Outcome) Reply() []byte     { return []byte(o.reply) }

// Handoff is bounded to one original operation and at most one retained reply.
// It performs no I/O and is not durable. The owning transaction's existing
// durability and reconciliation gates remain prerequisites for integration.
type Handoff struct {
	mu       sync.Mutex
	original Request
	outcome  Outcome
}

// Prepare checks retained bytes/math, including the original author signature.
// The caller must first validate its complete internal messageCertificate.
// This check does not appoint an issuer or authenticate a publishing principal.
func Prepare(transaction, envelope, contentID string) (*Handoff, error) {
	if len(transaction) != 32 || strings.ToLower(transaction) != transaction {
		return nil, ErrInvalid
	}
	if _, err := hex.DecodeString(transaction); err != nil || !record.IsContentID(contentID) || len(envelope) > base64.RawURLEncoding.EncodedLen(MaxWireBytes) {
		return nil, ErrInvalid
	}
	raw, err := record.DecodeBase64(envelope, -1)
	if err != nil || len(raw) == 0 || len(raw) > MaxWireBytes {
		return nil, ErrInvalid
	}
	value, err := record.Parse(raw, MaxWireBytes, 16)
	if err != nil {
		return nil, ErrInvalid
	}
	env, ok := value.(map[string]any)
	if !ok || len(env) != 4 || env["version"] != "swarm-envelope/2" || env["id"] != contentID {
		return nil, ErrInvalid
	}
	body, ok := env["body"].(map[string]any)
	if !ok || body["type"] != "attestation/1" || body["purpose"] != "swarma-msg" || body["key_class"] != "agent" {
		return nil, ErrInvalid
	}
	id, err := record.ContentID("attestation/1", body)
	if err != nil || id != contentID {
		return nil, ErrInvalid
	}
	issuer, ok := body["issuer"].(string)
	if !ok {
		return nil, ErrInvalid
	}
	sigs, ok := env["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return nil, ErrInvalid
	}
	sig, ok := sigs[0].(map[string]any)
	if !ok || len(sig) != 3 || sig["key"] != issuer || sig["role"] != "author" {
		return nil, ErrInvalid
	}
	encoded, ok := sig["sig"].(string)
	if !ok {
		return nil, ErrInvalid
	}
	signature, err := record.DecodeBase64(encoded, 64)
	preimage, preErr := record.SigningPreimage("attestation/1", issuer, "author", body)
	if err != nil || preErr != nil || record.VerifySignature(issuer, signature, preimage) != nil {
		return nil, ErrInvalid
	}
	r := Request{transaction, contentID, envelope, string(raw)}
	return &Handoff{original: r, outcome: Outcome{original: r, state: NoReply}}, nil
}

func (h *Handoff) Original() (Request, error) {
	if h == nil {
		return Request{}, ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.original.transaction == "" {
		return Request{}, ErrInvalid
	}
	return h.original, nil
}

// Retry returns the original operation for later reconciliation. It does not
// resend, allocate a transaction, renew a deadline, or presume a lost reply
// means failure. A future connector must resolve this same original operation.
func (h *Handoff) Retry(original Request) (Request, Outcome, error) {
	if h == nil {
		return Request{}, Outcome{}, ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.original.transaction == "" {
		return Request{}, Outcome{}, ErrInvalid
	}
	if original != h.original {
		return Request{}, Outcome{}, ErrConflict
	}
	return h.original, h.outcome, nil
}

// RetainReply retains only an opaque, bounded, unverified original outcome.
// Exact replay is idempotent. A different reply cannot overwrite retained
// evidence, even when the claimed transaction and content ID are unchanged.
func (h *Handoff) RetainReply(original Request, reply []byte) error {
	if h == nil || len(reply) == 0 || len(reply) > MaxReplyBytes {
		return ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.original.transaction == "" {
		return ErrInvalid
	}
	if original != h.original {
		return ErrConflict
	}
	if h.outcome.state == UnverifiedReply {
		if h.outcome.reply != string(reply) {
			return ErrConflict
		}
		return nil
	}
	h.outcome = Outcome{h.original, UnverifiedReply, string(reply)}
	return nil
}

// PublishedWire stays unavailable until the source owner supplies the real
// authenticated publishing principal, transport and complete resolved
// record/journal/checkpoint/witness proof mapping. Neither retained bytes nor
// any reply can manufacture that view. This package has no success route.
func (h *Handoff) PublishedWire() ([]byte, error) { return nil, ErrUnavailable }
