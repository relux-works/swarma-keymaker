package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
	format "github.com/relux-works/swarma-registrar/registration"
)

// RegistrationHelper has one configured host key and trusted dependencies. No
// request can select its path, key, clock, entropy or enrollment policy.
type RegistrationHelper struct {
	authority *enrollment.Authority
	builder   *proof.Builder
	key       string
}

type registrationSigner struct {
	master *Master
	path   string
}

func (s registrationSigner) Sign(ctx context.Context, preimage []byte) ([]byte, proof.Code) {
	if auditContextExpired(ctx) {
		return nil, proof.DeadlineExceeded
	}
	// Only Builder can reach this private adapter. Its preimage remains owned by
	// the registrar; surface A cannot call this purpose-selecting operation.
	signature, code, cause := s.master.withPurposeCause(s.path, "host-registration", func(k ed25519.PrivateKey) []byte { return ed25519.Sign(k, preimage) })
	if connection := connectionFrom(ctx); connection != nil {
		connection.custodyCause = cause
	}
	if auditContextExpired(ctx) {
		return nil, proof.DeadlineExceeded
	}
	return signature, proof.Code(code)
}

func NewRegistrationHelper(master *Master, path string, authority *enrollment.Authority, clock proof.TrustedClock, random io.Reader) (*RegistrationHelper, error) {
	if master == nil || authority == nil {
		return nil, failure("registration dependencies unavailable")
	}
	public, code := master.withPurpose(path, "host-registration", func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k[32:]...) })
	if code != "" {
		return nil, code
	}
	builder, err := proof.New(clock, random, registrationSigner{master, path})
	if err != nil {
		return nil, err
	}
	return &RegistrationHelper{authority: authority, builder: builder, key: "ed25519:" + base64.RawURLEncoding.EncodeToString(public)}, nil
}

func helperParams(r control.Request) (string, string, Code) {
	if !exactMembers(r.Params, "name", "aud") {
		return "", "", "request_malformed"
	}
	name, nok := r.Params["name"].(string)
	aud, aok := r.Params["aud"].(string)
	if !nok || !aok {
		return "", "", "request_malformed"
	}
	return name, aud, ""
}
func helperEnvelope(obj control.Object) ([]byte, Code) {
	if !exactMembers(obj, "envelope") {
		return nil, "audit_unavailable"
	}
	envelope, ok := obj["envelope"].(control.Object)
	if !ok {
		return nil, "audit_unavailable"
	}
	raw, err := control.Marshal(envelope)
	if err != nil {
		return nil, "audit_unavailable"
	}
	return raw, ""
}
func helperIssued(raw []byte, now time.Time) (time.Time, Code) {
	if raw == nil {
		return now.Truncate(time.Second), ""
	}
	body, err := format.Verify(raw)
	if err != nil {
		return time.Time{}, "audit_unavailable"
	}
	issued, err := time.Parse(time.RFC3339, body.IssuedAt)
	if err != nil {
		return time.Time{}, "audit_unavailable"
	}
	return issued, ""
}

// Lock order on both preparation and release: generation -> binding/result
// Store -> enrollment read barrier. No reload/revocation can overtake a write.
func (n *Native) signRegistration(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {
	name, aud, code := helperParams(r)
	if code != "" {
		return nil, control.Code(code)
	}
	var result control.Object
	c := n.Engine.Generations.WithActive(ctx, peer.UID, peer.Generation, func(ctx context.Context) Code {
		s := n.Engine.Store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		b, c := s.lookup(peer.UID, peer.Generation)
		if c != "" {
			return c
		}
		conn := connectionFrom(ctx)
		if c := conn.pin(s, b); c != "" {
			return c
		}
		h := n.Config.Helper
		if h == nil {
			return "enrollment_unavailable"
		}
		old, c := s.retained(nativePrincipal(peer), r)
		if c != "" {
			return c
		}
		var raw []byte
		if old != nil {
			result, c = s.resultObject(old)
			if c != "" {
				return c
			}
			raw, c = helperEnvelope(result)
			if c != "" {
				return c
			}
		}
		now, pc := h.builder.Time(ctx)
		if pc != "" {
			return Code(pc)
		}
		issued, c := helperIssued(raw, now)
		if c != "" {
			return c
		}
		return Code(h.authority.WithAuthorized(ctx, peer.UID, peer.Generation, h.key, name, aud, issued, now, func(enrolled enrollment.EnrolledKey) enrollment.Code {
			if c := n.helperCredit(h.key, name); c != "" {
				return enrollment.Code(c)
			}
			in := proof.Input{Name: name, Audience: aud, Enrolled: enrolled}
			if old != nil {
				_, pc := h.builder.Restore(ctx, raw, in)
				return enrollment.Code(pc)
			}
			built, pc := h.builder.Build(ctx, in)
			if pc != "" {
				return enrollment.Code(pc)
			}
			envelope, err := control.Decode(built.Envelope())
			if err != nil {
				return "audit_unavailable"
			}
			result = control.Object{"envelope": envelope}
			encoded, err := control.Marshal(result)
			if err != nil {
				return "audit_unavailable"
			}
			args, c := requestArguments(r)
			if c != "" {
				return enrollment.Code(c)
			}
			entry := retainedRequest{Caller: nativePrincipal(peer), ID: r.ID, Method: r.Method, Arguments: string(args), Status: "committed", Result: encoded}
			prospective := append(append([]retainedRequest(nil), s.requests...), entry)
			if !s.fitsState(s.records, s.next, prospective) {
				return "state_capacity_exceeded"
			}
			record := n.record(&peer, r, args, "")
			record.Result = "unknown"
			if c := n.auditContext(ctx, record); c != "" {
				return enrollment.Code(c)
			}
			// Retain before release, including a lost response. Serialization prevents
			// concurrent same-ID attempts from ever obtaining a second signed nonce.
			s.appendRequest(entry)
			if c := s.persistContext(ctx); c != "" {
				s.failed = true
				n.Engine.fail()
				return enrollment.Code(c)
			}
			return ""
		}))
	})
	return result, control.Code(c)
}

// Called only inside Native.WithActive's generation barrier and Store lock.
func (n *Native) releaseRegistration(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) Code {
	s := n.Engine.Store
	if _, c := s.lookup(peer.UID, peer.Generation); c != "" {
		return c
	}
	h := n.Config.Helper
	if h == nil {
		return "enrollment_unavailable"
	}
	name, aud, c := helperParams(r)
	if c != "" {
		return c
	}
	prior, c := s.retained(nativePrincipal(peer), r)
	if c != "" {
		return c
	}
	encoded, err := control.Marshal(result)
	if err != nil || prior == nil || !bytes.Equal(encoded, prior.Result) {
		return "audit_unavailable"
	}
	raw, c := helperEnvelope(result)
	if c != "" {
		return c
	}
	now, pc := h.builder.Time(ctx)
	if pc != "" {
		return Code(pc)
	}
	issued, c := helperIssued(raw, now)
	if c != "" {
		return c
	}
	return Code(h.authority.WithAuthorized(ctx, peer.UID, peer.Generation, h.key, name, aud, issued, now, func(enrolled enrollment.EnrolledKey) enrollment.Code {
		retained, pc := h.builder.Restore(ctx, raw, proof.Input{Name: name, Audience: aud, Enrolled: enrolled})
		if pc != "" {
			return enrollment.Code(pc)
		}
		args, _ := requestArguments(r)
		if c := n.auditContext(ctx, n.record(&peer, r, args, "")); c != "" {
			return enrollment.Code(c)
		}
		// Durable evidence may take time. Sample again immediately before release.
		if pc := retained.Recheck(ctx); pc != "" {
			return enrollment.Code(pc)
		}
		if auditContextExpired(ctx) {
			return "request_deadline_exceeded"
		}
		return enrollment.Code(release(ctx))
	}))
}

// In addition to the shared per-peer/global budgets, section 10 limits each
// admitted host key/name to two helper operations per second, burst four.
func (n *Native) helperCredit(key, name string) Code {
	n.helperMu.Lock()
	defer n.helperMu.Unlock()
	now := n.Engine.rateNow()
	index := key + "\x00" + name
	b := n.helpers[index]
	if b == nil {
		if len(n.helpers) >= 4096 {
			for k, b := range n.helpers {
				if now.Sub(b.last) > 2*time.Second {
					delete(n.helpers, k)
				}
			}
			if len(n.helpers) >= 4096 {
				return "busy"
			}
		}
		b = &bucket{}
		n.helpers[index] = b
	}
	if !b.take(now, 2, 4) {
		return "rate_limited"
	}
	return ""
}
