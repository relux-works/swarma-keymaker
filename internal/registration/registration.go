// Package registration builds registrar-owned registration/1 proofs from trusted
// enrollment data. It supplies no peer, binding, registry or transport authority.
package registration

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
	windows "github.com/relux-works/swarma-registrar/enrollment"
	format "github.com/relux-works/swarma-registrar/registration"
)

// Code is a stable local refusal or a registrar-owned signed-document verdict.
type Code string

const (
	OK                    Code = ""
	ClockUntrusted        Code = "clock_untrusted"
	EntropyUnavailable    Code = "entropy_unavailable"
	RequestExpired        Code = "request_expired"
	DeadlineExceeded      Code = "request_deadline_exceeded"
	KeyNotValidNow        Code = "key_not_valid_now"
	AudienceMismatch      Code = "audience_mismatch"
	EnrollmentUnsupported Code = "enrollment_unsupported"
)

// Input contains only request name/audience and public data from Authorize.
// Enrolled must come from current trusted enrollment authority, not a request.
type Input struct {
	Name     string
	Audience string
	Enrolled enrollment.EnrolledKey
}

// TrustedClock supplies the shared provider verdict, uncertainty and authority
// endpoint unchanged, and must honor cancellation.
// Builder additionally detects backward wall-time steps across all its proofs;
// a clock failure fences that Builder permanently. Recovery needs a new owner.
type TrustedClock interface {
	Sample(context.Context) (timeconf.Sample, error)
}

// Signer signs only the internally built registrar preimage with the admitted
// purpose-2 Ed25519 key. Failures use existing section-15 codes, not diagnostics.
// It must honor cancellation and allow concurrent calls. The core owns key
// selection and custody failures.
type Signer interface {
	Sign(context.Context, []byte) ([]byte, Code)
}

type Builder struct {
	clock     TrustedClock
	random    io.Reader
	signer    Signer
	clockMu   sync.Mutex
	entropyMu sync.Mutex
	last      time.Time
	fenced    bool
}

// New requires bounded trusted adapters. The Reader must supply CSPRNG bytes;
// an arbitrary deterministic Reader is suitable only for isolated test fixtures.
func New(clock TrustedClock, random io.Reader, signer Signer) (*Builder, error) {
	if clock == nil || random == nil || signer == nil {
		return nil, errors.New("registration: dependencies required")
	}
	return &Builder{clock: clock, random: random, signer: signer}, nil
}

func (b *Builder) sample(ctx context.Context) (timeconf.Sample, Code) {
	if ctx.Err() != nil {
		return timeconf.Sample{}, DeadlineExceeded
	}
	b.clockMu.Lock()
	defer b.clockMu.Unlock()
	if b.fenced {
		return timeconf.Sample{}, ClockUntrusted
	}
	v, err := b.clock.Sample(ctx)
	now := v.Now
	if ctx.Err() != nil {
		return timeconf.Sample{}, DeadlineExceeded
	}
	// Strip monotonic metadata: wall-clock rollback must remain visible even when
	// the Go monotonic clock continues forward through a UTC correction.
	now = now.Round(0).UTC()
	if err != nil || !timeconfidence.Valid(v) || !b.last.IsZero() && now.Before(b.last) {
		b.fenced = true
		return timeconf.Sample{}, ClockUntrusted
	}
	b.last = now
	v.Now = now
	return v, OK
}

func (b *Builder) now(ctx context.Context) (time.Time, Code) { v, c := b.sample(ctx); return v.Now, c }

// Proof has immutable bytes and validity data. Envelope returns a copy; it is not
// release authority. Integration must call Recheck inside its final authority
// barrier after durable audit and before writing, plus revalidate enrollment and
// binding separately. This pure layer does not retain transport request IDs.
type Proof struct {
	raw             []byte
	issued, expires time.Time
	authorityUntil  time.Time
	window          windows.Window
	builder         *Builder
}

func (p *Proof) Envelope() []byte {
	if p == nil {
		return nil
	}
	return append([]byte(nil), p.raw...)
}

// Keep the provider's uncertainty unchanged; authorization must contain both
// extremes. Earlier key/expiry refusal precedence is retained when bounds end
// together. A later sample never extends this proof's original exclusive grant.
func (p *Proof) validAt(v timeconf.Sample) Code {
	now := v.Now
	if !p.window.ValidAt(p.issued.Unix(), now.Add(-v.Uncertainty).Unix()) || !p.window.ValidAt(p.issued.Unix(), now.Add(v.Uncertainty).Unix()) {
		return KeyNotValidNow
	}
	if !now.Add(v.Uncertainty).Before(p.expires) {
		return RequestExpired
	}
	if !now.Add(v.Uncertainty).Before(p.authorityUntil) {
		return ClockUntrusted
	}
	return OK
}

// Recheck reads trusted time afresh; callers cannot supply a substitute timestamp.
func (p *Proof) Recheck(ctx context.Context) Code {
	if p == nil || p.builder == nil {
		return RequestExpired
	}
	v, code := p.builder.sample(ctx)
	if code != "" {
		return code
	}
	return p.validAt(v)
}

// Build accepts no caller body, key selector, nonce, timestamp, TTL or preimage.
// Format construction, validation, encoding and strict signature verification
// all belong to the pinned registrar package. No envelope escapes on refusal.
func (b *Builder) Build(ctx context.Context, in Input) (*Proof, Code) {
	v, code := b.sample(ctx)
	now := v.Now
	if code != "" {
		return nil, code
	}
	issued := now.Truncate(time.Second)
	window := windows.Window{Key: in.Enrolled.Key, NotBefore: in.Enrolled.NotBefore, NotAfter: in.Enrolled.NotAfter}
	if !window.ValidAt(issued.Unix(), now.Add(-v.Uncertainty).Unix()) || !window.ValidAt(issued.Unix(), now.Add(v.Uncertainty).Unix()) {
		return nil, KeyNotValidNow
	}
	nonce := make([]byte, 16)
	b.entropyMu.Lock()
	_, err := io.ReadFull(b.random, nonce)
	b.entropyMu.Unlock()
	if err != nil {
		return nil, EntropyUnavailable
	}
	if ctx.Err() != nil {
		return nil, DeadlineExceeded
	}
	body := format.Body{Key: in.Enrolled.Key, Name: in.Name, Audience: in.Audience, Nonce: nonce, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(120 * time.Second).Format(time.RFC3339)}
	canonical, preimage, err := format.Build(body, in.Enrolled.Audience)
	if err != nil {
		return nil, registrarCode(err)
	}
	if err = format.Check(canonical, in.Enrolled.Audience); err != nil {
		return nil, registrarCode(err)
	}
	// Name checks use the trusted configured audience before exact comparison.
	if in.Audience != in.Enrolled.Audience {
		return nil, AudienceMismatch
	}
	// This is the local algorithm policy, not a key decoder or point validator.
	if !strings.HasPrefix(in.Enrolled.Key, "ed25519:") {
		return nil, EnrollmentUnsupported
	}
	signature, code := b.signer.Sign(ctx, preimage)
	if ctx.Err() != nil {
		return nil, DeadlineExceeded
	}
	if code != "" {
		return nil, code
	}
	raw, err := format.Assemble(canonical, signature)
	if err != nil {
		return nil, registrarCode(err)
	}
	if _, err := format.Verify(raw); err != nil {
		return nil, registrarCode(err)
	}
	proof := &Proof{raw: raw, issued: issued, expires: issued.Add(120 * time.Second), window: window, builder: b, authorityUntil: v.AuthorityUntil}
	if code = proof.Recheck(ctx); code != "" {
		return nil, code
	}
	return proof, OK
}

func registrarCode(err error) Code {
	var refusal *format.Error
	if errors.As(err, &refusal) {
		return Code(refusal.Code)
	}
	// The pinned API promises typed errors; an unexpected failure still returns
	// no document and never turns an implementation diagnostic into a wire code.
	return Code(format.RegistrationMalformed)
}

// Time samples the same trusted rollback-detecting clock used by Build/Recheck.
// It grants no enrollment or release authority.
func (b *Builder) Time(ctx context.Context) (time.Time, Code) { return b.now(ctx) }

// Restore revalidates a durably retained envelope without signing or consuming
// entropy. Current enrollment and binding authority remain the caller's duty.
func (b *Builder) Restore(ctx context.Context, raw []byte, in Input) (*Proof, Code) {
	return b.restore(ctx, raw, in, time.Time{})
}

// Reauthorize verifies the same prepared bytes against current enrollment and a
// fresh confidence observation, preserving the original exclusive clock grant.
// Use it at the live release barrier; Restore is only for previously retained
// bytes being prepared under a new request's independent observation.
func (p *Proof) Reauthorize(ctx context.Context, in Input) (*Proof, Code) {
	if p == nil || p.builder == nil || p.authorityUntil.IsZero() {
		return nil, RequestExpired
	}
	return p.builder.restore(ctx, p.raw, in, p.authorityUntil)
}

func (b *Builder) restore(ctx context.Context, raw []byte, in Input, authorityUntil time.Time) (*Proof, Code) {
	body, err := format.Verify(raw)
	if err != nil {
		return nil, registrarCode(err)
	}
	if body.Key != in.Enrolled.Key {
		return nil, Code("key_not_enrolled")
	}
	if body.Name != in.Name {
		return nil, Code("name_not_permitted")
	}
	if body.Audience != in.Audience || in.Audience != in.Enrolled.Audience {
		return nil, AudienceMismatch
	}
	canonical, _, err := format.Build(*body, in.Enrolled.Audience)
	if err != nil {
		return nil, registrarCode(err)
	}
	if err := format.Check(canonical, in.Enrolled.Audience); err != nil {
		return nil, registrarCode(err)
	}
	issued, err := time.Parse(time.RFC3339, body.IssuedAt)
	if err != nil {
		return nil, RequestExpired
	}
	expires, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil || !expires.Equal(issued.Add(120*time.Second)) {
		return nil, RequestExpired
	}
	proof := &Proof{raw: append([]byte(nil), raw...), issued: issued, expires: expires, window: windows.Window{Key: in.Enrolled.Key, NotBefore: in.Enrolled.NotBefore, NotAfter: in.Enrolled.NotAfter}, builder: b}
	v, code := b.sample(ctx)
	now := v.Now
	if authorityUntil.IsZero() {
		authorityUntil = v.AuthorityUntil
	}
	proof.authorityUntil = authorityUntil
	if code != OK {
		return nil, code
	}
	if now.Before(issued) {
		// A verified retained proof carries the earlier owner's trusted issue time.
		// This rollback evidence must fence fresh builds too, even after restart.
		b.clockMu.Lock()
		b.fenced = true
		b.clockMu.Unlock()
		return nil, ClockUntrusted
	}
	if code := proof.validAt(v); code != OK {
		return nil, code
	}
	return proof, OK
}
