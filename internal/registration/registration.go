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

	"github.com/relux-works/swarma-keymaker/internal/enrollment"
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

// TrustedClock supplies synchronized UTC health and must honor cancellation.
// Builder additionally detects backward wall-time steps across all its proofs;
// a clock failure fences that Builder permanently. Recovery needs a new owner.
type TrustedClock interface {
	Now(context.Context) (time.Time, bool)
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

func (b *Builder) now(ctx context.Context) (time.Time, Code) {
	if ctx.Err() != nil {
		return time.Time{}, DeadlineExceeded
	}
	b.clockMu.Lock()
	defer b.clockMu.Unlock()
	if b.fenced {
		return time.Time{}, ClockUntrusted
	}
	now, trusted := b.clock.Now(ctx)
	if ctx.Err() != nil {
		return time.Time{}, DeadlineExceeded
	}
	// Strip monotonic metadata: wall-clock rollback must remain visible even when
	// the Go monotonic clock continues forward through a UTC correction.
	now = now.Round(0).UTC()
	if !trusted || now.IsZero() || !b.last.IsZero() && now.Before(b.last) {
		b.fenced = true
		return time.Time{}, ClockUntrusted
	}
	b.last = now
	return now, OK
}

// Proof has immutable bytes and validity data. Envelope returns a copy; it is not
// release authority. Integration must call Recheck inside its final authority
// barrier after durable audit and before writing, plus revalidate enrollment and
// binding separately. This pure layer does not retain transport request IDs.
type Proof struct {
	raw             []byte
	issued, expires time.Time
	window          windows.Window
	builder         *Builder
}

func (p *Proof) Envelope() []byte {
	if p == nil {
		return nil
	}
	return append([]byte(nil), p.raw...)
}
func (p *Proof) validAt(now time.Time) Code {
	if !p.window.ValidAt(p.issued.Unix(), now.Unix()) {
		return KeyNotValidNow
	}
	if !now.Before(p.expires) {
		return RequestExpired
	}
	return OK
}

// Recheck reads trusted time afresh; callers cannot supply a substitute timestamp.
func (p *Proof) Recheck(ctx context.Context) Code {
	if p == nil || p.builder == nil {
		return RequestExpired
	}
	now, code := p.builder.now(ctx)
	if code != "" {
		return code
	}
	return p.validAt(now)
}

// Build accepts no caller body, key selector, nonce, timestamp, TTL or preimage.
// Format construction, validation, encoding and strict signature verification
// all belong to the pinned registrar package. No envelope escapes on refusal.
func (b *Builder) Build(ctx context.Context, in Input) (*Proof, Code) {
	now, code := b.now(ctx)
	if code != "" {
		return nil, code
	}
	issued := now.Truncate(time.Second)
	window := windows.Window{Key: in.Enrolled.Key, NotBefore: in.Enrolled.NotBefore, NotAfter: in.Enrolled.NotAfter}
	if !window.ValidAt(issued.Unix(), now.Unix()) {
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
	proof := &Proof{raw: raw, issued: issued, expires: issued.Add(120 * time.Second), window: window, builder: b}
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
