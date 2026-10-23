package registration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	format "github.com/relux-works/swarma-registrar/registration"
)

type clockFixture struct {
	mu      sync.Mutex
	at      time.Time
	trusted bool
}

func (c *clockFixture) Now(context.Context) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at, c.trusted
}
func (c *clockFixture) set(at time.Time, trusted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at, c.trusted = at, trusted
}

type signFunc func(context.Context, []byte) ([]byte, Code)

func (f signFunc) Sign(ctx context.Context, p []byte) ([]byte, Code) { return f(ctx, p) }

type fixture struct {
	builder *Builder
	clock   *clockFixture
	in      Input
	key     ed25519.PrivateKey
	calls   int
	seen    []byte
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 1, 0, 1, 0, 456000000, time.FixedZone("offset", 3600)).UTC()
	f := &fixture{key: key, clock: &clockFixture{at: now, trusted: true}}
	f.in = Input{Name: "host-a_project_role", Audience: "example.org", Enrolled: enrollment.EnrolledKey{Key: "ed25519:" + base64.RawURLEncoding.EncodeToString(pub), Audience: "example.org", NotBefore: now.Unix() - 300, NotAfter: now.Unix() + 1000}}
	f.builder, err = New(f.clock, rand.Reader, signFunc(func(_ context.Context, p []byte) ([]byte, Code) {
		f.calls++
		f.seen = append([]byte(nil), p...)
		return ed25519.Sign(f.key, p), OK
	}))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func built(t *testing.T, f *fixture) *Proof {
	t.Helper()
	p, c := f.builder.Build(context.Background(), f.in)
	if c != "" || p == nil {
		t.Fatalf("valid proof failed: %s", c)
	}
	if _, err := format.Verify(p.Envelope()); err != nil {
		t.Fatal(err)
	}
	return p
}
func denied(t *testing.T, f *fixture, want Code) {
	t.Helper()
	p, c := f.builder.Build(context.Background(), f.in)
	if p != nil || c != want {
		t.Fatalf("proof refusal=%s envelope=%t want=%s", c, p != nil, want)
	}
}

// Invalid dependencies reject at construction, beside the same valid adapters.
func TestDependencies(t *testing.T) {
	f := setup(t)
	for _, which := range []string{"clock", "entropy", "signer"} {
		t.Run(which, func(t *testing.T) {
			var c TrustedClock = f.clock
			var r io.Reader = rand.Reader
			var s Signer = f.builder.signer
			switch which {
			case "clock":
				c = nil
			case "entropy":
				r = nil
			case "signer":
				s = nil
			}
			if b, err := New(c, r, s); b != nil || err == nil {
				t.Fatal("missing dependency accepted")
			}
			built(t, setup(t))
		})
	}
}

// Caller authority is limited to name/audience. A weakening that adds and uses
// an issue-time selector must not move the proof away from trusted UTC.
func TestNoCallerTime(t *testing.T) {
	f := setup(t)
	in := f.in
	v := reflect.ValueOf(&in).Elem()
	if field := v.FieldByName("IssuedAt"); field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(f.clock.at.Add(-10 * time.Second)))
	}
	p, c := f.builder.Build(context.Background(), in)
	if c != "" || p == nil {
		t.Fatal("caller iat affected proof construction")
	}
	b, err := format.Verify(p.Envelope())
	if err != nil {
		t.Fatal(err)
	}
	want := f.clock.at.Truncate(time.Second).Format(time.RFC3339)
	if b.IssuedAt != want {
		t.Fatal("caller iat affected proof construction")
	}
	typ := reflect.TypeOf(Input{})
	if typ.NumField() != 3 {
		t.Fatal("caller body/key/nonce/time/TTL field added")
	}
	for _, name := range []string{"Name", "Audience", "Enrolled"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Fatal("missing valid input field")
		}
	}
}

// Separate fresh requests consume separate entropy. With deterministic distinct
// fixture bytes the nonces differ exactly; signatures/IDs still verify upstream.
func TestFreshNonce(t *testing.T) {
	f := setup(t)
	f.builder.random = bytes.NewReader(append(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)...))
	a, b := built(t, f), built(t, f)
	first, _ := format.Verify(a.Envelope())
	second, _ := format.Verify(b.Envelope())
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("fresh builds reused nonce")
	}
	if !bytes.Equal(first.Nonce, bytes.Repeat([]byte{1}, 16)) || !bytes.Equal(second.Nonce, bytes.Repeat([]byte{2}, 16)) {
		t.Fatal("nonce did not come from full independent entropy reads")
	}
}

// Short/error entropy never reaches signing. A complete 16-byte read still
// builds a valid proof. io.ReadFull must join short reads, not reject them all.
func TestEntropyFailures(t *testing.T) {
	for _, which := range []string{"short", "error"} {
		t.Run(which, func(t *testing.T) {
			f := setup(t)
			if which == "short" {
				f.builder.random = bytes.NewReader(make([]byte, 15))
			} else {
				f.builder.random = errorReader{}
			}
			denied(t, f, EntropyUnavailable)
			if f.calls != 0 {
				t.Fatal("entropy refusal reached signer")
			}
			control := setup(t)
			control.builder.random = oneByteReader{bytes.NewReader(make([]byte, 16))}
			built(t, control)
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("test-only entropy fault") }

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:1]) }

// An unhealthy clock or any backward wall step fences this Builder. Recovery of
// the source alone cannot reopen it; a new healthy Builder is a positive control.
func TestClockRefusals(t *testing.T) {
	for _, which := range []string{"untrusted", "rollback", "subsecond"} {
		t.Run(which, func(t *testing.T) {
			f := setup(t)
			initial := f.clock.at
			if which == "untrusted" {
				f.clock.set(initial, false)
			} else {
				built(t, f)
				step := time.Second
				if which == "subsecond" {
					step = time.Nanosecond
				}
				f.clock.set(initial.Add(-step), true)
			}
			calls := f.calls
			denied(t, f, ClockUntrusted)
			if f.calls != calls {
				t.Fatal("clock refusal signed")
			}
			f.clock.set(initial.Add(time.Second), true)
			denied(t, f, ClockUntrusted)
			built(t, setup(t))
		})
	}
}

// Both half-open edges apply separately at issue and release with no skew.
// A proof TTL may outlast its key window, but such a proof cannot be released.
func TestKeyWindow(t *testing.T) {
	for _, which := range []string{"issue-before", "issue-at-end", "release-at-end", "empty", "reversed"} {
		t.Run(which, func(t *testing.T) {
			f := setup(t)
			now := f.clock.at.Unix()
			switch which {
			case "issue-before":
				f.in.Enrolled.NotBefore = now + 1
			case "issue-at-end":
				f.in.Enrolled.NotAfter = now
			case "empty":
				f.in.Enrolled.NotBefore = now
				f.in.Enrolled.NotAfter = now
			case "reversed":
				f.in.Enrolled.NotBefore = now + 1
				f.in.Enrolled.NotAfter = now
			case "release-at-end":
				f.in.Enrolled.NotAfter = now + 1
			}
			if which == "release-at-end" {
				p := built(t, f)
				f.clock.set(time.Unix(now+1, 0), true)
				if c := p.Recheck(context.Background()); c != KeyNotValidNow {
					t.Fatalf("key release boundary=%s", c)
				}
			} else {
				denied(t, f, KeyNotValidNow)
				if f.calls != 0 {
					t.Fatal("invalid issue window signed")
				}
			}
			valid := setup(t)
			valid.in.Enrolled.NotBefore = valid.clock.at.Unix()
			valid.in.Enrolled.NotAfter = valid.clock.at.Unix() + 1
			built(t, valid)
		})
	}
}

// Expiry is exact and has no receiver skew allowance; the one-nanosecond-before
// control succeeds. The builder also checks again after a delayed signature.
func TestReleaseExpiry(t *testing.T) {
	f := setup(t)
	p := built(t, f)
	f.clock.set(p.expires.Add(-time.Nanosecond), true)
	if c := p.Recheck(context.Background()); c != "" {
		t.Fatal("pre-expiry control refused", c)
	}
	f.clock.set(p.expires, true)
	if c := p.Recheck(context.Background()); c != RequestExpired {
		t.Fatal("release-time expiry check bypassed", c)
	}
	slow := setup(t)
	sign := slow.builder.signer
	slow.builder.signer = signFunc(func(ctx context.Context, b []byte) ([]byte, Code) {
		sig, c := sign.Sign(ctx, b)
		slow.clock.set(slow.clock.at.Add(121*time.Second), true)
		return sig, c
	})
	denied(t, slow, RequestExpired)
}

// Signer errors propagate an existing local code unchanged, and invalid returned
// signatures fail upstream self-verification without exposing an envelope.
func TestSigningFailures(t *testing.T) {
	for _, which := range []string{"typed-error", "bad-signature", "short-signature", "other-key"} {
		t.Run(which, func(t *testing.T) {
			f := setup(t)
			want := Code(format.RegistrationSignatureInvalid)
			f.builder.signer = signFunc(func(_ context.Context, p []byte) ([]byte, Code) {
				switch which {
				case "typed-error":
					return nil, "sign_key_mismatch"
				case "short-signature":
					return make([]byte, 63), OK
				case "other-key":
					_, key, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					return ed25519.Sign(key, p), OK
				}
				return make([]byte, 64), OK
			})
			if which == "typed-error" {
				want = "sign_key_mismatch"
			}
			if which == "short-signature" {
				want = Code(format.RegistrationMalformed)
			}
			proof, code := f.builder.Build(context.Background(), f.in)
			if proof != nil || code != want {
				t.Fatalf("self-check released invalid proof: code=%s envelope=%t want=%s", code, proof != nil, want)
			}
			built(t, setup(t))
		})
	}
}

// The signer sees exactly Build's registrar-owned preimage, not a body, a digest
// or caller bytes. UTC timestamps are whole seconds and TTL is exactly 120s.
func TestSigningInput(t *testing.T) {
	f := setup(t)
	nonce := bytes.Repeat([]byte{7}, 16)
	f.builder.random = bytes.NewReader(nonce)
	iat := f.clock.at.Truncate(time.Second)
	canonical, expected, err := format.Build(format.Body{Key: f.in.Enrolled.Key, Name: f.in.Name, Audience: f.in.Audience, Nonce: nonce, IssuedAt: iat.Format(time.RFC3339), ExpiresAt: iat.Add(120 * time.Second).Format(time.RFC3339)}, f.in.Enrolled.Audience)
	if err != nil {
		t.Fatal(err)
	}
	p, code := f.builder.Build(context.Background(), f.in)
	if !bytes.Equal(f.seen, expected) || bytes.Equal(f.seen, canonical) {
		t.Fatal("signer received non-registrar signing input")
	}
	if p == nil || code != "" {
		t.Fatal("valid registrar signing input failed", code)
	}
	body, err := format.Verify(p.Envelope())
	if err != nil {
		t.Fatal(err)
	}
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Sub(iat) != 120*time.Second || strings.Contains(body.IssuedAt, ".") || !strings.HasSuffix(body.IssuedAt, "Z") {
		t.Fatal("proof time/TTL differs")
	}
}

// Returned bytes are copies and cannot alter later retries/rechecks. Context
// cancellation returns no proof and does not falsely fence a healthy clock.
func TestOwnershipAndCancellation(t *testing.T) {
	f := setup(t)
	p := built(t, f)
	raw := p.Envelope()
	raw[0] ^= 1
	if _, err := format.Verify(p.Envelope()); err != nil {
		t.Fatal("caller altered immutable proof")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c := p.Recheck(ctx); c != DeadlineExceeded {
		t.Fatal(c)
	}
	if c := p.Recheck(context.Background()); c != "" {
		t.Fatal("cancellation fenced healthy clock", c)
	}
	if got, c := f.builder.Build(ctx, f.in); got != nil || c != DeadlineExceeded {
		t.Fatal("cancelled build released proof")
	}
	if (*Proof)(nil).Recheck(context.Background()) != RequestExpired || (*Proof)(nil).Envelope() != nil {
		t.Fatal("nil proof became valid")
	}
	built(t, setup(t))
}

// Faults introduced during signing suppress the completed proof, including a
// backward step smaller than one second. A healthy signer/clock still succeeds.
func TestPostSigningRefusals(t *testing.T) {
	for _, which := range []string{"rollback", "health-loss", "cancel", "key-expired"} {
		t.Run(which, func(t *testing.T) {
			f := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := f.clock.at
			want := ClockUntrusted
			f.builder.signer = signFunc(func(_ context.Context, preimage []byte) ([]byte, Code) {
				switch which {
				case "rollback":
					f.clock.set(start.Add(-time.Nanosecond), true)
				case "health-loss":
					f.clock.set(start, false)
				case "cancel":
					cancel()
				case "key-expired":
					f.clock.set(time.Unix(f.in.Enrolled.NotAfter, 0), true)
				}
				return ed25519.Sign(f.key, preimage), OK
			})
			if which == "cancel" {
				want = DeadlineExceeded
			}
			if which == "key-expired" {
				want = KeyNotValidNow
			}
			if p, code := f.builder.Build(ctx, f.in); p != nil || code != want {
				t.Fatalf("post-sign fault returned proof=%t code=%s want=%s", p != nil, code, want)
			}
			built(t, setup(t))
		})
	}
}

// Parallel builds share a non-concurrent entropy Reader without races or nonce
// reuse. Each output verifies and rechecks; this exercises one shared Builder.
func TestConcurrentBuild(t *testing.T) {
	f := setup(t)
	const n = 8
	var entropy []byte
	for i := 0; i < n; i++ {
		entropy = append(entropy, bytes.Repeat([]byte{byte(i + 1)}, 16)...)
	}
	f.builder.random = bytes.NewReader(entropy)
	f.builder.signer = signFunc(func(_ context.Context, preimage []byte) ([]byte, Code) {
		return ed25519.Sign(f.key, preimage), OK
	})
	type result struct {
		proof *Proof
		code  Code
	}
	out := make(chan result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, c := f.builder.Build(context.Background(), f.in)
			if p != nil && c == OK {
				c = p.Recheck(context.Background())
			}
			out <- result{p, c}
		}()
	}
	wg.Wait()
	close(out)
	seen := map[string]bool{}
	for got := range out {
		if got.code != OK || got.proof == nil {
			t.Fatal("concurrent build failed", got.code)
		}
		body, err := format.Verify(got.proof.Envelope())
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(body.Nonce)] {
			t.Fatal("concurrent builds reused nonce")
		}
		seen[string(body.Nonce)] = true
	}
	if len(seen) != n || f.builder.random.(*bytes.Reader).Len() != 0 {
		t.Fatal("parallel entropy consumption differs")
	}
}
