package keymaker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

// This fake exists only in the test binary. Its complete binding and current
// tuple are held through the same callback as a future qualified issuer seam.
type maLiveFixtureCurrent struct {
	mu          sync.Mutex
	b           Binding
	tuple       maLiveTuple
	from, until time.Time
	refusal     Code
	reads       int
	before      func(int)
}

func (f *maLiveFixtureCurrent) WithCurrent(ctx context.Context, b Binding, at j7GateTime, fn func(maLiveTuple) Code) Code {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.before != nil {
		f.before(f.reads)
	}
	if f.refusal != "" {
		return f.refusal
	}
	if b != f.b || !maLiveInterval(at, f.from, f.until) {
		return "message_author_unqualified"
	}
	return fn(f.tuple)
}

type maLiveFixture struct {
	h        *maLiveHolder
	source   *maLiveFixtureCurrent
	dir      *os.File
	b        Binding
	v        maVectors
	preimage []byte
	calls    atomic.Int32
	at       j7GateTime
}

func newMALiveFixture(t *testing.T, uid ...uint32) *maLiveFixture {
	t.Helper()
	k, _, b := maFixture(t)
	if len(uid) == 1 {
		b.UID = uid[0]
	}
	if c := protectMALiveMemory(k); c != "" {
		t.Fatal("protected fixture", c)
	}
	path := t.TempDir()
	if e := os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	dir, e := OpenDirectory(path, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { dir.Close() })
	s, c := initMALive(t.Context(), dir, uint32(os.Getuid()), fixtureAuditClock{}, k.instance, k.epoch, k.registry)
	if c != "" {
		t.Fatal("init control", c)
	}
	t.Cleanup(func() { s.Close() })
	if c = s.enrollMALive(t.Context(), fixtureOperator, b); c != "" {
		t.Fatal("enroll control", c)
	}
	v := maData(t)
	now := time.Unix(2000000000, 0).UTC()
	at := j7GateTime{Now: now, Lower: now.Add(-time.Millisecond), Upper: now.Add(time.Millisecond)}
	f := &maLiveFixture{dir: dir, b: b, v: v, at: at, preimage: maBytes(t, v.Preimage)}
	f.source = &maLiveFixtureCurrent{b: b, tuple: maLiveTuple{Key: v.Key, T: v.T, Attestation: maBytes(t, v.Attestation)}, from: now.Add(-time.Hour), until: now.Add(time.Hour)}
	f.h = &maLiveHolder{store: s, key: k, generations: newGenerations(b.UID, b.Generation), current: f.source, clock: func(context.Context) (j7GateTime, Code) { return f.at, "" }}
	// The counter is owned by the test adapter, absent from the product binary.
	// Its boundary follows successful entropy preparation and durable invoking.
	f.h.invoke = func(s *Store, b Binding, p *messageAuthorPlan, before func() Code) ([]byte, Code) {
		return k.selectedHeld(s, b, p, func() Code {
			c := before()
			if c == "" {
				f.calls.Add(1)
			}
			return c
		})
	}
	return f
}
func (f *maLiveFixture) request() messageauthor.Request {
	return messageauthor.Request{ID: strings.Repeat("a", 32), TimeoutMS: 2000, Method: messageauthor.SignMethod, Preimage: append([]byte(nil), f.preimage...)}
}
func (f *maLiveFixture) call(ctx context.Context, r messageauthor.Request) (messageauthor.Response, Code) {
	var out messageauthor.Response
	c := f.h.handle(ctx, Principal{f.b.UID, f.b.Generation}, r, func(_ context.Context, r messageauthor.Response) Code { out = r; return "" })
	return out, c
}
func (f *maLiveFixture) control(t *testing.T) messageauthor.Response {
	t.Helper()
	r := f.request()
	out, c := f.call(t.Context(), r)
	if c != "" || out.Signature == nil || record.VerifySignature(f.v.Key, out.Signature.Signature, r.Preimage) != nil || f.calls.Load() != 1 {
		t.Fatal("valid control", c, f.calls.Load())
	}
	if f.h.store.maLive.Attempts[0].Status != "released" {
		t.Fatal("admitting request stopped before release")
	}
	t.Logf("VC-2 invocation_count=%d", f.calls.Load())
	return out
}
func (f *maLiveFixture) refusal(t *testing.T, r messageauthor.Request, want Code, count int32) {
	t.Helper()
	out, c := f.call(t.Context(), r)
	if c != want || out.Signature != nil || out.Identity != nil || f.calls.Load() != count {
		t.Fatal("negative standing/effect", c, want, f.calls.Load(), count)
	}
	t.Logf("%s invocation_count=%d retained=%d", want, f.calls.Load(), len(f.h.store.maLive.Attempts))
}

// Each malformed preimage is rejected before intent/crypto. Its adjacent fresh
// valid control proves that the held interface is not a reject-all stub.
func TestMALiveTagDomain(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    []byte
		want Code
	}{{"malformed", []byte("swarma-msg/2"), "signer_tag_malformed"}, {"wrong-domain", []byte("other/2\n{}"), "signer_domain_refused"}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMALiveFixture(t)
			r := f.request()
			r.Preimage = tc.p
			f.refusal(t, r, tc.want, 0)
			if len(f.h.store.maLive.Attempts) != 0 {
				t.Fatal("bad input retained")
			}
			f.control(t)
		})
	}
}
func TestMALiveAuthorEqualsOwnKey(t *testing.T) {
	f := newMALiveFixture(t)
	r := f.request()
	obj := maRecord(t, f.v)
	obj["body"].(map[string]any)["author"] = "bip340:eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g"
	r.Preimage = maPre(t, obj)
	f.refusal(t, r, "signer_identity_mismatch", 0)
	f.control(t)
}
func TestMALiveCurrentTAdmission(t *testing.T) {
	f := newMALiveFixture(t)
	r := f.request()
	old := f.source.tuple.T
	f.source.tuple.T = "sha256:" + strings.Repeat("b", 64)
	f.refusal(t, r, "signer_identity_mismatch", 0)
	f.source.tuple.T = old
	f.control(t)
}
func TestMALiveCanonicalPayload(t *testing.T) {
	f := newMALiveFixture(t)
	r := f.request()
	r.Preimage = append(r.Preimage, '\n')
	f.refusal(t, r, "signer_payload_invalid", 0)
	f.control(t)
}
func TestMALivePreimageBounds(t *testing.T) {
	f := newMALiveFixture(t)
	r := f.request()
	r.Preimage = make([]byte, 24577)
	f.refusal(t, r, "signer_preimage_too_large", 0)
	if f.source.reads != 0 {
		t.Fatal("oversized preimage reached authority before cap")
	}
	obj := maRecord(t, f.v)
	padding := []any{"", "", ""}
	obj["padding"] = padding
	left := 24576 - len(maPre(t, obj))
	for i := range padding {
		n := left
		if n > 8192 {
			n = 8192
		}
		padding[i] = strings.Repeat("x", n)
		left -= n
	}
	r.Preimage = maPre(t, obj)
	if len(r.Preimage) != 24576 {
		t.Fatal("boundary fixture length", len(r.Preimage))
	}
	out, c := f.call(t.Context(), r)
	if c != "" || out.Signature == nil || record.VerifySignature(f.v.Key, out.Signature.Signature, r.Preimage) != nil || f.calls.Load() != 1 {
		t.Fatal("valid decoded boundary refused", c)
	}
	t.Log("24577 bytes invocation_count=0; admitted 24576 bytes invocation_count=1")
}

// The original admitting request crosses intent -> invoking -> result ->
// handoff -> released. An exact cross-connection retry retains the same S and
// never invokes crypto again; callback failure keeps unknown receipt distinct.
func TestMALiveIntentBeforeCrypto(t *testing.T) {
	f := newMALiveFixture(t)
	original := f.h.invoke
	f.h.invoke = func(s *Store, b Binding, p *messageAuthorPlan, before func() Code) ([]byte, Code) {
		check := func(want string) {
			disk, e := loadStoreMessage(f.dir, s.uid, maLiveSchema, false)
			if e != nil || disk.maLive == nil || len(disk.maLive.Attempts) != 1 || disk.maLive.Attempts[0].Status != want || !disk.matchesCommit(s.journal.binding) || f.calls.Load() != 0 {
				t.Fatal("durable boundary missing before crypto", want, e)
			}
		}
		check("intent")
		return original(s, b, p, func() Code {
			c := before()
			if c == "" {
				check("invoking")
			}
			return c
		})
	}
	f.control(t)
}
func TestMALiveRetryAcrossConnection(t *testing.T) {
	f := newMALiveFixture(t)
	first := f.control(t)
	out, c := f.call(t.Context(), f.request())
	if c != "" || out.Signature == nil || !bytes.Equal(first.Signature.Signature, out.Signature.Signature) || f.calls.Load() != 1 {
		t.Fatal("released replay", c)
	}
	f.h.store.maLive.Attempts[0].Status = "handoff_unknown"
	if c = f.h.store.persistMALive(t.Context(), 0); c != "" {
		t.Fatal(c)
	}
	out, c = f.call(t.Context(), f.request())
	if c != "" || !bytes.Equal(first.Signature.Signature, out.Signature.Signature) || f.calls.Load() != 1 {
		t.Fatal("unknown replay", c)
	}
	t.Logf("VC-2b released/unknown invocation_count=%d", f.calls.Load())
}
func TestMALiveConcurrentEqualRetry(t *testing.T) {
	t.Run("claim-waits", func(t *testing.T) {
		f := newMALiveFixture(t)
		p := Principal{f.b.UID, f.b.Generation}
		release, c := f.h.claim(t.Context(), p, f.request().ID)
		if c != "" {
			t.Fatal(c)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		next, c := f.h.claim(ctx, p, f.request().ID)
		if next != nil {
			next()
		}
		if c != "request_deadline_exceeded" {
			t.Fatal("duplicate did not wait for running handoff", c)
		}
		release()
		f.control(t)
	})
	f := newMALiveFixture(t)
	r := f.request()
	var wg sync.WaitGroup
	results := make(chan messageauthor.Response, 2)
	codes := make(chan Code, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); out, c := f.call(t.Context(), r); results <- out; codes <- c }()
	}
	wg.Wait()
	close(results)
	close(codes)
	for c := range codes {
		if c != "" {
			t.Fatal(c)
		}
	}
	var sig []byte
	for out := range results {
		if out.Signature == nil {
			t.Fatal("no result")
		}
		if sig != nil && !bytes.Equal(sig, out.Signature.Signature) {
			t.Fatal("different replay")
		}
		sig = out.Signature.Signature
	}
	if f.calls.Load() != 1 {
		t.Fatal("duplicate invocation", f.calls.Load())
	}
	t.Logf("concurrent invocation_count=%d", f.calls.Load())
}
func TestMALiveRequestConflict(t *testing.T) {
	for _, change := range []string{"method", "preimage"} {
		t.Run(change, func(t *testing.T) {
			f := newMALiveFixture(t)
			f.control(t)
			r := f.request()
			if change == "method" {
				r.Method = messageauthor.IdentityMethod
				r.Preimage = nil
			} else {
				r.Preimage = append(r.Preimage, ' ')
			}
			f.refusal(t, r, "request_conflict", 1)
		})
	}
}
func TestMALiveRetryOldT(t *testing.T) {
	f := newMALiveFixture(t)
	f.control(t)
	f.source.tuple.T = "sha256:" + strings.Repeat("b", 64)
	f.refusal(t, f.request(), "signer_identity_mismatch", 1)
	if f.h.store.maLive.Attempts[0].Status != "dead" {
		t.Fatal("old T not dead")
	}
	f.refusal(t, f.request(), "signer_identity_mismatch", 1)
	obj := maRecord(t, f.v)
	obj["body"].(map[string]any)["author_attestation"] = f.source.tuple.T
	r := f.request()
	r.ID = strings.Repeat("b", 32)
	r.Preimage = maPre(t, obj)
	out, c := f.call(t.Context(), r)
	if c != "" || out.Signature == nil || record.VerifySignature(f.v.Key, out.Signature.Signature, r.Preimage) != nil || f.calls.Load() != 2 {
		t.Fatal("new current T control", c)
	}
	t.Log("new T/new id invocation_count=2; old attempt remains dead")
}
func TestMALiveDeadlineThroughHandoff(t *testing.T) {
	f := newMALiveFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := f.request()
	// The last complete snapshot is a result. Expiry then suppresses callback;
	// its exact retry crosses a new barrier without another signing call.
	f.h.store.messageFault = func(point string) Code {
		if point == "snapshot-directory-sync" && len(f.h.store.maLive.Attempts) > 0 && f.h.store.maLive.Attempts[0].Status == "result" {
			cancel()
		}
		return ""
	}
	out, c := f.call(ctx, r)
	if c != "request_deadline_exceeded" || out.Signature != nil || f.calls.Load() != 1 {
		t.Fatal("late result", c, f.calls.Load())
	}
	f.h.store.messageFault = nil
	if f.h.store.maLive.Attempts[0].Status != "result" {
		t.Fatal("lost proven result")
	}
	out, c = f.call(t.Context(), r)
	if c != "" || out.Signature == nil || f.calls.Load() != 1 {
		t.Fatal("deadline replay", c)
	}
	t.Logf("deadline/retry invocation_count=%d", f.calls.Load())
	t.Run("last-disclosure-check", func(t *testing.T) {
		g := newMALiveFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		g.h.store.messageFault = func(point string) Code {
			if point == "ma-before-disclosure" {
				cancel()
			}
			return ""
		}
		out, c := g.call(ctx, g.request())
		if c != "request_deadline_exceeded" || out.Signature != nil || g.calls.Load() != 1 || g.h.store.maLive.Attempts[0].Status != "handoff_unknown" {
			t.Fatal("negative standing/effect: late callback disclosed", c, g.calls.Load())
		}
		g.h.store.messageFault = nil
		g.control(t)
	})
}

// Transient custody/entropy failures stay distinct from terminal identity LOSS;
// restoring each fixture permits a fresh valid signature without a prior effect.
func TestMALiveCustodyAndEntropy(t *testing.T) {
	for _, fault := range []string{"closed", "unloaded", "protection", "role", "instance", "entropy"} {
		t.Run(fault, func(t *testing.T) {
			f := newMALiveFixture(t)
			k := f.h.key
			seed := k.seed
			mapped := k.mapped
			entropy := k.entropy
			want := Code("custody_unavailable")
			switch fault {
			case "closed":
				k.closed = true
			case "unloaded":
				k.seed = nil
			case "protection":
				k.mapped = false
			case "role":
				k.role = "j7-request"
			case "instance":
				k.instance = strings.Repeat("8", 32)
				want = "message_author_unqualified"
			case "entropy":
				k.entropy = errorMAReader{}
				want = "entropy_unavailable"
			}
			f.refusal(t, f.request(), want, 0)
			k.closed = false
			k.seed = seed
			k.mapped = mapped
			k.role = messageAuthorRole
			k.instance = f.h.store.maLive.Instance
			k.entropy = entropy
			f.control(t)
		})
	}
}

type errorMAReader struct{}

func (errorMAReader) Read([]byte) (int, error) { return 0, errors.New("fixture unavailable") }
func TestMALiveProductionProviderRefuses(t *testing.T) {
	f := newMALiveFixture(t)
	f.h.current = maLiveUnqualified{}
	f.refusal(t, f.request(), "message_author_unqualified", 0)
	identity := f.request()
	identity.Method = messageauthor.IdentityMethod
	identity.Preimage = nil
	f.refusal(t, identity, "message_author_unqualified", 0)
	if len(f.h.store.maLive.Attempts) != 0 {
		t.Fatal("production refusal allocated intent")
	}
	f.h.current = f.source
	f.control(t)
}
func TestMALiveSchemaAndExplicitInit(t *testing.T) {
	f := newMALiveFixture(t)
	if _, e := loadStoreMessage(f.dir, uint32(os.Getuid()), 0, false); e == nil {
		t.Fatal("old reader accepted schema 7")
	}
	if _, c := initMALive(t.Context(), f.dir, uint32(os.Getuid()), fixtureAuditClock{}, f.h.key.instance, f.b.Epoch, f.b.RegistryRevision); c != "message_author_unqualified" {
		t.Fatal("implicit reinitialization", c)
	}
	d := t.TempDir()
	os.Chmod(d, 0700)
	dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	if _, e = loadStoreMessage(dir, uint32(os.Getuid()), 7, false); e == nil {
		t.Fatal("serve initialized empty state")
	}
	entries, _ := dir.ReadDir(-1)
	if len(entries) != 0 {
		t.Fatal("refusal left artifacts")
	}
	f.control(t)
}
func TestMALiveOwnBindingUniqueness(t *testing.T) {
	f := newMALiveFixture(t)
	b := f.b
	b.Number = 2
	if c := f.h.store.enrollMALive(t.Context(), fixtureOperator, b); c != "binding_conflict" {
		t.Fatal("duplicate active", c)
	}
	b = f.b
	b.Number = 2
	b.UID++
	b.Path = "m/1'/1'/2'/4'"
	b.Epoch = "different"
	if c := f.h.store.enrollMALive(t.Context(), fixtureOperator, b); c != "binding_conflict" {
		t.Fatal("C2 epoch mismatch", c)
	}
	f.control(t)
	if c := f.h.store.retireMALive(t.Context(), fixtureOperator, f.b.Number); c != "" {
		t.Fatal(c)
	}
	if f.h.store.records[0].Status != "revoked" || f.h.store.maLive.Attempts[0].Status != "dead" {
		t.Fatal("retirement evidence lost")
	}
	if c := f.restart(t); c != "" {
		t.Fatal("tombstone restart", c)
	}
	if len(f.h.store.records) != 1 || f.h.store.records[0].Status != "revoked" {
		t.Fatal("retired tombstone lost on restart")
	}
	b = f.b
	b.Number = 2
	b.Generation = "new-generation"
	if c := f.h.store.enrollMALive(t.Context(), fixtureOperator, b); c != "binding_conflict" {
		t.Fatal("resurrected tombstone", c)
	}
	// A fresh external registration on a fresh path remains admissible after
	// retirement; the historical path prohibition must not reject everything.
	b.Path = "m/1'/1'/2'/4'"
	if c := f.h.store.enrollMALive(t.Context(), fixtureOperator, b); c != "" {
		t.Fatal("fresh post-retirement binding refused", c)
	}
}
func TestMALiveTimeRefusalNotFence(t *testing.T) {
	f := newMALiveFixture(t)
	clock := f.h.clock
	f.h.clock = func(context.Context) (j7GateTime, Code) { return j7GateTime{}, "clock_untrusted" }
	f.refusal(t, f.request(), "clock_untrusted", 0)
	if f.h.store.maLive.Fenced {
		t.Fatal("time fenced")
	}
	f.h.clock = clock
	f.control(t)
	f.h.store.maLive.Fenced = true
	f.refusal(t, f.request(), "message_author_unqualified", 1)
	if !f.h.store.maLive.Fenced {
		t.Fatal("healthy source cleared fence")
	}
}
