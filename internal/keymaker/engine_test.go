package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeGenerations struct {
	mu          sync.Mutex
	entries     map[uint32]Generation
	unavailable bool
	watchers    map[uint32][]chan struct{}
}

// Exhausted UID or global buckets refuse before signing and retain precise audit
// evidence; restoring the independent bucket admits the paired signing control.
func TestRateLimits(t *testing.T) {
	for _, scope := range []string{"uid", "global"} {
		t.Run(scope, func(t *testing.T) {
			e, _, signer, a, s := fixtureEngine(t)
			e.rateMu.Lock()
			if scope == "uid" {
				e.peers[Principal{s.Peer.UID, s.Generation}] = &bucket{last: time.Now()}
			} else {
				e.global = bucket{last: time.Now()}
			}
			e.rateMu.Unlock()
			body := validBody(signer.key[32:], "git")
			if code := e.Handle(context.Background(), s, body, func([]byte) error { t.Fatal("rate refusal released"); return nil }); code != "rate_limited" || signer.calls.Load() != 0 {
				t.Fatal("exhausted bucket admitted", code)
			}
			if len(a.records) != 1 || a.records[0].RefusalCode == nil || *a.records[0].RefusalCode != "rate_limited" {
				t.Fatal("rate refusal missing audit")
			}
			e.rateMu.Lock()
			e.global = bucket{}
			e.peers = map[Principal]*bucket{}
			e.rateMu.Unlock()
			if code := e.Handle(context.Background(), s, body, func([]byte) error { return nil }); code != "" || signer.calls.Load() != 1 {
				t.Fatal("rate control denied", code)
			}
		})
	}
}

func newGenerations(uid uint32, token string) *fakeGenerations {
	return &fakeGenerations{entries: map[uint32]Generation{uid: {UID: uid, Generation: token, State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}}, watchers: map[uint32][]chan struct{}{}}
}
func (f *fakeGenerations) lookup(uid uint32) (Generation, Code) {
	if f.unavailable {
		return Generation{}, "generation_source_unavailable"
	}
	g, ok := f.entries[uid]
	if !ok {
		return Generation{}, "generation_source_unavailable"
	}
	return g, ""
}
func (f *fakeGenerations) Lookup(_ context.Context, uid uint32) (Generation, Code) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookup(uid)
}
func (f *fakeGenerations) WithActive(ctx context.Context, uid uint32, token string, fn func() Code) Code {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil {
		return "request_deadline_exceeded"
	}
	g, c := f.lookup(uid)
	if c != "" {
		return c
	}
	if !g.Verified || g.Fenced || g.Provenance == "" || g.Revision == "" {
		return "generation_source_unavailable"
	}
	if g.State != "active" {
		return "generation_inactive"
	}
	if g.Generation != token {
		return "generation_mismatch"
	}
	return fn()
}
func (f *fakeGenerations) Watch(uid uint32, _ string) (<-chan struct{}, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := make(chan struct{})
	f.watchers[uid] = append(f.watchers[uid], c)
	return c, func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		v := f.watchers[uid]
		for i, x := range v {
			if x == c {
				f.watchers[uid] = append(v[:i], v[i+1:]...)
				break
			}
		}
	}
}
func (f *fakeGenerations) set(uid uint32, state, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.entries[uid]
	g.State = state
	g.Generation = token
	f.entries[uid] = g
	for _, c := range f.watchers[uid] {
		close(c)
	}
	delete(f.watchers, uid)
}

type memoryAudit struct {
	mu      sync.Mutex
	records []AuditRecord
	fail    bool
}

func (a *memoryAudit) Append(r AuditRecord) Code {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return "audit_unavailable"
	}
	a.records = append(a.records, r)
	return ""
}

type testSigner struct {
	key     ed25519.PrivateKey
	calls   atomic.Int32
	entered chan struct{}
	proceed chan struct{}
}

func (s *testSigner) Public(string) ([]byte, Code) { return append([]byte(nil), s.key[32:]...), "" }
func (s *testSigner) Sign(_ string, data []byte) ([]byte, Code) {
	s.calls.Add(1)
	if s.entered != nil {
		s.entered <- struct{}{}
		<-s.proceed
	}
	return ed25519.Sign(s.key, data), ""
}
func fixtureSigner(t *testing.T) *testSigner {
	t.Helper()
	node := deriveNode(fromHex(t, "000102030405060708090a0b0c0d0e0f"), nil)
	defer erase(node)
	return &testSigner{key: ed25519.NewKeyFromSeed(node[:32])}
}
func fixtureEngine(t *testing.T) (*Engine, *fakeGenerations, *testSigner, *memoryAudit, Session) {
	t.Helper()
	b := fixtureBinding(30001)
	s := NewStore()
	if _, c := s.Register(fixtureOperator, fixtureOperator, b); c != "" {
		t.Fatal(c)
	}
	g := newGenerations(b.UID, b.Generation)
	k := fixtureSigner(t)
	a := &memoryAudit{}
	e := NewEngine(s, g, k, a)
	session := e.OpenSession(context.Background(), Peer{UID: b.UID})
	if session.Admission != "" {
		t.Fatal(session.Admission)
	}
	return e, g, k, a, session
}
func validBody(public []byte, namespace string) []byte {
	data := append([]byte("SSHSIG"), SSHString([]byte(namespace))...)
	data = append(data, SSHString(nil)...)
	data = append(data, SSHString([]byte("sha256"))...)
	data = append(data, SSHString(make([]byte, 32))...)
	body := append([]byte{13}, SSHString(PublicBlob(public))...)
	body = append(body, SSHString(data)...)
	return append(body, 0, 0, 0, 0)
}
func checkResponse(t *testing.T, response, public []byte, body []byte) {
	t.Helper()
	payload, c := ReadFrame(bytes.NewReader(response))
	if c != "" || len(payload) == 0 {
		t.Fatal("invalid success packet", c)
	}
	if body[0] == 11 {
		if payload[0] != 12 {
			t.Fatal("wrong identities response")
		}
		r := wireReader{b: payload[1:]}
		if r.u32() != 1 || !bytes.Equal(r.string(), PublicBlob(public)) || string(r.string()) != "keymaker" || r.bad || len(r.b) != 0 {
			t.Fatal("foreign or malformed identity list")
		}
		return
	}
	if payload[0] != 14 {
		t.Fatal("missing signature")
	}
	r := wireReader{b: payload[1:]}
	signature := r.string()
	if r.bad || len(r.b) != 0 {
		t.Fatal("malformed signature envelope")
	}
	s := wireReader{b: signature}
	if string(s.string()) != "ssh-ed25519" {
		t.Fatal("wrong algorithm")
	}
	sig := s.string()
	q, c := parseAgent(body)
	if c != "" || s.bad || len(s.b) != 0 || !ed25519.Verify(public, q.data, sig) {
		t.Fatal("signature verification failed")
	}
}

type refusalRow struct {
	ID      string          `json:"id"`
	Input   json.RawMessage `json:"input"`
	Code    Code            `json:"expected_code"`
	Control string          `json:"positive_control"`
}
type fixtureDocument struct {
	Negative []refusalRow `json:"negative"`
	Positive []struct {
		ID    string          `json:"id"`
		Input json.RawMessage `json:"input"`
	} `json:"positive"`
}

// Every K1a fixture runs its negative before the nearest positive control. Wire
// cases exercise Handle and verify real signatures; internal binding/path cases
// test their named primitive then the common audited refusal path. Static fixtures
// alone do not prove concurrency; TestReleaseFences below controls the actual race.
func TestRefusalVectors(t *testing.T) {
	var doc fixtureDocument
	readFixture(t, "refusals.json", &doc)
	positive := map[string]json.RawMessage{}
	for _, r := range doc.Positive {
		positive[r.ID] = r.Input
	}
	count := 0
	for _, row := range doc.Negative {
		var layer struct {
			Evaluation string `json:"evaluation"`
		}
		json.Unmarshal(row.Input, &layer)
		switch layer.Evaluation {
		case "binding_authorize", "derive_path", "ssh_agent", "audit_release":
		default:
			continue
		}
		count++
		t.Run(row.ID, func(t *testing.T) {
			for _, sample := range []struct {
				name string
				data json.RawMessage
				code Code
			}{{"negative", row.Input, row.Code}, {"control", positive[row.Control], ""}} {
				t.Run(sample.name, func(t *testing.T) { runVector(t, layer.Evaluation, sample.data, sample.code) })
			}
		})
	}
	if count != 31 {
		t.Fatalf("unexpected K1a fixture coverage %d", count)
	}
}
func runVector(t *testing.T, layer string, raw json.RawMessage, expected Code) {
	e, g, k, a, session := fixtureEngine(t)
	before := e.Store.Snapshot()
	var response []byte
	var actual Code
	release := func(b []byte) error { response = append([]byte(nil), b...); return nil }
	switch layer {
	case "binding_authorize":
		var in struct {
			UID      uint32 `json:"peer_uid"`
			Token    string `json:"connection_generation"`
			Evidence struct {
				Available bool   `json:"available"`
				State     string `json:"state"`
				Token     string `json:"generation"`
			} `json:"generation_evidence"`
			Binding Binding `json:"binding"`
		}
		if json.Unmarshal(raw, &in) != nil {
			t.Fatal("invalid binding fixture")
		}
		evidence := Generation{UID: in.UID, Generation: in.Evidence.Token, State: in.Evidence.State, Revision: "fixture", Provenance: "fixture", Verified: true}
		actual = "generation_source_unavailable"
		if in.Evidence.Available {
			actual = authorize(Peer{UID: in.UID}, in.Token, evidence, in.Binding)
		}
		if actual != "" {
			actual = e.refuse(session, agentRequest{operation: "sign"}, nil, actual)
		} else {
			body := validBody(k.key[32:], "git")
			actual = e.Handle(context.Background(), session, body, release)
			if actual == "" {
				checkResponse(t, response, k.key[32:], body)
			}
		}
	case "derive_path":
		var in struct {
			Path    string `json:"path"`
			Purpose string `json:"purpose"`
		}
		json.Unmarshal(raw, &in)
		actual = ValidatePath(in.Path, in.Purpose)
		if actual != "" {
			actual = e.refuse(session, agentRequest{operation: "derive"}, nil, actual)
		} else {
			body := validBody(k.key[32:], "git")
			actual = e.Handle(context.Background(), session, body, release)
			if actual == "" {
				checkResponse(t, response, k.key[32:], body)
			}
		}
	case "ssh_agent":
		var in struct {
			Frame string `json:"frame_hex"`
		}
		json.Unmarshal(raw, &in)
		body, c := ReadFrame(bytes.NewReader(fromHex(t, in.Frame)))
		if c != "" {
			actual = e.RejectFrame(session, c)
		} else {
			actual = e.Handle(context.Background(), session, body, release)
			if actual == "" {
				checkResponse(t, response, k.key[32:], body)
			}
		}
	case "audit_release":
		var in struct {
			Writable bool `json:"audit_writable"`
			Sync     bool `json:"audit_sync_ok"`
		}
		json.Unmarshal(raw, &in)
		dir := t.TempDir()
		os.Chmod(dir, 0700)
		fd, err := OpenDirectory(dir, uint32(os.Getuid()), 0700)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		journal, err := OpenJournal(fd, uint32(os.Getuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer journal.Close()
		journal.writer = &faultFile{file: journal.file, writeFail: !in.Writable, syncFail: !in.Sync}
		e.Audit = journal
		body := validBody(k.key[32:], "git")
		actual = e.Handle(context.Background(), session, body, release)
		if actual == "" {
			if journal.seq != 1 {
				t.Fatal("missing durable audit")
			}
			checkResponse(t, response, k.key[32:], body)
		} else {
			if !e.closed.Load() {
				t.Fatal("audit failure did not close admission")
			}
			calls := k.calls.Load()
			if c := e.Handle(context.Background(), session, body, release); c != "audit_unavailable" || k.calls.Load() != calls {
				t.Fatal("continued signing after audit failure")
			}
		}
	}
	_ = g
	if actual != expected {
		t.Fatalf("code %q, want %q", actual, expected)
	}
	if !reflect.DeepEqual(before, e.Store.Snapshot()) {
		t.Fatal("refusal/control mutated bindings")
	}
	if expected != "" && len(response) != 0 {
		t.Fatal("refused request released signature")
	}
	if layer != "audit_release" {
		if len(a.records) != 1 {
			t.Fatal("operation missing audit record")
		}
		record := a.records[0]
		if expected != "" && (record.RefusalCode == nil || *record.RefusalCode != expected || record.Result != "refused") {
			t.Fatal("incorrect refusal audit")
		}
	}
}

type faultFile struct {
	file                       *os.File
	writeFail, syncFail, short bool
}

func (f *faultFile) Write(b []byte) (int, error) {
	if f.writeFail {
		return 0, errors.New("injected append failure")
	}
	if f.short {
		return f.file.Write(b[:len(b)/2])
	}
	return f.file.Write(b)
}
func (f *faultFile) Sync() error {
	if f.syncFail {
		return errors.New("injected sync failure")
	}
	return f.file.Sync()
}

// Production has no usable generation authority. The same core succeeds with an
// injected verified fake; unverified provenance and fenced evidence also refuse.
func TestProductionGenerationRefuses(t *testing.T) {
	e, g, k, a, s := fixtureEngine(t)
	e.Generations = UnavailableGeneration{}
	s = e.OpenSession(context.Background(), s.Peer)
	var out []byte
	c := e.Handle(context.Background(), s, validBody(k.key[32:], "git"), func(b []byte) error { out = append(out, b...); return nil })
	if c != "generation_source_unavailable" || len(out) != 0 || k.calls.Load() != 0 || len(a.records) != 1 {
		t.Fatal("production generation bypass", c)
	}
	e, g, k, _, s = fixtureEngine(t)
	if c = e.Handle(context.Background(), s, validBody(k.key[32:], "git"), func([]byte) error { return nil }); c != "" {
		t.Fatal(c)
	}
	g.mu.Lock()
	bad := g.entries[s.Peer.UID]
	bad.Verified = false
	g.entries[s.Peer.UID] = bad
	g.mu.Unlock()
	if c = e.Handle(context.Background(), s, []byte{11}, func([]byte) error { t.Fatal("unverified evidence released"); return nil }); c != "generation_source_unavailable" {
		t.Fatal(c)
	}
}

// A revocation/retirement that wins while signing is paused blocks final release;
// a subsequent request on the old session cannot adopt another generation.
func TestReleaseFences(t *testing.T) {
	for _, change := range []string{"revoke", "retire", "reuse"} {
		t.Run(change, func(t *testing.T) {
			e, g, k, a, s := fixtureEngine(t)
			k.entered = make(chan struct{}, 1)
			k.proceed = make(chan struct{})
			result := make(chan Code, 1)
			var released atomic.Bool
			body := validBody(k.key[32:], "git")
			go func() {
				result <- e.Handle(context.Background(), s, body, func([]byte) error { released.Store(true); return nil })
			}()
			<-k.entered
			expected := Code("identity_revoked")
			switch change {
			case "revoke":
				if c := e.Store.Revoke(context.Background(), fixtureOperator, fixtureOperator, s.Binding.Number, approvedAct{}); c != "" {
					t.Fatal(c)
				}
			case "retire":
				g.set(s.Peer.UID, "retiring", s.Generation)
				expected = "generation_inactive"
			case "reuse":
				g.set(s.Peer.UID, "active", "replacement")
				expected = "generation_mismatch"
			}
			close(k.proceed)
			if c := <-result; c != expected || released.Load() {
				t.Fatal("late signature release", c)
			}
			if c := e.Handle(context.Background(), s, []byte{11}, func([]byte) error { released.Store(true); return nil }); c != expected || released.Load() {
				t.Fatal("old session reused", c)
			}
			if len(a.records) != 2 {
				t.Fatal("missing refusal audit")
			}
		})
	}
}
