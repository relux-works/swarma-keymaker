//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

func maiAdvance(f *maLiveFixture, delta time.Duration) {
	f.at.Now = f.at.Now.Add(delta)
	f.at.Lower = f.at.Lower.Add(delta)
	f.at.Upper = f.at.Upper.Add(delta)
}
func maiCrash(t *testing.T, f *maLiveFixture, i *maIssuer, point string) {
	t.Helper()
	i.store.messageFault = func(p string) Code {
		if p == point {
			return "request_deadline_exceeded"
		}
		return ""
	}
	if c := i.issue(t.Context(), f.b); c != "request_deadline_exceeded" {
		t.Fatal("fault did not apply", c)
	}
	if c := maIssuerRestart(t, f); c != "" {
		t.Fatal(c)
	}
	i.store = f.h.store
}

// Both durable dead ends recover after proven expiry without retiring the path.
// Before proof, a straddling interval cannot discard old evidence; fresh issuance
// after S1 retains K and creates a new T. Pending cancellation also resumes promptly.
func TestMAIssuerRenewalNoExit(t *testing.T) {
	for _, state := range []string{"no-candidate", "cancelled", "valid-pending", "valid-candidate"} {
		t.Run(state, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			if c := i.issue(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			old := maIssuerRead(t, f, i, "")
			maiAdvance(f, time.Hour)
			point := "mai-pending"
			if state == "valid-candidate" {
				point = "mai-candidate"
			}
			maiCrash(t, f, i, point)
			if state == "cancelled" {
				i.store.messageFault = func(p string) Code {
					if p == "mai-cancel" {
						return "request_deadline_exceeded"
					}
					return ""
				}
				if c := i.cancel(t.Context(), f.b); c != "request_deadline_exceeded" {
					t.Fatal(c)
				}
				if c := maIssuerRestart(t, f); c != "" {
					t.Fatal(c)
				}
				i.store = f.h.store
			}
			if strings.HasPrefix(state, "valid-") {
				if c := i.maintain(t.Context(), f.b); c != "" {
					t.Fatal("pending cancellation did not resume", c)
				}
				if got := maIssuerRead(t, f, i, ""); got.T != old.T {
					t.Fatal("cancellation replaced predecessor")
				}
				return
			}
			until, _ := time.Parse(time.RFC3339, i.store.maLive.Issuers[0].Current.Until)
			f.at = j7GateTime{Now: until, Lower: until.Add(-time.Millisecond), Upper: until.Add(time.Millisecond)}
			before := i.store.version
			if c := i.maintain(t.Context(), f.b); c == "" || i.store.version != before {
				t.Fatal("unproven predecessor expiry discarded evidence", c)
			}
			f.at = j7GateTime{Now: until.Add(time.Second), Lower: until.Add(time.Second), Upper: until.Add(time.Second)}
			i.store.messageFault = func(p string) Code {
				if p == "mai-expired" {
					return "request_deadline_exceeded"
				}
				return ""
			}
			c := i.maintain(t.Context(), f.b)
			if state == "no-candidate" && c != "request_deadline_exceeded" {
				t.Fatal("no-candidate expiry did not enter S1", c)
			}
			if state == "cancelled" && c != "request_deadline_exceeded" {
				t.Fatal("cancelled expired predecessor did not restore S1", c)
			}
			r := &i.store.maLive.Issuers[0]
			if state == "no-candidate" {
				if r.Phase != "bound" || r.Current != nil || r.Pending != nil {
					t.Fatal("no-candidate expiry retained T")
				}
			}
			i.store.messageFault = nil
			if c := i.maintain(t.Context(), f.b); c != "" {
				t.Fatal("fresh issue after dead end", c)
			}
			next := maIssuerRead(t, f, i, "")
			if next.Key != old.Key || next.T == old.T {
				t.Fatal("dead-end recovery resurrected T or replaced K")
			}
		})
	}
}

// A cancelled proof is checked before expired evidence is discarded; a false
// proof remains closed, beside the proven recovery and new-T positive above.
func TestMAIssuerExpiredCancelProof(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	maiAdvance(f, time.Hour)
	maiCrash(t, f, i, "mai-pending")
	i.store.messageFault = func(p string) Code {
		if p == "mai-cancel" {
			return "request_deadline_exceeded"
		}
		return ""
	}
	_ = i.cancel(t.Context(), f.b)
	maiAdvance(f, 25*time.Hour)
	i.store.messageFault = nil
	i.store.maLive.Issuers[0].CancelHash = strings.Repeat("f", 64)
	before := i.store.version
	if c := i.maintain(t.Context(), f.b); c != "message_author_unqualified" || i.store.version != before {
		t.Fatal("false expired cancellation proof accepted", c)
	}
}

// A per-principal unpaired receipt can fence only its one active binding (the
// binding validator forbids two active rows for a UID/generation). Resolving a
// proven pending marker/candidate uses the SAME durable cancellation proof.
func TestMAIssuerBindingLocalResolve(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		t.Run(map[bool]string{false: "marker", true: "candidate"}[candidate], func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			if c := i.issue(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			old := maIssuerRead(t, f, i, "")
			maiAdvance(f, time.Hour)
			point := "mai-pending"
			if candidate {
				point = "mai-candidate"
			}
			maiCrash(t, f, i, point)
			r := &i.store.maLive.Issuers[0]
			digest := strings.Repeat("a", 64)
			if _, _, c := i.store.maLiveAppend(t.Context(), Principal{f.b.UID + 1, f.b.Generation}, "", "message_author_attestation_issue", &digest); c != "" {
				t.Fatal(c)
			}
			if i.store.maIssuerUnpaired(r) || i.store.recoverMAIssuers() || r.Phase != "pending" {
				t.Fatal("other binding audit fenced pending")
			}
			r.Phase = "fenced"
			i.store.messageFault = func(p string) Code {
				if p == "mai-cancel" {
					return "request_deadline_exceeded"
				}
				return ""
			}
			if c := i.resolve(t.Context(), f.b); c != "request_deadline_exceeded" || r.Phase != "cancelled" || r.CancelSeq == 0 {
				t.Fatal("resolve bypassed cancel proof", c)
			}
			i.store.messageFault = nil
			if c := i.cancel(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			if v := maIssuerRead(t, f, i, ""); v.T != old.T {
				t.Fatal("resolve minted T")
			}
		})
	}
	// Both instances are actually enrolled; one reaches a real unpaired audit,
	// then restart fences only that instance and still serves the other current.
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	b := f.b
	b.UID++
	b.Number++
	b.Path = "m/1'/1'/1'/2'"
	if c := i.store.enrollMALive(t.Context(), fixtureOperator, b); c != "" {
		t.Fatal(c)
	}
	g := i.generations.(*fakeGenerations)
	g.entries[b.UID] = Generation{UID: b.UID, Generation: b.Generation, State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}
	i.store.messageFault = func(p string) Code {
		if p == "mai-success-audit" {
			return "request_deadline_exceeded"
		}
		return ""
	}
	if c := i.issue(t.Context(), b); c != "request_deadline_exceeded" {
		t.Fatal(c)
	}
	if r := i.store.maLive.Issuers[i.store.maIssuerIndex(b)]; r.Pending == nil || r.Pending.Seq != 0 {
		t.Fatal("uncommitted pending acquired receipt")
	}
	i.store.messageFault = nil
	// A different holder-local persistence can advance the shared snapshot;
	// that does not pair the issuance receipt with this candidate's commit.
	if c := i.store.maIssuerPersist(t.Context()); c != "" {
		t.Fatal(c)
	}

	if c := maIssuerRestart(t, f); c != "" {
		t.Fatal(c)
	}
	i.store = f.h.store
	maIssuerRead(t, f, i, "")
	if r := i.store.maLive.Issuers[i.store.maIssuerIndex(b)]; r.Phase != "fenced" {
		t.Fatal("unpaired binding was not fenced")
	}
	calls := 0
	if c := i.WithCurrent(t.Context(), b, f.at, func(maLiveTuple) Code { calls++; return "" }); c != "message_author_unqualified" || calls != 0 {
		t.Fatal("unpaired binding disclosed", c)
	}

}

// Renewal's audit receipt binds old T as well as new A. Neither metadata
// substitution may satisfy the committed proof; the authentic pair does.
func TestMAIssuerRenewAudit(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	old := maIssuerRead(t, f, i, "")
	maiAdvance(f, time.Hour)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	c := i.store.maLive.Issuers[0].Current
	if c.PreviousT != old.T || !i.store.maIssuerCommitted(c) {
		t.Fatal("renewal omitted old T")
	}
	r := i.store.journal.maIssuerEvents[c.Seq]
	raw, _ := canonical(struct {
		OldT string `json:"old_t"`
		NewA []byte `json:"new_a"`
	}{old.T, c.A})
	if r.PayloadDigest == nil || *r.PayloadDigest != maLiveHash(raw) {
		t.Fatal("renewal audit lacks old/new evidence")
	}
	changed := *c
	changed.PreviousT = "sha256:" + strings.Repeat("a", 64)
	if i.store.maIssuerCommitted(&changed) {
		t.Fatal("substituted old T proved current")
	}
	changed = *c
	changed.A = append([]byte{}, c.A...)
	changed.A[0] ^= 1
	if i.store.maIssuerCommitted(&changed) {
		t.Fatal("substituted A proved current")
	}
	maIssuerRead(t, f, i, "")
}

// A pre-commit refusal without s.failed must still leave no in-memory current;
// an authenticated issuance audit cannot make an unpersisted candidate readable.
func TestMAIssuerCommitPersistFailure(t *testing.T) {
	for _, point := range []string{"precheck", "snapshot-rename"} {
		t.Run(point, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			var live *maIssuerRecord
			i.store.messageFault = func(p string) Code {
				if p == "mai-success-audit" {
					live = &i.store.maLive.Issuers[0]
					if point == "precheck" {
						i.store.version = j7SafeInteger
					}
				}
				if live != nil && p == "snapshot-rename" {
					if live.Phase == "current" {
						t.Error("current before durable commit")
					}
					if point == "snapshot-rename" {
						return "request_deadline_exceeded"
					}
				}
				return ""
			}
			if c := i.issue(t.Context(), f.b); c != "message_author_unqualified" {
				t.Fatal("persist failure missing", c)
			}
			if !i.store.failed || !i.store.maLive.Fenced || i.store.maLive.Issuers[0].Phase == "current" {
				t.Fatal("failed commit retained current standing")
			}
			maIssuerRead(t, f, i, "message_author_unqualified")
		})
	}
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	maIssuerRead(t, f, i, "")
}

func maiServiceConfig(t *testing.T, f *maLiveFixture) (Config, string) {
	t.Helper()
	socket, e := os.MkdirTemp(os.Getenv("TMPDIR"), "mai-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(socket) })
	if e = os.Chmod(socket, 0755); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("../../packaging/message-author.example.json")
	if e != nil {
		t.Fatal(e)
	}
	var o map[string]any
	if e = json.Unmarshal(raw, &o); e != nil {
		t.Fatal(e)
	}
	o["operator_principal"] = map[string]any{"uid": fixtureOperator.UID, "generation": fixtureOperator.Generation}
	o["instance_id"] = f.h.store.maLive.Instance
	o["service_uid"] = os.Getuid()
	o["service_gid"] = os.Getgid()
	o["master_epoch"] = f.b.Epoch
	o["registry_revision"] = f.b.RegistryRevision
	o["issuer_pin"] = filepath.Join(socket, "issuer-pin.json")
	state := o["state"].(map[string]any)
	state["path"] = f.dir.Name()
	state["head_file"] = filepath.Join(filepath.Dir(socket), "fixture-head")
	sock := o["socket"].(map[string]any)
	sock["dir"] = socket
	sock["group"] = os.Getgid()
	raw, e = json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := ParseConfig(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	return cfg, string(raw)
}
func maiDeps(t *testing.T, f *maLiveFixture, head j7Expectation) maLiveServiceDeps {
	d := productionMALiveDeps()
	d.clock = func(*timeconf.Policy) (*timeconf.Provider, error) {
		p, _, _ := fixtureTimeProvider(t, helperNow)
		return p, nil
	}
	d.head = func(string) (j7Expectation, error) { return head, nil }
	d.generation = func(*Store, generationJournalConfig) GenerationSource {
		g := newGenerations(f.b.UID, f.b.Generation)
		g.entries[fixtureOperator.UID] = Generation{UID: fixtureOperator.UID, Generation: fixtureOperator.Generation, State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}
		return g
	}
	d.config = func(p string, c *Config) error {
		raw, e := protectedRead(p, 1<<20, uint32(os.Getuid()), uint32(os.Getgid()), 0600)
		if e != nil {
			return e
		}
		return StrictJSON(bytes.NewReader(raw), c)
	}
	return d
}

type maiStatus chan string

func (w maiStatus) Write(p []byte) (int, error) { w <- string(p); return len(p), nil }

// Real startup (not just the pin parser) must refuse malformed/mismatched pins
// and invalid custody before readiness/socket creation; matching and absent pins
// start beside them, retain the production closed provider, and erase the seed.
func TestMAIssuerStartupProduction(t *testing.T) {
	for _, fault := range []string{"match", "absent", "key", "malformed", "format", "profile", "no-seed", "seed-mode", "seed-mode-absent", "seed-empty"} {
		t.Run(fault, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			cfg, _ := maiServiceConfig(t, f)
			seed := bytes.Repeat([]byte{0xa5}, 32)
			if fault == "seed-empty" {
				seed = nil
			}
			if fault != "no-seed" {
				mode := os.FileMode(0600)
				if fault == "seed-mode" || fault == "seed-mode-absent" {
					mode = 0644
				}
				if e := os.WriteFile(filepath.Join(f.dir.Name(), maIssuerSeedFile), seed, mode); e != nil {
					t.Fatal(e)
				}
			}
			pin, c := i.custody.pin()
			if c != "" {
				t.Fatal(c)
			}
			switch fault {
			case "key":
				k, c := newMAIssuerKey(bytes.Repeat([]byte{0xa6}, 32))
				if c != "" {
					t.Fatal(c)
				}
				pin, c = k.pin()
				k.close()
				if c != "" {
					t.Fatal(c)
				}
			case "malformed":
				pin = []byte("{\n")
			case "format":
				pin = bytes.Replace(pin, []byte("keymaker-purpose5-pin/1"), []byte("keymaker-purpose5-pin/0"), 1)
			case "profile":
				pin = bytes.Replace(pin, []byte("attestation/1"), []byte("attestation/0"), 1)
			}
			if fault != "absent" && fault != "seed-mode-absent" {
				if e := os.WriteFile(cfg.maLive.IssuerPin, pin, 0644); e != nil {
					t.Fatal(e)
				}
			}
			head := maLiveExpected(t, f.h.store)
			f.h.store.Close()
			d := maiDeps(t, f, head)
			var loaded *maIssuerKey
			d.pinCheck = func(p string, k *maIssuerKey) (bool, Code) {
				loaded = k
				return maIssuerStartupPinOwner(p, k, uint32(os.Getuid()))
			}
			status := make(maiStatus, 8)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- serveMALive(ctx, cfg, status, d) }()
			if fault == "match" || fault == "absent" {
				foundAbsent := false
				for {
					select {
					case p := <-status:
						if p == "issuer_pin=absent\n" {
							foundAbsent = true
						}
						if p == "ready\n" {
							goto ready
						}
					case e := <-done:
						t.Fatal("valid startup refused", e)
					case <-time.After(5 * time.Second):
						t.Fatal("startup timed out")
					}
				}
			ready:
				if foundAbsent != (fault == "absent") {
					t.Fatal("absent pin status missing or forged")
				}
				loaded.mu.Lock()
				closed := loaded.closed && len(loaded.seed) == 0
				loaded.mu.Unlock()
				if !closed {
					t.Fatal("startup retained issuer seed")
				}
				cancel()
				if e := <-done; e != nil {
					t.Fatal(e)
				}
			} else {
				want := Code("message_author_issuer_pin_invalid")
				if fault == "key" {
					want = "message_author_issuer_pin_mismatch"
				}
				if fault == "no-seed" || strings.HasPrefix(fault, "seed-") {
					want = "custody_unavailable"
				}
				select {
				case p := <-status:
					t.Fatal("startup pin refusal bypassed", p)
				case e := <-done:
					if e != want {
						t.Fatal("startup pin refusal", fault, e, want)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("pin refusal timed out")
				}
				if len(status) != 0 {
					t.Fatal("refused pin published status")
				}
				if _, e := os.Stat(filepath.Join(cfg.maLive.Socket.Dir, "control.sock")); !os.IsNotExist(e) {
					t.Fatal("refused pin published socket")
				}
				if loaded != nil {
					loaded.mu.Lock()
					closed := loaded.closed
					loaded.mu.Unlock()
					if !closed {
						t.Fatal("refused startup retained issuer seed")
					}
				}
			}
		})
	}
}

// Phase validation rejects impossible state/evidence combinations, while exact
// bound/withdrawn/pending states remain valid beside each negative.
func TestMAIssuerPhaseEvidence(t *testing.T) {
	for _, phase := range []string{"bound", "withdrawn", "pending"} {
		t.Run(phase, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			if c := i.issue(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			r := &i.store.maLive.Issuers[0]
			cert := *r.Current
			r.Phase = phase
			r.Current = nil
			r.Pending = nil
			if phase == "pending" {
				r.Pending = &cert
				r.Pending.Seq = 0
				r.Pending.Hash = ""
			}
			if e := i.store.validateMAIssuers(); e != nil {
				t.Fatal("valid phase control", e)
			}
			if phase == "pending" {
				r.Pending.Seq = 1
			} else {
				r.Current = &cert
			}
			if e := i.store.validateMAIssuers(); e == nil {
				t.Fatal("invalid phase evidence accepted")
			}
			if phase != "pending" {
				r.Current = nil
				r.Pending = &cert
				if e := i.store.validateMAIssuers(); e == nil {
					t.Fatal("hidden pending evidence accepted")
				}
			}
		})
	}
}

// A genuine pre-issuer /1 snapshot refuses by the schema name on the normal
// openMALive path, before head/digest reconciliation. No upgrade is attempted.
func TestMAIssuerSchema7Original(t *testing.T) {
	f, _ := newMAIssuerFixture(t)
	head := maLiveExpected(t, f.h.store)
	f.h.store.Close()
	old := map[string]any{"schema_version": 7, "next_registration_number": uint64(2), "version": uint64(1), "audit_seq": uint64(1), "audit_hash": strings.Repeat("a", 64), "records": []Binding{f.b}, "requests": []any{}, "message_author": map[string]any{"format": "keymaker-message-author-state/1", "instance": f.h.store.maLive.Instance, "master_epoch": f.b.Epoch, "registry_revision": f.b.RegistryRevision, "fenced": false, "attempts": []any{}}}
	raw, e := canonical(old)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.dir.Name(), "bindings.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if s, c := openMALive(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, head); c != "message_author_state_schema_unsupported" || s != nil {
		t.Fatal("genuine schema7 accepted", c)
	}
}

// Actual operator dispatch initializes only a test-owned seed under the same
// generation authorization and audit-before-effect path, then public pin output
// adds no audit and existing-seed retry cannot replace custody.
func TestMAIssuerCommandDispatch(t *testing.T) {
	f, _ := newMAIssuerFixture(t)
	_, raw := maiServiceConfig(t, f)
	head := maLiveExpected(t, f.h.store)
	f.h.store.Close()
	d := maiDeps(t, f, head)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if e := os.WriteFile(cfgPath, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if c := runMessageAuthorOperator(t.Context(), "issuer-seed-init", cfgPath, 0, nil, &out, d); c != "" {
		t.Fatal("seed command control", c)
	}
	seed, e := os.ReadFile(filepath.Join(f.dir.Name(), maIssuerSeedFile))
	if e != nil || len(seed) != 32 {
		t.Fatal("seed command absent", e)
	}
	auditBefore := maiAuditFiles(t, f.dir.Name())
	// The pin-only public command intentionally does not need time/head/generation.
	out.Reset()
	if c := runMessageAuthorOperator(t.Context(), "issuer-pin", cfgPath, 0, nil, &out, d); c != "" {
		t.Fatal("pin command control", c)
	}
	if after := maiAuditFiles(t, f.dir.Name()); !bytes.Equal(auditBefore, after) {
		t.Fatal("pin command changed audit")
	}
	k, c := loadMAIssuerKey(f.dir, uint32(os.Getuid()))
	if c != "" {
		t.Fatal(c)
	}
	want, c := k.pin()
	k.close()
	if c != "" || !bytes.Equal(want, out.Bytes()) {
		t.Fatal("pin command leaked or changed output", c)
	}
	// Use the newly reported exact physical head for the duplicate command.
	s, e := loadStoreMessage(f.dir, uint32(os.Getuid()), maLiveSchema, false)
	if e != nil {
		t.Fatal(e)
	}
	head = maLiveExpected(t, s)
	d.head = func(string) (j7Expectation, error) { return head, nil }
	out.Reset()
	if c := runMessageAuthorOperator(t.Context(), "issuer-seed-init", cfgPath, 0, nil, &out, d); c == "" {
		t.Fatal("duplicate seed command replaced custody")
	}
	after, e := os.ReadFile(filepath.Join(f.dir.Name(), maIssuerSeedFile))
	if e != nil || !bytes.Equal(seed, after) || out.Len() != 0 {
		t.Fatal("refused command changed custody or output", e)
	}
}

func maiAuditFiles(t *testing.T, dir string) []byte {
	t.Helper()
	var out []byte
	e := filepath.WalkDir(filepath.Join(dir, "audit"), func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			out = append(out, []byte(p)...)
			out = append(out, b...)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
