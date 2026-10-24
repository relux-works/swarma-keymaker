package keymaker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

const nativeToken = "00000000000000000000000000000001"

type fixtureAct struct{ code Code }

func (v fixtureAct) Verify(context.Context, Principal, Binding, []byte) Code { return v.code }

type nativeFixture struct {
	server     *Server
	engine     *Engine
	generation *fakeGenerations
	native     *Native
	master     *Master
	state      *os.File
	store      *Store
	config     NativeConfig
	socketDir  string
	cancel     context.CancelFunc
	done       chan error
	stopped    bool
}

func nativeRegistry() Registry {
	return Registry{Products: []Product{{Name: "sample", Index: 1, Projects: []Project{{Name: "core", Index: 1, Agents: []AgentName{{"station-a", 1}, {"station-b", 2}}}}}}}
}
func nativeBase(t *testing.T, operator Principal, verifier OperatorActVerifier, binding *Binding) *nativeFixture {
	t.Helper()
	uid := uint32(os.Getuid())
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(d, "seed")
	if err := os.WriteFile(seed, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	master, err := LoadMaster(seed, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { master.Close() })
	statePath := filepath.Join(d, "state")
	if err := os.Mkdir(statePath, 0700); err != nil {
		t.Fatal(err)
	}
	state, err := OpenDirectory(statePath, uid, 0700)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	lock, err := LockState(state, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	store, err := fixtureOpenStore(state, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if binding != nil {
		if _, c := store.Register(operator, operator, *binding); c != "" {
			t.Fatal(c)
		}
	}
	generation := newGenerations(uid, nativeToken)
	if binding != nil && binding.UID != uid {
		generation.entries[binding.UID] = Generation{UID: binding.UID, Generation: binding.Generation, State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}
	}
	engine := NewEngine(store, generation, master, store.journal)
	socketDir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "n-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socketDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	cfg := NativeConfig{Operator: operator, Registry: nativeRegistry(), Epoch: "fixture-epoch", RegistryRevision: "fixture-revision"}
	server, err := NewDaemonServer(socketDir, engine, cfg, uint32(os.Getgid()), verifier)
	if err != nil {
		t.Fatal(err)
	}
	f := &nativeFixture{server: server, engine: engine, generation: generation, native: server.native, master: master, state: state, store: store, config: cfg, socketDir: socketDir}
	t.Cleanup(func() {
		if f.cancel != nil {
			f.cancel()
			select {
			case err := <-f.done:
				if err != nil && err != Code("audit_unavailable") {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("daemon did not stop")
			}
		} else if !f.stopped {
			server.Close()
			server.cleanup()
		}
	})
	return f
}
func (f *nativeFixture) start() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.done = make(chan error, 1)
	go func() { f.done <- f.server.Serve(ctx) }()
}
func nativeOwnBinding() Binding {
	b := fixtureBinding(uint32(os.Getuid()))
	b.Generation = nativeToken
	return b
}
func nativeID(n int) string { return fmt.Sprintf("%032x", n) }
func nativeHello(n int) control.Object {
	return control.Object{"method": "hello", "request_id": nativeID(n), "versions": []any{int64(1)}}
}
func nativeRequest(n int, method string, params control.Object) control.Object {
	return control.Object{"method": method, "params": params, "request_id": nativeID(n), "timeout_ms": int64(2000)}
}
func nativeDial(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	return c
}
func nativeSend(t *testing.T, c *net.UnixConn, obj control.Object) {
	t.Helper()
	body, err := control.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeResponse(c, Packet(body)); err != nil {
		t.Fatal(err)
	}
}
func nativeReceive(t *testing.T, c *net.UnixConn) control.Object {
	t.Helper()
	body, code := ReadFrame(c)
	if code != "" {
		t.Fatal("native response frame", code)
	}
	obj, err := control.Decode(body)
	if err != nil {
		t.Fatal("native response canonical wrapper", err)
	}
	return obj
}
func nativeResponse(t *testing.T, obj control.Object, id any, code Code) control.Object {
	t.Helper()
	if len(obj) != 2 || obj["request_id"] != id {
		t.Fatal("native response wrapper mismatch", obj)
	}
	for _, field := range []string{"private_key", "chain_code", "extended_private_key", "parent_seed", "sibling_seed", "signature", "envelope"} {
		encoded, _ := json.Marshal(obj)
		if bytes.Contains(encoded, []byte(`"`+field+`"`)) {
			t.Fatal("native response exposed forbidden field", field)
		}
	}
	if code != "" {
		err, ok := obj["error"].(control.Object)
		retry := code == "rate_limited" || code == "busy" || code == "generation_source_unavailable" || code == "enrollment_unavailable" || code == "audit_unavailable" || code == "request_deadline_exceeded"
		if !ok || len(err) != 2 || err["code"] != string(code) || err["retryable"] != retry {
			t.Fatalf("native refusal=%v, want %s", obj, code)
		}
		return nil
	}
	result, ok := obj["result"].(control.Object)
	if !ok {
		t.Fatal("native success result missing", obj)
	}
	return result
}
func nativeNegotiate(t *testing.T, c *net.UnixConn, n int) {
	t.Helper()
	nativeSend(t, c, nativeHello(n))
	result := nativeResponse(t, nativeReceive(t, c), nativeID(n), "")
	if !reflect.DeepEqual(result, control.Object{"version": int64(1)}) {
		t.Fatal("hello result", result)
	}
}
func nativeAudit(t *testing.T, j *Journal) []AuditRecord {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []AuditRecord
	for i := uint64(1); i <= j.segment; i++ {
		data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/%s", j.dir.Fd(), auditName(i)))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var record AuditRecord
			if err := json.Unmarshal(line, &record); err != nil {
				t.Fatal(err)
			}
			out = append(out, record)
		}
	}
	return out
}
func nativeSnapshot(t *testing.T, f *nativeFixture) []byte {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/bindings.json", f.state.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// All assigned vectors traverse the real dual-surface daemon, real Linux peer
// credentials, real Master and cross-bound Store/journal. Fixture role equality
// is projected onto the current UID/configured operator; no kernel UID is faked.
// Signed-act verdicts are injected interfaces, never parsed wire authority.
func TestNativeVectors(t *testing.T) {
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
		if err := json.Unmarshal(row.Input, &layer); err != nil {
			t.Fatal(err)
		}
		if layer.Evaluation != "native_framing" && !(layer.Evaluation == "native_method" && !strings.HasPrefix(row.ID, "helper-")) {
			continue
		}
		count++
		t.Run(row.ID, func(t *testing.T) {
			for _, sample := range []struct {
				name string
				data json.RawMessage
				code Code
			}{{"negative", row.Input, row.Code}, {"control", positive[row.Control], ""}} {
				t.Run(sample.name, func(t *testing.T) { runNativeVector(t, layer.Evaluation, sample.data, sample.code) })
			}
		})
	}
	if count != 23 {
		t.Fatal("native vector coverage drift", count)
	}
}
func runNativeVector(t *testing.T, evaluation string, data json.RawMessage, want Code) {
	t.Helper()
	var input struct {
		PeerUID            uint32          `json:"peer_uid"`
		OperatorUID        uint32          `json:"operator_uid"`
		PeerGeneration     string          `json:"peer_generation"`
		OperatorGeneration string          `json:"operator_generation"`
		Verdict            string          `json:"operator_record_verdict"`
		Lifetime           string          `json:"binding_lifetime"`
		Request            json.RawMessage `json:"request"`
		Frame              string          `json:"frame_hex"`
		EOF                bool            `json:"eof"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	operator := Principal{uid, nativeToken}
	if input.OperatorUID != 0 && input.PeerUID != input.OperatorUID {
		operator.UID = uid + 1
	}
	var verifier OperatorActVerifier
	if input.Verdict == "valid" {
		verifier = fixtureAct{}
	} else if input.Verdict == "invalid" {
		verifier = fixtureAct{code: "operator_record_invalid"}
	}
	var request control.Object
	var binding *Binding
	if evaluation == "native_method" {
		canonical, err := canonical(input.Request)
		if err != nil {
			t.Fatal(err)
		}
		request, err = control.Decode(canonical)
		if err != nil {
			t.Fatal(err)
		}
		if request["method"] != "register" {
			b := nativeOwnBinding()
			if request["method"] == "revoke" {
				b.UID = 30001
				b.Lifetime = input.Lifetime
			}
			binding = &b
		}
	}
	f := nativeBase(t, operator, verifier, binding)
	if request != nil && request["method"] == "register" {
		params := request["params"].(control.Object)
		target := uint32(params["target_uid"].(int64))
		f.generation.entries[target] = Generation{UID: target, Generation: params["target_generation"].(string), State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}
	}
	f.start()
	conn := nativeDial(t, f.server.ControlPath)
	var id any
	if evaluation == "native_method" {
		nativeNegotiate(t, conn, 100)
		id = request["request_id"]
	}
	before := nativeSnapshot(t, f)
	if evaluation == "native_framing" {
		body, err := hex.DecodeString(input.Frame)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeResponse(conn, body); err != nil {
			t.Fatal(err)
		}
		if input.EOF {
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		}
		if want == "" || want == "version_unsupported" || want == "request_malformed" {
			id = nativeID(1)
		}
	} else {
		nativeSend(t, conn, request)
	}
	result := nativeResponse(t, nativeReceive(t, conn), id, want)
	records := nativeAudit(t, f.store.journal)
	last := records[len(records)-1]
	if last.Surface != "control" {
		t.Fatal("native operation audited on wrong surface")
	}
	if want != "" {
		if last.RefusalCode == nil || *last.RefusalCode != want {
			t.Fatal("native refusal not audited", last.RefusalCode)
		}
		if !bytes.Equal(before, nativeSnapshot(t, f)) {
			t.Fatal("native refusal mutated binding/result state")
		}
	} else {
		if last.RefusalCode != nil || last.Result != "success" {
			t.Fatal("native success not audited")
		}
		if evaluation == "native_framing" {
			if !reflect.DeepEqual(result, control.Object{"version": int64(1)}) {
				t.Fatal("hello control", result)
			}
		} else if request["method"] == "revoke" {
			if !reflect.DeepEqual(result, control.Object{"registration_number": int64(1), "status": "revoked"}) || f.store.Snapshot()[0].Status != "revoked" {
				t.Fatal("revoke control", result)
			}
		} else {
			if !exactMembers(result, "public_key", "path", "registration_number", "master_epoch") {
				t.Fatal("public result schema", result)
			}
			public, err := base64.StdEncoding.DecodeString(result["public_key"].(string))
			expected, c := f.master.Public(result["path"].(string))
			if err != nil || c != "" || !bytes.Equal(public, expected) {
				t.Fatal("wrong public key")
			}
			if request["method"] == "register" && len(f.store.Snapshot()) != 1 {
				t.Fatal("registration not committed")
			}
		}
	}
}

type nativeCountSigner struct {
	Signer
	calls atomic.Int32
}

func (s *nativeCountSigner) Sign(path string, data []byte) ([]byte, Code) {
	s.calls.Add(1)
	return s.Signer.Sign(path, data)
}

// Unconfigured helper intake cannot reach a signer. Nearby self pubkey succeeds
// over the same daemon connection and contains only public metadata.
func TestNativeHelperUnsupported(t *testing.T) {
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
	signer := &nativeCountSigner{Signer: f.master}
	f.engine.Signer = signer
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	before := nativeSnapshot(t, f)
	nativeSend(t, c, nativeRequest(2, "sign_registration", control.Object{"name": "station-a", "aud": "fixture"}))
	nativeResponse(t, nativeReceive(t, c), nativeID(2), "enrollment_unavailable")
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("unsupported helper mutated state")
	}
	nativeSend(t, c, nativeRequest(3, "pubkey", control.Object{}))
	nativeResponse(t, nativeReceive(t, c), nativeID(3), "")
	if signer.calls.Load() != 0 {
		t.Fatal("unsupported helper reached signing path")
	}
}

func (f *nativeFixture) stop(t *testing.T) {
	t.Helper()
	if f.cancel == nil {
		return
	}
	f.cancel()
	select {
	case err := <-f.done:
		if err != nil && err != Code("audit_unavailable") {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon stop timeout")
	}
	f.cancel = nil
	f.stopped = true
}
func (f *nativeFixture) restart(t *testing.T, verifier OperatorActVerifier) {
	t.Helper()
	f.stop(t)
	f.store.Close()
	store, err := fixtureOpenStore(f.state, uint32(os.Getuid()))
	if err != nil {
		t.Fatal("reopen", err)
	}
	t.Cleanup(func() { store.Close() })
	f.store = store
	f.engine = NewEngine(store, f.generation, f.master, store.journal)
	f.server, err = NewDaemonServer(f.socketDir, f.engine, f.config, uint32(os.Getgid()), verifier)
	if err != nil {
		t.Fatal(err)
	}
	f.native = f.server.native
	f.stopped = false
	f.start()
}
func nativeRegisterRequest(n int) control.Object {
	return nativeRequest(n, "register", control.Object{"target_uid": int64(30001), "target_generation": nativeToken, "owner": "fixture-owner", "names": control.Object{"purpose": "agent-identity", "product": "sample", "project": "core", "agent": "station-a"}, "lifetime": "ephemeral"})
}
func nativeTarget(f *nativeFixture) {
	f.generation.entries[30001] = Generation{UID: 30001, Generation: nativeToken, State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}
}

// Unknown method strings are client content, not trusted audit metadata. Even
// a large marker refuses without reaching the journal verbatim or closing a
// healthy daemon; the adjacent public lookup still succeeds.
func TestNativeAuditMetadataBounded(t *testing.T) {
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	marker := strings.Repeat("fixture-sensitive-marker", 500)
	before := nativeSnapshot(t, f)
	nativeSend(t, c, nativeRequest(2, marker, control.Object{}))
	nativeResponse(t, nativeReceive(t, c), nativeID(2), "operation_unsupported")
	records := nativeAudit(t, f.store.journal)
	last := records[len(records)-1]
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if last.Operation != "unparsed" || bytes.Contains(encoded, []byte("fixture-sensitive-marker")) {
		t.Fatal("raw method entered typed audit")
	}
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("unknown method mutated result state")
	}
	nativeSend(t, c, nativeRequest(3, "pubkey", control.Object{}))
	nativeResponse(t, nativeReceive(t, c), nativeID(3), "")
}
