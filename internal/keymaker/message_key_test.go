package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/waggle/record"
)

type messageKeyFixture struct {
	Seed    string `json:"seed_hex"`
	Vectors []struct {
		IdentityPath string            `json:"identity_path"`
		MessagePath  string            `json:"message_path"`
		Public       string            `json:"public_key_hex"`
		ID           string            `json:"key_id"`
		Siblings     map[string]string `json:"sibling_public_hex"`
	} `json:"vectors"`
}

func messageFixtures(t *testing.T) messageKeyFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/message-key.json")
	if err != nil {
		t.Fatal(err)
	}
	var f messageKeyFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) != 3 {
		t.Fatal("missing independent message fixtures")
	}
	return f
}

func messageAdapterFixture(t *testing.T, path string) (messageKeyAdapter, Binding) {
	t.Helper()
	f := messageFixtures(t)
	m := &Master{seed: fromHex(t, f.Seed)}
	t.Cleanup(func() { m.Close() })
	s := NewStore()
	b := fixtureBinding(30001)
	b.Path = path
	b.Lifetime = "persistent"
	b, c := s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" {
		t.Fatal(c)
	}
	return messageKeyAdapter{master: m, store: s, epoch: b.Epoch, registryRevision: b.RegistryRevision}, b
}

// Static public-byte oracles come from the pinned upstream Python SLIP reference,
// not this package's deriveNode; three tuples include nontrivial and 31-bit indices.
func TestMsgV09PurposeKeyBytes(t *testing.T) {
	f := messageFixtures(t)
	for _, v := range f.Vectors {
		t.Run(v.IdentityPath, func(t *testing.T) {
			a, b := messageAdapterFixture(t, v.IdentityPath)
			// Wrong binding input cannot select even another otherwise valid identity path.
			changed := b
			changed.Path = "m/1'/99'/98'/97'"
			if pub, id, c := a.public(changed); c != "binding_conflict" || pub != nil || id != "" {
				t.Fatal("caller-selected path admitted", c)
			}
			pub, id, c := a.public(b)
			if c != "" || hex.EncodeToString(pub) != v.Public || id != v.ID {
				t.Fatal("independent purpose-4 oracle mismatch", c)
			}
			alg, decoded, err := record.KeyBytes(id)
			if err != nil || alg != "ed25519" || !bytes.Equal(decoded, pub) || record.ValidateKey(id) != nil {
				t.Fatal("noncanonical or invalid message key")
			}
			for purpose, want := range v.Siblings {
				if purpose == "4" {
					continue
				}
				if hex.EncodeToString(pub) == want {
					t.Fatal("purpose sibling collision", purpose)
				}
			}
			// Returned public bytes are owned by the caller, never shared cached authority.
			pub[0] ^= 1
			again, againID, c := a.public(b)
			if c != "" || hex.EncodeToString(again) != v.Public || againID != v.ID {
				t.Fatal("public result aliases adapter state", c)
			}
		})
	}
}

// Purpose-4 access is internal only: public Master APIs remain purpose-1 and the
// reserved signer verifies only with the independent purpose-4 fixture key.
func TestMsgPurposeGuards(t *testing.T) {
	f := messageFixtures(t)
	v := f.Vectors[0]
	a, b := messageAdapterFixture(t, v.IdentityPath)
	for _, path := range []string{v.MessagePath, "m/2'/1'/1'/1'", "m/3'/1'/1'/1'", "m/5'/1'/1'/1'"} {
		if pub, c := a.master.Public(path); c != "purpose_unknown" || pub != nil {
			t.Fatal("general Public exposed another purpose", c)
		}
		if sig, c := a.master.Sign(path, []byte("test")); c != "purpose_unknown" || sig != nil {
			t.Fatal("general Sign exposed another purpose", c)
		}
	}
	for _, path := range []string{"m/4/1'/1'/1'", "m/4'/1'/1'/1", "m/4'/1'/1'", "m/4'/1'/1'/1'/1'", "m/4'/2147483648'/1'/1'"} {
		if ValidatePath(path, "swarma-msg") == "" {
			t.Fatal("malformed message path admitted")
		}
	}
	if ValidatePath(v.MessagePath, "swarma-msg") != "" {
		t.Fatal("valid message path refused")
	}
	pub, c := a.master.Public(v.IdentityPath)
	if c != "" || hex.EncodeToString(pub) != v.Siblings["1"] {
		t.Fatal("purpose-1 public control refused", c)
	}
	data := []byte("internal purpose-4 capability fixture; not a production signing API")
	sig, c := a.sign(b, data)
	if c != "" || len(sig) != 64 || !ed25519.Verify(fromHex(t, v.Public), data, sig) {
		t.Fatal("reserved purpose-4 signer mismatch", c)
	}
	for purpose, raw := range v.Siblings {
		if purpose != "4" && ed25519.Verify(fromHex(t, raw), data, sig) {
			t.Fatal("wrong-purpose signature verified", purpose)
		}
	}
}

// Rejected bindings never derive/sign; epoch/revision selection is service-owned,
// and actual Store tombstones/retirement prevent stale selected-binding reuse.
func TestMsgBindingGuards(t *testing.T) {
	for _, field := range []string{"path", "epoch", "registry", "owner", "registration", "uid", "generation", "status"} {
		t.Run(field, func(t *testing.T) {
			a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
			changed := b
			switch field {
			case "path":
				changed.Path = "m/1'/2'/2'/2'"
			case "epoch":
				changed.Epoch = "different"
			case "registry":
				changed.RegistryRevision = "different"
			case "owner":
				changed.Owner = "different"
			case "registration":
				changed.Number++
			case "uid":
				changed.UID++
			case "generation":
				changed.Generation = "different"
			case "status":
				changed.Status = "revoked"
			}
			want := Code("binding_conflict")
			if field == "uid" || field == "generation" {
				want = "binding_not_found"
			}
			if pub, id, c := a.public(changed); c != want || pub != nil || id != "" {
				t.Fatal("selected binding substitution admitted", c, want)
			}
			if sig, c := a.sign(changed, []byte("test")); c != want || sig != nil {
				t.Fatal("selected binding substitution signed", c, want)
			}
			if _, _, c := a.public(b); c != "" {
				t.Fatal("unchanged binding control refused", c)
			}
		})
	}
	for _, mode := range []string{"retired", "revoked", "wrong-epoch", "wrong-registry", "failed-store"} {
		t.Run(mode, func(t *testing.T) {
			a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
			if _, _, c := a.public(b); c != "" {
				t.Fatal(c)
			}
			want := Code("binding_conflict")
			switch mode {
			case "retired":
				if c := a.store.Unbind(fixtureOperator, fixtureOperator, b.UID, b.Generation); c != "" {
					t.Fatal(c)
				}
				want = "binding_not_found"
			case "revoked":
				// Persistent native revoke is separately gated; install a valid stored
				// tombstone as the internal custody state this adapter must always refuse.
				a.store.mu.Lock()
				a.store.records[0].Status = "revoked"
				a.store.mu.Unlock()
				want = "identity_revoked"
			case "wrong-epoch":
				a.epoch = "different"
			case "wrong-registry":
				a.registryRevision = "different"
			case "failed-store":
				a.store.failed = true
				want = "audit_unavailable"
			}
			before := a.store.Snapshot()
			if pub, id, c := a.public(b); c != want || pub != nil || id != "" {
				t.Fatal("withdrawn binding disclosed key", c, want)
			}
			if sig, c := a.sign(b, []byte("test")); c != want || sig != nil {
				t.Fatal("withdrawn binding signed", c, want)
			}
			if !reflect.DeepEqual(before, a.store.Snapshot()) {
				t.Fatal("refusal changed bindings")
			}
		})
	}
}

// Persistent explicit reuse preserves purpose-4 bytes, whereas ephemeral reuse
// and revoked-path resurrection fail before a new adapter-selected key exists.
func TestMsgV16StablePersistentKey(t *testing.T) {
	for _, life := range []string{"ephemeral", "persistent"} {
		t.Run(life, func(t *testing.T) {
			a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
			a.store.records[0].Lifetime = life
			b.Lifetime = life
			pub, id, c := a.public(b)
			if c != "" {
				t.Fatal(c)
			}
			if c := a.store.Unbind(fixtureOperator, fixtureOperator, b.UID, b.Generation); c != "" {
				t.Fatal(c)
			}
			if _, _, c := a.public(b); c != "binding_not_found" {
				t.Fatal("retired binding recovered key", c)
			}
			next := b
			next.Generation = "next-generation"
			next, c = a.store.Register(fixtureOperator, fixtureOperator, next)
			if life == "ephemeral" {
				if c != "binding_conflict" {
					t.Fatal("ephemeral path recycled", c)
				}
				next = b
				next.Path = "m/1'/1'/1'/2'"
				next.Generation = "next-generation"
				next, c = a.store.Register(fixtureOperator, fixtureOperator, next)
				if c != "" {
					t.Fatal(c)
				}
				other, _, c := a.public(next)
				if c != "" || bytes.Equal(other, pub) {
					t.Fatal("fresh ephemeral key control failed", c)
				}
			} else {
				if c != "" || next.Number == b.Number {
					t.Fatal("explicit persistent reuse refused", c)
				}
				again, againID, c := a.public(next)
				if c != "" || !bytes.Equal(again, pub) || againID != id {
					t.Fatal("stable purpose-4 key changed", c)
				}
			}
		})
	}
	a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
	a.store.records[0].Status = "revoked"
	if _, c := a.store.Register(fixtureOperator, fixtureOperator, b); c != "identity_revoked" {
		t.Fatal("tombstone resurrected", c)
	}
}

// Purpose-4 bindings/selectors remain outside both registry/native registration;
// current daemon dispatch rejects sign_message while ordinary pubkey still works.
func TestMsgProductionBoundary(t *testing.T) {
	a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
	bad := b
	bad.Path = "m/4'/1'/1'/1'"
	bad.Generation = "another"
	before := a.store.Snapshot()
	if _, c := a.store.Register(fixtureOperator, fixtureOperator, bad); c != "binding_conflict" {
		t.Fatal("purpose-4 register admitted", c)
	}
	if !reflect.DeepEqual(before, a.store.Snapshot()) {
		t.Fatal("purpose-4 register changed state")
	}
	names := Names{Purpose: "swarma-msg", Product: "sample", Project: "core", Agent: "station-a"}
	if _, c := nativeRegistry().Resolve(names); c != "purpose_unknown" {
		t.Fatal("registry exposes purpose 4", c)
	}
	names.Purpose = "agent-identity"
	if path, c := nativeRegistry().Resolve(names); c != "" || path != b.Path {
		t.Fatal("identity registry control refused", c)
	}
	own := nativeOwnBinding()
	f := nativeBase(t, Principal{own.UID, nativeToken}, nil, &own)
	f.start()
	beforeNative := f.store.Snapshot()
	conn := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, conn, 1)
	nativeSend(t, conn, nativeRequest(2, "sign_message", control.Object{"preimage": "c3dhcm1hLW1zZy8yCg"}))
	nativeResponse(t, nativeReceive(t, conn), nativeID(2), "operation_unsupported")
	conn = nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, conn, 3)
	params := control.Object{"target_uid": int64(own.UID), "target_generation": nativeToken, "owner": own.Owner, "lifetime": "ephemeral", "names": control.Object{"purpose": "swarma-msg", "product": "sample", "project": "core", "agent": "station-a"}}
	nativeSend(t, conn, nativeRequest(4, "register", params))
	nativeResponse(t, nativeReceive(t, conn), nativeID(4), "purpose_unknown")
	conn = nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, conn, 5)
	nativeSend(t, conn, nativeRequest(6, "pubkey", control.Object{"purpose": "swarma-msg", "path": "m/4'/1'/1'/1'"}))
	nativeResponse(t, nativeReceive(t, conn), nativeID(6), "request_malformed")
	if !reflect.DeepEqual(beforeNative, f.store.Snapshot()) {
		t.Fatal("native negative controls changed bindings")
	}
	f.store.mu.Lock()
	for _, r := range f.store.requests {
		if r.Method != "hello" {
			t.Errorf("native negative control retained a success for %s", r.Method)
		}
	}
	f.store.mu.Unlock()
	conn = nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, conn, 7)
	nativeSend(t, conn, nativeRequest(8, "pubkey", control.Object{}))
	nativeResponse(t, nativeReceive(t, conn), nativeID(8), "")
}

// Surface A advertises precisely one purpose-1 key, and cannot sign with the
// purpose-4 public key. The existing exact identity decoder is the positive gate.
func TestMsgSurfaceAIsolation(t *testing.T) {
	a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
	e := NewEngine(a.store, newGenerations(b.UID, b.Generation), a.master, &memoryAudit{})
	session := e.OpenSession(context.Background(), Peer{UID: b.UID})
	if session.Admission != "" {
		t.Fatal(session.Admission)
	}
	msg, _, c := a.public(b)
	if c != "" {
		t.Fatal(c)
	}
	if c := e.Handle(context.Background(), session, validBody(msg, "git"), func(context.Context, []byte) error { t.Fatal("A signed with message key"); return nil }); c != "sign_key_mismatch" {
		t.Fatal("A selected message key", c)
	}
	identity, c := a.master.Public(b.Path)
	if c != "" {
		t.Fatal(c)
	}
	if c := e.Handle(context.Background(), session, []byte{11}, func(_ context.Context, response []byte) error {
		checkResponse(t, response, identity, []byte{11})
		return nil
	}); c != "" {
		t.Fatal("A identity control refused", c)
	}
}

// An AST boundary supplements wire controls: no non-test package file outside
// message_key.go may construct/name the adapter. This deliberately checks source
// reachability, not dynamic whole-program proof or future activation permission.
func TestMsgAdapterUnreachable(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if ok && id.Name == "messageKeyAdapter" {
				if path != "message_key.go" {
					t.Errorf("message adapter reached by production source %s", path)
				}
				found = true
			}
			return true
		})
	}
	if !found {
		t.Fatal("adapter boundary control did not locate adapter")
	}
}

// Unavailable/closed/malformed custody and a missing Store return no public key,
// ID or signature; the independently known healthy key is the positive control.
func TestMsgCustodyGuards(t *testing.T) {
	for _, mode := range []string{"nil-master", "closed", "unloaded", "malformed", "nil-store"} {
		t.Run(mode, func(t *testing.T) {
			a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
			if _, _, c := a.public(b); c != "" {
				t.Fatal(c)
			}
			want := Code("custody_unavailable")
			switch mode {
			case "nil-master":
				a.master = nil
			case "closed":
				a.master.Close()
			case "unloaded":
				a.master = &Master{}
			case "malformed":
				a.master = &Master{seed: []byte{1}}
			case "nil-store":
				a.store = nil
				want = "binding_not_found"
			}
			if pub, id, c := a.public(b); c != want || pub != nil || id != "" {
				t.Fatal("unavailable custody disclosed key", c)
			}
			if sig, c := a.sign(b, []byte("test")); c != want || sig != nil {
				t.Fatal("unavailable custody signed", c)
			}
		})
	}
}
