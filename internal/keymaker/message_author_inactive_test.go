//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"github.com/relux-works/swarma-keymaker/internal/control"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Actual legacy Unix transport refuses both new methods while ordinary pubkey
// succeeds. No message-author retained success, binding or key allocation is
// created. This is a private single-UID fixture, not native qualification.
func TestMessageAuthorRuntimeStaysClosed(t *testing.T) {
	own := nativeOwnBinding()
	f := nativeBase(t, Principal{own.UID, nativeToken}, nil, &own)
	f.start()
	before := f.store.Snapshot()
	for i, m := range []string{"message_author_identity", "sign_message_author"} {
		conn := nativeDial(t, f.server.ControlPath)
		nativeNegotiate(t, conn, 10+i*2)
		params := control.Object{}
		if m == "sign_message_author" {
			params["preimage"] = "Zml4dHVyZQ"
		}
		nativeSend(t, conn, nativeRequest(11+i*2, m, params))
		nativeResponse(t, nativeReceive(t, conn), nativeID(11+i*2), "operation_unsupported")
		_ = conn.Close()
	}
	if !reflect.DeepEqual(before, f.store.Snapshot()) {
		t.Fatal("message fixture methods changed bindings")
	}
	f.store.mu.Lock()
	for _, r := range f.store.requests {
		if r.Method != "hello" {
			t.Errorf("unregistered method retained: %s", r.Method)
		}
	}
	f.store.mu.Unlock()
	conn := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, conn, 20)
	nativeSend(t, conn, nativeRequest(21, "pubkey", control.Object{}))
	nativeResponse(t, nativeReceive(t, conn), nativeID(21), "")
	_ = conn.Close()
	// Legacy path/name/registration unions do not gain purpose9 from a catalog row.
	m := &Master{seed: make([]byte, 32)}
	defer m.Close()
	if p, c := m.Public("m/9'/1'/2'/3'"); c != "purpose_unknown" || p != nil {
		t.Fatal("legacy key surface widened", c)
	}
	if p, c := m.Sign("m/9'/1'/2'/3'", []byte("fixture")); c != "purpose_unknown" || p != nil {
		t.Fatal("legacy signing widened", c)
	}
	if path, c := nativeRegistry().Resolve(Names{Purpose: "message-author", Product: "sample", Project: "core", Agent: "station-a"}); c != "purpose_unknown" || path != "" {
		t.Fatal("legacy registry widened", c)
	}
	k, s, b := maFixture(t)
	_ = k
	bad := b
	bad.Path = "m/9'/1'/2'/3'"
	before = s.Snapshot()
	if _, c := s.Register(fixtureOperator, fixtureOperator, bad); c != "binding_conflict" || !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("purpose9 registered", c)
	}
	if cert, c := s.messageCurrent(b); c != "key_not_enrolled" || !reflect.DeepEqual(cert, messageCertificate{}) {
		t.Fatal("invented current certificate", c)
	}
	if _, e := ParseConfig(strings.NewReader(strings.Replace(j7Config(j7RequestRole), j7RequestRole, messageAuthorRole, 1))); e == nil {
		t.Fatal("message role accepted by config")
	}
	for _, role := range []string{j7RequestRole, j7DelegationRole} {
		cfg, e := ParseConfig(strings.NewReader(j7Config(role)))
		if e != nil {
			t.Fatal(e)
		}
		var status bytes.Buffer
		want := Code("operation_unsupported")
		if role == j7RequestRole {
			want = "j7_configuration_incomplete"
		}
		if e := serveValidatedConfig(context.Background(), cfg, &status, nil); e != want || status.Len() != 0 {
			t.Fatal("startup gate widened", e)
		}
	}
}

// Source reachability supplements runtime refusals: only the two private files
// can name the new capability/plan; no production constructor or key-loading API
// exists. It is a syntactic guard, not whole-program authority proof.
func TestMessageAuthorSourceIsolation(t *testing.T) {
	files, e := filepath.Glob("*.go")
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		allowed := path == "message_author_issuer.go" || path == "message_author_key.go" || path == "message_author_preimage.go" || path == "message_author_live.go" || path == "message_author_live_state.go" || path == "message_author_live_service_linux.go" || path == "message_author_live_custody_linux.go"
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if n.Name == "messageAuthorKey" || n.Name == "messageAuthorPlan" || n.Name == "prepareMessageAuthor" {
					if !allowed {
						t.Errorf("capability reachable: %s", path)
					}
					found = true
				}
			case *ast.FuncDecl:
				if allowed && n.Recv == nil && n.Name.IsExported() {
					t.Errorf("public initializer/factory: %s", n.Name)
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("source isolation instrument empty")
	}
	for _, path := range []string{"native.go", "../control/server.go", "config_linux.go"} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"message_author_identity", "sign_message_author", "message-author"} {
			if path == "config_linux.go" && name == "message-author" {
				continue
			}
			if bytes.Contains(b, []byte(name)) {
				t.Fatal("runtime profile/route added", path)
			}
		}
	}
}
