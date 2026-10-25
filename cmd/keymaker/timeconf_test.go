package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func collectorFirst(raw []byte) bool {
	f, e := parser.ParseFile(token.NewFileSet(), "main.go", raw, 0)
	if e != nil {
		return false
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) == 0 {
			return false
		}
		stmt, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := stmt.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "timeconf" || sel.Sel.Name != "CollectorEntry" {
			return false
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"github.com/relux-works/swarma-credential-broker/timeconf"` && (imp.Name == nil || imp.Name.Name == "timeconf") {
				return true
			}
		}
	}
	return false
}

// The actual entry dispatch must precede even argument parsing. A test-only
// source override lets the external narrowing control feed an exact bad file;
// neither this reader nor its environment variable is in production builds.
func TestCollectorEntryFirst(t *testing.T) {
	path := "main.go"
	if p := os.Getenv("KEYMAKER_TEST_MAIN_SOURCE"); p != "" {
		path = p
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if !collectorFirst(raw) {
		t.Fatal("CollectorEntry is not first statement in main")
	}
	bad := strings.Replace(string(raw), "timeconf.CollectorEntry()", "_ = os.Args\n timeconf.CollectorEntry()", 1)
	if collectorFirst([]byte(bad)) {
		t.Fatal("conformance checker accepted preceding argument access")
	}
}

// The normal binary pins the public provider and has no fixture collector
// symbols. Collector-mode malformed input exits125 before ordinary dispatch;
// version remains a valid nonservice command. No collector command is executed.
func TestTimeConfidenceProductionBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keymaker")
	if b, e := exec.Command("go", "build", "-buildvcs=false", "-o", path, ".").CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	meta, e := exec.Command("go", "version", "-m", path).CombinedOutput()
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(meta), "github.com/relux-works/swarma-credential-broker\tv0.0.0-20261025133248-8cdea829b261") || strings.Contains(string(meta), "=>") {
		t.Fatalf("provider pin/replacement: %s", meta)
	}
	symbols, e := exec.Command("go", "tool", "nm", path).CombinedOutput()
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"confidenceCollector", "confidenceClock", "fixtureAuditClock", "fixtureTimeClock", "fixtureTimeCollector", "approvalEvidence", "approvalPoint", "fixedApprovalSource", "helperClock"} {
		if strings.Contains(string(symbols), name) {
			t.Fatal("fixture reachable in production", name)
		}
	}
	cmd := exec.Command(path, "--internal-timeconf-exec", "invalid-operation")
	if out, e := cmd.CombinedOutput(); e == nil {
		t.Fatal("invalid collector mode succeeded", string(out))
	} else if x, ok := e.(*exec.ExitError); !ok || x.ExitCode() != 125 || len(out) != 0 {
		t.Fatalf("collector did not dispatch first: %v %s", e, out)
	}
	if out, e := exec.Command(path, "version").CombinedOutput(); e != nil || strings.TrimSpace(string(out)) != version {
		t.Fatal("version control", e, string(out))
	}
}
