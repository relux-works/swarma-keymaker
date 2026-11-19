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

// productionTimeConfidenceMetadata pins the provider and accepts only the
// adjacent in-tree messageauthor dep/replacement pair. It checks module records,
// not incidental substrings in binary paths, build settings or other modules.
func productionTimeConfidenceMetadata(raw []byte) bool {
	const broker = "github.com/relux-works/swarma-credential-broker"
	const brokerVersion = "v0.0.0-20261030053047-e7619dfc4b2a"
	const author = "github.com/relux-works/swarma-keymaker/messageauthor"
	const authorVersion = "v0.0.0-00010101000000-000000000000"
	lines := strings.Split(string(raw), "\n")
	brokerSeen, authorSeen := false, false
	for i := 0; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "dep":
			if len(fields) < 3 || len(fields) > 4 {
				return false
			}
			if fields[1] == broker {
				if brokerSeen || fields[2] != brokerVersion {
					return false
				}
				brokerSeen = true
			}
			if fields[1] == author {
				if authorSeen || len(fields) != 3 || fields[2] != authorVersion || i+1 == len(lines) {
					return false
				}
				replacement := strings.Fields(lines[i+1])
				if len(replacement) != 3 || replacement[0] != "=>" || replacement[1] != "./messageauthor" || replacement[2] != "(devel)" {
					return false
				}
				authorSeen = true
				i++
			}
		case "=>":
			return false
		}
	}
	return brokerSeen && authorSeen
}

// Literal dep/replacement fixtures distinguish the one permitted pair from
// foreign, duplicate, nonadjacent or changed pins. These are parser controls;
// the separate real-binary test also checks linked symbols and entry dispatch.
func TestTimeConfidenceProductionMetadata(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata string
		want     bool
	}{
		{"valid-in-repo-pair", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)`, true},
		{"valid-other-unreplaced-dependency", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)
dep example.com/other v1.0.0 h1:fixture`, true},
		{"extra-other-replacement", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)
dep example.com/other v1.0.0
=> ../other (devel)`, false},
		{"messageauthor-other-path", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ../elsewhere (devel)`, false},
		{"messageauthor-version-target", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> example.com/author v1.0.0 h1:fixture`, false},
		{"broker-pin-changed", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053048-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)`, false},
		{"broker-replaced", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
=> ../broker (devel)
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)`, false},
		{"second-in-repo-pair", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)`, false},
		{"stray-second-replacement", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)
=> ./messageauthor (devel)`, false},
		{"nonadjacent-pair", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
build -trimpath=true
=> ./messageauthor (devel)`, false},
		{"blank-between-pair", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000

=> ./messageauthor (devel)`, false},
		{"messageauthor-source-version-changed", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-20261030053047-e7619dfc4b2a
=> ./messageauthor (devel)`, false},
		{"messageauthor-path-prefix", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor-extra (devel)`, false},
		{"messageauthor-target-version-changed", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor v1.0.0`, false},
		{"replacement-extra-field", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel) h1:extra`, false},
		{"missing-replacement", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000`, false},
		{"missing-broker", `dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)`, false},
		{"duplicate-broker", `dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)`, false},
		{"broker-substring-only", `dep example.com/github.com/relux-works/swarma-credential-broker v0.0.0-20261030053047-e7619dfc4b2a h1:fixture
dep github.com/relux-works/swarma-keymaker/messageauthor v0.0.0-00010101000000-000000000000
=> ./messageauthor (devel)`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := productionTimeConfidenceMetadata([]byte(tc.metadata)); got != tc.want {
				t.Fatalf("metadata verdict = %t, want %t", got, tc.want)
			}
		})
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
	if !productionTimeConfidenceMetadata(meta) {
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
