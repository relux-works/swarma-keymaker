//go:build linux

package timeconfidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	brokerModule   = "github.com/relux-works/swarma-credential-broker"
	fixturePackage = brokerModule + "/timeconftest"
	fixtureTag     = "swarma_timeconf_fixture"
)

type fixturePolicyError struct{ rule, path string }

func (e *fixturePolicyError) Error() string { return e.rule + ": " + e.path }

// All other tags are free variables. A false fixture tag must leave no
// satisfying assignment; evaluating only the current platform would miss ORs.
func requiresFixtureTag(expr constraint.Expr) bool {
	tags := []string{}
	seen := map[string]bool{fixtureTag: true}
	var collect func(constraint.Expr)
	collect = func(expr constraint.Expr) {
		switch e := expr.(type) {
		case *constraint.TagExpr:
			if !seen[e.Tag] {
				seen[e.Tag] = true
				tags = append(tags, e.Tag)
			}
		case *constraint.NotExpr:
			collect(e.X)
		case *constraint.AndExpr:
			collect(e.X)
			collect(e.Y)
		case *constraint.OrExpr:
			collect(e.X)
			collect(e.Y)
		}
	}
	collect(expr)
	values := map[string]bool{}
	var satisfies func(int) bool
	satisfies = func(i int) bool {
		if i == len(tags) {
			return expr.Eval(func(tag string) bool { return values[tag] })
		}
		values[tags[i]] = false
		if satisfies(i + 1) {
			return true
		}
		values[tags[i]] = true
		return satisfies(i + 1)
	}
	return !satisfies(0)
}

func fixtureImportPolicy(name string, raw []byte) error {
	f, err := parser.ParseFile(token.NewFileSet(), name, raw, parser.ParseComments)
	if err != nil {
		return err
	}
	importsFixture := false
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		importsFixture = importsFixture || path == fixturePackage
	}
	if !importsFixture {
		return nil
	}
	if !strings.HasSuffix(name, "_test.go") {
		return &fixturePolicyError{"fixture_application_import", name}
	}
	var modern, legacy constraint.Expr
	for _, group := range f.Comments {
		for _, c := range group.List {
			if c.Pos() >= f.Package {
				continue
			}
			if !constraint.IsGoBuild(c.Text) && !constraint.IsPlusBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				return err
			}
			if constraint.IsGoBuild(c.Text) {
				if modern != nil {
					return &fixturePolicyError{"fixture_build_constraint", name}
				}
				modern = expr
			} else if legacy == nil {
				legacy = expr
			} else {
				legacy = &constraint.AndExpr{X: legacy, Y: expr}
			}
		}
	}
	if modern == nil {
		modern = legacy
	}
	if modern == nil || !requiresFixtureTag(modern) || (legacy != nil && !requiresFixtureTag(legacy)) {
		return &fixturePolicyError{"fixture_build_constraint", name}
	}
	return nil
}

func checkFixtureSources(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		// Explicit imports can reach dot/underscore and scratch-named directories
		// even when ./... omits them. Only VCS internals are outside this scan.
		if entry.IsDir() {
			if path != root && entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return fixtureImportPolicy(path, raw)
	})
}

func fixtureGo(ctx context.Context, root string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	// CI downloads modules before tests. Even private modules must stay offline;
	// user workspaces, persisted Go settings and inherited tags cannot select code.
	cmd.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOPROXY=off", "GONOPROXY=none", "GOSUMDB=off", "GOTELEMETRY=off", "GOFLAGS=-p=2")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("graph_command: go %s: %w: %s; run go mod download before tests", strings.Join(args, " "), err, &stderr)
	}
	return out, nil
}

type fixtureGraphPackage struct {
	ImportPath, Dir, ForTest string
	CompiledGoFiles          []string
}

func checkCompiledTimeconf(name string) error {
	f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		return err
	}
	var violation error
	ast.Inspect(f, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.Ident:
			if strings.Contains(strings.ToLower(n.Name), "fixture") {
				violation = &fixturePolicyError{"compiled_fixture_implementation", name}
			}
		case *ast.CompositeLit:
			if id, ok := n.Type.(*ast.Ident); ok && id.Name == "pathQualification" {
				violation = &fixturePolicyError{"compiled_fixture_construction", name}
			}
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 {
				if typ, ok := n.Args[0].(*ast.Ident); ok && typ.Name == "pathQualification" {
					violation = &fixturePolicyError{"compiled_fixture_construction", name}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "timePath" {
					violation = &fixturePolicyError{"compiled_fixture_construction", name}
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := n.Key.(*ast.Ident); ok && key.Name == "timePath" {
				violation = &fixturePolicyError{"compiled_fixture_construction", name}
			}
		}
		return violation == nil
	})
	return violation
}

func checkFixtureGraph(ctx context.Context, root, tags string) error {
	raw, err := fixtureGo(ctx, root, "list", "-mod=readonly", "-deps", "-compiled", "-json", "-tags="+tags, "./...")
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	brokerFiles := 0
	for {
		var pkg fixtureGraphPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if pkg.ImportPath == fixturePackage {
			return &fixturePolicyError{"graph_fixture_import", pkg.ImportPath}
		}
		if pkg.ForTest != "" {
			return fmt.Errorf("unexpected test graph: %s", pkg.ImportPath)
		}
		if pkg.ImportPath != brokerModule && !strings.HasPrefix(pkg.ImportPath, brokerModule+"/") {
			continue
		}
		for _, name := range pkg.CompiledGoFiles {
			brokerFiles++
			if !filepath.IsAbs(name) {
				name = filepath.Join(pkg.Dir, name)
			}
			if tags == "" {
				if err := checkCompiledTimeconf(name); err != nil {
					return err
				}
			}
		}
	}
	if brokerFiles == 0 {
		return fmt.Errorf("graph lacks compiled timeconf sources")
	}
	return nil
}

func fixturePolicyWant(t *testing.T, err error, rule string) {
	t.Helper()
	if rule == "" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var policy *fixturePolicyError
	if !errors.As(err, &policy) || policy.rule != rule {
		t.Fatalf("expected %s assertion, got %v", rule, err)
	}
	t.Logf("rejected at %s", rule)
}

func fixturePolicyWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// Graph controls copy module metadata, never the checkout or module cache.
// The current CI download step supplies all selected modules for offline probes.
func fixtureGraphRoot(t *testing.T, root, source string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum"} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		fixturePolicyWrite(t, filepath.Join(dir, name), string(raw))
	}
	fixturePolicyWrite(t, filepath.Join(dir, "probe.go"), source)
	return dir
}

// This gate runs in ordinary Linux CI. Source checks cover excluded files;
// actual non-test graphs cover default and fixture tags independently. It
// contains fixtures at this exact pin, not arbitrary obfuscated source or a
// deployed artifact, and does not qualify receipts, time or restore protection.
func TestTimeconfFixtureDependencyPolicy(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	t.Run("RepositorySources", func(t *testing.T) {
		fixturePolicyWant(t, checkFixtureSources(root), "")
	})
	for _, tags := range []string{"", fixtureTag} {
		t.Run("RepositoryGraph/"+map[bool]string{true: "default", false: "tagged"}[tags == ""], func(t *testing.T) {
			fixturePolicyWant(t, checkFixtureGraph(ctx, root, tags), "")
		})
	}
	// Each syntactically valid import plant has an independent policy verdict;
	// filename exclusion never makes application imports acceptable. The two
	// passing controls prevent a reject-all implementation satisfying this table.
	t.Run("SourceControls", func(t *testing.T) {
		cases := []struct{ name, file, guard, imp, use, rule string }{
			{"AliasedApplication", "probe.go", fixtureTag, "renamed ", "renamed.New", "fixture_application_import"},
			{"BlankApplication", "probe.go", fixtureTag, "_ ", "", "fixture_application_import"},
			{"DotApplication", "probe.go", fixtureTag, ". ", "New", "fixture_application_import"},
			{"ExcludedApplication", "probe_windows.go", "windows && " + fixtureTag, "_ ", "", "fixture_application_import"},
			{"UnguardedTest", "probe_test.go", "", "_ ", "", "fixture_build_constraint"},
			{"ORGuardedTest", "probe_test.go", fixtureTag + " || other", "_ ", "", "fixture_build_constraint"},
			{"NestedORTest", "probe_test.go", fixtureTag + " || (other && another)", "_ ", "", "fixture_build_constraint"},
			{"UnrelatedANDTest", "probe_test.go", "other && another", "_ ", "", "fixture_build_constraint"},
			{"NegatedGuardTest", "probe_test.go", "!" + fixtureTag, "_ ", "", "fixture_build_constraint"},
			{"GuardedTest", "probe_test.go", "linux && " + fixtureTag, "_ ", "", ""},
			{"NonLinuxGuardedTest", "probe_test.go", fixtureTag + " && !linux", "_ ", "", ""},
			{"DeMorganGuardedTest", "probe_test.go", "!(!" + fixtureTag + " || other)", "_ ", "", ""},
			{"OrdinarySource", "probe.go", "", "_ ", "", ""},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				guard := ""
				if c.guard != "" {
					guard = "//go:build " + c.guard + "\n\n"
				}
				path := fixturePackage
				if c.name == "OrdinarySource" {
					path = "context"
				}
				source := guard + "package probe\nimport " + c.imp + strconv.Quote(path) + "\n"
				if c.use != "" {
					source += "var _ = " + c.use + "\n"
				}
				dir := t.TempDir()
				fixturePolicyWrite(t, filepath.Join(dir, c.file), source)
				fixturePolicyWant(t, checkFixtureSources(dir), c.rule)
			})
		}
	})
	// Successful real Go graphs (not fabricated JSON) must reach the dependency
	// assertion independently of the AST pass. A guarded test import stays out
	// of both production graphs and is also accepted by the source policy.
	t.Run("GraphControls", func(t *testing.T) {
		for _, tags := range []string{"", fixtureTag} {
			label := "default"
			if tags != "" {
				label = "tagged"
			}
			t.Run(label, func(t *testing.T) {
				dir := fixtureGraphRoot(t, root, "package probe\nimport _ "+strconv.Quote(fixturePackage)+"\n")
				fixturePolicyWant(t, checkFixtureGraph(ctx, dir, tags), "graph_fixture_import")
			})
		}
		t.Run("GuardedTest", func(t *testing.T) {
			dir := fixtureGraphRoot(t, root, "package probe\nimport _ "+strconv.Quote(brokerModule+"/timeconf")+"\n")
			fixturePolicyWrite(t, filepath.Join(dir, "probe_test.go"), "//go:build linux && "+fixtureTag+"\n\npackage probe\nimport _ "+strconv.Quote(fixturePackage)+"\n")
			fixturePolicyWant(t, checkFixtureSources(dir), "")
			for _, tags := range []string{"", fixtureTag} {
				fixturePolicyWant(t, checkFixtureGraph(ctx, dir, tags), "")
			}
		})
		t.Run("CommandFailure", func(t *testing.T) {
			dir := fixtureGraphRoot(t, root, "package probe\nimport _ \"example.invalid/not-cached\"\n")
			err := checkFixtureGraph(ctx, dir, "")
			if err == nil || !strings.Contains(err.Error(), "graph_command:") {
				t.Fatalf("expected failed Go command to refuse, got %v", err)
			}
		})
	})
	// Scratch-named directories can hold a real, explicitly imported application
	// package. Both required graphs may omit its alternate-tag caller, so they
	// cannot replace the all-source check. The adjacent positive control permits
	// an ordinary application plus a properly guarded fixture test in that path.
	t.Run("ScratchSourceCoverage", func(t *testing.T) {
		for _, name := range []string{".temp", ".tmp", ".hidden", "_private"} {
			t.Run(name, func(t *testing.T) {
				dir := fixtureGraphRoot(t, root, "package probe\nimport _ "+strconv.Quote(brokerModule+"/timeconf")+"\n")
				app := filepath.Join(dir, name, "x", "x.go")
				fixturePolicyWrite(t, app, "package x\nimport _ \"context\"\n")
				fixturePolicyWrite(t, filepath.Join(dir, name, "x", "x_test.go"), "//go:build "+fixtureTag+"\n\npackage x\nimport _ "+strconv.Quote(fixturePackage)+"\n")
				fixturePolicyWrite(t, filepath.Join(dir, "other.go"), "//go:build other_boundary\n\npackage probe\nimport _ \"github.com/relux-works/swarma-keymaker/"+name+"/x\"\n")
				fixturePolicyWant(t, checkFixtureSources(dir), "")
				if _, err := fixtureGo(ctx, dir, "build", "-mod=readonly", "-tags=other_boundary", "./..."); err != nil {
					t.Fatal("ordinary hidden application control must compile", err)
				}
				fixturePolicyWrite(t, app, "package x\nimport _ "+strconv.Quote(fixturePackage)+"\n")
				for _, tags := range []string{"", fixtureTag} {
					fixturePolicyWant(t, checkFixtureGraph(ctx, dir, tags), "")
				}
				if _, err := fixtureGo(ctx, dir, "build", "-mod=readonly", "-tags=other_boundary", "./..."); err != nil {
					t.Fatal("explicit scratch application import must compile before policy rejection", err)
				}
				fixturePolicyWant(t, checkFixtureGraph(ctx, dir, "other_boundary"), "graph_fixture_import")
				fixturePolicyWant(t, checkFixtureSources(dir), "fixture_application_import")
			})
		}
	})
	// The actual pinned timeconf package is copied privately. Both the clean
	// graph and a compiling qualification-construction plant use identical module
	// metadata. This catches default activation without a timeconftest import.
	t.Run("CompiledSourceControl", func(t *testing.T) {
		raw, err := fixtureGo(ctx, root, "list", "-m", "-json", brokerModule)
		if err != nil {
			t.Fatal(err)
		}
		var module struct{ Dir string }
		if err := json.Unmarshal(raw, &module); err != nil || module.Dir == "" {
			t.Fatalf("broker module metadata: %v", err)
		}
		copyRoot := t.TempDir()
		for _, name := range []string{"go.mod", "go.sum"} {
			raw, err := os.ReadFile(filepath.Join(module.Dir, name))
			if err != nil {
				t.Fatal(err)
			}
			fixturePolicyWrite(t, filepath.Join(copyRoot, name), string(raw))
		}
		entries, err := os.ReadDir(filepath.Join(module.Dir, "timeconf"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(module.Dir, "timeconf", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			fixturePolicyWrite(t, filepath.Join(copyRoot, "timeconf", entry.Name()), string(raw))
		}
		dir := fixtureGraphRoot(t, root, "package probe\nimport _ "+strconv.Quote(brokerModule+"/timeconf")+"\n")
		mod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			t.Fatal(err)
		}
		fixturePolicyWrite(t, filepath.Join(dir, "go.mod"), string(mod)+"\nreplace "+brokerModule+" => "+strconv.Quote(copyRoot)+"\n")
		fixturePolicyWant(t, checkFixtureGraph(ctx, dir, ""), "")
		for _, plant := range []string{
			"func boundary(c *Consumer) { c.timePath = &pathQualification{} }",
			"func boundary() *pathQualification { return new(pathQualification) }",
		} {
			fixturePolicyWrite(t, filepath.Join(copyRoot, "timeconf", "boundary_linux.go"), "package timeconf\n"+plant+"\n")
			if _, err := fixtureGo(ctx, dir, "build", "-mod=readonly", "-tags=", "./..."); err != nil {
				t.Fatal("construction plant must compile before policy rejection", err)
			}
			fixturePolicyWant(t, checkFixtureGraph(ctx, dir, ""), "compiled_fixture_construction")
		}
		// Removing the construction plant isolates the independent implementation
		// check: compiling the real bridge by default must also be detected.
		if err := os.Remove(filepath.Join(copyRoot, "timeconf", "boundary_linux.go")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(copyRoot, "timeconf", "consumer_fixture_linux.go")
		raw, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fixturePolicyWrite(t, path, strings.TrimPrefix(string(raw), "//go:build linux && "+fixtureTag+"\n"))
		if _, err := fixtureGo(ctx, dir, "build", "-mod=readonly", "-tags=", "./..."); err != nil {
			t.Fatal("implementation plant must compile before policy rejection", err)
		}
		fixturePolicyWant(t, checkFixtureGraph(ctx, dir, ""), "compiled_fixture_implementation")
	})
}
