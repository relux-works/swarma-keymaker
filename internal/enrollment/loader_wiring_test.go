package enrollment

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type loaderLiteral struct {
	position     token.Position
	objectFormat string
	present      bool
}

// Inspect direct literals of the public registry Loader, including renamed and
// dot imports. This checks explicit wiring, not value provenance or subsequent
// assignments; runtime enrollment and helper tests retain those obligations.
func registryLoaderLiterals(name string, source []byte) ([]loaderLiteral, error) {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, name, source, 0)
	if err != nil {
		return nil, err
	}
	imports := map[string]bool{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		if path == "github.com/relux-works/swarma-registrar/registry" {
			alias := "registry"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			imports[alias] = true
		}
	}
	var sites []loaderLiteral
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		matched := false
		switch typ := literal.Type.(type) {
		case *ast.SelectorExpr:
			qualifier, ok := typ.X.(*ast.Ident)
			matched = ok && imports[qualifier.Name] && typ.Sel.Name == "Loader"
		case *ast.Ident:
			matched = imports["."] && typ.Name == "Loader"
		}
		if !matched {
			return true
		}
		site := loaderLiteral{position: positions.Position(literal.Pos())}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			if ok && key.Name == "ObjectFormat" {
				site.present = true
				site.objectFormat = string(source[positions.Position(field.Value.Pos()).Offset:positions.Position(field.Value.End()).Offset])
			}
		}
		sites = append(sites, site)
		return true
	})
	return sites, nil
}

// All Go source in this module, including inactive platform files, tests and
// tools, must wire each direct Loader literal explicitly. The upstream refusal
// test deliberately assigns empty/unknown formats and checks their rejection.
// This does not inspect external modules, vendor or private scratch directories,
// or claim to detect dynamically assembled values or local type aliases.
func TestRegistryLoaderObjectFormatWiring(t *testing.T) {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(directory, "..", ".."))
	count := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sites, err := registryLoaderLiterals(name, data)
		if err != nil {
			return err
		}
		for _, site := range sites {
			count++
			if !site.present {
				t.Errorf("%s: registry Loader literal lacks ObjectFormat", site.position)
			} else {
				t.Logf("%s: ObjectFormat=%s", site.position, site.objectFormat)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("module Loader sweep found no sites")
	}
}

// The guard detects a planted omission under ordinary, renamed, and dot imports
// (including multiline pointer literals). Matching explicit-field controls pass;
// comments, strings and unrelated Loader types cannot satisfy or trip the check.
func TestRegistryLoaderObjectFormatGuardControl(t *testing.T) {
	for _, alias := range []string{"registry", "renamed", "."} {
		t.Run(alias, func(t *testing.T) {
			declaration, qualifier := "", "registry."
			if alias != "registry" {
				declaration = alias + " "
				qualifier = alias + "."
			}
			if alias == "." {
				qualifier = ""
			}
			for _, explicit := range []bool{false, true} {
				field := ""
				if explicit {
					field = "ObjectFormat: config.ObjectFormat,"
				}
				plant := fmt.Sprintf("package fixture\nimport %s%q\nvar loader = &%sLoader{\n// ObjectFormat: misleading comment\n%s\nPolicy: policy,\n}\n", declaration, "github.com/relux-works/swarma-registrar/registry", qualifier, field)
				sites, err := registryLoaderLiterals("fixture.go", []byte(plant))
				if err != nil || len(sites) != 1 || sites[0].present != explicit {
					t.Fatalf("guard control explicit=%t: sites=%v err=%v", explicit, sites, err)
				}
				if explicit && sites[0].objectFormat != "config.ObjectFormat" {
					t.Fatal("explicit protected expression was not retained")
				}
			}
		})
	}
	unrelated := []byte("package fixture\ntype Loader struct{}\nvar loader = Loader{}\nvar text = `registry.Loader{}`\n")
	if sites, err := registryLoaderLiterals("unrelated.go", unrelated); err != nil || len(sites) != 0 {
		t.Fatalf("unrelated Loader or string mistaken for registry construction: %v %v", sites, err)
	}
}
