package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The real fixture checker accepts the exact public corpus and rejects one
// changed expected sibling key with its intended diagnostic, not a setup error.
func TestJ7VectorCheckerControl(t *testing.T) {
	if os.Getenv("KEYMAKER_J7_VECTOR_CONTROL") == "1" {
		checkJ7Vectors()
		return
	}
	keys, err := os.ReadFile("../../vectors/j7/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	csv, err := os.ReadFile("../../vectors/j7/bip340.csv")
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []bool{false, true} {
		root := t.TempDir()
		dir := filepath.Join(root, "vectors", "j7")
		if os.MkdirAll(dir, 0700) != nil {
			t.Fatal("fixture directory")
		}
		data := keys
		if bad {
			var v map[string]any
			if json.Unmarshal(keys, &v) != nil {
				t.Fatal("fixture JSON")
			}
			row := v["cases"].([]any)[0].(map[string]any)
			old := row["public_x_hex"].(string)
			prefix := "0"
			if old[0] == '0' {
				prefix = "1"
			}
			row["public_x_hex"] = prefix + old[1:]
			data, err = json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(data, keys) {
				t.Fatal("plant not applied")
			}
		}
		if os.WriteFile(filepath.Join(dir, "keys.json"), data, 0600) != nil || os.WriteFile(filepath.Join(dir, "bip340.csv"), csv, 0600) != nil {
			t.Fatal("fixture write")
		}
		cmd := exec.Command(exe, "-test.run=^TestJ7VectorCheckerControl$")
		cmd.Dir = root
		cmd.Env = []string{"KEYMAKER_J7_VECTOR_CONTROL=1"}
		output, err := cmd.CombinedOutput()
		if !bad {
			if err != nil || !strings.Contains(string(output), "secp fixture integrity") {
				t.Fatalf("positive checker: %v %s", err, output)
			}
		} else {
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "secp sibling public: m/7'") {
				t.Fatalf("intended checker control did not fail: %v %s", err, output)
			}
		}
	}
}

// The new corpus checker detects a one-nibble wrong literal preimage, with all
// other bytes preserved. A green neighboring child proves setup reached checker.
func TestJ7DelegationVectorCheckerControl(t *testing.T) {
	if os.Getenv("KEYMAKER_J7_DELEGATION_VECTOR_CONTROL") == "1" {
		checkJ7DelegationVectors()
		return
	}
	raw, e := os.ReadFile("../../vectors/j7/delegation.json")
	if e != nil {
		t.Fatal(e)
	}
	var f delegationVectorFile
	if json.Unmarshal(raw, &f) != nil || len(f.Positive) != 2 {
		t.Fatal("corpus")
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []bool{false, true} {
		root := t.TempDir()
		dir := filepath.Join(root, "vectors", "j7")
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
		data := raw
		if bad {
			preimage := f.Positive[0].Preimage
			replacement := "0" + preimage[1:]
			if replacement == preimage {
				replacement = "1" + preimage[1:]
			}
			data = bytes.Replace(raw, []byte(preimage), []byte(replacement), 1)
			if bytes.Equal(raw, data) {
				t.Fatal("preimage plant not applied")
			}
		}
		if e := os.WriteFile(filepath.Join(dir, "delegation.json"), data, 0600); e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(exe, "-test.run=^TestJ7DelegationVectorCheckerControl$")
		cmd.Dir = root
		cmd.Env = []string{"KEYMAKER_J7_DELEGATION_VECTOR_CONTROL=1"}
		output, e := cmd.CombinedOutput()
		if !bad {
			if e != nil || !strings.Contains(string(output), "J7 delegation fixtures: 2 positives/17 negatives") {
				t.Fatalf("positive checker %v %s", e, output)
			}
		} else {
			exit, ok := e.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "J7 delegation fixture bytes drift") {
				t.Fatalf("wrong preimage not detected %v %s", e, output)
			}
		}
	}
}
