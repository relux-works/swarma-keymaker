package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/testwindow"
)

// Missing provisioning is exactly stderr/PENDING/3. A valid fake configuration
// reaches the real verifier; wrong identity is a configuration error, so a deny-all
// runner returning PENDING for every input cannot satisfy the nearby control.
func TestPendingAndConfiguredCheck(t *testing.T) {
	var out, errOut bytes.Buffer
	calls := 0
	command := func(string, ...string) (string, error) { calls++; return "0", errors.New("must not run") }
	if code := run([]string{"-check"}, &out, &errOut, command, 1000); code != 3 || out.Len() != 0 || errOut.String() != "PENDING: test window not provisioned\n" || calls != 0 {
		t.Fatal("wrong PENDING contract", code, errOut.String())
	}
	d := t.TempDir()
	path := filepath.Join(d, "window.json")
	b, _ := json.Marshal(testwindow.Config{Runner: "runner", A: "client-a", B: "client-b", Group: "test-reg"})
	os.WriteFile(path, b, 0600)
	out.Reset()
	errOut.Reset()
	command = func(string, ...string) (string, error) { calls++; return "0", nil }
	if code := run([]string{"-check", "-config", path}, &out, &errOut, command, 1000); code != 2 || calls == 0 || strings.Contains(errOut.String(), "PENDING") {
		t.Fatal("configured real check was bypassed", code, calls)
	}
}

// Invalid syntax is distinct from test failure and PENDING; it never invokes sudo.
func TestUsageAndMalformedConfig(t *testing.T) {
	var out bytes.Buffer
	noCommands := func(string, ...string) (string, error) { t.Fatal("unexpected command"); return "", nil }
	if code := run([]string{"-unknown"}, &out, &out, noCommands, 1000); code != 2 {
		t.Fatal(code)
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("invalid"), 0600)
	if code := run([]string{"-config", path}, &out, &out, noCommands, 1000); code != 2 {
		t.Fatal(code)
	}
}

// The canonical reviewed file carries configured paths into every Verify
// command. -check creates no scratch/report; invalid or missing tools refuse
// before any command. Fake identities do not prove sudo or installed custody.
func TestWindowConfiguredFileFlow(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "window.json")
	cfg := testwindow.Config{Runner: "runner", A: "client-a", B: "client-b", Group: "test-reg", IDPath: filepath.Join(d, "id"), EnvPath: filepath.Join(d, "env"), Scratch: filepath.Join(d, "uncreated-scratch")}
	for _, tool := range []string{cfg.IDPath, cfg.EnvPath} {
		if err := os.WriteFile(tool, nil, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range []string{"valid", "malformed", "missing", "ambiguous"} {
		t.Run(scenario, func(t *testing.T) {
			c := cfg
			if scenario == "malformed" {
				c.EnvPath = "relative/env"
			}
			if scenario == "missing" {
				c.EnvPath = filepath.Join(d, "missing-env")
			}
			raw, _ := json.Marshal(c)
			if scenario == "ambiguous" {
				value, _ := json.Marshal(c.IDPath)
				raw = append(raw[:len(raw)-1], append([]byte(`,"id_path":`), append(value, '}')...)...)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			calls := 0
			code := run([]string{"-config", path, "-check"}, &out, &errOut, func(name string, args ...string) (string, error) {
				calls++
				if name == "sudo" {
					found := false
					for i, a := range args {
						if a == "--" && i+1 < len(args) {
							found = args[i+1] == cfg.IDPath
						}
					}
					if !found {
						t.Fatal("canonical sudo tool lost", args)
					}
				} else if name != cfg.IDPath {
					t.Fatal("canonical lookup tool lost", name)
				}
				switch args[len(args)-1] {
				case "-g":
					return "2000", nil
				case "-G":
					if args[2] == "client-a" {
						return "100 2000", nil
					}
					return "100", nil
				}
				user := args[1]
				if name == "sudo" {
					user = args[2]
				}
				return map[string]string{"runner": "1000", "client-a": "1001", "client-b": "1002"}[user], nil
			}, 1000)
			switch scenario {
			case "valid":
				if code != 0 || calls != 8 || out.String() != "test window verified\n" || errOut.Len() != 0 {
					t.Fatal(code, calls, out.String(), errOut.String())
				}
			case "malformed":
				if code != 2 || calls != 0 || !strings.Contains(errOut.String(), "invalid window tool path") {
					t.Fatal(code, calls, errOut.String())
				}
			case "ambiguous":
				if code != 2 || calls != 0 || !strings.Contains(errOut.String(), "ambiguous window tool path") {
					t.Fatal(code, calls, errOut.String())
				}
			case "missing":
				if code != 3 || calls != 0 || errOut.String() != "PENDING: test window not provisioned\n" {
					t.Fatal(code, calls, errOut.String())
				}
			}
			if _, err := os.Stat(cfg.Scratch); !os.IsNotExist(err) {
				t.Fatal("check created scratch", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("check changed configuration", err)
			}
		})
	}
}
