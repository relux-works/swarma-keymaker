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
