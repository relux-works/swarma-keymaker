// Narrowing controls for two Keymaker authorization gates. Source changes exist
// only in Go overlay files under the caller's scratch directory.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	scratch := flag.String("scratch", "", "existing task scratch parent")
	flag.Parse()
	if *scratch == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "use -scratch <directory>")
		os.Exit(2)
	}
	root, e := os.Getwd()
	if e != nil {
		panic(e)
	}
	dir, e := os.MkdirTemp(*scratch, "mutation-")
	if e != nil {
		fmt.Fprintln(os.Stderr, "scratch unavailable")
		os.Exit(2)
	}
	controls := []struct{ name, file, old, new, test, needle string }{
		{"peer-uid", "binding.go", "if b.UID != peer.UID {", "if false {", "^TestRefusalVectors$/^binding-wrong-uid$/^negative$", "--- FAIL: TestRefusalVectors/binding-wrong-uid/negative"},
		{"namespace", "wire.go", "if string(namespace) != \"git\" {", "if len(namespace) < 0 {", "^TestRefusalVectors$/^ssh-namespace$/^negative$", "--- FAIL: TestRefusalVectors/ssh-namespace/negative"},
	}
	good := true
	for _, c := range controls {
		source := filepath.Join(root, "internal/keymaker", c.file)
		raw, e := os.ReadFile(source)
		if e != nil || strings.Count(string(raw), c.old) != 1 {
			fmt.Fprintln(os.Stderr, c.name, "plant not applied")
			os.Exit(2)
		}
		mutant := filepath.Join(dir, c.name+".go")
		if os.WriteFile(mutant, []byte(strings.Replace(string(raw), c.old, c.new, 1)), 0600) != nil {
			os.Exit(2)
		}
		overlay := filepath.Join(dir, c.name+".json")
		mapping, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: mutant}})
		if os.WriteFile(overlay, mapping, 0600) != nil {
			os.Exit(2)
		}
		cmd := exec.Command("go", "test", "-overlay", overlay, "./internal/keymaker", "-run", c.test, "-count=1", "-v")
		out, e := cmd.CombinedOutput()
		status := 0
		if e != nil {
			if code, ok := e.(*exec.ExitError); ok {
				status = code.ExitCode()
			} else {
				status = 127
			}
		}
		log := filepath.Join(dir, c.name+".log")
		os.WriteFile(log, out, 0600)
		killed := status == 1 && bytes.Contains(out, []byte(c.needle)) && bytes.Contains(out, []byte("code \"\", want"))
		fmt.Printf("mutant=%s test=%s actual_exit=%d killed=%t log=%s\n", c.name, c.test, status, killed, log)
		if !killed {
			fmt.Fprintln(os.Stderr, string(out))
			good = false
		}
	}
	if !good {
		os.Exit(1)
	}
}
