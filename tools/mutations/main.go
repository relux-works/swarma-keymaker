// Narrowing controls for Keymaker authorization, recovery and refusal gates. Source changes exist
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
	controls := []struct{ name, file, old, new, test, needle, witness string }{
		{"peer-uid", "binding.go", "if b.UID != peer.UID {", "if false {", "^TestRefusalVectors$/^binding-wrong-uid$/^negative$", "--- FAIL: TestRefusalVectors/binding-wrong-uid/negative", "code \"\", want"},
		{"namespace", "wire.go", "if string(namespace) != \"git\" {", "if len(namespace) < 0 {", "^TestRefusalVectors$/^ssh-namespace$/^negative$", "--- FAIL: TestRefusalVectors/ssh-namespace/negative", "code \"\", want"},
		{"missing-snapshot", "binding.go", "if len(entries) != 0 || err != io.EOF {", "if len(entries) < 0 && err != io.EOF {", "^TestMissingSnapshotRecovery$/^missing$", "--- FAIL: TestMissingSnapshotRecovery/missing", "incomplete recovery admitted a store"},
		{"path-history", "binding.go", "if old.Status != \"unbound\" || old.Lifetime", "if old.Status == \"revoked\" || b.Status == \"active\" && old.Status == \"active\" || old.Lifetime", "^TestBindingHistoryUniqueness$/^hidden-active$", "--- FAIL: TestBindingHistoryUniqueness/hidden-active", "want binding_conflict"},
		{"framing-budget", "engine.go", "if limit := e.charge(s); limit != \"\" {", "if limit := Code(\"\"); limit != \"\" {", "^TestFrameRefusalAccounting$/^oversize$", "--- FAIL: TestFrameRefusalAccounting/oversize", "refusal bypassed work buckets"},
		{"busy-budget", "engine.go", "if c := e.charge(s); c != \"\" {\n\t\treturn e.overloadRefusal(s, c)\n\t}\n\tq, _ := parseAgent(body)", "if c := Code(\"\"); c != \"\" {\n\t\treturn e.overloadRefusal(s, c)\n\t}\n\tq, _ := parseAgent(body)", "^TestFrameRefusalAccounting$/^busy$", "--- FAIL: TestFrameRefusalAccounting/busy", "refusal bypassed work buckets"},
		{"overload-audit", "engine.go", "emit := e.overload.take(e.rateNow(), 1, 1)", "emit := true", "^TestOverloadRefusalBudget$", "--- FAIL: TestOverloadRefusalBudget", "overload amplified journal writes"},
		{"missing-journal", "snapshot.go", "if commit.Version == 0 ||", "if commit.Version == 0 { return true }; if", "^TestCustodyStartupReconciliation$/^empty-audit$", "--- FAIL: TestCustodyStartupReconciliation/empty-audit", "incomplete custody evidence admitted startup"},
		{"snapshot-journal-divergence", "custody_linux.go", "if !s.matchesCommit(j.binding) {", "if false && !s.matchesCommit(j.binding) {", "^TestSnapshotJournalDivergence$/^snapshot-before-revoke$", "--- FAIL: TestSnapshotJournalDivergence/snapshot-before-revoke", "BYPASS: restored pre-revoke snapshot signed"},
		{"snapshot-records-optional", "snapshot.go", "if _, ok := fields[\"records\"]; !ok {", "if _, ok := fields[\"records\"]; !ok && false {", "^TestSnapshotSchemaRequired$/^revoked$/^missing-records$", "--- FAIL: TestSnapshotSchemaRequired/revoked/missing-records", "missing snapshot member admitted"},
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
		killed := status == 1 && bytes.Contains(out, []byte(c.needle)) && bytes.Contains(out, []byte(c.witness))
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
