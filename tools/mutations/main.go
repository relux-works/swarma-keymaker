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
	group := flag.String("group", "core", "core or registration controls")
	flag.Parse()
	if *scratch == "" || flag.NArg() != 0 || (*group != "core" && *group != "registration") {
		fmt.Fprintln(os.Stderr, "use -scratch <directory> [-group core|registration]")
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
	pkg := "./internal/keymaker"
	if *group == "registration" {
		pkg = "./internal/registration"
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"registration-nonce-reuse", "registration.go", "_, err := io.ReadFull(b.random, nonce)", "_, err := copy(nonce, make([]byte, 16)), error(nil)", "^TestFreshNonce$", "--- FAIL: TestFreshNonce", "fresh builds reused nonce"},
			{"registration-caller-iat", "registration.go", "type Input struct {", "type Input struct {\n\tIssuedAt time.Time", "^TestNoCallerTime$", "--- FAIL: TestNoCallerTime", "caller iat affected proof construction"},
			{"registration-release-time", "registration.go", "return p.validAt(now)", "now = p.issued\n\treturn p.validAt(now)", "^Test(KeyWindow|ReleaseExpiry)$", "--- FAIL: TestReleaseExpiry", "release-time expiry check bypassed"},
			{"registration-self-verify", "registration.go", "if _, err := format.Verify(raw); err != nil {", "if _, err := format.Verify(raw); false && err != nil {", "^TestSigningFailures$/^bad-signature$", "--- FAIL: TestSigningFailures/bad-signature", "self-check released invalid proof"},
			{"registration-wrong-preimage", "registration.go", "signature, code := b.signer.Sign(ctx, preimage)", "_ = preimage\n\tsignature, code := b.signer.Sign(ctx, canonical)", "^TestSigningInput$", "--- FAIL: TestSigningInput", "signer received non-registrar signing input"},
		}
	}
	good := true
	for _, c := range controls {
		source := filepath.Join(root, pkg, c.file)
		raw, e := os.ReadFile(source)
		if e != nil || strings.Count(string(raw), c.old) != 1 {
			fmt.Fprintln(os.Stderr, c.name, "plant not applied")
			os.Exit(2)
		}
		mutant := filepath.Join(dir, c.name+".go")
		if os.WriteFile(mutant, []byte(plant(c.name, string(raw), c.old, c.new)), 0600) != nil {
			os.Exit(2)
		}
		overlay := filepath.Join(dir, c.name+".json")
		mapping, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: mutant}})
		if os.WriteFile(overlay, mapping, 0600) != nil {
			os.Exit(2)
		}
		cmd := exec.Command("go", "test", "-overlay", overlay, pkg, "-run", c.test, "-count=1", "-v")
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		pid := 0
		e = cmd.Start()
		if e == nil {
			pid = cmd.Process.Pid
			e = cmd.Wait()
		}
		out := output.Bytes()
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
		fmt.Printf("mutant=%s test=%s actual_exit=%d killed=%t pid=%d log=%s\n", c.name, c.test, status, killed, pid, log)
		if !killed {
			fmt.Fprintln(os.Stderr, string(out))
			good = false
		}
	}
	if !good {
		os.Exit(1)
	}
}

// Caller-time weakening adds the forbidden selector and actually uses it. The
// other controls each replace one uniquely matched authority gate.
func plant(name, source, old, replacement string) string {
	mutant := strings.Replace(source, old, replacement, 1)
	if name == "registration-caller-iat" {
		const timestamp = "issued := now.Truncate(time.Second)"
		if strings.Count(mutant, timestamp) != 1 {
			fmt.Fprintln(os.Stderr, "caller iat use plant not applied")
			os.Exit(2)
		}
		mutant = strings.Replace(mutant, timestamp, timestamp+"\n\tif !in.IssuedAt.IsZero() { issued = in.IssuedAt.UTC().Truncate(time.Second) }", 1)
	}
	return mutant
}
