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
	group := flag.String("group", "core", "core (including native), native, registration, helper or packaging controls")
	flag.Parse()
	if *scratch == "" || flag.NArg() != 0 || (*group != "core" && *group != "native" && *group != "registration" && *group != "helper" && *group != "packaging") {
		fmt.Fprintln(os.Stderr, "use -scratch <directory> [-group core|native|registration|helper|packaging]")
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
	socketGuard := "\tif syscall.Fchownat(fd, \"control.sock\", os.Getuid(), int(gid), 0x100 /* Linux AT_SYMLINK_NOFOLLOW */) != nil || syscall.Fchmodat(fd, \"control.sock\", 0660, 0) != nil {\n\t\treturn fail()\n\t}\n\tst, err := os.Lstat(staged)\n\tif err != nil {\n\t\treturn fail()\n\t}\n\tstat := st.Sys().(*syscall.Stat_t)\n\tif st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 || stat.Uid != uint32(os.Getuid()) || stat.Gid != gid {\n\t\treturn fail()\n\t}\n"
	socketFallback := "\t_ = syscall.Fchmodat(fd, \"control.sock\", 0666, 0)\n\tst, err := os.Lstat(staged)\n\tif err != nil { return fail() }\n\tstat := st.Sys().(*syscall.Stat_t)\n"
	// Move only the authoritative retained snapshot before the generation
	// barrier, retaining Store synchronization and every authority predicate.
	replayInside := `	var result control.Object
	c = n.Engine.Generations.WithEvidence(ctx, effectConditions, func() Code {
		s := n.Engine.Store
		s.mu.Lock()
		defer s.mu.Unlock()
		if c := connection.bindingActive(s); c != "" {
			return c
		}
		old, c := s.retained(p, r)`
	replayOutside := `	var result control.Object
	n.Engine.Store.mu.Lock()
	outside, outsideCode := n.Engine.Store.retained(p, r)
	n.Engine.Store.mu.Unlock()
	c = n.Engine.Generations.WithEvidence(ctx, effectConditions, func() Code {
		s := n.Engine.Store
		s.mu.Lock()
		defer s.mu.Unlock()
		if c := connection.bindingActive(s); c != "" {
			return c
		}
		old, c := outside, outsideCode`
	controls := []struct{ name, file, old, new, test, needle, witness string }{
		{"custody-legacy-recovery", "audit.go", `!validReplayAuditCustody(r)`, `!validAuditCustody(r)`, "^TestCustodyLegacyRecovery$", "--- FAIL: TestCustodyLegacyRecovery/custody", "legacy custody history refused"},
		{"custody-result-linkage", "custody_reason.go", `isCustody && r.Result == "refused" && r.CustodyCause.valid()`, `isCustody && r.CustodyCause.valid()`, "^TestCustodyResultLinkage$", "--- FAIL: TestCustodyResultLinkage/Append/success", "invalid custody result admitted or changed journal"},
		{"custody-wrong-cause", "derive.go", `return nil, "custody_unavailable", custodyClosed`, `return nil, "custody_unavailable", custodyUnloaded`, "^TestCustodyAuditCauses$/^(agent-sign|control-pubkey|helper)$/^closed$", "--- FAIL: TestCustodyAuditCauses/agent-sign/closed", "custody audit cause mismatch"},
		{"custody-native-response-cause", "native.go", "return refusal\n}\n\n// Admit", "if record.CustodyCause != nil { return control.Code(*record.CustodyCause) }; return refusal\n}\n\n// Admit", "^TestCustodyAuditCauses$/^control-pubkey$/^closed$", "--- FAIL: TestCustodyAuditCauses/control-pubkey/closed", "custody response bytes changed"},
		{"custody-agent-response-cause", "server_linux.go", "if writeResponse(c, AgentFailure) != nil ||", "if writeResponse(c, Packet(append([]byte{5}, []byte(\"closed\")...))) != nil ||", "^TestCustodyAuditCauses$/^agent-sign$/^closed$", "--- FAIL: TestCustodyAuditCauses/agent-sign/closed", "custody response bytes changed"},
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
		{"native-operator", "native.go", "if p != n.Config.Operator {", "if false {", "^TestNativeVectors$/^register-wrong-uid$/^negative$", "--- FAIL: TestNativeVectors/register-wrong-uid/negative", "want role_not_permitted"},
		{"native-refusal-audit-wait", "audit.go", "if !j.mu.LockContext(ctx) {\n\t\treturn \"request_deadline_exceeded\"\n\t}", "j.mu.Lock()", "^TestReviewAdmissionQueuedAuditDeadline$", "--- FAIL: TestReviewAdmissionQueuedAuditDeadline", "expired refusal retained slot and appended after deadline"},
		{"native-generation-admission-refusal", "../control/server.go", "func (s *Server) ServeConnRefused(ctx context.Context, conn net.Conn, peer Peer, refusal Code) {", "func (s *Server) ServeConnRefused(ctx context.Context, conn net.Conn, peer Peer, refusal Code) {\n\tconn.Close()\n\treturn", "^TestNativeGenerationAdmissionRefusal$/^generation_inactive$/^initial$", "--- FAIL: TestNativeGenerationAdmissionRefusal/generation_inactive/initial", "generation admission silently closed"},
		{"native-persistent-revoke", "native.go", "if b.Lifetime == \"persistent\" && mode == \"ephemeral\" {", "if false {", "^TestNativeVectors$/^revoke-persistent-as-ephemeral$/^negative$", "--- FAIL: TestNativeVectors/revoke-persistent-as-ephemeral/negative", "want persistent_revoke_requires_operator"},
		{"native-socket-permissions", "native_socket_linux.go", socketGuard, socketFallback, "^TestNativeSocketPermissions$/^invalid-group$", "--- FAIL: TestNativeSocketPermissions/invalid-group", "unsafe control group or path admitted"},
		{"native-replay-before-target-barrier", "native.go", replayInside, replayOutside, "^TestNativeConcurrentTargetReplay$/^same-id-(retired|reused)$", "--- FAIL: TestNativeConcurrentTargetReplay/same-id-retired", "REGRESSION: concurrent exact retry refused after committed result became available"},
		{"native-target-release", "native.go", "connection.conditions = conditions", "connection.conditions = conditions[:1]", "^TestNativeMutationReleasePrincipals$/^target$", "--- FAIL: TestNativeMutationReleasePrincipals/target", "mutation release lost target authority but emitted result"},
		{"native-binding-pin", "native.go", "if c := connection.pin(n.Engine.Store, b); c != \"\" {", "if c := Code(\"\"); c != \"\" {", "^TestNativeConnectionBindingPin$", "--- FAIL: TestNativeConnectionBindingPin", "old control connection adopted replacement binding"},
		{"native-accepted-generation", "server_linux.go", "s.controlWire.ServeConnAccepted(nativeCtx, c, control.Peer{UID: p.UID, Generation: g.Generation})", "s.controlWire.ServeConn(nativeCtx, c)", "^TestNativeAcceptTupleBeforeHello$/^true$", "--- FAIL: TestNativeAcceptTupleBeforeHello/true", "accepted tuple changed before hello but emitted success"},
		{"native-release-fence", "native.go", "return n.Engine.Generations.WithActive(ctx, p.UID, p.Generation, release)", "return release()", "^TestNativeReleaseFence$/^hello$/^retirement-wins$", "--- FAIL: TestNativeReleaseFence/hello/retirement-wins", "native retirement released success"},
	}
	// Preserve the default custody controls; native selects only their subset.
	if *group == "native" {
		all := controls
		controls = nil
		for _, c := range all {
			if strings.HasPrefix(c.name, "native-") {
				controls = append(controls, c)
			}
		}
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
	if *group == "helper" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"helper-reader-handoff", "../enrollment/gate.go", "if !g.paused || queued && phase != g.phase {", "if !g.paused {", "^TestReviewR2SocketReloadFairness$", "--- FAIL: TestReviewR2SocketReloadFairness", "valid helper starved by successive valid reloads"},
			{"helper-uncancellable-enrollment", "../enrollment/gate.go", "select {\n\t\tcase <-ctx.Done():\n\t\tcase <-changed:\n\t\t}", "<-changed", "^TestReviewHelperReloadDeadline$/^slow-reload$", "--- FAIL: TestReviewHelperReloadDeadline/slow-reload", "parallel pubkey blocked by expired helper before reload I/O resumed"},
			{"helper-reload-io-lock", "../enrollment/authority.go", "code := candidate.load(ctx)\n\ta.mu.Lock()", "a.mu.Lock()\n\tcode := candidate.load(ctx)", "^TestHelperReloadPreparesOutsideWrite$", "--- FAIL: TestHelperReloadPreparesOutsideWrite/valid", "reload I/O waited for the actual socket write"},
			{"helper-binding", "registration.go", `b, c := s.lookup(peer.UID, peer.Generation)`, `b, c := Binding{}, Code("")`, "^TestDaemonHelperVectors$/^helper-missing-binding$/^negative$", "--- FAIL: TestDaemonHelperVectors/helper-missing-binding/negative", "native response exposed forbidden field envelope"},
			{"helper-release-recheck", "registration.go", `if pc := retained.Recheck(ctx); pc != "" {`, `if pc := proof.Code(""); retained == nil && pc != "" {`, "^TestHelperExpiryAfterAudit$/^expired$", "--- FAIL: TestHelperExpiryAfterAudit/expired", "native response exposed forbidden field envelope"},
			{"helper-surface-a-key", "registration.go", `s.master.withPurposeCause(s.path, "host-registration",`, `s.master.withPurposeCause("m/1'"+s.path[len("m/2'"):], "agent-identity",`, "^TestHelperDomainSeparation$", "--- FAIL: TestHelperDomainSeparation", "helper refused positive control"},
			{"helper-retry-nonce", "registration.go", `if old != nil {
				_, pc := h.builder.Restore(ctx, raw, in)`, `if false {
				_, pc := h.builder.Restore(ctx, raw, in)`, "^TestHelperDurableRetry$", "--- FAIL: TestHelperDurableRetry", "same-ID retry minted a new nonce"},
		}
	}
	if *group == "packaging" {
		pkg = "./tools/release-bundle"
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"packaging-dirty-tree", "source.go", "if len(status) != 0 {", "if false && len(status) != 0 {", "^TestReleaseDirtyTree$/^tracked$", "--- FAIL: TestReleaseDirtyTree/tracked", "dirty source admitted"},
			{"packaging-unit-drift", "source.go", "if !ok || !bytes.Equal(unit, []byte(block)) {", "if !ok || false && !bytes.Equal(unit, []byte(block)) {", "^TestReleaseUnitMatchesSpec$/^modified$", "--- FAIL: TestReleaseUnitMatchesSpec/modified", "unit drift admitted"},
			{"packaging-enrollment-policy", "inputs.go", "if _, err := enrollment.ParseConfig(pins); err != nil {", "if _, err := enrollment.ParseConfig(pins); false && err != nil {", "^TestReleaseEnrollmentGate$/^revision$", "--- FAIL: TestReleaseEnrollmentGate/revision", "refusal=<nil> want=release enrollment pin configuration refused"},
			{"packaging-output-path", "bundle.go", "owned.writeFile(root, name, body, 0600)", "os.WriteFile(filepath.Join(p.target, name), body, 0600)", "^TestReleaseOutputSymlink$/^true$", "--- FAIL: TestReleaseOutputSymlink/true", "output symlink overwrote sibling victim"},
			{"packaging-replacement", "source.go", "\"--no-replace-objects\", ", "", "^TestReleaseReplacementCommit$/^true$", "--- FAIL: TestReleaseReplacementCommit/true", "replacement changed release provenance"},
			{"packaging-tree-hash", "source.go", "if err != nil || got != expected {", "if err != nil || false && got != expected {", "^TestReleaseExportTreeMismatch$/^true$", "--- FAIL: TestReleaseExportTreeMismatch/true", "export tree mismatch admitted"},
			{"packaging-child-write", "root_linux.go", "err := restrictWrites(int(root.Fd()), extra...)", "err := error(nil)", "^TestReleaseChildWriteBoundary$/^true$", "--- FAIL: TestReleaseChildWriteBoundary/true", "child escape not refused"},
			{"packaging-recursive-cleanup", "root_linux.go", "var result error", "if true { dir, _ := root.Open(\".\"); entries, _ := dir.ReadDir(-1); dir.Close(); for _, entry := range entries { if err := root.RemoveAll(entry.Name()); err != nil { return err } }; return nil }; var result error", "^TestReleaseCleanupCreatedOnly$/^unrelated$", "--- FAIL: TestReleaseCleanupCreatedOnly/unrelated", "cleanup removed unrelated object"},
			{"packaging-root-verification", "root_linux.go", "if err := verifyAdoptedRoot(f); err != nil {", "if err := verifyAdoptedRoot(f); false && err != nil {", "^TestReleaseAdoptedRoot$/^nonempty$", "--- FAIL: TestReleaseAdoptedRoot/nonempty", "unsafe adopted root admitted"},
			{"packaging-git-boundary", "source.go", "return runConfined(cmd, anchor, null)", "return runCommand(cmd)", "^TestReleaseGitPreflightBoundary$/^true$", "--- FAIL: TestReleaseGitPreflightBoundary/true", "Git preflight escaped scratch boundary"},
			{"packaging-filters", "source.go", "status, err := worktreeStatus(ctx, repo, commit)", "status, err := gitRead(ctx, repo, \"status\", \"--porcelain=v1\", \"--untracked-files=all\")", "^TestReleaseConfiguredFilters$/^attributes-file$", "--- FAIL: TestReleaseConfiguredFilters/attributes-file", "configured filter admitted"},
			{"packaging-null-rdev", "root_linux.go", "st.Rdev == unix.Mkdev(1, 3)", "true", "^TestReleaseNullDeviceVerification$", "--- FAIL: TestReleaseNullDeviceVerification", "wrong rdev admitted"},
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
		// Reproduce the fairness finding's one-processor schedule regardless
		// of the calling shell's parallelism.
		if c.name == "helper-reader-handoff" {
			cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
		}
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
		if os.WriteFile(log, out, 0600) != nil {
			fmt.Fprintln(os.Stderr, c.name, "evidence log unavailable")
			os.Exit(2)
		}
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
// replacement control removes both Git replacement guards. Other controls
// replace one uniquely matched authority gate.
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
	if name == "helper-binding" {
		old := `if _, c := s.lookup(peer.UID, peer.Generation); c != "" {`
		if strings.Count(mutant, old) != 1 {
			fmt.Fprintln(os.Stderr, "helper release binding plant not applied")
			os.Exit(2)
		}
		mutant = strings.Replace(mutant, old, `if _, c := s.lookup(peer.UID, peer.Generation); false && c != "" {`, 1)
	}
	if name == "packaging-replacement" {
		const environment = "\"GIT_NO_REPLACE_OBJECTS=1\", "
		if strings.Count(mutant, environment) != 1 {
			fmt.Fprintln(os.Stderr, "replacement environment plant not applied")
			os.Exit(2)
		}
		mutant = strings.Replace(mutant, environment, "", 1)
	}

	return mutant
}
