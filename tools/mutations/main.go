// Narrowing controls for Keymaker authorization, recovery and refusal gates. Source changes exist
// only in Go overlay files under the caller's scratch directory.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	scratch := flag.String("scratch", "", "existing task scratch parent")
	only := flag.String("only", "", "run one named plant within the selected group")
	applies := flag.Bool("check-applies", false, "check selected source plants without running tests")
	group := flag.String("group", "core", "core (including native), native, registration, helper, packaging, genjournal-core, genjournal, message-key, message-state, j7-state j7-continuity j7-signing j7-delegation, j7-delegation-r2, j7-lifecycle-wire, j7-idle message-author, message-author-live, message-author-issuer or j7-service controls")
	flag.Parse()
	if *scratch == "" || flag.NArg() != 0 || (*group != "core" && *group != "native" && *group != "registration" && *group != "helper" && *group != "packaging" && *group != "genjournal-core" && *group != "genjournal" && *group != "message-key" && *group != "message-state" && *group != "j7-state" && *group != "j7-continuity" && *group != "j7-signing" && *group != "j7-delegation" && *group != "j7-delegation-r2" && *group != "j7-lifecycle-wire" && *group != "j7-idle" && *group != "message-author-live" && *group != "message-author" && *group != "j7-service" && *group != "message-author-issuer") {
		fmt.Fprintln(os.Stderr, "use -scratch <directory> [-group core|native|registration|helper|packaging|genjournal-core|genjournal|message-key|message-state|j7-state|j7-continuity|j7-signing|j7-delegation|j7-delegation-r2|j7-lifecycle-wire|j7-idle|message-author|message-author-live|message-author-issuer|j7-service]")
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
	socketGuard := "\tif syscall.Fchownat(fd, \"control.sock\", os.Getuid(), int(gid), 0x100 /* Linux AT_SYMLINK_NOFOLLOW */) != nil || syscall.Fchmodat(fd, \"control.sock\", 0660, 0) != nil {\n\t\treturn fail()\n\t}\n\tst, err := os.Lstat(staged)\n\tif err != nil {\n\t\treturn fail()\n\t}\n\tstat := st.Sys().(*syscall.Stat_t)\n\tif st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 || stat.Uid != uint32(os.Getuid()) || stat.Gid != gid || !j7SocketNoACL(staged) {\n\t\treturn fail()\n\t}\n"
	socketFallback := "\t_ = syscall.Fchmodat(fd, \"control.sock\", 0666, 0)\n\tst, err := os.Lstat(staged)\n\tif err != nil { return fail() }\n\tstat := st.Sys().(*syscall.Stat_t)\n"
	// Move only the authoritative retained snapshot before the generation
	// barrier, retaining Store synchronization and every authority predicate.
	replayInside := `	var result control.Object
	c = n.Engine.Generations.WithEvidence(ctx, effectConditions, func(ctx context.Context) Code {
		s := n.Engine.Store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if c := connection.bindingActive(s); c != "" {
			return c
		}
		old, c := s.retained(p, r)`
	replayOutside := `	var result control.Object
	n.Engine.Store.mu.Lock()
	outside, outsideCode := n.Engine.Store.retained(p, r)
	n.Engine.Store.mu.Unlock()
	c = n.Engine.Generations.WithEvidence(ctx, effectConditions, func(ctx context.Context) Code {
		s := n.Engine.Store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
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
		{"snapshot-journal-divergence", "custody_linux.go", "if !s.matchesCommit(j.binding) && !recovery {", "if false && !s.matchesCommit(j.binding) && !recovery {", "^TestSnapshotJournalDivergence$/^snapshot-before-revoke$", "--- FAIL: TestSnapshotJournalDivergence/snapshot-before-revoke", "BYPASS: restored pre-revoke snapshot signed"},
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
		{"native-release-fence", "native.go", "return n.Engine.Generations.WithActive(ctx, p.UID, p.Generation, release)", "return release(ctx)", "^TestNativeReleaseFence$/^hello$/^retirement-wins$", "--- FAIL: TestNativeReleaseFence/hello/retirement-wins", "native retirement released success"},
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
	if *group == "message-author" || *group == "message-author-live" {
		// Only new source gates are weakened. Each named assertion must fail;
		// compiler/setup errors, timeouts and unplanted controls are not kills.
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"ma-authority-algorithm", "authority_codec.go", `(algorithm != "ed25519" && algorithm != "p256")`, `false && (algorithm != "ed25519" && algorithm != "p256")`, "^TestMessageAuthorLegacyAuthorityAlgorithms$/^bip340$", "--- FAIL: TestMessageAuthorLegacyAuthorityAlgorithms/bip340", "legacy algorithm accepted"},
			{"ma-purpose5-issuer-algorithm", "message_files.go", `algorithm == "ed25519" && record.ValidateKey(key) == nil`, `algorithm != "" && record.ValidateKey(key) == nil`, "^TestMessageAuthorPurpose5(Intent|Certificate)IssuerAlgorithms$", "--- FAIL: TestMessageAuthorPurpose5IntentIssuerAlgorithms/bip340", "purpose5 issuer algorithm accepted"},
			{"ma-wire-received-id", "../../messageauthor/codec.go", `if !ok || !validID(id) {`, `if !ok || false && !validID(id) {`, "^TestMessageAuthorReceivedResponseID$", "--- FAIL: TestMessageAuthorReceivedResponseID/busy", "received nonnull ID alias"},
			{"ma-wire-cap", "../../messageauthor/codec.go", `if n > MaxFrame {`, `if false && n > MaxFrame {`, "^TestMessageAuthorFrameLimits$", "--- FAIL: TestMessageAuthorFrameLimits", "cap header accepted"},
			{"ma-wire-params", "../../messageauthor/codec.go", `if !members(p, "preimage") {`, `if false && !members(p, "preimage") {`, "^TestMessageAuthorClosedRequests$", "--- FAIL: TestMessageAuthorClosedRequests", "request refusal/zero"},
			{"ma-wire-id", "../../messageauthor/codec.go", `r.ID != q.ID`, `false && r.ID != q.ID`, "^TestMessageAuthorResponseContext$", "--- FAIL: TestMessageAuthorResponseContext", "response refusal/zero"},
			{"ma-wire-key", "../../messageauthor/codec.go", `&& record.ValidateKey(s) == nil`, ``, "^TestMessageAuthorResponseContext$", "--- FAIL: TestMessageAuthorResponseContext", "invalid identity accepted"},
			{"ma-wire-preimage-cap", "../../messageauthor/codec.go", `return len(r.Preimage) <= MaxPreimage`, `return len(r.Preimage) <= MaxFrame`, "^TestMessageAuthorFrameLimits$", "--- FAIL: TestMessageAuthorFrameLimits", "oversize copied"},
			{"ma-binding", "message_author_key.go", `current != b || `, ``, "^TestMessageAuthorBindingSelection$/^registration$", "--- FAIL: TestMessageAuthorBindingSelection/registration", "binding substitution public"},
			{"ma-role", "message_author_key.go", `k.role != messageAuthorRole || `, ``, "^TestMessageAuthorCustodyNoRelease$/^wrong-role$", "--- FAIL: TestMessageAuthorCustodyNoRelease/wrong-role", "custody failure output"},
			{"ma-entropy", "message_author_key.go", `if _, e := io.ReadFull(k.entropy, aux[:]); e != nil {`, `if _, e := io.ReadFull(k.entropy, aux[:]); false && e != nil {`, "^TestMessageAuthorCustodyNoRelease$/^short-entropy$", "--- FAIL: TestMessageAuthorCustodyNoRelease/short-entropy", "custody failure output"},
			{"ma-double-hash", "message_author_key.go", `hash := sha256.Sum256(plan.original)`, `first := sha256.Sum256(plan.original); hash := sha256.Sum256(first[:])`, "^TestMessageAuthorEnvelopeProfile$", "--- FAIL: TestMessageAuthorEnvelopeProfile", "independent original preimage signature"},
			{"ma-admission", "message_author_preimage.go", `if err != nil {`, `if false && err != nil {`, "^TestMessageAuthorPreimageAdmission$/^space$", "--- FAIL: TestMessageAuthorPreimageAdmission/space", "preimage refusal"},
			{"ma-identity", "message_author_preimage.go", `MultiAgent: true, Check: true`, `MultiAgent: false, Check: false`, "^TestMessageAuthorCallerIdentity$/^attestation$", "--- FAIL: TestMessageAuthorCallerIdentity/attestation", "identity path accepted"},
			{"ma-no-copy", "message_author_preimage.go", `original: append([]byte(nil), original...)`, `original: original`, "^TestMessageAuthorEnvelopeProfile$", "--- FAIL: TestMessageAuthorEnvelopeProfile", "preimage alias"},
			{"ma-export", "message_author_key.go", `io.WriteString(s, "[message-author custody]")`, `fmt.Fprintf(s, "%x", k.seed)`, "^TestMessageAuthorCustodyNoRelease$", "--- FAIL: TestMessageAuthorCustodyNoRelease", "secret diagnostic"},
		}
	}
	if *group == "message-author-live" {
		// The original fixture/codec guards above stay in this group. These
		// additional plants narrow only the live holder's accepted contracts.
		controls = append(controls, []struct{ name, file, old, new, test, needle, witness string }{
			{"malive-custody-identity-cause", "message_author_live.go", "if h.key.instance != s.maLive.Instance || h.key.epoch != s.maLive.Epoch || h.key.registry != s.maLive.Registry {\n\t\t\t\tmaLiveSetCause(ctx, custodyProtectionFailed)", "if h.key.instance != s.maLive.Instance || h.key.epoch != s.maLive.Epoch || h.key.registry != s.maLive.Registry {", "^TestMALiveCustodyIdentityRefusalFrame$", "--- FAIL: TestMALiveCustodyIdentityRefusalFrame", "custody refusal missing exact single audit"},
			{"malive-load-unchanged-signature", "message_author_live_state.go", "len(a.Signature) > 0 && record.VerifySignature(a.Key, a.Signature, a.Preimage) != nil", "false && len(a.Signature) > 0 && record.VerifySignature(a.Key, a.Signature, a.Preimage) != nil", "^TestMALiveIncrementalPersistence$", "--- FAIL: TestMALiveIncrementalPersistence", "corrupt unchanged row accepted at load"},
			{"malive-full-retention-validation", "message_author_live_state.go", "if s.maLiveCache == nil {", "if true {", "^TestMALiveIncrementalPersistence$", "--- FAIL: TestMALiveIncrementalPersistence", "unchanged row revalidated during transition"},
			{"malive-idle-debt", "message_author_live_budget.go", "maLiveBucketFull(old.all, now, 20, 40) && maLiveBucketFull(old.sign, now, 2, 4)", "maLiveBucketFull(old.all, now, 20, 40)", "^TestMALiveIdlePeerReclamation$", "--- FAIL: TestMALiveIdlePeerReclamation", "sign debt erased"},
			{"malive-connection-current-t", "message_author_preimage.go", "return nil, Code(e.Code)", "if e.Code == \"signer_identity_mismatch\" { return &messageAuthorPlan{original:append([]byte(nil),original...),key:key,attestation:attestation}, \"\" }; return nil, Code(e.Code)", "^TestMALiveSecondConnectionIdentity$", "--- FAIL: TestMALiveSecondConnectionIdentity", "old connection currentness reused"},
			{"malive-diagnostics-material", "message_author_key.go", "io.WriteString(s, \"[message-author custody]\")", "fmt.Fprintf(s, \"%x\", k.seed)", "^TestMALiveNoMaterialInDiagnostics$", "--- FAIL: TestMALiveNoMaterialInDiagnostics", "capability formatting exposed material"},
			{"malive-schema-explicit-reader", "binding.go", "if (s.schema == maLiveSchema || floor == maLiveSchema) &&", "if false && (s.schema == maLiveSchema || floor == maLiveSchema) &&", "^TestMALiveSchemaAndExplicitInit$", "--- FAIL: TestMALiveSchemaAndExplicitInit", "old reader accepted schema 7"},
			{"malive-tag", "message_author_preimage.go", "return nil, Code(e.Code)", "if e.Code == \"signer_tag_malformed\" { return &messageAuthorPlan{original:append([]byte(nil),original...),key:key,attestation:attestation}, \"\" }; return nil, Code(e.Code)", "^TestMALiveTagDomain$", "--- FAIL: TestMALiveTagDomain", "negative standing/effect"},
			{"malive-domain", "message_author_preimage.go", "return nil, Code(e.Code)", "if e.Code == \"signer_domain_refused\" { return &messageAuthorPlan{original:append([]byte(nil),original...),key:key,attestation:attestation}, \"\" }; return nil, Code(e.Code)", "^TestMALiveTagDomain$", "--- FAIL: TestMALiveTagDomain", "negative standing/effect"},
			{"malive-author", "message_author_preimage.go", "return nil, Code(e.Code)", "if e.Code == \"signer_identity_mismatch\" { return &messageAuthorPlan{original:append([]byte(nil),original...),key:key,attestation:attestation}, \"\" }; return nil, Code(e.Code)", "^TestMALiveAuthorEqualsOwnKey$", "--- FAIL: TestMALiveAuthorEqualsOwnKey", "negative standing/effect"},
			{"malive-t-admit", "message_author_preimage.go", "return nil, Code(e.Code)", "if e.Code == \"signer_identity_mismatch\" { return &messageAuthorPlan{original:append([]byte(nil),original...),key:key,attestation:attestation}, \"\" }; return nil, Code(e.Code)", "^TestMALiveCurrentTAdmission$", "--- FAIL: TestMALiveCurrentTAdmission", "negative standing/effect"},
			{"malive-payload", "message_author_preimage.go", "return nil, Code(e.Code)", "if e.Code == \"signer_payload_invalid\" { return &messageAuthorPlan{original:append([]byte(nil),original...),key:key,attestation:attestation}, \"\" }; return nil, Code(e.Code)", "^TestMALiveCanonicalPayload$", "--- FAIL: TestMALiveCanonicalPayload", "negative standing/effect"},
			{"malive-record-key", "message_author_preimage.go", "return nil, Code(e.Code)", "if e.Code == \"signer_identity_mismatch\" { return &messageAuthorPlan{original:append([]byte(nil),original...),key:key,attestation:attestation}, \"\" }; return nil, Code(e.Code)", "^TestMALiveRecordKeyEqualsOwnKey$", "--- FAIL: TestMALiveRecordKeyEqualsOwnKey", "negative standing/effect"},
			{"malive-decoded-cap", "message_author_live.go", "if len(r.Preimage) > messageauthor.MaxPreimage {", "if false && len(r.Preimage) > messageauthor.MaxPreimage {", "^TestMALivePreimageBounds$", "--- FAIL: TestMALivePreimageBounds", "oversized preimage reached authority before cap"},
			{"malive-encoded-cap", "message_author_live_socket_linux.go", "len(p64) > 32768", "len(p64) > 65536", "^TestMALiveWireAndCodeClosure$", "--- FAIL: TestMALiveWireAndCodeClosure", "wire refusal"},
			{"malive-opaque-claims", "message_author_live.go", "plan, c := prepareMessageAuthor(r.Preimage, tuple.Key, tuple.T)", "if bytes.Contains(r.Preimage,[]byte(`\"approver\":true`)) { return \"role_not_permitted\" }; plan, c := prepareMessageAuthor(r.Preimage, tuple.Key, tuple.T)", "^TestMALiveOpaqueClaimsGrantNothing$", "--- FAIL: TestMALiveOpaqueClaimsGrantNothing", "opaque claims interpreted"},
			{"malive-intent-sync", "message_author_live.go", "if c = s.persistMALiveAdmission(ctx, i); c != \"\" {\n\t\t\t\tif c == \"state_capacity_exceeded\"", "if c = Code(\"\"); c != \"\" {\n\t\t\t\tif c == \"state_capacity_exceeded\"", "^TestMALiveIntentBeforeCrypto$", "--- FAIL: TestMALiveIntentBeforeCrypto", "durable boundary missing before crypto"},
			{"malive-invoking-sync", "message_author_live.go", "a.Status = \"invoking\"\n\t\t\tc := s.persistMALive(ctx, i)", "a.Status = \"invoking\"\n\t\t\tc := Code(\"\")", "^TestMALiveIntentBeforeCrypto$", "--- FAIL: TestMALiveIntentBeforeCrypto", "durable boundary missing before crypto"},
			{"malive-retained-lookup", "message_author_live.go", "if a.Status != \"intent\" {\n\t\t\treturn \"\"", "if false && a.Status != \"intent\" {\n\t\t\treturn \"\"", "^TestMALiveRetryAcrossConnection$", "--- FAIL: TestMALiveRetryAcrossConnection", "released replay"},
			{"malive-wait-owner", "message_author_live.go", "if wait := h.running[k]; wait != nil {", "if wait := h.running[k]; false && wait != nil {", "^TestMALiveConcurrentEqualRetry$", "--- FAIL: TestMALiveConcurrentEqualRetry", "duplicate did not wait for running handoff"},
			{"malive-conflict-first", "message_author_live.go", "if a.Method != string(r.Method) || !bytes.Equal(a.Preimage, r.Preimage) {\n\t\t\treturn \"request_conflict\"", "if false && (a.Method != string(r.Method) || !bytes.Equal(a.Preimage, r.Preimage)) {\n\t\t\treturn \"request_conflict\"", "^TestMALiveRequestConflict$", "--- FAIL: TestMALiveRequestConflict", "negative standing/effect"},
			{"malive-principal", "message_author_live_state.go", "a.Caller == p && a.ID == id", "a.ID == id", "^TestMALivePrincipalIsolation$", "--- FAIL: TestMALivePrincipalIsolation", "principal borrowed retained result"},
			{"malive-old-t", "message_author_live.go", "if a.Attestation != tuple.T {", "if false && a.Attestation != tuple.T {", "^TestMALiveRetryOldT$", "--- FAIL: TestMALiveRetryOldT", "old T not dead"},
			{"malive-recover-invoking", "message_author_live_audit.go", "a.Status = \"dead\"\n\t\t\t\trows = append(rows, i)\n\t\t\t}", "a.Status = \"intent\"\n\t\t\t\trows = append(rows, i)\n\t\t\t}", "^TestMALiveCrashStatusMatrix$", "--- FAIL: TestMALiveCrashStatusMatrix", "recovery row"},
			{"malive-unproven-audit", "message_author_live_audit.go", "if !s.maLiveResultProven(*a) {", "if false && !s.maLiveResultProven(*a) {", "^TestMALiveCrashStatusMatrix$", "--- FAIL: TestMALiveCrashStatusMatrix", "unproven audit admitted result"},
			{"malive-journal-append", "../keymaker/audit.go", "if e != nil || n != len(b) {", "if false && (e != nil || n != len(b)) {", "^TestMALiveKnownAuditFailure$", "--- FAIL: TestMALiveKnownAuditFailure", "negative standing/effect"},
			{"malive-journal-sync", "../keymaker/audit.go", "if j.writer.Sync() != nil {", "if j.writer.Sync() != nil && false {", "^TestMALiveKnownAuditFailure$", "--- FAIL: TestMALiveKnownAuditFailure", "negative standing/effect"},
			{"malive-release-current", "message_author_live.go", "if a.Attestation != tuple.T {", "if a.Attestation != tuple.T && a.Status != \"handoff_unknown\" {", "^TestMALiveWithdrawalBarrier$", "--- FAIL: TestMALiveWithdrawalBarrier", "negative standing/effect"},
			{"malive-release-gen-loss", "message_author_live.go", "s.maLive.Attempts[i].Status = \"dead\"", "s.maLive.Attempts[i].Status = \"released\"", "^TestMALiveTerminalGenerationLoss$", "--- FAIL: TestMALiveTerminalGenerationLoss", "terminal generation loss retained releasable result"},
			{"malive-lower-bound", "message_author_live.go", "!at.Lower.Before(notBefore)", "!at.Now.Before(notBefore)", "^TestMALiveTimeScope$", "--- FAIL: TestMALiveTimeScope", "negative standing/effect"},
			{"malive-upper-bound", "message_author_live.go", "at.Upper.Before(notAfter)", "at.Now.Before(notAfter)", "^TestMALiveTimeScope$", "--- FAIL: TestMALiveTimeScope", "negative standing/effect"},
			{"malive-message-exp", "message_author_live.go", "plan, c := prepareMessageAuthor(r.Preimage, tuple.Key, tuple.T)", "if bytes.Contains(r.Preimage,[]byte(`\"exp\":`)) {return \"key_not_valid_now\"};plan, c := prepareMessageAuthor(r.Preimage, tuple.Key, tuple.T)", "^TestMALiveTimeScope$", "--- FAIL: TestMALiveTimeScope", "valid control"},
			{"malive-deadline-callback", "message_author_live.go", "if auditContextExpired(ctx) {\n\t\t\ts.journal.mu.Unlock()", "if false && auditContextExpired(ctx) {\n\t\t\ts.journal.mu.Unlock()", "^TestMALiveDeadlineThroughHandoff$", "--- FAIL: TestMALiveDeadlineThroughHandoff", "negative standing/effect"},
			{"malive-attempt-cap", "message_author_live.go", "if len(s.maLive.Attempts) >= maLiveAttemptLimit {", "if false && len(s.maLive.Attempts) >= maLiveAttemptLimit {", "^TestMALiveRetentionNoEviction$", "--- FAIL: TestMALiveRetentionNoEviction", "negative standing/effect"},
			{"malive-generic-register", "binding.go", "if s.schema == maLiveSchema {\n\t\treturn Binding{}, \"operation_unsupported\"", "if false && s.schema == maLiveSchema {\n\t\treturn Binding{}, \"operation_unsupported\"", "^TestMALiveGenericMutatorsRefuse$/^register$", "--- FAIL: TestMALiveGenericMutatorsRefuse", "generic mutator changed schema-7 state"},
			{"malive-generic-revoke", "binding.go", "if s.schema == maLiveSchema {\n\t\ts.mu.Unlock()", "if false && s.schema == maLiveSchema {\n\t\ts.mu.Unlock()", "^TestMALiveGenericMutatorsRefuse$/^revoke$", "--- FAIL: TestMALiveGenericMutatorsRefuse", "generic mutator changed schema-7 state"},
			{"malive-generic-unbind", "binding.go", "func (s *Store) Unbind(caller, operator Principal, uid uint32, generation string) Code {\n\tif caller != operator || !validGeneration(caller.Generation) {\n\t\treturn \"role_not_permitted\"\n\t}\n\ts.mu.Lock()\n\tdefer s.mu.Unlock()\n\tif s.schema == maLiveSchema {", "func (s *Store) Unbind(caller, operator Principal, uid uint32, generation string) Code {\n\tif caller != operator || !validGeneration(caller.Generation) {\n\t\treturn \"role_not_permitted\"\n\t}\n\ts.mu.Lock()\n\tdefer s.mu.Unlock()\n\tif false && s.schema == maLiveSchema {", "^TestMALiveGenericMutatorsRefuse$/^unbind$", "--- FAIL: TestMALiveGenericMutatorsRefuse", "generic mutator changed schema-7 state"},
			{"malive-native-mutator", "native.go", "unsupported := n.Engine.Store.schema == maLiveSchema", "unsupported := false", "^TestMALiveGenericMutatorsRefuse$/^native-", "--- FAIL: TestMALiveGenericMutatorsRefuse", "generic mutator changed schema-7 state"},
			{"malive-retire-reserve", "message_author_live_state.go", "const maLiveRetireReserve = 64 << 10", "const maLiveRetireReserve = 0", "^TestMALiveRetireByteCeiling$", "--- FAIL: TestMALiveRetireByteCeiling", "retirement refused at ceiling"},
			{"malive-state-cap-callsite", "message_author_live_state.go", "if !maLiveStateRoom(bound + reserve) {", "if false && !maLiveStateRoom(bound + reserve) {", "^TestMALiveStateCapBeforeIntent$", "--- FAIL: TestMALiveStateCapBeforeIntent", "negative standing/effect"},
			{"malive-state-cap-load", "message_author_live_state.go", "if !maLiveStateRoom(s.maLiveBodySize(j7SafeInteger, len(s.maLive.Attempts), s.maLiveCache.total) + maLiveReceiptBound) {", "if false && !maLiveStateRoom(s.maLiveBodySize(j7SafeInteger, len(s.maLive.Attempts), s.maLiveCache.total) + maLiveReceiptBound) {", "^TestMALiveStateCapLoad$", "--- FAIL: TestMALiveStateCapLoad", "over-byte-cap state loaded or wrong gate"},
			{"malive-dead-request-cancel", "message_author_live.go", "context.WithTimeout(context.WithoutCancel(ctx), 250*time.Millisecond)", "context.WithTimeout(ctx, 250*time.Millisecond)", "^TestMALiveExpiredDeadDurable$", "--- FAIL: TestMALiveExpiredDeadDurable", "terminal persist retained request cancellation"},
			{"malive-retire-headroom", "message_author_live_operator_linux.go", "c := s.persistMALive(context.WithoutCancel(ctx), changed...)", "c := s.persistMALiveAdmission(context.WithoutCancel(ctx), changed...)", "^TestMALiveRetireByteCeiling$", "--- FAIL: TestMALiveRetireByteCeiling", "retirement refused at ceiling"},
			{"malive-loss-code", "message_author_live.go", "maLiveSetCause(ctx, custodyProtectionFailed)\n\t\t\t\treturn s.maLiveTerminal(ctx, p, r.ID, \"message_author_unqualified\")", "maLiveSetCause(ctx, custodyProtectionFailed)\n\t\t\t\treturn s.maLiveTerminal(ctx, p, r.ID, \"custody_unavailable\")", "^TestMALiveCustodyIdentityRefusalFrame$", "--- FAIL: TestMALiveCustodyIdentityRefusalFrame", "custody identity refusal"},
			{"malive-state-cap", "message_author_live_state.go", "bytes <= (maLiveStateLimit-maLiveStateOverhead)/3", "bytes <= maLiveStateLimit", "^TestMALiveCapacityAndRate$", "--- FAIL: TestMALiveCapacityAndRate", "state byte limit widened"},
			{"malive-entropy", "message_author_key.go", "if _, e := io.ReadFull(k.entropy, aux[:]); e != nil {", "if _, e := io.ReadFull(k.entropy, aux[:]); false && e != nil {", "^TestMALiveCustodyAndEntropy$", "--- FAIL: TestMALiveCustodyAndEntropy", "negative standing/effect"},
			{"malive-self-verify", "message_author_key.go", "if record.VerifySignature(key, out, plan.original) != nil {", "if false && record.VerifySignature(key, out, plan.original) != nil {", "^TestMALiveSelfVerifyFailure$", "--- FAIL: TestMALiveSelfVerifyFailure", "primitive released corrupt signature"},
			{"malive-audit-material", "message_author_live_audit.go", "if r.Path != nil || r.Epoch != nil {", "if false && (r.Path != nil || r.Epoch != nil) {", "^TestMALiveAuditOperations$", "--- FAIL: TestMALiveAuditOperations", "raw material written"},
			{"malive-resolve-head", "message_author_live_audit.go", "!s.j7HeadMatches(expected) || !s.matchesCommit(s.journal.binding)", "!s.matchesCommit(s.journal.binding)", "^TestMALiveUnknownAuditNeedsResolve$", "--- FAIL: TestMALiveUnknownAuditNeedsResolve", "single source/readback cleared uncertainty"},
			{"malive-sync-uncertainty", "message_author_live_audit.go", "if s.maLiveUnpairedSign(*a) {", "if false && s.maLiveUnpairedSign(*a) {", "^TestMALiveKilledAuditSync$", "--- FAIL: TestMALiveKilledAuditSync", "unknown audit inferred absence/result"},
			{"malive-production-refuser", "message_author_live.go", "func (maLiveUnqualified) WithCurrent(context.Context, Binding, j7GateTime, func(maLiveTuple) Code) Code {\n\treturn \"message_author_unqualified\"\n}", "func (maLiveUnqualified) WithCurrent(ctx context.Context,b Binding,at j7GateTime,fn func(maLiveTuple)Code) Code { return fn(maLiveTuple{Key:\"bip340:WowJ0rnekTFSPtivBWuoato06f_BXuc3w-BkTJspoPE\",T:\"sha256:557f3ffbd6aaa0a341ca3e817fc72dca935ec06f155dcd3d92fd4aab0b7f9989\",Attestation:[]byte(\"fixture\")}) }", "^TestMALiveProductionProviderRefuses$", "--- FAIL: TestMALiveProductionProviderRefuses", "negative standing/effect"},
			{"malive-schema-floor", "message_author_live_config_linux.go", "m.State.Minimum != maLiveSchema", "m.State.Minimum != maLiveSchema && m.State.Minimum != 6", "^TestMALivePackagingContract$", "--- FAIL: TestMALivePackagingContract", "old schema floor accepted"},
			{"malive-epoch", "message_author_live_operator_linux.go", "b.Epoch != s.maLive.Epoch || b.RegistryRevision != s.maLive.Registry", "b.RegistryRevision != s.maLive.Registry", "^TestMALiveOwnBindingUniqueness$", "--- FAIL: TestMALiveOwnBindingUniqueness", "C2 epoch mismatch"},
			{"malive-tombstone", "message_author_live_operator_linux.go", "old.Epoch == b.Epoch && old.Path == b.Path", "old.Status == \"active\" && old.Epoch == b.Epoch && old.Path == b.Path", "^TestMALiveOwnBindingUniqueness$", "--- FAIL: TestMALiveOwnBindingUniqueness", "resurrected tombstone"},
			{"malive-tombstone-restart", "message_author_live_operator_linux.go", "if c := s.recoverMALive(context.Background()); c != \"\" {\n\t\ts.Close()\n\t\treturn nil, c\n\t}\n\treturn s, \"\"", "if c := s.recoverMALive(context.Background()); c != \"\" {\n\t\ts.Close()\n\t\treturn nil, c\n\t}\n var active []Binding; for _, b := range s.records { if b.Status == \"active\" { active=append(active,b) } }; s.records=active\n\treturn s, \"\"", "^TestMALiveOwnBindingUniqueness$", "--- FAIL: TestMALiveOwnBindingUniqueness", "retired tombstone lost on restart"},
			{"malive-generation", "message_author_live.go", "if h.generations == nil {\n\t\treturn \"generation_source_unavailable\"\n\t}", "if h.generations == nil {return fn(ctx)}", "^TestMALiveRequiredGeneration$", "--- FAIL: TestMALiveRequiredGeneration", "negative standing/effect"},
			{"malive-existing-fence", "message_author_live.go", "if s.failed || s.maLive == nil || s.maLive.Fenced {\n\t\treturn Binding{}, \"message_author_unqualified\"", "if s.failed || s.maLive == nil {\n\t\treturn Binding{}, \"message_author_unqualified\"", "^TestMALiveTimeRefusalNotFence$", "--- FAIL: TestMALiveTimeRefusalNotFence", "negative standing/effect"},
			{"malive-connection-limit", "message_author_live_socket_linux.go", "return global < 32 && uid < 4", "return global < 128 && uid < 16", "^TestMALiveCapacityAndRate$", "--- FAIL: TestMALiveCapacityAndRate", "connection limits widened"},
			{"malive-slot-limit", "message_author_live_socket_linux.go", "slots: make(chan struct{}, 16)", "slots: make(chan struct{}, 128)", "^TestMALiveCapacityAndRate$", "--- FAIL: TestMALiveCapacityAndRate", "request slot limit widened"},
			{"malive-rate-peer", "message_author_live_budget.go", "!peer.all.take(now, 20, 40)", "!peer.all.take(now, 20, 41)", "^TestMALiveCapacityAndRate$", "--- FAIL: TestMALiveCapacityAndRate", "forty-first peer request admitted"},
			{"malive-rate-sign", "message_author_live_budget.go", "if sign && !peer.sign.take(now, 2, 4)", "if sign && !peer.sign.take(now, 2, 5)", "^TestMALiveCapacityAndRate$", "--- FAIL: TestMALiveCapacityAndRate", "fifth sign admitted"},
			{"malive-rate-global", "message_author_live_budget.go", "!b.global.take(now, 200, 256)", "!b.global.take(now, 200, 257)", "^TestMALiveCapacityAndRate$", "--- FAIL: TestMALiveCapacityAndRate", "257th global request admitted"},
			{"malive-audit-reserve", "message_author_live.go", "s.journal.totalLimit-s.journal.reserve", "s.journal.totalLimit", "^TestMALiveCapacityAndRate$", "--- FAIL: TestMALiveCapacityAndRate", "negative standing/effect"},
			{"malive-audit-domain", "message_author_live_audit.go", "domain = \"swarma-msg\"\n\t}\n\tr := AuditRecord", "domain = \"control\"\n\t}\n\tr := AuditRecord", "^TestMALiveAuditOperations$", "--- FAIL: TestMALiveAuditOperations", "audit_unavailable"},
			{"malive-audit-receipt", "message_author_live.go", "a.SuccessSeq, a.SuccessHash = seq, hash", "_ = seq; _ = hash; s.journal.mu.Lock(); a.SuccessSeq, a.SuccessHash = s.journal.seq, s.journal.previous; s.journal.mu.Unlock()", "^TestMALiveAuditReceiptAssociation$", "--- FAIL: TestMALiveAuditReceiptAssociation", "unrelated audit head substituted for sign receipt"},
			{"malive-audit-clock-standing", "audit.go", "if maLiveOperation(r.Operation) && r.Time == nil {", "if false && maLiveOperation(r.Operation) && r.Time == nil {", "^TestMALiveAuditTimeRefusal$", "--- FAIL: TestMALiveAuditTimeRefusal", "negative standing/effect"},
			{"malive-audit-clock-fence", "message_author_live_audit.go", "c != \"request_deadline_exceeded\" && c != \"clock_untrusted\"", "c != \"request_deadline_exceeded\"", "^TestMALiveAuditTimeRefusal$", "--- FAIL: TestMALiveAuditTimeRefusal", "temporary audit time latched failure/fence"},
			{"malive-retire-connection", "message_author_live_operator_linux.go", "s.notify(number)", "// deliberately omit binding withdrawal notification", "^TestMALiveRetirementClosesConnection$", "--- FAIL: TestMALiveRetirementClosesConnection", "retired connection not invalidated"},
			{"malive-wire-retry", "../control/protocol.go", "\"enrollment_unavailable\", \"audit_unavailable\", DeadlineExceeded:", "\"enrollment_unavailable\", \"audit_unavailable\", \"message_author_unqualified\", DeadlineExceeded:", "^TestMALiveControlCodes$", "--- FAIL: TestMALiveControlCodes", "message-author code closure or retryability changed"},
			{"malive-legacy-method", "native.go", "func (n *Native) Handle(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {", "func (n *Native) Handle(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {\n if r.Method == \"message_author_identity\" { return control.Object{}, \"\" }", "^TestMALiveLegacyIsolation$", "--- FAIL: TestMALiveLegacyIsolation", "operation_unsupported"},
		}...)
	}
	if *group == "j7-service" {
		// Every plant weakens a composed startup or socket invariant; a kill
		// requires the named assertion, never a setup or compilation failure.
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"j7-static-release-class", "j7_static_gate_linux.go", `class := j7GateClass(r.Method)`, `class := staticgate.ClassEnd`, "^TestJ7StaticGatePreparedSignatureExpiry$/^expired$", "--- FAIL: TestJ7StaticGatePreparedSignatureExpiry/expired", "want STATIC_GATE_WINDOW"},
			{"j7-static-release-callback", "j7_static_gate_linux.go", `		if code := h.recheck(ctx, class); code != "" {
			return code
		}
`, ``, "^TestJ7StaticGateReleaseWait$", "--- FAIL: TestJ7StaticGateReleaseWait/start-expired", "expired callback released"},
			{"j7-static-start-bounds", "j7_static_gate_linux.go", `points = []time.Time{at.Lower, at.Upper}`, `points = []time.Time{at.Now}`, "^TestJ7StaticGateTrustedBounds$", "--- FAIL: TestJ7StaticGateTrustedBounds/lower", "effect interval admitted"},
			{"j7-static-publication-recheck", "j7_service_linux.go", `		if code := gated.recheck(ctx, staticgate.ClassStart); code != "" {
			return nil, 0, 0, Code(code)
		}
`, ``, "^TestJ7StaticGateStartupPublicationExpiry$/^expired$", "--- FAIL: TestJ7StaticGateStartupPublicationExpiry/expired", "want STATIC_GATE_WINDOW"},
			{"j7-service-root-identity", "j7_service_linux.go", `if uid == 0 || euid == 0 || gid == 0 || egid == 0 {`, `if false && (uid == 0 || euid == 0 || gid == 0 || egid == 0) {`, "^TestJ7ServiceRootRefusal$", "--- FAIL: TestJ7ServiceRootRefusal", "want role_not_permitted"},
			{"j7-service-root-config", "config_linux.go", `if request && (parsed.ServiceUID == 0 || parsed.ServiceGID == 0) {`, `if false && request && (parsed.ServiceUID == 0 || parsed.ServiceGID == 0) {`, "^TestJ7ServiceConfigRootRefusal$", "--- FAIL: TestJ7ServiceConfigRootRefusal", "root config admitted"},
			{"j7-static-pin-key-order", "j7_static_gate_linux.go", `	keyFile, err := g.read(in.Files.ApproverKeyFile, 65)
	key, ok := j7HexLine(keyFile, 64)
	if err != nil || !ok {
		return empty, Code(staticgate.CodeKey)
	}
`, ``, "^TestJ7StaticGatePinBeforeKey$", "--- FAIL: TestJ7StaticGatePinBeforeKey", "want STATIC_GATE_PIN"},
			{"j7-service-key-before-lock", "j7_service_linux.go", `	key, e := d.loadKey(cfg.J7KeyFile, uid, j7RequestRole, cfg.InstanceID, cfg.Epoch, cfg.RegistryRevision)
	if e != nil {
		return e
	}
	defer key.close()
`, ``, "^TestJ7ServiceStartupOrder$", "--- FAIL: TestJ7ServiceStartupOrder", "startup order violated"},
			{"j7-service-listener-before-state", "j7_service_linux.go", `	publish := func(dir *os.File, group uint32) (*net.UnixListener, uint64, uint64, error) {
		if code := gated.recheck(ctx, staticgate.ClassStart); code != "" {
			return nil, 0, 0, Code(code)
		}
		return d.listen(dir, group)
	}
	socket, e := openJ7Socket(cfg.J7Socket.Dir, uid, cfg.J7Socket.Group, publish)
	if e != nil {
		return e
	}
	defer socket.remove()
`, ``, "^TestJ7ServiceStartupOrder$", "--- FAIL: TestJ7ServiceStartupOrder", "startup order violated"},
			{"j7-service-head-canonical", "j7_service_linux.go", `if !bytes.Equal(raw, []byte(canonical)) {`, `if false && !bytes.Equal(raw, []byte(canonical)) {`, "^TestJ7ServiceHeadCanonical$", "--- FAIL: TestJ7ServiceHeadCanonical", "noncanonical head accepted"},
			{"j7-service-idle-failure", "j7_service_socket_linux.go", `if health != nil {`, `if false && health != nil {`, "^TestJ7ServiceIdleStoreHealth$/^store$", "--- FAIL: TestJ7ServiceIdleStoreHealth/store", "idle Store failure did not stop service"},
			{"j7-service-peer-limit", "j7_service_socket_linux.go", `s.counts[uid] >= 8`, `s.counts[uid] >= 9`, "^TestJ7ServiceAcceptBounds$", "--- FAIL: TestJ7ServiceAcceptBounds", "ninth connection of one UID was served"},
			{"j7-service-global-limit", "j7_service_socket_linux.go", `len(s.connections) >= 128`, `len(s.connections) >= 129`, "^TestJ7ServiceAdmissionCapacity$", "--- FAIL: TestJ7ServiceAdmissionCapacity", "global limit admitted at bound"},
		}
	}
	if *group == "j7-idle" {
		// Each plant weakens an actual changed read-state/budget boundary.
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"j7-bound-idle-deadline", "../control/server.go", "if bound {\n\t\t// Clear the prior frame deadline", "if false && bound {\n\t\t// Clear the prior frame deadline", "^TestJ7LifecycleBoundIdle$", "--- FAIL: TestJ7LifecycleBoundIdle", "bound idle channel lost"},
			{"j7-unbound-idle-exemption", "../control/server.go", `bound = source.BoundChannel(probe, conn, state.accepted)`, `bound = source.BoundChannel(probe, conn, state.accepted) || state.negotiated`, "^TestJ7LifecycleUnboundIdle$/^hello$", "--- FAIL: TestJ7LifecycleUnboundIdle/hello", "unbound channel received indefinite read deadline"},
			{"j7-unbound-probe-budget", "../control/server.go", `readDeadline := readStarted.Add(frameBudget)`, `_ = readStarted; readDeadline := time.Now().Add(frameBudget)`, "^TestUnboundProbeReadBudget$", "--- FAIL: TestUnboundProbeReadBudget", "unbound probe extended original frame budget"},
			{"j7-obsolete-idle-exemption", "j7_run_linux.go", `l.channels[ch.run] != ch`, `false && l.channels[ch.run] != ch`, "^TestJ7LifecycleSingleIdleChannel$/^obsolete-map$", "--- FAIL: TestJ7LifecycleSingleIdleChannel/obsolete-map", "obsolete channel received indefinite read deadline"},
		}
	}
	if *group == "j7-lifecycle-wire" {
		pkg = "./j7lifecycle"
		// Only changed wire/bridge gates are planted. Each requires its named
		// intended assertion, not a compiler/setup failure or a fixed quota.
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"wire-frame-cap", "codec.go", `if n > MaxFrame {`, `if false && n > MaxFrame {`, "^TestLifecycleWireGrammarBounds$", "--- FAIL: TestLifecycleWireGrammarBounds", "cap header accepted"},
			{"wire-open-bind", "codec.go", `if !members(p, "identity_registration_number", "input_principal", "origin", "parent_run") {`, `if false && !members(p, "identity_registration_number", "input_principal", "origin", "parent_run") {`, "^TestLifecycleWireGrammarBounds$", "--- FAIL: TestLifecycleWireGrammarBounds", "request refusal/zero value"},
			{"wire-no-id", "codec.go", `r.ID != q.ID`, `false && r.ID != q.ID`, "^TestLifecycleWireResponseCorrelation$", "--- FAIL: TestLifecycleWireResponseCorrelation", "response refusal/zero value"},
			{"wire-end-live", "codec.go", `r.Run.State == "ended" && r.Run.RunID == q.RunID`, `(r.Run.State == "ended" || r.Run.State == "live") && r.Run.RunID == q.RunID`, "^TestLifecycleWireResponseCorrelation$", "--- FAIL: TestLifecycleWireResponseCorrelation", "response refusal/zero value"},
			{"wire-no-run-match", "codec.go", `return r.Run.State == "ended" && r.Run.RunID == q.RunID`, `return r.Run.State == "ended"`, "^TestLifecycleWireResponseCorrelation$", "--- FAIL: TestLifecycleWireResponseCorrelation", "response refusal/zero value"},
			{"wire-timeout-widen", "codec.go", `r.TimeoutMS > MaxTimeoutMS`, `r.TimeoutMS > 5000`, "^TestLifecycleWireDeadlines$", "--- FAIL: TestLifecycleWireDeadlines", "timeout accepted: 2001"},
			{"wire-retry-bit", "../internal/control/protocol.go", `return validCode(code) && retryable(code) == retry`, `return validCode(code)`, "^TestLifecycleWireRefusals$", "--- FAIL: TestLifecycleWireRefusals", "retry bit accepted"},
			{"wire-free-code", "../internal/control/protocol.go", `return validCode(code) && retryable(code) == retry`, `return retryable(code) == retry`, "^TestLifecycleWireRefusals$", "--- FAIL: TestLifecycleWireRefusals", "free form"},
			{"wire-origin-mode", "codec.go", `o.Mode == "enforcing"`, `(o.Mode == "enforcing" || o.Mode == "held")`, "^TestLifecycleWireClosedRequests$/^admission-mode$", "--- FAIL: TestLifecycleWireClosedRequests/admission-mode", "invalid typed request encoded"},
			{"wire-generation-preflight", "codec.go", `len(b.InputPrincipal.Generation) > MaxFrame || `, ``, "^TestLifecycleWireGrammarBounds$", "--- FAIL: TestLifecycleWireGrammarBounds", "obvious oversize copied or allocated: generation"},
		}
	}
	if *group == "j7-delegation" {
		// Requirement-derived controls; setup/compile failures are never kills.
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"j7-delegation-as-use", "j7_sign.go", `row == nil || !j7Listed(row.Delegate, id)`, `row == nil || !j7Listed(row.Use, id)`, "^TestJ7DelegationRootConsentBootstrap$", "--- FAIL: TestJ7DelegationRootConsentBootstrap", "want GRANT_NOT_FOR_RUN"},
			{"j7-delegation-any-row", "j7_profile2.go", `row := p.Delegate.Slots[c.Ordinal-1]`, `row := p.Delegate.Slots[c.Ordinal-1]
 for _, candidate := range p.Delegate.Slots { if candidate.Executor == c.Agent { row = candidate; break } }`, "^TestJ7DelegationChildFit$", "--- FAIL: TestJ7DelegationChildFit", "want CHILD_AGENT_NOT_ALLOWED"},
			{"j7-delegation-child-key", "j7_sign.go", `if p.operation != "" && p.contract.Grantee != public {`, `required := p.contract.Grantee
 if p.delegation != nil { required = p.delegation.child.Grantee }
 if p.operation != "" && required != public {`, "^TestJ7DelegationRootConsentBootstrap$", "--- FAIL: TestJ7DelegationRootConsentBootstrap", "native success result missing"},
			{"j7-delegation-no-release-proof", "j7_release.go", `if c = a.evidence.check(ctx, *p.grant, p.evidence, checked); c != "" {`, `if c = Code(""); c != "" {`, "^TestJ7DelegationFreshProofBeforeCallback$", "--- FAIL: TestJ7DelegationFreshProofBeforeCallback", "want delegation_evidence_unavailable"},
			{"j7-delegation-no-final-delegate", "j7_release.go", `c = a.withRun(ctx, peer, r, p, func(run j7Run`, `finalPlan := p
 if p.delegation != nil { finalPlan.operation = "envelope_v3" }
 c = a.withRun(ctx, peer, r, finalPlan, func(run j7Run`, "^TestJ7DelegationWithdrawalInsideFinalEvidence$", "--- FAIL: TestJ7DelegationWithdrawalInsideFinalEvidence", "want GRANT_NOT_FOR_RUN"},
			{"j7-delegation-resign-retained", "j7_sign.go", `if prior != nil {
			rec := s.j7SigningRecord`, `if false && prior != nil {
			rec := s.j7SigningRecord`, "^TestJ7DelegationRetainedSigningInvocation$", "--- FAIL: TestJ7DelegationRetainedSigningInvocation", "retained request invoked signing again"},
			{"j7-delegation-schema5-widen", "j7_delegation.go", `if schema != j7DelegationSchema || r.Method != "j7_sign" {`, `if schema != j7DelegationSchema && schema != j7SigningSchema || r.Method != "j7_sign" {`, "^TestJ7DelegationSchemaFloorPairedEndpoint$", "--- FAIL: TestJ7DelegationSchemaFloorPairedEndpoint", "want operation_unsupported"},
			{"j7-delegation-no-unknown", "j7_release.go", `record.Release = "handoff_unknown"
		if r.Method == "j7_enroll" {`, `// Plant: skip pre-callback unknown commitment.
        if r.Method == "j7_enroll" {`, "^TestJ7DelegationPartialWrite$", "--- FAIL: TestJ7DelegationPartialWrite", "unknown missing"},
		}
	}

	if *group == "j7-delegation-r2" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"j7-r2-created-at", "j7_sign.go", `if !p.eventTimeValid(now) {`, `if false && !p.eventTimeValid(now) {`, "^TestJ7DelegationCreationTimeBoundary$", "--- FAIL: TestJ7DelegationCreationTimeBoundary", "out-of-window creation retained or signed a result"},
			{"j7-r2-retained-window", "j7_release.go", `if !ok || code != "" || !valid || !p.eventTimeValid(event.CreatedAt) {`, `if !ok || code != "" || !valid || false && !p.eventTimeValid(event.CreatedAt) {`, "^TestJ7DelegationRetainedWindowRelease$", "--- FAIL: TestJ7DelegationRetainedWindowRelease", "out-of-window retained event reached callback"},
			{"j7-r2-config-floor", "config_linux.go", `(p.Minimum != 4 && p.Minimum != 5)`, `!j7StateSchema(p.Minimum)`, "^TestJ7ConfigReaderFloorPin$", "--- FAIL: TestJ7ConfigReaderFloorPin", "configuration admitted unapproved reader floor 6"},
			{"j7-r2-parent-order", "j7_delegation.go", `if code = j7ChildParentIdentity(pc, cc, g.ID()); code != "" {`, `if pc.Profile != "swarma-trust-contract/2" || cc.Profile != "swarma-trust-contract/2" { return p, "operation_unsupported" }
 if code = j7ChildParentIdentity(pc, cc, g.ID()); code != "" {`, "^TestJ7DelegationProfile1ParentOrder$", "--- FAIL: TestJ7DelegationProfile1ParentOrder", "want NOT_DELEGABLE"},
		}
	}

	if *group == "j7-state" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"j7-owner-row-selection", "j7_policy_linux.go", `row := j7PolicyRowFor(table, origin.key())`, `row := j7PolicyRowFor(table, j7OriginKey{Kind:"owner_command"})`, "^TestJ7PolicyOriginPermissions$", "--- FAIL: TestJ7PolicyOriginPermissions", "foreign origin grant admitted"},
			{"j7-spawn-origin", "j7_run_linux.go", `origin = parent.Origin`, `origin = j7Origin{Kind:"owner_command",Command:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`, "^TestJ7RunOriginAndRebind$", "--- FAIL: TestJ7RunOriginAndRebind", "spawn changed origin"},
			{"j7-policy-rollback", "j7_policy_linux.go", `if table.Version < j.Version {`, `if false {`, "^TestJ7PolicyRollbackAfterRestart$", "--- FAIL: TestJ7PolicyRollbackAfterRestart", "policy verdict , want GRANT_NOT_FOR_RUN"},
			{"j7-omit-denial", "j7_policy_linux.go", `next.Denials = reconcileJ7Denials(j.Policy, table, j.Denials)`, `next.Denials = []j7Denial{}`, "^TestJ7PolicyWithdrawalContinuity$", "--- FAIL: TestJ7PolicyWithdrawalContinuity", "withdrawal denial lost"},
			{"j7-reuse-connection", "j7_run_linux.go", `ch.ever || ch.run != "" || l.run(id) != nil`, `l.run(id) != nil`, "^TestJ7RunChannelIsolation$", "--- FAIL: TestJ7RunChannelIsolation", "want run_identity_unavailable"},
			{"j7-drop-snapshot-participant", "message_state.go", `J7: s.j7, J7Signing: s.j7Signing}`, `J7: nil, J7Signing: s.j7Signing}`, "^TestJ7RecoveryReaderAndExpectedHead$", "--- FAIL: TestJ7RecoveryReaderAndExpectedHead", "exact head positive"},
			{"j7-policy-acl", "j7_policy_linux.go", `if !j7NoACL(int(f.Fd()), false) {`, `if false {`, "^TestJ7PolicyProtection$", "--- FAIL: TestJ7PolicyProtection", "ACL accepted"},
			{"j7-policy-ancestor", "j7_policy_linux.go", `st.Mode&022 != 0`, `false`, "^TestJ7PolicyProtection$", "--- FAIL: TestJ7PolicyProtection", "writable ancestry accepted"},
			{"j7-policy-row-capacity", "j7_policy_linux.go", `len(p.Rows) > j7PolicyRows`, `false`, "^TestJ7PolicyCapacity$", "--- FAIL: TestJ7PolicyCapacity", "row overflow"},
		}
	}

	if *group == "j7-signing" {
		// Every plant must produce the forbidden successful socket result in
		// its named endpoint test; setup errors or unrelated refusals do not kill it.
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"j7-signing-owner-origin", "j7_sign.go", `row := j7PolicyRowFor(table, run.Origin.key())
	if p.operation == "consent_v3" {`, `row := j7PolicyRowFor(table, j7OriginKey{Kind:"owner_command"})
	if p.operation == "consent_v3" {`, "^TestJ7SigningGrantOrigin$", "--- FAIL: TestJ7SigningGrantOrigin", "result:map["},
			{"j7-signing-final-withdrawal", "j7_release.go", `c = a.withRun(ctx, peer, r, p, func(run j7Run, table *j7PolicyTable, public string, _ func(*[32]byte) ([]byte, error)) Code {`, `c = a.withRun(ctx, peer, r, j7Plan{}, func(run j7Run, table *j7PolicyTable, public string, _ func(*[32]byte) ([]byte, error)) Code {`, "^TestJ7SigningWithdrawalAfterEvidence$", "--- FAIL: TestJ7SigningWithdrawalAfterEvidence", "result:map["},
			{"j7-signing-durable-deny", "j7_policy_linux.go", `next.Denials = reconcileJ7Denials(j.Policy, table, j.Denials)`, `next.Denials = []j7Denial{}`, "^TestJ7SigningDurableDenyAndStandingConsent$", "--- FAIL: TestJ7SigningDurableDenyAndStandingConsent", "result:map["},
			{"j7-signing-unreleased-enrollment", "j7_sign.go", `r.Release != "released" || r.Origin.key() != run.Origin.key()`, `false || r.Origin.key() != run.Origin.key()`, "^TestJ7EnrollmentRequiresReleasedConsent$", "--- FAIL: TestJ7EnrollmentRequiresReleasedConsent", "result:map["},
			{"j7-signing-altered-retry", "request_ids.go", `prior.Method != r.Method || prior.Arguments != string(args)`, `prior.Method != r.Method || false && prior.Arguments != string(args)`, "^TestJ7SigningRetryInput$", "--- FAIL: TestJ7SigningRetryInput", "result:map["},
		}
	}

	if *group == "j7-continuity" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"j7-canceled-channel-authority", "j7_run_linux.go", `func (c *j7Channel) active() bool { return c.ctx.Err() == nil }`, `func (c *j7Channel) active() bool { return true }`, "^TestJ7RunCanceledCapabilityBoundaries$/^handling-after-admission$", "--- FAIL: TestJ7RunCanceledCapabilityBoundaries/handling-after-admission", "canceled channel changed durable state"},
			{"j7-terminal-channel-authority", "j7_run_linux.go", `s := l.store
			if !ch.active() {`, `s := l.store
			if false {`, "^TestJ7RunCanceledCapabilityBoundaries$/^handling-in-evidence$", "--- FAIL: TestJ7RunCanceledCapabilityBoundaries/handling-in-evidence", "canceled channel changed durable state"},
			{"j7-terminal-release-authority", "j7_run_linux.go", `defer s.mu.Unlock()
			if !ch.releasePermitted(nativePrincipal(peer), r) {`, `defer s.mu.Unlock()
			if false {`, "^TestJ7RunCanceledCapabilityBoundaries$/^release-in-evidence$", "--- FAIL: TestJ7RunCanceledCapabilityBoundaries/release-in-evidence", "canceled capability released a response"},
			{"j7-end-reply-retirement", "j7_run_linux.go", `ch.endReply = nil
					defer ch.conn.Close()`, `// Mutation: leave the exact reply permit and wire lifetime outstanding.`, "^TestJ7RunSelfEndReleasePermit$", "--- FAIL: TestJ7RunSelfEndReleasePermit", "self-end permit reused"},
			{"j7-migration-digest", "j7_state.go", `d == e.Digest`, `d != ""`, "^TestJ7RecoveryUnmigratedMigrationAuthority$", "--- FAIL: TestJ7RecoveryUnmigratedMigrationAuthority", "wrong unmigrated head accepted"},
		}
	}

	if *group == "message-state" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"message-capacity-drops-recovery-snapshot", "message_state.go", `recovery := int64(rawBytes) * int64(transitions)`, `recovery := int64(0)`, "^TestMsgCapacityCommitAfterRefusal$", "--- FAIL: TestMsgCapacityCommitAfterRefusal", "capacity admitted simultaneous snapshot copies"},
			{"message-arbitrary-root-sign", "message_attestation.go", `type messageBinding struct {`, `func(i *messageIssuer) Sign(raw []byte)([]byte,Code){return i.master.withPurpose(i.policy.Path,"root-attestation",func(k ed25519.PrivateKey)[]byte{return ed25519.Sign(k,raw)})}
type messageBinding struct {`, "^TestMsgV17RootIsolation$", "--- FAIL: TestMsgV17RootIsolation", "arbitrary issuer signing API"},
			{"message-issuer-purpose-two", "derive.go", `// Internal fixed-body issuer only; public APIs and bindings remain purpose 1.
		index = 5`, `// Fixture mutation: select the wrong sibling.
		index = 2`, "^TestMsgV18IssuerAndLifetime$", "--- FAIL: TestMsgV18IssuerAndLifetime", "86400 control"},
			{"message-lifetime-86401", "message_attestation.go", `i.policy.LifetimeSeconds > 86400`, `i.policy.LifetimeSeconds > 86401`, "^TestMsgV18IssuerAndLifetime$", "--- FAIL: TestMsgV18IssuerAndLifetime", "24-hour bound bypassed"},
			{"message-truncate-uid", "message_attestation.go", `func (i *messageIssuer) body(b Binding, public []byte, now time.Time) (map[string]any, Code) {`, `func (i *messageIssuer) body(b Binding, public []byte, now time.Time) (map[string]any, Code) {
	b.UID %= 0xffffffff`, "^TestMsgV23AttestationProfile$/^uid$", "--- FAIL: TestMsgV23AttestationProfile/uid", "profile builder pre-sign bound"},
			{"message-premature-current", "message_state.go", `tx.Phase = "issued"`, `tx.Phase = "issued"
		association.Current = &id`, "^TestMsgV26RenewalCommit$", "--- FAIL: TestMsgV26RenewalCommit", "candidate promoted before publication/activation"},
			{"message-restart-loses-fence", "message_reconcile.go", `s.messageLock = lock`, `s.messageLock = lock
	for n:=range s.messages.Associations {s.messages.Associations[n].Pending=nil}`, "^TestMsgV27RenewalRestart$/^issued$", "--- FAIL: TestMsgV27RenewalRestart/issued", "restart cleared uncertain fence"},
			{"message-recovery-sign-capability", "message_reconcile.go", `type messageMaintenance struct {`, `type messageMaintenance struct {
	issuer *messageIssuer`, "^TestMsgV27RenewalRestart$/^no-signing-capability$", "--- FAIL: TestMsgV27RenewalRestart/no-signing-capability", "reconciliation gained signing capability"},
		}
	}
	if *group == "message-key" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"message-caller-path", "message_key.go", `if current != selected ||`, `comparison := current
	comparison.Path = selected.Path
	if comparison != selected ||`, "^TestMsgV09PurposeKeyBytes$", "--- FAIL: TestMsgV09PurposeKeyBytes", "caller-selected path admitted"},
			{"message-unhardened", "derive.go", `indices, _ := parsePath(path)
	node := deriveNode(m.seed, indices)`, `indices, _ := parsePath(path)
	indices[0] &^= 0x80000000
	node := deriveNode(m.seed, indices)`, "^TestMsgV09PurposeKeyBytes$", "--- FAIL: TestMsgV09PurposeKeyBytes", "independent purpose-4 oracle mismatch"},
			{"message-purpose-one", "message_key.go", `path := "m/4'"`, `path := "m/1'"`, "^TestMsgV09PurposeKeyBytes$", "--- FAIL: TestMsgV09PurposeKeyBytes", "independent purpose-4 oracle mismatch"},
			{"message-public-exposure", "derive.go", `func (m *Master) Public(path string) ([]byte, Code) {`, `func (m *Master) Public(path string) ([]byte, Code) {
	if strings.HasPrefix(path, "m/4'") { return m.withPurpose(path, "swarma-msg", func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k[32:]...) }) }`, "^TestMsgPurposeGuards$", "--- FAIL: TestMsgPurposeGuards", "general Public exposed another purpose"},
		}
	}
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
	if *group == "genjournal-core" || *group == "genjournal" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"generation-stale-retryable", "generation_linux.go", `case "journal_rollback", "journal_fork", "journal_writer_stale", "journal_capacity_reserve":`, `case "journal_writer_stale": return "generation_source_unavailable"
case "journal_rollback", "journal_fork", "journal_capacity_reserve":`, "^TestGenerationSourceIncidentClassification$/^journal_writer_stale$", "--- FAIL: TestGenerationSourceIncidentClassification/journal_writer_stale", "generation_source_unavailable want generation_source_fenced"},
			{"generation-skip-floor", "generation_linux.go", `g.window.WithEvidence(ctx, g.anchor.Path, g.anchor.Floor,`, `g.window.WithEvidence(ctx, g.anchor.Path, gj.Floor{Hash:gj.ZeroHash},`, "^TestGenerationAnchorContinuity$/^(rollback|fork)$", "--- FAIL: TestGenerationAnchorContinuity/rollback", "incident not fenced once"},
		}
	}

	if *group == "message-author-issuer" {
		controls = []struct{ name, file, old, new, test, needle, witness string }{
			{"mai-pending-current", "message_author_issuer.go", `r.Phase == "current" && pc == ""`, `pc == ""`, "^TestMAIssuerRenewal$", "--- FAIL: TestMAIssuerRenewal", `current gate got "" want "message_author_unqualified"`},
			{"mai-cancel-proof", "message_author_issuer.go", `a.Digest != r.CancelHash`, `false`, "^TestMAIssuerCancelRecovery$", "--- FAIL: TestMAIssuerCancelRecovery/true", "false cancellation proof accepted"},
			{"mai-cancel-after-commit", "message_author_issuer.go", `if r.Phase != "pending" {`, `if false && r.Phase != "pending" {`, "^TestMAIssuerRenewal$", "--- FAIL: TestMAIssuerRenewal", "post-commit cancellation changed evidence"},
			{"mai-unknown-audit", "message_author_issuer.go", `if a.Seq > s.auditSeq && (a.Operation == "message_author_attestation_issue" || a.Operation == "message_author_attestation_renew") {`, `if false && a.Seq > s.auditSeq && (a.Operation == "message_author_attestation_issue" || a.Operation == "message_author_attestation_renew") {`, "^TestMAIssuerCrash$/^mai-success-audit$", "--- FAIL: TestMAIssuerCrash/mai-success-audit", "unknown cancellation restored"},
			{"mai-pin-equality", "message_author_issuer_custody_linux.go", `if pin.Issuer != key {`, `if false && pin.Issuer != key {`, "^TestMAIssuerCustodyPin$/^key$", "--- FAIL: TestMAIssuerCustodyPin/key", "pin mutation key"},
			{"mai-profile-reader", "message_author_issuer.go", `if !bytes.Equal(want, got) {`, `if false && !bytes.Equal(want, got) {`, "^TestMAIssuerEnvelopeClosed$/^(roles|actions|purpose|algorithm|binding)$", "--- FAIL: TestMAIssuerEnvelopeClosed/roles", "wider signed issuer record accepted"},
			{"mai-lifetime", "message_author_issuer.go", `lifetime > 86400*time.Second`, `false`, "^TestMAIssuerProfile$", "--- FAIL: TestMAIssuerProfile", "lifetime gate"},
			{"mai-interval-lower", "message_author_issuer.go", `maLiveInterval(at, from, until)`, `(at.startBoundsValid() && at.Upper.Before(until))`, "^TestMAIssuerInterval$/^lower$", "--- FAIL: TestMAIssuerInterval/lower", "issuer interval lost bound"},
			{"mai-interval-upper", "message_author_issuer.go", `maLiveInterval(at, from, until)`, `(at.startBoundsValid() && !at.Lower.Before(from))`, "^TestMAIssuerInterval$/^upper$", "--- FAIL: TestMAIssuerInterval/upper", "issuer interval lost bound"},
			{"mai-shared-budget", "message_author_issuer.go", `if !maLiveStateRoom(before + 2*((8192+2)/3*4) + 2048 + maLiveRetireReserve) {`, `if false && !maLiveStateRoom(before + 2*((8192+2)/3*4) + 2048 + maLiveRetireReserve) {`, "^TestMAIssuerCapacity$", "--- FAIL: TestMAIssuerCapacity", "over-cap issue changed durable state"},
			{"mai-current-audit", "message_author_issuer.go", `&& s.maIssuerCommitted(r.Current) {`, `{`, "^TestMAIssuerCurrentProof$/^audit$", "--- FAIL: TestMAIssuerCurrentProof/audit", `current gate got "" want "message_author_unqualified"`},
			{"mai-current-root", "message_author_issuer.go", `&& maIssuerSignedBy(r.Current, pub)`, `&& (pub == "" || pub != "")`, "^TestMAIssuerCurrentProof$/^root$", "--- FAIL: TestMAIssuerCurrentProof/root", `current gate got "" want "message_author_unqualified"`},
			{"mai-retained-t", "message_author_live.go", `if a.Attestation != tuple.T {`, `if false && a.Attestation != tuple.T {`, "^TestMAIssuerOldTRelease$", "--- FAIL: TestMAIssuerOldTRelease", "old T not dead"},
			{"mai-tombstone-reuse", "message_author_issuer.go", `if old == nextT {`, `if false && old == nextT {`, "^TestMAIssuerTombstoneNoResurrection$", "--- FAIL: TestMAIssuerTombstoneNoResurrection", "tombstoned candidate resurrected"},
			{"mai-timestamp", "message_author_issuer.go", `messageStamp(from) == c.From && messageStamp(until) == c.Until`, `true`, "^TestMAIssuerEnvelopeClosed$/^timestamp$", "--- FAIL: TestMAIssuerEnvelopeClosed/timestamp", "wider signed issuer record accepted"},
			{"mai-expiry-proof", "message_author_issuer.go", `if e != nil || !at.startBoundsValid() || at.Lower.Before(until) {`, `if e != nil || !at.startBoundsValid() || at.Upper.Before(until) {`, "^TestMAIssuerExpiry$/^pending$", "--- FAIL: TestMAIssuerExpiry/pending", "unproven expiry changed evidence"},
			{"mai-expiry-uncertain", "message_author_issuer.go", `if s.maIssuerUnpaired() || r.Current != nil && !s.maIssuerCommitted(r.Current) {`, `if r.Current != nil && !s.maIssuerCommitted(r.Current) {`, "^TestMAIssuerExpiry$/^unknown$", "--- FAIL: TestMAIssuerExpiry/unknown", "unknown commit erased by expiry"},
			{"mai-resolve-proof", "message_author_issuer.go", `|| !s.maIssuerCommitted(r.Current) ||`, `|| false ||`, "^TestMAIssuerStateBoundaries$/^fenced$", "--- FAIL: TestMAIssuerStateBoundaries/fenced", "unknown resolution changed evidence"},
			{"mai-withdraw-fence", "message_author_live_operator_linux.go", `if r.Phase != "fenced" {`, `if true {`, "^TestMAIssuerStateBoundaries$/^fenced$", "--- FAIL: TestMAIssuerStateBoundaries/fenced", "withdraw cleared fence"},
			{"mai-production-closed", "message_author_live.go", `func (maLiveUnqualified) WithCurrent(context.Context, Binding, j7GateTime, func(maLiveTuple) Code) Code {
	return "message_author_unqualified"
}`, `func (maLiveUnqualified) WithCurrent(context.Context, Binding, j7GateTime, func(maLiveTuple) Code) Code {
	return ""
}`, "^TestMAIssuerSchemaProduction$", "--- FAIL: TestMAIssuerSchemaProduction", "production gate opened"},
		}
	}

	dependencySource := ""
	dependencyWorkspace := ""
	if *group == "genjournal" {
		out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "github.com/relux-works/swarma-user-manager/tools/genjournal").Output()
		if err != nil || !filepath.IsAbs(strings.TrimSpace(string(out))) {
			fmt.Fprintln(os.Stderr, "pinned genjournal source unavailable")
			os.Exit(2)
		}
		dependencySource = strings.TrimSpace(string(out))
		// Go refuses overlays beneath GOMODCACHE. Materialize the exact pinned
		// public module in private scratch and select it in a test-only workspace.
		// No product go.mod replace directive or dependency bytes are changed.
		moduleRoot := filepath.Dir(filepath.Dir(dependencySource))
		snapshot := filepath.Join(dir, "source-snapshot")
		if err := os.CopyFS(snapshot, os.DirFS(moduleRoot)); err != nil {
			fmt.Fprintln(os.Stderr, "source snapshot unavailable", err)
			os.Exit(2)
		}
		dependencySource = filepath.Join(snapshot, "tools", "genjournal")
		dependencyWorkspace = filepath.Join(dir, "go.work")
		body := fmt.Sprintf("go 1.26.10\nuse (\n %q\n %q\n)\n", root, snapshot)
		if err := os.WriteFile(dependencyWorkspace, []byte(body), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		baseline := exec.Command("go", "test", "-tags", "genjournal_testseam", pkg, "-run", "^TestGenerationTagged(PendingGap|Vectors)$/^(broken-chain|late-broken-chain)$", "-count=1", "-v")
		baseline.Env = append(baseline.Environ(), "GOWORK="+dependencyWorkspace)
		var baselineLog bytes.Buffer
		baseline.Stdout, baseline.Stderr = &baselineLog, &baselineLog
		err = baseline.Start()
		baselinePID := 0
		if err == nil {
			baselinePID = baseline.Process.Pid
			err = baseline.Wait()
		}
		baselineExit := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				baselineExit = e.ExitCode()
			} else {
				baselineExit = 127
			}
		}
		baselinePath := filepath.Join(dir, "source-workspace-control.log")
		if os.WriteFile(baselinePath, baselineLog.Bytes(), 0600) != nil {
			os.Exit(2)
		}
		fmt.Printf("baseline=source-workspace actual_exit=%d pid=%d log=%s\n", baselineExit, baselinePID, baselinePath)
		if baselineExit != 0 {
			os.Exit(2)
		}

		controls = append(controls, []struct{ name, file, old, new, test, needle, witness string }{
			{"generation-pending-before-lock", "@genjournal/secure_linux.go", `	if e = d.pending(); e != nil {
		unlock(gate)
		return e
	}
`, ``, "^TestGenerationTaggedPendingGap$", "--- FAIL: TestGenerationTaggedPendingGap", "pending gap admitted or active control denied"},
			{"generation-skip-chain", "@genjournal/journal.go", `if r.Prev != view.Tail.Hash {`, `if false && r.Prev != view.Tail.Hash {`, "^TestGenerationTaggedVectors$/^(broken-chain|late-broken-chain)$", "--- FAIL: TestGenerationTaggedVectors/broken-chain", "format verdict=ok want=journal_chain"},
		}...)
	}
	good := true
	selected := 0
	for _, c := range controls {
		if *only != "" && *only != c.name {
			continue
		}
		selected++
		source := filepath.Join(root, pkg, c.file)
		if strings.HasPrefix(c.file, "@genjournal/") {
			source = filepath.Join(dependencySource, strings.TrimPrefix(c.file, "@genjournal/"))
		}
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
		replacements := map[string]string{source: mutant}
		if c.name == "malive-legacy-method" {
			transport := filepath.Join(root, "internal/control/server.go")
			raw, err := os.ReadFile(transport)
			const old = `case "hello", "pubkey", "register", "revoke", "sign_registration":`
			if err != nil || strings.Count(string(raw), old) != 1 {
				fmt.Fprintln(os.Stderr, "legacy transport plant not applied")
				os.Exit(2)
			}
			file := filepath.Join(dir, c.name+"-transport.go")
			if os.WriteFile(file, []byte(strings.Replace(string(raw), old, `case "message_author_identity", "hello", "pubkey", "register", "revoke", "sign_registration":`, 1)), 0600) != nil {
				os.Exit(2)
			}
			replacements[transport] = file
		}
		mapping, _ := json.Marshal(map[string]any{"Replace": replacements})
		if os.WriteFile(overlay, mapping, 0600) != nil {
			os.Exit(2)
		}
		if *applies {
			fmt.Printf("mutant=%s applied=true matches=1 overlay=%s\n", c.name, overlay)
			continue
		}
		args := []string{"test", "-overlay", overlay}
		if *group == "message-state" {
			args = append(args, "-timeout=90s")
		}
		if *group == "genjournal" {
			args = append(args, "-tags", "genjournal_testseam")
		}
		testPackage := pkg
		if (*group == "message-author" || *group == "message-author-live") && strings.HasPrefix(c.name, "ma-wire-") {
			testPackage = "github.com/relux-works/swarma-keymaker/messageauthor"
		}
		if (*group == "message-author-live" && c.name == "malive-wire-retry") || (*group == "j7-idle" && c.name == "j7-unbound-probe-budget") {
			testPackage = "./internal/control"
		}
		args = append(args, testPackage, "-run", c.test, "-count=1", "-v")
		cmd := exec.Command("go", args...)
		if dependencyWorkspace != "" {
			cmd.Env = append(cmd.Environ(), "GOWORK="+dependencyWorkspace)
		}
		// Reproduce the fairness finding's one-processor schedule regardless
		// of the calling shell's parallelism.
		if c.name == "helper-reader-handoff" {
			cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
		}
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		pid := 0
		started := time.Now().UTC()
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
		if *group == "core" || *group == "native" || *group == "j7-delegation" || *group == "j7-delegation-r2" || *group == "j7-lifecycle-wire" || *group == "j7-idle" || *group == "message-author" || *group == "message-author-live" || *group == "j7-service" || *group == "message-author-issuer" {
			// Bind every new bounded plant's real child command and output to its own
			// receipt; an applied setup/compile failure still cannot count as a kill.
			receipt, err := json.MarshalIndent(map[string]any{
				"argv": cmd.Args, "executable": cmd.Path, "cwd": root, "pid": pid,
				"start": started.Format(time.RFC3339Nano), "end": time.Now().UTC().Format(time.RFC3339Nano),
				"actual_exit": status, "applied": true, "killed": killed, "test": c.test,
				"witness": c.witness, "log": log, "output_sha256": fmt.Sprintf("%x", sha256.Sum256(out)),
				"plant_sha256":   fmt.Sprintf("%x", sha256.Sum256([]byte(plant(c.name, string(raw), c.old, c.new)))),
				"overlay_sha256": fmt.Sprintf("%x", sha256.Sum256(mapping)),
			}, "", "  ")
			if err != nil || os.WriteFile(filepath.Join(dir, c.name+".receipt.json"), append(receipt, '\n'), 0600) != nil {
				fmt.Fprintln(os.Stderr, c.name, "receipt unavailable")
				os.Exit(2)
			}
		}

		fmt.Printf("mutant=%s test=%s actual_exit=%d killed=%t pid=%d log=%s\n", c.name, c.test, status, killed, pid, log)
		if !killed {
			fmt.Fprintln(os.Stderr, string(out))
			good = false
		}
	}
	if selected == 0 {
		fmt.Fprintln(os.Stderr, "no matching plant")
		os.Exit(2)
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
	if name == "malive-existing-fence" || name == "malive-conflict-first" {
		target, replacement := "if s.failed || s.maLive == nil || s.maLive.Fenced {", "if s.failed || s.maLive == nil {"
		if name == "malive-conflict-first" {
			target = "if a.Method != string(r.Method) || !bytes.Equal(a.Preimage, r.Preimage) {"
			replacement = "if false && (a.Method != string(r.Method) || !bytes.Equal(a.Preimage, r.Preimage)) {"
		}
		if strings.Count(mutant, target) != 1 {
			fmt.Fprintln(os.Stderr, "paired gate plant not applied")
			os.Exit(2)
		}
		mutant = strings.Replace(mutant, target, replacement, 1)
	}

	if name == "j7-static-pin-key-order" {
		const beforePin = "\tdigestFile, err := g.read(in.Files.DigestFile, 65)"
		if strings.Count(mutant, beforePin) != 1 {
			fmt.Fprintln(os.Stderr, "PIN/KEY order plant not applied")
			os.Exit(2)
		}
		mutant = strings.Replace(mutant, beforePin, old+beforePin, 1)
	}
	if name == "j7-service-key-before-lock" || name == "j7-service-listener-before-state" {
		const beforeState = "\tstate, e := OpenDirectory(cfg.J7State.Path, uid, 0700)"
		if strings.Count(mutant, beforeState) != 1 {
			fmt.Fprintln(os.Stderr, "startup order plant not applied")
			os.Exit(2)
		}
		block := old
		if name == "j7-service-listener-before-state" {
			// The deliberately early listener precedes adapter construction;
			// call the same listener seam without its later publication wrapper.
			block = block[strings.Index(block, "	socket, e := openJ7Socket"):]
			block = strings.Replace(block, ", publish)", ", d.listen)", 1)
		}
		mutant = strings.Replace(mutant, beforeState, block+beforeState, 1)
	}
	if name == "message-caller-path" {
		old := `strings.TrimPrefix(current.Path, "m/1'")`
		if strings.Count(mutant, old) != 1 {
			fmt.Fprintln(os.Stderr, "caller path source plant not applied")
			os.Exit(2)
		}
		mutant = strings.Replace(mutant, old, `strings.TrimPrefix(selected.Path, "m/1'")`, 1)
	}
	if name == "message-purpose-one" {
		old := `a.master.withPurpose(path, "swarma-msg", use)`
		if strings.Count(mutant, old) != 1 {
			fmt.Fprintln(os.Stderr, "purpose-one guard plant not applied")
			os.Exit(2)
		}
		mutant = strings.Replace(mutant, old, `a.master.withPurpose(path, "agent-identity", use)`, 1)
	}
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
