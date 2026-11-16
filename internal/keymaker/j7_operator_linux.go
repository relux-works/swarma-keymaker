//go:build linux

package keymaker

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// The stopped-operator commands for the request role. They are local command
// boundaries, never socket methods, daemon startup actions or agent APIs. Each
// runs as the service user, holds the exclusive state lock for its whole
// duration (so it cannot overlap a running service), takes only explicit
// absolute paths and reports a closed result without secret material.
const (
	J7OperatorSeedInit      = "j7 seed-init"
	J7OperatorMigrate       = "j7 migrate"
	J7OperatorPolicyPublish = "j7 policy-publish"
	J7OperatorHead          = "j7 head"
)

// J7OperatorRequest carries one command's explicit operator inputs. Unused
// members of a command must stay zero; nothing is defaulted from the host.
type J7OperatorRequest struct {
	Command    string
	ServiceUID uint32
	StateDir   string
	// Schema is the schema the operator asserts the store has now: the source
	// schema for migrate (0, 2 or 4) and the reader schema otherwise.
	Schema int
	// Expected is the independently retained head. It is required by migrate
	// and policy-publish and is an optional verification for head.
	Expected        bool
	ExpectedVersion uint64
	ExpectedDigest  string

	KeyFile           string // seed-init
	Instance          string // seed-init, migrate, policy-publish
	Identity          uint64 // migrate, policy-publish
	GenerationJournal string // migrate: the journal path the carried anchor must name
	PolicyFile        string // policy-publish: the table the service reads
	PolicyInput       string // policy-publish: the closed policy file to publish
}

// J7OperatorResult is the closed result. Every member is always present. The
// head members describe the store after the command whenever it was opened;
// they are zero for seed-init and for refusals before the store was read.
type J7OperatorResult struct {
	Command string `json:"command"`
	Outcome string `json:"outcome"` // "ok" or "refused"
	Refusal string `json:"refusal"` // empty on "ok"
	Detail  string `json:"detail"`  // fixed diagnostic text, never input or state bytes
	Schema  int    `json:"state_schema"`
	Version uint64 `json:"head_version"`
	Digest  string `json:"head_digest"`
}

// The seam is private: no command argument selects an identity or clock source.
// Stopped-operator commits use no time source (see j7OperatorProduction).
type j7OperatorDeps struct {
	clock    AuditClock
	identity func() (uint32, uint32) // real and effective UID, for executable identity refusals
}

// A command argument must not select a time source, so operator commits are
// recorded with a null time and the `unknown` result that replay accepts.
func j7OperatorProduction() j7OperatorDeps {
	return j7OperatorDeps{clock: systemAuditClock{}, identity: func() (uint32, uint32) { return uint32(os.Getuid()), uint32(os.Geteuid()) }}
}

// RunJ7Operator executes one stopped-operator command.
func RunJ7Operator(ctx context.Context, req J7OperatorRequest) J7OperatorResult {
	return runJ7Operator(ctx, req, j7OperatorProduction())
}

type j7OperatorRefusal struct {
	code   Code
	detail string
}

func j7Refuse(code Code, detail string) *j7OperatorRefusal {
	return &j7OperatorRefusal{code, detail}
}

// Only fixed package texts and payload-free codes become a detail. Any other
// error (for example an errno) collapses to one constant.
func j7OperatorDetail(err error) string {
	if err != nil {
		// An allowlist prevents a future error containing a path or state payload
		// from becoming a diagnostic. Codes outside this set also stay opaque.
		switch err.Error() {
		case "keymaker: state already locked", "keymaker: unsafe directory ownership or mode",
			"keymaker: message schema floor mismatch", "keymaker: J7 expected head mismatch",
			"keymaker: unresolved binding intent", "keymaker: J7 policy pins unavailable",
			"keymaker: unsafe policy holder", "keymaker: unknown signing handoff":
			return strings.TrimPrefix(err.Error(), "keymaker: ")
		}
	}
	return "unavailable"
}

func j7OperatorPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func j7OperatorArguments(req J7OperatorRequest) *j7OperatorRefusal {
	bad := func(detail string) *j7OperatorRefusal { return j7Refuse("request_malformed", detail) }
	if !j7OperatorPath(req.StateDir) {
		return bad("path must be absolute and clean")
	}
	paths := map[string]bool{}
	schemas := map[int]bool{}
	expected, pins := false, false
	switch req.Command {
	case J7OperatorSeedInit:
		paths[req.KeyFile] = true
		if !validJ7Instance(req.Instance) || req.Identity != 0 || req.Schema != 0 || req.Expected {
			return bad("invalid seed arguments")
		}
		if req.GenerationJournal != "" || req.PolicyFile != "" || req.PolicyInput != "" {
			return bad("unexpected argument")
		}
	case J7OperatorMigrate:
		paths[req.GenerationJournal] = true
		schemas, expected, pins = map[int]bool{0: true, 2: true, j7Schema: true}, true, true
		if req.KeyFile != "" || req.PolicyFile != "" || req.PolicyInput != "" {
			return bad("unexpected argument")
		}
	case J7OperatorPolicyPublish:
		paths[req.PolicyFile], paths[req.PolicyInput] = true, true
		schemas, expected, pins = map[int]bool{j7Schema: true, j7SigningSchema: true}, true, true
		if req.PolicyFile == req.PolicyInput || req.KeyFile != "" || req.GenerationJournal != "" {
			return bad("unexpected argument")
		}
	case J7OperatorHead:
		schemas = map[int]bool{0: true, 2: true, j7Schema: true, j7SigningSchema: true}
		if req.KeyFile != "" || req.Instance != "" || req.Identity != 0 || req.GenerationJournal != "" || req.PolicyFile != "" || req.PolicyInput != "" {
			return bad("unexpected argument")
		}
	default:
		return bad("unknown command")
	}
	for path := range paths {
		if !j7OperatorPath(path) {
			return bad("path must be absolute and clean")
		}
		// Key, policy and input files never live inside the state directory.
		if (path == req.StateDir || strings.HasPrefix(path, req.StateDir+string(filepath.Separator))) && req.Command != J7OperatorMigrate {
			return bad("path must be outside the state directory")
		}
	}
	if req.Command != J7OperatorSeedInit && !schemas[req.Schema] {
		return bad("unsupported schema")
	}
	if expected && !req.Expected {
		return bad("expected head required")
	}
	if req.Expected && (req.ExpectedVersion == 0 || req.ExpectedVersion > j7SafeInteger || !validDigest(req.ExpectedDigest)) {
		return bad("invalid expected head")
	}
	if !req.Expected && (req.ExpectedVersion != 0 || req.ExpectedDigest != "") {
		return bad("invalid expected head")
	}
	if pins && (!validJ7Instance(req.Instance) || req.Identity == 0 || req.Identity > j7SafeInteger) {
		return bad("invalid instance or identity")
	}
	return nil
}

func runJ7Operator(ctx context.Context, req J7OperatorRequest, deps j7OperatorDeps) J7OperatorResult {
	result := J7OperatorResult{Outcome: "refused"}
	switch req.Command {
	case J7OperatorSeedInit, J7OperatorMigrate, J7OperatorPolicyPublish, J7OperatorHead:
		result.Command = req.Command
	}
	refusal := j7OperatorRun(ctx, req, deps, &result)
	if refusal == nil {
		result.Outcome = "ok"
		return result
	}
	result.Refusal, result.Detail = string(refusal.code), refusal.detail
	return result
}

func j7OperatorRun(ctx context.Context, req J7OperatorRequest, deps j7OperatorDeps, result *J7OperatorResult) *j7OperatorRefusal {
	// Arguments are judged before any path is touched.
	if r := j7OperatorArguments(req); r != nil {
		return r
	}
	// Only the unprivileged service user operates its own custody. Root is
	// refused too: it would create root-owned evidence the service cannot open.
	identity := deps.identity
	if identity == nil {
		identity = j7OperatorProduction().identity
	}
	ruid, euid := identity()
	if euid == 0 || ruid != euid || euid != req.ServiceUID {
		return j7Refuse("role_not_permitted", "command runs only as the service user")
	}
	uid := req.ServiceUID
	if err := safeAncestors(req.StateDir, uid); err != nil {
		return j7Refuse("state_unavailable", j7OperatorDetail(err))
	}
	state, err := OpenDirectory(req.StateDir, uid, 0700)
	if err != nil {
		return j7Refuse("state_unavailable", j7OperatorDetail(err))
	}
	defer state.Close()
	// The same exclusive lock the service holds for its Store lifetime. It is
	// taken before any other effect and released only when the command returns.
	lock, err := LockState(state, uid)
	if err != nil {
		if j7OperatorDetail(err) == "state already locked" {
			return j7Refuse("state_locked", "state already locked")
		}
		return j7Refuse("state_unavailable", j7OperatorDetail(err))
	}
	defer lock.Close()
	switch req.Command {
	case J7OperatorSeedInit:
		return j7OperatorSeed(req, uid)
	case J7OperatorMigrate:
		return j7OperatorMigrateState(ctx, req, deps, state, uid, result)
	case J7OperatorPolicyPublish:
		return j7OperatorPublish(ctx, req, deps, state, uid, result)
	}
	return j7OperatorExport(req, deps, state, uid, result)
}

func j7OperatorSeed(req J7OperatorRequest, uid uint32) *j7OperatorRefusal {
	if err := safeAncestors(filepath.Dir(req.KeyFile), uid); err != nil {
		return j7Refuse("j7_key_unavailable", j7OperatorDetail(err))
	}
	// This names the common refusal; the initializer's no-replace publication
	// below remains the authority that nothing is overwritten.
	var st unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, req.KeyFile, &st, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		if err == nil {
			return j7Refuse("j7_seed_exists", "existing seed is never replaced")
		}
		return j7Refuse("j7_key_unavailable", "unavailable")
	}
	if InitializeJ7Seed(req.KeyFile, uid, j7RequestRole, req.Instance) != nil {
		return j7Refuse("j7_key_unavailable", "key custody unavailable")
	}
	return nil
}

func (r J7OperatorRequest) expectation() []j7Expectation {
	if !r.Expected {
		return nil
	}
	return []j7Expectation{{Version: r.ExpectedVersion, Digest: r.ExpectedDigest}}
}

// An empty directory at reader 0 would otherwise be first-use initialization.
// No operator command initializes binding state.
func j7OperatorOpen(req J7OperatorRequest, deps j7OperatorDeps, state *os.File, uid uint32) (*Store, *j7OperatorRefusal) {
	var st unix.Stat_t
	if unix.Fstatat(int(state.Fd()), "bindings.json", &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, j7Refuse("j7_state_fenced", "binding snapshot unavailable")
	}
	s, _, _, err := openCustodyStateMessageMode(state, uid, deps.clock, req.Schema, false, true, req.expectation()...)
	if err != nil {
		return nil, j7Refuse("j7_state_fenced", j7OperatorDetail(err))
	}
	if s.initialized || s.schema != req.Schema {
		s.Close()
		return nil, j7Refuse("j7_state_fenced", "message schema floor mismatch")
	}
	return s, nil
}

func (s *Store) j7OperatorHead(result *J7OperatorResult) (j7Expectation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A head that cannot be proved against the journal, or that no opener would
	// accept (a retained pending publication), is never reported.
	result.Schema, result.Version, result.Digest = 0, 0, ""
	digest, err := s.contentDigest(s.version)
	if err != nil || s.version == 0 || s.version > j7SafeInteger || !s.matchesCommit(s.journal.binding) || s.j7 != nil && s.j7.Pending || s.j7UnknownHandoff() {
		return j7Expectation{}, false
	}
	result.Schema, result.Version, result.Digest = s.schema, s.version, digest
	return j7Expectation{Version: s.version, Digest: digest}, true
}

func j7OperatorExport(req J7OperatorRequest, deps j7OperatorDeps, state *os.File, uid uint32, result *J7OperatorResult) *j7OperatorRefusal {
	s, refusal := j7OperatorOpen(req, deps, state, uid)
	if refusal != nil {
		return refusal
	}
	defer s.Close()
	if _, ok := s.j7OperatorHead(result); !ok {
		return j7Refuse("j7_state_fenced", "head unavailable")
	}
	return nil
}

func j7OperatorMigrateState(ctx context.Context, req J7OperatorRequest, deps j7OperatorDeps, state *os.File, uid uint32, result *J7OperatorResult) *j7OperatorRefusal {
	s, refusal := j7OperatorOpen(req, deps, state, uid)
	if refusal != nil {
		return refusal
	}
	closed := false
	defer func() {
		if !closed {
			s.Close()
		}
	}()
	if _, ok := s.j7OperatorHead(result); !ok {
		return j7Refuse("j7_state_fenced", "head unavailable")
	}
	// The anchor is carried in place: the state directory and its audit journal
	// already hold both sides of it. A store that lacks a consistent anchor for
	// the named journal would start fenced, so it is refused before migration.
	if _, fenced := loadGenerationAnchor(s, req.GenerationJournal, gj.Floor{}); fenced {
		return j7Refuse("generation_source_fenced", "generation anchor unavailable")
	}
	// The first transition is judged against the operator's own expectation,
	// not a head read back from this store. Only the intermediate schema-4
	// head, created by this command under the lock, is computed in process.
	head := j7Expectation{Version: req.ExpectedVersion, Digest: req.ExpectedDigest}
	if req.Schema != j7Schema {
		if c := s.migrateJ7(ctx, head, req.Instance, req.Identity); c != "" {
			return j7Refuse(c, "migration to schema 4 refused")
		}
		var ok bool
		if head, ok = s.j7OperatorHead(result); !ok {
			return j7Refuse("j7_state_fenced", "head unavailable")
		}
	} else {
		if s.j7 == nil || s.j7.Instance != req.Instance || s.j7.Identity != req.Identity {
			return j7Refuse("j7_state_fenced", "J7 pins mismatch")
		}
		// A resumed schema-4 migration still needs the active station binding;
		// its historic J7 identity pin alone does not authorize provisioning.
		active := false
		for _, binding := range s.records {
			if binding.Number == req.Identity && binding.Status == "active" {
				active = true
			}
		}
		if !active {
			return j7Refuse("binding_not_found", "active station binding required")
		}
	}
	if c := s.migrateJ7Signing(ctx, head); c != "" {
		return j7Refuse(c, "migration to schema 5 refused")
	}
	head, ok := s.j7OperatorHead(result)
	if !ok {
		return j7Refuse("j7_state_fenced", "head unavailable")
	}
	// Prove the result with the opener the service uses, and that the anchor
	// survived unchanged, before reporting the head the operator will retain.
	closed = true
	if s.Close() != nil {
		return j7Refuse("j7_state_fenced", "state close failed")
	}
	check, err := openJ7SigningStore(state, uid, deps.clock, head)
	if err != nil {
		return j7Refuse("j7_state_fenced", j7OperatorDetail(err))
	}
	defer check.Close()
	if _, fenced := loadGenerationAnchor(check, req.GenerationJournal, gj.Floor{}); fenced {
		return j7Refuse("generation_source_fenced", "generation anchor unavailable")
	}
	return nil
}

// The input is read once, bounded, without following a final symlink. Its
// closed grammar is judged by the publication itself.
func j7OperatorInput(path string, uid uint32) ([]byte, bool) {
	if safeAncestors(filepath.Dir(path), uid) != nil {
		return nil, false
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	f := os.NewFile(uintptr(fd), "policy input")
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || (st.Uid != 0 && st.Uid != uid) || st.Mode&022 != 0 || st.Nlink != 1 || !j7NoACL(fd, false) {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, j7PolicyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > j7PolicyBytes {
		return nil, false
	}
	return raw, true
}

func j7OperatorPublish(ctx context.Context, req J7OperatorRequest, deps j7OperatorDeps, state *os.File, uid uint32, result *J7OperatorResult) *j7OperatorRefusal {
	raw, ok := j7OperatorInput(req.PolicyInput, uid)
	if !ok {
		return j7Refuse("request_malformed", "policy input unavailable")
	}
	// Judge the closed file before the store is opened; publish repeats this.
	if _, err := decodeJ7Policy(raw, req.Instance, req.Identity); err != nil {
		return j7Refuse("request_malformed", "invalid policy file")
	}
	s, refusal := j7OperatorOpen(req, deps, state, uid)
	if refusal != nil {
		return refusal
	}
	defer s.Close()
	if req.Schema == j7SigningSchema && s.j7UnknownHandoff() {
		return j7Refuse("j7_state_fenced", "unknown signing handoff")
	}
	if _, ok := s.j7OperatorHead(result); !ok {
		return j7Refuse("j7_state_fenced", "head unavailable")
	}
	policy, err := newJ7Policy(req.PolicyFile, uid, s, req.Instance, req.Identity)
	if err != nil {
		return j7Refuse("j7_policy_unavailable", j7OperatorDetail(err))
	}
	defer policy.close()
	code := policy.publish(ctx, raw)
	// Report the head as it now is, including after an interrupted publication.
	if _, ok := s.j7OperatorHead(result); !ok && code == "" {
		return j7Refuse("j7_state_fenced", "head unavailable")
	}
	if code != "" {
		return j7Refuse(code, "publication refused")
	}
	return nil
}
