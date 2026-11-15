package keymaker

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"syscall"
)

const j7Schema = 4 // Reader 3 belongs to the separate authority-root format.
const j7HistoryLimit = 65536
const j7SafeInteger = uint64(9007199254740991)

type j7Origin struct {
	Kind    string `json:"kind"`
	Event   string `json:"event_id"`
	Grant   string `json:"grant_id"`
	Tip     string `json:"tip_hash"`
	Mode    string `json:"mode"`
	Command string `json:"command_id"`
}
type j7OriginKey struct {
	Kind  string `json:"kind"`
	Event string `json:"event_id"`
	Grant string `json:"grant_id"`
}

func (o j7Origin) key() j7OriginKey { return j7OriginKey{o.Kind, o.Event, o.Grant} }
func (o j7Origin) valid() bool {
	if o.Kind == "owner_command" {
		return validDigest(o.Command) && o.Event == "" && o.Grant == "" && o.Tip == "" && o.Mode == ""
	}
	return o.Kind == "admission" && validDigest(o.Event) && validDigest(o.Grant) && validDigest(o.Tip) && o.Mode == "enforcing" && o.Command == ""
}
func (o j7OriginKey) valid() bool {
	return o.Kind == "owner_command" && o.Event == "" && o.Grant == "" || o.Kind == "admission" && validDigest(o.Event) && validDigest(o.Grant)
}

type j7Run struct {
	ID       string    `json:"id"`
	Binding  Binding   `json:"binding"`
	Origin   j7Origin  `json:"origin"`
	Launcher Principal `json:"launcher"`
	Input    Principal `json:"input"`
	Parent   string    `json:"parent"`
	State    string    `json:"state"`
}
type j7Denial struct {
	Origin  j7OriginKey `json:"origin"`
	Grant   string      `json:"grant_id"`
	Version uint64      `json:"version"`
}
type j7Inventory struct {
	Format     string         `json:"format"`
	BaseSchema int            `json:"base_schema"`
	Instance   string         `json:"instance"`
	Identity   uint64         `json:"identity_registration_number"`
	Version    uint64         `json:"policy_version"`
	Digest     string         `json:"policy_digest"`
	Policy     *j7PolicyTable `json:"policy"`
	Pending    bool           `json:"publication_pending"`
	Runs       []j7Run        `json:"runs"`
	Denials    []j7Denial     `json:"denials"`
}

func (j *j7Inventory) UnmarshalJSON(raw []byte) error {
	if e := messageRequired(raw, reflect.TypeFor[j7Inventory]()); e != nil {
		return e
	}
	type plain j7Inventory
	return StrictJSON(bytes.NewReader(raw), (*plain)(j))
}
func cloneJ7(j *j7Inventory) *j7Inventory {
	if j == nil {
		return nil
	}
	c := *j
	c.Runs = append([]j7Run{}, j.Runs...)
	c.Denials = append([]j7Denial{}, j.Denials...)
	return &c
}
func (s *Store) validateJ7() error {
	j := s.j7
	if s.schema != j7Schema || j == nil || j.Format != "keymaker-j7-state/1" || (j.BaseSchema != 0 && j.BaseSchema != 2) || !validJ7Instance(j.Instance) || j.Identity == 0 || j.Version > j7SafeInteger || j.Pending || len(j.Runs) > j7HistoryLimit || len(j.Denials) > j7HistoryLimit {
		return failure("invalid J7 state")
	}
	if (j.BaseSchema == 2) != (s.messages != nil) {
		return failure("lost message participant")
	}
	identity := false
	for _, b := range s.records {
		if b.Number == j.Identity {
			identity = true
		}
	}
	if !identity {
		return failure("missing J7 identity")
	}
	if j.Version == 0 {
		if j.Digest != "" || j.Policy != nil || len(j.Denials) != 0 || len(j.Runs) != 0 {
			return failure("missing policy floor")
		}
	} else if !validDigest(j.Digest) || j.Policy == nil || j.Policy.Version != j.Version || validateJ7Policy(j.Policy, j.Instance, j.Identity) != nil {
		return failure("invalid policy continuity")
	}
	runs := map[string]j7Run{}
	inputs := map[uint32]bool{}
	for _, r := range j.Runs {
		if !messageID(r.ID) || runs[r.ID].ID != "" || r.Binding.Number != j.Identity || !r.Origin.valid() || !validGeneration(r.Launcher.Generation) || !validGeneration(r.Input.Generation) || r.Input.UID == r.Launcher.UID || r.Input.UID == r.Binding.UID || r.State != "live" && r.State != "ended" {
			return failure("invalid retained run")
		}
		found := false
		for _, b := range s.records {
			b.Status = r.Binding.Status
			if b == r.Binding {
				found = true
			}
		}
		if !found {
			return failure("foreign run binding")
		}
		if r.Parent != "" {
			parent, ok := runs[r.Parent]
			if !ok || parent.Origin != r.Origin {
				return failure("changed run origin")
			}
		}
		if r.State == "live" && inputs[r.Input.UID] {
			return failure("ambiguous run input")
		}
		if r.State == "live" {
			inputs[r.Input.UID] = true
		}
		runs[r.ID] = r
	}
	denials := map[struct {
		Origin j7OriginKey
		Grant  string
	}]bool{}
	for _, d := range j.Denials {
		key := struct {
			Origin j7OriginKey
			Grant  string
		}{d.Origin, d.Grant}
		if !d.Origin.valid() || !validDigest(d.Grant) || d.Version == 0 || d.Version > j.Version || denials[key] {
			return failure("invalid retained denial")
		}
		denials[key] = true
	}
	return nil
}

// An independently retained expectation is supplied by the stopped operator,
// never inferred from missing local files. It detects rollback only relative to
// that independent copy; joint loss of all copies cannot be detected locally.
type j7Expectation struct {
	Version uint64
	Digest  string
}

func (s *Store) j7HeadMatches(e j7Expectation) bool {
	d, err := s.contentDigest(s.version)
	return err == nil && e.Version == s.version && validDigest(e.Digest) && d == e.Digest && s.matchesCommit(s.journal.binding)
}

// The caller holds LockState(dir) for the entire Store lifetime, as for
// OpenStore. A pathname or a locally computed head is not that exclusion.
func openJ7Store(dir *os.File, uid uint32, clock AuditClock, expected j7Expectation) (*Store, error) {
	s, _, _, err := openCustodyStateMessage(dir, uid, clock, j7Schema, false, expected)
	if err != nil {
		return nil, err
	}
	if !s.j7HeadMatches(expected) {
		s.Close()
		return nil, failure("J7 expected head mismatch")
	}
	return s, nil
}

// migrateJ7 is an explicit stopped-operator action on a reconciled paired store.
// It preserves prior participant bytes and requires a previously retained head.
// No wire method, restart path or missing-file branch calls it.
func (s *Store) migrateJ7(ctx context.Context, expected j7Expectation, instance string, identity uint64) Code {
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.failed || s.dir == nil || s.journal == nil || s.j7 != nil || (s.schema != 0 && s.schema != 2) || !validJ7Instance(instance) || !s.j7HeadMatches(expected) {
		return "j7_state_fenced"
	}
	found := false
	for _, b := range s.records {
		if b.Number == identity && b.Status == "active" {
			found = true
		}
	}
	if !found {
		return "binding_not_found"
	}
	j := &j7Inventory{Format: "keymaker-j7-state/1", BaseSchema: s.schema, Instance: instance, Identity: identity, Runs: []j7Run{}, Denials: []j7Denial{}}
	s.schema, s.j7 = j7Schema, j
	return s.commitJ7(ctx)
}
func (s *Store) j7Point(point string) Code {
	if s.j7Fault != nil {
		return s.j7Fault(point)
	}
	return ""
}
func (s *Store) commitJ7(ctx context.Context) Code {
	if s.failed || s.schema != j7Schema || s.j7 == nil {
		return "j7_state_fenced"
	}
	code := s.persistContext(ctx)
	if code != "" {
		s.failed = true
		if code == "audit_unavailable" || s.j7AuditFailed() {
			return "audit_unavailable"
		}
		return "j7_state_fenced"
	}
	return ""
}

func (s *Store) j7AuditFailed() bool {
	if s.journal == nil {
		return true
	}
	s.journal.mu.Lock()
	defer s.journal.mu.Unlock()
	return s.journal.failed
}

// Reserve audit capacity before either participant's recovery-file effects.
func (s *Store) persistJ7ParticipantContext(ctx context.Context) Code {
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	if s.journal == nil {
		return "audit_unavailable"
	}
	ctx, release, code := s.journal.reserveMessageAudit(ctx)
	if code != "" {
		return code
	}
	defer release()
	if s.messages != nil {
		return s.persistMessagesContext(ctx)
	}
	return s.persistJ7Context(ctx)
}
func (s *Store) j7SnapshotFailure(code Code) Code {
	if s.schema == j7Schema && code == "audit_unavailable" {
		return "j7_state_fenced"
	}
	return code
}

// Schema4 without a message participant retains the historical journal-first
// ordering. Space for the installed and staged snapshots is reserved before
// journal effects. Any uncertain phase poisons the Store, including deadlines.
func (s *Store) persistJ7Context(ctx context.Context) Code {
	if s.dir == nil || s.journal == nil || s.version >= j7SafeInteger {
		return "audit_unavailable"
	}
	version := s.version + 1
	bound, err := canonical(s.disk(version, bindingCommit{Seq: j7SafeInteger, Hash: string(bytes.Repeat([]byte("0"), 64))}))
	if err != nil || len(bound) > stateBudget/3 || len(s.j7.Runs) > j7HistoryLimit || len(s.j7.Denials) > j7HistoryLimit {
		return "state_capacity_exceeded"
	}
	installed, err := openRelative(s.dir, "bindings.json", syscall.O_RDONLY, s.uid, 0600)
	if err != nil {
		return "j7_state_fenced"
	}
	st, err := installed.Stat()
	closeErr := installed.Close()
	if err != nil || closeErr != nil || st.Size()+2*int64(len(bound)) > stateBudget {
		return "state_capacity_exceeded"
	}
	if c := s.j7Point("prepare"); c != "" {
		return c
	}
	digest, err := s.contentDigest(version)
	if err != nil {
		return "state_capacity_exceeded"
	}
	if code := s.j7Point("before-journal"); code != "" {
		return code
	}
	commit, code := s.journal.commitBindingContext(ctx, version, digest)
	if code != "" {
		return code
	}
	if code = s.j7Point("after-journal"); code != "" {
		return code
	}
	raw, err := canonical(s.disk(version, commit))
	if err != nil || len(raw) > len(bound) {
		return "audit_unavailable"
	}
	f, err := openRelative(s.dir, "bindings.next", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, s.uid, 0600)
	if err != nil {
		return "j7_state_fenced"
	}
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = failure("short snapshot")
	}
	if err == nil {
		if c := s.j7Point("snapshot-write"); c != "" {
			err = c
		}
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		if c := s.j7Point("snapshot-sync"); c != "" {
			err = c
		}
	}
	closeErr = f.Close()
	if err != nil || closeErr != nil {
		return "j7_state_fenced"
	}
	if syscall.Renameat(int(s.dir.Fd()), "bindings.next", int(s.dir.Fd()), "bindings.json") != nil {
		return "j7_state_fenced"
	}
	if c := s.j7Point("snapshot-rename"); c != "" {
		return c
	}
	if s.dir.Sync() != nil {
		return "j7_state_fenced"
	}
	if c := s.j7Point("snapshot-directory-sync"); c != "" {
		return c
	}
	s.version, s.auditSeq, s.auditHash = version, commit.Seq, commit.Hash
	return ""
}
