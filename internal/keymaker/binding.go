package keymaker

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"syscall"
)

type Generation struct {
	UID        uint32
	Generation string
	State      string
	Revision   string
	Provenance string
	Verified   bool
	Fenced     bool
}
type GenerationSource interface {
	Lookup(context.Context, uint32) (Generation, Code)
	// WithActive must not invoke the callback unless current authoritative evidence
	// is active; its callback/release is ordered against retirement.
	WithActive(context.Context, uint32, string, func() Code) Code
	Watch(uint32, string) (<-chan struct{}, func())
}

// Generation tokens are opaque; their encoding belongs to the user-manager journal.
func validGeneration(s string) bool { return s != "" }

type Principal struct {
	UID        uint32 `json:"uid"`
	Generation string `json:"generation"`
}
type Binding struct {
	UID              uint32    `json:"uid"`
	Generation       string    `json:"generation"`
	Path             string    `json:"path"`
	Owner            string    `json:"owner"`
	Number           uint64    `json:"registration_number"`
	Lifetime         string    `json:"lifetime"`
	Registrar        Principal `json:"registrar_principal"`
	Status           string    `json:"status"`
	Epoch            string    `json:"master_epoch"`
	RegistryRevision string    `json:"registry_revision"`
}
type bindingDisk struct {
	Next    uint64    `json:"next_registration_number"`
	Records []Binding `json:"records"`
}
type Store struct {
	mu          sync.Mutex
	records     []Binding
	next        uint64
	dir         *os.File
	uid         uint32
	watchers    map[uint64][]chan struct{}
	failed      bool
	initialized bool // This call durably bootstrapped a provably empty directory.
}

// NewStore is an in-process store; durable deployments use OpenStore. No caller
// credential is accepted on a wire through these trusted lifecycle methods.
func NewStore() *Store { return &Store{next: 1, watchers: map[uint64][]chan struct{}{}} }
func OpenStore(dir *os.File, uid uint32) (*Store, error) {
	s := NewStore()
	fd, pending := syscall.Openat(int(dir.Fd()), "bindings.next", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if pending != syscall.ENOENT {
		if pending == nil {
			syscall.Close(fd)
		}
		return nil, failure("unresolved binding intent")
	}
	s.dir = dir
	s.uid = uid
	f, e := openRelative(dir, "bindings.json", syscall.O_RDONLY, uid, 0600)
	if e != nil { // Absence is the sole permissible new-store case.
		var st syscall.Stat_t
		// Openat distinguishes ENOENT from corrupt/unsafe evidence without following links.
		fd, err := syscall.Openat(int(dir.Fd()), "bindings.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if err != syscall.ENOENT {
			if err == nil {
				syscall.Fstat(fd, &st)
				syscall.Close(fd)
			}
			return nil, failure("binding store unavailable")
		}
		// Absence alone is not first use: any retained entry (including audit or
		// an old lock file) is evidence requiring operator recovery. Enumerate an
		// independent directory fd so retries cannot inherit an exhausted cursor.
		fd, err = syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, failure("binding evidence unavailable")
		}
		listing := os.NewFile(uintptr(fd), "state")
		entries, err := listing.ReadDir(1)
		listing.Close()
		if len(entries) != 0 || err != io.EOF {
			return nil, failure("missing binding snapshot with retained evidence")
		}
		// Persist even the empty snapshot before any journal/lock artifact is
		// created. A crash from here on requires recovery, never empty admission.
		if c := s.persist(); c != "" {
			return nil, c
		}
		s.initialized = true
		return s, nil
	}
	defer f.Close()
	var disk bindingDisk
	if StrictJSON(f, &disk) != nil {
		return nil, failure("invalid binding journal")
	}
	s.records = disk.Records
	s.next = disk.Next
	if c := s.validate(); c != "" {
		return nil, c
	}
	return s, nil
}
func (s *Store) validate() Code {
	if s.next == 0 || s.next > 9007199254740991 {
		return "binding_conflict"
	}
	nums := map[uint64]bool{}
	active := map[Principal]bool{}
	paths := map[string]Binding{}
	var previousNumber uint64
	for _, b := range s.records {
		if b.Number <= previousNumber || b.Number >= s.next || nums[b.Number] || !validGeneration(b.Generation) || !validGeneration(b.Registrar.Generation) || b.Owner == "" || b.Epoch == "" || b.RegistryRevision == "" || ValidatePath(b.Path, "agent-identity") != "" || (b.Lifetime != "ephemeral" && b.Lifetime != "persistent") || (b.Status != "active" && b.Status != "unbound" && b.Status != "revoked") {
			return "binding_conflict"
		}
		nums[b.Number] = true
		previousNumber = b.Number
		p := Principal{b.UID, b.Generation}
		key := b.Epoch + ":" + b.Path
		if b.Status == "active" {
			if active[p] {
				return "binding_conflict"
			}
			active[p] = true
		}
		if old, ok := paths[key]; ok {
			// A later registration is legal only after the preceding persistent
			// binding was unbound. Checking every edge means no active or revoked
			// predecessor can be concealed by an intervening historical record.
			if old.Status != "unbound" || old.Lifetime != "persistent" || old.Owner != b.Owner || old.Lifetime != b.Lifetime {
				return "binding_conflict"
			}
		}
		paths[key] = b
	}
	return ""
}
func (s *Store) persist() Code {
	if s.dir == nil {
		return ""
	}
	b, e := json.Marshal(bindingDisk{s.next, s.records})
	if e != nil {
		return "state_capacity_exceeded"
	}
	if len(b) > 256<<20 {
		return "state_capacity_exceeded"
	}
	f, e := openRelative(s.dir, "bindings.next", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, s.uid, 0600)
	if e != nil {
		return "audit_unavailable"
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		s.failed = true
		return "audit_unavailable"
	}
	if e = syscall.Renameat(int(s.dir.Fd()), "bindings.next", int(s.dir.Fd()), "bindings.json"); e != nil {
		s.failed = true
		return "audit_unavailable"
	}
	if s.dir.Sync() != nil {
		s.failed = true
		return "audit_unavailable"
	}
	return ""
}

// Register is a custody transition for a trusted operator coordinator. K1b must
// combine its generation/act verification and durable audit intent with this
// transition before exposing native mutations. There is no K1a mutation endpoint.
func (s *Store) Register(caller, operator Principal, b Binding) (Binding, Code) {
	if caller != operator || !validGeneration(caller.Generation) {
		return Binding{}, "role_not_permitted"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return Binding{}, "audit_unavailable"
	}
	for _, old := range s.records {
		if old.Epoch == b.Epoch && old.Path == b.Path && old.Status == "revoked" {
			return Binding{}, "identity_revoked"
		}
	}
	b.Number = s.next
	b.Status = "active"
	b.Registrar = caller
	s.records = append(s.records, b)
	s.next++
	if c := s.validate(); c != "" {
		s.records = s.records[:len(s.records)-1]
		s.next--
		return Binding{}, c
	}
	if c := s.persist(); c != "" {
		s.failed = true
		return Binding{}, c
	}
	return b, ""
}

// RevokeVerifier is trusted authority, never a request boolean. Production has no
// published act verifier yet. Persistent revocation always refuses in v0.
type RevokeVerifier interface {
	VerifyEphemeral(context.Context, Binding) Code
}

func (s *Store) Revoke(ctx context.Context, caller, operator Principal, number uint64, verifier RevokeVerifier) Code {
	if caller != operator || !validGeneration(caller.Generation) {
		return "role_not_permitted"
	}
	s.mu.Lock()
	var candidate Binding
	for _, b := range s.records {
		if b.Number == number {
			candidate = b
			break
		}
	}
	s.mu.Unlock()
	if candidate.Number == 0 {
		return "binding_not_found"
	}
	if candidate.Lifetime == "persistent" || verifier == nil {
		return "operator_record_unavailable"
	}
	if c := verifier.VerifyEphemeral(ctx, candidate); c != "" {
		return c
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return "audit_unavailable"
	}
	for i, b := range s.records {
		if b.Number == number {
			s.records[i].Status = "revoked"
			if c := s.persist(); c != "" {
				s.failed = true
				return c
			}
			s.notify(number)
			return ""
		}
	}
	return "binding_not_found"
}
func (s *Store) notify(n uint64) {
	for _, c := range s.watchers[n] {
		close(c)
	}
	delete(s.watchers, n)
}
func (s *Store) Watch(n uint64) (<-chan struct{}, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := make(chan struct{})
	s.watchers[n] = append(s.watchers[n], c)
	return c, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		v := s.watchers[n]
		for i, x := range v {
			if x == c {
				s.watchers[n] = append(v[:i], v[i+1:]...)
				break
			}
		}
	}
}
func (s *Store) lookup(uid uint32, gen string) (Binding, Code) {
	if s.failed {
		return Binding{}, "audit_unavailable"
	}
	for i := len(s.records) - 1; i >= 0; i-- {
		b := s.records[i]
		if b.UID == uid && b.Generation == gen {
			if b.Status == "revoked" {
				return b, "identity_revoked"
			}
			if b.Status == "active" {
				return b, ""
			}
		}
	}
	return Binding{}, "binding_not_found"
}
func (s *Store) Snapshot() []Binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Binding(nil), s.records...)
}

func authorize(peer Peer, sessionGeneration string, g Generation, b Binding) Code {
	if g.Fenced || !g.Verified || g.Provenance == "" || g.Revision == "" || !validGeneration(g.Generation) || g.UID != peer.UID {
		return "generation_source_unavailable"
	}
	if g.State != "active" {
		return "generation_inactive"
	}
	if g.Generation != sessionGeneration || b.Generation != sessionGeneration {
		return "generation_mismatch"
	}
	if b.UID != peer.UID {
		return "peer_binding_mismatch"
	}
	if b.Status == "revoked" {
		return "identity_revoked"
	}
	if b.Status != "active" {
		return "binding_not_found"
	}
	return ""
}

// Unbind records an explicitly coordinated retirement without revoking an identity.
// A later operator re-registration may reuse only a non-revoked persistent path.
func (s *Store) Unbind(caller, operator Principal, uid uint32, generation string) Code {
	if caller != operator || !validGeneration(caller.Generation) {
		return "role_not_permitted"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return "audit_unavailable"
	}
	for i, b := range s.records {
		if b.UID == uid && b.Generation == generation && b.Status == "active" {
			s.records[i].Status = "unbound"
			if c := s.persist(); c != "" {
				s.failed = true
				return c
			}
			s.notify(b.Number)
			return ""
		}
	}
	return "binding_not_found"
}
