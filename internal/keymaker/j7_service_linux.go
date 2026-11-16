//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
	"github.com/relux-works/swarma-keymaker/staticgate"
)

// j7StaticGateInput is everything the static gate may bind at startup: the
// four configured files, the digest of the exact static configuration bytes,
// the service identity and trusted time. No host-clock value is ever supplied.
type j7StaticGateInput struct {
	Files        j7StaticGateConfiguration
	ConfigSHA256 string
	ServiceUID   uint32
	Now          time.Time
	Lower        time.Time
	Upper        time.Time
}

// j7StaticGateResult carries the request public key the signed statement
// expects: 64 lowercase hex characters of the x-only key.
type j7StaticGateResult struct {
	RequestKey string
	check      func(j7GateTime, staticgate.Class) Code
}

// j7GateTime keeps the provider's point for audit and its complete trusted
// uncertainty interval for START admission. END retains point-time semantics.
type j7GateTime struct{ Now, Lower, Upper time.Time }

func (at j7GateTime) startBoundsValid() bool {
	return !at.Now.IsZero() && !at.Lower.IsZero() && !at.Upper.IsZero() &&
		!at.Lower.After(at.Now) && !at.Now.After(at.Upper)
}

// j7StaticGate is the required startup seam for the signed static gate.
// A nil gate or a verdict without a per-effect check never passes.
type j7StaticGate interface {
	verify(context.Context, j7StaticGateInput) (j7StaticGateResult, Code)
}

// j7ServiceDeps is the private startup seam. Production values are fixed by
// productionJ7ServiceDeps; no configuration member or flag selects another.
// Tests substitute single members to reach later gates without privilege.
type j7ServiceDeps struct {
	identity   func() (uint32, uint32, uint32, uint32) // real/effective UID and GID; never configurable
	clock      func(*timeconf.Policy) (*timeconf.Provider, error)
	gate       j7StaticGate
	ancestors  func(string, uint32) error
	head       func(string) (j7Expectation, error)
	generation func(*Store, generationJournalConfig) GenerationSource
	policy     func(string, uint32, *Store, string, uint64) (*j7Policy, error)
	loadKey    func(string, uint32, string, string, string, string) (*j7Key, error)
	listen     func(*os.File, uint32) (*net.UnixListener, uint64, uint64, error)
}

func productionJ7ServiceDeps() j7ServiceDeps {
	var d j7ServiceDeps
	d.identity = func() (uint32, uint32, uint32, uint32) {
		return uint32(os.Getuid()), uint32(os.Geteuid()), uint32(os.Getgid()), uint32(os.Getegid())
	}
	d.clock = func(p *timeconf.Policy) (*timeconf.Provider, error) { return timeconf.Production(p, nil) }
	d.gate = productionJ7StaticGate()
	d.ancestors = safeAncestors
	d.head = protectedJ7Head
	d.generation = func(s *Store, c generationJournalConfig) GenerationSource {
		return newJournalGeneration(productionGenerationWindow{}, s, c.Path, c.InitialFloor)
	}
	d.policy = newJ7Policy
	d.loadKey = loadJ7Key
	d.listen = createControlSocket
	return d
}

type j7HeadPin struct {
	Version uint64 `json:"expected_version"`
	Digest  string `json:"expected_digest"`
}

// decodeJ7Head accepts exactly the two pin members of the stopped-operator
// head file. An empty, partial, oversized or reset expectation refuses.
func decodeJ7Head(raw []byte) (j7Expectation, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return j7Expectation{}, failure("invalid J7 head pin")
	}
	if _, err := objectMembers(raw, []string{"expected_version", "expected_digest"}); err != nil {
		return j7Expectation{}, failure("invalid J7 head pin")
	}
	var pin j7HeadPin
	if StrictJSON(bytes.NewReader(raw), &pin) != nil || pin.Version == 0 || pin.Version > j7SafeInteger || !validDigest(pin.Digest) {
		return j7Expectation{}, failure("invalid J7 head pin")
	}
	canonical := fmt.Sprintf("{\"expected_version\":%d,\"expected_digest\":\"%s\"}\n", pin.Version, pin.Digest)
	if !bytes.Equal(raw, []byte(canonical)) {
		return j7Expectation{}, failure("invalid J7 head pin")
	}
	return j7Expectation{Version: pin.Version, Digest: pin.Digest}, nil
}

// protectedJ7Head reads the head pin under the protected-configuration rules:
// root-owned 0640 single-link file with the service's primary group below
// protected root-owned ancestors, without ACLs. The service cannot write it.
func protectedJ7Head(path string) (j7Expectation, error) {
	raw, err := protectedBytes(path)
	if err != nil {
		return j7Expectation{}, err
	}
	return decodeJ7Head(raw)
}

func j7PathWithin(parent, child string) bool {
	return parent == child || parent == "/" || strings.HasPrefix(child, parent+"/")
}

func j7SocketGroupAvailable(gid uint32) bool {
	if gid == uint32(os.Getegid()) {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, group := range groups {
		if uint32(group) == gid {
			return true
		}
	}
	return false
}

// j7ServiceDirs lists the four service directories that must stay distinct:
// key parent, Store directory, policy table parent and socket directory.
func j7ServiceDirs(cfg Config) []string {
	return []string{filepath.Dir(cfg.J7KeyFile), cfg.J7State.Path, filepath.Dir(cfg.J7Policy.Path), cfg.J7Socket.Dir}
}

// j7ServiceComplete names a missing required stanza. It reads only the parsed
// configuration: no path, clock, state, key or socket is touched.
func j7ServiceComplete(cfg Config) Code {
	if cfg.ServiceRole != j7RequestRole {
		return "operation_unsupported"
	}
	if cfg.J7Policy == nil || cfg.J7State == nil || cfg.J7State.HeadFile == "" || cfg.J7Socket == nil || cfg.StaticGate == nil {
		return "j7_configuration_incomplete"
	}
	if cfg.GenerationJournal == nil {
		return "generation_source_unavailable"
	}
	// Reader floor 4 would be a lifecycle-only service; request signing needs 5.
	if cfg.J7State.Minimum != j7SigningSchema {
		return "j7_signing_floor_required"
	}
	return ""
}

// j7ServiceCrossField adds lexical cross-member rules. Descriptor identity is
// checked separately before state-file/key access to refuse bind-mount aliases.
func j7ServiceCrossField(cfg Config) Code {
	if c := j7ServiceComplete(cfg); c != "" {
		return c
	}
	if cfg.J7Policy.Launcher.UID == cfg.ServiceUID {
		return "j7_configuration_conflict"
	}
	dirs := j7ServiceDirs(cfg)
	for i, a := range dirs {
		for _, b := range dirs[:i] {
			if j7PathWithin(a, b) || j7PathWithin(b, a) {
				return "j7_configuration_conflict"
			}
		}
	}
	// Operator-owned inputs must not live inside a service-writable directory.
	g := cfg.StaticGate
	for _, file := range []string{cfg.J7State.HeadFile, g.ApproverKeyFile, g.StatementFile, g.SignatureFile, g.DigestFile} {
		for _, dir := range dirs {
			if j7PathWithin(dir, file) {
				return "j7_configuration_conflict"
			}
		}
	}
	return ""
}

// j7ServiceDirectoryIdentity opens only directories, never custody files. A
// bind-mounted alias has a different path but the same device/inode pair.
func j7ServiceDirectoryIdentity(cfg Config, uid uint32) error {
	var dirs []*os.File
	defer func() {
		for _, dir := range dirs {
			dir.Close()
		}
	}()
	for i, path := range j7ServiceDirs(cfg) {
		mode := uint32(0700)
		if i == 3 {
			mode = 0755
		}
		dir, err := OpenDirectory(path, uid, mode)
		if err != nil {
			if i == 0 {
				return errJ7Key
			}
			return err
		}
		dirs = append(dirs, dir)
	}
	if !j7DistinctDirectoryIDs(dirs) {
		return Code("j7_configuration_conflict")
	}
	return nil
}

func j7DistinctDirectoryIDs(dirs []*os.File) bool {
	type identity struct {
		device uint64
		inode  uint64
	}
	seen := map[identity]bool{}
	for _, dir := range dirs {
		var st syscall.Stat_t
		if syscall.Fstat(int(dir.Fd()), &st) != nil {
			return false
		}
		id := identity{uint64(st.Dev), st.Ino}
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// j7ServiceStation selects the pinned station binding and checks the Store's
// instance, identity, epoch and registry pins before any key material loads.
func j7ServiceStation(s *Store, cfg Config) (Binding, Code) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed || s.j7 == nil || s.j7.Instance != cfg.InstanceID || s.j7.Identity != cfg.J7Policy.Identity {
		return Binding{}, "j7_state_identity_mismatch"
	}
	var station Binding
	found := false
	for _, b := range s.records {
		if b.Epoch != cfg.Epoch || b.RegistryRevision != cfg.RegistryRevision {
			return Binding{}, "j7_state_identity_mismatch"
		}
		if b.Number == cfg.J7Policy.Identity {
			station, found = b, true
		}
	}
	if !found || station.Status != "active" || ValidatePath(station.Path, "agent-identity") != "" {
		return Binding{}, "binding_not_found"
	}
	return station, ""
}

// j7PolicyTablePresent is the readiness rule for the policy table: it must
// exist as a protected regular file. Its content is still read per request,
// where an existing empty or unreadable table is empty authority.
func j7PolicyTablePresent(p *j7Policy) bool {
	f, err := openRelative(p.dir, p.name, syscall.O_RDONLY, p.uid, 0600)
	if err != nil {
		return false
	}
	defer f.Close()
	return j7NoACL(int(f.Fd()), false)
}

// serveJ7Request is the only entry of the request role. static holds the exact
// protected configuration bytes, or nil when a caller has none.
func serveJ7Request(ctx context.Context, cfg Config, static []byte, status io.Writer, d j7ServiceDeps) error {
	// Step 3: required stanzas and cross-field rules, before any path access.
	if c := j7ServiceCrossField(cfg); c != "" {
		return c
	}
	return startJ7Request(ctx, cfg, static, status, d)
}

// startJ7Request runs steps 4 onward. No secret is loaded and no listener is
// published before every earlier precondition holds; the legacy
// secret-before-lock order is deliberately not copied. Deferred closes give
// the shutdown order: socket unlink, key, policy, Store, state lock.
func startJ7Request(ctx context.Context, cfg Config, static []byte, status io.Writer, d j7ServiceDeps) error {
	if c := j7ServiceComplete(cfg); c != "" {
		return c
	}
	// Step 4: service identity.
	if d.identity == nil {
		return Code("role_not_permitted")
	}
	uid, euid, gid, egid := d.identity()
	if uid == 0 || euid == 0 || gid == 0 || egid == 0 {
		return Code("role_not_permitted")
	}
	if euid != uid || cfg.ServiceUID != uid || cfg.ServiceGID != gid {
		return failure("configuration identity mismatch")
	}
	if !j7SocketGroupAvailable(cfg.J7Socket.Group) {
		return Code("j7_socket_group_unavailable")
	}
	// Step 5: trusted time comes first; the gate never sees a host-clock value.
	if d.clock == nil {
		return Code("clock_untrusted")
	}
	provider, err := d.clock(cfg.TimePolicy)
	if err != nil || provider == nil || timeconfidence.Start(ctx, provider) != nil {
		return Code("clock_untrusted")
	}
	sample, err := timeconfidence.Sample(ctx, provider)
	if err != nil {
		return Code("clock_untrusted")
	}
	lower, upper, ok := timeconfidence.Bounds(sample)
	if !ok {
		return Code("clock_untrusted")
	}
	// Step 6: the static gate is required. A missing implementation or missing
	// static bytes refuses by name; nothing below runs without its verdict.
	if d.gate == nil || static == nil {
		return Code("static_gate_unavailable")
	}
	sum := sha256.Sum256(static)
	verdict, code := d.gate.verify(ctx, j7StaticGateInput{Files: *cfg.StaticGate, ConfigSHA256: hex.EncodeToString(sum[:]), ServiceUID: uid, Now: sample.Now, Lower: lower, Upper: upper})
	if code != "" {
		return code
	}
	if !validDigest(verdict.RequestKey) || verdict.check == nil {
		return Code("static_gate_unavailable")
	}
	// Step 7: ancestors of every service directory.
	if d.ancestors == nil || d.head == nil || d.generation == nil || d.policy == nil || d.loadKey == nil || d.listen == nil {
		return failure("J7 service unavailable")
	}
	for _, dir := range j7ServiceDirs(cfg) {
		if e := d.ancestors(dir, uid); e != nil {
			return e
		}
	}
	// Step 8: reject an unavailable operator head before opening state. The
	// service never writes this root-owned pin.
	expected, e := d.head(cfg.J7State.HeadFile)
	if e != nil {
		return Code("j7_head_pin_unavailable")
	}
	if err := j7ServiceDirectoryIdentity(cfg, uid); err != nil {
		return err
	}
	// State directory, exclusive lock, then the exact-head Store.
	state, e := OpenDirectory(cfg.J7State.Path, uid, 0700)
	if e != nil {
		return e
	}
	defer state.Close()
	lock, e := LockState(state, uid)
	if e != nil {
		return e
	}
	defer lock.Close()
	audit := systemAuditClock{provider: provider}
	store, e := openJ7SigningStore(state, uid, audit, expected)
	if e != nil {
		return e
	}
	defer store.Close()
	station, code := j7ServiceStation(store, cfg)
	if code != "" {
		return code
	}
	// Step 9: generation source with the launcher and station principals active.
	generation := d.generation(store, *cfg.GenerationJournal)
	if generation == nil {
		return Code("generation_source_unavailable")
	}
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	code = generation.WithEvidence(probe, []GenerationCondition{{Principal: cfg.J7Policy.Launcher}, {Principal: Principal{UID: station.UID, Generation: station.Generation}}}, func(context.Context) Code { return "" })
	cancel()
	if code != "" {
		return code
	}
	// Step 10: policy directory; a missing table refuses readiness.
	policy, e := d.policy(cfg.J7Policy.Path, uid, store, cfg.InstanceID, cfg.J7Policy.Identity)
	if e != nil {
		return e
	}
	defer policy.close()
	if !j7PolicyTablePresent(policy) {
		return Code("j7_policy_unavailable")
	}
	// Step 11: the key is loaded last and must be the key the gate expects.
	key, e := d.loadKey(cfg.J7KeyFile, uid, j7RequestRole, cfg.InstanceID, cfg.Epoch, cfg.RegistryRevision)
	if e != nil {
		return e
	}
	defer key.close()
	public, e := key.request(store, station, nil)
	if e != nil {
		return e
	}
	if hex.EncodeToString(public) != verdict.RequestKey {
		return Code("j7_request_key_mismatch")
	}
	// Step 12: compose the landed adapters. No node is configured, so grant
	// operations refuse delegation_evidence_unavailable.
	lifecycle, e := newJ7Lifecycle(store, policy, generation, cfg.J7Policy.Launcher)
	if e != nil {
		return e
	}
	custody, e := newJ7RequestCustody(lifecycle, key, audit, nil)
	if e != nil {
		return e
	}
	gated := &j7GatedHandler{j7ServiceAdapter: custody, check: verdict.check, now: func(ctx context.Context) (j7GateTime, Code) {
		sample, err := timeconfidence.Sample(ctx, provider)
		if err != nil {
			return j7GateTime{}, "clock_untrusted"
		}
		lower, upper, ok := timeconfidence.Bounds(sample)
		if !ok {
			return j7GateTime{}, "clock_untrusted"
		}
		return j7GateTime{Now: sample.Now, Lower: lower, Upper: upper}, ""
	}}
	latch := newJ7Latch()
	handler := &j7ServiceHandler{inner: gated, latch: latch, health: func() Code { return j7StoreHealth(store) }}
	wire, e := control.New(handler, handler, handler, handler, handler)
	if e != nil {
		return e
	}
	// Step 13: socket directory lock and listener publication.
	// R-U2-5: the final sample is fresh after state/GEN/policy/key setup and
	// socket-directory admission, immediately before listener publication.
	publish := func(dir *os.File, group uint32) (*net.UnixListener, uint64, uint64, error) {
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
	// Step 14: one readiness line, only after the listener is published.
	if _, e := fmt.Fprintf(status, "j7-request control ready; memory_locked=%t\n", key.locked); e != nil {
		return failure("readiness status unavailable")
	}
	return socket.serve(ctx, wire, latch, func() Code { return j7StoreHealth(store) })
}
