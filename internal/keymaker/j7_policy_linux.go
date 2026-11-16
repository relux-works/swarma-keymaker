//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const j7PolicyBytes = 1 << 20
const j7PolicyRows = 4096
const j7PolicyPermissions = 16384

type j7ConsentPermission struct {
	Contract string `json:"contract_sha256"`
	Booking  string `json:"booking_sha256"`
	Privacy  string `json:"privacy_sha256"`
	AndUse   bool   `json:"and_use"`
}
type j7PolicyRow struct {
	Origin   j7OriginKey           `json:"origin"`
	Use      []string              `json:"use"`
	Delegate []string              `json:"delegate"`
	Consent  []j7ConsentPermission `json:"consent"`
	Deny     []string              `json:"deny"`
}
type j7PolicyTable struct {
	Format   string        `json:"format"`
	Instance string        `json:"instance"`
	Identity uint64        `json:"identity_registration_number"`
	Version  uint64        `json:"version"`
	Rows     []j7PolicyRow `json:"rows"`
}

func validateJ7Policy(p *j7PolicyTable, instance string, identity uint64) error {
	if p == nil || p.Format != "keymaker-j7-policy/1" || p.Instance != instance || p.Identity != identity || !validJ7Instance(instance) || identity == 0 || identity > j7SafeInteger || p.Version == 0 || p.Version > j7SafeInteger || p.Rows == nil || len(p.Rows) > j7PolicyRows {
		return failure("invalid J7 policy")
	}
	rows := map[j7OriginKey]bool{}
	total := 0
	for _, r := range p.Rows {
		if !r.Origin.valid() || rows[r.Origin] || r.Use == nil || r.Delegate == nil || r.Consent == nil || r.Deny == nil {
			return failure("invalid policy row")
		}
		rows[r.Origin] = true
		total += len(r.Use) + len(r.Delegate) + len(r.Consent) + len(r.Deny)
		if total > j7PolicyPermissions {
			return failure("policy permission capacity")
		}
		sets := []map[string]bool{}
		for _, list := range [][]string{r.Use, r.Delegate, r.Deny} {
			seen := map[string]bool{}
			for _, id := range list {
				if !validDigest(id) || seen[id] {
					return failure("invalid policy permission")
				}
				seen[id] = true
			}
			sets = append(sets, seen)
		}
		for id := range sets[0] {
			if sets[2][id] {
				return failure("conflicting policy permission")
			}
		}
		consents := map[[3]string]bool{}
		for _, c := range r.Consent {
			key := [3]string{c.Contract, c.Booking, c.Privacy}
			if !validDigest(c.Contract) || !validDigest(c.Booking) || !validDigest(c.Privacy) || consents[key] {
				return failure("invalid consent permission")
			}
			consents[key] = true
		}
	}
	return nil
}
func decodeJ7Policy(raw []byte, instance string, identity uint64) (*j7PolicyTable, error) {
	if len(raw) == 0 || len(raw) > j7PolicyBytes {
		return nil, failure("policy byte capacity")
	}
	if messageRequired(raw, reflect.TypeFor[j7PolicyTable]()) != nil {
		return nil, failure("invalid policy members")
	}
	var p j7PolicyTable
	if StrictJSON(bytes.NewReader(raw), &p) != nil || validateJ7Policy(&p, instance, identity) != nil {
		return nil, failure("invalid policy")
	}
	return &p, nil
}
func j7PolicyRowFor(p *j7PolicyTable, key j7OriginKey) *j7PolicyRow {
	if p != nil {
		for i := range p.Rows {
			if p.Rows[i].Origin == key {
				return &p.Rows[i]
			}
		}
	}
	return nil
}
func j7Listed(list []string, id string) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

// This transition uses only explicit operator lists. An enrolled grant's absence
// from an unchanged list is not a removal. PR2 creates no enrollment evidence.
func reconcileJ7Denials(old, next *j7PolicyTable, denials []j7Denial) []j7Denial {
	result := append([]j7Denial{}, denials...)
	add := func(origin j7OriginKey, grant string) {
		for i := range result {
			if result[i].Origin == origin && result[i].Grant == grant {
				result[i].Version = next.Version
				return
			}
		}
		result = append(result, j7Denial{origin, grant, next.Version})
	}
	if old != nil {
		for _, r := range old.Rows {
			n := j7PolicyRowFor(next, r.Origin)
			for _, g := range r.Use {
				if n == nil || !j7Listed(n.Use, g) {
					add(r.Origin, g)
				}
			}
		}
	}
	for _, r := range next.Rows {
		for _, g := range r.Deny {
			add(r.Origin, g)
		}
	}
	kept := result[:0]
	for _, d := range result {
		r := j7PolicyRowFor(next, d.Origin)
		if r != nil && next.Version > d.Version && j7Listed(r.Use, d.Grant) {
			continue
		}
		kept = append(kept, d)
	}
	return kept
}
func j7NoACL(fd int, directory bool) bool {
	return j7NoACLQuery(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) }, directory)
}

// Socket inodes cannot be opened for Fgetxattr. Lgetxattr on the retained
// directory's descriptor path checks the inode without following a final link.
func j7SocketNoACL(path string) bool {
	return j7NoACLQuery(func(name string) (int, error) { return unix.Lgetxattr(path, name, nil) }, false)
}

func j7NoACLQuery(get func(string) (int, error), directory bool) bool {
	names := []string{"system.posix_acl_access"}
	if directory {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		_, err := get(name)
		if err != unix.ENODATA && err != unix.ENOTSUP {
			return false
		}
	}
	return true
}
func j7PolicyDirectory(path string, uid uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, failure("unsafe policy directory")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range append([]string{""}, parts...) {
		if part != "" {
			next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			unix.Close(fd)
			if e != nil {
				return nil, e
			}
			fd = next
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uid) || st.Mode&022 != 0 || !j7NoACL(fd, true) {
			unix.Close(fd)
			return nil, failure("unsafe policy ancestry")
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&07777 != 0700 {
		unix.Close(fd)
		return nil, failure("unsafe policy holder")
	}
	return os.NewFile(uintptr(fd), path), nil
}

type j7Policy struct {
	gate     auditGate
	dir      *os.File
	name     string
	uid      uint32
	instance string
	identity uint64
	store    *Store
}

func newJ7Policy(path string, uid uint32, store *Store, instance string, identity uint64) (*j7Policy, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || store == nil || store.j7 == nil || store.j7.Instance != instance || store.j7.Identity != identity {
		return nil, failure("J7 policy pins unavailable")
	}
	dir, err := j7PolicyDirectory(filepath.Dir(path), uid)
	if err != nil {
		return nil, err
	}
	return &j7Policy{dir: dir, name: filepath.Base(path), uid: uid, instance: instance, identity: identity, store: store}, nil
}
func (p *j7Policy) close() error { return p.dir.Close() }
func (p *j7Policy) locked(ctx context.Context, fn func() Code) Code {
	if !p.gate.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer p.gate.Unlock()
	for {
		err := unix.Flock(int(p.dir.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return "j7_state_fenced"
		}
		select {
		case <-ctx.Done():
			return "request_deadline_exceeded"
		case <-time.After(time.Millisecond * 5):
		}
	}
	defer unix.Flock(int(p.dir.Fd()), unix.LOCK_UN)
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	return fn()
}
func (p *j7Policy) read() ([]byte, error) {
	f, err := openRelative(p.dir, p.name, syscall.O_RDONLY, p.uid, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if !j7NoACL(int(f.Fd()), false) {
		return nil, failure("unsafe policy ACL")
	}
	b, err := io.ReadAll(io.LimitReader(f, j7PolicyBytes+1))
	if err != nil || len(b) > j7PolicyBytes {
		return nil, failure("policy capacity")
	}
	return b, nil
}
func (p *j7Policy) cause(ctx context.Context, cause Code) Code {
	domain := "control"
	r := AuditRecord{Surface: "control", Operation: "j7_policy_read", Domain: &domain, Result: "refused", RefusalCode: &cause}
	if p.store.journal == nil {
		p.store.failed = true
		return "audit_unavailable"
	}
	code := p.store.journal.AppendContext(ctx, r)
	if code == "request_deadline_exceeded" {
		return code
	}
	if code != "" {
		p.store.failed = true
		return "audit_unavailable"
	}
	return "GRANT_NOT_FOR_RUN"
}
func (p *j7Policy) accept(ctx context.Context, table *j7PolicyTable, digest string, pending bool) Code {
	s := p.store
	j := s.j7
	if s.failed || j == nil || j.Pending {
		return "j7_state_fenced"
	}
	if table.Version < j.Version {
		return p.cause(ctx, "policy_rollback")
	}
	if table.Version == j.Version {
		if digest != j.Digest {
			return p.cause(ctx, "policy_equivocation")
		}
		return ""
	}
	next := cloneJ7(j)
	next.Denials = reconcileJ7Denials(j.Policy, table, j.Denials)
	if len(next.Denials) > j7HistoryLimit {
		return "state_capacity_exceeded"
	}
	next.Version, next.Digest, next.Policy, next.Pending = table.Version, digest, table, pending
	s.j7 = next
	return s.commitJ7(ctx)
}

// withTable is the shared publication fence. Parse before taking its terminal
// locks; bounded exact-byte revalidation under the gate prevents stale parsing.
// A future release caller must first hold authoritative generation evidence and
// derive the origin from its connection capability, never from request fields.
func (p *j7Policy) withTable(ctx context.Context, fn func(*j7PolicyTable) Code) Code {
	raw, readErr := p.read()
	table, decodeErr := decodeJ7Policy(raw, p.instance, p.identity)
	return p.locked(ctx, func() Code {
		s := p.store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if s.failed || s.j7 == nil || s.j7.Pending {
			return "j7_state_fenced"
		}
		current, err := p.read()
		if readErr != nil || decodeErr != nil || err != nil || !bytes.Equal(raw, current) {
			return p.cause(ctx, "policy_unavailable")
		}
		if table.Version > s.j7.Version {
			// Bring externally staged bytes into the same durability protocol before
			// accepting a floor. Raw edits without this shared gate remain unsupported.
			f, e := openRelative(p.dir, p.name, syscall.O_RDONLY, p.uid, 0600)
			if e != nil {
				return p.cause(ctx, "policy_unavailable")
			}
			e = f.Sync()
			ce := f.Close()
			if e != nil || ce != nil || p.dir.Sync() != nil {
				s.failed = true
				return "j7_state_fenced"
			}
		}
		if c := p.accept(ctx, table, messageHash(raw), false); c != "" {
			return c
		}
		if auditContextExpired(ctx) {
			return "request_deadline_exceeded"
		}
		return fn(table)
	})
}

// publish is a holder-only, trusted operator boundary, not a native operation.
// The pending floor/denials commit precedes file effects; completion is another
// durable commit. Failures retain intent and poison this Store until recovery.
func (p *j7Policy) publish(ctx context.Context, raw []byte) Code {
	if uint32(os.Geteuid()) != p.uid {
		return "role_not_permitted"
	}
	table, err := decodeJ7Policy(raw, p.instance, p.identity)
	if err != nil {
		return "request_malformed"
	}
	return p.locked(ctx, func() Code {
		s := p.store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if s.failed || s.j7 == nil || s.j7.Pending {
			return "j7_state_fenced"
		}
		// Never rename over another holder artifact, even on an advancing
		// version. Inspect before the pending commit under the publication lock.
		var target unix.Stat_t
		targetErr := unix.Fstatat(int(p.dir.Fd()), p.name, &target, unix.AT_SYMLINK_NOFOLLOW)
		if targetErr != unix.ENOENT {
			current, readErr := p.read()
			_, decodeErr := decodeJ7Policy(current, p.instance, p.identity)
			if targetErr != nil || readErr != nil || decodeErr != nil {
				return "j7_policy_target_invalid"
			}
		}
		if table.Version == s.j7.Version {
			current, e := p.read()
			if e != nil || !bytes.Equal(current, raw) {
				return p.cause(ctx, "policy_equivocation")
			}
			return p.accept(ctx, table, messageHash(raw), false)
		}
		if c := p.accept(ctx, table, messageHash(raw), true); c != "" {
			return c
		}
		fail := func() Code { s.failed = true; return "j7_state_fenced" }
		if c := s.j7Point("policy-prepared"); c != "" {
			return fail()
		}
		name := "." + p.name + ".next"
		f, e := openRelative(p.dir, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, p.uid, 0600)
		if e != nil {
			return fail()
		}
		n, e := f.Write(raw)
		if e == nil && n != len(raw) {
			e = io.ErrShortWrite
		}
		if e == nil {
			if c := s.j7Point("policy-write"); c != "" {
				e = c
			}
		}
		if e == nil {
			e = f.Sync()
		}
		if e == nil {
			if c := s.j7Point("policy-sync"); c != "" {
				e = c
			}
		}
		ce := f.Close()
		if e != nil || ce != nil {
			return fail()
		}
		if syscall.Renameat(int(p.dir.Fd()), name, int(p.dir.Fd()), p.name) != nil {
			return fail()
		}
		if c := s.j7Point("policy-rename"); c != "" {
			return fail()
		}
		if p.dir.Sync() != nil {
			return fail()
		}
		if c := s.j7Point("policy-directory-sync"); c != "" {
			return fail()
		}
		s.j7 = cloneJ7(s.j7)
		s.j7.Pending = false
		return s.commitJ7(ctx)
	})
}
func (p *j7Policy) permission(ctx context.Context, origin j7Origin, kind string, ids []string, consent *j7ConsentPermission) Code {
	consentCheck := kind == "consent"
	if !origin.valid() {
		if consentCheck {
			return "CONSENT_NOT_FOR_RUN"
		}
		return "GRANT_NOT_FOR_RUN"
	}
	code := p.withTable(ctx, func(table *j7PolicyTable) Code {
		row := j7PolicyRowFor(table, origin.key())
		deny := Code("GRANT_NOT_FOR_RUN")
		if consentCheck {
			deny = "CONSENT_NOT_FOR_RUN"
		}
		if row == nil {
			return p.cause(ctx, "policy_row_missing")
		}
		if consentCheck {
			if consent == nil {
				return p.cause(ctx, "policy_consent_missing")
			}
			for _, c := range row.Consent {
				if c.Contract == consent.Contract && c.Booking == consent.Booking && c.Privacy == consent.Privacy {
					return ""
				}
			}
			return p.cause(ctx, "policy_consent_missing")
		}
		if kind != "use" && kind != "delegate" || len(ids) == 0 {
			return deny
		}
		for _, id := range ids {
			list := row.Use
			if kind == "delegate" {
				list = row.Delegate
			}
			if !j7Listed(list, id) {
				return p.cause(ctx, "policy_permission_missing")
			}
			if kind == "use" {
				for _, d := range p.store.j7.Denials {
					if d.Origin == row.Origin && d.Grant == id {
						return p.cause(ctx, "policy_grant_denied")
					}
				}
			}
		}
		return ""
	})
	if consentCheck && code == "GRANT_NOT_FOR_RUN" {
		return "CONSENT_NOT_FOR_RUN"
	}
	return code
}
