//go:build linux

package keymaker

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
)

type maLiveServiceDeps struct {
	clock      func(*timeconf.Policy) (*timeconf.Provider, error)
	head       func(string) (j7Expectation, error)
	generation func(*Store, generationJournalConfig) GenerationSource
	current    maLiveCurrent
	key        *messageAuthorKey
	invoke     func(*Store, Binding, *messageAuthorPlan, func() Code) ([]byte, Code)
}

func productionMALiveDeps() maLiveServiceDeps {
	return maLiveServiceDeps{clock: func(p *timeconf.Policy) (*timeconf.Provider, error) { return timeconf.Production(p, nil) }, head: protectedJ7Head, generation: func(s *Store, g generationJournalConfig) GenerationSource {
		return newJournalGeneration(productionGenerationWindow{}, s, g.Path, g.InitialFloor)
	}, current: maLiveUnqualified{}}
}
func serveMALive(ctx context.Context, cfg Config, status io.Writer, d maLiveServiceDeps) error {
	m := cfg.maLive
	if m == nil {
		return failure("message-author configuration unavailable")
	}
	if m.Generation == nil {
		return Code("generation_source_unavailable")
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if uid == 0 || gid == 0 || uint32(os.Geteuid()) != uid || uint32(os.Getegid()) != gid || m.UID != uid || m.GID != gid {
		return Code("role_not_permitted")
	}
	if !j7SocketGroupAvailable(m.Socket.Group) {
		return Code("role_not_permitted")
	}
	if d.clock == nil {
		return Code("clock_untrusted")
	}
	clock, e := d.clock(m.Time)
	if e != nil || clock == nil || timeconfidence.Start(ctx, clock) != nil {
		return Code("clock_untrusted")
	}
	if d.head == nil {
		return Code("message_author_unqualified")
	}
	expected, e := d.head(m.State.Head)
	if e != nil {
		return Code("message_author_unqualified")
	}
	if safeAncestors(m.State.Path, uid) != nil || safeAncestors(m.Socket.Dir, uid) != nil {
		return failure("unsafe service ancestors")
	}
	state, e := OpenDirectory(m.State.Path, uid, 0700)
	if e != nil {
		return e
	}
	defer state.Close()
	if !j7NoACL(int(state.Fd()), true) {
		return failure("unsafe state ACL")
	}
	lock, e := LockState(state, uid)
	if e != nil {
		return e
	}
	defer lock.Close()
	s, c := openMALive(state, uid, systemAuditClock{provider: clock}, expected)
	if c != "" {
		return c
	}
	defer s.Close()
	if s.maLive.Instance != m.Instance || s.maLive.Epoch != m.Epoch || s.maLive.Registry != m.Registry || s.maLive.Fenced {
		return Code("message_author_unqualified")
	}
	if d.generation == nil {
		return Code("generation_source_unavailable")
	}
	generation := d.generation(s, *m.Generation)
	if generation == nil {
		return Code("generation_source_unavailable")
	}
	if c = generation.WithEvidence(ctx, nil, func(context.Context) Code { return "" }); c != "" {
		return c
	}
	socket, e := OpenDirectory(m.Socket.Dir, uid, 0755)
	if e != nil {
		return e
	}
	defer socket.Close()
	if !j7DistinctDirectoryIDs([]*os.File{state, socket}) {
		return failure("conflicting service directories")
	}
	if syscall.Flock(int(socket.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return failure("socket directory already locked")
	}
	listener, ino, dev, e := createControlSocket(socket, m.Socket.Group)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer func() {
		var st unix.Stat_t
		if unix.Fstatat(int(socket.Fd()), "control.sock", &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Ino == ino && uint64(st.Dev) == dev {
			_ = syscall.Unlinkat(int(socket.Fd()), "control.sock")
		}
	}()
	h := &maLiveHolder{store: s, key: d.key, invoke: d.invoke, generations: generation, current: d.current, clock: func(ctx context.Context) (j7GateTime, Code) {
		v, e := timeconfidence.Sample(ctx, clock)
		if e != nil {
			return j7GateTime{}, "clock_untrusted"
		}
		lower, upper, ok := timeconfidence.Bounds(v)
		if !ok {
			return j7GateTime{}, "clock_untrusted"
		}
		return j7GateTime{Now: v.Now, Lower: lower, Upper: upper}, ""
	}}
	server := newMALiveServer(h)

	if status != nil {
		_, _ = io.WriteString(status, "ready\n")
	}
	return server.serve(ctx, listener)
}
