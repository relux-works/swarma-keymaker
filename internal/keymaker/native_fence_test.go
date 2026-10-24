package keymaker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// Notifications may lag authoritative journal state. Delaying this revocation
// signal isolates the final authority barrier from the independent idle closer.
type delayedGenerationWatch struct{ *fakeGenerations }

func (g delayedGenerationWatch) Watch(uint32, string) (<-chan struct{}, func()) {
	return make(chan struct{}), func() {}
}

type nativeFenceProbe struct {
	native  *Native
	method  string
	before  func()
	entered chan struct{}
	allow   <-chan struct{}
	once    atomic.Bool
}

func (f *nativeFenceProbe) WithActive(ctx context.Context, p control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if r.Method != f.method || !f.once.CompareAndSwap(false, true) {
		return f.native.WithActive(ctx, p, r, result, release)
	}
	if f.before != nil {
		f.before()
	}
	return f.native.WithActive(ctx, p, r, result, func(ctx context.Context) control.Code {
		if f.entered != nil {
			close(f.entered)
			select {
			case <-f.allow:
			case <-ctx.Done():
				return control.DeadlineExceeded
			}
		}
		return release(ctx)
	})
}

// Through the real daemon socket, authoritative retirement before the final
// barrier suppresses hello/pubkey success; an already-held barrier orders the
// actual write before retirement. Notification delivery is deliberately delayed.
func TestNativeReleaseFence(t *testing.T) {
	for _, method := range []string{"hello", "pubkey"} {
		t.Run(method, func(t *testing.T) {
			for _, order := range []string{"retirement-wins", "release-wins"} {
				t.Run(order, func(t *testing.T) {
					b := nativeOwnBinding()
					f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
					f.engine.Generations = delayedGenerationWatch{f.generation}
					probe := &nativeFenceProbe{native: f.native, method: method}
					entered, allow := make(chan struct{}), make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(allow) }) }
					defer unblock()
					if order == "retirement-wins" {
						probe.before = func() { f.generation.set(b.UID, "retiring", b.Generation) }
					} else {
						probe.entered = entered
						probe.allow = allow
					}
					wire, err := control.New(f.native, f.native, f.native, probe, f.native)
					if err != nil {
						t.Fatal(err)
					}
					f.server.controlWire = wire
					f.start()
					c := nativeDial(t, f.server.ControlPath)
					request, id := nativeHello(1), nativeID(1)
					if method != "hello" {
						nativeNegotiate(t, c, 1)
						request = nativeRequest(2, "pubkey", control.Object{})
						id = nativeID(2)
					}
					before := nativeSnapshot(t, f)
					nativeSend(t, c, request)
					if order == "retirement-wins" {
						obj := nativeReceive(t, c)
						if _, ok := obj["result"]; ok {
							t.Fatal("native retirement released success")
						}
						nativeResponse(t, obj, id, "generation_inactive")
						if !bytes.Equal(before, nativeSnapshot(t, f)) {
							t.Fatal("retired release retained a success ID")
						}
						return
					}
					select {
					case <-entered:
					case <-time.After(time.Second):
						t.Fatal("actual native release did not enter barrier")
					}
					attempting, retired := make(chan struct{}), make(chan struct{})
					go func() { close(attempting); f.generation.set(b.UID, "retiring", b.Generation); close(retired) }()
					<-attempting
					select {
					case <-retired:
						t.Fatal("retirement overtook native write barrier")
					case <-time.After(25 * time.Millisecond):
					}
					unblock()
					nativeResponse(t, nativeReceive(t, c), id, "")
					select {
					case <-retired:
					case <-time.After(time.Second):
						t.Fatal("retirement did not follow release")
					}
					nativeSend(t, c, nativeRequest(9, "pubkey", control.Object{}))
					nativeResponse(t, nativeReceive(t, c), nativeID(9), "generation_inactive")
				})
			}
		})
	}
}

// Unassignable groups and pre-existing paths cannot make startup fall back to
// a world-accessible control socket; the intact control has exact0660/own group.
func TestNativeSocketPermissions(t *testing.T) {
	for _, mode := range []string{"invalid-group", "existing-file", "symlink", "existing-stage", "intact"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			f.server.Close()
			f.server.cleanup()
			f.stopped = true
			gid := uint32(os.Getgid())
			controlPath := filepath.Join(f.socketDir, "control.sock")
			switch mode {
			case "invalid-group":
				gid = 4000000000
			case "existing-file":
				if err := os.WriteFile(controlPath, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("never-follow", controlPath); err != nil {
					t.Fatal(err)
				}
			case "existing-stage":
				if err := os.Mkdir(filepath.Join(f.socketDir, "control.stage"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			server, err := NewDaemonServer(f.socketDir, f.engine, f.config, gid, nil)
			if mode != "intact" {
				if err == nil || server != nil {
					if server != nil {
						server.Close()
						server.cleanup()
					}
					t.Fatal("unsafe control group or path admitted")
				}
				if mode == "existing-file" {
					data, err := os.ReadFile(controlPath)
					if err != nil || string(data) != "retained" {
						t.Fatal("startup removed existing control evidence")
					}
				}
				if mode == "symlink" {
					target, err := os.Readlink(controlPath)
					if err != nil || target != "never-follow" {
						t.Fatal("startup followed/removed control symlink")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer server.cleanup()
			defer server.Close()
			st, err := os.Lstat(server.ControlPath)
			if err != nil {
				t.Fatal(err)
			}
			stat := st.Sys().(*syscall.Stat_t)
			if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 || stat.Uid != uint32(os.Getuid()) || stat.Gid != gid {
				t.Fatal("unsafe control mode/group")
			}
		})
	}
}
