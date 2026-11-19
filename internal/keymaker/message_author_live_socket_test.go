//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

type maLiveSocketFixture struct {
	f    *maLiveFixture
	s    *maLiveServer
	path string
}

func newMALiveSocketFixture(t *testing.T, configure ...func(*maLiveServer)) *maLiveSocketFixture {
	t.Helper()
	f := newMALiveFixture(t, uint32(os.Getuid()))
	dir, e := os.MkdirTemp(os.Getenv("TMPDIR"), "ma-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	fd, e := OpenDirectory(dir, uint32(os.Getuid()), 0755)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	l, _, _, e := createControlSocket(fd, uint32(os.Getgid()))
	if e != nil {
		t.Fatal(e)
	}
	s := newMALiveServer(f.h)
	for _, fn := range configure {
		fn(s)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		s.close()
		select {
		case e := <-done:
			if e != nil && e != Code("audit_unavailable") {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("owned socket did not stop")
		}
	})
	return &maLiveSocketFixture{f: f, s: s, path: filepath.Join(dir, "control.sock")}
}
func (f *maLiveSocketFixture) dial(t *testing.T, hello bool) *net.UnixConn {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	if e = c.SetDeadline(time.Now().Add(3 * time.Second)); e != nil {
		t.Fatal(e)
	}
	if hello {
		raw, e := maLiveFrame(control.Object{"method": "hello", "request_id": strings.Repeat("f", 32), "versions": []any{int64(1)}})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.Write(raw); e != nil {
			t.Fatal(e)
		}
		frame, code := maLiveRead(c)
		if code != "" || !bytes.Contains(frame, []byte(`"version":1`)) {
			t.Fatal("hello control", code, string(frame))
		}
	}
	return c
}
func maLiveSocketCall(t *testing.T, c net.Conn, r messageauthor.Request) messageauthor.Response {
	t.Helper()
	frame, e := messageauthor.EncodeRequestFrame(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Write(frame); e != nil {
		t.Fatal(e)
	}
	raw, code := maLiveRead(c)
	if code != "" {
		t.Fatal("response frame", code)
	}
	out, e := messageauthor.DecodeResponseFrame(r, raw)
	if e != nil {
		t.Fatal("typed response", e)
	}
	return out
}

// Both connections use real SO_PEERCRED. A reconnect retries the identical S
// without a second signature. This fixture establishes only its own Unix UID.
func TestMALiveSecondConnectionIdentity(t *testing.T) {
	f := newMALiveSocketFixture(t)
	c := f.dial(t, true)
	r := f.f.request()
	r.Method = messageauthor.IdentityMethod
	r.Preimage = nil
	identity := maLiveSocketCall(t, c, r)
	if identity.Identity == nil || identity.Identity.AuthorAttestation != f.f.v.T {
		t.Fatal("identity control")
	}
	c.Close()
	f.f.source.mu.Lock()
	f.f.source.tuple.T = "sha256:" + strings.Repeat("b", 64)
	f.f.source.mu.Unlock()
	next := f.dial(t, true)
	out := maLiveSocketCall(t, next, f.f.request())
	if out.Refusal == nil || out.Refusal.Code != "signer_identity_mismatch" || f.f.calls.Load() != 0 {
		t.Fatal("old connection currentness reused")
	}
	f.f.source.mu.Lock()
	f.f.source.tuple.T = f.f.v.T
	f.f.source.mu.Unlock()
	valid := maLiveSocketCall(t, next, f.f.request())
	if valid.Signature == nil || f.f.calls.Load() != 1 {
		t.Fatal("renewal restore control")
	}
	next.Close()
	fresh := f.dial(t, true)
	replay := maLiveSocketCall(t, fresh, f.f.request())
	if replay.Signature == nil || !bytes.Equal(valid.Signature.Signature, replay.Signature.Signature) || f.f.calls.Load() != 1 {
		t.Fatal("connection retry re-signed")
	}
	t.Log("identity invocation_count=0; stale sign=0; valid=1; reconnected replay=1")
}

type maLivePartialConn struct{ net.Conn }

func (c maLivePartialConn) Write(raw []byte) (int, error) {
	n, e := c.Conn.Write(raw[:5])
	if e != nil {
		return n, e
	}
	return n, errors.New("fixture partial write")
}

// Actual Unix delivery is interrupted after a frame prefix. No refusal bytes
// follow that prefix, and recovery/reconnect returns the retained exact result.
func TestMALivePartialFrame(t *testing.T) {
	f := newMALiveSocketFixture(t)
	f.s.write = func(ctx context.Context, c net.Conn, p []byte) Code { return maLiveWrite(ctx, maLivePartialConn{c}, p) }
	c := f.dial(t, true)
	raw, e := messageauthor.EncodeRequestFrame(f.f.request())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Write(raw); e != nil {
		t.Fatal(e)
	}
	partial, e := io.ReadAll(c)
	if e != nil {
		t.Fatal(e)
	}
	if len(partial) != 5 || f.f.calls.Load() != 1 {
		t.Fatal("partial success followed by another frame", len(partial), f.f.calls.Load())
	}
	f.f.h.store.mu.Lock()
	status := f.f.h.store.maLive.Attempts[0].Status
	sig := append([]byte(nil), f.f.h.store.maLive.Attempts[0].Signature...)
	f.f.h.store.mu.Unlock()
	if status != "handoff_unknown" {
		t.Fatal("partial delivery marked released", status)
	}
	// Start a separate server over the same retained holder; the first server's
	// configuration stays immutable while its goroutines are live.
	f.s.close()
	next := newMALiveSocketFixture(t, func(s *maLiveServer) { s.holder = f.f.h })
	conn := next.dial(t, true)
	out := maLiveSocketCall(t, conn, f.f.request())
	if out.Signature == nil || !bytes.Equal(sig, out.Signature.Signature) || f.f.calls.Load() != 1 {
		t.Fatal("unknown receipt did not replay exact S")
	}
	t.Log("partial frame invocation_count=1; replay invocation_count=1")
}

// Bad wire bodies fail at the fixed grammar before intent or crypto. Each
// isolated connection is paired with a successful identity on the same server.
func TestMALiveWireAndCodeClosure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object control.Object
		want   string
	}{
		{"extra-field", control.Object{"method": string(messageauthor.IdentityMethod), "request_id": strings.Repeat("a", 32), "timeout_ms": int64(2000), "params": control.Object{}, "uid": int64(1)}, "request_malformed"},
		{"encoded-cap", control.Object{"method": string(messageauthor.SignMethod), "request_id": strings.Repeat("a", 32), "timeout_ms": int64(2000), "params": control.Object{"preimage": strings.Repeat("A", 32769)}}, "signer_preimage_too_large"},
		{"old-method", control.Object{"method": "pubkey", "request_id": strings.Repeat("a", 32), "timeout_ms": int64(2000), "params": control.Object{}}, "operation_unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMALiveSocketFixture(t)
			c := f.dial(t, true)
			raw, e := maLiveFrame(tc.object)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = c.Write(raw); e != nil {
				t.Fatal(e)
			}
			out, code := maLiveRead(c)
			if code != "" || !bytes.Contains(out, []byte(`"code":"`+tc.want+`"`)) || f.f.calls.Load() != 0 {
				t.Fatal("wire refusal", code, string(out))
			}
			r := f.f.request()
			r.Method = messageauthor.IdentityMethod
			r.Preimage = nil
			if out := maLiveSocketCall(t, c, r); out.Identity == nil {
				t.Fatal("valid identity refused")
			}
			t.Log("negative and identity invocation_count=0")
		})
	}
	t.Run("frame-allocation", func(t *testing.T) {
		for _, n := range []uint32{0, 65537} {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], n)
			_, code := maLiveRead(bytes.NewReader(header[:]))
			want := Code("frame_too_large")
			if n == 0 {
				want = "frame_malformed"
			}
			if code != want {
				t.Fatal("frame header admitted", code)
			}
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], 65536)
		raw := append(header[:], make([]byte, 65536)...)
		if frame, c := maLiveRead(bytes.NewReader(raw)); c != "" || len(frame) != 65540 {
			t.Fatal("frame boundary refused", c)
		}
	})
}

// An accepted connection is invalidated by retirement under the same Store
// barrier. The successful hello and signature are controls for real transport
// and authority; a read timeout does not count as invalidation evidence.
func TestMALiveRetirementClosesConnection(t *testing.T) {
	f := newMALiveSocketFixture(t)
	conn := f.dial(t, true)
	f.f.control(t)
	if c := f.f.h.store.retireMALive(t.Context(), fixtureOperator, f.f.b.Number); c != "" {
		t.Fatal(c)
	}
	if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	n, err := conn.Read(one[:])
	if n != 0 || err != io.EOF {
		t.Fatal("retired connection not invalidated", n, err)
	}
	if f.f.h.store.maLive.Attempts[0].Status != "dead" || f.f.calls.Load() != 1 {
		t.Fatal("retirement lost evidence")
	}
	t.Log("retirement closes idle real Unix connection; invocation_count=1")
	newMALiveFixture(t).control(t)
}

// The actual Unix writer must frame and audit each custody identity refusal,
// once and without signing; an unchanged identity still returns a valid result.
func TestMALiveCustodyIdentityRefusalFrame(t *testing.T) {
	for _, field := range []string{"instance", "epoch", "registry"} {
		t.Run(field, func(t *testing.T) {
			f := newMALiveSocketFixture(t)
			c := f.dial(t, true)
			f.f.h.key.mu.Lock()
			switch field {
			case "instance":
				f.f.h.key.instance = "different"
			case "epoch":
				f.f.h.key.epoch = "different"
			case "registry":
				f.f.h.key.registry = "different"
			}
			f.f.h.key.mu.Unlock()
			out := maLiveSocketCall(t, c, f.f.request())
			if out.Refusal == nil || out.Refusal.Code != "custody_unavailable" || out.Refusal.Retryable || out.Signature != nil || f.f.calls.Load() != 0 {
				t.Fatal("custody identity refusal", out)
			}
			s := f.f.h.store
			s.journal.mu.Lock()
			raw, e := os.ReadFile(filepath.Join(f.f.dir.Name(), "audit", s.journal.file.Name()))
			s.journal.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Count(raw, []byte(`"refusal_code":"custody_unavailable"`)) != 1 || bytes.Count(raw, []byte(`"custody_cause":"protection_failed"`)) != 1 {
				t.Fatal("custody refusal missing exact single audit", string(raw))
			}
			if len(s.maLive.Attempts) != 0 {
				t.Fatal("custody refusal retained intent")
			}
			valid := newMALiveSocketFixture(t)
			positive := maLiveSocketCall(t, valid.dial(t, true), valid.f.request())
			if positive.Signature == nil || valid.f.calls.Load() != 1 {
				t.Fatal("valid custody control")
			}
		})
	}
}
