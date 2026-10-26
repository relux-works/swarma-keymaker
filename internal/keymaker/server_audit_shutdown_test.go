//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

type shutdownCountingSigner struct {
	Signer
	calls atomic.Int32
}

func (s *shutdownCountingSigner) Sign(path string, data []byte) ([]byte, Code) {
	s.calls.Add(1)
	return s.Signer.Sign(path, data)
}

func shutdownAgentControl(t *testing.T, c *net.UnixConn, public []byte) {
	t.Helper()
	body := validBody(public, "git")
	if err := writeResponse(c, Packet(body)); err != nil {
		t.Fatal(err)
	}
	reply, code := ReadFrame(c)
	if code != "" {
		t.Fatal("healthy signing control", code)
	}
	checkResponse(t, Packet(reply), public, body)
}

// Blocking the real Server.Close mutex holds both listeners open. A failed
// request must not expose EOF before that close can run, even if its own handler
// exits first. Actual append/sync faults cover agent dispatch/framing/overload
// and control success/refusal exits. Healthy signatures/hello precede each fault;
// this isolated two-socket fixture does not qualify deployment or other failures.
func TestAuditFailureShutdownOrdering(t *testing.T) {
	for _, origin := range []string{"agent-sign", "agent-frame", "agent-busy", "control-pubkey", "control-refusal"} {
		for _, fault := range []string{"append", "sync"} {
			t.Run(origin+"/"+fault, func(t *testing.T) {
				b := nativeOwnBinding()
				f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
				signer := &shutdownCountingSigner{Signer: f.engine.Signer}
				f.engine.Signer = signer
				f.start()
				public, code := f.master.Public(b.Path)
				if code != "" {
					t.Fatal(code)
				}
				agent := nativeDial(t, f.server.Path)
				shutdownAgentControl(t, agent, public)
				idleAgent := nativeDial(t, f.server.Path)
				shutdownAgentControl(t, idleAgent, public)
				native := nativeDial(t, f.server.ControlPath)
				nativeNegotiate(t, native, 1)
				idleNative := nativeDial(t, f.server.ControlPath)
				nativeNegotiate(t, idleNative, 3)
				before, bindings := nativeSnapshot(t, f), f.store.Snapshot()
				j := f.store.journal
				j.mu.Lock()
				j.writer = &faultFile{file: j.file, writeFail: fault == "append", syncFail: fault == "sync"}
				j.mu.Unlock()
				if origin == "agent-busy" {
					for i := 0; i < cap(f.server.requests); i++ {
						f.server.requests <- struct{}{}
					}
					defer func() {
						for len(f.server.requests) != 0 {
							<-f.server.requests
						}
					}()
				}

				// Admission and healthy replies completed before taking this
				// barrier. The failure watcher and synchronous transport close
				// must both use this actual lifecycle mutex, not a test callback.
				f.server.mu.Lock()
				locked := true
				defer func() {
					if locked {
						f.server.mu.Unlock()
					}
				}()
				active := agent
				switch origin {
				case "agent-sign", "agent-busy":
					if err := writeResponse(agent, Packet(validBody(public, "git"))); err != nil {
						t.Fatal(err)
					}
				case "agent-frame":
					var header [4]byte
					binary.BigEndian.PutUint32(header[:], MaxFrame+1)
					if err := writeResponse(agent, header[:]); err != nil {
						t.Fatal(err)
					}
				case "control-pubkey", "control-refusal":
					active = native
					method := "pubkey"
					if origin == "control-refusal" {
						method = "unknown"
					}
					nativeSend(t, native, nativeRequest(2, method, control.Object{}))
				}
				select {
				case <-f.engine.Failed():
				case <-time.After(2 * time.Second):
					t.Fatal("real audit fault did not fence engine")
				}
				// A deadline bounds the negative observation while the actual
				// close is deliberately blocked; it is not a retry for shutdown.
				active.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
				out, err := io.ReadAll(io.LimitReader(active, MaxFrame+5))
				if len(out) != 0 {
					if active == agent {
						if !bytes.Equal(out, AgentFailure) {
							t.Fatal("audit failure released agent success")
						}
					} else {
						raw := bytes.NewReader(out)
						body, code := ReadFrame(raw)
						obj, decodeErr := control.Decode(body)
						if code != "" || raw.Len() != 0 || decodeErr != nil {
							t.Fatal("audit failure released invalid control response", code, decodeErr)
						}
						nativeResponse(t, obj, nativeID(2), "audit_unavailable")
					}
				}
				if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
					t.Fatal("connection terminated before audit shutdown closed listeners", err)
				}

				// Concurrent explicit Close/cancellation must not wait on the
				// calling handler's own WaitGroup slot or deadlock on each other.
				var closes sync.WaitGroup
				for i := 0; i < 3; i++ {
					closes.Go(f.server.Close)
				}
				f.cancel()
				f.server.mu.Unlock()
				locked = false
				for _, c := range []*net.UnixConn{agent, native, idleAgent, idleNative} {
					c.SetReadDeadline(time.Now().Add(time.Second))
					var next [1]byte
					if n, err := c.Read(next[:]); n != 0 || err != io.EOF {
						t.Fatal("audit shutdown retained connection or released bytes", n, err)
					}
				}
				for _, path := range []string{f.server.Path, f.server.ControlPath} {
					c, err := net.DialTimeout("unix", path, time.Second)
					if err == nil {
						c.Close()
						t.Fatal("listener remained open after audit shutdown EOF")
					}
				}
				select {
				case err := <-f.done:
					f.cancel = nil
					f.stopped = true
					if err != Code("audit_unavailable") {
						t.Fatal("audit service-health code", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("audit shutdown waited for its own handler")
				}
				closes.Wait()
				if !bytes.Equal(before, nativeSnapshot(t, f)) || !reflect.DeepEqual(bindings, f.store.Snapshot()) {
					t.Fatal("failed request mutated binding state")
				}
				calls := signer.calls.Load()
				session := f.engine.OpenSession(context.Background(), Peer{UID: b.UID})
				code = f.engine.Handle(context.Background(), session, validBody(public, "git"), func(context.Context, []byte) error {
					t.Error("failed engine released response")
					return nil
				})
				if code != "audit_unavailable" || signer.calls.Load() != calls {
					t.Fatal("failed engine resumed signing", code)
				}
			})
		}
	}
}
