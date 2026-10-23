package keymaker

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// A real control-side sync fault must suppress success and autonomously close
// both listeners. The healthy control serves native and agent public responses
// from the same Store and audit journal.
func TestNativeAuditClosesBothSurfaces(t *testing.T) {
	for _, fault := range []bool{true, false} {
		name := "healthy"
		if fault {
			name = "sync-fault"
		}
		t.Run(name, func(t *testing.T) {
			b := nativeOwnBinding()
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			if fault {
				f.store.journal.mu.Lock()
				f.store.journal.writer = &faultFile{file: f.store.journal.file, syncFail: true}
				f.store.journal.mu.Unlock()
			}
			nativeSend(t, c, nativeRequest(2, "pubkey", control.Object{}))
			if !fault {
				nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
				agent := nativeDial(t, f.server.Path)
				if err := writeResponse(agent, Packet([]byte{11})); err != nil {
					t.Fatal(err)
				}
				body, code := ReadFrame(agent)
				if code != "" || len(body) == 0 || body[0] != 12 {
					t.Fatal("healthy shared agent refused")
				}
				return
			}
			body, code := ReadFrame(c)
			if code != "" {
				t.Fatal("audit fault did not promptly close", code)
			}
			if body != nil {
				obj, err := control.Decode(body)
				if err != nil {
					t.Fatal(err)
				}
				nativeResponse(t, obj, nativeID(2), "audit_unavailable")
			}
			select {
			case err := <-f.done:
				if err != Code("audit_unavailable") {
					t.Fatal("wrong dual service health", err)
				}
				f.cancel()
				f.cancel = nil
				f.stopped = true
			case <-time.After(time.Second):
				t.Fatal("audit fault left daemon admission open")
			}
			if !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("failed public request changed durable state")
			}
			for _, path := range []string{f.server.Path, f.server.ControlPath} {
				conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
				if err == nil {
					conn.Close()
					t.Fatal("audit fault left listener open")
				}
			}
		})
	}
}

// The active slot channel is shared, not one independent allowance per socket.
// Deterministic saturation exercises both real dispatch branches; draining it
// allows native hello/pubkey and agent identities through the same daemon.
func TestNativeSharedWorkBudget(t *testing.T) {
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
	f.start()
	for i := 0; i < cap(f.server.requests); i++ {
		f.server.requests <- struct{}{}
	}
	native := nativeDial(t, f.server.ControlPath)
	nativeSend(t, native, nativeHello(1))
	nativeResponse(t, nativeReceive(t, native), nil, "busy")
	agent := nativeDial(t, f.server.Path)
	if err := writeResponse(agent, Packet([]byte{11})); err != nil {
		t.Fatal(err)
	}
	response, code := ReadFrame(agent)
	if code != "" || !bytes.Equal(response, []byte{5}) {
		t.Fatal("agent evaded shared work budget")
	}
	for i := 0; i < cap(f.server.requests); i++ {
		<-f.server.requests
	}
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 3)
	nativeSend(t, fresh, nativeRequest(4, "pubkey", control.Object{}))
	nativeResponse(t, nativeReceive(t, fresh), nativeID(4), "")
	if err := writeResponse(agent, Packet([]byte{11})); err != nil {
		t.Fatal(err)
	}
	response, code = ReadFrame(agent)
	if code != "" || len(response) == 0 || response[0] != 12 {
		t.Fatal("agent control after shared saturation refused")
	}
}

// Duplicate mutations consume the separate 2/s burst-4 intake budget even
// though they recover one effect. Restored credit admits the same retained ID.
func TestNativeMutationRetryBudget(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	nativeTarget(f)
	f.engine.rateNow = func() time.Time { return time.Unix(1000000, 0) }
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	for i := 0; i < 4; i++ {
		nativeSend(t, c, nativeRegisterRequest(2))
		nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
	}
	before := nativeSnapshot(t, f)
	nativeSend(t, c, nativeRegisterRequest(2))
	nativeResponse(t, nativeReceive(t, c), nativeID(2), "rate_limited")
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("rate-limited retry changed state")
	}
	f.native.rateMu.Lock()
	f.native.mutations = map[Principal]*bucket{}
	f.native.rateMu.Unlock()
	nativeSend(t, c, nativeRegisterRequest(2))
	nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
	if len(f.store.Snapshot()) != 1 || f.store.next != 2 {
		t.Fatal("retry accounting duplicated effect")
	}
}

// Exhaustion of either shared work bucket refuses on both sockets. Resetting
// that bucket permits real native hello and agent identities on the same daemon.
func TestNativeSharedRateBudget(t *testing.T) {
	for _, scope := range []string{"global", "principal"} {
		t.Run(scope, func(t *testing.T) {
			b := nativeOwnBinding()
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
			now := time.Unix(1000000, 0)
			f.engine.rateNow = func() time.Time { return now }
			if scope == "global" {
				f.engine.global = bucket{last: now}
			} else {
				f.engine.peers[f.config.Operator] = &bucket{last: now}
			}
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeSend(t, c, nativeHello(1))
			nativeResponse(t, nativeReceive(t, c), nil, "rate_limited")
			agent := nativeDial(t, f.server.Path)
			if err := writeResponse(agent, Packet([]byte{11})); err != nil {
				t.Fatal(err)
			}
			body, code := ReadFrame(agent)
			if code != "" || !bytes.Equal(body, []byte{5}) {
				t.Fatal("agent evaded shared rate bucket")
			}
			f.engine.rateMu.Lock()
			f.engine.global = bucket{}
			f.engine.peers = map[Principal]*bucket{}
			f.engine.rateMu.Unlock()
			fresh := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, fresh, 2)
			if err := writeResponse(agent, Packet([]byte{11})); err != nil {
				t.Fatal(err)
			}
			body, code = ReadFrame(agent)
			if code != "" || len(body) == 0 || body[0] != 12 {
				t.Fatal("shared rate control refused")
			}
		})
	}
}

// Four connections on each socket exhaust one UID's eight-connection allowance;
// a ninth native connection closes before hello. Releasing an agent connection
// permits native admission. This is not a global-128-connection load test.
func TestNativeSharedConnectionBudget(t *testing.T) {
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
	f.start()
	var first *net.UnixConn
	for i := 0; i < 4; i++ {
		agent := nativeDial(t, f.server.Path)
		if i == 0 {
			first = agent
		}
		if err := writeResponse(agent, Packet([]byte{11})); err != nil {
			t.Fatal(err)
		}
		body, code := ReadFrame(agent)
		if code != "" || len(body) == 0 || body[0] != 12 {
			t.Fatal("agent connection control refused")
		}
		c := nativeDial(t, f.server.ControlPath)
		nativeNegotiate(t, c, 10+i)
	}
	c := nativeDial(t, f.server.ControlPath)
	body, code := ReadFrame(c)
	if code != "" || body != nil {
		t.Fatal("ninth mixed-surface connection did not close")
	}
	first.Close()
	deadline := time.Now().Add(time.Second)
	for {
		f.server.mu.Lock()
		count := f.server.counts[uint32(os.Getuid())]
		f.server.mu.Unlock()
		if count == 7 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed agent connection retained shared allowance")
		}
		time.Sleep(time.Millisecond)
	}
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 20)
}

// The reserved journal tail admits control or refusal evidence after ordinary
// agent credit is exhausted; agent success cannot consume it. A small isolated
// budget exercises the actual writer, not a 1 GiB journal/load qualification.
func TestNativeAuditReserve(t *testing.T) {
	for _, kind := range []string{"agent-success", "control-success", "agent-refusal"} {
		t.Run(kind, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			j := f.store.journal
			before := nativeAudit(t, j)
			j.mu.Lock()
			j.totalLimit = j.total + 4096
			j.reserve = 4096
			j.mu.Unlock()
			r := AuditRecord{Surface: "agent", Operation: "pubkey", Result: "success"}
			if kind == "control-success" {
				r.Surface = "control"
			}
			if kind == "agent-refusal" {
				code := Code("request_malformed")
				r.RefusalCode = &code
				r.Result = "refused"
			}
			got := j.Append(r)
			if kind == "agent-success" {
				if got != "audit_unavailable" || !j.failed || len(nativeAudit(t, j)) != len(before) {
					t.Fatal("agent success consumed reserved audit tail", got)
				}
				return
			}
			if got != "" || len(nativeAudit(t, j)) != len(before)+1 {
				t.Fatal("control/refusal reserve unavailable", got)
			}
		})
	}
}
