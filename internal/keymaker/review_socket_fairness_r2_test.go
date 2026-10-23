package keymaker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
)

// All inputs and every reload remain valid. A request already waiting for one
// reload must get an admission opportunity between later completed reloads.
// Once traffic stops, the exact request succeeds as the positive control.
func TestReviewR2SocketReloadFairness(t *testing.T) {
	f, tr := helperSetup(t)
	files, resume := helperReloadAuthority(t, f, tr)
	defer resume()
	clock := &reviewHelperClockEntry{clock: tr.clock, entered: make(chan struct{})}
	builder, err := proof.New(clock, &reviewHelperEntropy{}, registrationSigner{f.master, helperPath})
	if err != nil {
		t.Fatal(err)
	}
	tr.helper.builder = builder
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	files.armed.Store(true)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan struct{})
	var reloads atomic.Int32
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if code := tr.authority.Reload(context.Background()); code != "" {
				t.Error("reload", code)
				return
			}
			reloads.Add(1)
		}
	}()
	<-files.entered
	req := helperRequest(2)
	req["timeout_ms"] = int64(2000)
	started := time.Now()
	nativeSend(t, c, req)
	select {
	case <-clock.entered:
	case <-time.After(time.Second):
		resume()
		stop()
		<-done
		t.Fatal("request never reached authority")
	}
	resume()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, code := ReadFrame(c)
	stop()
	<-done
	if code != "" || raw == nil {
		t.Fatal("transport", code)
	}
	response, err := control.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("completed reloads=%d elapsed=%v response_error=%v", reloads.Load(), time.Since(started), response["error"])
	if response["error"] != nil {
		t.Error("valid helper starved by successive valid reloads")
	}
	if reloads.Load() < 2 {
		t.Fatal("reload traffic control absent")
	}
	// Retry the unchanged request through a fresh connection after traffic stops.
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 3)
	nativeSend(t, fresh, req)
	helperResult(t, nativeReceive(t, fresh), nativeID(2), "", tr.helper.key)
}
