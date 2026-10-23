package keymaker

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
)

// Without reload traffic, the same fixture's valid helper returns a proof
// verified against its enrolled key. This is the socket fairness control.
func TestHelperReloadFairnessControl(t *testing.T) {
	f, _ := helperSetup(t)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	helperCall(t, f, c, 2, "")
}

// Once helper preparation has entered the shared authority chain, concurrent
// pubkey traffic and the verified helper proof both succeed at the normal
// native budget. This checks valid concurrency independently of a 100ms refusal.
func TestHelperConcurrentPubkeyControl(t *testing.T) {
	f, tr := helperSetup(t)
	clock := &reviewHelperClockEntry{clock: tr.clock, entered: make(chan struct{})}
	builder, err := proof.New(clock, rand.Reader, registrationSigner{f.master, helperPath})
	if err != nil {
		t.Fatal(err)
	}
	tr.helper.builder = builder
	f.start()
	c, other := nativeDial(t, f.server.ControlPath), nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	nativeNegotiate(t, other, 2)
	nativeSend(t, c, helperRequest(3))
	select {
	case <-clock.entered:
	case <-time.After(time.Second):
		t.Fatal("helper did not reach authority")
	}
	nativeSend(t, other, nativeRequest(4, "pubkey", control.Object{}))
	helperResult(t, nativeReceive(t, c), nativeID(3), "", tr.helper.key)
	nativeResponse(t, nativeReceive(t, other), nativeID(4), "")
}
