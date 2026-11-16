package control

import "testing"

// Claim: only the seven static-gate refusal codes are wire-safe and all are nonretryable.
func TestStaticGateCodes(t *testing.T) {
	for _, bad := range []Code{"STATIC_GATE_OTHER", "STATIC_GATE_WINDOW: window_now"} {
		if validCode(bad) {
			t.Fatal("unregistered static-gate diagnostic accepted")
		}
		for _, good := range []Code{"STATIC_GATE_KEY", "STATIC_GATE_PIN", "STATIC_GATE_FORM", "STATIC_GATE_SIGNATURE", "STATIC_GATE_HOST", "STATIC_GATE_WINDOW", "STATIC_GATE_SCOPE_MISMATCH"} {
			if !validCode(good) || retryable(good) {
				t.Fatal("static-gate code lost", good)
			}
		}
	}
}
