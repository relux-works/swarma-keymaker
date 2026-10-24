package control

import "testing"

// Clock confidence failure is a terminal wire error; busy is the adjacent
// retryable control. The wire response uses this exact closed allowlist.
func TestTimeConfidenceNonRetryable(t *testing.T) {
	for _, code := range []Code{"clock_untrusted", "busy"} {
		if !validCode(code) || retryable(code) != (code == "busy") {
			t.Fatal("clock retry policy", code, retryable(code))
		}
	}
}
