package control

import "testing"

// A7a-2 adds exactly eight non-retryable standings; it neither admits unknown
// codes nor changes any existing retryable standing or registers a method.
func TestMALiveControlCodes(t *testing.T) {
	for _, code := range []Code{"signer_preimage_too_large", "signer_tag_malformed", "signer_domain_refused", "signer_payload_invalid", "signer_identity_unavailable", "signer_identity_malformed", "signer_identity_mismatch", "message_author_unqualified"} {
		t.Run(string(code), func(t *testing.T) {
			if !validCode(code) || retryable(code) || !ValidRefusal(code, false) || ValidRefusal(code, true) {
				t.Fatal("message-author code closure or retryability changed", code)
			}
		})
	}
	for _, code := range []Code{"rate_limited", "busy", "generation_source_unavailable", "enrollment_unavailable", "audit_unavailable", DeadlineExceeded} {
		if !ValidRefusal(code, true) || ValidRefusal(code, false) {
			t.Fatal("existing retryable code changed", code)
		}
	}
	for _, code := range []Code{"message_author_unknown", "signer_payload_valid", "", "clock_untrusted"} {
		if retryable(code) {
			t.Fatal("retryable set widened", code)
		}
		if code != "clock_untrusted" && validCode(code) {
			t.Fatal("unknown code admitted", code)
		}
	}
}
