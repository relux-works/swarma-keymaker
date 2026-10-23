package control

import "testing"

// An incident fence is a stable terminal generation failure, never retry advice
// or an arbitrary diagnostic. The normal writer-pending refusal stays retryable.
func TestGenerationSourceFencedContract(t *testing.T) {
	if !validCode("generation_source_fenced") || retryable("generation_source_fenced") || !generationFailure("generation_source_fenced") {
		t.Fatal("generation incident fence is not a stable nonretryable terminal refusal")
	}
	if !validCode("generation_source_unavailable") || !retryable("generation_source_unavailable") || !generationFailure("generation_source_unavailable") {
		t.Fatal("transient generation refusal control changed")
	}
	if validCode("generation_source_free_form") || generationFailure("generation_source_free_form") {
		t.Fatal("unknown generation diagnostic admitted")
	}
}
