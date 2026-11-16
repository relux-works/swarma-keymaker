package keymaker

import "github.com/relux-works/swarma-envelope/record"

// A private bytes plan conveys admission of original bytes, never currentness,
// generation, durable retry or final-write authority. No caller digest is used.
type messageAuthorPlan struct {
	original         []byte
	key, attestation string
}

func prepareMessageAuthor(original []byte, key, attestation string) (*messageAuthorPlan, Code) {
	_, err := record.AdmitSigner(original, record.IdentityPolicy{MultiAgent: true, Check: true, CallerKey: key, CallerAttestationID: attestation})
	if err != nil {
		if e, ok := err.(*record.Error); ok {
			return nil, Code(e.Code)
		}
		return nil, "signer_payload_invalid"
	}
	return &messageAuthorPlan{original: append([]byte(nil), original...), key: key, attestation: attestation}, ""
}
