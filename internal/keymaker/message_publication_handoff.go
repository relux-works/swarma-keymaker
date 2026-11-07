package keymaker

import (
	"encoding/base64"

	"github.com/relux-works/swarma-keymaker/internal/keymaker/publicationhandoff"
)

// preparedMessagePublication accepts only a previously prepared certificate.
// It has no issuer, master, store mutation, transport, or activation path.
// Before integration the caller must bind the exact retained certificate to
// its original durable transaction; this helper does not read that store.
func preparedMessagePublication(c messageCertificate) (*publicationhandoff.Handoff, error) {
	// Bound encoded input before the existing validator decodes/copies it.
	if !messageID(c.Transaction) || len(c.Envelope) > base64.RawURLEncoding.EncodedLen(publicationhandoff.MaxWireBytes) {
		return nil, publicationhandoff.ErrInvalid
	}
	if validateMessageCertificate(c) != nil {
		return nil, publicationhandoff.ErrInvalid
	}
	return publicationhandoff.Prepare(c.Transaction, c.Envelope, c.ContentID)
}
