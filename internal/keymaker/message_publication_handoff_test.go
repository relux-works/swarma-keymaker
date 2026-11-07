package keymaker

import (
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/keymaker/publicationhandoff"
)

// No issuer fixture runs here: the helper accepts only an already formed
// internal certificate. Incomplete metadata and oversized carriers refuse.
func TestPreparedMessagePublicationRefusesIncomplete(t *testing.T) {
	for _, c := range []messageCertificate{
		{},
		{Transaction: "00112233445566778899aabbccddeeff", Envelope: strings.Repeat("A", 12000)},
		{Transaction: "00112233445566778899aabbccddeeff", Envelope: "e30"},
	} {
		h, err := preparedMessagePublication(c)
		if h != nil || !errors.Is(err, publicationhandoff.ErrInvalid) {
			t.Fatal("incomplete certificate accepted", err)
		}
	}
}
