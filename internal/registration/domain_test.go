package registration

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"github.com/relux-works/swarma-registrar/envelope"
	format "github.com/relux-works/swarma-registrar/registration"
)

// This fixed SSHSIG-v1 git preimage has independent standard SSH string framing
// and a positive Ed25519 signature control. Neither domain's signature verifies
// over the other preimage. This is not an SSH-agent transport qualification.
func TestSSHSIGDomainSeparation(t *testing.T) {
	f := setup(t)
	p := built(t, f)
	e, err := envelope.Parse(p.Envelope(), envelope.Registration)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("test-only git object"))
	ssh := []byte("SSHSIG")
	for _, field := range [][]byte{[]byte("git"), {}, []byte("sha512"), digest[:]} {
		ssh = binary.BigEndian.AppendUint32(ssh, uint32(len(field)))
		ssh = append(ssh, field...)
	}
	pub := f.key.Public().(ed25519.PublicKey)
	if ed25519.Verify(pub, ssh, e.Signature) {
		t.Fatal("registration signature verified as SSHSIG")
	}
	agent := ed25519.Sign(f.key, ssh)
	if !ed25519.Verify(pub, ssh, agent) {
		t.Fatal("SSHSIG positive control failed")
	}
	body, err := format.Verify(p.Envelope())
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := format.Build(*body, f.in.Enrolled.Audience)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := format.Assemble(canonical, agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = format.Verify(wrong); upstreamCode(t, err) != string(format.RegistrationSignatureInvalid) {
		t.Fatal("SSHSIG verified as registration proof", err)
	}
	if code := p.Recheck(context.Background()); code != "" {
		t.Fatal("registration control lost validity", code)
	}
}
