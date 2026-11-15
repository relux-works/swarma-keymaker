//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

type j7SignFixture struct {
	f        *j7StateFixture
	a        *j7RequestCustody
	gen      *fakeGenerations
	socket   string
	stop     context.CancelFunc
	done     chan error
	contract j7Contract
	raw      []byte
	public   string
}

func j7SigningSetup(t *testing.T) *j7SignFixture { return j7SigningSetupFence(t, nil) }
func j7SigningSetupFence(t *testing.T, fence func(*j7RequestCustody) control.ReleaseFence) *j7SignFixture {
	return j7SigningSetupOptions(t, fence, nil)
}
func j7SigningSetupOptions(t *testing.T, fence func(*j7RequestCustody) control.ReleaseFence, wrap func(net.Listener) net.Listener) *j7SignFixture {
	t.Helper()
	f := j7StateSetup(t)
	if c := f.store.migrateJ7Signing(t.Context(), j7Head(t, f.store)); c != "" {
		t.Fatal("signing migration", c)
	}
	k := j7Fixture(t, j7RequestRole)
	k.epoch = f.binding.Epoch
	k.registry = f.binding.RegistryRevision
	k.entropy = rand.Reader
	public, e := k.request(f.store, f.binding, nil)
	if e != nil {
		t.Fatal(e)
	}
	c := j7Contract{Profile: "swarma-trust-contract/1", Network: "regtest", Landlord: "id/test-owner", Agent: "id/test-executor", Grantee: hex.EncodeToString(public), Actions: []string{"instruct"}, Repos: []string{}, NotBefore: 1, NotAfter: 2000000000}
	raw, _ := j7Compact(c)
	p := f.table(1)
	p.Rows[0].Use = []string{}
	triple := j7ConsentTriple(raw)
	triple.AndUse = true
	p.Rows[0].Consent = []j7ConsentPermission{triple}
	f.publish(t, p)
	launcher := Principal{f.uid, nativeToken}
	g := newGenerations(f.uid, nativeToken)
	for _, p := range []Principal{{f.binding.UID, f.binding.Generation}, {f.uid + 200, "input-a"}, {f.uid + 201, "input-b"}} {
		g.entries[p.UID] = Generation{UID: p.UID, Generation: p.Generation, State: "active", Revision: "fixture", Provenance: "fixture-only", Verified: true}
	}
	l, e := newJ7Lifecycle(f.store, f.policy, g, launcher)
	if e != nil {
		t.Fatal(e)
	}
	a, e := newJ7RequestCustody(l, k, fixtureAuditClock{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	var release control.ReleaseFence = a
	if fence != nil {
		release = fence(a)
	}
	wire, e := control.New(a, a, a, release, a)
	if e != nil {
		t.Fatal(e)
	}
	address := fmt.Sprintf("@j7-signing-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
	listener, e := net.Listen("unix", address)
	if e != nil {
		t.Fatal(e)
	}
	if wrap != nil {
		listener = wrap(listener)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wire.Serve(ctx, listener); close(done) }()
	sf := &j7SignFixture{f: f, a: a, gen: g, socket: address, stop: cancel, done: done, contract: c, raw: raw, public: hex.EncodeToString(public)}
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("request server did not stop")
		}
	})
	return sf
}
func (f *j7SignFixture) dial(t *testing.T, id int) *net.UnixConn {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	nativeNegotiate(t, c, id)
	return c
}
func (f *j7SignFixture) bind(t *testing.T, c *net.UnixConn, id int, origin j7Origin, input uint32) string {
	t.Helper()
	args := j7BindArguments{Identity: f.f.binding.Number, Origin: &origin, Input: Principal{input, func() string {
		if input == f.f.uid+201 {
			return "input-b"
		}
		return "input-a"
	}()}}
	return j7Call(t, c, id, "j7_run_bind", j7Params(t, args), "")["run_id"].(string)
}
func j7TypedParams(t *testing.T, op string, obj any) control.Object {
	t.Helper()
	raw, e := j7Compact(obj)
	if e != nil {
		t.Fatal(e)
	}
	ev, _ := j7Compact(j7Evidence{Format: "keymaker-j7-evidence/1"})
	return control.Object{"operation": op, "object_b64": j7Encode64(raw), "evidence_b64": j7Encode64(ev)}
}
func (f *j7SignFixture) consent(t *testing.T) control.Object {
	return j7TypedParams(t, "consent_v3", j7ConsentInput{Contract: j7Encode64(f.raw)})
}
func j7ResultEvent(t *testing.T, obj control.Object) rental.Event {
	t.Helper()
	encoded, ok := obj["signed_object_b64"].(string)
	if !ok {
		t.Fatal("missing complete signed object")
	}
	raw, c := j7Decode64(encoded, 16384)
	if c != "" {
		t.Fatal(c)
	}
	var e rental.Event
	if c := j7StrictObject(raw, &e); c != "" {
		t.Fatal(c)
	}
	var preimage bytes.Buffer
	encoder := json.NewEncoder(&preimage)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes.TrimSuffix(preimage.Bytes(), []byte{'\n'}))
	if e.ID != hex.EncodeToString(digest[:]) || obj["object_id"] != e.ID || obj["public_key"] != e.Pubkey || !rental.VerifySignature(e.Pubkey, e.ID, e.Sig) {
		t.Fatal("independent NIP01/BIP340 verification")
	}
	b, _ := j7Compact(e)
	if string(b) != string(raw) {
		t.Fatal("signed bytes changed")
	}
	return e
}

// Real Unix/kernel launcher channels reach actual purpose-7 custody. Complete
// first consent needs no grant; retries disclose exactly the durable same event.
// Fixture generation evidence does not qualify P17 or distinct-UID isolation.
func TestJ7SigningFirstConsent(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	pub := j7Call(t, c, 3, "j7_pubkey", control.Object{}, "")
	if pub["public_key"] != f.public {
		t.Fatal("bound public key")
	}
	params := f.consent(t)
	result := j7Call(t, c, 4, "j7_sign", params, "")
	event := j7ResultEvent(t, result)
	if event.Kind != 8181 || event.Content != "" || len(event.Tags) != 4 || event.Tags[1][1] != j7Hash(f.raw) {
		t.Fatal("typed consent bytes")
	}
	retry := j7Call(t, c, 4, "j7_sign", params, "")
	if !reflect.DeepEqual(retry, result) {
		t.Fatal("retry re-signed consent")
	}
	f.f.store.mu.Lock()
	record := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4))
	valid := record != nil && record.Release == "released" && record.EventID == event.ID && len(f.f.store.j7Signing.Enrollments) == 0
	f.f.store.mu.Unlock()
	if !valid {
		t.Fatal("consent release continuity")
	}
}

// Profile/2, kind8186, v4, transport/raw/batch operations stay unavailable by
// name beside a valid profile/1 positive. Forbidden selectors remain malformed.
func TestJ7SigningClosedProfiles(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 10)
	f.bind(t, c, 11, f.f.origin, f.f.uid+200)
	for i, op := range []string{"delegation_request_v3", "kind8186", "invocation_v4", "consent_v4", "transport_message", "sign_child_grant", "raw_digest", "batch"} {
		j7Call(t, c, 20+i, "j7_sign", j7TypedParams(t, op, control.Object{}), "operation_unsupported")
	}
	bad := f.consent(t)
	bad["run_id"] = strings.Repeat("a", 32)
	j7Call(t, c, 30, "j7_sign", bad, "request_malformed")
	raw := strings.Replace(string(f.raw), "swarma-trust-contract/1", "swarma-trust-contract/2", 1)
	j7Call(t, c, 31, "j7_sign", j7TypedParams(t, "consent_v3", j7ConsentInput{Contract: j7Encode64([]byte(raw))}), "operation_unsupported")
	j7ResultEvent(t, j7Call(t, c, 32, "j7_sign", f.consent(t), ""))
	f.f.store.mu.Lock()
	count := len(f.f.store.j7Signing.Records)
	f.f.store.mu.Unlock()
	if count != 1 {
		t.Fatal("closed profile retained a result")
	}
}
