package keymaker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func fixtureBinding(uid uint32) Binding {
	return Binding{UID: uid, Generation: "fixture-generation", Path: "m/1'/1'/1'/1'", Owner: "fixture-owner", Lifetime: "ephemeral", Epoch: "fixture-epoch", RegistryRevision: "fixture-revision"}
}

var fixtureOperator = Principal{UID: 1, Generation: "operator-incarnation"}

type approvedAct struct{}

func (approvedAct) VerifyEphemeral(context.Context, Binding) Code { return "" }

// Only the configured principal may create/revoke; uniqueness, tombstones and
// monotonic registration numbers survive reopening the durable store.
func TestBindingLifecycle(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	s, e := OpenStore(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	b := fixtureBinding(30001)
	if _, c := s.Register(Principal{}, fixtureOperator, b); c != "role_not_permitted" {
		t.Fatal(c)
	}
	if len(s.Snapshot()) != 0 {
		t.Fatal("denied registration mutated state")
	}
	b, c := s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" || b.Number != 1 {
		t.Fatal(c)
	}
	if _, c = s.Register(fixtureOperator, fixtureOperator, b); c != "binding_conflict" {
		t.Fatal(c)
	}
	if c = s.Revoke(context.Background(), Principal{}, fixtureOperator, b.Number, approvedAct{}); c != "role_not_permitted" {
		t.Fatal(c)
	}
	if c = s.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, nil); c != "operator_record_unavailable" {
		t.Fatal(c)
	}
	if c = s.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, approvedAct{}); c != "" {
		t.Fatal(c)
	}
	s, e = OpenStore(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	if _, c = s.Register(fixtureOperator, fixtureOperator, b); c != "identity_revoked" {
		t.Fatal("revoked path resurrected", c)
	}
	b.Path = "m/1'/1'/1'/2'"
	b.Generation = "fresh-generation"
	b, c = s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" || b.Number != 2 {
		t.Fatal(c)
	}
}

// Retirement is not persistent revocation; only explicit operator re-registration
// restores that key. Persistent revoke stays unavailable even with a test verifier.
func TestPersistentRetirement(t *testing.T) {
	s := NewStore()
	b := fixtureBinding(30001)
	b.Lifetime = "persistent"
	b, c := s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" {
		t.Fatal(c)
	}
	if c = s.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, approvedAct{}); c != "operator_record_unavailable" {
		t.Fatal(c)
	}
	if c = s.Unbind(fixtureOperator, fixtureOperator, b.UID, b.Generation); c != "" {
		t.Fatal(c)
	}
	b.Generation = "new-incarnation"
	next, c := s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" || next.Path != b.Path || next.Number == b.Number {
		t.Fatal("explicit persistent recovery failed", c)
	}
}

// Interrupted/corrupt state must not become an empty store on startup.
func TestBindingRecoveryFences(t *testing.T) {
	for _, name := range []string{"bindings.next", "bindings.json"} {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			os.Chmod(d, 0700)
			os.WriteFile(filepath.Join(d, name), []byte("invalid"), 0600)
			dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			if _, e = OpenStore(dir, uint32(os.Getuid())); e == nil {
				t.Fatal("invalid state treated as first use")
			}
		})
	}
}
