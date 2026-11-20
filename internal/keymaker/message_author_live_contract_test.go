package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

// Record key, author and current T are independent protected paths.
func TestMALiveRecordKeyEqualsOwnKey(t *testing.T) {
	f := newMALiveFixture(t)
	r := f.request()
	obj := maRecord(t, f.v)
	obj["key"] = "bip340:eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g"
	r.Preimage = maPre(t, obj)
	f.refusal(t, r, "signer_identity_mismatch", 0)
	f.control(t)
}

// Canonical claims are opaque, including text claiming another role's power.
// Their presence never changes binding/generation admission or the protocol.
func TestMALiveOpaqueClaimsGrantNothing(t *testing.T) {
	f := newMALiveFixture(t)
	obj := maRecord(t, f.v)
	obj["claims"] = map[string]any{"approver": true, "service": "root", "grant": "all", "device": "issuer", "root": true}
	r := f.request()
	r.Preimage = maPre(t, obj)
	out, c := f.call(t.Context(), r)
	if c != "" || out.Signature == nil || record.VerifySignature(f.v.Key, out.Signature.Signature, r.Preimage) != nil || f.calls.Load() != 1 {
		t.Fatal("opaque claims interpreted", c)
	}
	p := Principal{f.b.UID + 1, f.b.Generation}
	var got messageauthor.Response
	c = f.h.handle(t.Context(), p, r, func(_ context.Context, r messageauthor.Response) Code { got = r; return "" })
	if c != "message_author_unqualified" || got.Signature != nil || f.calls.Load() != 1 {
		t.Fatal("opaque claims granted binding", c)
	}
	t.Log("admitted opaque claims=1; unbound caller=1")
}

// Another UID and the same UID under a replacement generation each have a
// distinct own purpose-9 path. Neither can obtain the prior caller's result.
func TestMALivePrincipalIsolation(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprint(replacement), func(t *testing.T) {
			f := newMALiveFixture(t)
			first := f.control(t)
			b := f.b
			b.Number = 2
			b.Path = "m/1'/1'/2'/4'"
			if replacement {
				b.Generation = "replacement"
			} else {
				b.UID++
			}
			if c := f.h.store.enrollMALive(t.Context(), fixtureOperator, b); c != "" {
				t.Fatal(c)
			}
			public, c := f.h.key.publicSelected(f.h.store, b)
			if c != "" || public == f.v.Key {
				t.Fatal("distinct public control", c)
			}
			f.source.b = b
			f.source.tuple.Key = public
			f.h.generations = newGenerations(b.UID, b.Generation)
			p := Principal{b.UID, b.Generation}
			var out messageauthor.Response
			r := f.request()
			c = f.h.handle(t.Context(), p, r, func(_ context.Context, r messageauthor.Response) Code { out = r; return "" })
			if c != "signer_identity_mismatch" || out.Signature != nil || f.calls.Load() != 1 {
				t.Fatal("principal borrowed retained result", c)
			}
			obj := maRecord(t, f.v)
			obj["key"] = public
			obj["body"].(map[string]any)["author"] = public
			r.Preimage = maPre(t, obj)
			c = f.h.handle(t.Context(), p, r, func(_ context.Context, r messageauthor.Response) Code { out = r; return "" })
			if c != "" || out.Signature == nil || bytes.Equal(first.Signature.Signature, out.Signature.Signature) || record.VerifySignature(public, out.Signature.Signature, r.Preimage) != nil || f.calls.Load() != 2 {
				t.Fatal("own principal control", c)
			}
			t.Log("foreign retry invocation_count=1; distinct own result invocation_count=2")
		})
	}
}

// Both trusted START bounds are required. Envelope exp is opaque to the holder;
// the scripted sender, rather than this API, owns its expired-message retry stop.
func TestMALiveTimeScope(t *testing.T) {
	for _, edge := range []string{"expired", "lower", "upper"} {
		t.Run(edge, func(t *testing.T) {
			f := newMALiveFixture(t)
			from, until := f.source.from, f.source.until
			switch edge {
			case "expired":
				f.source.until = f.at.Lower
			case "lower":
				f.source.from = f.at.Now
			case "upper":
				f.source.until = f.at.Upper
			}
			f.refusal(t, f.request(), "message_author_unqualified", 0)
			if f.h.store.maLive.Fenced {
				t.Fatal("time/source refusal latched fence")
			}
			f.source.from, f.source.until = from, until
			// The historical message exp is before this fixture's trusted time; admission
			// of the unmodified P is the positive control for the holder's time scope.
			f.control(t)
		})
	}
}

// Missing/temporary generation evidence never manufactures active identity and
// never changes a durable fence. A fresh authoritative fixture restores access.
func TestMALiveRequiredGeneration(t *testing.T) {
	raw, e := os.ReadFile("../../packaging/message-author.example.json")
	if e != nil {
		t.Fatal(e)
	}
	var o map[string]any
	if e = json.Unmarshal(raw, &o); e != nil {
		t.Fatal(e)
	}
	delete(o, "generation_journal")
	raw, e = json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := ParseConfig(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if e = serveMALive(t.Context(), cfg, nil, maLiveServiceDeps{}); e != Code("generation_source_unavailable") {
		t.Fatal("missing generation source did not refuse startup", e)
	}
	f := newMALiveFixture(t)
	f.h.generations = nil
	f.refusal(t, f.request(), "generation_source_unavailable", 0)
	if f.h.store.maLive.Fenced {
		t.Fatal("temporary source absence fenced")
	}
	f.h.generations = newGenerations(f.b.UID, f.b.Generation)
	f.control(t)
	f.h.store.maLive.Fenced = true
	f.h.generations = nil
	f.refusal(t, f.request(), "message_author_unqualified", 1)
}

// Boundary arithmetic is tested directly; row-count admission uses a populated
// index with a real retained result and dead row. This is not a 65K-history
// durability/soak qualification, and the byte bound is not a disk-fill test.
func TestMALiveCapacityAndRate(t *testing.T) {
	t.Run("connections-slots", func(t *testing.T) {
		if !maLiveConnectionRoom(31, 3) || maLiveConnectionRoom(32, 3) || maLiveConnectionRoom(31, 4) {
			t.Fatal("connection limits widened")
		}
		s := newMALiveServer(nil)
		if cap(s.slots) != 16 {
			t.Fatal("request slot limit widened")
		}
		for i := 0; i < 16; i++ {
			select {
			case s.slots <- struct{}{}:
			default:
				t.Fatal("valid slot refused")
			}
		}
		select {
		case s.slots <- struct{}{}:
			t.Fatal("seventeenth request admitted")
		default:
		}
	})
	t.Run("state-bytes", func(t *testing.T) {
		if !maLiveStateRoom((maLiveStateLimit-maLiveStateOverhead)/3) || maLiveStateRoom((maLiveStateLimit-maLiveStateOverhead)/3+1) || maLiveStateRoom(-1) {
			t.Fatal("state byte limit widened")
		}
	})
	t.Run("peer-and-sign-rate", func(t *testing.T) {
		now := time.Unix(2000000000, 0)
		b := &maLiveBudget{now: func() time.Time { return now }}
		p := Principal{1, "a"}
		for i := 0; i < 4; i++ {
			if c := b.charge(p, true); c != "" {
				t.Fatal("valid sign burst", c)
			}
		}
		if c := b.charge(p, true); c != "rate_limited" {
			t.Fatal("fifth sign admitted", c)
		}
		now = now.Add(500 * time.Millisecond)
		if c := b.charge(p, true); c != "" {
			t.Fatal("2/s sign neighbor", c)
		}
		b = &maLiveBudget{now: func() time.Time { return now }}
		for i := 0; i < 40; i++ {
			if c := b.charge(p, false); c != "" {
				t.Fatal("valid general burst", c)
			}
		}
		if c := b.charge(p, false); c != "rate_limited" {
			t.Fatal("forty-first peer request admitted", c)
		}
		now = now.Add(50 * time.Millisecond)
		if c := b.charge(p, false); c != "" {
			t.Fatal("20/s peer neighbor", c)
		}
	})
	t.Run("global-rate", func(t *testing.T) {
		now := time.Unix(2000000000, 0)
		b := &maLiveBudget{now: func() time.Time { return now }}
		for i := 0; i < 256; i++ {
			if c := b.charge(Principal{uint32(i), "g"}, false); c != "" {
				t.Fatal("valid global burst", c)
			}
		}
		if c := b.charge(Principal{999, "g"}, false); c != "rate_limited" {
			t.Fatal("257th global request admitted", c)
		}
		now = now.Add(5 * time.Millisecond)
		if c := b.charge(Principal{999, "g"}, false); c != "" {
			t.Fatal("200/s neighbor", c)
		}
	})
	t.Run("duplicate-charged", func(t *testing.T) {
		f := newMALiveFixture(t)
		now := time.Now()
		f.h.budget = &maLiveBudget{now: func() time.Time { return now }}
		f.control(t)
		for i := 0; i < 3; i++ {
			f.control(t)
		}
		f.refusal(t, f.request(), "rate_limited", 1)
		now = now.Add(500 * time.Millisecond)
		f.control(t)
	})
	t.Run("audit-data-reserve", func(t *testing.T) {
		f := newMALiveFixture(t)
		j := f.h.store.journal
		if j.segmentLimit != 64<<20 || j.totalLimit-j.reserve != 1<<30 || j.reserve != 16<<20 {
			t.Fatal("audit capacity constants changed")
		}
		j.totalLimit = j.total + j.reserve + messageAuditReserve - 1
		f.refusal(t, f.request(), "audit_unavailable", 0)
		if len(f.h.store.maLive.Attempts) != 0 {
			t.Fatal("intent admitted using audit control reserve")
		}
		j.totalLimit = (1 << 30) + (16 << 20)
		f.control(t)
	})
}
func TestMALiveRetentionNoEviction(t *testing.T) {
	f := newMALiveFixture(t)
	first := f.control(t)
	s := f.h.store
	retained := s.maLive.Attempts[0]
	dead := retained
	dead.ID = strings.Repeat("d", 32)
	dead.Status = "dead"
	dead.Signature = nil
	dead.SuccessSeq = 0
	dead.SuccessHash = ""
	s.maLive.Attempts = make([]maLiveAttempt, maLiveAttemptLimit)
	s.maLive.Attempts[0] = retained
	s.maLive.Attempts[1] = dead
	for i := 2; i < len(s.maLive.Attempts); i++ {
		a := dead
		a.ID = fmt.Sprintf("%032x", i)
		s.maLive.Attempts[i] = a
	}
	if e := s.validateMALive(); e != nil {
		t.Fatal(e)
	}
	if c := s.persistMALive(t.Context()); c != "" {
		t.Fatal(c)
	}
	last := s.maLive.Attempts[len(s.maLive.Attempts)-1].ID
	r := f.request()
	r.ID = strings.Repeat("e", 32)
	f.refusal(t, r, "state_capacity_exceeded", 1)
	if len(s.maLive.Attempts) != maLiveAttemptLimit || s.maLive.Attempts[0].ID != retained.ID || s.maLive.Attempts[1].Status != "dead" || s.maLive.Attempts[len(s.maLive.Attempts)-1].ID != last || !bytes.Equal(s.maLive.Attempts[0].Signature, first.Signature.Signature) {
		t.Fatal("capacity evicted evidence")
	}
	// Replay at the actual retained cap, without shrinking or evicting history.
	f.control(t)
}

// Retirement and the actual callback use the same Store barrier. A retirement
// that wins the gap suppresses bytes; a callback that wins is never recalled.
func TestMALiveWithdrawalBarrier(t *testing.T) {
	t.Run("retire-before-callback", func(t *testing.T) {
		f := newMALiveFixture(t)
		f.source.before = func(n int) {
			if n == 2 {
				if c := f.h.store.retireMALive(t.Context(), fixtureOperator, f.b.Number); c != "" {
					t.Error(c)
				}
			}
		}
		f.refusal(t, f.request(), "message_author_unqualified", 1)
		if f.h.store.maLive.Attempts[0].Status != "dead" {
			t.Fatal("retirement did not kill retained result")
		}
		newMALiveFixture(t).control(t)
	})
	t.Run("callback-before-retire", func(t *testing.T) {
		f := newMALiveFixture(t)
		inside, release, retired := make(chan struct{}), make(chan struct{}), make(chan Code, 1)
		delivered := make(chan Code, 1)
		go func() {
			delivered <- f.h.handle(t.Context(), Principal{f.b.UID, f.b.Generation}, f.request(), func(context.Context, messageauthor.Response) Code { close(inside); <-release; return "" })
		}()
		select {
		case <-inside:
		case <-time.After(3 * time.Second):
			t.Fatal("callback not reached")
		}
		started := make(chan struct{})
		go func() { close(started); retired <- f.h.store.retireMALive(t.Context(), fixtureOperator, f.b.Number) }()
		<-started
		select {
		case c := <-retired:
			t.Fatal("retirement crossed actual callback", c)
		case <-time.After(20 * time.Millisecond):
		}
		close(release)
		if c := <-delivered; c != "" {
			t.Fatal("callback-first control", c)
		}
		if c := <-retired; c != "" {
			t.Fatal(c)
		}
		f.refusal(t, f.request(), "message_author_unqualified", 1)
		t.Log("callback-first invocation_count=1; retired retry invocation_count=1")
	})
	t.Run("renew-before-release", func(t *testing.T) {
		f := newMALiveFixture(t)
		f.source.before = func(n int) {
			if n == 3 {
				f.source.tuple.T = "sha256:" + strings.Repeat("b", 64)
			}
		}
		f.refusal(t, f.request(), "signer_identity_mismatch", 1)
		if f.h.store.maLive.Attempts[0].Status != "dead" {
			t.Fatal("renewal not observed at actual callback")
		}
		newMALiveFixture(t).control(t)
	})
	t.Run("expire-before-release", func(t *testing.T) {
		f := newMALiveFixture(t)
		f.source.before = func(n int) {
			if n == 3 {
				f.source.until = f.at.Upper
			}
		}
		f.refusal(t, f.request(), "message_author_unqualified", 1)
		if f.h.store.maLive.Attempts[0].Status != "handoff_unknown" {
			t.Fatal("temporary unqualified source destroyed result")
		}
		newMALiveFixture(t).control(t)
	})
}

// Packaging is checked as source. No installer, service or protected host file
// is touched. Head-path selection remains an explicit installer prerequisite.
func TestMALivePackagingContract(t *testing.T) {
	raw, e := os.ReadFile("../../packaging/message-author.example.json")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := ParseConfig(bytes.NewReader(raw))
	if e != nil || cfg.maLive == nil {
		t.Fatal("packaging config control", e)
	}
	m := cfg.maLive
	if m.State.Minimum != 8 || m.Socket.Dir != "/run/swarma-keymaker-ma" || m.Socket.Group == 0 || m.State.Head != "/REPLACE_WITH_INSTALLER_SELECTED_PROTECTED_MA_HEAD" {
		t.Fatal("packaging custody contract drift")
	}
	unit, e := os.ReadFile("../../packaging/swarma-keymaker-message-author.service")
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range []string{"User=swarma-keymaker-ma\n", "Group=swarma-keymaker-ma\n", "ExecStart=/usr/local/bin/keymaker serve --config /etc/swarma-keymaker-ma/config.json\n", "RuntimeDirectoryMode=0755\n", "NoNewPrivileges=yes\n", "ProtectSystem=strict\n", "ProtectHome=yes\n", "RestrictAddressFamilies=AF_UNIX\n", "CapabilityBoundingSet=\n", "AmbientCapabilities=\n", "LimitCORE=0\n", "ReadWritePaths=/var/lib/swarma-keymaker-ma/state /run/swarma-keymaker-ma\n", "Configuration is root-owned 0640"} {
		if !strings.Contains(string(unit), line) {
			t.Fatal("packaging hardening contract missing", line)
		}
	}
	pin := []byte(`{"expected_version":1,"expected_digest":"` + strings.Repeat("a", 64) + `"}` + "\n")
	if _, e := decodeJ7Head(pin); e != nil {
		t.Fatal("head grammar control", e)
	}
	if _, e := decodeJ7Head(bytes.TrimSuffix(pin, []byte("\n"))); e == nil {
		t.Fatal("noncanonical head accepted")
	}
	// A service-owned fixture file cannot act as a root-owned protected pin.
	path := t.TempDir() + "/head"
	if e := os.WriteFile(path, pin, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := protectedJ7Head(path); e == nil {
		t.Fatal("unprotected expected head admitted")
	}
	changed := strings.Replace(string(raw), `"minimum_reader_schema": 8`, `"minimum_reader_schema": 6`, 1)
	if _, e := ParseConfig(strings.NewReader(changed)); e == nil {
		t.Fatal("old schema floor accepted")
	}
	changed = strings.Replace(string(raw), `"max_sync_age_ns": 2048000000000`, `"max_sync_age_ns": 2048000000001`, 1)
	if _, e := ParseConfig(strings.NewReader(changed)); e == nil {
		t.Fatal("looser time policy accepted")
	}
	t.Log("source-only packaging/head checks; invocation_count=0; protected root-owned positive permission fixture remains privileged qualification")
}
func TestMALiveLegacyIsolation(t *testing.T) {
	TestMessageAuthorRuntimeStaysClosed(t)
	TestMessageAuthorSourceIsolation(t)
	t.Log("legacy guards retained unchanged; message-author invocation_count=0")
}

// Terminal generation loss marks an existing result dead; temporary evidence
// failure leaves it recoverable and never invents a healthy current provider.
func TestMALiveTerminalGenerationLoss(t *testing.T) {
	f := newMALiveFixture(t)
	f.control(t)
	g := f.h.generations.(*fakeGenerations)
	g.mu.Lock()
	entry := g.entries[f.b.UID]
	entry.State = "removed"
	g.entries[f.b.UID] = entry
	g.mu.Unlock()
	f.refusal(t, f.request(), "message_author_unqualified", 1)
	if f.h.store.maLive.Attempts[0].Status != "dead" {
		t.Fatal("terminal generation loss retained releasable result")
	}
	newMALiveFixture(t).control(t)
}

// O10's joint corpus is optional only while the actual upstream files are
// absent. Never invent it or silently treat an appeared, unchecked corpus green.
func TestMALiveContractManifest(t *testing.T) {
	const path = "../../messageauthor/testdata/m2-contract-v1/"
	_, payload := os.Stat(path + "m2-contract-v1.json")
	_, manifest := os.Stat(path + "manifest.json")
	if os.IsNotExist(payload) && os.IsNotExist(manifest) {
		t.Skip("not produced: upstream O10 payload and manifest absent; historical wire-v1 fixtures remain unchanged")
	}
	t.Fatal("O10 corpus appeared: requires its actual accepted payload/manifest identity and holder oracle before claiming coverage")
}

// A retained result cannot survive proven root-identity replacement. Restore of
// the old root does not resurrect its terminal row; an independent holder signs.
func TestMALiveTerminalCustodyIdentity(t *testing.T) {
	for _, field := range []string{"instance", "epoch", "registry", "seed"} {
		t.Run(field, func(t *testing.T) {
			f := newMALiveFixture(t)
			f.control(t)
			k := f.h.key
			old := k.instance
			seedByte := k.seed[0]
			if field == "seed" {
				// Alter only this mapped copy of the public fixture root.
				k.seed[0] ^= 1
			} else if field == "epoch" {
				old = k.epoch
				k.epoch = "replacement"
			} else if field == "registry" {
				old = k.registry
				k.registry = "replacement"
			} else {
				k.instance = "replacement"
			}
			f.refusal(t, f.request(), "message_author_unqualified", 1)
			if f.h.store.maLive.Attempts[0].Status != "dead" {
				t.Fatal("custody identity loss retained live result")
			}
			if field == "seed" {
				k.seed[0] = seedByte
			} else if field == "epoch" {
				k.epoch = old
			} else if field == "registry" {
				k.registry = old
			} else {
				k.instance = old
			}
			f.refusal(t, f.request(), "message_author_unqualified", 1)
			newMALiveFixture(t).control(t)
		})
	}
}
