package keymaker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A syntactically valid partial restore must not erase a durable tombstone or
// reset audit continuity while the other store still contains later evidence.
// These are one-sided restores, not rollback of both stores together.
func TestSnapshotJournalDivergence(t *testing.T) {
	for _, mode := range []string{"snapshot-before-revoke", "snapshot-before-register", "snapshot-member-omitted", "journal-zeroed", "intact", "active-intact"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			dir, err := OpenDirectory(d, uid, 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			lock, err := LockState(dir, uid)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			s, j, ad, err := fixtureOpenCustodyState(dir, uid)
			if err != nil {
				t.Fatal("bootstrap", err)
			}
			snapshot := filepath.Join(d, "bindings.json")
			beforeRegister, err := os.ReadFile(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			b, c := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(uid))
			if c != "" {
				t.Fatal(c)
			}
			beforeRevoke, err := os.ReadFile(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "active-intact" {
				if c = s.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, approvedAct{}); c != "" {
					t.Fatal(c)
				}
			}
			code := Code("identity_revoked")
			masterDir := t.TempDir()
			os.Chmod(masterDir, 0700)
			seedPath := filepath.Join(masterDir, "fixture.seed")
			if err = os.WriteFile(seedPath, make([]byte, 32), 0600); err != nil {
				t.Fatal(err)
			}
			master, err := LoadMaster(seedPath, uid)
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			public, c := master.Public(b.Path)
			if c != "" {
				t.Fatal(c)
			}
			generation := newGenerations(b.UID, b.Generation)
			prior := NewEngine(s, generation, master, j)
			priorSession := prior.OpenSession(context.Background(), Peer{UID: b.UID})
			want := Code("identity_revoked")
			if mode == "active-intact" {
				want = ""
			}
			if c = prior.Handle(context.Background(), priorSession, validBody(public, "git"), func(_ context.Context, response []byte) error {
				if mode != "active-intact" {
					t.Fatal("revoked control released")
				}
				checkResponse(t, response, public, validBody(public, "git"))
				return nil
			}); c != want {
				t.Fatal("revoked control", c)
			}
			j.Close()
			ad.Close()
			switch mode {
			case "snapshot-before-revoke":
				err = os.WriteFile(snapshot, beforeRevoke, 0600)
			case "snapshot-before-register":
				err = os.WriteFile(snapshot, beforeRegister, 0600)
			case "snapshot-member-omitted":
				err = os.WriteFile(snapshot, []byte(`{"next_registration_number":2}`), 0600)
			case "journal-zeroed":
				err = os.Truncate(filepath.Join(d, "audit", auditName(1)), 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			s, j, ad, err = fixtureOpenCustodyState(dir, uid)
			if err != nil {
				if mode == "intact" || mode == "active-intact" {
					t.Fatal("intact control", err)
				}
				return
			}
			defer j.Close()
			defer ad.Close()
			if mode == "intact" {
				if _, c = s.Register(fixtureOperator, fixtureOperator, b); c != "identity_revoked" {
					t.Fatal("lost intact tombstone", c)
				}
				return
			}
			if mode == "snapshot-member-omitted" {
				next, c := s.Register(fixtureOperator, fixtureOperator, b)
				if c != "" {
					t.Fatal("unexpected refusal", c)
				}
				t.Fatalf("BYPASS: omitted records erased tombstone and re-registered revoked path as number=%d", next.Number)
			}
			if mode == "snapshot-before-register" {
				next, c := s.Register(fixtureOperator, fixtureOperator, b)
				if c != "" {
					t.Fatal("unexpected later refusal", c)
				}
				t.Fatalf("BYPASS: one-sided old snapshot resurrected revoked path and reused number=%d; retained journal seq=%d", next.Number, j.seq)
			}
			if mode == "snapshot-before-revoke" || mode == "active-intact" {
				// Recovered authority is exercised over a real Unix socket using
				// Linux SO_PEERCRED, the real Master and durable journal.
				e := NewEngine(s, generation, master, j)
				socketDir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "s-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(socketDir)
				os.Chmod(socketDir, 0755)
				server, err := NewServer(socketDir, e, LinuxPeer{})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- server.Serve(ctx) }()
				defer func() {
					cancel()
					if err := <-done; err != nil {
						t.Error(err)
					}
				}()
				conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: server.Path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				body := validBody(public, "git")
				if _, err = conn.Write(Packet(body)); err != nil {
					t.Fatal(err)
				}
				response, c := ReadFrame(conn)
				if c != "" {
					t.Fatal(c)
				}
				checkResponse(t, Packet(response), public, body)
				if mode == "active-intact" {
					return
				}
				t.Fatal("BYPASS: restored pre-revoke snapshot signed despite retained identity_revoked audit evidence")
			}
			if j.seq != 0 {
				t.Fatal("unexpected replay sequence", j.seq)
			}
			if c = j.Append(AuditRecord{Surface: "agent", Operation: "probe", Result: "refused", RefusalCode: &code}); c != "" {
				t.Fatal(c)
			}
			t.Fatalf("BYPASS: zeroed retained journal admitted populated tombstone snapshot and restarted audit at seq=%d", j.seq)
		})
	}
}
