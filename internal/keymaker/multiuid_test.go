//go:build multiuid

package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/testwindow"
)

var windowToken = flag.String("keymaker-window-token", "", "non-secret test-run provenance")

func TestMain(m *testing.M) {
	if os.Getenv("KEYMAKER_TEST_CLIENT") == "1" {
		os.Exit(windowClient())
	}
	os.Exit(m.Run())
}

// Each foreign-UID client exits itself within five seconds, including when its
// runner disappears. It makes no child processes or filesystem writes.
func windowClient() int {
	timer := time.AfterFunc(5*time.Second, func() { os.Exit(124) })
	defer timer.Stop()
	uid, e := strconv.ParseUint(os.Getenv("KEYMAKER_CLIENT_UID"), 10, 32)
	if e != nil || uint32(uid) != uint32(os.Getuid()) || uid == 0 {
		return 1
	}
	public, e := base64.StdEncoding.DecodeString(os.Getenv("KEYMAKER_CLIENT_PUBLIC"))
	if e != nil || len(public) != 32 {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, e := dialer.DialContext(ctx, "unix", os.Getenv("KEYMAKER_CLIENT_SOCKET"))
	if e != nil {
		return 1
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	body := validBody(public, "git")
	if _, e = conn.Write(Packet(body)); e != nil {
		return 1
	}
	response, code := ReadFrame(conn)
	if code != "" {
		return 1
	}
	if os.Getenv("KEYMAKER_CLIENT_REFUSED") == "1" {
		if !bytes.Equal(response, []byte{5}) {
			return 1
		}
		return 0
	}
	if len(response) == 0 || response[0] != 14 {
		return 1
	}
	r := wireReader{b: response[1:]}
	blob := r.string()
	s := wireReader{b: blob}
	algorithm := s.string()
	signature := s.string()
	q, c := parseAgent(body)
	if c != "" || r.bad || len(r.b) != 0 || s.bad || len(s.b) != 0 || string(algorithm) != "ssh-ed25519" || !ed25519.Verify(public, q.data, signature) {
		return 1
	}
	return 0
}
func runWindowClient(t *testing.T, w testwindow.Window, user string, uid uint32, f *runningFixture, public []byte, refused bool) {
	t.Helper()

	expected := "0"
	if refused {
		expected = "1"
	}
	// Test expectations are environment inputs only; the service uses SO_PEERCRED.
	// sudo may reset environment. Explicit env arguments carry only public test
	// expectations; no -E privilege or policy change is required.
	args := []string{"-n", "-u", user, "--", "/usr/bin/env", "KEYMAKER_TEST_CLIENT=1", "KEYMAKER_CLIENT_UID=" + strconv.FormatUint(uint64(uid), 10), "KEYMAKER_CLIENT_SOCKET=" + f.server.Path, "KEYMAKER_CLIENT_PUBLIC=" + base64.StdEncoding.EncodeToString(public), "KEYMAKER_CLIENT_REFUSED=" + expected, os.Args[0], "-keymaker-window-token=" + *windowToken}
	cmd := exec.Command("sudo", args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("test client failed: %v %s", e, output)
	}
}
func lastJournalCode(t *testing.T, j *Journal) Code {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	f, e := openRelative(j.dir, auditName(j.segment), 0, j.uid, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	data, e := io.ReadAll(f)
	if e != nil {
		t.Fatal(e)
	}
	var record AuditRecord
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if json.Unmarshal(line, &record) != nil {
			t.Fatal("invalid audit record")
		}
	}
	if record.RefusalCode != nil {
		return *record.RefusalCode
	}
	return ""
}

// Real second-UID clients cannot use a foreign key, an unbound identity or a
// retired generation. Every negative precedes an independent active control.
// This suite is PENDING until the separately provisioned sudo window is verified.
func TestMultiUID(t *testing.T) {
	cfg, status, e := testwindow.Load(os.Getenv("KEYMAKER_WINDOW_CONFIG"))
	if e != nil {
		t.Fatalf("PENDING: test window not provisioned (runner status %d): %v", status, e)
	}
	w, status, e := testwindow.Verify(cfg, uint32(os.Getuid()), testwindow.CommandOutput)
	if e != nil {
		t.Fatalf("window status %d: %v", status, e)
	}
	for _, scenario := range []struct {
		name string
		code Code
	}{{"foreign-key", "sign_key_mismatch"}, {"unbound", "binding_not_found"}, {"retired", "generation_inactive"}} {
		t.Run(scenario.name, func(t *testing.T) {
			for _, negative := range []bool{true, false} {
				phase := "control"
				if negative {
					phase = "negative"
				}
				t.Run(phase, func(t *testing.T) {
					f := startRealFixture(t, w.AID)
					b := fixtureBinding(w.BID)
					b.Generation = "other-test-incarnation"
					b.Path = "m/1'/1'/1'/2'"
					g, _ := newGenerations(w.BID, b.Generation).Lookup(context.Background(), w.BID)
					if negative && scenario.name == "retired" {
						g.State = "retiring"
					}
					f.generation.mu.Lock()
					f.generation.entries[w.BID] = g
					f.generation.mu.Unlock()
					if !negative || scenario.name != "unbound" {
						if _, c := f.engine.Store.Register(fixtureOperator, fixtureOperator, b); c != "" {
							t.Fatal(c)
						}
					}
					own, c := f.engine.Signer.Public(b.Path)
					if c != "" {
						t.Fatal(c)
					}
					requested := own
					if negative && scenario.name == "foreign-key" {
						requested = f.public
					}
					before := f.engine.Store.Snapshot()
					runWindowClient(t, w, w.B, w.BID, f, requested, negative)
					want := Code("")
					if negative {
						want = scenario.code
					}
					if got := lastJournalCode(t, f.audit); got != want {
						t.Fatalf("audit refusal %q, expected %q", got, want)
					}
					if !reflect.DeepEqual(before, f.engine.Store.Snapshot()) {
						t.Fatal("client changed binding state")
					}
					runWindowClient(t, w, w.A, w.AID, f, f.public, false)
					select {
					case peer := <-f.seen:
						if peer.UID != w.BID {
							t.Fatal("second UID not authenticated by kernel")
						}
					case <-time.After(time.Second):
						t.Fatal(fmt.Sprint("no second UID peer"))
					}
				})
			}
		})
	}
}
