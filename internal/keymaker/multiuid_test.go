//go:build multiuid

package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
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
		if os.Getenv("KEYMAKER_CLIENT_CONNECT_DENIED") == "1" && errors.Is(e, syscall.EACCES) {
			return 0
		}
		return 1
	}
	if os.Getenv("KEYMAKER_CLIENT_CONNECT_DENIED") == "1" {
		conn.Close()
		return 1
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if os.Getenv("KEYMAKER_CLIENT_SURFACE") == "control" {
		return windowNativeClient(conn, public)
	}
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

// Native clients validate the canonical wrapper, exact refusal or their own
// derived public key. No expectation can supply service authority.
func windowNativeClient(conn net.Conn, public []byte) int {
	exchange := func(obj control.Object) (control.Object, error) {
		body, err := control.Marshal(obj)
		if err != nil {
			return nil, err
		}
		for frame := Packet(body); len(frame) > 0; {
			n, err := conn.Write(frame)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("native write failed")
			}
			frame = frame[n:]
		}
		body, c := ReadFrame(conn)
		if c != "" || body == nil {
			return nil, fmt.Errorf("native read failed")
		}
		return control.Decode(body)
	}
	expected := os.Getenv("KEYMAKER_CLIENT_CODE")
	response, err := exchange(nativeHello(1))
	if err != nil {
		return 1
	}
	if expected == "generation_inactive" {
		if windowNativeError(response, nativeID(1), expected) {
			return 0
		}
		return 1
	}
	if len(response) != 2 || response["request_id"] != nativeID(1) {
		return 1
	}
	hello, ok := response["result"].(control.Object)
	if !ok || len(hello) != 1 || hello["version"] != int64(1) {
		return 1
	}
	response, err = exchange(nativeRequest(2, "pubkey", control.Object{}))
	if err != nil {
		return 1
	}
	if expected != "" {
		if windowNativeError(response, nativeID(2), expected) {
			return 0
		}
		return 1
	}
	result, ok := response["result"].(control.Object)
	if !ok || len(response) != 2 || response["request_id"] != nativeID(2) || !exactMembers(result, "public_key", "path", "registration_number", "master_epoch") {
		return 1
	}
	key, ok := result["public_key"].(string)
	decoded, err := base64.StdEncoding.DecodeString(key)
	if !ok || err != nil || !bytes.Equal(decoded, public) {
		return 1
	}
	return 0
}
func windowNativeError(response control.Object, id, code string) bool {
	e, ok := response["error"].(control.Object)
	return ok && len(response) == 2 && response["request_id"] == id && len(e) == 2 && e["code"] == code && e["retryable"] == false
}
func runNativeWindowClient(t *testing.T, w testwindow.Window, user string, uid uint32, f *nativeFixture, public []byte, code string, deny bool) {
	t.Helper()
	denied := "0"
	if deny {
		denied = "1"
	}
	args := []string{"-n", "-u", user, "--", "/usr/bin/env", "KEYMAKER_TEST_CLIENT=1", "KEYMAKER_CLIENT_SURFACE=control", "KEYMAKER_CLIENT_UID=" + strconv.FormatUint(uint64(uid), 10), "KEYMAKER_CLIENT_SOCKET=" + f.server.ControlPath, "KEYMAKER_CLIENT_PUBLIC=" + base64.StdEncoding.EncodeToString(public), "KEYMAKER_CLIENT_CODE=" + code, "KEYMAKER_CLIENT_CONNECT_DENIED=" + denied, os.Args[0], "-keymaker-window-token=" + *windowToken}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Logf("native window client PID=%d", cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("native window client failed: %v %s", err, output.Bytes())
	}
}

// Run the daemon as the same unprivileged runner with the provisioned helper
// group. Only A may connect; B's EACCES is a separate kernel-level assertion.
// The role command is already required by the shared window, never broadened.
func TestMultiUIDControl(t *testing.T) {
	cfg, status, err := testwindow.Load(os.Getenv("KEYMAKER_WINDOW_CONFIG"))
	if err != nil {
		t.Fatalf("PENDING: test window not provisioned (runner status %d): %v", status, err)
	}
	w, status, err := testwindow.Verify(cfg, uint32(os.Getuid()), testwindow.CommandOutput)
	if err != nil {
		t.Fatalf("window status %d: %v", status, err)
	}
	if uint32(os.Getgid()) != w.GroupID {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		args := []string{"-n", "-u", w.Runner, "-g", w.Group, "--", "/usr/bin/env", "KEYMAKER_WINDOW_CONFIG=" + os.Getenv("KEYMAKER_WINDOW_CONFIG"), "KEYMAKER_WINDOW_SCRATCH=" + os.Getenv("KEYMAKER_WINDOW_SCRATCH"), "TMPDIR=" + os.Getenv("TMPDIR"), os.Args[0], "-test.run=^TestMultiUIDControl$", "-test.timeout=30s", "-test.v", "-keymaker-window-token=" + *windowToken}
		cmd := exec.CommandContext(ctx, "sudo", args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Logf("native group test child PID=%d", cmd.Process.Pid)
		if err := cmd.Wait(); err != nil {
			t.Fatalf("native group suite failed: %v %s", err, output.Bytes())
		}
		t.Log(output.String())
		return
	}
	for _, scenario := range []string{"foreign-uid", "unbound", "retired"} {
		t.Run(scenario, func(t *testing.T) {
			for _, negative := range []bool{true, false} {
				phase := "control"
				if negative {
					phase = "negative"
				}
				t.Run(phase, func(t *testing.T) {
					binding := fixtureBinding(w.AID)
					binding.Generation = nativeToken
					var retained *Binding = &binding
					if negative && scenario == "foreign-uid" {
						other := binding
						other.UID = w.BID
						other.Path = "m/1'/1'/1'/2'"
						retained = &other
					}
					if negative && scenario == "unbound" {
						retained = nil
					}
					f := nativeBase(t, Principal{w.UID, nativeToken}, nil, retained)
					f.generation.entries[w.AID] = Generation{UID: w.AID, Generation: nativeToken, State: "active", Revision: "fixture-order", Provenance: "verified-fixture", Verified: true}
					if negative && scenario == "retired" {
						f.generation.set(w.AID, "retiring", nativeToken)
					}
					f.start()
					public, c := f.master.Public(binding.Path)
					if c != "" {
						t.Fatal(c)
					}
					before := f.store.Snapshot()
					expected := ""
					if negative {
						expected = "binding_not_found"
						if scenario == "retired" {
							expected = "generation_inactive"
						}
					}
					runNativeWindowClient(t, w, w.A, w.AID, f, public, expected, false)
					records := nativeAudit(t, f.store.journal)
					last := records[len(records)-1]
					if last.PeerUID == nil || *last.PeerUID != w.AID || last.Surface != "control" {
						t.Fatal("native kernel UID attribution missing")
					}
					if negative && (last.RefusalCode == nil || string(*last.RefusalCode) != expected) {
						t.Fatal("native multi-UID audit mismatch")
					}
					if !reflect.DeepEqual(before, f.store.Snapshot()) {
						t.Fatal("native client changed bindings")
					}
					runNativeWindowClient(t, w, w.B, w.BID, f, public, "", true)
					if after := nativeAudit(t, f.store.journal); len(after) != len(records) {
						t.Fatal("group-denied client reached daemon")
					}
				})
			}
		})
	}
}
