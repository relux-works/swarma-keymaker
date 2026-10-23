package keymaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type observedPeer struct{ seen chan Peer }

func (p observedPeer) Credentials(c *net.UnixConn) (Peer, Code) {
	v, code := (LinuxPeer{}).Credentials(c)
	if code == "" {
		select {
		case p.seen <- v:
		default:
		}
	}
	return v, code
}

// Already admitted real connections are closed when a binding is revoked or its
// generation retires/changes. The preceding public response is a positive control;
// the in-flight signature ordering and precise codes are tested in ReleaseFences.
func TestLiveConnectionInvalidation(t *testing.T) {
	for _, change := range []string{"revoke", "retire", "reuse"} {
		t.Run(change, func(t *testing.T) {
			f := startRealFixture(t)
			c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.server.Path, Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			if _, e = c.Write(Packet([]byte{11})); e != nil {
				t.Fatal(e)
			}
			body, code := ReadFrame(c)
			if code != "" || len(body) == 0 || body[0] != 12 {
				t.Fatal("positive identity control failed", code)
			}
			uid := uint32(os.Getuid())
			b := f.engine.Store.Snapshot()[0]
			switch change {
			case "revoke":
				if code = f.engine.Store.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, approvedAct{}); code != "" {
					t.Fatal(code)
				}
			case "retire":
				f.generation.set(uid, "retiring", b.Generation)
			case "reuse":
				f.generation.set(uid, "active", "replacement")
			}
			var next [1]byte
			if n, err := c.Read(next[:]); n != 0 || err != io.EOF {
				t.Fatalf("old connection survived: n=%d err=%v", n, err)
			}
		})
	}
}

// A second holder cannot open the same protected state; releasing the first lock
// permits a new holder without creating a file in the state directory.
func TestStateLock(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	first, e := LockState(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	if second, err := LockState(dir, uint32(os.Getuid())); err == nil {
		second.Close()
		t.Fatal("duplicate state owner")
	}
	first.Close()
	second, e := LockState(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	second.Close()
}

type runningFixture struct {
	server     *Server
	engine     *Engine
	generation *fakeGenerations
	public     []byte
	audit      *Journal
	seen       chan Peer
}

func startRealFixture(t *testing.T, overrideUID ...uint32) *runningFixture {
	t.Helper()
	state := t.TempDir()
	os.Chmod(state, 0700)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	seedPath := filepath.Join(state, "master.seed")
	if e := os.WriteFile(seedPath, seed, 0600); e != nil {
		t.Fatal(e)
	}
	master, e := LoadMaster(seedPath, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { master.Close() })
	auditPath := filepath.Join(state, "audit")
	os.Mkdir(auditPath, 0700)
	auditDir, e := OpenDirectory(auditPath, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	audit, e := OpenJournal(auditDir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { audit.Close(); auditDir.Close() })
	s := NewStore()
	uid := uint32(os.Getuid())
	if len(overrideUID) > 0 {
		uid = overrideUID[0]
	}
	b := fixtureBinding(uid)
	b, c := s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" {
		t.Fatal(c)
	}
	g := newGenerations(b.UID, b.Generation)
	engine := NewEngine(s, g, master, audit)
	socketDir, e := os.MkdirTemp(os.Getenv("TMPDIR"), "socket-")
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(socketDir, 0755)
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	seen := make(chan Peer, 128)
	server, e := NewServer(socketDir, engine, observedPeer{seen})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			var want error
			if engine.closed.Load() {
				want = Code("audit_unavailable")
			}
			if e != want {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("fixture did not stop")
		}
	})
	public, c := master.Public(b.Path)
	if c != "" {
		t.Fatal(c)
	}
	return &runningFixture{server, engine, g, public, audit, seen}
}

// An actual audit append failure closes all listeners/connections without a
// signature or state mutation and returns the bounded service-health code. Normal
// socket/signing controls are exercised by TestRealClients on the same server.
func TestAuditFailureClosesListener(t *testing.T) {
	f := startRealFixture(t)
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.server.Path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	f.audit.mu.Lock()
	f.audit.writer = &faultFile{file: f.audit.file, writeFail: true}
	f.audit.mu.Unlock()
	before := f.engine.Store.Snapshot()
	if _, e = c.Write(Packet(validBody(f.public, "git"))); e != nil {
		t.Fatal(e)
	}
	body, _ := ReadFrame(c)
	if len(body) != 0 && !bytes.Equal(body, []byte{5}) {
		t.Fatal("audit failure released response")
	}
	// EOF proves the connection is invalidated; listener closure precedes it.
	var next [1]byte
	if n, err := c.Read(next[:]); n != 0 || err != io.EOF {
		t.Fatal("audit failure kept connection", n, err)
	}
	if !f.engine.closed.Load() || !reflect.DeepEqual(before, f.engine.Store.Snapshot()) {
		t.Fatal("audit closure invariant")
	}
	other, err := net.DialTimeout("unix", f.server.Path, time.Second)
	if err == nil {
		other.Close()
		t.Fatal("listener remained open after audit failure")
	}
}

// Environment is constructed from an allowlist: no inherited Git variables,
// SSH identities, HOME, command overrides or system/global Git configuration.
func isolatedEnv(home, socket string) []string {
	return []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "SSH_AUTH_SOCK=" + socket, "LC_ALL=C", "LANG=C"}
}
func clientCommand(t *testing.T, dir string, env []string, input []byte, name string, args ...string) []byte {
	t.Helper()
	path, e := exec.LookPath(name)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(path, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(input)
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("%s failed: %v: %s", name, e, output)
	}
	return output
}

// Real SO_PEERCRED and stock OpenSSH/Git use only a derived public fixture key.
// The client environment never accesses host signing configuration or ~/.ssh.
// Negative namespace/raw requests share the same live kernel/socket boundary.
func TestRealClients(t *testing.T) {
	f := startRealFixture(t)
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.server.Path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case peer := <-f.seen:
		if peer.UID != uint32(os.Getuid()) {
			t.Fatal("kernel peer UID mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("no real peer credential")
	}
	before := f.engine.Store.Snapshot()
	for _, body := range [][]byte{validBody(f.public, "file"), append(append(append([]byte{13}, SSHString(PublicBlob(f.public))...), SSHString([]byte("raw message"))...), 0, 0, 0, 0)} {
		if _, e = conn.Write(Packet(body)); e != nil {
			t.Fatal(e)
		}
		reply, c := ReadFrame(conn)
		if c != "" || !bytes.Equal(reply, []byte{5}) {
			t.Fatal("forbidden request accepted", c)
		}
	}
	if !reflect.DeepEqual(before, f.engine.Store.Snapshot()) {
		t.Fatal("negative socket request mutated binding")
	}
	conn.Close()
	home := t.TempDir()
	repo := t.TempDir()
	env := isolatedEnv(home, f.server.Path)
	publicText := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(PublicBlob(f.public))
	pubfile := filepath.Join(repo, "fixture.pub")
	os.WriteFile(pubfile, []byte(publicText+"\n"), 0600)
	allowed := filepath.Join(repo, "allowed-signers")
	os.WriteFile(allowed, []byte("fixture@example.invalid namespaces=\"git\" "+publicText+"\n"), 0600)
	message := []byte("public fixture message\n")
	messagePath := filepath.Join(repo, "message")
	os.WriteFile(messagePath, message, 0600)
	clientCommand(t, repo, env, nil, "ssh-keygen", "-Y", "sign", "-U", "-n", "git", "-f", pubfile, messagePath)
	clientCommand(t, repo, env, message, "ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "fixture@example.invalid", "-n", "git", "-s", messagePath+".sig")
	clientCommand(t, repo, env, nil, "git", "init", "--quiet")
	for _, pair := range [][2]string{{"user.name", "Fixture Author"}, {"user.email", "fixture@example.invalid"}, {"gpg.format", "ssh"}, {"user.signingkey", "key::" + publicText}, {"gpg.ssh.allowedSignersFile", allowed}} {
		clientCommand(t, repo, env, nil, "git", "config", "--local", pair[0], pair[1])
	}
	configured := strings.TrimSpace(string(clientCommand(t, repo, env, nil, "git", "config", "--get", "user.signingkey")))
	if configured != "key::"+publicText {
		t.Fatal("non-fixture signing key selected")
	}
	// Git's allowed-signers verification checks the exact derived key and identity;
	// success by any inherited host signing key cannot satisfy this assertion.
	clientCommand(t, repo, env, nil, "git", "add", "--", "message")
	clientCommand(t, repo, env, nil, "git", "-c", "core.hooksPath=/dev/null", "commit", "-S", "--quiet", "-m", "Public fixture")
	verified := string(clientCommand(t, repo, env, nil, "git", "verify-commit", "HEAD"))
	if !strings.Contains(verified, "Good") || !strings.Contains(verified, "fixture@example.invalid") {
		t.Fatal("fixture commit not verified")
	}
	fingerprint := sha256.Sum256(PublicBlob(f.public))
	expectedFingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(fingerprint[:])
	if !strings.Contains(verified, expectedFingerprint) {
		t.Fatal("a non-fixture signing key was used")
	}
}

// Unsafe existing paths and a second instance refuse without overwriting; normal
// shutdown removes only the inode created by this server.
func TestSocketGuards(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "unsafe-parent", "second-instance"} {
		t.Run(kind, func(t *testing.T) {
			d, e := os.MkdirTemp(os.Getenv("TMPDIR"), "socket-")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(d)
			os.Chmod(d, 0755)
			e1, _, _, _, _ := fixtureEngine(t)
			switch kind {
			case "file":
				os.WriteFile(filepath.Join(d, "agent.sock"), []byte("keep"), 0600)
			case "symlink":
				os.Symlink("missing", filepath.Join(d, "agent.sock"))
			case "unsafe-parent":
				os.Chmod(d, 0777)
			case "second-instance":
				first, err := NewServer(d, e1, LinuxPeer{})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { first.Close(); first.cleanup() }()
			}
			if server, err := NewServer(d, e1, LinuxPeer{}); err == nil {
				server.Close()
				server.cleanup()
				t.Fatal("unsafe/duplicate socket accepted")
			}
			if kind == "file" {
				b, _ := os.ReadFile(filepath.Join(d, "agent.sock"))
				if string(b) != "keep" {
					t.Fatal("pre-existing path changed")
				}
			}
		})
	}
}

// Fatal frame limits reject before response allocation; complete nearby frames
// succeed. Truncation requires EOF, rather than a timeout masquerading as EOF.
func TestAgentFrameBounds(t *testing.T) {
	for _, sample := range []struct {
		raw  []byte
		code Code
	}{{[]byte{0, 1, 0, 1}, "frame_too_large"}, {[]byte{0, 0, 0, 0}, "frame_malformed"}, {[]byte{0, 0}, "frame_truncated"}, {[]byte{0, 0, 0, 2, 11}, "frame_truncated"}, {Packet([]byte{11}), ""}} {
		_, c := ReadFrame(bytes.NewReader(sample.raw))
		if c != sample.code {
			t.Fatal(fmt.Sprintf("frame code %s want %s", c, sample.code))
		}
	}
}
