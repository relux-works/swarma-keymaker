// keymaker-window is a non-root test harness; it is not part of the daemon.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-keymaker/internal/testwindow"
)

type manifest struct {
	UID    uint32 `json:"uid"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Token  string `json:"token"`
	Path   string `json:"path"`
	PID    int    `json:"pid"`
	Start  string `json:"process_start"`
}

func persist(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func run(args []string, out, errOut io.Writer, command testwindow.Command, uid uint32) int {
	flags := flag.NewFlagSet("keymaker-window", flag.ContinueOnError)
	flags.SetOutput(errOut)
	config := flags.String("config", "", "test-window configuration")
	scratch := flags.String("scratch", "", "runner-owned shared scratch parent")
	check := flags.Bool("check", false, "verify provisioning without running tests")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	cfg, code, e := testwindow.Load(*config)
	if e == nil {
		_, code, e = testwindow.Verify(cfg, uid, command)
	}
	if e != nil {
		if code == testwindow.Pending {
			fmt.Fprintln(errOut, "PENDING: test window not provisioned")
		} else {
			fmt.Fprintln(errOut, e)
		}
		return code
	}
	if *check {
		fmt.Fprintln(out, "test window verified")
		return 0
	}
	parent := *scratch
	if parent == "" {
		parent = cfg.Scratch
	}
	if parent == "" {
		parent = os.TempDir()
	}
	parent, e = filepath.Abs(parent)
	if e != nil {
		return 1
	}
	d, e := os.MkdirTemp(parent, "keymaker-window-")
	if e != nil {
		fmt.Fprintln(errOut, "cannot create fixture work directory")
		return 1
	}
	if os.Chmod(d, 0755) != nil {
		return 1
	}
	d, e = filepath.EvalSymlinks(d)
	if e != nil {
		return 1
	}
	info, e := os.Lstat(d)
	if e != nil {
		return 1
	}
	stat := info.Sys().(*syscall.Stat_t)
	var token [16]byte
	if _, e = rand.Read(token[:]); e != nil {
		return 1
	}
	m := manifest{UID: uint32(os.Getuid()), Device: uint64(stat.Dev), Inode: stat.Ino, Token: hex.EncodeToString(token[:]), Path: d}
	if e = persist(filepath.Join(d, "manifest.json"), m); e != nil {
		return 1
	}
	absoluteConfig, e := filepath.Abs(*config)
	if e != nil {
		return 1
	}
	binary := filepath.Join(d, "suite")
	build := exec.Command("go", "test", "-c", "-buildvcs=false", "-tags", "multiuid", "-o", binary, "./internal/keymaker")
	buildOutput, e := build.CombinedOutput()
	var output []byte
	exit := 0
	if e != nil {
		output = buildOutput
		exit = 1
	} else {
		os.Chmod(binary, 0755)
		cmd := exec.Command(binary, "-test.run=^TestMultiUID", "-test.timeout=60s", "-test.v", "-keymaker-window-token="+m.Token)
		// Inherited client-mode variables must never bypass the actual test suite.
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "KEYMAKER_WINDOW_CONFIG=" + absoluteConfig, "KEYMAKER_WINDOW_SCRATCH=" + d, "TMPDIR=" + d}
		var stream bytes.Buffer
		cmd.Stdout = &stream
		cmd.Stderr = &stream
		// Only this recorded direct child can be stopped; Run waits for its exit. Test
		// clients have their own five-second timeout and never create OS accounts.
		if e = cmd.Start(); e != nil {
			exit = 1
			output = []byte("test process start failed\n")
		} else {
			m.PID = cmd.Process.Pid
			proc, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", m.PID))
			if readErr == nil {
				tail := strings.Fields(string(proc)[strings.LastIndexByte(string(proc), ')')+1:])
				if len(tail) > 19 {
					m.Start = tail[19]
				}
			}
			if e = persist(filepath.Join(d, "process.json"), m); e != nil {
				cmd.Process.Kill()
				cmd.Wait()
				return 1
			}
			e = cmd.Wait()
			output = append([]byte(nil), stream.Bytes()...)
			if e != nil {
				exit = 1
			}
		}
	}
	report := filepath.Join(parent, "keymaker-report-"+m.Token+".json")
	if e = persist(report, map[string]any{"exit": exit, "work_dir": d, "token": m.Token, "child_pid": m.PID, "output": string(output)}); e != nil {
		fmt.Fprintln(errOut, "report persistence failed; work directory retained")
		return 1
	}
	// Deletion requires exact inode/device/UID and the unchanged private manifest.
	current, e := os.Lstat(d)
	if e != nil {
		return 1
	}
	v := current.Sys().(*syscall.Stat_t)
	b, e := os.ReadFile(filepath.Join(d, "manifest.json"))
	var saved manifest
	if e != nil || json.Unmarshal(b, &saved) != nil || saved.Token != m.Token || saved.Path != d || v.Uid != m.UID || v.Ino != m.Inode || uint64(v.Dev) != m.Device || current.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(errOut, "cleanup ownership mismatch; work directory retained")
		return 1
	}
	if e = os.RemoveAll(d); e != nil {
		return 1
	}
	fmt.Fprint(out, string(output))
	fmt.Fprintln(out, "retained report:", report)
	return exit
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, testwindow.CommandOutput, uint32(os.Getuid())))
}
