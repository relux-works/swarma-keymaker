//go:build linux

package keymaker

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func maLiveParseVmHWM(status string) (uint64, error) {
	var result uint64
	found := false
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "VmHWM:" {
			continue
		}
		if found || len(fields) != 3 || fields[2] != "kB" {
			return 0, fmt.Errorf("invalid VmHWM field")
		}
		found = true
		for _, c := range fields[1] {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("invalid VmHWM number")
			}
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || n == 0 || n > ^uint64(0)/1024 {
			return 0, fmt.Errorf("invalid VmHWM size")
		}
		result = n * 1024
	}
	if !found {
		return 0, fmt.Errorf("missing VmHWM")
	}
	return result, nil
}

func maLiveVmHWM(t *testing.T) uint64 {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	peak, err := maLiveParseVmHWM(string(status))
	if err != nil {
		t.Fatal(err)
	}
	return peak
}

// Missing, malformed and overflowing measurements must not become a zero-byte
// passing RSS result; the valid control uses the kernel's kB-to-byte convention.
func TestMALiveVmHWMParser(t *testing.T) {
	if got, err := maLiveParseVmHWM("Name:\tfixture\nVmHWM:\t12345 kB\nVmRSS: 7 kB\n"); err != nil || got != 12345*1024 {
		t.Fatal(got, err)
	}
	for _, s := range []string{"", "VmRSS: 123 kB", "VmHWM: 0 kB", "VmHWM: -1 kB", "VmHWM: +1 kB", "VmHWM: 1 MB", "VmHWM: 1", "VmHWM: 1 kB extra", "VmHWM: 18014398509481984 kB", "VmHWM: 18446744073709551616 kB", "VmHWM: 1 kB\nVmHWM: 2 kB"} {
		t.Run(strconv.Quote(s), func(t *testing.T) {
			if n, err := maLiveParseVmHWM(s); err == nil || n != 0 {
				t.Fatal("invalid measurement accepted", n, err)
			}
		})
	}
}

// A trivial exec child has its own small mm high-water mark even after a
// touched parent allocation. ru_maxrss inheritance is observed, not required
// on kernels with different exec accounting; neither case gates participant RSS.
func TestMALiveRSSAccounting(t *testing.T) {
	if os.Getenv("KEYMAKER_MA_RSS_CHILD") == "1" {
		own := maLiveVmHWM(t)
		var usage syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("RSS_MEASUREMENT %d %d\n", own, usage.Maxrss*1024)
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, contaminated := range []bool{false, true} {
		t.Run(fmt.Sprintf("contaminated-%t", contaminated), func(t *testing.T) {
			var held []byte
			if contaminated {
				held = make([]byte, 208<<20)
				for i := 0; i < len(held); i += os.Getpagesize() {
					held[i] = 1
				}
			}
			parentHWM := maLiveVmHWM(t)
			if contaminated && parentHWM < 200<<20 {
				t.Fatal("parent allocation did not establish contamination", parentHWM)
			}
			cmd := exec.Command(binary, "-test.run=^TestMALiveRSSAccounting$", "-test.v", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "KEYMAKER_MA_RSS_CHILD=1", "GOTMPDIR="+t.TempDir())
			output, err := cmd.CombinedOutput()
			runtime.KeepAlive(held)
			if err != nil {
				t.Fatalf("measurement child: %v\n%s", err, output)
			}
			var own, diagnostic uint64
			found := false
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, "RSS_MEASUREMENT ") {
					if _, err := fmt.Sscanf(line, "RSS_MEASUREMENT %d %d", &own, &diagnostic); err != nil {
						t.Fatal(err)
					}
					found = true
				}
			}
			if !found || own == 0 || own >= 64<<20 {
				t.Fatal("trivial child's own VmHWM is not small", own, string(output))
			}
			t.Logf("contaminated=%t parent_vmhwm=%d participant_vmhwm=%d ru_maxrss_possibly_inherited=%d inheritance_observed=%t", contaminated, parentHWM, own, diagnostic, contaminated && diagnostic >= 200<<20)
			if contaminated && diagnostic < 200<<20 {
				t.Log("kernel did not expose the parent's touched 200 MiB via child ru_maxrss; VmHWM remains authoritative")
			}
		})
	}
}
