//go:build linux

package keymaker

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

func maLiveSizedPreimage(t *testing.T, f *maLiveFixture, size int) []byte {
	t.Helper()
	obj := maRecord(t, f.v)
	padding := []any{"", "", ""}
	obj["padding"] = padding
	left := size - len(maPre(t, obj))
	if left < 0 {
		t.Fatal("preimage fixture too small")
	}
	for i := range padding {
		n := min(left, 8192)
		padding[i] = strings.Repeat("x", n)
		left -= n
	}
	raw := maPre(t, obj)
	if left != 0 || len(raw) != size {
		t.Fatal("preimage fixture size", len(raw), size)
	}
	return raw
}

// The last free row accepts a maximum-size P beside nearly exhausted encoded
// state; at the exact row cap an identical replay is durable and never re-signs.
// The measurements bound this fixture/environment, not native qualification.
func TestMALiveCapacityLatency(t *testing.T) {
	// RSS high-water marks are process-wide. A dedicated child prevents another
	// test's old high-water mark from being presented as this participant's heap.
	if root := os.Getenv("KEYMAKER_MA_CAPACITY_CHILD"); root == "" {
		root = t.TempDir()
		binary, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		// Exercise both the unit-like one-CPU case and all CPUs visible to a
		// hosted runner; a fresh process owns each RSS high-water mark.
		cpus := []int{1}
		if n := runtime.NumCPU(); n != 1 {
			cpus = append(cpus, n)
		}
		for _, n := range cpus {
			t.Run(fmt.Sprintf("cpus-%d", n), func(t *testing.T) {
				cmd := exec.Command(binary, "-test.run=^TestMALiveCapacityLatency$", "-test.v", "-test.timeout=120s")
				cmd.Env = append(os.Environ(), "KEYMAKER_MA_CAPACITY_CHILD="+root, "GOTMPDIR="+root, "GOMAXPROCS="+strconv.Itoa(n))
				var log bytes.Buffer
				cmd.Stdout = &log
				cmd.Stderr = &log
				e := cmd.Run()
				t.Log(log.String())
				if e != nil {
					t.Fatal("isolated capacity process", e)
				}
			})
		}
		return
	} else if !filepath.IsAbs(root) || root != os.Getenv("GOTMPDIR") {
		t.Fatal("capacity child outside isolated scratch")
	}

	// The diagnostic negative control changes only the runtime limit. It keeps
	// the same workload and every time/heap/RSS assertion; a passing control is
	// reported as a survivor, not proof that local RSS reproduces hosted RSS.
	if os.Getenv("KEYMAKER_MA_CAPACITY_NO_LIMIT") == "1" {
		debug.SetMemoryLimit(int64(^uint64(0) >> 1))
	} else {
		setMALiveMemoryLimit()
		if got := debug.SetMemoryLimit(-1); got != maLiveMemoryLimit {
			t.Fatal("production runtime memory limit missing", got)
		}
	}

	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			for old := peak.Load(); m.HeapAlloc > old && !peak.CompareAndSwap(old, m.HeapAlloc); old = peak.Load() {
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	defer func() { close(stop); <-done }()
	f := newMALiveFixture(t)
	s := f.h.store
	maximal := maLiveSizedPreimage(t, f, 24576)
	f.preimage = maximal
	seed := maLiveIntent(f)
	seed.Status = "dead"
	// The setup uses valid durable dead unsigned attempts, not invented success proofs.
	seed.Preimage = maBytes(t, f.v.Preimage)
	s.maLive.Attempts = make([]maLiveAttempt, maLiveAttemptLimit-1)
	for i := range s.maLive.Attempts {
		a := seed
		a.ID = fmt.Sprintf("%032x", i+1)
		s.maLive.Attempts[i] = a
	}
	if e := s.validateMALive(); e != nil {
		t.Fatal(e)
	}
	future := maLiveIntent(f)
	_, reserve, e := maLiveRowBytes(future)
	if e != nil {
		t.Fatal(e)
	}
	body := s.maLiveBody(j7SafeInteger, nil, s.maLiveCache.total)
	used := len(body) + maLiveReceiptBound + s.maLiveCache.total - s.maLiveCache.actual
	ceiling := (maLiveStateLimit - maLiveStateOverhead) / 3
	// Leave space for the final maximum-sized result, largest integer receipts,
	// and less than one maximum row of unused state. No fixture horizon/eviction.
	remaining := ceiling - used - reserve - 256
	if remaining < 0 {
		t.Fatal("row cap cannot fit state budget", used, reserve, ceiling)
	}
	for i := range s.maLive.Attempts {
		if remaining < 64 {
			break
		}
		a := s.maLive.Attempts[i]
		a.Preimage = maximal
		raw, n, e := maLiveRowBytes(a)
		if e != nil {
			t.Fatal(e)
		}
		extra := n - s.maLiveCache.reserved[i]
		if extra > remaining {
			size := len(seed.Preimage) + (remaining * 3 / 4) - 32
			if size <= len(seed.Preimage)+64 {
				break
			}
			a.Preimage = maLiveSizedPreimage(t, f, size)
			raw, n, e = maLiveRowBytes(a)
			if e != nil {
				t.Fatal(e)
			}
			extra = n - s.maLiveCache.reserved[i]
		}
		if extra > remaining {
			t.Fatal("fixture reservation overflow")
		}
		remaining -= extra
		s.maLive.Attempts[i] = a
		s.maLiveCache.total += extra
		s.maLiveCache.actual += len(raw) - len(s.maLiveCache.rows[i])
		s.maLiveCache.rows[i] = raw
		s.maLiveCache.reserved[i] = n
	}
	// Install, then independently decode/full-validate the actual retained bytes.
	if c := s.persistMALive(t.Context()); c != "" {
		t.Fatal("capacity fixture persistence", c)
	}
	expected := maLiveExpected(t, s)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	// A stopped process cannot retain its predecessor's heap. Release the setup
	// inventory before opening the pair, while retaining all actual disk bytes.
	s.maLive = nil
	s.maLiveCache = nil
	runtime.GC()
	opened, code := openMALive(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, expected)
	if code != "" {
		t.Fatal("capacity fixture restart", code)
	}
	f.h.store = opened
	s = opened
	t.Cleanup(func() { opened.Close() })
	if !s.j7HeadMatches(expected) {
		t.Fatal("restart changed paired head")
	}
	start := time.Now()
	first, c := f.call(t.Context(), f.request())
	fresh := time.Since(start)
	if c != "" || first.Signature == nil || f.calls.Load() != 1 || len(s.maLive.Attempts) != maLiveAttemptLimit {
		t.Fatal("at-bound fresh", c, fresh, f.calls.Load())
	}
	start = time.Now()
	replay, c := f.call(t.Context(), f.request())
	elapsed := time.Since(start)
	if c != "" || replay.Signature == nil || !bytes.Equal(first.Signature.Signature, replay.Signature.Signature) || f.calls.Load() != 1 {
		t.Fatal("at-bound replay", c, elapsed)
	}
	if record.VerifySignature(f.v.Key, replay.Signature.Signature, maximal) != nil {
		t.Fatal("boundary signature invalid")
	}
	raw, e := os.ReadFile(filepath.Join(f.dir.Name(), "bindings.json"))
	if e != nil {
		t.Fatal(e)
	}
	// One request over the full cap refuses before intent, audit mutation or
	// crypto. The exact-at-cap replay above remains a positive control.
	before := s.journal.seq
	other := f.request()
	other.ID = strings.Repeat("e", 32)
	f.refusal(t, other, "state_capacity_exceeded", 1)
	if len(s.maLive.Attempts) != maLiveAttemptLimit || s.journal.seq != before || s.maLive.Attempts[0].ID != "00000000000000000000000000000001" {
		t.Fatal("at-capacity refusal changed evidence")
	}
	if _, e = loadStoreMessage(f.dir, s.uid, maLiveSchema, false); e != nil {
		t.Fatal("durable boundary result", e)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	p := max(peak.Load(), m.HeapAlloc)
	var u syscall.Rusage
	if e = syscall.Getrusage(syscall.RUSAGE_SELF, &u); e != nil {
		t.Fatal(e)
	}
	t.Logf("runtime_limit=%d gomaxprocs=%d rows=%d state_budget=%d snapshot_bytes=%d utilization=%.4f preimage_bytes=%d fresh=%s replay=%s peak_heap=%d process_peak_rss=%d", debug.SetMemoryLimit(-1), runtime.GOMAXPROCS(0), len(s.maLive.Attempts), maLiveStateLimit, len(raw), float64(len(raw))/float64(ceiling), len(maximal), fresh, elapsed, p, u.Maxrss*1024)
	if len(raw) < ceiling*95/100 {
		t.Fatal("capacity fixture not near byte budget")
	}
	if fresh >= time.Second || elapsed >= time.Second {
		t.Fatal("capacity operation lacks 2x deadline margin", fresh, elapsed)
	}
	if u.Maxrss*1024 >= 240<<20 {
		t.Fatal("capacity RSS lacks 16 MiB unit headroom", u.Maxrss*1024)
	}
	if p >= 128<<20 || u.Maxrss*1024 >= 256<<20 {
		t.Fatal("capacity heap margin or unit RSS exceeded", p, u.Maxrss*1024)
	}
}
