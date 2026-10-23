package keymaker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
	"github.com/relux-works/swarma-registrar/registry"
)

func helperReloadAuthority(t *testing.T, f *nativeFixture, tr *helperTrust) (*reviewReloadFiles, func()) {
	t.Helper()
	resume := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(resume) }) }
	files := &reviewReloadFiles{helperFiles: helperFiles{filepath.Dir(tr.config)}, config: tr.config, entered: make(chan struct{}), resume: resume}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(tr.config), "state", "high-water.json"))
	if err != nil {
		t.Fatal(err)
	}
	var disk struct {
		High *registry.HighWater `json:"high_water"`
	}
	if err = json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	a := enrollment.New(tr.config, files, &helperPublication{high: disk.High})
	if code := a.Reload(context.Background()); code != "" {
		t.Fatal("initial reload", code)
	}
	t.Cleanup(func() { f.stop(t); _ = a.Close() })
	tr.authority, tr.helper.authority = a, a
	return files, unblock
}

type reloadCountingSigner struct {
	signer registrationSigner
	calls  atomic.Int32
}

func (s *reloadCountingSigner) Sign(ctx context.Context, raw []byte) ([]byte, proof.Code) {
	s.calls.Add(1)
	return s.signer.Sign(ctx, raw)
}

// Slow fixture pin I/O cannot retain generation/Store locks after a 100ms
// helper deadline: parallel pubkey succeeds before I/O resumes. Its one retained
// result is the only Store change; the helper has only its required refusal
// audit record and consumes no nonce/signature. Undelayed control signs normally.
func TestReviewHelperReloadDeadline(t *testing.T) {
	for _, slow := range []bool{false, true} {
		t.Run(map[bool]string{false: "control", true: "slow-reload"}[slow], func(t *testing.T) {
			f, tr := helperSetup(t)
			files, unblock := helperReloadAuthority(t, f, tr)
			defer unblock()
			clock := &reviewHelperClockEntry{clock: tr.clock, entered: make(chan struct{})}
			entropy := &reviewHelperEntropy{}
			signer := &reloadCountingSigner{signer: registrationSigner{f.master, helperPath}}
			builder, err := proof.New(clock, entropy, signer)
			if err != nil {
				t.Fatal(err)
			}
			tr.helper.builder = builder
			f.start()
			c, other := nativeDial(t, f.server.ControlPath), nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			nativeNegotiate(t, other, 2)
			var before bindingDisk
			if err = json.Unmarshal(nativeSnapshot(t, f), &before); err != nil {
				t.Fatal(err)
			}
			auditBefore := len(nativeAudit(t, f.store.journal))
			reloaded := make(chan enrollment.Code, 1)
			if slow {
				files.armed.Store(true)
				go func() { reloaded <- tr.authority.Reload(context.Background()) }()
				<-files.entered
				defer func() { unblock(); <-reloaded }()
			}
			req := helperRequest(3)
			req["timeout_ms"] = int64(100)
			started := time.Now()
			nativeSend(t, c, req)
			select {
			case <-clock.entered:
			case <-time.After(time.Second):
				t.Fatal("helper failed to reach enrollment stage")
			}
			pub := nativeRequest(4, "pubkey", control.Object{})
			pub["timeout_ms"] = int64(1500)
			nativeSend(t, other, pub)
			if !slow {
				helperResult(t, nativeReceive(t, c), nativeID(3), "", tr.helper.key)
				nativeResponse(t, nativeReceive(t, other), nativeID(4), "")
				if entropy.calls.Load() != 1 || signer.calls.Load() != 1 {
					t.Fatal("undelayed control did not build exactly one proof")
				}
				return
			}
			// Keep the original review's 2.2s read bound; independently tighten
			// the normal deadline-response check to a 500ms scheduling margin.
			_ = c.SetReadDeadline(started.Add(2200 * time.Millisecond))
			raw, code := ReadFrame(c)
			if code != "" || raw == nil {
				t.Error("helper failed to refuse at its request deadline", code)
			} else {
				obj, err := control.Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				nativeResponse(t, obj, nativeID(3), "request_deadline_exceeded")
			}
			if time.Since(started) > 500*time.Millisecond {
				t.Error("helper exceeded deadline scheduling margin")
			}
			_ = other.SetReadDeadline(started.Add(2200 * time.Millisecond))
			raw, code = ReadFrame(other)
			if code != "" || raw == nil {
				t.Fatal("parallel pubkey blocked by expired helper before reload I/O resumed", code)
			}
			obj, err := control.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			pubResult := nativeResponse(t, obj, nativeID(4), "")
			// A successful pubkey traversed both shared locks, independently
			// proving the expired helper relinquished them before reload resumes.
			var after bindingDisk
			if err = json.Unmarshal(nativeSnapshot(t, f), &after); err != nil {
				t.Fatal(err)
			}
			if after.Next != before.Next || !reflect.DeepEqual(after.Records, before.Records) || after.Version != before.Version+1 || len(after.Requests) != len(before.Requests)+1 {
				t.Fatal("expired helper changed bindings/counter or retained a result")
			}
			if !reflect.DeepEqual(after.Requests[:len(before.Requests)], before.Requests) {
				t.Fatal("expired helper changed existing retained results")
			}
			encoded, err := control.Marshal(pubResult)
			if err != nil {
				t.Fatal(err)
			}
			want := retainedRequest{Caller: Principal{uint32(os.Getuid()), nativeToken}, ID: nativeID(4), Method: "pubkey", Arguments: "{}", Status: "committed", Result: encoded}
			if !reflect.DeepEqual(after.Requests[len(before.Requests)], want) {
				t.Fatal("Store delta was not exactly the successful pubkey result")
			}
			if entropy.calls.Load() != 0 || signer.calls.Load() != 0 {
				t.Fatal("expired helper generated a nonce or signature")
			}
			refusals, successes, commits := 0, 0, 0
			records := nativeAudit(t, f.store.journal)[auditBefore:]
			if len(records) != 3 {
				t.Fatal("unexpected audit delta beyond helper refusal and pubkey commit/success", len(records))
			}
			for _, record := range records {
				if record.RequestID != nil && *record.RequestID == nativeID(3) {
					if record.Operation != "sign_registration" || record.Result != "refused" || record.RefusalCode == nil || *record.RefusalCode != "request_deadline_exceeded" {
						t.Fatal("expired helper emitted effect/success/unknown audit evidence")
					}
					refusals++
				}
				if record.RequestID != nil && *record.RequestID == nativeID(4) && record.Operation == "pubkey" && record.Result == "success" {
					successes++
				}
				if record.Operation == "binding_commit" && record.Result == "success" && record.RequestID != nil && *record.RequestID == "binding:"+strconv.FormatUint(after.Version, 10) && record.Seq == after.AuditSeq && record.Digest == after.AuditHash {
					commits++
				}
			}
			if refusals != 1 || successes != 1 || commits != 1 {
				t.Fatal("missing or duplicate helper refusal/pubkey success audit", refusals, successes)
			}
		})
	}
}

// A real socket write holds the enrollment read barrier while reload can still
// enter pin-file I/O. Publication waits for the write; failed publication then
// refuses every new helper call instead of using the old valid enrollment.
func TestHelperReloadPreparesOutsideWrite(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "failed"}[invalid], func(t *testing.T) {
			f, tr := helperSetup(t)
			files, unblockIO := helperReloadAuthority(t, f, tr)
			defer unblockIO()
			entered, allow := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblockWrite := func() { once.Do(func() { close(allow) }) }
			defer unblockWrite()
			probe := &nativeFenceProbe{native: f.native, method: "sign_registration", entered: entered, allow: allow}
			wire, err := control.New(f.native, f.native, f.native, probe, f.native)
			if err != nil {
				t.Fatal(err)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			nativeSend(t, c, helperRequest(2))
			<-entered
			if invalid {
				if err = os.WriteFile(tr.config, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			files.armed.Store(true)
			reloaded := make(chan enrollment.Code, 1)
			go func() { reloaded <- tr.authority.Reload(context.Background()) }()
			defer func() { unblockWrite(); unblockIO(); <-reloaded }()
			select {
			case <-files.entered:
			case <-time.After(time.Second):
				t.Fatal("reload I/O waited for the actual socket write")
			}
			unblockIO()
			select {
			case code := <-reloaded:
				reloaded <- code // Keep deferred cleanup nonblocking on failure.
				t.Fatal("reload overtook the actual socket write")
			case <-time.After(25 * time.Millisecond):
			}
			unblockWrite()
			helperResult(t, nativeReceive(t, c), nativeID(2), "", tr.helper.key)
			want := Code("")
			wantReload := enrollment.OK
			if invalid {
				want, wantReload = "enrollment_unverified", enrollment.EnrollmentUnverified
			}
			code := <-reloaded
			reloaded <- code
			if code != wantReload {
				t.Fatal("reload", code)
			}
			helperCall(t, f, c, 3, want)
		})
	}
}
