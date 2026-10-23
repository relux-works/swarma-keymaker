package enrollment

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

type pausedReloadFiles struct {
	Files
	path    string
	entered chan struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func (f *pausedReloadFiles) Read(path string, limit int64) ([]byte, Metadata, error) {
	if path == f.path {
		f.once.Do(func() { close(f.entered); <-f.resume })
	}
	return f.Files.Read(path, limit)
}

// Pin-file I/O runs while an existing release holds its consistent snapshot.
// Publication, including a failure fence, waits for that release; a fresh
// successful reload is required before old enrollment can be admitted again.
func TestReloadPreparesOutsideReleaseBarrier(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "failed"}[invalid], func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			a := f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			before, code := authorize(a)
			expectCode(t, OK, code)
			if invalid {
				if err := os.WriteFile(f.configPath, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblockRelease := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblockRelease()
			admitted := make(chan Code, 1)
			go func() {
				admitted <- a.WithAuthorized(context.Background(), 30001, testGeneration, public(2), testName, testAudience, testNow, testNow, func(key EnrolledKey) Code {
					close(entered)
					<-release
					if key != before || a.config.Revision != before.Revision || a.snapshot.Revision() != before.Revision {
						t.Error("release observed a mixed snapshot")
					}
					return OK
				})
			}()
			<-entered
			resume := make(chan struct{})
			var resumeOnce sync.Once
			unblockIO := func() { resumeOnce.Do(func() { close(resume) }) }
			defer unblockIO()
			files := &pausedReloadFiles{Files: f.files, path: f.configPath, entered: make(chan struct{}), resume: resume}
			a.files = files // No serving path performs file I/O.
			reloaded := make(chan Code, 1)
			go func() { reloaded <- a.Reload(context.Background()) }()
			select {
			case <-files.entered:
			case <-time.After(time.Second):
				unblockRelease()
				unblockIO()
				<-admitted
				<-reloaded
				t.Fatal("reload I/O waited for the release barrier")
			}
			unblockIO()
			select {
			case <-reloaded:
				t.Fatal("reload published over an active release")
			case <-time.After(25 * time.Millisecond):
			}
			unblockRelease()
			expectCode(t, OK, <-admitted)
			want := OK
			if invalid {
				want = EnrollmentUnverified
			}
			expectCode(t, want, <-reloaded)
			_, code = authorize(a)
			expectCode(t, want, code)
			if invalid {
				f.writeConfig()
				expectCode(t, OK, a.Reload(context.Background()))
				_, code = authorize(a)
				expectCode(t, OK, code)
			}
		})
	}
}

// A pending reload cannot extend a caller's budget or invoke its effect. The
// same authority accepts a fresh call after publication, ruling out reject-all.
func TestEnrollmentGateDeadline(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	a.mu.pause()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	called := false
	result := make(chan Code, 1)
	go func() {
		result <- a.WithAuthorized(ctx, 30001, testGeneration, public(2), testName, testAudience, testNow, testNow, func(EnrolledKey) Code { called = true; return OK })
	}()
	select {
	case code := <-result:
		expectCode(t, RequestDeadlineExceeded, code)
	case <-time.After(250 * time.Millisecond):
		a.mu.Lock()
		a.mu.Unlock()
		<-result
		t.Fatal("enrollment acquisition ignored the deadline")
	}
	a.mu.Lock()
	a.mu.Unlock()
	if called {
		t.Fatal("expired admission invoked its effect")
	}
	_, code := authorize(a)
	expectCode(t, OK, code)
}
