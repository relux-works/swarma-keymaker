package enrollment

import (
	"context"
	"os"
	"testing"
	"time"
)

// A failed current authorization never calls release. A successful release keeps
// Reload outside the authority barrier; once release ends, failed reload fences
// subsequent attempts. A fresh independent authority is the positive control.
func TestWithAuthorizedReleaseBarrier(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	called := false
	code := a.WithAuthorized(context.Background(), 30002, testGeneration, public(2), testName, testAudience, testNow, testNow, func(EnrolledKey) Code { called = true; return OK })
	expectCode(t, UIDNotPermitted, code)
	if called {
		t.Fatal("unauthorized release called")
	}
	entered, allow := make(chan struct{}), make(chan struct{})
	result := make(chan Code, 1)
	go func() {
		result <- a.WithAuthorized(context.Background(), 30001, testGeneration, public(2), testName, testAudience, testNow, testNow, func(EnrolledKey) Code { close(entered); <-allow; return OK })
	}()
	<-entered
	if err := os.WriteFile(f.configPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded := make(chan Code, 1)
	go func() { reloaded <- a.Reload(context.Background()) }()
	select {
	case <-reloaded:
		close(allow)
		t.Fatal("reload overtook release")
	case <-time.After(25 * time.Millisecond):
	}
	close(allow)
	expectCode(t, OK, <-result)
	expectCode(t, EnrollmentUnverified, <-reloaded)
	called = false
	code = a.WithAuthorized(context.Background(), 30001, testGeneration, public(2), testName, testAudience, testNow, testNow, func(EnrolledKey) Code { called = true; return OK })
	expectCode(t, EnrollmentUnverified, code)
	if called {
		t.Fatal("fenced authority released")
	}
}
