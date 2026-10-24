package control

import (
	"context"
	"net"
	"testing"
	"time"
)

// Actual transport receives the shorter authority deadline. An expired window
// emits no bytes; a blocked write terminates at that deadline, not the request's
// two-second budget. A post-callback check cannot undo a late response.
func TestGenerationDeadlineTransport(t *testing.T) {
	for _, mode := range []string{"active", "expired", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			s := testServer(t, nil, nil, nil, fenceFunc(func(ctx context.Context, _ Peer, _ Request, _ Object, write func(context.Context) Code) Code {
				deadline := time.Now().Add(40 * time.Millisecond)
				if mode == "expired" {
					deadline = time.Now().Add(-time.Second)
				}
				bounded, cancel := context.WithDeadline(ctx, deadline)
				defer cancel()
				return write(bounded)
			}))
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			received := make(chan Object, 1)
			if mode == "active" {
				go func() { received <- receive(t, client) }()
			}
			start := time.Now()
			code, err := s.release(context.Background(), server, Peer{UID: 1001, Generation: "active"}, Request{ID: requestID(1)}, Object{"ok": true}, time.Now().Add(2*time.Second))
			if mode == "active" {
				if code != "" || err != nil {
					t.Fatal(code, err)
				}
				wantSuccess(t, <-received, requestID(1))
				return
			}
			if mode == "expired" && (code != DeadlineExceeded || err != nil) {
				t.Fatal(code, err)
			}
			if mode == "blocked" && err == nil {
				t.Fatal("unbounded write succeeded", code)
			}
			if time.Since(start) > 500*time.Millisecond {
				t.Fatal("transport lost authority deadline")
			}
			client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			var b [1]byte
			n, _ := client.Read(b[:])
			if n != 0 {
				t.Fatal("expired response bytes emitted")
			}
		})
	}
}
