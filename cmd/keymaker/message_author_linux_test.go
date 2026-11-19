//go:build linux

package main

import (
	"bytes"
	"context"
	"testing"
)

// CLI usage is closed before input/config/state I/O. The existing version
// action remains available; tests do not execute an installed operator action.
func TestMALiveCommandUsage(t *testing.T) {
	for _, args := range [][]string{{"message-author"}, {"message-author", "sign"}, {"message-author", "export"}, {"message-author", "init"}, {"message-author", "enroll", "--key-file", "x"}, {"message-author", "retire", "--config", "x", "extra"}} {
		var out, diagnostic bytes.Buffer
		if c := run(context.Background(), args, &out, &diagnostic); c != 2 || out.Len() != 0 {
			t.Fatal("invalid operator CLI had an effect", c)
		}
	}
	var out, diagnostic bytes.Buffer
	if c := run(context.Background(), []string{"version"}, &out, &diagnostic); c != 0 || out.String() != "0.1.0\n" {
		t.Fatal("version control", c)
	}
}
