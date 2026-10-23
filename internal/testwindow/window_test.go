package testwindow

import (
	"errors"
	"reflect"
	"testing"
)

// Missing permission is PENDING; malformed/root/colliding identities are failures.
// The minimal names-only configuration needs no root state file or numeric pins.
func TestMinimalWindow(t *testing.T) {
	c := Config{Runner: "runner", A: "client-a", B: "client-b", Group: "test-reg"}
	calls := 0
	run := func(name string, args ...string) (string, error) {
		calls++
		if name == "/usr/bin/id" {
			switch args[1] {
			case "runner":
				return "1000", nil
			case "client-a":
				return "1001", nil
			case "client-b":
				return "1002", nil
			}
		}
		if reflect.DeepEqual(args, []string{"-n", "-u", "runner", "-g", "test-reg", "--", "/usr/bin/id", "-g"}) {
			return "2000", nil
		}
		if len(args) == 6 && args[5] == "-G" {
			if args[2] == "client-a" {
				return "100 2000", nil
			}
			return "100", nil
		}
		if args[2] == "client-a" {
			return "1001", nil
		}
		return "1002", nil
	}
	if _, code, e := Verify(c, 1000, func(string, ...string) (string, error) { return "", errors.New("absent") }); code != Pending || e == nil {
		t.Fatal("absent window not PENDING")
	}
	bad := c
	bad.A = "root"
	if _, code, _ := Verify(bad, 1000, run); code != 2 || calls != 0 {
		t.Fatal("root Runas attempted")
	}
	if w, code, e := Verify(c, 1000, run); e != nil || code != 0 || w.AID != 1001 || w.BID != 1002 {
		t.Fatal("minimal window failed", code, e)
	}
}
