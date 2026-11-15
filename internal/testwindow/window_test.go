package testwindow

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func windowReply(args []string) string {
	if args[len(args)-1] == "-g" {
		return "2000"
	}
	if args[len(args)-1] == "-G" {
		if args[2] == "client-a" {
			return "100 2000"
		}
		return "100"
	}
	name := args[1]
	if args[0] == "-n" {
		name = args[2]
	}
	return map[string]string{"runner": "1000", "client-a": "1001", "client-b": "1002"}[name]
}
func toolConfig(t *testing.T) Config {
	t.Helper()
	c := Config{Runner: "runner", A: "client-a", B: "client-b", Group: "test-reg"}
	d := t.TempDir()
	c.IDPath = filepath.Join(d, "literal id;name")
	c.EnvPath = filepath.Join(d, "env")
	// Real metadata only; fake Command captures argv without executing these files.
	for _, p := range []string{c.IDPath, c.EnvPath} {
		if err := os.WriteFile(p, nil, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// Every lookup/sudo probe uses the selected path, with legacy argv/defaults
// unchanged. Fake command outputs do not establish real UID or root custody.
func TestConfiguredToolInvocations(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "configured"}[configured], func(t *testing.T) {
			c := toolConfig(t)
			id, env := c.IDPath, c.EnvPath
			if !configured {
				c.IDPath, c.EnvPath = "", ""
				id, env = "/usr/bin/id", "/usr/bin/env"
			}
			var calls [][]string
			w, code, err := Verify(c, 1000, func(name string, args ...string) (string, error) {
				calls = append(calls, append([]string{name}, args...))
				return windowReply(args), nil
			})
			if code != 0 || err != nil || w.IDPath != id || w.EnvPath != env {
				t.Fatal("configured positive", w, code, err)
			}
			want := [][]string{{id, "-u", "runner"}, {id, "-u", "client-a"}, {id, "-u", "client-b"},
				{"sudo", "-n", "-u", "client-a", "--", id, "-u"}, {"sudo", "-n", "-u", "client-b", "--", id, "-u"},
				{"sudo", "-n", "-u", "runner", "-g", "test-reg", "--", id, "-g"},
				{"sudo", "-n", "-u", "client-a", "--", id, "-G"}, {"sudo", "-n", "-u", "client-b", "--", id, "-G"}}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("configured invocation mismatch: got %q want %q", calls, want)
			}
			for _, group := range []string{"", "test-reg"} {
				want := []string{"-n", "-u", "client-a"}
				if group != "" {
					want = append(want, "-g", group)
				}
				want = append(want, "--", env, "EXPECT=1", "/fixture/suite", "-test.run=^TestWindow$")
				if got := w.ClientArgs("client-a", group, "EXPECT=1", "/fixture/suite", "-test.run=^TestWindow$"); !reflect.DeepEqual(got, want) {
					t.Fatal("configured client prefix", got, want)
				}
			}
		})
	}
}

// Malformed paths refuse before any command; unavailable explicit files are
// PENDING without falling back. Literal spaces/metacharacters are tested above.
func TestWindowToolPathRefusals(t *testing.T) {
	for _, field := range []string{"id", "env"} {
		for _, value := range []string{"id", "relative/id", "/fixture/../id", "/fixture//id", "/fixture/id/", "/fixture/\nid", "/fixture/\x00id", "--help"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				c := toolConfig(t)
				if field == "id" {
					c.IDPath = value
				} else {
					c.EnvPath = value
				}
				calls := 0
				_, code, err := Verify(c, 1000, func(string, ...string) (string, error) { calls++; return "", nil })
				if code != 2 || err == nil || err.Error() != "invalid window tool path" || calls != 0 {
					t.Fatal("malformed path reached command", code, err, calls)
				}
				raw, _ := json.Marshal(c)
				path := filepath.Join(t.TempDir(), "window.json")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if _, code, err := Load(path); code != 2 || err == nil || err.Error() != "invalid window tool path" {
					t.Fatal("Load path validation", code, err)
				}
			})
		}
		for _, kind := range []string{"missing", "directory", "nonexecutable"} {
			t.Run(field+"/"+kind, func(t *testing.T) {
				c := toolConfig(t)
				bad := filepath.Join(t.TempDir(), "changed-tool")
				if kind == "directory" {
					if err := os.Mkdir(bad, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "nonexecutable" {
					if err := os.WriteFile(bad, nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if field == "id" {
					c.IDPath = bad
				} else {
					c.EnvPath = bad
				}
				calls := 0
				_, code, err := Verify(c, 1000, func(string, ...string) (string, error) { calls++; return "", nil })
				if code != Pending || err == nil || err.Error() != "test "+field+" executable unavailable" || calls != 0 {
					t.Fatal("explicit unavailable tool fell back", code, err, calls)
				}
			})
		}
	}
}

// Explicit empty/null/wrong-type paths are not omissions. Existing unknown
// fields, extra JSON and missing-input statuses remain distinct and unchanged.
func TestWindowToolLoadContract(t *testing.T) {
	for _, fields := range []string{
		`"id_path":"/fixture/id","id_path":"/fixture/other"`,
		`"env_path":"/fixture/env","env_path":"/fixture/env"`,
		`"id_path":"/fixture/id","ID_PATH":"/fixture/id"`,
		`"ENV_PATH":"/fixture/env"`,
	} {
		raw := `{"runner_user":"runner","client_a":"client-a","client_b":"client-b","registration_group":"test-reg",` + fields + `}`
		path := filepath.Join(t.TempDir(), "ambiguous.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, code, err := Load(path); code != 2 || err == nil || err.Error() != "ambiguous window tool path" {
			t.Fatal("ambiguous tool declaration admitted", fields, code, err)
		}
	}

	for _, field := range []string{"id_path", "env_path", "ID_PATH", "ENV_PATH"} {
		for _, value := range []any{"", nil, 123} {
			raw, _ := json.Marshal(map[string]any{"runner_user": "runner", "client_a": "client-a", "client_b": "client-b", "registration_group": "test-reg", field: value})
			path := filepath.Join(t.TempDir(), "window.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, code, err := Load(path); code != 2 || err == nil {
				t.Fatal("explicit invalid field became default", field, value, code, err)
			}
		}
	}
	c := toolConfig(t)
	raw, _ := json.Marshal(c)
	for _, suffix := range []string{"", " {}"} {
		path := filepath.Join(t.TempDir(), "window.json")
		if err := os.WriteFile(path, append(append([]byte{}, raw...), suffix...), 0600); err != nil {
			t.Fatal(err)
		}
		got, code, err := Load(path)
		if suffix == "" {
			if code != 0 || err != nil || !reflect.DeepEqual(got, c) {
				t.Fatal("configured Load", got, code, err)
			}
		} else if code != 2 || err == nil {
			t.Fatal("extra JSON admitted")
		}
	}
	path := filepath.Join(t.TempDir(), "unknown.json")
	os.WriteFile(path, []byte(`{"unknown":1}`), 0600)
	if _, code, err := Load(path); code != 2 || err == nil {
		t.Fatal("unknown field admitted")
	}
	if _, code, err := Load(path + ".absent"); code != Pending || err == nil || err.Error() != "test window not provisioned" {
		t.Fatal("missing file changed status")
	}
}

// Pin, root/collision, numeric, group and command failures keep their exact
// status/reason and stop at the intended command, beside an unchanged positive.
func TestWindowIdentityRefusals(t *testing.T) {
	pin := uint32(9999)
	cases := []struct {
		name   string
		edit   func(*Config)
		at     int
		reply  string
		fail   bool
		code   int
		reason string
	}{
		{"root-name", func(c *Config) { c.A = "root" }, 0, "", false, 2, "invalid non-root window name"},
		{"same-name", func(c *Config) { c.A = c.B }, 0, "", false, 2, "window identities must be distinct and unprivileged"},
		{"pin", func(c *Config) { c.AUID = &pin }, 2, "1001", false, 2, "window UID mismatch"},
		{"root-uid", nil, 2, "0", false, 2, "window UID mismatch"},
		{"runner-mismatch", nil, 1, "99", false, 2, "window UID mismatch"},
		{"bad-number", nil, 2, "not-a-uid", false, 2, "window UID mismatch"},
		{"collision", nil, 3, "1001", false, 2, "window UID collision"},
		{"account-missing", nil, 1, "", true, 3, "test account unavailable"},
		{"sudo-missing", nil, 4, "", true, 3, "test sudo unavailable"},
		{"sudo-wrong", nil, 4, "9999", false, 1, "sudo identity mismatch"},
		{"group-missing", nil, 6, "", true, 3, "test group sudo unavailable"},
		{"group-zero", nil, 6, "0", false, 1, "test group mismatch"},
		{"group-pin", func(c *Config) { c.GID = &pin }, 6, "2000", false, 1, "test group mismatch"},
		{"membership-missing", nil, 7, "", true, 3, "test membership unavailable"},
		{"membership-invalid", nil, 7, "invalid", false, 1, "invalid group list"},
		{"membership-wrong", nil, 8, "100 2000", false, 1, "test group membership mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Runner: "runner", A: "client-a", B: "client-b", Group: "test-reg"}
			if tc.edit != nil {
				tc.edit(&c)
			}
			calls := 0
			_, code, err := Verify(c, 1000, func(_ string, args ...string) (string, error) {
				calls++
				if calls == tc.at {
					if tc.fail {
						return "", errors.New("intended command failure")
					}
					return tc.reply, nil
				}
				return windowReply(args), nil
			})
			if code != tc.code || err == nil || err.Error() != tc.reason || calls != tc.at {
				t.Fatal("identity refusal changed", code, err, calls, tc)
			}
		})
	}
	c := Config{Runner: "runner", A: "client-a", B: "client-b", Group: "test-reg"}
	if _, code, err := Verify(c, 0, func(string, ...string) (string, error) { t.Fatal("root command"); return "", nil }); code != 2 || err == nil {
		t.Fatal("root runner admitted")
	}
	// The configured path, not its default, is still used if actual execution fails.
	c = toolConfig(t)
	calls := 0
	_, code, err := Verify(c, 1000, func(name string, args ...string) (string, error) {
		calls++
		if name != c.IDPath || !reflect.DeepEqual(args, []string{"-u", c.Runner}) {
			t.Fatal("configured failure fell back", name, args)
		}
		return "", errors.New("exec failed")
	})
	if code != Pending || err == nil || !strings.Contains(err.Error(), "test account unavailable") || calls != 1 {
		t.Fatal(code, err, calls)
	}
}
