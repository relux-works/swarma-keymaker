// Package testwindow validates a non-root integration-test window. It is never
// linked into the production keymaker command and supplies no generation authority.
package testwindow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const Pending = 3

type Config struct {
	Runner    string  `json:"runner_user"`
	RunnerUID *uint32 `json:"runner_uid,omitempty"`
	A         string  `json:"client_a"`
	AUID      *uint32 `json:"client_a_uid,omitempty"`
	B         string  `json:"client_b"`
	BUID      *uint32 `json:"client_b_uid,omitempty"`
	Group     string  `json:"registration_group"`
	GID       *uint32 `json:"registration_gid,omitempty"`
	Scratch   string  `json:"scratch_dir,omitempty"`
	IDPath    string  `json:"id_path,omitempty"`
	EnvPath   string  `json:"env_path,omitempty"`
}
type Window struct {
	Config
	UID, AID, BID, GroupID uint32
}
type Command func(string, ...string) (string, error)

func CommandOutput(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
	b, e := cmd.Output()
	return strings.TrimSpace(string(b)), e
}

var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func Load(path string) (Config, int, error) {
	var c Config
	if path == "" {
		return c, Pending, fmt.Errorf("test window not provisioned")
	}
	f, e := os.Open(path)
	if os.IsNotExist(e) {
		return c, Pending, fmt.Errorf("test window not provisioned")
	}
	if e != nil {
		return c, 2, fmt.Errorf("window configuration unavailable")
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 16384))
	if e != nil {
		return c, 2, fmt.Errorf("window configuration unavailable")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, 2, fmt.Errorf("invalid window configuration")
	}
	var more any
	if d.Decode(&more) != io.EOF {
		return c, 2, fmt.Errorf("invalid window configuration")
	}
	// Inspect top-level keys without losing duplicate declarations to a map.
	keys := json.NewDecoder(bytes.NewReader(raw))
	first, _ := keys.Token()
	seen := map[string]bool{}
	if first == json.Delim('{') {
		for keys.More() {
			name, e := keys.Token()
			var value json.RawMessage
			if e != nil || keys.Decode(&value) != nil {
				return c, 2, fmt.Errorf("invalid window configuration")
			}
			key := name.(string)
			canonical := strings.ToLower(key)
			if canonical == "id_path" || canonical == "env_path" {
				if key != canonical || seen[canonical] {
					return c, 2, fmt.Errorf("ambiguous window tool path")
				}
				seen[canonical] = true
				var path string
				if json.Unmarshal(value, &path) != nil || path == "" {
					return c, 2, fmt.Errorf("invalid window tool path")
				}
			}
		}
	}
	if _, e := resolveTools(c); e != nil {
		return c, 2, e
	}
	return c, 0, nil
}

func resolveTools(c Config) (Config, error) {
	for _, tool := range []struct {
		path     *string
		fallback string
	}{{&c.IDPath, "/usr/bin/id"}, {&c.EnvPath, "/usr/bin/env"}} {
		if *tool.path == "" {
			*tool.path = tool.fallback
		} else if !filepath.IsAbs(*tool.path) || filepath.Clean(*tool.path) != *tool.path || strings.IndexFunc(*tool.path, unicode.IsControl) >= 0 {
			return c, fmt.Errorf("invalid window tool path")
		}
	}
	return c, nil
}

// ClientArgs uses the paths resolved by Verify. It only constructs the existing
// sudo argument vector; it grants no permission and does not execute a command.
func (w Window) ClientArgs(user, group string, payload ...string) []string {
	args := []string{"-n", "-u", user}
	if group != "" {
		args = append(args, "-g", group)
	}
	args = append(args, "--", w.EnvPath)
	return append(args, payload...)
}

func Verify(c Config, uid uint32, run Command) (Window, int, error) {
	w := Window{Config: c, UID: uid}
	resolved, e := resolveTools(c)
	if e != nil {
		return w, 2, e
	}
	w.Config = resolved
	for _, name := range []string{c.Runner, c.A, c.B, c.Group} {
		if !accountName.MatchString(name) || name == "root" {
			return w, 2, fmt.Errorf("invalid non-root window name")
		}
	}
	if uid == 0 || c.A == c.B || c.A == c.Runner || c.B == c.Runner {
		return w, 2, fmt.Errorf("window identities must be distinct and unprivileged")
	}
	// Only explicit paths add this availability check. Defaults retain their
	// existing command-driven behavior. Stat is not root custody qualification.
	for _, tool := range []struct{ name, path string }{{"id", c.IDPath}, {"env", c.EnvPath}} {
		if tool.path != "" {
			info, e := os.Stat(tool.path)
			if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return w, Pending, fmt.Errorf("test %s executable unavailable", tool.name)
			}
		}
	}
	number := func(s string) (uint32, error) {
		v, e := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
		return uint32(v), e
	}
	ids := []*uint32{&w.UID, &w.AID, &w.BID}
	names := []string{c.Runner, c.A, c.B}
	pins := []*uint32{c.RunnerUID, c.AUID, c.BUID}
	// Resolve the test accounts before sudo, so an alias of UID 0 is never used as
	// Runas. These checks validate provisioning, never infer account generations.
	for i, name := range names {
		s, e := run(w.IDPath, "-u", name)
		if e != nil {
			return w, Pending, fmt.Errorf("test account unavailable")
		}
		v, e := number(s)
		if e != nil || v == 0 || i == 0 && v != uid || pins[i] != nil && v != *pins[i] {
			return w, 2, fmt.Errorf("window UID mismatch")
		}
		*ids[i] = v
	}
	if w.AID == w.BID || w.AID == uid || w.BID == uid {
		return w, 2, fmt.Errorf("window UID collision")
	}
	for i, name := range names[1:] {
		s, e := run("sudo", "-n", "-u", name, "--", w.IDPath, "-u")
		if e != nil {
			return w, Pending, fmt.Errorf("test sudo unavailable")
		}
		v, e := number(s)
		if e != nil || v != *ids[i+1] {
			return w, 1, fmt.Errorf("sudo identity mismatch")
		}
	}
	s, e := run("sudo", "-n", "-u", c.Runner, "-g", c.Group, "--", w.IDPath, "-g")
	if e != nil {
		return w, Pending, fmt.Errorf("test group sudo unavailable")
	}
	w.GroupID, e = number(s)
	if e != nil || w.GroupID == 0 || c.GID != nil && w.GroupID != *c.GID {
		return w, 1, fmt.Errorf("test group mismatch")
	}
	for _, sample := range []struct {
		name string
		want bool
	}{{c.A, true}, {c.B, false}} {
		s, e := run("sudo", "-n", "-u", sample.name, "--", w.IDPath, "-G")
		if e != nil {
			return w, Pending, fmt.Errorf("test membership unavailable")
		}
		found := false
		for _, field := range strings.Fields(s) {
			v, e := number(field)
			if e != nil {
				return w, 1, fmt.Errorf("invalid group list")
			}
			if v == w.GroupID {
				found = true
			}
		}
		if found != sample.want {
			return w, 1, fmt.Errorf("test group membership mismatch")
		}
	}
	return w, 0, nil
}
