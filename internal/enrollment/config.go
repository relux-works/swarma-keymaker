// Package enrollment supplies protected local trust and authorization around the
// registrar's pinned schema, signature and snapshot implementation.
package enrollment

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
	format "github.com/relux-works/swarma-registrar/enrollment"
)

// Metadata is the small ownership boundary used by configuration fixtures.
type Metadata struct {
	Mode fs.FileMode
	UID  uint32
}

// Files supplies no-follow file reads and lstat metadata. Production uses LinuxFiles.
// Test implementations must not be installed in a deployed service.
type Files interface {
	Lstat(string) (Metadata, error)
	Read(string, int64) ([]byte, Metadata, error)
	Readable(string) error
}

// PinConfig is local policy, never an enrollment/1 document. Registry is the
// absolute Git directory (a bare repository or an explicitly selected .git).
// Stations classifies every host independently of its signed enrollment.
type PinConfig struct {
	Maintainers []string          `json:"maintainers"`
	Revision    string            `json:"revision"`
	Publisher   string            `json:"publisher"`
	Audience    string            `json:"audience"`
	Registry    string            `json:"registry"`
	StateDir    string            `json:"state_dir"`
	Stations    map[string]bool   `json:"stations"`
	Generations map[string]string `json:"generations"`
	FirstUse    bool              `json:"first_use"`
}

var errTrust = errors.New("unverified local trust")
var revisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var generationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hostPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func absolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
func safeMeta(m Metadata, directory bool, owner uint32) bool {
	return (m.UID == 0 || m.UID == owner) && m.Mode&0022 == 0 &&
		((directory && m.Mode.IsDir()) || (!directory && m.Mode.IsRegular()))
}
func safeParents(files Files, path string, owner uint32) error {
	if !absolute(path) {
		return errTrust
	}
	for dir := path; ; dir = filepath.Dir(dir) {
		m, err := files.Lstat(dir)
		if err != nil {
			return err
		}
		if !safeMeta(m, true, owner) {
			return errTrust
		}
		if dir == "/" {
			return nil
		}
	}
}
func protectedRead(files Files, path string, limit int64, owner uint32) ([]byte, error) {
	if !absolute(path) {
		return nil, errTrust
	}
	if err := safeParents(files, filepath.Dir(path), owner); err != nil {
		return nil, err
	}
	m, err := files.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !safeMeta(m, false, owner) {
		return nil, errTrust
	}
	b, opened, err := files.Read(path, limit)
	if err != nil {
		return nil, err
	}
	if !safeMeta(opened, false, owner) {
		return nil, errTrust
	}
	return b, nil
}
func strictJSON(b []byte, out any) error {
	if _, err := ccj.Parse(b, ccj.EnrollmentMalformed); err != nil {
		return errTrust
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errTrust
	}
	if dec.Decode(new(any)) != io.EOF {
		return errTrust
	}
	return nil
}
func loadConfig(path string, files Files) (PinConfig, *format.Policy, error) {
	var c PinConfig
	b, err := protectedRead(files, path, 1<<20, 0)
	if err != nil {
		return c, nil, err
	}
	if err = strictJSON(b, &c); err != nil {
		return c, nil, err
	}
	if !revisionPattern.MatchString(c.Revision) || !absolute(c.Registry) || !absolute(c.StateDir) || len(c.Maintainers) == 0 || !canonicalAudience(c.Audience) || len(c.Stations) == 0 {
		return c, nil, errTrust
	}
	for _, key := range c.Maintainers {
		if _, err := parseMaintainer(key); err != nil {
			return c, nil, err
		}
	}
	for host := range c.Stations {
		if !hostPattern.MatchString(host) {
			return c, nil, errTrust
		}
	}
	for uid, generation := range c.Generations {
		n, err := strconv.ParseUint(uid, 10, 32)
		if err != nil || n == 0 || n == 4294967295 || strconv.FormatUint(n, 10) != uid || !generationPattern.MatchString(generation) || generation == strings.Repeat("0", 32) {
			return c, nil, errTrust
		}
	}
	p, err := format.NewPolicy(c.Audience, c.Publisher, c.Stations)
	return c, p, err
}

// Matrix server names are canonical ASCII DNS/IPv4 or bracketed IPv6, with an
// optional canonical decimal port. Request input never selects this value.
func canonicalAudience(s string) bool {
	if len(s) < 1 || len(s) > 255 || strings.ToLower(s) != s {
		return false
	}
	host, port := s, ""
	if strings.HasPrefix(s, "[") {
		close := strings.IndexByte(s, ']')
		if close < 0 {
			return false
		}
		host = s[1:close]
		ip := net.ParseIP(host)
		if ip == nil || !strings.Contains(host, ":") || ip.String() != host {
			return false
		}
		rest := s[close+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return false
			}
			port = rest[1:]
			if port == "" {
				return false
			}
		}
	} else {
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			host, port = s[:i], s[i+1:]
			if port == "" {
				return false
			}
		}
		if len(host) < 1 || len(host) > 253 || strings.HasSuffix(host, ".") {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, c := range []byte(label) {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
		}
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return false
		}
	}
	return true
}
func localCode(err error) Code {
	if errors.Is(err, errTrust) {
		return EnrollmentUnverified
	}
	var refusal *format.Error
	if errors.As(err, &refusal) {
		return EnrollmentUnverified
	}
	return EnrollmentUnavailable
}
