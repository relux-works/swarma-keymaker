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
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
	format "github.com/relux-works/swarma-registrar/enrollment"
)

// Metadata is the small ownership boundary used by configuration fixtures.
type Metadata struct {
	Mode  fs.FileMode
	UID   uint32
	Links uint64
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
	ServiceUID  *uint32           `json:"service_uid,omitempty"`
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
	value, err := ccj.Parse(b, ccj.EnrollmentMalformed)
	target := reflect.TypeOf(out)
	if err != nil || target == nil || target.Kind() != reflect.Pointer || !exactJSONMembers(value, target.Elem()) {
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

// Check member spellings before encoding/json can apply case-insensitive struct
// matching. Map keys remain data, but integer keys must have one canonical
// spelling so that distinct JSON keys cannot collapse into one history entry.
func exactJSONMembers(value any, target reflect.Type) bool {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if value == nil {
		return true // Callers retain their required-value checks.
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := make(map[string]reflect.Type, target.NumField())
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			// Protected records have no promoted fields or custom unmarshalers.
			if field.Anonymous {
				return false
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, member := range object {
			field, exists := fields[name]
			if !exists || !exactJSONMembers(member, field) {
				return false
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		for key, member := range object {
			if target.Key().Kind() != reflect.String {
				if target.Key().Kind() != reflect.Int64 {
					return false
				}
				number, err := strconv.ParseInt(key, 10, 64)
				if err != nil || strconv.FormatInt(number, 10) != key {
					return false
				}
			}
			if !exactJSONMembers(member, target.Elem()) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, member := range array {
			if !exactJSONMembers(member, target.Elem()) {
				return false
			}
		}
	}
	return true
}

// configLocation contains only the protected bytes and the path required to
// acquire the lock. No other config member is typed or validated before it.
type configLocation struct {
	stateDir string
	raw      []byte
}

func locateConfig(path string, files Files) (configLocation, error) {
	b, err := protectedRead(files, path, 1<<20, 0)
	if err != nil {
		return configLocation{}, err
	}
	value, err := ccj.Parse(b, ccj.EnrollmentMalformed)
	if err != nil {
		return configLocation{}, errTrust
	}
	object, ok := value.(map[string]any)
	if !ok {
		return configLocation{}, errTrust
	}
	state, ok := object["state_dir"].(string)
	if !ok || !absolute(state) {
		return configLocation{}, errTrust
	}
	return configLocation{state, b}, nil
}
func decodeConfig(location configLocation) (PinConfig, *format.Policy, error) {
	var c PinConfig
	if err := strictJSON(location.raw, &c); err != nil {
		return c, nil, err
	}
	p, err := validateConfig(c)
	return c, p, err
}
func loadConfig(path string, files Files) (PinConfig, *format.Policy, error) {
	location, err := locateConfig(path, files)
	if err != nil {
		return PinConfig{}, nil, err
	}
	return decodeConfig(location)
}

func validateConfig(c PinConfig) (*format.Policy, error) {
	if !revisionPattern.MatchString(c.Revision) || !absolute(c.Registry) || !absolute(c.StateDir) || len(c.Maintainers) == 0 || !canonicalAudience(c.Audience) || len(c.Stations) == 0 {
		return nil, errTrust
	}
	if c.ServiceUID != nil && (*c.ServiceUID == 0 || *c.ServiceUID == 4294967295) {
		return nil, errTrust
	}
	for _, key := range c.Maintainers {
		if _, err := parseMaintainer(key); err != nil {
			return nil, err
		}
	}
	for host := range c.Stations {
		if !hostPattern.MatchString(host) {
			return nil, errTrust
		}
	}
	for uid, generation := range c.Generations {
		n, err := strconv.ParseUint(uid, 10, 32)
		if err != nil || n == 0 || n == 4294967295 || strconv.FormatUint(n, 10) != uid || !generationPattern.MatchString(generation) || generation == strings.Repeat("0", 32) {
			return nil, errTrust
		}
	}
	p, err := format.NewPolicy(c.Audience, c.Publisher, c.Stations)
	return p, err
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
