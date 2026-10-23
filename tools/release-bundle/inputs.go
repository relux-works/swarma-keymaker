package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-keymaker/internal/keymaker"
)

var (
	errInput      = errors.New("release input must be a bounded regular file without symlinks")
	errTarget     = errors.New("release target must be new, outside source and system paths")
	errConfig     = errors.New("release configuration refused")
	errRegistry   = errors.New("release name-index registry refused")
	errEnrollment = errors.New("enrollment validation unavailable at this revision")
)

const inputLimit = 8 << 20

// Check every existing component rather than following a symlinked ancestor.
func pathWithoutLinks(name string, allowMissing bool) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", errInput
	}
	for at := abs; ; at = filepath.Dir(at) {
		st, err := os.Lstat(at)
		if err != nil {
			if !(allowMissing && at == abs && os.IsNotExist(err)) {
				return "", errInput
			}
		} else if st.Mode()&os.ModeSymlink != 0 {
			return "", errInput
		}
		if at == filepath.Dir(at) {
			break
		}
	}
	return abs, nil
}
func readInput(name string) ([]byte, error) {
	if name == "" {
		return nil, errInput
	}
	abs, err := pathWithoutLinks(name, false)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errInput
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > inputLimit {
		return nil, errInput
	}
	body, err := io.ReadAll(io.LimitReader(f, inputLimit+1))
	if err != nil || len(body) > inputLimit {
		return nil, errInput
	}
	return body, nil
}
func inside(root, name string) bool {
	rel, err := filepath.Rel(root, name)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func targetPath(repo, name string) (string, error) {
	if name == "" {
		return "", errTarget
	}
	abs, err := filepath.Abs(name)
	if err != nil || abs == "/" || abs == "/home" || inside(repo, abs) {
		return "", errTarget
	}
	// Read-only policy checks precede all target filesystem access.
	for _, root := range []string{"/etc", "/usr", "/var", "/run", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys", "/root", "/opt", "/srv"} {
		if inside(root, abs) {
			return "", errTarget
		}
	}
	if _, err := os.Lstat(abs); !os.IsNotExist(err) {
		return "", errTarget
	}
	if _, err := pathWithoutLinks(abs, true); err != nil {
		return "", errTarget
	}
	st, err := os.Stat(filepath.Dir(abs))
	if err != nil || !st.IsDir() {
		return "", errTarget
	}
	return abs, nil
}
func validateInputs(o options) (map[string][]byte, error) {
	config, err := readInput(o.config)
	if err != nil {
		return nil, err
	}
	if _, err = keymaker.ParseConfig(bytes.NewReader(config)); err != nil {
		return nil, fmt.Errorf("%w: invalid members, types or pins", errConfig)
	}
	registry, err := readInput(o.registry)
	if err != nil {
		return nil, err
	}
	var parsed keymaker.Registry
	if keymaker.StrictJSON(bytes.NewReader(registry), &parsed) != nil || parsed.Validate() != "" {
		return nil, errRegistry
	}
	if o.enrollment != "" {
		if _, err := readInput(o.enrollment); err != nil {
			return nil, err
		}
		return nil, errEnrollment
	}
	return map[string][]byte{"config.json": config, "name-indices.json": registry}, nil
}
