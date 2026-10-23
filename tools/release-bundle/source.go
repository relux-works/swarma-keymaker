package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	errDirty   = errors.New("release source tree is dirty")
	errCommit  = errors.New("release source must be at the requested full commit")
	errVersion = errors.New("release version mismatch")
	errUnit    = errors.New("release unit differs from specification section 12.1")
)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func gitEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0"}
}
func gitCommand(ctx context.Context, repo string, args ...string) *exec.Cmd {
	full := append([]string{"--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repo}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = gitEnv()
	return cmd
}
func gitRead(ctx context.Context, repo string, args ...string) ([]byte, error) {
	cmd := gitCommand(ctx, repo, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	// Never repeat repository command diagnostics containing operator input.
	if err := runCommand(cmd); err != nil {
		return nil, fmt.Errorf("source inspection failed")
	}
	return out.Bytes(), nil
}
func cleanSource(ctx context.Context, repo, commit string) error {
	if !commitPattern.MatchString(commit) {
		return errCommit
	}
	head, err := gitRead(ctx, repo, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || strings.TrimSpace(string(head)) != commit {
		return errCommit
	}
	status, err := gitRead(ctx, repo, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none")
	if err != nil {
		return err
	}
	if len(status) != 0 {
		return errDirty
	}
	return nil
}
func unitMatchesSpec(unit, spec []byte) error {
	_, section, ok := strings.Cut(string(spec), "### 12.1 ")
	if !ok {
		return errUnit
	}
	section, _, _ = strings.Cut(section, "### 12.2 ")
	_, block, ok := strings.Cut(section, "```ini\n")
	if !ok {
		return errUnit
	}
	block, _, ok = strings.Cut(block, "```")
	if !ok || !bytes.Equal(unit, []byte(block)) {
		return errUnit
	}
	return nil
}
func sourceVersion(raw []byte) (string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", raw, 0)
	if err != nil {
		return "", errVersion
	}
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if name.Name != "version" || i >= len(value.Values) {
					continue
				}
				literal, ok := value.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return "", errVersion
				}
				version, err := strconv.Unquote(literal.Value)
				if err != nil {
					return "", errVersion
				}
				return version, nil
			}
		}
	}
	return "", errVersion
}

// git archive supplies an immutable source snapshot. Only ordinary files and
// directories are materialized under the newly owned target, never links.
func extractSource(ctx context.Context, repo, commit, dest string) error {
	cmd := gitCommand(ctx, repo, "archive", "--format=tar", commit)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release child pid=%d\n", cmd.Process.Pid)
	readErr := extractTar(pipe, dest)
	pipe.Close()
	waitErr := cmd.Wait()
	if readErr != nil {
		return readErr
	}
	return waitErr
}
func extractTar(r io.Reader, dest string) error {
	tarReader := tar.NewReader(r)
	var total int64
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("source archive refused")
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || path.IsAbs(name) || path.Clean(name) != name || strings.Contains(name, "\\") || name == ".." || strings.HasPrefix(name, "../") || strings.Contains("/"+name+"/", "/.git/") {
			return fmt.Errorf("source archive path refused")
		}
		file := filepath.Join(dest, filepath.FromSlash(name))
		if !inside(dest, file) {
			return fmt.Errorf("source archive path refused")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(file, 0700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > (128<<20)-total {
				return fmt.Errorf("source archive size refused")
			}
			total += h.Size
			if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
				return err
			}
			f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tarReader, h.Size)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("source archive entry refused")
		}
	}
}
