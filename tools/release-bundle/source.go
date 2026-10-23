package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
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
	"sort"
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
	return []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_GRAFT_FILE=/dev/null", "GIT_SHALLOW_FILE=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_COUNT=0", "GIT_ALLOW_PROTOCOL="}
}
func gitCommand(ctx context.Context, repo string, args ...string) *exec.Cmd {
	full := append([]string{"--no-optional-locks", "--no-replace-objects", "-c", "core.commitGraph=false", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repo}, args...)
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
	// Alternates are not a self-contained immutable source. Resolve the actual
	// object directory even for linked worktrees; never inherit an object redirect.
	common, err := gitRead(ctx, repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return errCommit
	}
	objects := filepath.Join(strings.TrimSpace(string(common)), "objects")
	if _, err := pathWithoutLinks(objects, false); err != nil {
		return errCommit
	}
	for _, name := range []string{"alternates", "http-alternates"} {
		raw, e := readInput(filepath.Join(objects, "info", name))
		if e == nil && len(raw) == 0 {
			continue
		}
		if _, e := os.Lstat(filepath.Join(objects, "info", name)); os.IsNotExist(e) {
			continue
		}
		return errCommit
	}

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
func extractSource(ctx context.Context, repo, commit string, dest *os.Root) error {
	cmd := gitCommand(ctx, repo, "archive", "--format=tar", commit+"^{tree}")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release child pid=%d\n", cmd.Process.Pid)
	readErr := extractTarRoot(pipe, dest)
	pipe.Close()
	waitErr := cmd.Wait()
	if readErr != nil {
		return readErr
	}
	return waitErr
}
func extractTar(r io.Reader, dest string) error {
	root, err := openRootNoLinks(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	return extractTarRoot(r, root)
}
func extractTarRoot(r io.Reader, dest *os.Root) error {
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
		file := filepath.FromSlash(name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := mkdirRootAll(dest, file); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > (128<<20)-total {
				return fmt.Errorf("source archive size refused")
			}
			total += h.Size
			if err := mkdirRootAll(dest, filepath.Dir(file)); err != nil {
				return err
			}
			mode := os.FileMode(0600)
			if h.Mode&0111 != 0 {
				mode = 0700
			}
			f, err := openRootFile(dest, file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
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

var errTree = errors.New("exported source tree does not match requested commit")

// Hash the actual exported file bytes/modes using Git's tree object encoding.
// No index, attributes, replace refs, grafts or repository configuration participate.
func treeHash(root *os.Root) (string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return "", err
	}
	entries, err := dir.ReadDir(-1)
	closeErr := dir.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].Name(), entries[j].Name()
		if entries[i].IsDir() {
			a += "/"
		}
		if entries[j].IsDir() {
			b += "/"
		}
		return a < b
	})
	var tree bytes.Buffer
	for _, entry := range entries {
		mode := "100644"
		var digest string
		file, err := openRootFile(root, entry.Name(), os.O_RDONLY, 0)
		if err != nil {
			return "", err
		}
		st, err := file.Stat()
		if err != nil {
			file.Close()
			return "", err
		}
		if st.IsDir() {
			file.Close()
			child, err := root.OpenRoot(entry.Name())
			if err != nil {
				return "", err
			}
			digest, err = treeHash(child)
			child.Close()
			if err != nil {
				return "", err
			}
			mode = "40000"
		} else if st.Mode().IsRegular() {
			h := sha1.New()
			fmt.Fprintf(h, "blob %d\x00", st.Size())
			_, err = io.Copy(h, file)
			closeErr := file.Close()
			if err != nil {
				return "", err
			}
			if closeErr != nil {
				return "", closeErr
			}
			digest = hex.EncodeToString(h.Sum(nil))
			if st.Mode()&0111 != 0 {
				mode = "100755"
			}
		} else {
			file.Close()
			return "", errTree
		}
		raw, err := hex.DecodeString(digest)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&tree, "%s %s\x00", mode, entry.Name())
		tree.Write(raw)
	}
	h := sha1.New()
	fmt.Fprintf(h, "tree %d\x00", tree.Len())
	h.Write(tree.Bytes())
	return hex.EncodeToString(h.Sum(nil)), nil
}
func verifyTree(root *os.Root, expected string) error {
	got, err := treeHash(root)
	if err != nil || got != expected {
		return errTree
	}
	return nil
}

// Bind the tree to the raw commit object, not only a rev-parse expression.
func commitTree(ctx context.Context, repo, commit string) (string, error) {
	raw, err := gitRead(ctx, repo, "cat-file", "commit", commit)
	if err != nil {
		return "", errCommit
	}
	h := sha1.New()
	fmt.Fprintf(h, "commit %d\x00", len(raw))
	h.Write(raw)
	if hex.EncodeToString(h.Sum(nil)) != commit {
		return "", errCommit
	}
	first, _, _ := strings.Cut(string(raw), "\n")
	tree, ok := strings.CutPrefix(first, "tree ")
	if !ok || !commitPattern.MatchString(tree) {
		return "", errCommit
	}
	return tree, nil
}
