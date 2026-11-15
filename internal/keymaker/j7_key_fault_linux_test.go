//go:build linux

package keymaker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Existing staging evidence and directory symlinks refuse without removing or
// overwriting unknown objects; a fresh protected fixture initializes and loads.
func TestJ7KeyInitializationNeighbours(t *testing.T) {
	uid := uint32(os.Getuid())
	instance := strings.Repeat("1", 32)
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("fixture mode")
	}
	path := filepath.Join(dir, "root")
	stage := filepath.Join(dir, ".root.next")
	if os.WriteFile(stage, []byte("retained intent"), 0600) != nil {
		t.Fatal("fixture intent")
	}
	if InitializeJ7Seed(path, uid, j7RequestRole, instance) == nil {
		t.Fatal("old intent overwritten")
	}
	got, err := os.ReadFile(stage)
	if err != nil || !bytes.Equal(got, []byte("retained intent")) {
		t.Fatal("old intent altered")
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	if InitializeJ7Seed(path, uid, j7RequestRole, instance) != nil {
		t.Fatal("fresh control")
	}
	key, err := loadJ7Key(path, uid, j7RequestRole, instance, "epoch", "registry")
	if err != nil {
		t.Fatal(err)
	}
	key.close()
	link := filepath.Join(t.TempDir(), "directory")
	if os.Symlink(dir, link) != nil {
		t.Fatal("fixture symlink")
	}
	if key, err := loadJ7Key(filepath.Join(link, "root"), uid, j7RequestRole, instance, "epoch", "registry"); err == nil || key != nil {
		t.Fatal("symlink directory admitted")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(path, raw[:len(raw)-1], 0600) != nil {
		t.Fatal("fixture truncation")
	}
	clear(raw)
	if key, err := loadJ7Key(path, uid, j7RequestRole, instance, "epoch", "registry"); err == nil || key != nil {
		t.Fatal("short root accepted")
	}
}

// Concurrent explicit initializers have one winner and cannot overwrite it;
// the one complete published record remains loadable under the exact pins.
func TestJ7KeyInitializationRace(t *testing.T) {
	uid := uint32(os.Getuid())
	id := strings.Repeat("1", 32)
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("fixture mode")
	}
	path := filepath.Join(dir, "root")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- InitializeJ7Seed(path, uid, j7RequestRole, id) }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("initialization winners %d", winners)
	}
	key, err := loadJ7Key(path, uid, j7RequestRole, id, "epoch", "registry")
	if err != nil {
		t.Fatal(err)
	}
	key.close()
}
