package main

import (
	"os"
	"strings"
	"testing"
)

// Removing the state install fails its named assertion; the actual excerpt passes.
func TestRunbookStateDirectory(t *testing.T) {
	raw, err := os.ReadFile("../../spec/keymaker.md")
	if err != nil {
		t.Fatal(err)
	}
	good := string(raw)
	if strings.Count(good, stateInstall) != 1 {
		t.Fatal("state install plant not applied")
	}
	if err := checkStateDirectory(strings.Replace(good, stateInstall, "", 1)); err == nil || err.Error() != "missing ordered private state directory install" {
		t.Fatal("state install removal undetected", err)
	}
	if err := checkStateDirectory(good); err != nil {
		t.Fatal("valid excerpt control", err)
	}
}
