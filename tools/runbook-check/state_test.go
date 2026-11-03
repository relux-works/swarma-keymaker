package main

import (
	"os"
	"strings"
	"testing"
)

// Removing the marked install fails even if an unmarked decoy remains; the
// actual excerpt passes. Missing or duplicate markers fail closed.
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
	decoy := strings.Replace(good, stateInstall, "", 1) + stateInstall
	if err := checkStateDirectory(decoy); err == nil || err.Error() != "missing ordered private state directory install" {
		t.Fatal("unmarked decoy accepted", err)
	}
	for _, bad := range []string{
		strings.Replace(good, "# runbook-check:begin service-state-directory\n", "", 1),
		good + "# runbook-check:begin service-state-directory\n",
	} {
		if err := checkStateDirectory(bad); err == nil || !strings.Contains(err.Error(), "ambiguous or missing runbook excerpt") {
			t.Fatal("invalid markers accepted", err)
		}
	}
	if err := checkStateDirectory(good); err != nil {
		t.Fatal("valid excerpt control", err)
	}
}
