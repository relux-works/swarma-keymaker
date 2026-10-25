//go:build qualifiedtime

package keymaker

import "testing"

// Audit currently collects while outer Store/generation and journal locks can
// be held. Moving collection just above the journal gate cannot qualify it.
func TestQualifiedTimePendingAuditPreWindow(t *testing.T) {
	t.Fatal("PENDING: no provider call under Store, generation or journal locks requires a bounded pre-window handoff or receipt checkable without a provider call, including C/F and original deadlines")
}

// The pure seconds arithmetic is not the missing authenticated K3 evidence;
// keep this qualification row explicitly failing until the owner API exists.
func TestQualifiedTimePendingK3Receipt(t *testing.T) {
	t.Fatal("PENDING: broker or registry authenticated receipt API, closed codec/validator and retained evidence, current boot/challenge/operation binding, confirmed continuity and interval-aware K3/G4 mapping")
}
