//go:build qualifiedtime && linux

package enrollment

import "testing"

// A replacement process cannot derive L_issue from the closed issue-point
// record. This remains a failing qualification row, never a skipped test.
func TestQualifiedTimePendingEnrollmentIssueBound(t *testing.T) {
	t.Fatal("PENDING: 600-second enrollment needs the approved durable issue delta, deadline and receipt reference; confirmed_utc_ns remains the issue point")
}
