//go:build qualifiedtime

package registration

import "testing"

// Volatile last/hold and an original point grant do not supply the provider's
// durable W or reboot recovery; this row stays red until that input exists.
func TestQualifiedTimePendingRegistrationContinuity(t *testing.T) {
	t.Fatal("PENDING: provider-owned durable W/in-flight/hold settlement and independent rollback-witness CAS, plus approved registration receipt and recovery mapping")
}
