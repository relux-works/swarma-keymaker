#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
control_dir="$(mktemp -d)"
trap 'rm -rf -- "$control_dir"' EXIT
mkdir -p "$control_dir/valid/internal/keymaker"
printf '%s\n' 'module example.invalid/pending-control' '' 'go 1.26.0' > "$control_dir/valid/go.mod"
printf '%s\n' 'package keymaker' > "$control_dir/valid/internal/keymaker/core.go"
cat > "$control_dir/valid/internal/keymaker/multiuid_test.go" <<'EOF'
//go:build multiuid

package keymaker

import "testing"

func TestMultiUID(t *testing.T) { t.Fatal("test body must not execute") }
func TestMultiUIDFuture(t *testing.T) { t.Fatal("test body must not execute") }
EOF

# Newly added matching rows must appear without editing the reporter; fatal test
# bodies make this positive control fail if the reporter executes either row.
(cd "$control_dir/valid" && bash "$script_dir/report-pending.sh") > "$control_dir/valid.out"
test "$(wc -l < "$control_dir/valid.out")" -eq 2
grep -Fx 'PENDING: TestMultiUID requires the provisioned multi-UID test window; compile-only in CI.' "$control_dir/valid.out"
grep -Fx 'PENDING: TestMultiUIDFuture requires the provisioned multi-UID test window; compile-only in CI.' "$control_dir/valid.out"
printf '%s\n' 'PASS TestCIPendingDynamicList: two rows listed without execution'

# Removing the build tag must reject the untagged leak, without running bodies
# or reporting any row as PENDING before the refusal.
cp -R "$control_dir/valid" "$control_dir/removed"
sed '/^\/\/go:build multiuid$/d' "$control_dir/valid/internal/keymaker/multiuid_test.go" > "$control_dir/removed/internal/keymaker/multiuid_test.go"
removed_status=0
(cd "$control_dir/removed" && bash "$script_dir/report-pending.sh") > "$control_dir/removed.out" 2> "$control_dir/removed.err" || removed_status=$?
test "$removed_status" -eq 1
test ! -s "$control_dir/removed.out"
test "$(cat "$control_dir/removed.err")" = "$(printf '%s\n' 'Privileged rows present without the multiuid tag:' 'TestMultiUID' 'TestMultiUIDFuture')"
printf 'PASS TestCIPendingRemovedTag: expected rejection=%s\n' "$removed_status"

# A renamed tag leaves an empty inventory and must fail explicitly.
cp -R "$control_dir/valid" "$control_dir/renamed"
sed 's/^\/\/go:build multiuid$/\/\/go:build otherwindow/' "$control_dir/valid/internal/keymaker/multiuid_test.go" > "$control_dir/renamed/internal/keymaker/multiuid_test.go"
empty_status=0
(cd "$control_dir/renamed" && bash "$script_dir/report-pending.sh") > "$control_dir/empty.out" 2> "$control_dir/empty.err" || empty_status=$?
test "$empty_status" -eq 1
test ! -s "$control_dir/empty.out"
test "$(cat "$control_dir/empty.err")" = 'No multiuid-tagged TestMultiUID rows found'
printf 'PASS TestCIPendingEmptyList: expected rejection=%s\n' "$empty_status"

# Substitute only the Go process boundary: either inventory failure must retain
# its exact stderr and nonzero status, with no premature PENDING output.
mkdir "$control_dir/bin"
cat > "$control_dir/bin/go" <<'EOF'
#!/usr/bin/env bash
if test "$2" = '-tags'; then
  if test "$FAIL_INVENTORY" = tagged; then
    printf '%s\n' 'tagged inventory unavailable' >&2
    exit 7
  fi
  printf '%s\n' 'TestMultiUID' 'ok example.invalid/pending-control/internal/keymaker'
else
  printf '%s\n' 'untagged inventory unavailable' >&2
  exit 9
fi
EOF
chmod 0700 "$control_dir/bin/go"
for inventory in tagged untagged; do
  failure_status=0
  FAIL_INVENTORY="$inventory" PATH="$control_dir/bin:$PATH" bash "$script_dir/report-pending.sh" > "$control_dir/failure.out" 2> "$control_dir/failure.err" || failure_status=$?
  expected_status=7
  if test "$inventory" = untagged; then expected_status=9; fi
  test "$failure_status" -eq "$expected_status"
  test ! -s "$control_dir/failure.out"
  test "$(cat "$control_dir/failure.err")" = "$inventory inventory unavailable"
  printf 'PASS TestCIPendingCommandFailure/%s: expected exit=%s and original stderr\n' "$inventory" "$failure_status"
done
