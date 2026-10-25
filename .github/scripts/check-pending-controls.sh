#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
control_dir="$(mktemp -d)"
trap 'rm -rf -- "$control_dir"' EXIT
mkdir -p "$control_dir/valid/.github/scripts"
cp "$script_dir/"{report-pending.sh,pending-inventories.txt,pending-rows.txt} "$control_dir/valid/.github/scripts/"
printf '%s\n' 'module example.invalid/pending-control' '' 'go 1.26.0' > "$control_dir/valid/go.mod"

# Real Go fixtures contain every baseline row, but fatal bodies ensure that
# list-only success cannot be confused with executing qualification tests.
expected=0
while read -r tag package name; do
  if test -z "$tag" || [[ "$tag" = \#* ]]; then continue; fi
  expected=$((expected + 1))
  directory="$control_dir/valid/$package"
  mkdir -p "$directory"
  printf 'package %s\n' "${package##*/}" > "$directory/core.go"
  fixture="$directory/${tag}_test.go"
  if ! test -f "$fixture"; then
    printf '//go:build %s\n\npackage %s\n\nimport "testing"\n\n' "$tag" "${package##*/}" > "$fixture"
  fi
  printf 'func %s(t *testing.T) { t.Fatal("test body must not execute") }\n' "$name" >> "$fixture"
done < "$script_dir/pending-rows.txt"
printf '%s\n' 'func TestMultiUIDFuture(t *testing.T) { t.Fatal("test body must not execute") }' >> "$control_dir/valid/internal/keymaker/multiuid_test.go"
printf '%s\n' 'func TestQualifiedTimePendingFuture(t *testing.T) { t.Fatal("test body must not execute") }' >> "$control_dir/valid/internal/registration/qualifiedtime_test.go"

# New rows for both tags appear without changing either config or baseline.
(cd "$control_dir/valid" && bash .github/scripts/report-pending.sh) > "$control_dir/valid.out"
test "$(wc -l < "$control_dir/valid.out")" -eq "$((expected + 2))"
grep -F 'PENDING: TestMultiUIDFuture (multiuid, ./internal/keymaker)' "$control_dir/valid.out"
grep -F 'PENDING: TestQualifiedTimePendingFuture (qualifiedtime, ./internal/registration)' "$control_dir/valid.out"
while read -r tag package name; do
  if test -z "$tag" || [[ "$tag" = \#* ]]; then continue; fi
  grep -F "PENDING: $name ($tag, $package)" "$control_dir/valid.out"
done < "$script_dir/pending-rows.txt"
printf '%s\n' 'PASS TestCIPendingDynamicList: both tags and new rows listed without execution'
printf '%s\n' 'PASS TestCIPendingQualifiedTimeInventory: all three packages discovered'

# Each plant must fail for its intended reason, with no partial PENDING output.
for plant in missing-row removed-tag empty-list compile-failure; do
  cp -R "$control_dir/valid" "$control_dir/$plant"
  target="$control_dir/$plant/internal/keymaker/qualifiedtime_test.go"
  case "$plant" in
    missing-row)
      sed '/^func TestQualifiedTimePendingK3Receipt(/d' "$target" > "$target.new"
      mv "$target.new" "$target"
      diagnostic='Missing expected PENDING row: qualifiedtime ./internal/keymaker TestQualifiedTimePendingK3Receipt'
      claim=TestCIPendingMissingRow
      ;;
    removed-tag)
      sed '/^\/\/go:build qualifiedtime$/d' "$target" > "$target.new"
      mv "$target.new" "$target"
      diagnostic='PENDING rows present without the qualifiedtime tag (./internal/keymaker):'
      claim=TestCIPendingRemovedTag
      ;;
    empty-list)
      for target in "$control_dir/$plant"/internal/*/qualifiedtime_test.go; do
        sed 's/^\/\/go:build qualifiedtime$/\/\/go:build otherwindow/' "$target" > "$target.new"
        mv "$target.new" "$target"
      done
      diagnostic='No qualifiedtime-tagged ^TestQualifiedTimePending rows found'
      claim=TestCIPendingEmptyList
      ;;
    compile-failure)
      printf '%s\n' 'func broken(' >> "$target"
      diagnostic='qualifiedtime_test.go:'
      claim=TestCIPendingCompileFailure
      ;;
  esac
  status=0
  (cd "$control_dir/$plant" && bash .github/scripts/report-pending.sh) > "$control_dir/$plant.out" 2> "$control_dir/$plant.err" || status=$?
  test "$status" -eq 1
  test ! -s "$control_dir/$plant.out"
  grep -F -- "$diagnostic" "$control_dir/$plant.err"
  printf 'PASS %s: plant=%s expected reporter exit=%s\n' "$claim" "$plant" "$status"
done

# Substituting only the process boundary verifies exact Go failure propagation
# before any report, separately from the real compiler-failure control above.
mkdir "$control_dir/bin"
cat > "$control_dir/bin/go" <<'EOF_GO'
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
EOF_GO
chmod 0700 "$control_dir/bin/go"
for inventory in tagged untagged; do
  failure_status=0
  (cd "$control_dir/valid" && FAIL_INVENTORY="$inventory" PATH="$control_dir/bin:$PATH" bash .github/scripts/report-pending.sh) > "$control_dir/failure.out" 2> "$control_dir/failure.err" || failure_status=$?
  expected_status=7
  if test "$inventory" = untagged; then expected_status=9; fi
  test "$failure_status" -eq "$expected_status"
  test ! -s "$control_dir/failure.out"
  test "$(cat "$control_dir/failure.err")" = "$inventory inventory unavailable"
  printf 'PASS TestCIPendingCommandFailure/%s: expected exit=%s and original stderr\n' "$inventory" "$failure_status"
done
