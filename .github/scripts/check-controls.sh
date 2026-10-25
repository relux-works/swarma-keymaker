#!/usr/bin/env bash
# Invoke with bash -eo pipefail. Valid controls and isolated copies prove
# tidy/vet/format/hygiene rejection, including Linux-excluded syntax errors.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
control_dir="$(mktemp -d)"
trap 'rm -rf -- "$control_dir"' EXIT
mkdir "$control_dir/valid"
printf '%s\n' 'module example.invalid/ci-control' '' 'go 1.26.0' > "$control_dir/valid/go.mod"
printf '%s\n' 'package control' '' 'func valid() {}' > "$control_dir/valid/good.go"
(cd "$control_dir/valid" && go vet ./...)
bash --noprofile --norc -eo pipefail "$script_dir/check-format.sh" "$control_dir/valid"
printf '%s\n' 'PASS TestCIToolsValidControl: vet=0 formatting=0'

# Unused checksum entries must fail the same tidy-diff command as CI, offline.
(cd "$control_dir/valid" && GOPROXY=off go mod tidy -diff)
cp -R "$control_dir/valid" "$control_dir/tidy"
printf '%s\n' 'example.invalid/stale v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > "$control_dir/tidy/go.sum"
tidy_status=0
(cd "$control_dir/tidy" && GOPROXY=off go mod tidy -diff) > "$control_dir/tidy.log" 2>&1 || tidy_status=$?
test "$tidy_status" -eq 1
grep -F -- '-example.invalid/stale v1.0.0' "$control_dir/tidy.log"
printf 'PASS TestCITidyControl: valid=0 expected stale-entry exit=%s\n' "$tidy_status"

# A compilable printf mismatch must fail vet at the intended diagnostic.
cp -R "$control_dir/valid" "$control_dir/vet"
printf '%s\n' 'package control' 'import "fmt"' 'func bad() { fmt.Printf("%d", "wrong") }' > "$control_dir/vet/vet.go"
vet_status=0
(cd "$control_dir/vet" && go vet ./...) > "$control_dir/vet.log" 2>&1 || vet_status=$?
test "$vet_status" -eq 1
grep -F 'fmt.Printf format %d has arg "wrong" of wrong type string' "$control_dir/vet.log"
printf 'PASS TestCIVetControl: expected vet exit=%s\n' "$vet_status"

# An otherwise valid source file must fail the exact formatting step and name it.
cp -R "$control_dir/valid" "$control_dir/format"
printf '%s\n' 'package control' 'func unformatted( ){ }' > "$control_dir/format/format.go"
format_status=0
bash --noprofile --norc -eo pipefail "$script_dir/check-format.sh" "$control_dir/format" > "$control_dir/format.log" 2>&1 || format_status=$?
test "$format_status" -eq 1
test "$(cat "$control_dir/format.log")" = "$control_dir/format/format.go"
printf 'PASS TestCIFormatControl: expected formatting exit=%s\n' "$format_status"

# Linux build/vet exclude this broken file. gofmt must still fail, even with
# empty stdout: testing only an inline command substitution would lose exit 2.
cp -R "$control_dir/valid" "$control_dir/syntax"
printf '%s\n' '//go:build windows' '' 'package control' '' 'func broken(' > "$control_dir/syntax/bad_windows.go"
(cd "$control_dir/syntax" && go build ./... && go vet ./...)
formatter_status=0
gofmt -l "$control_dir/syntax" > "$control_dir/parse.out" 2> "$control_dir/parse.log" || formatter_status=$?
test "$formatter_status" -eq 2
test ! -s "$control_dir/parse.out"
grep -F 'bad_windows.go:' "$control_dir/parse.log"
parse_status=0
bash --noprofile --norc -eo pipefail "$script_dir/check-format.sh" "$control_dir/syntax" > "$control_dir/parse-step.log" 2>&1 || parse_status=$?
if test "$parse_status" -ne 2; then
  printf 'FAIL TestFormatCommandSubstitutionStatus: expected step exit 2, got %s\n' "$parse_status" >&2
  exit 1
fi
grep -F 'bad_windows.go:' "$control_dir/parse-step.log"
printf 'PASS TestFormatCommandSubstitutionStatus: expected gofmt=%s step=%s\n' "$formatter_status" "$parse_status"

# The all-tracked-file hygiene check must accept ordinary prose and refuse
# each attribution class; no commit, signing key or source-repository edit.
mkdir "$control_dir/hygiene"
git -C "$control_dir/hygiene" -c init.templateDir= init --quiet
printf '%s\n' 'Ordinary project documentation.' > "$control_dir/hygiene/notes.txt"
git -C "$control_dir/hygiene" add notes.txt
(cd "$control_dir/hygiene" && python3 "$script_dir/check-hygiene.py")
for kind in link session generated attribution identity; do
  case "$kind" in
    link) printf 'https://claude%sai/chat/example\n' '.' ;;
    session) printf 'session%smetadata\n' '_' ;;
    generated) printf 'Generated%swith example\n' ' ' ;;
    attribution) printf 'Co%sAuthored%sBy: example\n' '-' '-' ;;
    identity) printf 'agents%s_ci_dev1\n' '1' ;;
  esac > "$control_dir/hygiene/notes.txt"
  hygiene_status=0
  (cd "$control_dir/hygiene" && python3 "$script_dir/check-hygiene.py") > "$control_dir/hygiene.log" 2>&1 || hygiene_status=$?
  test "$hygiene_status" -eq 1
  grep -F 'Attribution metadata in tracked file:' "$control_dir/hygiene.log"
  printf 'PASS TestCIHygieneControl/%s: valid=0 expected rejection=%s\n' "$kind" "$hygiene_status"
done
