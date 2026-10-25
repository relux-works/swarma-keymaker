#!/usr/bin/env bash
# Invoke with bash -eo pipefail. A valid control and three isolated copies prove
# vet/format rejection, including a syntax error excluded from the Linux build.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
control_dir="$(mktemp -d)"
trap 'rm -rf -- "$control_dir"' EXIT
mkdir "$control_dir/valid"
printf '%s\n' 'module example.invalid/ci-control' '' 'go 1.26.0' > "$control_dir/valid/go.mod"
printf '%s\n' 'package control' '' 'func valid() {}' > "$control_dir/valid/good.go"
(cd "$control_dir/valid" && go vet ./...)
bash --noprofile --norc -eo pipefail "$script_dir/check-format.sh" "$control_dir/valid"
printf '%s\n' 'PASS TestCIToolsValidControl: vet=0 formatting=0'

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
