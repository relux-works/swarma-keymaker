#!/usr/bin/env bash
# Invoke with bash -eo pipefail. Capture separately so syntax errors fail even
# when gofmt emits no filenames, including for platform-excluded source files.
out="$(gofmt -l "${1:-.}")"
if test -n "$out"; then
  printf '%s\n' "$out"
fi
test -z "$out"
