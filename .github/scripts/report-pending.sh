#!/usr/bin/env bash
# List-only compilation does not qualify the privileged test window.
set -euo pipefail

# Keep these assignments standalone: Go's stderr and exit status must survive.
tagged="$(go test -tags multiuid -list '^TestMultiUID' ./internal/keymaker)"
tagged_names="$(printf '%s\n' "$tagged" | awk '/^TestMultiUID[^[:space:]]*$/')"
if test -z "$tagged_names"; then
  printf '%s\n' 'No multiuid-tagged TestMultiUID rows found' >&2
  exit 1
fi

# A removed build tag must fail before the ordinary suite can execute these rows.
untagged="$(go test -list '^TestMultiUID' ./internal/keymaker)"
untagged_names="$(printf '%s\n' "$untagged" | awk '/^TestMultiUID[^[:space:]]*$/')"
if test -n "$untagged_names"; then
  printf 'Privileged rows present without the multiuid tag:\n%s\n' "$untagged_names" >&2
  exit 1
fi

while IFS= read -r name; do
  printf 'PENDING: %s requires the provisioned multi-UID test window; compile-only in CI.\n' "$name"
done <<< "$tagged_names"
