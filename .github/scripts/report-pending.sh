#!/usr/bin/env bash
# Compilation and discovery never qualify or execute pending test bodies.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
rows=''
report=''
inventories=0

# Keep Go assignments standalone: original compile errors/statuses must survive.
# One mechanism covers every configured tag/pattern and its package set.
while IFS='|' read -r tag pattern reason packages; do
  if test -z "$tag" || [[ "$tag" = \#* ]]; then continue; fi
  inventories=$((inventories + 1))
  count=0
  read -r -a package_list <<< "$packages"
  for package in "${package_list[@]}"; do
    tagged="$(go test -tags "$tag" -list "$pattern" "$package")"
    tagged_names="$(printf '%s\n' "$tagged" | awk -v pattern="$pattern" '$0 ~ pattern && $0 !~ /[[:space:]]/')"

    # Missing tags must not leak qualification bodies into the ordinary suite.
    untagged="$(go test -list "$pattern" "$package")"
    untagged_names="$(printf '%s\n' "$untagged" | awk -v pattern="$pattern" '$0 ~ pattern && $0 !~ /[[:space:]]/')"
    if test -n "$untagged_names"; then
      printf 'PENDING rows present without the %s tag (%s):\n%s\n' "$tag" "$package" "$untagged_names" >&2
      exit 1
    fi

    if test -n "$tagged_names"; then
      while IFS= read -r name; do
        count=$((count + 1))
        rows+="$tag $package $name"$'\n'
        report+="PENDING: $name ($tag, $package) requires $reason; compile-only in CI."$'\n'
      done <<< "$tagged_names"
    fi
  done
  if test "$count" -eq 0; then
    printf 'No %s-tagged %s rows found\n' "$tag" "$pattern" >&2
    exit 1
  fi
done < "$script_dir/pending-inventories.txt"
if test "$inventories" -eq 0; then
  printf '%s\n' 'No PENDING inventories configured' >&2
  exit 1
fi

# This independent lower bound detects deletion of one expected row even when
# other matching rows remain. It never supplies the discovered report output.
expected=0
while read -r tag package name; do
  if test -z "$tag" || [[ "$tag" = \#* ]]; then continue; fi
  expected=$((expected + 1))
  if ! grep -Fxq -- "$tag $package $name" <<< "$rows"; then
    printf 'Missing expected PENDING row: %s %s %s\n' "$tag" "$package" "$name" >&2
    exit 1
  fi
done < "$script_dir/pending-rows.txt"
if test "$expected" -eq 0; then
  printf '%s\n' 'No expected PENDING rows configured' >&2
  exit 1
fi

# Publish nothing until every compile, exclusion and baseline check passes.
printf '%s' "$report"
