#!/usr/bin/env bash
# Wrap the existing offline bundle; never compile release binaries here.
set -euo pipefail
export LC_ALL=C TZ=UTC GOTOOLCHAIN=local GOWORK=off GOENV=off GOTELEMETRY=off
export CGO_ENABLED=0 GOEXPERIMENT= GOFLAGS='-mod=readonly -p=2'
umask 077
fail() { printf 'release build: %s\n' "$1" >&2; exit 1; }
[[ ( $# == 1 || $# == 2 ) && $1 == /* ]] || fail absolute-new-output-directory-required
out=$1
go_bin=$(command -v "${GO:-go}")
export PATH="$(dirname "$go_bin"):$PATH"
policy_root=$(cd "$(dirname "$0")/.." && pwd -P)
root=${2:-$(git rev-parse --show-toplevel)}
[[ $root == /* ]] || fail absolute-source-directory-required
cd "$root"
[[ -z $(git status --porcelain --untracked-files=all) ]] || fail dirty-build-source
commit=$(git rev-parse HEAD)
[[ $("$go_bin" env GOVERSION) == go1.26.10 ]] || fail go1.26.10-required
[[ $("$go_bin" env GOHOSTOS) == linux ]] || fail native-linux-required
arch=$("$go_bin" env GOHOSTARCH)
[[ $arch == amd64 || $arch == arm64 ]] || fail unsupported-native-architecture
export GOOS=linux GOARCH=$arch
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || fail invalid-source-epoch
[[ ! -e $out && ! -L $out ]] || fail absolute-new-output-directory-required
# The assembler owns its private source, empty build cache and offline dependency
# extraction. Only download-cache archives are seeded; no second binary recipe.
module_cache=$("$go_bin" env GOMODCACHE)
if [[ -n ${RELEASE_MODULE_CACHE:-} ]]; then
  [[ $RELEASE_MODULE_CACHE == /* ]] || fail absolute-module-cache-required
  export GOPROXY="file://$RELEASE_MODULE_CACHE/cache/download" GOSUMDB=off
fi
"$go_bin" mod download
cd "$policy_root"
"$go_bin" mod download
work=$(mktemp -d "${TMPDIR:?private-absolute-TMPDIR-required}/release-wrapper.XXXXXX")
work=$(cd "$work" && pwd -P)
version=$(python3 - "$root/cmd/keymaker/main.go" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r'^const version = "([0-9][0-9A-Za-z.+-]*)"$', text, re.M)
if not match:
    raise SystemExit("source-version-required")
print(match[1])
PY
)
"$go_bin" run ./tools/release-bundle -repo "$root" -commit "$commit" \
  -version "$version" -target "$work/bundle" \
  -config "$policy_root/packaging/config.example.json" \
  -name-indices "$policy_root/.github/release/name-indices.json" -module-cache "$module_cache"
mkdir "$out"
# Archive bytes, checksums and provenance are all derived from the bundle.
python3 "$policy_root/.scripts/release-metadata.py" bundle "$out" "$work/bundle" "$SOURCE_DATE_EPOCH"
python3 "$policy_root/.scripts/release-metadata.py" create "$out" "$commit" go1.26.10 "$SOURCE_DATE_EPOCH"
cd "$out"
sha256sum --strict --check SHA256SUMS
