#!/usr/bin/env python3
"""Canonical bundle-derived release metadata; no signature establishes origin."""
import hashlib
import io
import json
import pathlib
import re
import sys
import tarfile


ARCHES = ("amd64", "arm64")
MEMBERS = ("VERSION.json", "config.json", "keymaker", "name-indices.json", "swarma-keymaker.service")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def digest(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError("missing-or-symlinked-artifact")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fragment(root, names):
    return canonical({"schema": "release-set-fragment/1", "artifacts": [
        {"name": name, "sha256": digest(root / name)} for name in sorted(names)]})


def sums(root, names):
    return "".join(f"{digest(root / name)}  {name}\n" for name in sorted(names)).encode("ascii")


def native_names(arch):
    return [f"swarma-keymaker-bundle_linux_{arch}.tar", f"bundle-SHA256SUMS_linux_{arch}",
            f"provenance_linux_{arch}.json"]


def record(raw):
    value = json.loads(raw)
    if set(value) != {"commit", "tree", "version", "go_version", "goos", "goarch", "trimpath"}:
        raise ValueError("invalid-bundle-provenance")
    if (not re.fullmatch(r"[0-9a-f]{40}", value["commit"])
            or not re.fullmatch(r"[0-9a-f]{40}", value["tree"])
            or value["go_version"] != "go1.26.10" or value["goos"] != "linux"
            or value["goarch"] not in ARCHES or value["trimpath"] is not True):
        raise ValueError("invalid-bundle-provenance")
    return value


def bundle_checksums(contents):
    return "".join(f"{hashlib.sha256(contents[name]).hexdigest()}  {name}\n"
                   for name in sorted(MEMBERS)).encode("ascii")


def pack(root, source, epoch):
    source = pathlib.Path(source)
    if not epoch.isdecimal() or set(p.name for p in source.iterdir()) != set(MEMBERS) | {"SHA256SUMS"}:
        raise ValueError("invalid-bundle-inventory")
    for name in (*MEMBERS, "SHA256SUMS"):
        digest(source / name)
    contents = {name: (source / name).read_bytes() for name in MEMBERS}
    manifest = (source / "SHA256SUMS").read_bytes()
    if manifest != bundle_checksums(contents):
        raise ValueError("bundle-checksum-mismatch")
    version = record(contents["VERSION.json"])
    arch = version["goarch"]
    archive, sidecar, provenance = native_names(arch)
    with tarfile.open(root / archive, "x", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted((*MEMBERS, "SHA256SUMS")):
            body = manifest if name == "SHA256SUMS" else contents[name]
            entry = tarfile.TarInfo(name)
            entry.size, entry.mtime = len(body), int(epoch)
            entry.mode = 0o700 if name == "keymaker" else 0o600
            tar.addfile(entry, io.BytesIO(body))
    (root / sidecar).write_bytes(manifest)
    (root / provenance).write_bytes(canonical({"bundle": version, "SOURCE_DATE_EPOCH": int(epoch)}))
    checksum = f"SHA256SUMS_linux_{arch}"
    (root / checksum).write_bytes(sums(root, native_names(arch)))
    (root / f"release-set_linux_{arch}.json").write_bytes(fragment(root, native_names(arch) + [checksum]))


def native_records(root):
    records = []
    names = []
    for arch in ARCHES:
        native = native_names(arch)
        if not any((root / name).exists() or (root / name).is_symlink() for name in native):
            continue
        checksum, subset = f"SHA256SUMS_linux_{arch}", f"release-set_linux_{arch}.json"
        for name in native + [checksum, subset]:
            digest(root / name)
        if (root / checksum).read_bytes() != sums(root, native):
            raise ValueError("native-checksum-mismatch")
        if (root / subset).read_bytes() != fragment(root, native + [checksum]):
            raise ValueError("native-release-set-mismatch")
        provenance = json.loads((root / native[2]).read_bytes())
        if set(provenance) != {"bundle", "SOURCE_DATE_EPOCH"}:
            raise ValueError("invalid-bundle-provenance")
        version = record(canonical(provenance["bundle"]))
        if version["goarch"] != arch or type(provenance["SOURCE_DATE_EPOCH"]) is not int or provenance["SOURCE_DATE_EPOCH"] < 0:
            raise ValueError("invalid-bundle-provenance")
        if (root / native[2]).read_bytes() != canonical(provenance):
            raise ValueError("noncanonical-provenance")
        with tarfile.open(root / native[0], "r:") as tar:
            entries = tar.getmembers()
            if ([e.name for e in entries] != sorted((*MEMBERS, "SHA256SUMS"))
                    or any(not e.isfile() or e.uid or e.gid or e.uname or e.gname
                           or e.mtime != provenance["SOURCE_DATE_EPOCH"]
                           or e.mode != (0o700 if e.name == "keymaker" else 0o600) for e in entries)):
                raise ValueError("invalid-bundle-archive")
            contents = {e.name: tar.extractfile(e).read() for e in entries}
        manifest = (root / native[1]).read_bytes()
        if manifest != contents["SHA256SUMS"] or manifest != bundle_checksums(contents):
            raise ValueError("bundle-checksum-mismatch")
        if record(contents["VERSION.json"]) != version:
            raise ValueError("bundle-provenance-mismatch")
        records.append(provenance)
        names.extend(native + [checksum, subset])
    if not records:
        raise ValueError("incomplete-manifest")
    if len({(r["bundle"]["commit"], r["bundle"]["tree"], r["bundle"]["version"], r["SOURCE_DATE_EPOCH"]) for r in records}) != 1:
        raise ValueError("inconsistent-bundle-sources")
    return records, sorted(names)


def run():
    mode, directory, *args = sys.argv[1:]
    root = pathlib.Path(directory)
    if mode == "bundle":
        source, epoch = args
        pack(root, source, epoch)
    elif mode in ("create", "combine"):
        commit, version, epoch = args
        if not re.fullmatch(r"[0-9a-f]{40}", commit) or version != "go1.26.10" or not epoch.isdecimal():
            raise ValueError("invalid-build-inputs")
        records, names = native_records(root)
        if mode == "combine" and {r["bundle"]["goarch"] for r in records} != set(ARCHES):
            raise ValueError("both-native-architectures-required")
        if any(r["bundle"]["commit"] != commit or r["SOURCE_DATE_EPOCH"] != int(epoch) for r in records):
            raise ValueError("bundle-source-binding-mismatch")
        (root / "provenance.json").write_bytes(canonical({"bundles": records}))
        names += ["provenance.json"]
        (root / "SHA256SUMS").write_bytes(sums(root, names))
        (root / "release-set.json").write_bytes(fragment(root, names + ["SHA256SUMS"]))
    elif mode == "check":
        if args:
            raise ValueError("unexpected-arguments")
        digest(root / "SHA256SUMS")
        digest(root / "release-set.json")
        names = []
        checksum_lines = []
        for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (provenance\.json|(?:swarma-keymaker-bundle_linux_(?:amd64|arm64)\.tar|bundle-SHA256SUMS_linux_(?:amd64|arm64)|provenance_linux_(?:amd64|arm64)\.json|SHA256SUMS_linux_(?:amd64|arm64)|release-set_linux_(?:amd64|arm64)\.json))", line)
            if not match:
                raise ValueError("invalid-checksum-entry")
            expected, name = match[1], match[2]
            if name in names:
                raise ValueError("duplicate-checksum-entry")
            if digest(root / name) != expected:
                raise ValueError("artifact-digest-mismatch")
            names.append(name)
            checksum_lines.append(f"{expected}  {name}\n")
        if "provenance.json" not in names or not any("_linux_" in n for n in names):
            raise ValueError("incomplete-manifest")
        if (root / "SHA256SUMS").read_bytes() != "".join(checksum_lines).encode("ascii") or names != sorted(names):
            raise ValueError("noncanonical-checksums")
        if (root / "release-set.json").read_bytes() != fragment(root, names + ["SHA256SUMS"]):
            raise ValueError("release-set-mismatch-or-noncanonical")
        records, native = native_records(root)
        if set(names) != set(native) | {"provenance.json"}:
            raise ValueError("incomplete-manifest")
        if (root / "provenance.json").read_bytes() != canonical({"bundles": records}):
            raise ValueError("bundle-provenance-mismatch")
    else:
        raise ValueError("unknown-mode")


if __name__ == "__main__":
    try:
        run()
    except (ValueError, OSError, UnicodeError, tarfile.TarError, KeyError, TypeError) as error:
        print(f"release metadata: {error}", file=sys.stderr)
        sys.exit(1)
