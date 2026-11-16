#!/usr/bin/env python3
"""Inert archive fixtures test metadata contracts, not native ARM execution."""
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("metadata", pathlib.Path(__file__).with_name("release-metadata.py"))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class BundleMetadata(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="release-metadata-test-")
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()

    def native(self, arch="amd64", commit="a" * 40, tree="b" * 40, epoch="1"):
        source = self.root / arch
        source.mkdir()
        version = {"commit": commit, "tree": tree, "version": "0.1.0", "go_version": "go1.26.10",
                   "goos": "linux", "goarch": arch, "trimpath": True}
        contents = {name: b"inert metadata fixture\n" for name in metadata.MEMBERS}
        contents["VERSION.json"] = json.dumps(version).encode()
        for name, raw in contents.items():
            (source / name).write_bytes(raw)
        (source / "SHA256SUMS").write_bytes(metadata.bundle_checksums(contents))
        metadata.pack(self.dist, source, epoch)
        return source

    def invoke(self, mode, *args):
        previous = sys.argv
        sys.argv = ["release-metadata.py", mode, str(self.dist), *args]
        try:
            metadata.run()
        finally:
            sys.argv = previous

    def rebind_native(self):
        names = metadata.native_names("amd64")
        (self.dist / "SHA256SUMS_linux_amd64").write_bytes(metadata.sums(self.dist, names))
        (self.dist / "release-set_linux_amd64.json").write_bytes(
            metadata.fragment(self.dist, names + ["SHA256SUMS_linux_amd64"]))

    # Both metadata-only architectures can combine iff source/tree/version/epoch
    # agree; no binary in these inert fixtures is claimed to run on either target.
    def test_valid_native_and_complete_set(self):
        self.native()
        self.invoke("create", "a" * 40, "go1.26.10", "1")
        self.invoke("check")
        self.native("arm64")
        self.invoke("combine", "a" * 40, "go1.26.10", "1")
        self.invoke("check")
        records = json.loads((self.dist / "provenance.json").read_bytes())["bundles"]
        self.assertEqual([r["bundle"]["goarch"] for r in records], ["amd64", "arm64"])

    # A valid single-architecture set is insufficient for hosted draft creation;
    # refusal must happen before writing the aggregate list or provenance.
    def test_missing_architecture_refuses_aggregate(self):
        self.native()
        with self.assertRaisesRegex(ValueError, "both-native-architectures-required"):
            self.invoke("combine", "a" * 40, "go1.26.10", "1")
        self.assertFalse((self.dist / "SHA256SUMS").exists())
        self.assertFalse((self.dist / "provenance.json").exists())

    # Recomputed outer checksums cannot authorize combining different sources,
    # trees, versions or archive epochs; the valid full set above is the control.
    def test_inconsistent_native_source_refuses(self):
        for field, changed in (("commit", "c" * 40), ("tree", "d" * 40), ("epoch", "2")):
            with self.subTest(field=field):
                other = self.root / ("case-" + field)
                other.mkdir()
                previous_root, previous_dist = self.root, self.dist
                self.root, self.dist = other, other / "dist"
                self.dist.mkdir()
                try:
                    self.native()
                    self.native("arm64", **{field: changed})
                    with self.assertRaisesRegex(ValueError, "inconsistent-bundle-sources"):
                        self.invoke("combine", "a" * 40, "go1.26.10", "1")
                    self.assertFalse((self.dist / "SHA256SUMS").exists())
                finally:
                    self.root, self.dist = previous_root, previous_dist

    # A bundle changed after assembly must fail its original inner list before
    # packaging. An existing good bundle from the same helper is the control.
    def test_corrupt_inner_bundle_refuses_pack(self):
        source = self.native()
        (source / "config.json").write_bytes(b"changed\n")
        refused = self.root / "refused"
        refused.mkdir()
        with self.assertRaisesRegex(ValueError, "bundle-checksum-mismatch"):
            metadata.pack(refused, source, "1")
        self.assertEqual(list(refused.iterdir()), [])

    # Even fully recomputed native metadata cannot replace the bundle's actual
    # VERSION record with a different tree. Detect semantic disagreement.
    def test_provenance_must_come_from_bundle(self):
        self.native()
        path = self.dist / "provenance_linux_amd64.json"
        value = json.loads(path.read_bytes())
        value["bundle"]["tree"] = "c" * 40
        path.write_bytes(metadata.canonical(value))
        self.rebind_native()
        with self.assertRaisesRegex(ValueError, "bundle-provenance-mismatch"):
            self.invoke("create", "a" * 40, "go1.26.10", "1")
        self.assertFalse((self.dist / "SHA256SUMS").exists())

    # Link/traversal entries refuse without extracting any archive member, even
    # when outer native checksums and fragment are consistently recomputed.
    def test_archive_links_and_traversal_refused(self):
        self.native()
        path = self.dist / metadata.native_names("amd64")[0]
        original = path.read_bytes()
        for traversal in (False, True):
            with self.subTest(traversal=traversal):
                with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as old:
                    contents = [(entry, old.extractfile(entry).read()) for entry in old.getmembers()]
                with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as new:
                    for entry, body in contents:
                        if entry.name == "keymaker":
                            if traversal:
                                entry.name = "../keymaker"
                            else:
                                entry.type, entry.linkname, entry.size = tarfile.SYMTYPE, "outside", 0
                        new.addfile(entry, io.BytesIO(body) if entry.isfile() else None)
                self.rebind_native()
                with self.assertRaisesRegex(ValueError, "invalid-bundle-archive"):
                    self.invoke("create", "a" * 40, "go1.26.10", "1")
                self.assertFalse((self.root / "outside").exists())

    # Supplying a different admitted commit cannot re-label a valid native set.
    def test_admitted_commit_binding_refused(self):
        self.native()
        with self.assertRaisesRegex(ValueError, "bundle-source-binding-mismatch"):
            self.invoke("create", "c" * 40, "go1.26.10", "1")
        self.assertFalse((self.dist / "SHA256SUMS").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
