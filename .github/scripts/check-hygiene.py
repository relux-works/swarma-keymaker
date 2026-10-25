#!/usr/bin/env python3
"""Reject attribution metadata in every tracked file, without following links."""

import os
from pathlib import Path
import re
import subprocess
import sys


# Character classes keep this check's own source free of literal markers.
MARKERS = re.compile(
    rb"claude[.]ai|session[_]|Claude[-]Session|Generated[ ]with|Co[-]Authored[-]By",
    re.IGNORECASE,
)


def git(*args):
    return subprocess.run(
        ["git", *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def main():
    root = Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip())
    failed = False
    for name in git("ls-files", "-z").split(b"\0"):
        if not name:
            continue
        path = root / os.fsdecode(name)
        content = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        if MARKERS.search(content):
            print(f"Attribution metadata in tracked file: {os.fsdecode(name)!r}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError, ValueError):
        print("Hygiene check unavailable", file=sys.stderr)
        sys.exit(2)
