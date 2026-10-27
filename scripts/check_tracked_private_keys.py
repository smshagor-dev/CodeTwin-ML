#!/usr/bin/env python3
"""Reject recognizable private-key armor headers in Git-tracked regular files.

This CI guard prevents some accidental key commits; it cannot prove external
key custody or detect raw seeds, encrypted blobs, or untracked files.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import stat

# Build the delimiter in parts so this scanner does not match its own source.
PRIVATE_KEY_ARMOR = re.compile(
    b"-----" + b"BEGIN " + rb"[A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)?-----"
)
CHUNK_SIZE = 64 * 1024
OVERLAP = 128


def has_private_key_armor(path: Path) -> bool:
    """Scan a regular file in bounded memory without printing its contents."""
    previous = b""
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            data = previous + chunk
            if PRIVATE_KEY_ARMOR.search(data):
                return True
            previous = data[-OVERLAP:]
    return False


def scan_tracked_files(root: Path) -> list[str]:
    """Scan index-declared regular files; reject unsafe working-tree substitutions."""
    root = root.resolve()
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--stage", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    findings: list[str] = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ")
        except ValueError as error:
            raise ValueError("Malformed Git index entry") from error
        if (
            mode not in (b"100644", b"100755", b"120000", b"160000")
            or len(object_id) not in (40, 64)
            or any(byte not in b"0123456789abcdef" for byte in object_id)
            or stage != b"0"
        ):
            raise ValueError("Unsupported or unmerged Git index entry")
        relative = os.fsdecode(raw_path)
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("Tracked path escapes checkout")
        path = root / relative_path
        if path.parent.resolve() != path.parent:
            raise ValueError(f"Tracked parent is a symlink: {relative!r}")
        try:
            file_mode = path.lstat().st_mode
        except FileNotFoundError as error:
            raise ValueError(f"Tracked file is unavailable: {relative!r}") from error
        if mode == b"120000":
            # Only an index-declared symlink may be skipped; do not follow it.
            if not stat.S_ISLNK(file_mode):
                raise ValueError(f"Tracked symlink type changed: {relative!r}")
            continue
        if mode == b"160000":
            # A Gitlink is a separate repository, not a regular tracked file.
            if not stat.S_ISDIR(file_mode):
                raise ValueError(f"Tracked gitlink type changed: {relative!r}")
            continue
        # A regular tracked file replaced by a directory or symlink must not
        # silently bypass the guard (the old is_dir() branch allowed this).
        if not stat.S_ISREG(file_mode):
            raise ValueError(f"Tracked regular file type changed: {relative!r}")
        if not path.resolve().is_relative_to(root):
            raise ValueError(f"Tracked file escapes checkout: {relative!r}")
        if has_private_key_armor(path):
            findings.append(relative)
    return findings


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        findings = scan_tracked_files(root)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Private-key custody guard could not complete: {error}")
        return 2
    if findings:
        print("Recognizable private-key armor found in tracked files:")
        for path in findings:
            print(f"  {path!r}")
        print("Remove the key material, revoke/rotate any exposed key, and retry.")
        return 1
    print("No recognizable private-key armor headers in tracked regular files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
