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


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Capture file identity and mutation-sensitive metadata for bounded checks."""
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def has_private_key_armor(
    path: Path, *, expected: os.stat_result | None = None,
) -> bool:
    """Scan through a verified regular-file descriptor without following symlinks.

    Recheck the descriptor and pathname after reading. This narrows local
    replacement races; it is not an atomic filesystem snapshot.
    """
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("Tracked regular file type changed before scan")
    if expected is not None and _file_identity(before) != _file_identity(expected):
        raise ValueError("Tracked file changed before scan")
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required for the tracked-file scan")
    # O_NONBLOCK prevents a substituted FIFO from blocking at open().
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or _file_identity(opened) != _file_identity(before)
        ):
            raise ValueError("Tracked file changed while opening")
        previous = b""
        found = False
        while chunk := source.read(CHUNK_SIZE):
            data = previous + chunk
            if PRIVATE_KEY_ARMOR.search(data):
                found = True
                break
            previous = data[-OVERLAP:]
        finished = os.fstat(source.fileno())
        if _file_identity(finished) != _file_identity(opened):
            raise ValueError("Tracked file changed while reading")
    if _file_identity(path.lstat()) != _file_identity(finished):
        raise ValueError("Tracked file path changed during scan")
    return found

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
            file_info = path.lstat()
            file_mode = file_info.st_mode
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
        if has_private_key_armor(path, expected=file_info):
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
