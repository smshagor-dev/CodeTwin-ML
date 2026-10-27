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
    """Return paths with private-key armor; fail if Git enumeration fails."""
    root = root.resolve()
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    findings: list[str] = []
    for raw_path in completed.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = os.fsdecode(raw_path)
        path = root / relative
        # Never follow a tracked symlink outside the checkout.
        if path.is_symlink():
            continue
        if not path.is_file():
            # Submodule directories are separate repositories, not file bytes.
            if path.is_dir():
                continue
            raise ValueError(f"Tracked file is unavailable: {relative}")
        if not path.resolve().is_relative_to(root):
            raise ValueError(f"Tracked file escapes checkout: {relative}")
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
            print(f"  {path}")
        print("Remove the key material, revoke/rotate any exposed key, and retry.")
        return 1
    print("No recognizable private-key armor headers in tracked regular files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
