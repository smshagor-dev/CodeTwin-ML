#!/usr/bin/env python3
"""Atomically publish a *public* trust-anchor pair after independent verification.

This is an optional POSIX administrator tool, not a signature verifier or key
vault. It cannot authenticate pins, verify policy signatures, or prevent an
attacker with write access to the administrator's anchor directory from
rolling back the entire directory. Keep independent trusted copies.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

FORMAT = "codetwin-external-signer-anchor-v1"
MAX_ANCHOR_BYTES = 4096
FIELDS = frozenset({
    "format", "authority_public_key_hex", "minimum_revision",
    "signed_policy_sha256_hex",
})


def _hex_pin(value: str, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise ValueError(f"{name} must be 64 lowercase hex characters")
    return value


def _positive_revision(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if value > 2**64 - 1:
        raise ValueError(f"{name} exceeds u64")
    return value


def _private_directory(directory: Path) -> None:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Atomic anchor publishing is supported only on POSIX")
    for component in (directory, *directory.parents):
        metadata = component.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Symlink in anchor directory path is not allowed")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Anchor directory path contains a non-directory")
    metadata = directory.lstat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("Anchor directory must be owned by this user and private (0700)")


def _private_regular_file(metadata: os.stat_result, name: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ValueError(f"{name} must be a private regular file owned by this user")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate trust-anchor field: {key}")
        result[key] = value
    return result


def _read_anchor(path: Path) -> dict[str, Any]:
    before = path.lstat()
    _private_regular_file(before, "Trust anchor")
    if before.st_size > MAX_ANCHOR_BYTES:
        raise ValueError("Trust anchor exceeds size limit")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        after = os.fstat(fd)
        _private_regular_file(after, "Trust anchor")
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("Trust anchor changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_ANCHOR_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_ANCHOR_BYTES:
        raise ValueError("Trust anchor exceeds size limit")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict) or value.keys() != FIELDS:
        raise ValueError("Trust anchor must have exactly the required fields")
    if value["format"] != FORMAT:
        raise ValueError("Unsupported trust-anchor format")
    _hex_pin(value["authority_public_key_hex"], "Authority public key")
    _hex_pin(value["signed_policy_sha256_hex"], "Signed policy SHA-256")
    _positive_revision(value["minimum_revision"], "Stored revision")
    return value


def _lock_directory(directory: Path, anchor_name: str) -> int:
    # Persistent lock inode: never unlink it, which could split flock domains.
    import fcntl

    lock_path = directory / (anchor_name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        _private_regular_file(os.fstat(fd), "Anchor lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _atomic_replace(path: Path, anchor: dict[str, Any]) -> None:
    payload = (json.dumps(anchor, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    if len(payload) > MAX_ANCHOR_BYTES:
        raise ValueError("Replacement trust anchor exceeds size limit")
    fd, temporary = tempfile.mkstemp(prefix=".trust-anchor-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # On POSIX, syncing the containing directory makes the rename durable.
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def publish(
    anchor_file: Path,
    *,
    expected_revision: int,
    expected_sha256: str,
    authority_public_key_hex: str,
    replacement_revision: int,
    replacement_sha256: str,
    approved: bool,
) -> dict[str, Any]:
    """CAS update a single public revision/digest record; never signs a policy."""
    if not approved:
        raise ValueError("Explicit external administrator approval is required")
    expected_revision = _positive_revision(expected_revision, "Expected revision")
    replacement_revision = _positive_revision(replacement_revision, "Replacement revision")
    if replacement_revision <= expected_revision:
        raise ValueError("Replacement revision must strictly increase")
    expected_sha256 = _hex_pin(expected_sha256, "Expected signed policy SHA-256")
    replacement_sha256 = _hex_pin(replacement_sha256, "Replacement signed policy SHA-256")
    authority_public_key_hex = _hex_pin(authority_public_key_hex, "Authority public key")
    if replacement_sha256 == expected_sha256:
        raise ValueError("Replacement digest must differ from current digest")

    path = Path(os.path.abspath(anchor_file))
    _private_directory(path.parent)
    lock_fd = _lock_directory(path.parent, path.name)
    try:
        current = _read_anchor(path)
        if (
            current["minimum_revision"] != expected_revision
            or current["signed_policy_sha256_hex"] != expected_sha256
            or current["authority_public_key_hex"] != authority_public_key_hex
        ):
            raise ValueError("Current anchor does not match independently supplied expectations")
        replacement = {
            "format": FORMAT,
            "authority_public_key_hex": authority_public_key_hex,
            "minimum_revision": replacement_revision,
            "signed_policy_sha256_hex": replacement_sha256,
        }
        _atomic_replace(path, replacement)
        if _read_anchor(path) != replacement:
            raise ValueError("Published anchor failed readback verification")
        return replacement
    finally:
        import fcntl

        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor-file", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--authority-public-key", required=True)
    parser.add_argument("--replacement-revision", required=True, type=int)
    parser.add_argument("--replacement-sha256", required=True)
    parser.add_argument("--approve", action="store_true", help="Explicit administrator approval")
    args = parser.parse_args()
    try:
        result = publish(
            args.anchor_file,
            expected_revision=args.expected_revision,
            expected_sha256=args.expected_sha256,
            authority_public_key_hex=args.authority_public_key,
            replacement_revision=args.replacement_revision,
            replacement_sha256=args.replacement_sha256,
            approved=args.approve,
        )
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        parser.exit(2, f"Trust anchor was not safely published: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
