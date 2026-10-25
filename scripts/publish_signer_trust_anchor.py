#!/usr/bin/env python3
"""Atomically publish a *public* trust-anchor pair after independent verification.

This is an optional POSIX administrator tool, not a private-key vault.
The command verifies both signed policy envelopes and independently supplied
pins before publishing; it cannot authenticate the source of those pins or
prevent a privileged rollback of the anchor directory. Keep independent copies.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Callable

if __package__:
    from .verify_signer_policy_rotation import verify_rotation_files
else:
    from verify_signer_policy_rotation import verify_rotation_files

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


def _private_directory(directory: Path) -> tuple[int, int]:
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
    return metadata.st_dev, metadata.st_ino


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


def _anchor_metadata(value: os.stat_result) -> tuple[int, ...]:
    # Observe in-place writes and mode/ownership changes, not just inode swaps.
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _read_anchor(path: Path) -> dict[str, Any]:
    before = path.lstat()
    _private_regular_file(before, "Trust anchor")
    if before.st_size > MAX_ANCHOR_BYTES:
        raise ValueError("Trust anchor exceeds size limit")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        _private_regular_file(opened, "Trust anchor")
        if _anchor_metadata(before) != _anchor_metadata(opened):
            raise ValueError("Trust anchor changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_ANCHOR_BYTES + 1)
        finished = os.fstat(fd)
        _private_regular_file(finished, "Trust anchor")
        if _anchor_metadata(opened) != _anchor_metadata(finished):
            raise ValueError("Trust anchor changed during read")
        # A replaced path may still leave the opened descriptor valid.
        if _anchor_metadata(path.lstat()) != _anchor_metadata(finished):
            raise ValueError("Trust anchor path changed during read")
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


def _lock_directory(directory: Path, anchor_name: str) -> tuple[int, tuple[int, ...]]:
    # Persistent lock inode: never unlink it, which could split flock domains.
    import fcntl

    lock_path = directory / (anchor_name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        opened = os.fstat(fd)
        _private_regular_file(opened, "Anchor lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        locked = os.fstat(fd)
        _private_regular_file(locked, "Anchor lock")
        # Waiting for a cooperating publisher must not silently continue on
        # an unlinked/replaced lock inode (which would split lock domains).
        if (
            _anchor_metadata(opened) != _anchor_metadata(locked)
            or _anchor_metadata(locked) != _anchor_metadata(lock_path.lstat())
        ):
            raise ValueError("Anchor lock changed while acquiring")
        return fd, _anchor_metadata(locked)
    except BaseException:
        os.close(fd)
        raise


def _check_lock_unchanged(
    fd: int, lock_path: Path, expected_metadata: tuple[int, ...]
) -> None:
    """Reject observed lock-file replacement or mutation after policy checks."""
    opened = os.fstat(fd)
    _private_regular_file(opened, "Anchor lock")
    if (
        _anchor_metadata(opened) != expected_metadata
        or _anchor_metadata(lock_path.lstat()) != expected_metadata
    ):
        raise ValueError("Anchor lock changed before publication")


def _atomic_replace(
    path: Path, anchor: dict[str, Any], expected_directory_identity: tuple[int, int]
) -> None:
    payload = (json.dumps(anchor, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    if len(payload) > MAX_ANCHOR_BYTES:
        raise ValueError("Replacement trust anchor exceeds size limit")

    # Pin all filesystem mutations to one verified directory descriptor.
    # A pathname swap after opening must not redirect the temporary file,
    # rename or durability sync into a different directory.
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary: str | None = None
    try:
        opened = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or (opened.st_dev, opened.st_ino) != expected_directory_identity
            or _private_directory(path.parent) != expected_directory_identity
        ):
            raise ValueError("Anchor directory changed before atomic replacement")

        temporary = ".trust-anchor-" + secrets.token_hex(16) + ".tmp"
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=directory_fd,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if _private_directory(path.parent) != expected_directory_identity:
            raise ValueError("Anchor directory changed before atomic replacement")
        os.replace(
            temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
        )
        # Sync the *same* directory inode used for the rename.
        os.fsync(directory_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass  # Successful rename already consumed the temporary name.
        os.close(directory_fd)


def publish(
    anchor_file: Path,
    *,
    expected_revision: int,
    expected_sha256: str,
    authority_public_key_hex: str,
    replacement_revision: int,
    replacement_sha256: str,
    approved: bool,
    _verify_before_replace: Callable[[], None] | None = None,
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
    directory_identity = _private_directory(path.parent)
    lock_fd, lock_metadata = _lock_directory(path.parent, path.name)
    try:
        # The path may have changed while waiting for the advisory lock.
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("Anchor directory changed while acquiring lock")
        current = _read_anchor(path)
        if (
            current["minimum_revision"] != expected_revision
            or current["signed_policy_sha256_hex"] != expected_sha256
            or current["authority_public_key_hex"] != authority_public_key_hex
        ):
            raise ValueError("Current anchor does not match independently supplied expectations")
        # For the authenticated CLI flow, repeat verification under the
        # publisher lock immediately before the durable replacement. The
        # first preflight alone cannot detect a signed-policy swap between
        # external validation and acquiring the publication lock.
        if _verify_before_replace is not None:
            _verify_before_replace()
        # Do not publish into a swapped or newly exposed directory.
        # This remains a point-in-time check, not an atomic path snapshot.
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("Anchor directory changed before publication")
        _check_lock_unchanged(lock_fd, path.parent / (path.name + ".lock"), lock_metadata)
        replacement = {
            "format": FORMAT,
            "authority_public_key_hex": authority_public_key_hex,
            "minimum_revision": replacement_revision,
            "signed_policy_sha256_hex": replacement_sha256,
        }
        _atomic_replace(path, replacement, directory_identity)
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("Anchor directory changed after publication")
        if _read_anchor(path) != replacement:
            raise ValueError("Published anchor failed readback verification")
        return replacement
    finally:
        import fcntl

        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def publish_verified(
    anchor_file: Path,
    *,
    previous_policy_file: Path,
    replacement_policy_file: Path,
    expected_revision: int,
    expected_sha256: str,
    authority_public_key_hex: str,
    replacement_revision: int,
    replacement_sha256: str,
    approved: bool,
) -> dict[str, Any]:
    """Require authenticated signed-policy rotation before public anchor CAS."""
    if not approved:
        raise ValueError("Explicit external administrator approval is required")
    def verify_current_inputs() -> None:
        verify_rotation_files(
            previous_policy_file,
            replacement_policy_file,
            authority_public_key_hex=authority_public_key_hex,
            expected_revision=expected_revision,
            expected_sha256=expected_sha256,
            replacement_revision=replacement_revision,
            replacement_sha256=replacement_sha256,
        )

    # Fail before acquiring a lock on invalid policy inputs, and repeat the
    # same signature/pin validation while holding the publication lock.
    verify_current_inputs()
    return publish(
        anchor_file,
        expected_revision=expected_revision,
        expected_sha256=expected_sha256,
        authority_public_key_hex=authority_public_key_hex,
        replacement_revision=replacement_revision,
        replacement_sha256=replacement_sha256,
        approved=True,
        _verify_before_replace=verify_current_inputs,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor-file", required=True, type=Path)
    parser.add_argument("--previous-signed-policy", required=True, type=Path)
    parser.add_argument("--replacement-signed-policy", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--authority-public-key", required=True)
    parser.add_argument("--replacement-revision", required=True, type=int)
    parser.add_argument("--replacement-sha256", required=True)
    parser.add_argument("--approve", action="store_true", help="Explicit administrator approval")
    args = parser.parse_args()
    try:
        result = publish_verified(
            args.anchor_file,
            previous_policy_file=args.previous_signed_policy,
            replacement_policy_file=args.replacement_signed_policy,
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
