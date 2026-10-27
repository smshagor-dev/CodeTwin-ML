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


def _private_directory(directory: Path) -> tuple[tuple[int, ...], ...]:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Atomic anchor publishing is supported only on POSIX")
    # Pin the entire directory ancestry, not only the private leaf inode.
    # Ancestor timestamps are intentionally omitted: shared sticky directories
    # can change independently of this publisher.
    observations: list[tuple[int, ...]] = []
    for component in (directory, *directory.parents):
        metadata = component.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Symlink in anchor directory path is not allowed")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Anchor directory path contains a non-directory")
        # A private leaf is insufficient when an untrusted ancestor permits
        # another account to rename or replace it. Preserve compatibility
        # with root-owned sticky shared temp directories (for example /tmp).
        if component != directory:
            if metadata.st_uid not in (os.geteuid(), 0):
                raise ValueError("Anchor ancestor directory must be owned by this user or root")
            if metadata.st_mode & 0o022:
                if not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX):
                    raise ValueError("Anchor ancestor directory must not be writable by group or others")
        observations.append((
            metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_uid, metadata.st_gid,
        ))
    metadata = directory.lstat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("Anchor directory must be owned by this user and private (0700)")
    observations[0] = (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid,
    )
    return tuple(observations)


def _checkout_root() -> Path | None:
    """Identify the source tree when this helper is run from a checkout."""
    root = Path(__file__).resolve().parent.parent
    if (root / "Cargo.toml").is_file() and (root / "scripts" / "publish_signer_trust_anchor.py").is_file():
        return root
    return None


def _require_external_anchor_path(path: Path) -> None:
    """Refuse to publish or audit trust state within the application checkout.

    This is a placement guard, not proof of independently protected custody.
    """
    checkout = _checkout_root()
    if checkout is None:
        return
    resolved = path.resolve(strict=False)
    if (
        path == checkout or checkout in path.parents
        or resolved == checkout or checkout in resolved.parents
    ):
        raise ValueError("External trust anchor must be outside the CodeTwin source checkout")


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


def _read_anchor_with_metadata(path: Path) -> tuple[dict[str, Any], tuple[int, ...]]:
    before = path.lstat()
    _private_regular_file(before, "Trust anchor")
    if before.st_size > MAX_ANCHOR_BYTES:
        raise ValueError("Trust anchor exceeds size limit")
    # Reject a FIFO swapped in after lstat without blocking in open().
    # Regular anchor files are unaffected by O_NONBLOCK.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
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
    # Bound nesting even when the host interpreter's recursion limit is raised.
    # Quotes and escaped characters must not contribute structural delimiters.
    depth = 0
    quoted = False
    escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError("Trust anchor JSON nesting is too deep")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except RecursionError as error:
        raise ValueError("Trust anchor JSON nesting is too deep") from error
    if not isinstance(value, dict) or value.keys() != FIELDS:
        raise ValueError("Trust anchor must have exactly the required fields")
    if value["format"] != FORMAT:
        raise ValueError("Unsupported trust-anchor format")
    _hex_pin(value["authority_public_key_hex"], "Authority public key")
    _hex_pin(value["signed_policy_sha256_hex"], "Signed policy SHA-256")
    _positive_revision(value["minimum_revision"], "Stored revision")
    # JSON decoding and field validation happen after the descriptor closes.
    # Reject an observed pathname replacement or metadata mutation in that
    # window, even if the replacement contains byte-identical JSON.
    if _anchor_metadata(path.lstat()) != _anchor_metadata(finished):
        raise ValueError("Trust anchor changed during decoding")
    return value, _anchor_metadata(finished)


def _read_anchor(path: Path) -> dict[str, Any]:
    return _read_anchor_with_metadata(path)[0]


def _lock_directory(directory: Path, anchor_name: str) -> tuple[int, tuple[int, ...]]:
    # Persistent lock inode: never unlink it, which could split flock domains.
    import fcntl

    lock_path = directory / (anchor_name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        opened = os.fstat(fd)
        _private_regular_file(opened, "Anchor lock")
        # Never wait indefinitely for another publisher or a held lock.
        # A busy lock is a safe, explicit failure; the operator may retry.
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Anchor publisher lock is busy") from error
        locked = os.fstat(fd)
        _private_regular_file(locked, "Anchor lock")
        # Acquiring the lock must not silently continue on
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
    path: Path,
    anchor: dict[str, Any],
    expected_directory_identity: tuple[tuple[int, ...], ...],
    expected_anchor_metadata: tuple[int, ...],
    *,
    lock_fd: int,
    lock_metadata: tuple[int, ...],
    verification_callback: Callable[[], bool],
) -> tuple[int, int]:
    payload = (json.dumps(anchor, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    if len(payload) > MAX_ANCHOR_BYTES:
        raise ValueError("Replacement trust anchor exceeds size limit")

    # Pin all filesystem mutations to one verified directory descriptor.
    # A pathname swap after opening must not redirect the temporary file,
    # rename or durability sync into a different directory.
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary: str | None = None
    temporary_fd: int | None = None
    try:
        opened = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or (opened.st_dev, opened.st_ino) != expected_directory_identity[0][:2]
            or _private_directory(path.parent) != expected_directory_identity
        ):
            raise ValueError("Anchor directory changed before atomic replacement")

        temporary = ".trust-anchor-" + secrets.token_hex(16) + ".tmp"
        temporary_fd = os.open(
            temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=directory_fd,
        )
        # Keep the staged inode open until the rename, so a pathname swap
        # cannot silently substitute another file for the verified payload.
        with os.fdopen(temporary_fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        staged_metadata = _anchor_metadata(os.fstat(temporary_fd))
        # A second hard link exposes the staged inode through another path.
        # Refuse publication even if that link existed before our snapshot.
        _private_regular_file(os.fstat(temporary_fd), "Staged trust anchor")
        # The signed-policy inputs can change while the temporary anchor is
        # staged. Repeat authenticated verification before the rename so an
        # observed late swap cannot publish metadata for different inputs.
        verification_result = verification_callback()
        if verification_result is not True:
            raise ValueError("Signed-policy verification callback rejected publication")
        if _private_directory(path.parent) != expected_directory_identity:
            raise ValueError("Anchor directory changed before atomic replacement")
        # The lock serializes cooperating publishers only. Reject observed
        # changes to the old anchor, even when its JSON values are identical.
        _, current_metadata = _read_anchor_with_metadata(path)
        if current_metadata != expected_anchor_metadata:
            raise ValueError("Trust anchor changed before publication")
        if _private_directory(path.parent) != expected_directory_identity:
            raise ValueError("Anchor directory changed before atomic replacement")
        # Staging and fsync may take time after the publisher's earlier lock
        # check. Reject an observed lock swap or mutation before the rename,
        # while the previous anchor is still intact.
        _check_lock_unchanged(lock_fd, path.parent / (path.name + ".lock"), lock_metadata)
        # A same-UID or privileged noncooperating writer may alter the staged
        # file while the final signed-policy check runs. Reject observed inode,
        # metadata or byte changes before publishing the public anchor.
        staged_path_metadata = os.stat(
            temporary, dir_fd=directory_fd, follow_symlinks=False,
        )
        _private_regular_file(os.fstat(temporary_fd), "Staged trust anchor")
        _private_regular_file(staged_path_metadata, "Staged trust anchor")
        if (
            _anchor_metadata(os.fstat(temporary_fd)) != staged_metadata
            or _anchor_metadata(staged_path_metadata) != staged_metadata
        ):
            raise ValueError("Staged trust anchor changed before publication")
        os.lseek(temporary_fd, 0, os.SEEK_SET)
        if os.read(temporary_fd, MAX_ANCHOR_BYTES + 1) != payload:
            raise ValueError("Staged trust anchor content changed before publication")
        # A same-UID or privileged writer can mutate the staged inode or
        # replace its pathname while the final bounded read is in progress.
        # Observe descriptor and pathname metadata again after the read.
        # This is not an atomic snapshot or a privileged rollback defense.
        final_staged_fd = os.fstat(temporary_fd)
        final_staged_path = os.stat(
            temporary, dir_fd=directory_fd, follow_symlinks=False,
        )
        _private_regular_file(final_staged_fd, "Staged trust anchor")
        _private_regular_file(final_staged_path, "Staged trust anchor")
        if (
            _anchor_metadata(final_staged_fd) != staged_metadata
            or _anchor_metadata(final_staged_path) != staged_metadata
        ):
            raise ValueError("Staged trust anchor changed during final read")
        # The bounded final payload read is another window in which a
        # noncooperating writer can replace the lock, old anchor or parent.
        # Re-observe all three immediately before the rename. This narrows
        # detected races; it cannot make filesystem custody atomic.
        if _private_directory(path.parent) != expected_directory_identity:
            raise ValueError("Anchor directory changed during final staged read")
        _check_lock_unchanged(
            lock_fd, path.parent / (path.name + ".lock"), lock_metadata,
        )
        _, final_anchor_metadata = _read_anchor_with_metadata(path)
        if final_anchor_metadata != expected_anchor_metadata:
            raise ValueError("Trust anchor changed during final staged read")
        os.replace(
            temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
        )
        # Sync the *same* directory inode used for the rename.
        os.fsync(directory_fd)
        # The staged inode is the only inode this publisher has verified.
        # Preserve its identity for post-publication readback, so an observed
        # same-content pathname substitution cannot pass as our publication.
        return (staged_metadata[0], staged_metadata[1])
    finally:
        # A failed publication must not delete an unrelated file or symlink
        # swapped into the unpredictable staging name by a noncooperating
        # writer. Cleanup only the inode opened by this publisher. This is
        # a point-in-time guard, not an atomic defense against same-UID races.
        try:
            if temporary is not None and temporary_fd is not None:
                try:
                    named = os.stat(
                        temporary, dir_fd=directory_fd, follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass  # Successful rename already consumed the staging name.
                else:
                    opened = os.fstat(temporary_fd)
                    if (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                        try:
                            os.unlink(temporary, dir_fd=directory_fd)
                        except FileNotFoundError:
                            pass  # A concurrent removal is not a cleanup failure.
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            os.close(directory_fd)


def _publish_anchor(
    anchor_file: Path,
    *,
    expected_revision: int,
    expected_sha256: str,
    authority_public_key_hex: str,
    replacement_revision: int,
    replacement_sha256: str,
    approved: bool,
    _verify_before_replace: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Internal CAS primitive; a callback is mandatory but not an identity proof."""
    # Do not accept truthy numbers, strings, or other caller-supplied objects
    # as proof of an explicit administrator approval decision.
    if approved is not True:
        raise ValueError("Explicit external administrator approval is required")
    if not callable(_verify_before_replace):
        raise ValueError("Callable signed-policy verification callback is required before publication")
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
    _require_external_anchor_path(path)
    directory_identity = _private_directory(path.parent)
    lock_fd, lock_metadata = _lock_directory(path.parent, path.name)
    try:
        # The path may have changed while waiting for the advisory lock.
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("Anchor directory changed while acquiring lock")
        current, current_anchor_metadata = _read_anchor_with_metadata(path)
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
        verification_result = _verify_before_replace()
        if verification_result is not True:
            raise ValueError("Signed-policy verification callback rejected publication")
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
        published_identity = _atomic_replace(
            path, replacement, directory_identity, current_anchor_metadata,
            lock_fd=lock_fd, lock_metadata=lock_metadata,
            verification_callback=_verify_before_replace,
        )
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("Anchor directory changed after publication")
        readback, readback_metadata = _read_anchor_with_metadata(path)
        # The readback itself is a filesystem observation window. Recheck
        # directory ancestry and the persistent lock after it completes so
        # an observed late substitution cannot be reported as a successful
        # publication. Failure here is post-rename: it does NOT roll back
        # the already published anchor.
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("Anchor directory changed during publication readback")
        _check_lock_unchanged(
            lock_fd, path.parent / (path.name + ".lock"), lock_metadata,
        )
        if readback_metadata[:2] != published_identity:
            raise ValueError("Published anchor identity changed during readback")
        if readback != replacement:
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
    independent_revision_floor: int,
    approved: bool,
) -> dict[str, Any]:
    """Require authenticated policy rotation and an out-of-band revision floor."""
    # Do not accept truthy numbers, strings, or other caller-supplied objects
    # as proof of an explicit administrator approval decision.
    if approved is not True:
        raise ValueError("Explicit external administrator approval is required")
    # The operator must obtain this floor from a separately protected record,
    # not infer it from the mutable anchor or signed-policy inputs. This
    # comparison cannot authenticate the provenance of the supplied number.
    independent_revision_floor = _positive_revision(
        independent_revision_floor, "Independent revision floor",
    )
    if _positive_revision(expected_revision, "Expected revision") < independent_revision_floor:
        raise ValueError("Current anchor revision is below independently trusted revision floor")

    def verify_current_inputs() -> bool:
        verify_rotation_files(
            previous_policy_file,
            replacement_policy_file,
            authority_public_key_hex=authority_public_key_hex,
            expected_revision=expected_revision,
            expected_sha256=expected_sha256,
            replacement_revision=replacement_revision,
            replacement_sha256=replacement_sha256,
        )
        return True

    # Fail before acquiring a lock on invalid policy inputs, and repeat the
    # same signature/pin validation while holding the publication lock.
    verify_current_inputs()
    return _publish_anchor(
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
    parser.add_argument("--independent-revision-floor", required=True, type=int,
                        help="Revision floor from separately protected administrator records")
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
            independent_revision_floor=args.independent_revision_floor,
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
