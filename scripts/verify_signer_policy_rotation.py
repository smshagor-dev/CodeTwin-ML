"""Read-only Ed25519 validation before publishing externally pinned policy metadata.

Inputs must come from an independently authenticated administrator channel.
This verifies bytes and revision continuity, not the administrator's identity,
the custody of a private key, or resistance to rollback of the anchor directory.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

POLICY_FORMAT = "codetwin-signer-trust-v1"
DOMAIN = b"CodeTwin-ML/signer-policy/ed25519/v1\0"
MAX_POLICY_BYTES = 16 * 1024
U64_MAX = 2**64 - 1


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError(f"Duplicate signed-policy field: {key}")
        fields[key] = value
    return fields


def _exact_fields(value: Any, names: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError(f"{label} must contain exactly the expected fields")
    return value


def _hex_bytes(value: Any, size: int, label: str) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) != size * 2
        or not value.isascii()
        or any(char not in "0123456789abcdefABCDEF" for char in value)
    ):
        raise ValueError(f"{label} must be {size * 2} hexadecimal characters")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} is not hexadecimal") from error


def _positive_revision(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= U64_MAX:
        raise ValueError(f"{label} must be a positive u64 integer")
    return value


def _json_bytes(value: dict[str, Any]) -> bytes:
    # Match serde_json::to_vec on Rust's typed structs, including field order.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _policy_parent_snapshot(path: Path) -> tuple[tuple[int, ...], ...]:
    """Observe the immediate parent and each ancestor across verification.

    The leaf snapshot includes ctime; ancestors include stable identity and
    security permissions, but not volatile directory timestamps (notably /tmp).
    This is a point-in-time check, not atomic filesystem path custody.
    """
    parent = path.parent
    parent_metadata = parent.lstat()
    observations: list[tuple[int, ...]] = []
    for component in (parent, *parent.parents):
        metadata = parent_metadata if component == parent else component.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Symlink in signed-policy directory path is not allowed")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Signed-policy path contains a non-directory")
        if component != parent:
            if metadata.st_uid not in (os.geteuid(), 0):
                raise ValueError("Signed-policy ancestor directory must be owned by this user or root")
            if metadata.st_mode & 0o022:
                if not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX):
                    raise ValueError("Signed-policy ancestor directory must not be writable by group or others")
        observations.append((
            metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_uid, metadata.st_gid,
        ))
    if parent_metadata.st_mode & 0o022:
        raise ValueError("Signed-policy parent directory must not be writable by group or others")
    if parent_metadata.st_uid not in (os.geteuid(), 0):
        raise ValueError("Signed-policy parent directory must be owned by this user or root")
    observations[0] += (parent_metadata.st_ctime_ns,)
    return tuple(observations)


def _policy_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    """Observe inode identity and security-relevant metadata across file reads."""
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _policy_path_snapshot(path: Path) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Observe a policy pathname and its parent across a full rotation check.

    A valid signature and unchanged bytes do not detect a same-byte inode
    replacement between the two bounded reads. This is only a point-in-time
    observation, not an atomic snapshot or privileged rollback defense.
    """
    parent = _policy_parent_snapshot(path)
    metadata = path.lstat()
    return parent, _policy_file_metadata(metadata)


def _read_signed_policy_bytes(path: Path) -> bytes:
    path = Path(os.path.abspath(path))
    parent_before = _policy_parent_snapshot(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("Signed policy must be a regular non-symlink file")
    # A foreign account must not control a policy file in an otherwise
    # administrator-owned input directory. Root-owned files remain supported.
    if before.st_uid not in (os.geteuid(), 0):
        raise ValueError("Signed policy must be owned by this user or root")
    if before.st_mode & 0o022:
        raise ValueError("Signed policy must not be writable by group or others")
    if before.st_size > MAX_POLICY_BYTES:
        raise ValueError("Signed policy exceeds 16 KiB")
    # A FIFO swapped in after lstat must not block the verifier at open().
    # O_NONBLOCK does not alter reads from an ordinary regular file.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        after = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or _policy_file_metadata(before) != _policy_file_metadata(after)
        ):
            # The inode may be unchanged while mode, owner, group, size or
            # timestamps change between the pathname check and open().
            raise ValueError("Signed policy changed while opening")
        if after.st_mode & 0o022:
            raise ValueError("Signed policy must not be writable by group or others")
        raw = stream.read(MAX_POLICY_BYTES + 1)
        finished = os.fstat(stream.fileno())
        # A writer can alter the opened inode after the first fstat and while
        # bytes are being read. Reject observed metadata changes even when
        # the writer restores identical JSON bytes before the next path read.
        if _policy_file_metadata(after) != _policy_file_metadata(finished):
            raise ValueError("Signed policy changed while reading")
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("Signed policy exceeds 16 KiB")
    # The opened descriptor can remain valid after the pathname is swapped.
    # Reject an observed replacement even when the new inode has identical bytes.
    path_after = path.lstat()
    if _policy_file_metadata(finished) != _policy_file_metadata(path_after):
        raise ValueError("Signed policy path changed during read")
    if _policy_parent_snapshot(path) != parent_before:
        raise ValueError("Signed-policy parent directory changed while reading")
    return raw


def _parse_signed_policy(raw: bytes) -> dict[str, Any]:
    return _exact_fields(
        json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields),
        {"policy", "authority_public_key_hex", "signature_hex"},
        "Signed policy envelope",
    )


def _read_signed_policy(path: Path) -> dict[str, Any]:
    return _parse_signed_policy(_read_signed_policy_bytes(path))


def _validated_policy(envelope: dict[str, Any], authority: bytes) -> tuple[int, bytes]:
    policy = _exact_fields(
        envelope["policy"], {"format", "revision", "signers"}, "Signer policy"
    )
    if policy["format"] != POLICY_FORMAT:
        raise ValueError("Unsupported signer policy format")
    revision = _positive_revision(policy["revision"], "Signer policy revision")
    signers = policy["signers"]
    if not isinstance(signers, list) or not 1 <= len(signers) <= 64:
        raise ValueError("Signer policy must have between 1 and 64 signers")

    typed_signers: list[dict[str, str]] = []
    distinct: set[bytes] = set()
    for entry in signers:
        entry = _exact_fields(entry, {"public_key_hex", "status"}, "Signer entry")
        key = _hex_bytes(entry["public_key_hex"], 32, "Evidence signer key")
        if key in distinct:
            raise ValueError("Duplicate evidence signer key")
        if key == authority:
            raise ValueError("Policy authority must differ from every evidence signer")
        distinct.add(key)
        if entry["status"] not in ("trusted", "revoked"):
            raise ValueError("Invalid signer status")
        typed_signers.append(
            {"public_key_hex": entry["public_key_hex"], "status": entry["status"]}
        )

    declared = _hex_bytes(envelope["authority_public_key_hex"], 32, "Declared authority")
    if declared != authority:
        raise ValueError("Signed policy authority differs from independently pinned authority")
    signature = _hex_bytes(envelope["signature_hex"], 64, "Authority signature")
    typed_policy = {
        "format": POLICY_FORMAT,
        "revision": revision,
        "signers": typed_signers,
    }
    payload = DOMAIN + _json_bytes(typed_policy)
    try:
        Ed25519PublicKey.from_public_bytes(authority).verify(signature, payload)
    except (InvalidSignature, ValueError) as error:
        raise ValueError("Ed25519 policy authority signature verification failed") from error

    typed_envelope = {
        "policy": typed_policy,
        "authority_public_key_hex": envelope["authority_public_key_hex"],
        "signature_hex": envelope["signature_hex"],
    }
    return revision, hashlib.sha256(_json_bytes(typed_envelope)).digest()


def verify_rotation_files(
    previous_policy_file: Path,
    replacement_policy_file: Path,
    *,
    authority_public_key_hex: str,
    expected_revision: int,
    expected_sha256: str,
    replacement_revision: int,
    replacement_sha256: str,
) -> int:
    """Verify both signatures, independent pins, key separation and revision continuity.

    Returns the replacement revision only if both signed policies authenticate.
    The caller must still obtain independent administrator approval and use a
    compare-and-swap publisher to protect against cooperating concurrent writers.
    """
    authority = _hex_bytes(authority_public_key_hex, 32, "Pinned authority")
    previous_pin = _hex_bytes(expected_sha256, 32, "Previous independent pin")
    replacement_pin = _hex_bytes(replacement_sha256, 32, "Replacement independent pin")
    expected_revision = _positive_revision(expected_revision, "Expected revision")
    replacement_revision = _positive_revision(replacement_revision, "Replacement revision")
    previous_path = Path(os.path.abspath(previous_policy_file))
    replacement_path = Path(os.path.abspath(replacement_policy_file))
    # Capture both inputs before verification; each individual bounded read
    # already checks its own descriptor/path metadata, but identical-byte
    # swaps between reads must also fail closed.
    previous_snapshot = _policy_path_snapshot(previous_path)
    replacement_snapshot = _policy_path_snapshot(replacement_path)
    # A rotation must compare two distinct file identities. Reusing one
    # pathname (or a hard-link alias) could otherwise let sequential reads
    # observe different policy generations from a mutable shared inode.
    if previous_snapshot[1][:2] == replacement_snapshot[1][:2]:
        raise ValueError("Previous and replacement signed policies must be distinct files")
    previous_bytes = _read_signed_policy_bytes(previous_path)
    replacement_bytes = _read_signed_policy_bytes(replacement_path)
    previous = _parse_signed_policy(previous_bytes)
    replacement = _parse_signed_policy(replacement_bytes)
    previous_value, previous_digest = _validated_policy(previous, authority)
    replacement_value, replacement_digest = _validated_policy(replacement, authority)
    if previous_digest != previous_pin or replacement_digest != replacement_pin:
        raise ValueError("Signed policy does not match independently pinned SHA-256")
    if previous_value != expected_revision:
        raise ValueError("Previous policy revision does not match the current anchor")
    if replacement_value != replacement_revision or replacement_value <= previous_value:
        raise ValueError("Replacement policy revision must strictly increase")
    # Detect byte-level changes observed during signature verification before success.
    # This is not an atomic snapshot or a defense against privileged file replacement.
    if (
        _read_signed_policy_bytes(previous_path) != previous_bytes
        or _policy_path_snapshot(previous_path) != previous_snapshot
    ):
        raise ValueError("Previous signed policy changed during verification")
    if (
        _read_signed_policy_bytes(replacement_path) != replacement_bytes
        or _policy_path_snapshot(replacement_path) != replacement_snapshot
    ):
        raise ValueError("Replacement signed policy changed during verification")
    return replacement_value
