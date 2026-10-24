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


def _read_signed_policy_bytes(path: Path) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("Signed policy must be a regular non-symlink file")
    if before.st_mode & 0o022:
        raise ValueError("Signed policy must not be writable by group or others")
    if before.st_size > MAX_POLICY_BYTES:
        raise ValueError("Signed policy exceeds 16 KiB")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        after = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ValueError("Signed policy changed while opening")
        if after.st_mode & 0o022:
            raise ValueError("Signed policy must not be writable by group or others")
        raw = stream.read(MAX_POLICY_BYTES + 1)
        finished = os.fstat(stream.fileno())
        # A writer can alter the opened inode after the first fstat and while
        # bytes are being read. Reject observed metadata changes even when
        # the writer restores identical JSON bytes before the next path read.
        metadata_fields = (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink",
            "st_size", "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(after, field) != getattr(finished, field) for field in metadata_fields):
            raise ValueError("Signed policy changed while reading")
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("Signed policy exceeds 16 KiB")
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
    previous_bytes = _read_signed_policy_bytes(previous_policy_file)
    replacement_bytes = _read_signed_policy_bytes(replacement_policy_file)
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
    if _read_signed_policy_bytes(previous_policy_file) != previous_bytes:
        raise ValueError("Previous signed policy changed during verification")
    if _read_signed_policy_bytes(replacement_policy_file) != replacement_bytes:
        raise ValueError("Replacement signed policy changed during verification")
    return replacement_value
