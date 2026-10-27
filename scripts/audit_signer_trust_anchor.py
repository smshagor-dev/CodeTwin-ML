#!/usr/bin/env python3
"""Read-only audit of an external public signer anchor against independent pins.

The expected authority, exact-envelope SHA-256 and revision MUST arrive over
an authenticated channel independent of the anchor and signed-policy files.
This detects mismatches at inspection time; it is not a protected monotonic
counter, private-key custody proof, or privileged rollback defense.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pathlib import Path

if __package__:
    from .publish_signer_trust_anchor import (
        _anchor_metadata, _private_directory, _read_anchor_with_metadata,
        _require_external_anchor_path,
    )
    from .verify_signer_policy_rotation import (
        _exact_fields,
        _hex_bytes,
        _json_bytes,
        _parse_signed_policy,
        _policy_path_snapshot,
        _policy_parent_snapshot,
        _positive_revision,
        _read_signed_policy_bytes,
        _unique_fields,
        _validated_policy,
    )
else:
    from publish_signer_trust_anchor import (
        _anchor_metadata, _private_directory, _read_anchor_with_metadata,
        _require_external_anchor_path,
    )
    from verify_signer_policy_rotation import (
        _exact_fields,
        _hex_bytes,
        _json_bytes,
        _parse_signed_policy,
        _policy_parent_snapshot,
        _policy_path_snapshot,
        _positive_revision,
        _read_signed_policy_bytes,
        _unique_fields,
        _validated_policy,
    )



FLOOR_CHECKPOINT_FORMAT = "codetwin-revision-floor-checkpoint-v1"
FLOOR_CHECKPOINT_DOMAIN = b"CodeTwin-ML/revision-floor/ed25519/v1" + bytes([0])


def _checkpoint_unchanged(
    path: Path,
    expected_bytes: bytes,
    expected_snapshot: tuple[tuple[int, ...], tuple[int, ...]],
) -> bool:
    """Bound both sides of a checkpoint re-read with path identity checks.

    This detects observed substitutions after the read, not an atomic snapshot
    or a defense against replacements outside the observation window.
    """
    if _policy_path_snapshot(path) != expected_snapshot:
        return False
    if _read_signed_policy_bytes(path) != expected_bytes:
        return False
    return _policy_path_snapshot(path) == expected_snapshot


def _verify_floor_checkpoint(
    path: Path,
    *,
    checkpoint_authority_hex: str,
    checkpoint_sha256: str,
    policy_authority: bytes,
    independent_floor: int,
    signed_policy_digest: bytes,
) -> tuple[bytes, tuple[tuple[int, ...], tuple[int, ...]]]:
    """Check an externally pinned, independently signed public floor record.

    An old but valid record can still be replayed if its external pins are
    rolled back. This does not provide a monotonic hardware counter.
    """
    checkpoint_key = _hex_bytes(checkpoint_authority_hex, 32, "Checkpoint authority")
    if checkpoint_key == policy_authority:
        raise ValueError("Checkpoint authority must differ from signer-policy authority")
    pinned_digest = _hex_bytes(checkpoint_sha256, 32, "Independent checkpoint SHA-256")
    path = Path(os.path.abspath(path))
    _require_external_anchor_path(path)
    before = _policy_path_snapshot(path)
    raw = _read_signed_policy_bytes(path)
    if hashlib.sha256(raw).digest() != pinned_digest:
        raise ValueError("Floor checkpoint differs from independently pinned digest")
    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields)
    except RecursionError as error:
        raise ValueError("Floor checkpoint JSON nesting is too deep") from error
    envelope = _exact_fields(
        decoded,
        {"record", "authority_public_key_hex", "signature_hex"},
        "Floor checkpoint envelope",
    )
    record = _exact_fields(
        envelope["record"],
        {"format", "minimum_revision", "signed_policy_sha256_hex"},
        "Floor checkpoint record",
    )
    if record["format"] != FLOOR_CHECKPOINT_FORMAT:
        raise ValueError("Unsupported floor checkpoint format")
    floor = _positive_revision(record["minimum_revision"], "Checkpoint revision floor")
    policy_digest = _hex_bytes(
        record["signed_policy_sha256_hex"], 32, "Checkpoint signed-policy SHA-256",
    )
    if floor != independent_floor or policy_digest != signed_policy_digest:
        raise ValueError("Floor checkpoint differs from independently trusted floor or policy digest")
    if _hex_bytes(envelope["authority_public_key_hex"], 32, "Checkpoint authority") != checkpoint_key:
        raise ValueError("Floor checkpoint authority differs from independent pin")
    signature = _hex_bytes(envelope["signature_hex"], 64, "Checkpoint signature")
    signed_record = {
        "format": record["format"],
        "minimum_revision": floor,
        "signed_policy_sha256_hex": policy_digest.hex(),
    }
    try:
        Ed25519PublicKey.from_public_bytes(checkpoint_key).verify(
            signature, FLOOR_CHECKPOINT_DOMAIN + _json_bytes(signed_record),
        )
    except InvalidSignature as error:
        raise ValueError("Floor checkpoint signature verification failed") from error
    if not _checkpoint_unchanged(path, raw, before):
        raise ValueError("Floor checkpoint changed during verification")
    return raw, before


def audit_anchor(
    anchor_file: Path,
    signed_policy_file: Path,
    *,
    authority_public_key_hex: str,
    expected_revision: int,
    independent_revision_floor: int,
    expected_sha256: str,
    floor_checkpoint_file: Path | None = None,
    checkpoint_authority_public_key_hex: str | None = None,
    checkpoint_sha256: str | None = None,
    require_floor_checkpoint: bool = False,
) -> dict[str, str | int]:
    """Fail closed unless both the anchor and signed policy match external pins.

    Requires a separately protected revision floor in addition to exact pins.
    Does not create locks, write files, sign anything or update SQLite.
    Concurrent, noncooperating filesystem replacement cannot be ruled out;
    re-read the anchor and compare inode metadata to detect observed replacement
    even when the JSON bytes are unchanged.
    """
    authority = _hex_bytes(authority_public_key_hex, 32, "Independent authority")
    digest = _hex_bytes(expected_sha256, 32, "Independent signed-policy SHA-256")
    revision = _positive_revision(expected_revision, "Independent revision")
    floor = _positive_revision(independent_revision_floor, "Independent revision floor")
    if revision < floor:
        raise ValueError("Independently pinned revision is below independent revision floor")
    checkpoint_inputs = (
        floor_checkpoint_file, checkpoint_authority_public_key_hex, checkpoint_sha256,
    )
    # Strict deployments must not silently fall back to a pin-only audit when
    # checkpoint arguments are omitted by an operator or automation.
    if require_floor_checkpoint and not all(value is not None for value in checkpoint_inputs):
        raise ValueError("Required floor checkpoint and both independent pins are missing")
    if any(value is not None for value in checkpoint_inputs) and not all(
        value is not None for value in checkpoint_inputs
    ):
        raise ValueError("All three independent floor checkpoint inputs are required")
    checkpoint_bytes: bytes | None = None
    checkpoint_snapshot: tuple[tuple[int, ...], tuple[int, ...]] | None = None
    checkpoint_path: Path | None = None
    if floor_checkpoint_file is not None:
        assert checkpoint_authority_public_key_hex is not None
        assert checkpoint_sha256 is not None
        checkpoint_path = Path(os.path.abspath(floor_checkpoint_file))
        checkpoint_bytes, checkpoint_snapshot = _verify_floor_checkpoint(
            checkpoint_path,
            checkpoint_authority_hex=checkpoint_authority_public_key_hex,
            checkpoint_sha256=checkpoint_sha256,
            policy_authority=authority,
            independent_floor=floor,
            signed_policy_digest=digest,
        )
    path = Path(os.path.abspath(anchor_file))
    _require_external_anchor_path(path)
    directory_identity = _private_directory(path.parent)
    before, before_metadata = _read_anchor_with_metadata(path)
    if (
        bytes.fromhex(before["authority_public_key_hex"]) != authority
        or before["minimum_revision"] != revision
        or bytes.fromhex(before["signed_policy_sha256_hex"]) != digest
    ):
        raise ValueError("External anchor differs from independently trusted values")

    # Capture path and parent identity across the *entire* audit, not just
    # within each bounded policy read. Identical-byte inode swaps must fail.
    policy_path = Path(os.path.abspath(signed_policy_file))
    policy_parent_before = _policy_parent_snapshot(policy_path)
    policy_metadata_before = _anchor_metadata(policy_path.lstat())
    policy_before_bytes = _read_signed_policy_bytes(policy_path)
    if (
        _policy_parent_snapshot(policy_path) != policy_parent_before
        or _anchor_metadata(policy_path.lstat()) != policy_metadata_before
    ):
        raise ValueError("Signed policy changed during audit")
    policy_before = _parse_signed_policy(policy_before_bytes)
    policy_revision, policy_digest = _validated_policy(policy_before, authority)
    if policy_revision != revision or policy_digest != digest:
        raise ValueError("Signed policy differs from independently trusted revision or digest")

    if _private_directory(path.parent) != directory_identity:
        raise ValueError("External anchor directory changed during audit")
    after, after_metadata = _read_anchor_with_metadata(path)
    if after != before or after_metadata != before_metadata:
        raise ValueError("External anchor changed during audit")
    if (
        _read_signed_policy_bytes(policy_path) != policy_before_bytes
        or _policy_parent_snapshot(policy_path) != policy_parent_before
        or _anchor_metadata(policy_path.lstat()) != policy_metadata_before
    ):
        raise ValueError("Signed policy changed during audit")
    # The anchor directory is separate from the policy's parent and can be
    # replaced or made nonprivate after the last anchor read. Recheck its
    # custody at the final audit boundary; this is not an atomic snapshot.
    if _private_directory(path.parent) != directory_identity:
        raise ValueError("External anchor directory changed during audit")
    # The final policy read may race with an independent anchor-file writer.
    # Compare both values and inode metadata again at the return boundary.
    # This is a bounded observation, not a filesystem snapshot.
    final_anchor, final_metadata = _read_anchor_with_metadata(path)
    if final_anchor != before or final_metadata != before_metadata:
        raise ValueError("External anchor changed during audit")
    # The final anchor read itself can race with a directory replacement or
    # permission relaxation. Check the directory once more before success.
    # This remains a bounded observation, not an atomic filesystem snapshot.
    if _private_directory(path.parent) != directory_identity:
        raise ValueError("External anchor directory changed during audit")
    # A policy swap after the earlier policy check but during the final
    # anchor read must not silently pass the audit. This is a final bounded
    # observation, not an atomic filesystem snapshot or custody guarantee.
    if (
        _read_signed_policy_bytes(policy_path) != policy_before_bytes
        or _policy_parent_snapshot(policy_path) != policy_parent_before
        or _anchor_metadata(policy_path.lstat()) != policy_metadata_before
    ):
        raise ValueError("Signed policy changed during audit")
    if checkpoint_path is not None:
        assert checkpoint_bytes is not None and checkpoint_snapshot is not None
        if not _checkpoint_unchanged(checkpoint_path, checkpoint_bytes, checkpoint_snapshot):
            raise ValueError("Floor checkpoint changed during audit")
    return {
        "status": "verified_against_supplied_pins",
        "minimum_revision": revision,
        "independent_revision_floor": floor,
        "signed_policy_sha256_hex": digest.hex(),
        "floor_checkpoint_verified": checkpoint_path is not None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor-file", required=True, type=Path)
    parser.add_argument("--signed-policy", required=True, type=Path)
    parser.add_argument("--authority-public-key", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--independent-revision-floor", required=True, type=int,
                        help="Current floor from separately protected administrator records")
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--floor-checkpoint-file", type=Path,
                        help="Optional separately signed public floor record outside checkout")
    parser.add_argument("--checkpoint-authority-public-key",
                        help="Independent Ed25519 checkpoint authority (distinct from policy authority)")
    parser.add_argument("--checkpoint-sha256",
                        help="SHA-256 of exact checkpoint envelope from independent records")
    parser.add_argument("--require-floor-checkpoint", action="store_true",
                        help="Fail closed unless a signed checkpoint and both pins are supplied")
    args = parser.parse_args()
    try:
        result = audit_anchor(
            args.anchor_file,
            args.signed_policy,
            authority_public_key_hex=args.authority_public_key,
            expected_revision=args.expected_revision,
            independent_revision_floor=args.independent_revision_floor,
            expected_sha256=args.expected_sha256,
            floor_checkpoint_file=args.floor_checkpoint_file,
            checkpoint_authority_public_key_hex=args.checkpoint_authority_public_key,
            checkpoint_sha256=args.checkpoint_sha256,
            require_floor_checkpoint=args.require_floor_checkpoint,
        )
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(2, f"External anchor audit failed: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
