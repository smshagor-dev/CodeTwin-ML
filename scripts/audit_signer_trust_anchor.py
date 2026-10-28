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
import time

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
        _reject_excessive_json_nesting,
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
        _reject_excessive_json_nesting,
        _read_signed_policy_bytes,
        _unique_fields,
        _validated_policy,
    )



FLOOR_CHECKPOINT_FORMAT = "codetwin-revision-floor-checkpoint-v1"
FLOOR_CHECKPOINT_DOMAIN = b"CodeTwin-ML/revision-floor/ed25519/v1" + bytes([0])
FLOOR_CHECKPOINT_FORMAT_V2 = "codetwin-revision-floor-checkpoint-v2"
FLOOR_CHECKPOINT_DOMAIN_V2 = b"CodeTwin-ML/revision-floor/ed25519/v2" + bytes([0])
MAX_CHECKPOINT_LIFETIME_SECONDS = 7 * 24 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 300


def _checkpoint_timestamp(value: object, name: str) -> int:
    if type(value) is not int or not 0 < value <= (1 << 63) - 1:
        raise ValueError(f"{name} must be a positive signed 64-bit Unix timestamp")
    return value


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
    require_fresh: bool = False,
    minimum_issued_at_unix: int | None = None,
    maximum_age_seconds: int | None = None,
) -> tuple[bytes, tuple[tuple[int, ...], tuple[int, ...]], int | None, int | None]:
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
    _reject_excessive_json_nesting(raw, "Floor checkpoint")
    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields)
    except RecursionError as error:
        raise ValueError("Floor checkpoint JSON nesting is too deep") from error
    envelope = _exact_fields(
        decoded,
        {"record", "authority_public_key_hex", "signature_hex"},
        "Floor checkpoint envelope",
    )
    raw_record = envelope["record"]
    if not isinstance(raw_record, dict):
        raise ValueError("Floor checkpoint record must be an object")
    version = raw_record.get("format")
    if version == FLOOR_CHECKPOINT_FORMAT_V2:
        record = _exact_fields(
            raw_record,
            {"format", "minimum_revision", "signed_policy_sha256_hex",
             "issued_at_unix", "expires_at_unix"},
            "Floor checkpoint record",
        )
        domain = FLOOR_CHECKPOINT_DOMAIN_V2
    elif version == FLOOR_CHECKPOINT_FORMAT and not (
        require_fresh or minimum_issued_at_unix is not None or maximum_age_seconds is not None
    ):
        record = _exact_fields(
            raw_record,
            {"format", "minimum_revision", "signed_policy_sha256_hex"},
            "Floor checkpoint record",
        )
        domain = FLOOR_CHECKPOINT_DOMAIN
    elif version == FLOOR_CHECKPOINT_FORMAT:
        raise ValueError("Fresh, issuance-pinned or age-bounded floor checkpoint requires signed v2 timestamps")
    else:
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
    issued_at: int | None = None
    expires_at: int | None = None
    if version == FLOOR_CHECKPOINT_FORMAT_V2:
        issued_at = _checkpoint_timestamp(record["issued_at_unix"], "Checkpoint issued_at_unix")
        expires_at = _checkpoint_timestamp(record["expires_at_unix"], "Checkpoint expires_at_unix")
        if expires_at <= issued_at or expires_at - issued_at > MAX_CHECKPOINT_LIFETIME_SECONDS:
            raise ValueError("Floor checkpoint lifetime is invalid or exceeds seven days")
        signed_record["issued_at_unix"] = issued_at
        signed_record["expires_at_unix"] = expires_at
    try:
        Ed25519PublicKey.from_public_bytes(checkpoint_key).verify(
            signature, domain + _json_bytes(signed_record),
        )
    except InvalidSignature as error:
        raise ValueError("Floor checkpoint signature verification failed") from error
    if expires_at is not None:
        # A separately protected issuance floor rejects older valid v2
        # records even when their signatures and expiry remain valid.
        if minimum_issued_at_unix is not None and issued_at < minimum_issued_at_unix:
            raise ValueError("Floor checkpoint predates independently pinned issuance floor")
        now = int(time.time())
        if issued_at > now + MAX_CLOCK_SKEW_SECONDS:
            raise ValueError("Floor checkpoint issued in the future")
        if now >= expires_at:
            raise ValueError("Floor checkpoint has expired")
        # An operator-chosen, bounded age cap narrows replay of still-valid
        # v2 checkpoints. It relies on the local clock, not trusted time.
        if maximum_age_seconds is not None and now - issued_at > maximum_age_seconds:
            raise ValueError("Floor checkpoint exceeds maximum age")
    if not _checkpoint_unchanged(path, raw, before):
        raise ValueError("Floor checkpoint changed during verification")
    return raw, before, issued_at, expires_at


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
    require_fresh_checkpoint: bool = False,
    minimum_checkpoint_issued_at_unix: int | None = None,
    minimum_audit_time_unix: int | None = None,
    max_checkpoint_age_seconds: int | None = None,
    historical_evidence_signer_keys_hex: tuple[str, ...] = (),
    historical_policy_authority_keys_hex: tuple[str, ...] = (),
    revoked_checkpoint_authority_keys_hex: tuple[str, ...] = (),
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
    # The current signed policy cannot attest to keys removed from earlier
    # revisions. An independently maintained historical inventory can forbid
    # reuse of those public keys as the checkpoint authority.
    if not isinstance(historical_evidence_signer_keys_hex, (tuple, list)) or len(historical_evidence_signer_keys_hex) > 256:
        raise ValueError("Historical evidence signer inventory must contain at most 256 keys")
    historical_keys = tuple(
        _hex_bytes(value, 32, "Historical evidence signer key")
        for value in historical_evidence_signer_keys_hex
    )
    if len(set(historical_keys)) != len(historical_keys):
        raise ValueError("Duplicate historical evidence signer key")
    # A rotated signer-policy authority must not become a checkpoint signer.
    # These public keys are independently supplied, not inferred from the
    # current policy (which cannot attest to historical authorities).
    if not isinstance(historical_policy_authority_keys_hex, (tuple, list)) or len(historical_policy_authority_keys_hex) > 256:
        raise ValueError("Historical policy authority inventory must contain at most 256 keys")
    historical_authorities = tuple(
        _hex_bytes(value, 32, "Historical policy authority key")
        for value in historical_policy_authority_keys_hex
    )
    if len(set(historical_authorities)) != len(historical_authorities):
        raise ValueError("Duplicate historical policy authority key")
    # Revocation decisions must be sourced from independent administrator
    # records, not the checkpoint envelope or a mutable local trust database.
    if not isinstance(revoked_checkpoint_authority_keys_hex, (tuple, list)) or len(revoked_checkpoint_authority_keys_hex) > 256:
        raise ValueError("Revoked checkpoint authority inventory must contain at most 256 keys")
    revoked_checkpoint_keys = tuple(
        _hex_bytes(value, 32, "Revoked checkpoint authority key")
        for value in revoked_checkpoint_authority_keys_hex
    )
    if len(set(revoked_checkpoint_keys)) != len(revoked_checkpoint_keys):
        raise ValueError("Duplicate revoked checkpoint authority key")
    checkpoint_inputs = (
        floor_checkpoint_file, checkpoint_authority_public_key_hex, checkpoint_sha256,
    )
    if minimum_checkpoint_issued_at_unix is not None:
        _checkpoint_timestamp(
            minimum_checkpoint_issued_at_unix, "Independent minimum checkpoint issued_at_unix",
        )
        if not all(value is not None for value in checkpoint_inputs):
            raise ValueError("Independent checkpoint issuance floor requires complete checkpoint inputs")
    if minimum_audit_time_unix is not None:
        _checkpoint_timestamp(minimum_audit_time_unix, "Independent minimum audit time")
        if not all(value is not None for value in checkpoint_inputs):
            raise ValueError("Independent audit clock floor requires complete checkpoint inputs")
    if max_checkpoint_age_seconds is not None:
        if (type(max_checkpoint_age_seconds) is not int or
                not 0 < max_checkpoint_age_seconds <= MAX_CHECKPOINT_LIFETIME_SECONDS):
            raise ValueError("Maximum checkpoint age must be a positive integer at most seven days")
        if not all(value is not None for value in checkpoint_inputs):
            raise ValueError("Maximum checkpoint age requires complete checkpoint inputs")
    if historical_keys and not all(value is not None for value in checkpoint_inputs):
        raise ValueError("Historical evidence signer inventory requires complete floor checkpoint inputs")
    if historical_authorities and not all(value is not None for value in checkpoint_inputs):
        raise ValueError("Historical policy authority inventory requires complete floor checkpoint inputs")
    if revoked_checkpoint_keys and not all(value is not None for value in checkpoint_inputs):
        raise ValueError("Revoked checkpoint authority inventory requires complete floor checkpoint inputs")
    # Strict deployments must not silently fall back to a pin-only audit when
    # checkpoint arguments are omitted by an operator or automation.
    if (require_floor_checkpoint or require_fresh_checkpoint) and not all(
        value is not None for value in checkpoint_inputs
    ):
        raise ValueError("Required floor checkpoint and both independent pins are missing")
    if any(value is not None for value in checkpoint_inputs) and not all(
        value is not None for value in checkpoint_inputs
    ):
        raise ValueError("All three independent floor checkpoint inputs are required")
    # Reject a clock observed below the separately authenticated lower bound
    # before opening any anchor or checkpoint file. This is not a trusted clock.
    # Every v2 checkpoint relies on the local wall clock, including v2
    # checkpoints accepted without optional strict freshness flags. Observe
    # it before inspecting files so a rollback during the audit cannot make
    # an expired or stale checkpoint appear valid at the final boundary.
    # V1 checkpoints have no signed timestamps and no final time comparison.
    audit_started_at_unix = (
        int(time.time()) if (
            floor_checkpoint_file is not None or minimum_audit_time_unix is not None
            or max_checkpoint_age_seconds is not None
        ) else None
    )
    # Monotonic elapsed time supplements (but cannot authenticate) the wall
    # clock. Sampling both clocks lets the final check detect a wall-clock
    # slowdown/rollback masked by a still-forward final wall-clock reading.
    audit_started_monotonic = (
        time.monotonic() if audit_started_at_unix is not None else None
    )
    if (minimum_audit_time_unix is not None
            and audit_started_at_unix is not None
            and audit_started_at_unix < minimum_audit_time_unix):
        raise ValueError("Local audit clock is below independently pinned minimum")
    checkpoint_bytes: bytes | None = None
    checkpoint_snapshot: tuple[tuple[int, ...], tuple[int, ...]] | None = None
    checkpoint_issued_at: int | None = None
    checkpoint_expires_at: int | None = None
    checkpoint_path: Path | None = None
    if floor_checkpoint_file is not None:
        assert checkpoint_authority_public_key_hex is not None
        assert checkpoint_sha256 is not None
        checkpoint_key = _hex_bytes(checkpoint_authority_public_key_hex, 32, "Checkpoint authority")
        if checkpoint_key in historical_keys:
            raise ValueError("Checkpoint authority must differ from historical evidence signers")
        if checkpoint_key in historical_authorities:
            raise ValueError("Checkpoint authority must differ from historical policy authorities")
        if checkpoint_key in revoked_checkpoint_keys:
            raise ValueError("Checkpoint authority has been independently listed as revoked")
        checkpoint_path = Path(os.path.abspath(floor_checkpoint_file))
        checkpoint_bytes, checkpoint_snapshot, checkpoint_issued_at, checkpoint_expires_at = _verify_floor_checkpoint(
            checkpoint_path,
            checkpoint_authority_hex=checkpoint_authority_public_key_hex,
            checkpoint_sha256=checkpoint_sha256,
            policy_authority=authority,
            independent_floor=floor,
            signed_policy_digest=digest,
            require_fresh=(require_fresh_checkpoint or minimum_audit_time_unix is not None
                           or max_checkpoint_age_seconds is not None),
            minimum_issued_at_unix=minimum_checkpoint_issued_at_unix,
            maximum_age_seconds=max_checkpoint_age_seconds,
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
    # A checkpoint authority reused as an evidence-signing key is not an
    # independent signing role, even when that signer is now revoked. Check
    # against the authenticated policy, never an unverified input envelope.
    if checkpoint_authority_public_key_hex is not None:
        checkpoint_key = _hex_bytes(
            checkpoint_authority_public_key_hex, 32, "Checkpoint authority",
        )
        if any(
            _hex_bytes(entry["public_key_hex"], 32, "Evidence signer key") == checkpoint_key
            for entry in policy_before["policy"]["signers"]
        ):
            raise ValueError("Checkpoint authority must differ from every evidence signer")
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
        # The final checkpoint read is not a transaction with the anchor and
        # policy reads above. A noncooperating writer could replace either
        # input while that last checkpoint read is in progress. Re-observe
        # both before reporting success in checkpoint mode.
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("External anchor directory changed during audit")
        checked_anchor, checked_metadata = _read_anchor_with_metadata(path)
        if checked_anchor != before or checked_metadata != before_metadata:
            raise ValueError("External anchor changed during audit")
        if (
            _read_signed_policy_bytes(policy_path) != policy_before_bytes
            or _policy_parent_snapshot(policy_path) != policy_parent_before
            or _anchor_metadata(policy_path.lstat()) != policy_metadata_before
        ):
            raise ValueError("Signed policy changed during audit")
        if _private_directory(path.parent) != directory_identity:
            raise ValueError("External anchor directory changed during audit")
        # These observations are bounded; no sequence of reads can establish
        # an atomic snapshot or prevent a privileged rollback after return.
    # Recheck the same lower bound at the return boundary: the local clock
    # can move backwards while the signed files are being inspected.
    final_now = int(time.time()) if (
        checkpoint_expires_at is not None or minimum_audit_time_unix is not None
        or max_checkpoint_age_seconds is not None
    ) else None
    if checkpoint_expires_at is not None and final_now >= checkpoint_expires_at:
        raise ValueError("Floor checkpoint expired during audit")
    if minimum_audit_time_unix is not None and final_now < minimum_audit_time_unix:
        raise ValueError("Local audit clock fell below independently pinned minimum during audit")
    # A rollback can stay above the administrator's minimum. Compare the
    # final observed wall clock with the audit's own initial observation as
    # an additional fail-closed check; neither reading is trusted time.
    if (audit_started_at_unix is not None and final_now is not None
            and final_now < audit_started_at_unix):
        raise ValueError("Local audit clock moved backwards during audit")
    # Whole-second wall-clock readings may differ from fractional monotonic
    # elapsed time by up to one second. Beyond that, reject even when the
    # final wall-clock reading is not earlier than the initial reading.
    # A compromised clock source or unobserved time manipulation remains
    # outside the guarantee of this point-in-time consistency check.
    if checkpoint_expires_at is not None:
        assert audit_started_monotonic is not None and audit_started_at_unix is not None
        monotonic_elapsed = time.monotonic() - audit_started_monotonic
        if not 0 <= monotonic_elapsed < float("inf"):
            raise ValueError("Local monotonic audit clock was invalid")
        if final_now + 1 < audit_started_at_unix + monotonic_elapsed:
            raise ValueError("Local audit wall clock lagged monotonic elapsed time")
    if max_checkpoint_age_seconds is not None and (
        checkpoint_issued_at is None or final_now is None or
        final_now - checkpoint_issued_at > max_checkpoint_age_seconds
    ):
        raise ValueError("Floor checkpoint exceeded maximum age during audit")
    return {
        "status": "verified_against_supplied_pins",
        "minimum_revision": revision,
        "independent_revision_floor": floor,
        "signed_policy_sha256_hex": digest.hex(),
        "floor_checkpoint_verified": checkpoint_path is not None,
        "floor_checkpoint_fresh": checkpoint_expires_at is not None,
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
    parser.add_argument("--require-fresh-checkpoint", action="store_true",
                        help="Require a signed v2 checkpoint with a currently valid expiry")
    parser.add_argument("--minimum-checkpoint-issued-at-unix", type=int,
                        help="Independently protected minimum signed v2 issuance timestamp")
    parser.add_argument("--minimum-audit-time-unix", type=int,
                        help="Independently protected lower bound for local audit clock; requires signed v2 checkpoint")
    parser.add_argument("--max-checkpoint-age-seconds", type=int,
                        help="Reject signed v2 checkpoints older than this many seconds (1..604800)")
    parser.add_argument("--historical-evidence-signer-key", action="append", default=[],
                        help="Independent historical evidence signer public key (64 hex); repeatable, max 256")
    parser.add_argument("--historical-policy-authority-key", action="append", default=[],
                        help="Independent historical signer-policy authority public key (64 hex); repeatable, max 256")
    parser.add_argument("--revoked-checkpoint-authority-key", action="append", default=[],
                        help="Independently revoked checkpoint authority public key (64 hex); repeatable, max 256")
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
            require_fresh_checkpoint=args.require_fresh_checkpoint,
            minimum_checkpoint_issued_at_unix=args.minimum_checkpoint_issued_at_unix,
            minimum_audit_time_unix=args.minimum_audit_time_unix,
            max_checkpoint_age_seconds=args.max_checkpoint_age_seconds,
            historical_evidence_signer_keys_hex=tuple(args.historical_evidence_signer_key),
            historical_policy_authority_keys_hex=tuple(args.historical_policy_authority_key),
            revoked_checkpoint_authority_keys_hex=tuple(args.revoked_checkpoint_authority_key),
        )
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(2, f"External anchor audit failed: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
