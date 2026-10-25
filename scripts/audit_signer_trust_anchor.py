#!/usr/bin/env python3
"""Read-only audit of an external public signer anchor against independent pins.

The expected authority, exact-envelope SHA-256 and revision MUST arrive over
an authenticated channel independent of the anchor and signed-policy files.
This detects mismatches at inspection time; it is not a protected monotonic
counter, private-key custody proof, or privileged rollback defense.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

if __package__:
    from .publish_signer_trust_anchor import _private_directory, _read_anchor_with_metadata
    from .verify_signer_policy_rotation import (
        _hex_bytes,
        _parse_signed_policy,
        _positive_revision,
        _read_signed_policy_bytes,
        _validated_policy,
    )
else:
    from publish_signer_trust_anchor import _private_directory, _read_anchor_with_metadata
    from verify_signer_policy_rotation import (
        _hex_bytes,
        _parse_signed_policy,
        _positive_revision,
        _read_signed_policy_bytes,
        _validated_policy,
    )


def audit_anchor(
    anchor_file: Path,
    signed_policy_file: Path,
    *,
    authority_public_key_hex: str,
    expected_revision: int,
    expected_sha256: str,
) -> dict[str, str | int]:
    """Fail closed unless both the anchor and signed policy match external pins.

    Does not create locks, write files, sign anything or update SQLite.
    Concurrent, noncooperating filesystem replacement cannot be ruled out;
    re-read the anchor and compare inode metadata to detect observed replacement
    even when the JSON bytes are unchanged.
    """
    authority = _hex_bytes(authority_public_key_hex, 32, "Independent authority")
    digest = _hex_bytes(expected_sha256, 32, "Independent signed-policy SHA-256")
    revision = _positive_revision(expected_revision, "Independent revision")
    path = Path(os.path.abspath(anchor_file))
    directory_identity = _private_directory(path.parent)
    before, before_metadata = _read_anchor_with_metadata(path)
    if (
        bytes.fromhex(before["authority_public_key_hex"]) != authority
        or before["minimum_revision"] != revision
        or bytes.fromhex(before["signed_policy_sha256_hex"]) != digest
    ):
        raise ValueError("External anchor differs from independently trusted values")

    policy_before_bytes = _read_signed_policy_bytes(signed_policy_file)
    policy_before = _parse_signed_policy(policy_before_bytes)
    policy_revision, policy_digest = _validated_policy(policy_before, authority)
    if policy_revision != revision or policy_digest != digest:
        raise ValueError("Signed policy differs from independently trusted revision or digest")

    if _private_directory(path.parent) != directory_identity:
        raise ValueError("External anchor directory changed during audit")
    after, after_metadata = _read_anchor_with_metadata(path)
    if after != before or after_metadata != before_metadata:
        raise ValueError("External anchor changed during audit")
    if _read_signed_policy_bytes(signed_policy_file) != policy_before_bytes:
        raise ValueError("Signed policy changed during audit")
    return {
        "status": "verified_against_supplied_pins",
        "minimum_revision": revision,
        "signed_policy_sha256_hex": digest.hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor-file", required=True, type=Path)
    parser.add_argument("--signed-policy", required=True, type=Path)
    parser.add_argument("--authority-public-key", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    try:
        result = audit_anchor(
            args.anchor_file,
            args.signed_policy,
            authority_public_key_hex=args.authority_public_key,
            expected_revision=args.expected_revision,
            expected_sha256=args.expected_sha256,
        )
    except (OSError, ValueError, UnicodeError) as error:
        parser.exit(2, f"External anchor audit failed: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
