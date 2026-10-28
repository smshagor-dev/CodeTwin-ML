"""Read-only external trust-anchor audit regression coverage."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.audit_signer_trust_anchor import (
    FLOOR_CHECKPOINT_DOMAIN, FLOOR_CHECKPOINT_FORMAT,
    FLOOR_CHECKPOINT_DOMAIN_V2, FLOOR_CHECKPOINT_FORMAT_V2, audit_anchor,
)
from scripts.publish_signer_trust_anchor import FORMAT
from scripts.verify_signer_policy_rotation import DOMAIN


@unittest.skipUnless(os.name == "posix", "External anchor audit requires POSIX")
class ExternalAnchorAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        authority = Ed25519PrivateKey.generate()
        signer = Ed25519PrivateKey.generate()
        # Test-only ephemeral keys remain in process memory, never on disk.
        self.authority_key = authority
        self.signer_key = signer
        self.authority_hex = authority.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        signer_hex = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.signer_hex = signer_hex
        policy = {
            "format": "codetwin-signer-trust-v1",
            "revision": 8,
            "signers": [{"public_key_hex": signer_hex, "status": "trusted"}],
        }
        self.envelope = {
            "policy": policy,
            "authority_public_key_hex": self.authority_hex,
            "signature_hex": authority.sign(
                DOMAIN + json.dumps(
                    policy, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
            ).hex(),
        }
        self.policy = self.root / "signed-policy.json"
        self.policy.write_text(json.dumps(self.envelope), encoding="utf-8")
        self.digest = self._digest(self.envelope)
        self.anchor = self.root / "anchor.json"
        self.original = {
            "format": FORMAT,
            "authority_public_key_hex": self.authority_hex,
            "minimum_revision": 8,
            "signed_policy_sha256_hex": self.digest,
        }
        self._write_anchor(self.original)

    @staticmethod
    def _digest(envelope: dict[str, object]) -> str:
        return hashlib.sha256(
            json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def _write_anchor(self, value: dict[str, object]) -> None:
        self.anchor.write_text(json.dumps(value), encoding="utf-8")
        self.anchor.chmod(0o600)

    def _audit(self, **overrides: object) -> dict[str, str | int]:
        arguments: dict[str, object] = {
            "authority_public_key_hex": self.authority_hex,
            "expected_revision": 8,
            "independent_revision_floor": 8,
            "expected_sha256": self.digest,
        }
        arguments.update(overrides)
        return audit_anchor(self.anchor, self.policy, **arguments)

    def _signed_floor_checkpoint(
        self, *, floor: int = 8, policy_digest: str | None = None,
        key: Ed25519PrivateKey | None = None,
        issued_at_unix: int | None = None, expires_at_unix: int | None = None,
    ) -> dict[str, object]:
        # Ephemeral test-only key: never written to the repository or SQLite.
        key = key if key is not None else Ed25519PrivateKey.generate()
        key_hex = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        record = {
            "format": FLOOR_CHECKPOINT_FORMAT,
            "minimum_revision": floor,
            "signed_policy_sha256_hex": policy_digest or self.digest,
        }
        v2 = issued_at_unix is not None or expires_at_unix is not None
        if v2:
            if issued_at_unix is None or expires_at_unix is None:
                raise ValueError("Both signed checkpoint timestamps are required")
            record["format"] = FLOOR_CHECKPOINT_FORMAT_V2
            record["issued_at_unix"] = issued_at_unix
            record["expires_at_unix"] = expires_at_unix
        payload = json.dumps(record, separators=(",", ":")).encode("utf-8")
        envelope = {
            "record": record,
            "authority_public_key_hex": key_hex,
            "signature_hex": key.sign(
                (FLOOR_CHECKPOINT_DOMAIN_V2 if v2 else FLOOR_CHECKPOINT_DOMAIN) + payload
            ).hex(),
        }
        checkpoint = self.root / "floor-checkpoint.json"
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        checkpoint.write_bytes(raw)
        checkpoint.chmod(0o600)
        return {
            "floor_checkpoint_file": checkpoint,
            "checkpoint_authority_public_key_hex": key_hex,
            "checkpoint_sha256": hashlib.sha256(raw).hexdigest(),
        }

    def test_independent_checkpoint_issuance_floor_rejects_valid_older_v2(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 180, expires_at_unix=now + 3600,
        )
        # This checkpoint is correctly signed and unexpired; only the
        # independently protected issuance floor should reject its replay.
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
            with patch(
                "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
                side_effect=AssertionError("unexpected anchor read"),
            ):
                with self.assertRaisesRegex(ValueError, "predates independently pinned issuance floor"):
                    self._audit(
                        minimum_checkpoint_issued_at_unix=now - 60,
                        **inputs,
                    )

    def test_independent_checkpoint_issuance_floor_accepts_equal_or_newer_v2(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
            for minimum in (now - 120, now - 60):
                with self.subTest(minimum=minimum):
                    result = self._audit(
                        minimum_checkpoint_issued_at_unix=minimum,
                        require_fresh_checkpoint=True,
                        **inputs,
                    )
                    self.assertTrue(result["floor_checkpoint_verified"])
                    self.assertTrue(result["floor_checkpoint_fresh"])

    def test_independent_checkpoint_issuance_floor_requires_v2_and_complete_pins(self) -> None:
        now = 1_800_000_000
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "requires complete checkpoint inputs"):
                self._audit(minimum_checkpoint_issued_at_unix=now)
            with self.assertRaisesRegex(ValueError, "requires signed v2 timestamps"):
                self._audit(
                    minimum_checkpoint_issued_at_unix=now,
                    **self._signed_floor_checkpoint(),
                )

    def test_independent_checkpoint_issuance_floor_rejects_invalid_values(self) -> None:
        inputs = self._signed_floor_checkpoint()
        for value in (0, -1, 1 << 63, True, 1.5, "1800000000"):
            with self.subTest(value=value):
                with patch(
                    "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
                    side_effect=AssertionError("unexpected anchor read"),
                ):
                    with self.assertRaisesRegex(ValueError, "positive signed 64-bit"):
                        self._audit(
                            minimum_checkpoint_issued_at_unix=value,
                            **inputs,
                        )

    def test_independent_audit_clock_floor_rejects_rollback_before_file_reads(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now - 200):
            with patch(
                "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
                side_effect=AssertionError("unexpected anchor read"),
            ):
                with self.assertRaisesRegex(ValueError, "clock is below independently pinned minimum"):
                    self._audit(minimum_audit_time_unix=now - 100, **inputs)

    def test_independent_audit_clock_floor_accepts_boundary_with_signed_v2(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
            result = self._audit(minimum_audit_time_unix=now, **inputs)
        self.assertTrue(result["floor_checkpoint_verified"])
        self.assertTrue(result["floor_checkpoint_fresh"])

    def test_independent_audit_clock_floor_rejects_missing_v2_and_invalid_values(self) -> None:
        now = 1_800_000_000
        with self.assertRaisesRegex(ValueError, "requires complete checkpoint inputs"):
            self._audit(minimum_audit_time_unix=now)
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
            with self.assertRaisesRegex(ValueError, "requires signed v2 timestamps"):
                self._audit(minimum_audit_time_unix=now, **self._signed_floor_checkpoint())
        inputs = self._signed_floor_checkpoint()
        for value in (0, -1, 1 << 63, True, 1.5, "1800000000"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "positive signed 64-bit"):
                    self._audit(minimum_audit_time_unix=value, **inputs)

    def test_independent_audit_clock_floor_rejects_mid_audit_rollback(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        # Initial clock and signature freshness checks pass; the clock
        # rolls back before the final success boundary.
        with patch("scripts.audit_signer_trust_anchor.time.time",
                   side_effect=[now, now, now - 200]):
            with self.assertRaisesRegex(ValueError, "clock fell below independently pinned minimum"):
                self._audit(minimum_audit_time_unix=now - 100, **inputs)

    def test_independent_audit_clock_floor_rejects_rollback_above_floor(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        # The final clock remains above the independent minimum, but is
        # earlier than the clock observed at the start of this audit.
        with patch("scripts.audit_signer_trust_anchor.time.time",
                   side_effect=[now, now, now - 50]):
            with self.assertRaisesRegex(ValueError, "clock moved backwards during audit"):
                self._audit(minimum_audit_time_unix=now - 100, **inputs)

    def test_independent_audit_clock_floor_accepts_forward_clock(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        with patch("scripts.audit_signer_trust_anchor.time.time",
                   side_effect=[now, now, now + 1]):
            result = self._audit(minimum_audit_time_unix=now - 100, **inputs)
        self.assertTrue(result["floor_checkpoint_verified"])
        self.assertTrue(result["floor_checkpoint_fresh"])

    def test_max_checkpoint_age_rejects_old_but_unexpired_v2(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 3600, expires_at_unix=now + 3600,
        )
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
            with patch(
                "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
                side_effect=AssertionError("unexpected anchor read"),
            ):
                with self.assertRaisesRegex(ValueError, "exceeds maximum age"):
                    self._audit(max_checkpoint_age_seconds=1800, **inputs)

    def test_max_checkpoint_age_accepts_equal_age_boundary(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
            result = self._audit(max_checkpoint_age_seconds=60, **inputs)
        self.assertTrue(result["floor_checkpoint_verified"])
        self.assertTrue(result["floor_checkpoint_fresh"])

    def test_max_checkpoint_age_requires_signed_v2_and_bounded_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires complete checkpoint inputs"):
            self._audit(max_checkpoint_age_seconds=60)
        with self.assertRaisesRegex(ValueError, "requires signed v2 timestamps"):
            self._audit(max_checkpoint_age_seconds=60, **self._signed_floor_checkpoint())
        inputs = self._signed_floor_checkpoint()
        for value in (0, -1, 604801, True, 1.5, "60"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "positive integer at most seven days"):
                    self._audit(max_checkpoint_age_seconds=value, **inputs)

    def test_max_checkpoint_age_rejects_expiry_during_audit(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        # Initial age is valid; it exceeds the caller's limit before success.
        with patch("scripts.audit_signer_trust_anchor.time.time",
                   side_effect=[now, now + 50]):
            with self.assertRaisesRegex(ValueError, "exceeded maximum age during audit"):
                self._audit(max_checkpoint_age_seconds=100, **inputs)

    def test_fresh_checkpoint_requires_complete_inputs_and_v2(self) -> None:
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "Required floor checkpoint"):
                self._audit(require_fresh_checkpoint=True)
        with self.assertRaisesRegex(ValueError, "requires signed v2"):
            self._audit(require_fresh_checkpoint=True, **self._signed_floor_checkpoint())

    def test_signed_v2_checkpoint_accepts_valid_bounded_lifetime(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
            result = self._audit(require_fresh_checkpoint=True, **inputs)
        self.assertTrue(result["floor_checkpoint_verified"])
        self.assertTrue(result["floor_checkpoint_fresh"])
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_signed_v2_checkpoint_rejects_stale_future_and_invalid_lifetime(self) -> None:
        now = 1_800_000_000
        for issued, expires, message in (
            (now - 3600, now, "expired"),
            (now + 301, now + 3600, "future"),
            (now - 1, now + 604801, "lifetime"),
            (now + 1, now, "lifetime"),
        ):
            with self.subTest(issued=issued, expires=expires):
                inputs = self._signed_floor_checkpoint(
                    issued_at_unix=issued, expires_at_unix=expires,
                )
                with patch("scripts.audit_signer_trust_anchor.time.time", return_value=now):
                    with self.assertRaisesRegex(ValueError, message):
                        self._audit(require_fresh_checkpoint=True, **inputs)

    def test_signed_v2_checkpoint_timestamp_tamper_fails_signature(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 3600,
        )
        checkpoint = Path(inputs["floor_checkpoint_file"])
        envelope = json.loads(checkpoint.read_text(encoding="utf-8"))
        envelope["record"]["expires_at_unix"] += 1
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        checkpoint.write_bytes(raw)
        inputs["checkpoint_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self._audit(require_fresh_checkpoint=True, **inputs)

    def test_signed_v2_checkpoint_expiring_during_audit_fails_closed(self) -> None:
        now = 1_800_000_000
        inputs = self._signed_floor_checkpoint(
            issued_at_unix=now - 60, expires_at_unix=now + 1800,
        )
        with patch(
            "scripts.audit_signer_trust_anchor.time.time",
            side_effect=(now, now + 1800),
        ):
            with self.assertRaisesRegex(ValueError, "expired during audit"):
                self._audit(require_fresh_checkpoint=True, **inputs)

    def test_required_checkpoint_rejects_omitted_inputs_before_anchor_read(self) -> None:
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "Required floor checkpoint"):
                self._audit(require_floor_checkpoint=True)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_required_checkpoint_rejects_partial_inputs(self) -> None:
        inputs = self._signed_floor_checkpoint()
        with self.assertRaisesRegex(ValueError, "Required floor checkpoint"):
            self._audit(
                require_floor_checkpoint=True,
                floor_checkpoint_file=inputs["floor_checkpoint_file"],
            )

    def test_required_checkpoint_verifies_complete_signed_inputs(self) -> None:
        inputs = self._signed_floor_checkpoint()
        result = self._audit(require_floor_checkpoint=True, **inputs)
        self.assertTrue(result["floor_checkpoint_verified"])
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_independently_signed_floor_checkpoint_validates_without_writes(self) -> None:
        inputs = self._signed_floor_checkpoint()
        before = Path(inputs["floor_checkpoint_file"]).read_bytes()
        result = self._audit(**inputs)
        self.assertTrue(result["floor_checkpoint_verified"])
        self.assertEqual(Path(inputs["floor_checkpoint_file"]).read_bytes(), before)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_signed_checkpoint_rejects_tampering_even_with_new_digest_pin(self) -> None:
        inputs = self._signed_floor_checkpoint()
        checkpoint = Path(inputs["floor_checkpoint_file"])
        envelope = json.loads(checkpoint.read_text(encoding="utf-8"))
        envelope["record"]["minimum_revision"] = 9
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        checkpoint.write_bytes(raw)
        inputs["checkpoint_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "floor or policy digest"):
            self._audit(**inputs)

    def test_signed_checkpoint_rejects_excessive_json_nesting_before_anchor_read(self) -> None:
        inputs = self._signed_floor_checkpoint()
        checkpoint = Path(inputs["floor_checkpoint_file"])
        # The exact-byte digest is updated to isolate the depth guard.
        raw = b'{"record":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"
        checkpoint.write_bytes(raw)
        inputs["checkpoint_sha256"] = hashlib.sha256(raw).hexdigest()
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "Floor checkpoint JSON nesting is too deep"):
                self._audit(**inputs)

    def test_checkpoint_depth_guard_ignores_escaped_quoted_brackets(self) -> None:
        from scripts.verify_signer_policy_rotation import _reject_excessive_json_nesting

        raw = json.dumps({"text": ('[\\\\\"{' * 80)}).encode("utf-8")
        _reject_excessive_json_nesting(raw, "Floor checkpoint")

    def test_signed_checkpoint_rejects_invalid_signature(self) -> None:
        inputs = self._signed_floor_checkpoint()
        checkpoint = Path(inputs["floor_checkpoint_file"])
        envelope = json.loads(checkpoint.read_text(encoding="utf-8"))
        envelope["signature_hex"] = "00" * 64
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        checkpoint.write_bytes(raw)
        inputs["checkpoint_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self._audit(**inputs)

    def test_signed_checkpoint_rejects_wrong_digest_and_authority(self) -> None:
        inputs = self._signed_floor_checkpoint()
        with self.assertRaisesRegex(ValueError, "independently pinned digest"):
            self._audit(**{**inputs, "checkpoint_sha256": "00" * 32})
        with self.assertRaisesRegex(ValueError, "must differ"):
            self._audit(**{
                **inputs, "checkpoint_authority_public_key_hex": self.authority_hex,
            })

    def test_checkpoint_rejects_historical_signer_not_in_current_policy(self) -> None:
        # A removed signer is absent from the current authenticated policy.
        # Its public key must still be forbidden when independently listed.
        historical = Ed25519PrivateKey.generate()
        inputs = self._signed_floor_checkpoint(key=historical)
        historical_hex = inputs["checkpoint_authority_public_key_hex"]
        with self.assertRaisesRegex(ValueError, "historical evidence signers"):
            self._audit(
                require_floor_checkpoint=True,
                historical_evidence_signer_keys_hex=(historical_hex,),
                **inputs,
            )
        # A distinct independently listed key does not block the checkpoint.
        result = self._audit(
            require_floor_checkpoint=True,
            historical_evidence_signer_keys_hex=(self.signer_hex,),
            **inputs,
        )
        self.assertTrue(result["floor_checkpoint_verified"])

    def test_historical_signer_inventory_rejects_missing_checkpoint(self) -> None:
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "requires complete floor checkpoint"):
                self._audit(historical_evidence_signer_keys_hex=(self.signer_hex,))

    def test_historical_signer_inventory_rejects_bad_or_duplicate_keys(self) -> None:
        inputs = self._signed_floor_checkpoint()
        for keys, message in (
            (("bad",), "Historical evidence signer key"),
            ((self.signer_hex, self.signer_hex), "Duplicate historical"),
            ((self.signer_hex,) * 257, "at most 256"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self._audit(historical_evidence_signer_keys_hex=keys, **inputs)

    def test_checkpoint_rejects_historical_policy_authority_after_rotation(self) -> None:
        # The current policy uses self.authority_key; a previously trusted
        # authority is absent from that policy and cannot be inferred from it.
        old_authority = Ed25519PrivateKey.generate()
        pins = self._signed_floor_checkpoint(key=old_authority)
        old_hex = pins["checkpoint_authority_public_key_hex"]
        with self.assertRaisesRegex(ValueError, "historical policy authorities"):
            self._audit(
                require_floor_checkpoint=True,
                historical_policy_authority_keys_hex=(old_hex,),
                **pins,
            )
        # An unrelated historical authority does not block a valid checkpoint.
        result = self._audit(
            require_floor_checkpoint=True,
            historical_policy_authority_keys_hex=(self.authority_hex,),
            **pins,
        )
        self.assertTrue(result["floor_checkpoint_verified"])

    def test_historical_policy_authority_inventory_requires_checkpoint(self) -> None:
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "Historical policy authority inventory requires complete"):
                self._audit(historical_policy_authority_keys_hex=(self.authority_hex,))

    def test_historical_policy_authority_inventory_rejects_bad_duplicate_and_oversized(self) -> None:
        pins = self._signed_floor_checkpoint()
        for keys, message in (
            (("bad",), "Historical policy authority key"),
            ((self.authority_hex, self.authority_hex), "Duplicate historical policy authority"),
            ((self.authority_hex,) * 257, "at most 256"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self._audit(historical_policy_authority_keys_hex=keys, **pins)

    def test_revoked_checkpoint_authority_rejects_valid_signed_checkpoint(self) -> None:
        revoked_key = Ed25519PrivateKey.generate()
        pins = self._signed_floor_checkpoint(key=revoked_key)
        revoked_hex = pins["checkpoint_authority_public_key_hex"]
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "independently listed as revoked"):
                self._audit(
                    require_floor_checkpoint=True,
                    revoked_checkpoint_authority_keys_hex=(revoked_hex,),
                    **pins,
                )
        # An independently revoked *other* authority must not invalidate
        # a checkpoint signed by a distinct, currently permitted key.
        result = self._audit(
            require_floor_checkpoint=True,
            revoked_checkpoint_authority_keys_hex=(self.authority_hex,),
            **pins,
        )
        self.assertTrue(result["floor_checkpoint_verified"])

    def test_revoked_checkpoint_inventory_requires_complete_checkpoint(self) -> None:
        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=AssertionError("unexpected anchor read"),
        ):
            with self.assertRaisesRegex(ValueError, "Revoked checkpoint authority inventory requires complete"):
                self._audit(revoked_checkpoint_authority_keys_hex=(self.authority_hex,))

    def test_revoked_checkpoint_inventory_rejects_malformed_duplicate_and_oversized(self) -> None:
        pins = self._signed_floor_checkpoint()
        for keys, message in (
            (("bad",), "Revoked checkpoint authority key"),
            ((self.authority_hex, self.authority_hex), "Duplicate revoked checkpoint authority"),
            ((self.authority_hex,) * 257, "at most 256"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self._audit(revoked_checkpoint_authority_keys_hex=keys, **pins)

    def test_signed_checkpoint_rejects_reused_evidence_signer_key(self) -> None:
        # An independently signed floor record must not share a private key
        # with an evidence signer, even when the evidence signer is revoked.
        for status in ("trusted", "revoked"):
            with self.subTest(status=status):
                policy = {
                    "format": "codetwin-signer-trust-v1",
                    "revision": 8,
                    "signers": [{"public_key_hex": self.signer_hex, "status": status}],
                }
                self.envelope["policy"] = policy
                self.envelope["signature_hex"] = self.authority_key.sign(
                    DOMAIN + json.dumps(
                        policy, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8")
                ).hex()
                self.policy.write_text(json.dumps(self.envelope), encoding="utf-8")
                self.digest = self._digest(self.envelope)
                self._write_anchor({
                    **self.original, "signed_policy_sha256_hex": self.digest,
                })
                pins = self._signed_floor_checkpoint(key=self.signer_key)
                with self.assertRaisesRegex(
                    ValueError, "Checkpoint authority must differ from every evidence signer",
                ):
                    self._audit(**pins)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_signed_checkpoint_rejects_stale_floor_and_partial_inputs(self) -> None:
        inputs = self._signed_floor_checkpoint(floor=7)
        with self.assertRaisesRegex(ValueError, "floor or policy digest"):
            self._audit(**inputs)
        with self.assertRaisesRegex(ValueError, "All three"):
            self._audit(floor_checkpoint_file=inputs["floor_checkpoint_file"])

    def test_signed_checkpoint_rejects_symlink_and_late_inode_swap(self) -> None:
        inputs = self._signed_floor_checkpoint()
        checkpoint = Path(inputs["floor_checkpoint_file"])
        original = self.root / "original-checkpoint.json"
        checkpoint.rename(original)
        checkpoint.symlink_to(original)
        with self.assertRaises(ValueError):
            self._audit(**inputs)
        checkpoint.unlink()
        original.rename(checkpoint)

        from scripts.audit_signer_trust_anchor import _validated_policy

        def replace_after_policy_validation(
            envelope: dict[str, object], authority: bytes,
        ) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            checkpoint.rename(original)
            checkpoint.write_bytes(original.read_bytes())
            checkpoint.chmod(0o600)
            return result

        with patch(
            "scripts.audit_signer_trust_anchor._validated_policy",
            side_effect=replace_after_policy_validation,
        ):
            # A shared parent ctime can reject the swap before the final checkpoint check.
            with self.assertRaisesRegex(ValueError, "changed during audit"):
                self._audit(**inputs)

    def test_checkpoint_replacement_after_verification_read_fails_closed(self) -> None:
        from scripts.audit_signer_trust_anchor import (
            _read_signed_policy_bytes, _verify_floor_checkpoint,
        )

        inputs = self._signed_floor_checkpoint()
        checkpoint = Path(inputs["floor_checkpoint_file"])
        displaced = self.root / "displaced-checkpoint.json"
        checkpoint_reads = 0

        def swap_after_read(path: Path) -> bytes:
            nonlocal checkpoint_reads
            raw = _read_signed_policy_bytes(path)
            if Path(path) == checkpoint:
                checkpoint_reads += 1
                if checkpoint_reads == 2:
                    checkpoint.rename(displaced)
                    checkpoint.write_bytes(raw)
                    checkpoint.chmod(0o600)
            return raw

        with patch(
            "scripts.audit_signer_trust_anchor._read_signed_policy_bytes",
            side_effect=swap_after_read,
        ):
            with self.assertRaisesRegex(ValueError, "changed during verification"):
                _verify_floor_checkpoint(
                    checkpoint,
                    checkpoint_authority_hex=inputs["checkpoint_authority_public_key_hex"],
                    checkpoint_sha256=inputs["checkpoint_sha256"],
                    policy_authority=bytes.fromhex(self.authority_hex),
                    independent_floor=8,
                    signed_policy_digest=bytes.fromhex(self.digest),
                )
        self.assertEqual(checkpoint_reads, 2)

    def test_checkpoint_replacement_after_final_audit_read_fails_closed(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_signed_policy_bytes

        inputs = self._signed_floor_checkpoint()
        checkpoint = Path(inputs["floor_checkpoint_file"])
        displaced = self.root / "displaced-checkpoint.json"
        checkpoint_reads = 0

        def swap_after_read(path: Path) -> bytes:
            nonlocal checkpoint_reads
            raw = _read_signed_policy_bytes(path)
            if Path(path) == checkpoint:
                checkpoint_reads += 1
                if checkpoint_reads == 3:
                    checkpoint.rename(displaced)
                    checkpoint.write_bytes(raw)
                    checkpoint.chmod(0o600)
            return raw

        with patch(
            "scripts.audit_signer_trust_anchor._read_signed_policy_bytes",
            side_effect=swap_after_read,
        ):
            with self.assertRaisesRegex(ValueError, "changed during audit"):
                self._audit(require_floor_checkpoint=True, **inputs)
        self.assertEqual(checkpoint_reads, 3)

    def test_valid_audit_is_read_only_and_does_not_create_lock(self) -> None:
        before = self.anchor.read_bytes()
        result = self._audit()
        self.assertEqual(result["status"], "verified_against_supplied_pins")
        self.assertEqual(result["minimum_revision"], 8)
        self.assertEqual(result["independent_revision_floor"], 8)
        self.assertEqual(self.anchor.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.anchor.stat().st_mode), 0o600)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_refuses_anchor_inside_source_checkout_without_writes(self) -> None:
        with patch(
            "scripts.publish_signer_trust_anchor._checkout_root",
            return_value=self.root,
        ):
            with self.assertRaisesRegex(ValueError, "outside the CodeTwin source checkout"):
                self._audit()
        self.assertEqual(json.loads(self.anchor.read_text(encoding="utf-8")), self.original)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_independent_revision_floor_detects_rolled_back_anchor(self) -> None:
        self._write_anchor({**self.original, "minimum_revision": 7})
        with self.assertRaisesRegex(ValueError, "independently trusted"):
            self._audit()

    def test_rejects_stale_but_consistent_anchor_and_policy_below_external_floor(self) -> None:
        # The anchor, policy, signature and exact pins all agree at revision 8.
        # A separately protected floor of 9 must reject this valid old state.
        with self.assertRaisesRegex(ValueError, "below independent revision floor"):
            self._audit(independent_revision_floor=9)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_accepts_revision_above_external_floor(self) -> None:
        result = self._audit(independent_revision_floor=7)
        self.assertEqual(result["independent_revision_floor"], 7)
        self.assertEqual(result["minimum_revision"], 8)

    def test_rejects_wrong_independent_revision_digest_and_authority(self) -> None:
        for overrides in (
            {"expected_revision": 9},
            {"expected_sha256": "ab" * 32},
            {"authority_public_key_hex": "cd" * 32},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(ValueError, "independently trusted"):
                    self._audit(**overrides)

    def test_rejects_policy_tampering_even_with_recomputed_digest(self) -> None:
        forged = json.loads(self.policy.read_text())
        forged["policy"]["signers"][0]["status"] = "revoked"
        self.policy.write_text(json.dumps(forged), encoding="utf-8")
        forged_digest = self._digest(forged)
        self._write_anchor({**self.original, "signed_policy_sha256_hex": forged_digest})
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self._audit(expected_sha256=forged_digest)

    def test_rejects_missing_or_malformed_external_pins(self) -> None:
        for overrides in (
            {"expected_sha256": ""},
            {"expected_sha256": "not-a-hash"},
            {"authority_public_key_hex": "bad"},
            {"expected_revision": 0},
            {"expected_revision": True},
            {"independent_revision_floor": 0},
            {"independent_revision_floor": True},
            {"independent_revision_floor": -1},
            {"independent_revision_floor": 2**64},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    self._audit(**overrides)

    def test_rejects_symlink_anchor_and_nonprivate_directory(self) -> None:
        real = self.root / "real.json"
        self.anchor.rename(real)
        self.anchor.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "private regular file"):
            self._audit()
        self.anchor.unlink()
        real.rename(self.anchor)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self._audit()

    def test_rejects_policy_symlink(self) -> None:
        real = self.root / "real-policy.json"
        self.policy.rename(real)
        self.policy.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self._audit()

    def test_detects_anchor_changed_during_signature_verification(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def mutate(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            self._write_anchor({**self.original, "minimum_revision": 9})
            return result

        with patch("scripts.audit_signer_trust_anchor._validated_policy", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "changed during audit"):
                self._audit()


    def test_rejects_policy_replacement_during_final_anchor_read(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_anchor_with_metadata

        calls = 0

        def swap_after_anchor_read(path: Path) -> tuple[dict[str, object], tuple[int, ...]]:
            nonlocal calls
            result = _read_anchor_with_metadata(path)
            calls += 1
            if calls == 3:
                previous = self.root / "previous-policy.json"
                self.policy.rename(previous)
                self.policy.write_bytes(previous.read_bytes())
                self.assertNotEqual(self.policy.stat().st_ino, previous.stat().st_ino)
            return result

        with patch(
            "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
            side_effect=swap_after_anchor_read,
        ):
            with self.assertRaisesRegex(ValueError, "Signed policy changed during audit"):
                self._audit()
        self.assertEqual(calls, 3)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_rejects_identical_anchor_inode_replacement_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def replace(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            previous = self.root / "previous-anchor.json"
            self.anchor.rename(previous)
            self._write_anchor(self.original)
            self.assertNotEqual(self.anchor.stat().st_ino, previous.stat().st_ino)
            return result

        with patch("scripts.audit_signer_trust_anchor._validated_policy", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "External anchor changed during audit"):
                self._audit()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_rejects_anchor_metadata_mutation_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def touch(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            metadata = self.anchor.stat()
            os.utime(
                self.anchor,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
            )
            return result

        with patch("scripts.audit_signer_trust_anchor._validated_policy", side_effect=touch):
            with self.assertRaisesRegex(ValueError, "External anchor changed during audit"):
                self._audit()

    def test_rejects_anchor_ancestor_identity_change_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        outer = self.root / "changing-anchor-ancestor"
        inner = outer / "private"
        inner.mkdir(parents=True, mode=0o700)
        original = self.anchor
        moved = inner / original.name
        original.rename(moved)
        self.anchor = moved
        original_lstat = Path.lstat
        changed = False

        def switch_after_signature(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            nonlocal changed
            result = _validated_policy(envelope, authority)
            changed = True
            return result

        def substituted_ancestor(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            metadata = original_lstat(path, *args, **kwargs)
            if path == outer and changed:
                fields = list(metadata)
                fields[1] += 1
                return os.stat_result(fields)
            return metadata

        try:
            with patch.object(Path, "lstat", new=substituted_ancestor), patch(
                "scripts.audit_signer_trust_anchor._validated_policy",
                side_effect=switch_after_signature,
            ):
                with self.assertRaisesRegex(ValueError, "External anchor directory changed"):
                    self._audit()
            self.assertFalse((inner / "anchor.json.lock").exists())
        finally:
            moved.rename(original)
            self.anchor = original
            inner.rmdir()
            outer.rmdir()

    def test_rejects_policy_ancestor_identity_change_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        outer = self.root / "audit-ancestor-identity"
        inner = outer / "private"
        inner.mkdir(parents=True, mode=0o700)
        moved = inner / self.policy.name
        self.policy.rename(moved)
        original_policy = self.policy
        self.policy = moved
        original_lstat = Path.lstat
        changed = False

        def switch_after_signature(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            nonlocal changed
            result = _validated_policy(envelope, authority)
            changed = True
            return result

        def substituted_ancestor(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            metadata = original_lstat(path, *args, **kwargs)
            if path == outer and changed:
                fields = list(metadata)
                fields[1] += 1
                return os.stat_result(fields)
            return metadata

        try:
            with patch.object(Path, "lstat", new=substituted_ancestor), patch(
                "scripts.audit_signer_trust_anchor._validated_policy",
                side_effect=switch_after_signature,
            ):
                with self.assertRaisesRegex(ValueError, "Signed policy changed during audit"):
                    self._audit()
            self.assertFalse((self.root / "anchor.json.lock").exists())
        finally:
            moved.rename(original_policy)
            self.policy = original_policy
            inner.rmdir()
            outer.rmdir()

    def test_detects_policy_changed_during_signature_verification(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def mutate(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            replacement = json.loads(self.policy.read_text(encoding="utf-8"))
            replacement["policy"]["signers"][0]["status"] = "revoked"
            self.policy.write_text(json.dumps(replacement), encoding="utf-8")
            return result

        with patch("scripts.audit_signer_trust_anchor._validated_policy", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "Signed policy changed during audit"):
                self._audit()

    def test_rejects_identical_policy_inode_replacement_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def replace(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            previous = self.root / "previous-policy.json"
            self.policy.rename(previous)
            self.policy.write_bytes(previous.read_bytes())
            self.assertNotEqual(self.policy.stat().st_ino, previous.stat().st_ino)
            return result

        with patch("scripts.audit_signer_trust_anchor._validated_policy", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "Signed policy changed during audit"):
                self._audit()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_rejects_policy_metadata_mutation_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def touch(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            metadata = self.policy.stat()
            os.utime(
                self.policy,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
            )
            return result

        with patch("scripts.audit_signer_trust_anchor._validated_policy", side_effect=touch):
            with self.assertRaisesRegex(ValueError, "Signed policy changed during audit"):
                self._audit()

    def test_detects_equivalent_policy_rewrite_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def rewrite(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            # Whitespace changes without altering the authenticated typed envelope.
            self.policy.write_text(
                json.dumps(json.loads(self.policy.read_text(encoding="utf-8")), indent=2),
                encoding="utf-8",
            )
            return result

        with patch("scripts.audit_signer_trust_anchor._validated_policy", side_effect=rewrite):
            with self.assertRaisesRegex(ValueError, "Signed policy changed during audit"):
                self._audit()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_rejects_policy_symlink_swap_during_audit(self) -> None:
        from scripts.audit_signer_trust_anchor import _validated_policy

        def replace_with_symlink(
            envelope: dict[str, object], authority: bytes
        ) -> tuple[int, bytes]:
            result = _validated_policy(envelope, authority)
            original = self.root / "original-policy.json"
            self.policy.rename(original)
            self.policy.symlink_to(original)
            return result

        with patch(
            "scripts.audit_signer_trust_anchor._validated_policy",
            side_effect=replace_with_symlink,
        ):
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                self._audit()


    def test_rejects_anchor_directory_permission_change_after_final_policy_read(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_signed_policy_bytes

        # Keep the policy in a separate directory: its parent check must not
        # incidentally detect a change to the independent anchor directory.
        with tempfile.TemporaryDirectory() as policy_directory:
            external_policy = Path(policy_directory) / "signed-policy.json"
            external_policy.write_bytes(self.policy.read_bytes())
            reads = 0

            def relax_after_read(path: Path) -> bytes:
                nonlocal reads
                raw = _read_signed_policy_bytes(path)
                reads += 1
                if reads == 2:
                    self.root.chmod(0o755)
                return raw

            try:
                with patch(
                    "scripts.audit_signer_trust_anchor._read_signed_policy_bytes",
                    side_effect=relax_after_read,
                ):
                    with self.assertRaisesRegex(ValueError, "private"):
                        audit_anchor(
                            self.anchor, external_policy,
                            authority_public_key_hex=self.authority_hex,
                            expected_revision=8, independent_revision_floor=8,
                            expected_sha256=self.digest,
                        )
                self.assertEqual(reads, 2)
            finally:
                self.root.chmod(0o700)

    def test_rejects_anchor_directory_replacement_after_final_policy_read(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_signed_policy_bytes

        with tempfile.TemporaryDirectory() as policy_directory:
            external_policy = Path(policy_directory) / "signed-policy.json"
            external_policy.write_bytes(self.policy.read_bytes())
            displaced = self.root.with_name(self.root.name + "-previous")
            reads = 0

            def replace_after_read(path: Path) -> bytes:
                nonlocal reads
                raw = _read_signed_policy_bytes(path)
                reads += 1
                if reads == 2:
                    self.root.rename(displaced)
                    self.root.mkdir(mode=0o700)
                    # Even a byte-identical anchor in a new directory must not
                    # pass an audit that started in a different directory.
                    self.anchor.write_bytes((displaced / "anchor.json").read_bytes())
                    self.anchor.chmod(0o600)
                return raw

            try:
                with patch(
                    "scripts.audit_signer_trust_anchor._read_signed_policy_bytes",
                    side_effect=replace_after_read,
                ):
                    with self.assertRaisesRegex(ValueError, "directory changed"):
                        audit_anchor(
                            self.anchor, external_policy,
                            authority_public_key_hex=self.authority_hex,
                            expected_revision=8, independent_revision_floor=8,
                            expected_sha256=self.digest,
                        )
                self.assertEqual(reads, 2)
            finally:
                if displaced.exists():
                    if self.root.exists():
                        shutil.rmtree(self.root)
                    displaced.rename(self.root)


    def test_rejects_anchor_value_change_after_final_policy_read(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_signed_policy_bytes

        # The signed policy lives elsewhere, so its parent metadata remains
        # unchanged when the anchor file is modified.
        with tempfile.TemporaryDirectory() as policy_directory:
            external_policy = Path(policy_directory) / "signed-policy.json"
            external_policy.write_bytes(self.policy.read_bytes())
            reads = 0

            def change_after_read(path: Path) -> bytes:
                nonlocal reads
                raw = _read_signed_policy_bytes(path)
                reads += 1
                if reads == 2:
                    self._write_anchor({**self.original, "minimum_revision": 9})
                return raw

            with patch(
                "scripts.audit_signer_trust_anchor._read_signed_policy_bytes",
                side_effect=change_after_read,
            ):
                with self.assertRaisesRegex(ValueError, "External anchor changed during audit"):
                    audit_anchor(
                        self.anchor, external_policy,
                        authority_public_key_hex=self.authority_hex,
                        expected_revision=8, independent_revision_floor=8,
                        expected_sha256=self.digest,
                    )
            self.assertEqual(reads, 2)

    def test_rejects_identical_anchor_inode_swap_after_final_policy_read(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_signed_policy_bytes

        with tempfile.TemporaryDirectory() as policy_directory:
            external_policy = Path(policy_directory) / "signed-policy.json"
            external_policy.write_bytes(self.policy.read_bytes())
            displaced = self.root / "previous-anchor.json"
            reads = 0

            def replace_after_read(path: Path) -> bytes:
                nonlocal reads
                raw = _read_signed_policy_bytes(path)
                reads += 1
                if reads == 2:
                    self.anchor.rename(displaced)
                    self.anchor.write_bytes(displaced.read_bytes())
                    self.anchor.chmod(0o600)
                    self.assertNotEqual(self.anchor.stat().st_ino, displaced.stat().st_ino)
                return raw

            with patch(
                "scripts.audit_signer_trust_anchor._read_signed_policy_bytes",
                side_effect=replace_after_read,
            ):
                with self.assertRaisesRegex(ValueError, "External anchor changed during audit"):
                    audit_anchor(
                        self.anchor, external_policy,
                        authority_public_key_hex=self.authority_hex,
                        expected_revision=8, independent_revision_floor=8,
                        expected_sha256=self.digest,
                    )
            self.assertEqual(reads, 2)


    def test_rejects_directory_permission_change_during_final_anchor_read(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_anchor_with_metadata

        reads = 0

        def relax_after_read(path: Path) -> tuple[dict[str, object], tuple[int, ...]]:
            nonlocal reads
            result = _read_anchor_with_metadata(path)
            reads += 1
            if reads == 3:
                self.root.chmod(0o755)
            return result

        try:
            with patch(
                "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
                side_effect=relax_after_read,
            ):
                with self.assertRaisesRegex(ValueError, "private"):
                    self._audit()
            self.assertEqual(reads, 3)
        finally:
            self.root.chmod(0o700)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_rejects_directory_replacement_during_final_anchor_read(self) -> None:
        from scripts.audit_signer_trust_anchor import _read_anchor_with_metadata

        displaced = self.root.with_name(self.root.name + "-late-previous")
        reads = 0

        def replace_after_read(path: Path) -> tuple[dict[str, object], tuple[int, ...]]:
            nonlocal reads
            result = _read_anchor_with_metadata(path)
            reads += 1
            if reads == 3:
                self.root.rename(displaced)
                self.root.mkdir(mode=0o700)
                self.anchor.write_bytes((displaced / "anchor.json").read_bytes())
                self.anchor.chmod(0o600)
            return result

        try:
            with patch(
                "scripts.audit_signer_trust_anchor._read_anchor_with_metadata",
                side_effect=replace_after_read,
            ):
                with self.assertRaisesRegex(ValueError, "directory changed"):
                    self._audit()
            self.assertEqual(reads, 3)
        finally:
            if displaced.exists():
                if self.root.exists():
                    shutil.rmtree(self.root)
                displaced.rename(self.root)
        self.assertFalse((self.root / "anchor.json.lock").exists())


    def test_rejects_anchor_swap_during_final_checkpoint_recheck(self) -> None:
        from scripts.audit_signer_trust_anchor import _checkpoint_unchanged

        pins = self._signed_floor_checkpoint()
        displaced = self.root / "anchor-before-final-checkpoint.json"
        checks = 0

        def swap_after_final_check(*args: object) -> bool:
            nonlocal checks
            result = _checkpoint_unchanged(*args)
            checks += 1
            if checks == 2:
                self.anchor.rename(displaced)
                self.anchor.write_bytes(displaced.read_bytes())
                self.anchor.chmod(0o600)
                self.assertNotEqual(self.anchor.stat().st_ino, displaced.stat().st_ino)
            return result

        with patch(
            "scripts.audit_signer_trust_anchor._checkpoint_unchanged",
            side_effect=swap_after_final_check,
        ):
            with self.assertRaisesRegex(ValueError, "External anchor changed during audit"):
                self._audit(**pins)
        self.assertEqual(checks, 2)

    def test_rejects_policy_swap_during_final_checkpoint_recheck(self) -> None:
        from scripts.audit_signer_trust_anchor import _checkpoint_unchanged

        pins = self._signed_floor_checkpoint()
        displaced = self.root / "policy-before-final-checkpoint.json"
        checks = 0

        def swap_after_final_check(*args: object) -> bool:
            nonlocal checks
            result = _checkpoint_unchanged(*args)
            checks += 1
            if checks == 2:
                self.policy.rename(displaced)
                self.policy.write_bytes(displaced.read_bytes())
                self.assertNotEqual(self.policy.stat().st_ino, displaced.stat().st_ino)
            return result

        with patch(
            "scripts.audit_signer_trust_anchor._checkpoint_unchanged",
            side_effect=swap_after_final_check,
        ):
            with self.assertRaisesRegex(ValueError, "Signed policy changed during audit"):
                self._audit(**pins)
        self.assertEqual(checks, 2)


if __name__ == "__main__":
    unittest.main()
