"""Regression coverage for independently pinned Ed25519 policy publication."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.publish_signer_trust_anchor import FORMAT, publish_verified
from scripts.verify_signer_policy_rotation import DOMAIN, verify_rotation_files


@unittest.skipUnless(os.name == "posix", "External anchor publisher is POSIX-only")
class VerifiedRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.root.chmod(0o700)
        self.authority = Ed25519PrivateKey.generate()
        self.signer = Ed25519PrivateKey.generate()
        self.authority_hex = self._public_hex(self.authority)
        self.signer_hex = self._public_hex(self.signer)
        self.previous = self.root / "previous.json"
        self.replacement = self.root / "replacement.json"
        self.old_pin = self._write_signed(self.previous, 4)
        self.new_pin = self._write_signed(self.replacement, 5)
        self.anchor = self.root / "anchor.json"
        self.original = {
            "format": FORMAT,
            "authority_public_key_hex": self.authority_hex,
            "minimum_revision": 4,
            "signed_policy_sha256_hex": self.old_pin,
        }
        self.anchor.write_text(json.dumps(self.original), encoding="utf-8")
        self.anchor.chmod(0o600)

    @staticmethod
    def _public_hex(key: Ed25519PrivateKey) -> str:
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    @staticmethod
    def _encoded(value: dict[str, object]) -> bytes:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _write_signed(
        self,
        path: Path,
        revision: int,
        *,
        signer_hex: str | None = None,
        signer_status: str = "trusted",
    ) -> str:
        policy: dict[str, object] = {
            "format": "codetwin-signer-trust-v1",
            "revision": revision,
            "signers": [{
                "public_key_hex": signer_hex or self.signer_hex,
                "status": signer_status,
            }],
        }
        envelope: dict[str, object] = {
            "policy": policy,
            "authority_public_key_hex": self.authority_hex,
            "signature_hex": self.authority.sign(DOMAIN + self._encoded(policy)).hex(),
        }
        path.write_text(json.dumps(envelope), encoding="utf-8")
        return hashlib.sha256(self._encoded(envelope)).hexdigest()

    def _verify(self, **overrides: object) -> int:
        arguments: dict[str, object] = {
            "authority_public_key_hex": self.authority_hex,
            "expected_revision": 4,
            "expected_sha256": self.old_pin,
            "replacement_revision": 5,
            "replacement_sha256": self.new_pin,
        }
        arguments.update(overrides)
        return verify_rotation_files(self.previous, self.replacement, **arguments)

    def _publish(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "previous_policy_file": self.previous,
            "replacement_policy_file": self.replacement,
            "authority_public_key_hex": self.authority_hex,
            "expected_revision": 4,
            "expected_sha256": self.old_pin,
            "replacement_revision": 5,
            "replacement_sha256": self.new_pin,
            "approved": True,
        }
        arguments.update(overrides)
        return publish_verified(self.anchor, **arguments)

    def _unchanged(self) -> None:
        self.assertEqual(json.loads(self.anchor.read_text()), self.original)

    def test_valid_rotation_publishes_only_public_anchor_metadata(self) -> None:
        self.assertEqual(self._verify(), 5)
        result = self._publish()
        self.assertEqual(result["minimum_revision"], 5)
        self.assertEqual(result["signed_policy_sha256_hex"], self.new_pin)
        self.assertEqual(json.loads(self.anchor.read_text()), result)
        self.assertNotIn("signature_hex", result)

    def test_wrong_previous_or_replacement_pin_is_rejected(self) -> None:
        for name in ("expected_sha256", "replacement_sha256"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "independently pinned"):
                    self._publish(**{name: "aa" * 32})
                self._unchanged()

    def test_modified_policy_with_recomputed_pin_still_fails_signature(self) -> None:
        envelope = json.loads(self.replacement.read_text())
        envelope["policy"]["signers"][0]["status"] = "revoked"
        self.replacement.write_text(json.dumps(envelope))
        forged_pin = hashlib.sha256(self._encoded(envelope)).hexdigest()
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self._publish(replacement_sha256=forged_pin)
        self._unchanged()

    def test_rejects_wrong_authority_even_with_matching_envelope_pin(self) -> None:
        with self.assertRaisesRegex(ValueError, "authority"):
            self._publish(authority_public_key_hex=self.signer_hex)
        self._unchanged()

    def test_rejects_authority_reused_as_evidence_signer(self) -> None:
        pin = self._write_signed(self.replacement, 5, signer_hex=self.authority_hex)
        with self.assertRaisesRegex(ValueError, "must differ"):
            self._publish(replacement_sha256=pin)
        self._unchanged()

    def test_rejects_replay_and_revision_mismatch(self) -> None:
        pin = self._write_signed(self.replacement, 4)
        with self.assertRaisesRegex(ValueError, "strictly increase"):
            self._publish(replacement_revision=4, replacement_sha256=pin)
        self._unchanged()

    def test_accepts_revoked_evidence_signer_under_valid_authority(self) -> None:
        pin = self._write_signed(self.replacement, 5, signer_status="revoked")
        self.assertEqual(self._verify(replacement_sha256=pin), 5)

    def test_rejects_duplicate_json_fields(self) -> None:
        raw = self.replacement.read_text()
        self.replacement.write_text(raw.replace('"policy":', '"policy":null,"policy":', 1))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self._publish()
        self._unchanged()

    def test_rejects_unknown_fields(self) -> None:
        envelope = json.loads(self.replacement.read_text())
        envelope["unexpected"] = True
        self.replacement.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(ValueError, "exactly"):
            self._publish()
        self._unchanged()

    def test_rejects_symlink_and_oversized_policy_files(self) -> None:
        target = self.root / "target.json"
        self.replacement.rename(target)
        self.replacement.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self._publish()
        self.replacement.unlink()
        self.replacement.write_bytes(b"x" * (16 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "16 KiB"):
            self._publish()
        self._unchanged()

    def test_rejects_previous_policy_changed_during_verification(self) -> None:
        from scripts.verify_signer_policy_rotation import _validated_policy

        calls = 0

        def change_after_validation(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            nonlocal calls
            result = _validated_policy(envelope, authority)
            calls += 1
            if calls == 1:
                self._write_signed(self.previous, 4, signer_status="revoked")
            return result

        with patch(
            "scripts.verify_signer_policy_rotation._validated_policy",
            side_effect=change_after_validation,
        ):
            with self.assertRaisesRegex(ValueError, "Previous signed policy changed during verification"):
                self._publish()
        self._unchanged()

    def test_rejects_replacement_policy_changed_during_verification(self) -> None:
        from scripts.verify_signer_policy_rotation import _validated_policy

        calls = 0

        def change_after_validation(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            nonlocal calls
            result = _validated_policy(envelope, authority)
            calls += 1
            if calls == 2:
                self._write_signed(self.replacement, 5, signer_status="revoked")
            return result

        with patch(
            "scripts.verify_signer_policy_rotation._validated_policy",
            side_effect=change_after_validation,
        ):
            with self.assertRaisesRegex(ValueError, "Replacement signed policy changed during verification"):
                self._publish()
        self._unchanged()

    def test_rejects_equivalent_previous_policy_rewrite_during_verification(self) -> None:
        from scripts.verify_signer_policy_rotation import _validated_policy

        calls = 0

        def rewrite_after_validation(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            nonlocal calls
            result = _validated_policy(envelope, authority)
            calls += 1
            if calls == 1:
                # JSON spacing changes, but the authenticated typed-envelope digest does not.
                self.previous.write_text(
                    json.dumps(json.loads(self.previous.read_text()), indent=2),
                    encoding="utf-8",
                )
            return result

        with patch(
            "scripts.verify_signer_policy_rotation._validated_policy",
            side_effect=rewrite_after_validation,
        ):
            with self.assertRaisesRegex(ValueError, "Previous signed policy changed"):
                self._publish()
        self._unchanged()

    def test_rejects_equivalent_replacement_policy_rewrite_during_verification(self) -> None:
        from scripts.verify_signer_policy_rotation import _validated_policy

        calls = 0

        def rewrite_after_validation(envelope: dict[str, object], authority: bytes) -> tuple[int, bytes]:
            nonlocal calls
            result = _validated_policy(envelope, authority)
            calls += 1
            if calls == 2:
                self.replacement.write_text(
                    json.dumps(json.loads(self.replacement.read_text()), indent=2),
                    encoding="utf-8",
                )
            return result

        with patch(
            "scripts.verify_signer_policy_rotation._validated_policy",
            side_effect=rewrite_after_validation,
        ):
            with self.assertRaisesRegex(ValueError, "Replacement signed policy changed"):
                self._publish()
        self._unchanged()

    def test_rejects_missing_approval_before_verification(self) -> None:
        with self.assertRaisesRegex(ValueError, "approval"):
            self._publish(approved=False)
        self._unchanged()
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_rejects_stale_anchor_even_after_valid_crypto_verification(self) -> None:
        self.anchor.write_text(json.dumps({**self.original, "minimum_revision": 3}))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self._publish()


if __name__ == "__main__":
    unittest.main()
