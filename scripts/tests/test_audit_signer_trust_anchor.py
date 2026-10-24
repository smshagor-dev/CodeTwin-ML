"""Read-only external trust-anchor audit regression coverage."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.audit_signer_trust_anchor import audit_anchor
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
        self.authority_hex = authority.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        signer_hex = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
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
            "expected_sha256": self.digest,
        }
        arguments.update(overrides)
        return audit_anchor(self.anchor, self.policy, **arguments)

    def test_valid_audit_is_read_only_and_does_not_create_lock(self) -> None:
        before = self.anchor.read_bytes()
        result = self._audit()
        self.assertEqual(result["status"], "verified_against_supplied_pins")
        self.assertEqual(result["minimum_revision"], 8)
        self.assertEqual(self.anchor.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.anchor.stat().st_mode), 0o600)
        self.assertFalse((self.root / "anchor.json.lock").exists())

    def test_independent_revision_floor_detects_rolled_back_anchor(self) -> None:
        self._write_anchor({**self.original, "minimum_revision": 7})
        with self.assertRaisesRegex(ValueError, "independently trusted"):
            self._audit()

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


if __name__ == "__main__":
    unittest.main()
