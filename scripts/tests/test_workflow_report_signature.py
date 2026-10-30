"""Independent (Python `cryptography`) verification of signed workflow reports."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.workflow_report_signature import load_bundle, sign, verify

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "crates/codetwin-core/tests/fixtures/workflow_report_bundle_python_signed.json"
)


class WorkflowReportSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        # Report bytes produced by the Rust `signed_workflow_reports` module.
        self.bundle = load_bundle(FIXTURE.read_text(encoding="utf-8"))
        self.key = self.bundle["signatures"][0]["public_key_hex"]

    def test_rust_produced_report_verifies_with_pinned_key(self) -> None:
        result = verify(self.bundle, [self.key.upper()])
        self.assertEqual(result["verdict"], "verified", result["problems"])
        self.assertIn("not that the findings are true", result["note"])

    def test_key_inside_bundle_is_not_trusted_by_itself(self) -> None:
        self.assertEqual(verify(self.bundle, [])["verdict"], "untrusted_signer")

    def test_modified_report_is_tampered(self) -> None:
        altered = copy.deepcopy(self.bundle)
        altered["report_json"] = altered["report_json"].replace("medium", "low")
        self.assertEqual(verify(altered, [self.key])["verdict"], "tampered")

    def test_rehashed_modification_breaks_signature(self) -> None:
        altered = copy.deepcopy(self.bundle)
        altered["report_json"] = altered["report_json"].replace("medium", "low")
        altered["report_sha256"] = hashlib.sha256(altered["report_json"].encode()).hexdigest()
        self.assertEqual(verify(altered, [self.key])["verdict"], "invalid_signature")

    def test_wrong_key_signature_is_invalid(self) -> None:
        forged = copy.deepcopy(self.bundle)
        other = sign(forged, Ed25519PrivateKey.generate())
        forged["signatures"][0]["signature_hex"] = other["signature_hex"]
        self.assertEqual(verify(forged, [self.key])["verdict"], "invalid_signature")

    def test_new_signer_round_trip(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        key = Ed25519PrivateKey.generate()
        signature = sign(bundle, key)
        bundle["signatures"] = [dict(signature, signer_label=None)]
        result = verify(bundle, [signature["public_key_hex"]])
        self.assertEqual(result["verdict"], "verified")

    def test_corrupted_and_ambiguous_bundles_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            load_bundle('{"format": "x"}')
        text = FIXTURE.read_text(encoding="utf-8")
        duplicated = text.replace('"format":', '"format": "x", "format":', 1)
        with self.assertRaises(ValueError):
            load_bundle(duplicated)
        corrupted = copy.deepcopy(self.bundle)
        corrupted["report_json"] = "{not json"
        corrupted["report_sha256"] = hashlib.sha256(b"{not json").hexdigest()
        self.assertEqual(verify(corrupted, [self.key])["verdict"], "tampered")
        with self.assertRaises(ValueError):
            sign(corrupted, Ed25519PrivateKey.generate())


if __name__ == "__main__":
    unittest.main()
