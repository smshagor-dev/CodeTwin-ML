import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.main import process_line  # noqa: E402


class ProtocolTests(unittest.TestCase):
    def test_health(self) -> None:
        response = process_line(json.dumps({"id": "r1", "method": "health", "params": {}}))
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["status"], "ready")

    def test_invalid_request_is_rejected(self) -> None:
        response = process_line('{"id":"","method":"health"}')
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_does_not_claim_uninstalled_models(self) -> None:
        response = process_line(json.dumps({"id": "r2", "method": "capabilities"}))
        self.assertEqual(response["result"]["inference"], [])
        self.assertEqual(response["result"]["training"], [])


if __name__ == "__main__":
    unittest.main()
