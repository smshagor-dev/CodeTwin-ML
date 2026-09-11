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
        self.assertTrue(response["result"]["models"]["registry"])
        self.assertTrue(response["result"]["models"]["execution_implemented"])
        self.assertEqual(response["result"]["models"]["execution_ready"], 0)
        self.assertTrue(response["result"]["datasets"]["downloadable"])
        self.assertIn("repair_verification", response["result"]["datasets"]["actions"])

    def test_routes_repair_verification_to_swe_bench_verified(self) -> None:
        response = process_line(
            json.dumps(
                {
                    "id": "r3",
                    "method": "datasets.route",
                    "params": {"action": "repair_verification"},
                }
            )
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["datasets"][0]["id"], "swe_bench_verified")

    def test_unknown_dataset_action_returns_structured_error(self) -> None:
        response = process_line(
            json.dumps(
                {
                    "id": "r4",
                    "method": "datasets.route",
                    "params": {"action": "not_real"},
                }
            )
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "dataset_error")

    def test_prefetch_requires_exactly_one_target(self) -> None:
        response = process_line(
            json.dumps({"id": "r5", "method": "datasets.prefetch", "params": {}})
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_model_inventory_is_empty_on_clean_checkout(self) -> None:
        response = process_line(json.dumps({"id": "r6", "method": "models.list", "params": {}}))
        self.assertTrue(response["ok"])
        self.assertTrue(response["result"]["execution_implemented"])
        self.assertEqual(response["result"]["models"], [])

    def test_inference_plan_reports_missing_model_without_fabricating_prediction(self) -> None:
        response = process_line(
            json.dumps(
                {
                    "id": "r7",
                    "method": "inference.plan",
                    "params": {"action": "defect_detection"},
                }
            )
        )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["status"], "model_unavailable")
        self.assertTrue(response["result"]["execution_implemented"])
        self.assertEqual(response["result"]["models"], [])

    def test_unknown_model_action_returns_structured_error(self) -> None:
        response = process_line(
            json.dumps(
                {
                    "id": "r8",
                    "method": "models.route",
                    "params": {"action": "not_real"},
                }
            )
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "model_error")

    def test_inference_run_without_model_returns_structured_error(self) -> None:
        response = process_line(
            json.dumps(
                {
                    "id": "r9",
                    "method": "inference.run",
                    "params": {"action": "security_analysis", "text": "eval(x)"},
                }
            )
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "inference_error")

    def test_inference_run_requires_text_string(self) -> None:
        response = process_line(
            json.dumps(
                {
                    "id": "r10",
                    "method": "inference.run",
                    "params": {"action": "security_analysis", "text": 7},
                }
            )
        )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
