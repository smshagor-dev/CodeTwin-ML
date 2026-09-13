import json
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.inference import InferenceRuntimeError  # noqa: E402
from codetwin_ml.isolated import (  # noqa: E402
    MAX_WORKER_RESPONSE_BYTES,
    WORKER_TIMEOUT_SECONDS,
    run_isolated_inference,
)


class IsolatedInferenceTests(unittest.TestCase):
    def test_runs_trusted_worker_module_and_parses_result(self) -> None:
        result = {
            "action": "security_analysis",
            "prediction": {"label": "review", "confidence": 0.8},
        }
        response = json.dumps({"protocol": 1, "ok": True, "result": result}).encode("utf-8")
        completed = subprocess.CompletedProcess(
            args=[sys.executable, "-m", "codetwin_ml.worker"],
            returncode=0,
            stdout=response,
        )

        with patch("codetwin_ml.isolated.subprocess.run", return_value=completed) as run:
            actual = run_isolated_inference(
                "security_analysis",
                "eval(x)",
                model_id="model-a",
                model_version="1.0.0",
            )

        self.assertEqual(actual, result)
        command = run.call_args.args[0]
        self.assertEqual(command, [sys.executable, "-m", "codetwin_ml.worker"])
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], WORKER_TIMEOUT_SECONDS)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stdout"], subprocess.PIPE)
        request = json.loads(kwargs["input"].decode("utf-8"))
        self.assertEqual(request["protocol"], 1)
        self.assertEqual(request["action"], "security_analysis")
        self.assertEqual(request["text"], "eval(x)")
        self.assertEqual(request["model_id"], "model-a")
        self.assertEqual(request["model_version"], "1.0.0")

    def test_timeout_is_reported_as_runtime_error(self) -> None:
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="worker", timeout=WORKER_TIMEOUT_SECONDS),
        ):
            with self.assertRaisesRegex(InferenceRuntimeError, "exceeded"):
                run_isolated_inference("security_analysis", "x")

    def test_nonzero_worker_exit_is_rejected(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[sys.executable],
            returncode=7,
            stdout=b"",
        )
        with patch("codetwin_ml.isolated.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(InferenceRuntimeError, "status 7"):
                run_isolated_inference("security_analysis", "x")

    def test_malformed_worker_json_is_rejected(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[sys.executable],
            returncode=0,
            stdout=b"not-json",
        )
        with patch("codetwin_ml.isolated.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(InferenceRuntimeError, "invalid JSON"):
                run_isolated_inference("security_analysis", "x")

    def test_oversized_worker_response_is_rejected_before_json_parse(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[sys.executable],
            returncode=0,
            stdout=b"x" * (MAX_WORKER_RESPONSE_BYTES + 1),
        )
        with patch("codetwin_ml.isolated.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(InferenceRuntimeError, "response exceeds"):
                run_isolated_inference("security_analysis", "x")

    def test_structured_worker_error_is_not_returned_as_prediction(self) -> None:
        response = json.dumps(
            {
                "protocol": 1,
                "ok": False,
                "error": {"code": "inference_error", "message": "model unavailable"},
            }
        ).encode("utf-8")
        completed = subprocess.CompletedProcess(
            args=[sys.executable],
            returncode=0,
            stdout=response,
        )
        with patch("codetwin_ml.isolated.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(InferenceRuntimeError, "model unavailable"):
                run_isolated_inference("security_analysis", "x")


if __name__ == "__main__":
    unittest.main()
