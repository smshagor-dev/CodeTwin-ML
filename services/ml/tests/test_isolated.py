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
    CLASSIFICATION_WORKER_TIMEOUT_SECONDS,
    GENERATION_WORKER_TIMEOUT_SECONDS,
    MAX_WORKER_RESPONSE_BYTES,
    run_isolated_generation,
    run_isolated_inference,
)


class IsolatedInferenceTests(unittest.TestCase):
    def _run_with_bytes(self, response: bytes, returncode: int = 0):
        def fake_run(command, **kwargs):
            output = kwargs["stdout"]
            output.write(response)
            output.flush()
            return subprocess.CompletedProcess(args=command, returncode=returncode)
        return fake_run

    def _run_with_result(self, result: dict):
        response = json.dumps({"protocol": 1, "ok": True, "result": result}).encode("utf-8")
        return self._run_with_bytes(response)

    def test_runs_trusted_classifier_worker_and_parses_result(self) -> None:
        result = {
            "action": "security_analysis",
            "prediction": {"label": "review", "confidence": 0.8},
        }
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=self._run_with_result(result),
        ) as run:
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
        self.assertEqual(kwargs["timeout"], CLASSIFICATION_WORKER_TIMEOUT_SECONDS)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertIsNot(kwargs["stdout"], subprocess.PIPE)
        request = json.loads(kwargs["input"].decode("utf-8"))
        self.assertEqual(request["protocol"], 1)
        self.assertEqual(request["mode"], "classification")
        self.assertEqual(request["action"], "security_analysis")
        self.assertEqual(request["text"], "eval(x)")
        self.assertEqual(request["model_id"], "model-a")
        self.assertEqual(request["model_version"], "1.0.0")

    def test_runs_generation_worker_with_separate_timeout(self) -> None:
        result = {
            "action": "repair_generation",
            "generation": {"text": "candidate patch"},
        }
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=self._run_with_result(result),
        ) as run:
            actual = run_isolated_generation(
                "repair_generation",
                "review this file",
                model_id="coder-a",
                model_version="1.0.0",
            )

        self.assertEqual(actual, result)
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], GENERATION_WORKER_TIMEOUT_SECONDS)
        request = json.loads(kwargs["input"].decode("utf-8"))
        self.assertEqual(request["mode"], "generation")
        self.assertEqual(request["action"], "repair_generation")
        self.assertEqual(request["text"], "review this file")

    def test_worker_environment_excludes_unrelated_secrets(self) -> None:
        result = {
            "action": "security_analysis",
            "prediction": {"label": "review", "confidence": 0.8},
        }
        model_cache = str(ROOT / "model-cache")
        with patch.dict(
            "codetwin_ml.isolated.os.environ",
            {
                "GITHUB_TOKEN": "github-secret",
                "AWS_SECRET_ACCESS_KEY": "aws-secret",
                "DATABASE_URL": "postgres://secret",
                "CODETWIN_MODEL_CACHE": model_cache,
                "TEMP": str(ROOT / "tmp"),
            },
            clear=True,
        ), patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=self._run_with_result(result),
        ) as run:
            run_isolated_inference("security_analysis", "x")

        environment = run.call_args.kwargs["env"]
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertNotIn("DATABASE_URL", environment)
        self.assertEqual(environment["CODETWIN_MODEL_CACHE"], model_cache)
        self.assertEqual(environment["PYTHONPATH"], str(ROOT))
        self.assertEqual(environment["OMP_NUM_THREADS"], "1")
        self.assertEqual(environment["OPENBLAS_NUM_THREADS"], "1")
        self.assertEqual(environment["MKL_NUM_THREADS"], "1")
        self.assertEqual(environment["NUMEXPR_NUM_THREADS"], "1")

    def test_classifier_timeout_is_reported_as_runtime_error(self) -> None:
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd="worker",
                timeout=CLASSIFICATION_WORKER_TIMEOUT_SECONDS,
            ),
        ):
            with self.assertRaisesRegex(InferenceRuntimeError, "exceeded"):
                run_isolated_inference("security_analysis", "x")

    def test_generation_timeout_is_reported_as_runtime_error(self) -> None:
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd="worker",
                timeout=GENERATION_WORKER_TIMEOUT_SECONDS,
            ),
        ):
            with self.assertRaisesRegex(InferenceRuntimeError, "exceeded"):
                run_isolated_generation("repair_generation", "x")

    def test_nonzero_worker_exit_is_rejected(self) -> None:
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=self._run_with_bytes(b"", returncode=7),
        ):
            with self.assertRaisesRegex(InferenceRuntimeError, "status 7"):
                run_isolated_inference("security_analysis", "x")

    def test_malformed_worker_json_is_rejected(self) -> None:
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=self._run_with_bytes(b"not-json"),
        ):
            with self.assertRaisesRegex(InferenceRuntimeError, "invalid JSON"):
                run_isolated_inference("security_analysis", "x")

    def test_oversized_worker_response_is_rejected_before_json_parse(self) -> None:
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=self._run_with_bytes(b"x" * (MAX_WORKER_RESPONSE_BYTES + 1)),
        ):
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
        with patch(
            "codetwin_ml.isolated.subprocess.run",
            side_effect=self._run_with_bytes(response),
        ):
            with self.assertRaisesRegex(InferenceRuntimeError, "model unavailable"):
                run_isolated_inference("security_analysis", "x")


if __name__ == "__main__":
    unittest.main()
