import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.datasets import load_catalog  # noqa: E402
from codetwin_ml.inference import (  # noqa: E402
    InferenceInputError,
    InferenceRuntimeError,
    plan_inference,
    run_inference,
)
from codetwin_ml.models import install_model  # noqa: E402


class _Io:
    def __init__(self, name: str, type_name: str | None = None) -> None:
        self.name = name
        self.type = type_name


class _Session:
    def __init__(self, logits: list[float]) -> None:
        self.logits = logits
        self.feeds = None

    def get_inputs(self):
        return [_Io("input_ids", "tensor(int64)")]

    def get_outputs(self):
        return [_Io("logits")]

    def run(self, output_names, feeds):
        self.feeds = feeds
        self.output_names = output_names
        return [[self.logits]]


class InferenceTests(unittest.TestCase):
    def _install(self, root: pathlib.Path, *, max_bytes: int = 16) -> pathlib.Path:
        package = root / "package"
        package.mkdir()
        artifact = package / "model.onnx"
        artifact.write_bytes(b"fake-onnx-for-unit-test")
        security = next(
            item for item in load_catalog()["datasets"] if item["id"] == "code_security_vulnerability"
        )
        manifest = {
            "schema_version": 1,
            "id": "openmindai-security-screen-v1",
            "name": "OpenMindAI Security Screen Test Model",
            "version": "1.0.0",
            "backend": "onnx-classification-v1",
            "actions": ["security_analysis"],
            "artifacts": [
                {
                    "role": "model",
                    "path": "model.onnx",
                    "size_bytes": artifact.stat().st_size,
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            ],
            "inference": {
                "preprocessing": {
                    "kind": "utf8-bytes-v1",
                    "input_name": "input_ids",
                    "max_bytes": max_bytes,
                },
                "output": {"name": "logits", "labels": ["safe", "review"]},
            },
            "evaluation": {
                "status": "passed",
                "evaluated_at": "2026-09-11T00:00:00Z",
                "datasets": [
                    {
                        "dataset_id": security["id"],
                        "revision": security["revision"],
                        "split": "test",
                        "metrics": {"f1": 0.5},
                    }
                ],
            },
            "license": {
                "name": "apache-2.0",
                "url": "https://www.apache.org/licenses/LICENSE-2.0",
                "acceptance_required": False,
            },
        }
        (package / "model.json").write_text(json.dumps(manifest), encoding="utf-8")
        model_root = root / "models"
        install_model(package, model_root=model_root)
        return model_root

    def test_runs_bounded_classifier_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install(root)
            session = _Session([0.1, 2.1])
            validated = []

            result = run_inference(
                "security_analysis",
                "eval(x)",
                model_root=model_root,
                session_factory=lambda path: session,
                array_factory=lambda values: values,
                model_validator=lambda path: validated.append(path),
            )

            self.assertEqual(result["prediction"]["label"], "review")
            self.assertGreater(result["prediction"]["confidence"], 0.5)
            self.assertEqual(result["input"]["utf8_bytes"], len("eval(x)".encode("utf-8")))
            self.assertFalse(result["input"]["truncated"])
            self.assertEqual(result["runtime"]["provider"], "CPUExecutionProvider")
            self.assertEqual(len(validated), 1)
            encoded = session.feeds["input_ids"][0]
            self.assertEqual(encoded[:4], [ord("e") + 1, ord("v") + 1, ord("a") + 1, ord("l") + 1])
            self.assertEqual(len(encoded), 16)
            self.assertEqual(session.output_names, ["logits"])

    def test_plan_reports_runtime_dependency_gap_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install(root)
            with patch("codetwin_ml.inference.importlib.util.find_spec", return_value=None):
                plan = plan_inference("security_analysis", model_root=model_root)
            self.assertEqual(plan["status"], "runtime_unavailable")
            self.assertFalse(plan["runtime_dependencies"]["available"])
            self.assertEqual(
                plan["runtime_dependencies"]["missing"],
                ["numpy", "onnx", "onnxruntime"],
            )

    def test_rejects_input_larger_than_model_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install(root, max_bytes=4)
            with self.assertRaises(InferenceInputError):
                run_inference(
                    "security_analysis",
                    "12345",
                    model_root=model_root,
                    session_factory=lambda path: _Session([0.0, 1.0]),
                    array_factory=lambda values: values,
                    model_validator=lambda path: None,
                )

    def test_rejects_logits_that_do_not_match_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install(root)
            with self.assertRaises(InferenceRuntimeError):
                run_inference(
                    "security_analysis",
                    "x",
                    model_root=model_root,
                    session_factory=lambda path: _Session([0.0, 1.0, 2.0]),
                    array_factory=lambda values: values,
                    model_validator=lambda path: None,
                )

    def test_does_not_execute_without_installed_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(InferenceInputError):
                run_inference(
                    "security_analysis",
                    "x",
                    model_root=pathlib.Path(temporary) / "models",
                    session_factory=lambda path: _Session([0.0, 1.0]),
                    array_factory=lambda values: values,
                    model_validator=lambda path: None,
                )


if __name__ == "__main__":
    unittest.main()
