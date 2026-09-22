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
    InferenceRuntimeError,
    plan_generation,
    run_generation,
)
from codetwin_ml.models import install_model  # noqa: E402


class _Generator:
    def __init__(self, value: dict) -> None:
        self.value = value
        self.prompt = None
        self.options = None

    def __call__(self, prompt: str, **options):
        self.prompt = prompt
        self.options = options
        return {"choices": [{"text": json.dumps(self.value)}]}


class GenerationTests(unittest.TestCase):
    def _install(self, root: pathlib.Path) -> pathlib.Path:
        package = root / "package"
        package.mkdir()
        artifact = package / "model.gguf"
        artifact.write_bytes(b"fake-gguf-for-unit-test")
        security = next(
            item
            for item in load_catalog()["datasets"]
            if item["id"] == "code_security_vulnerability"
        )
        manifest = {
            "schema_version": 1,
            "id": "openmindai-security-advisor-v1",
            "name": "OpenMindAI Safe Security Advisor Test Model",
            "version": "1.0.0",
            "backend": "gguf-llama-cpp-v1",
            "actions": ["security_analysis"],
            "artifacts": [
                {
                    "role": "model",
                    "path": "model.gguf",
                    "size_bytes": artifact.stat().st_size,
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            ],
            "inference": {
                "preprocessing": {
                    "kind": "utf8-prompt-v1",
                    "max_bytes": 4096,
                },
                "generation": {
                    "max_tokens": 128,
                    "context_tokens": 2048,
                    "output_schema": "codetwin-safe-advisory-v1",
                },
            },
            "evaluation": {
                "status": "passed",
                "evaluated_at": "2026-09-22T00:00:00Z",
                "datasets": [
                    {
                        "dataset_id": security["id"],
                        "revision": security["revision"],
                        "split": "test",
                        "metrics": {"schema_valid_rate": 1.0},
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

    def test_generates_only_structured_safe_advisory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install(root)
            generator = _Generator(
                {
                    "summary": "Review the login query boundary.",
                    "probe_intents": [
                        {
                            "family": "sql_quote_error",
                            "parameter": "email",
                            "rationale": "The source route maps email into a database lookup.",
                        }
                    ],
                    "repair_notes": ["Use a parameterized query for the email lookup."],
                }
            )
            result = run_generation(
                "security_analysis",
                "POST /login body.email -> query",
                model_root=model_root,
                generator_factory=lambda path, context: generator,
            )
            self.assertEqual(result["model"]["backend"], "gguf-llama-cpp-v1")
            self.assertEqual(
                result["advisory"]["probe_intents"][0]["family"],
                "sql_quote_error",
            )
            self.assertNotIn("payload", result["advisory"]["probe_intents"][0])
            self.assertEqual(generator.options["temperature"], 0.0)
            self.assertIn("Never return", generator.prompt)
            self.assertIn("symbolic names only", generator.prompt)

    def test_rejects_model_output_outside_probe_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install(root)
            generator = _Generator(
                {
                    "summary": "Unsafe output attempt.",
                    "probe_intents": [
                        {
                            "family": "arbitrary_shell",
                            "parameter": "q",
                            "rationale": "Not allowed.",
                        }
                    ],
                    "repair_notes": [],
                }
            )
            with self.assertRaises(InferenceRuntimeError):
                run_generation(
                    "security_analysis",
                    "GET /search?q=x",
                    model_root=model_root,
                    generator_factory=lambda path, context: generator,
                )

    def test_generation_plan_reports_missing_runtime_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install(root)
            with patch("codetwin_ml.inference.importlib.util.find_spec", return_value=None):
                plan = plan_generation("security_analysis", model_root=model_root)
            self.assertEqual(plan["status"], "runtime_unavailable")
            self.assertEqual(plan["runtime_dependencies"]["missing"], ["llama_cpp"])


if __name__ == "__main__":
    unittest.main()
