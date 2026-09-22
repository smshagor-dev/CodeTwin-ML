import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.datasets import load_catalog  # noqa: E402
from codetwin_ml.generation import (  # noqa: E402
    InferenceInputError,
    InferenceRuntimeError,
    generation_runtime_status,
    run_generation,
)
from codetwin_ml.models import install_model  # noqa: E402


class GenerationTests(unittest.TestCase):
    def _install_gguf(self, root: pathlib.Path) -> pathlib.Path:
        package = root / "package"
        package.mkdir()
        artifact = package / "coder.gguf"
        artifact.write_bytes(b"fake-gguf-model-for-unit-test")
        dataset = next(
            item for item in load_catalog()["datasets"]
            if item["id"] == "code_x_glue_code_refinement"
        )
        manifest = {
            "schema_version": 1,
            "id": "codetwin-test-coder",
            "name": "CodeTwin Test Coder",
            "version": "1.0.0",
            "backend": "llama-cpp-gguf-v1",
            "actions": ["repair_generation"],
            "artifacts": [{
                "role": "model",
                "path": "coder.gguf",
                "size_bytes": artifact.stat().st_size,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }],
            "inference": {
                "generation": {
                    "max_new_tokens": 128,
                    "context_tokens": 2048,
                    "temperature": 0.1,
                    "top_p": 0.9,
                }
            },
            "evaluation": {
                "status": "passed",
                "evaluated_at": "2026-09-22T00:00:00Z",
                "datasets": [{
                    "dataset_id": dataset["id"],
                    "revision": dataset["revision"],
                    "split": "test",
                    "metrics": {"exact_match": 0.1},
                }],
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

    def test_generation_requires_hash_pinned_llama_runtime(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            status = generation_runtime_status()
        self.assertFalse(status["available"])
        self.assertIn("CODETWIN_LLAMA_CLI", status["reason"])

    def test_runs_hash_pinned_local_generation_without_shell_or_prompt_on_command_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install_gguf(root)
            cli = root / ("llama-cli.exe" if os.name == "nt" else "llama-cli")
            cli.write_bytes(b"trusted-cli")
            if os.name != "nt":
                cli.chmod(0o700)
            cli_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
            completed = subprocess.CompletedProcess(
                args=[str(cli)],
                returncode=0,
                stdout=b"Use a parameterized query and add a regression test.\n",
            )

            with patch.dict(
                os.environ,
                {
                    "CODETWIN_LLAMA_CLI": str(cli),
                    "CODETWIN_LLAMA_CLI_SHA256": cli_hash,
                },
                clear=False,
            ), patch(
                "codetwin_ml.generation.subprocess.run",
                return_value=completed,
            ) as run:
                result = run_generation(
                    "repair_generation",
                    "Review this source and propose a bounded repair.",
                    model_root=model_root,
                )

            self.assertEqual(result["generation"]["text"], "Use a parameterized query and add a regression test.")
            self.assertEqual(result["model"]["backend"], "llama-cpp-gguf-v1")
            self.assertFalse(result["runtime"]["uses_shell"])
            self.assertFalse(result["runtime"]["network_access_requested"])
            command = run.call_args.args[0]
            self.assertEqual(command[0], str(cli.resolve()))
            self.assertIn("-f", command)
            self.assertNotIn("Review this source and propose a bounded repair.", command)
            prompt_path = pathlib.Path(command[command.index("-f") + 1])
            self.assertIn("codetwin-generation-", str(prompt_path))
            self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
            self.assertFalse(run.call_args.kwargs["check"])

    def test_rejects_oversized_prompt_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install_gguf(root)
            with self.assertRaises(InferenceInputError):
                run_generation(
                    "repair_generation",
                    "x" * 70_000,
                    model_root=model_root,
                )

    def test_rejects_mismatched_runtime_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = self._install_gguf(root)
            cli = root / "llama-cli"
            cli.write_bytes(b"trusted-cli")
            with patch.dict(
                os.environ,
                {
                    "CODETWIN_LLAMA_CLI": str(cli),
                    "CODETWIN_LLAMA_CLI_SHA256": "0" * 64,
                },
                clear=False,
            ):
                with self.assertRaisesRegex(InferenceRuntimeError, "hash does not match"):
                    run_generation(
                        "repair_generation",
                        "review source",
                        model_root=model_root,
                    )


if __name__ == "__main__":
    unittest.main()
