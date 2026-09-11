import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.datasets import load_catalog  # noqa: E402
from codetwin_ml.models import (  # noqa: E402
    ModelIntegrityError,
    ModelLicenseError,
    inference_plan,
    install_model,
    list_models,
    model_status,
    route_model,
)


class ModelRegistryTests(unittest.TestCase):
    def _package(
        self,
        root: pathlib.Path,
        *,
        acceptance_required: bool = False,
    ) -> pathlib.Path:
        package = root / "package"
        package.mkdir()
        artifact = package / "model.onnx"
        artifact.write_bytes(b"codetwin-test-model-bytes")
        security = next(
            item for item in load_catalog()["datasets"] if item["id"] == "code_security_vulnerability"
        )
        manifest = {
            "schema_version": 1,
            "id": "openmindai-security-screen-v1",
            "name": "OpenMindAI Security Screen Test Model",
            "version": "1.0.0",
            "backend": "onnx-classification-v1",
            "actions": ["security_analysis", "vulnerability_detection"],
            "artifacts": [
                {
                    "role": "model",
                    "path": "model.onnx",
                    "size_bytes": artifact.stat().st_size,
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            ],
            "evaluation": {
                "status": "passed",
                "evaluated_at": "2026-09-11T00:00:00Z",
                "datasets": [
                    {
                        "dataset_id": security["id"],
                        "revision": security["revision"],
                        "split": "test",
                        "metrics": {"f1": 0.5, "precision": 0.5, "recall": 0.5},
                    }
                ],
            },
            "license": {
                "name": "apache-2.0",
                "url": "https://www.apache.org/licenses/LICENSE-2.0",
                "acceptance_required": acceptance_required,
            },
        }
        (package / "model.json").write_text(json.dumps(manifest), encoding="utf-8")
        return package

    def test_installs_integrity_checked_package_and_routes_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = root / "models"
            installed = install_model(self._package(root), model_root=model_root)
            self.assertTrue(installed["integrity_verified"])
            self.assertFalse(installed["execution_supported"])

            inventory = list_models(model_root=model_root)
            self.assertEqual(len(inventory["models"]), 1)
            self.assertTrue(inventory["models"][0]["ready"])
            self.assertFalse(inventory["execution_implemented"])

            route = route_model("security_analysis", model_root=model_root)
            self.assertTrue(route["ready"])
            self.assertEqual(route["models"][0]["id"], "openmindai-security-screen-v1")
            self.assertFalse(route["execution_implemented"])

    def test_tampered_artifact_is_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = root / "models"
            package = self._package(root)
            install_model(package, model_root=model_root)
            installed_artifact = model_root / "openmindai-security-screen-v1" / "1.0.0" / "model.onnx"
            installed_artifact.write_bytes(b"tampered")

            status = model_status("openmindai-security-screen-v1", model_root=model_root)
            self.assertTrue(status["installed"])
            self.assertFalse(status["ready"])

    def test_package_tamper_is_rejected_before_install(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = self._package(root)
            (package / "model.onnx").write_bytes(b"different")
            with self.assertRaises(ModelIntegrityError):
                install_model(package, model_root=root / "models")

    def test_required_model_license_must_be_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = self._package(root, acceptance_required=True)
            with self.assertRaises(ModelLicenseError):
                install_model(package, model_root=root / "models")
            installed = install_model(
                package,
                accepted_licenses=["apache-2.0"],
                model_root=root / "models",
            )
            self.assertEqual(installed["license"]["name"], "apache-2.0")

    def test_inference_plan_never_claims_execution_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            model_root = root / "models"
            install_model(self._package(root), model_root=model_root)
            plan = inference_plan("security_analysis", model_root=model_root)
            self.assertEqual(plan["status"], "model_ready_execution_pending")
            self.assertFalse(plan["execution_implemented"])
            self.assertIn("code_security_vulnerability", plan["dataset_provenance"])


if __name__ == "__main__":
    unittest.main()
