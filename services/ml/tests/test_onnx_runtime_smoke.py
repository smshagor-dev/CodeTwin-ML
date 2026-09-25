import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.datasets import load_catalog  # noqa: E402
from codetwin_ml.inference import run_inference  # noqa: E402
from codetwin_ml.models import install_model  # noqa: E402


class RealOnnxRuntimeSmokeTests(unittest.TestCase):
    def test_installed_model_executes_with_real_cpu_runtime(self) -> None:
        import onnx
        from onnx import TensorProto, helper

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = root / "package"
            package.mkdir()
            artifact = package / "model.onnx"

            input_info = helper.make_tensor_value_info(
                "input_ids",
                TensorProto.INT64,
                [1, 16],
            )
            output_info = helper.make_tensor_value_info(
                "logits",
                TensorProto.FLOAT,
                [1, 2],
            )
            nodes = [
                helper.make_node("Cast", ["input_ids"], ["input_float"], to=TensorProto.FLOAT),
                helper.make_node(
                    "ReduceSum",
                    ["input_float"],
                    ["sum"],
                    axes=[1],
                    keepdims=1,
                ),
                helper.make_node("Neg", ["sum"], ["negative_sum"]),
                helper.make_node(
                    "Concat",
                    ["sum", "negative_sum"],
                    ["logits"],
                    axis=1,
                ),
            ]
            graph = helper.make_graph(
                nodes,
                "codetwin-real-onnx-smoke",
                [input_info],
                [output_info],
            )
            model = helper.make_model(
                graph,
                producer_name="codetwin-ci",
                opset_imports=[helper.make_opsetid("", 11)],
            )
            model.ir_version = 8
            onnx.checker.check_model(model)
            onnx.save_model(model, artifact)

            security = next(
                item
                for item in load_catalog()["datasets"]
                if item["id"] == "code_security_vulnerability"
            )
            manifest = {
                "schema_version": 1,
                "id": "codetwin-real-onnx-smoke",
                "name": "CodeTwin Real ONNX Runtime Smoke",
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
                        "max_bytes": 16,
                    },
                    "output": {
                        "name": "logits",
                        "labels": ["positive", "negative"],
                    },
                },
                "evaluation": {
                    "status": "passed",
                    "evaluated_at": "2026-09-25T00:00:00Z",
                    "datasets": [
                        {
                            "dataset_id": security["id"],
                            "revision": security["revision"],
                            "split": "test",
                            "metrics": {"f1": 1.0},
                        }
                    ],
                },
                "license": {
                    "name": "apache-2.0",
                    "url": "https://www.apache.org/licenses/LICENSE-2.0",
                    "acceptance_required": False,
                },
            }
            (package / "model.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )

            model_root = root / "models"
            installed = install_model(package, model_root=model_root)
            self.assertEqual(installed["integrity_verified"], True)

            result = run_inference(
                "security_analysis",
                "abc",
                model_id="codetwin-real-onnx-smoke",
                model_version="1.0.0",
                model_root=model_root,
            )

            self.assertEqual(result["runtime"]["engine"], "onnxruntime")
            self.assertEqual(result["runtime"]["provider"], "CPUExecutionProvider")
            self.assertEqual(result["prediction"]["label"], "positive")
            self.assertEqual(
                [item["label"] for item in result["prediction"]["scores"]],
                ["positive", "negative"],
            )
            self.assertAlmostEqual(
                sum(item["score"] for item in result["prediction"]["scores"]),
                1.0,
                places=6,
            )


if __name__ == "__main__":
    unittest.main()
