from __future__ import annotations

import hashlib
import importlib.util
import math
from pathlib import Path
from typing import Any, Callable, Iterator

from codetwin_ml.models import (
    ModelError,
    inference_plan as registry_inference_plan,
    resolve_model_for_inference,
)

MAX_TEXT_BYTES = 65_536
MAX_OUTPUT_ELEMENTS = 256
RUNTIME_MODULES = ("numpy", "onnx", "onnxruntime")


class InferenceError(RuntimeError):
    """Base error for bounded local inference failures."""


class InferenceInputError(InferenceError):
    """Raised when an inference request violates the model input contract."""


class InferenceRuntimeError(InferenceError):
    """Raised when the local ONNX runtime cannot execute a verified model."""


SessionFactory = Callable[[Path], Any]
ArrayFactory = Callable[[list[list[int]]], Any]
ModelValidator = Callable[[Path], None]


def runtime_dependency_status() -> dict[str, Any]:
    missing = [name for name in RUNTIME_MODULES if importlib.util.find_spec(name) is None]
    return {"available": not missing, "required": list(RUNTIME_MODULES), "missing": missing}


def plan_inference(action: str, *, model_root: Path | str | None = None) -> dict[str, Any]:
    plan = registry_inference_plan(action, model_root=model_root)
    dependencies = runtime_dependency_status()
    plan["runtime_dependencies"] = dependencies
    if plan["status"] == "ready" and not dependencies["available"]:
        plan["status"] = "runtime_unavailable"
        plan["note"] = (
            "An execution-ready model is installed, but numpy, onnx, and onnxruntime must all be "
            "installed before local inference can run."
        )
    return plan


def _iter_graph_tensors(graph: Any, onnx: Any) -> Iterator[Any]:
    yield from graph.initializer
    for sparse in getattr(graph, "sparse_initializer", []):
        yield sparse.values
        yield sparse.indices
    for node in graph.node:
        for attribute in node.attribute:
            if attribute.type == onnx.AttributeProto.TENSOR:
                yield attribute.t
            elif attribute.type == onnx.AttributeProto.TENSORS:
                yield from attribute.tensors
            elif attribute.type == onnx.AttributeProto.SPARSE_TENSOR:
                yield attribute.sparse_tensor.values
                yield attribute.sparse_tensor.indices
            elif attribute.type == onnx.AttributeProto.SPARSE_TENSORS:
                for sparse in attribute.sparse_tensors:
                    yield sparse.values
                    yield sparse.indices
            elif attribute.type == onnx.AttributeProto.GRAPH:
                yield from _iter_graph_tensors(attribute.g, onnx)
            elif attribute.type == onnx.AttributeProto.GRAPHS:
                for nested in attribute.graphs:
                    yield from _iter_graph_tensors(nested, onnx)


def _validate_single_file_onnx(model_path: Path) -> None:
    try:
        import onnx  # type: ignore[import-not-found]
    except ImportError as error:
        raise InferenceRuntimeError(
            "ONNX validation dependency is not installed; install the ml optional dependencies"
        ) from error

    try:
        model = onnx.load_model(str(model_path), load_external_data=False)
    except Exception as error:  # pragma: no cover - exact exception types depend on onnx
        raise InferenceRuntimeError(f"cannot validate ONNX model: {error}") from error

    for tensor in _iter_graph_tensors(model.graph, onnx):
        if tensor.data_location == onnx.TensorProto.EXTERNAL:
            raise InferenceRuntimeError("external-data ONNX models are not supported")
        if getattr(tensor, "external_data", None):
            raise InferenceRuntimeError("external-data ONNX models are not supported")


def _default_array_factory(values: list[list[int]]) -> Any:
    try:
        import numpy as np  # type: ignore[import-not-found]
    except ImportError as error:
        raise InferenceRuntimeError(
            "NumPy is not installed; install the ml optional dependencies"
        ) from error
    return np.asarray(values, dtype=np.int64)


def _default_session_factory(model_path: Path) -> Any:
    try:
        import onnxruntime as ort  # type: ignore[import-not-found]
    except ImportError as error:
        raise InferenceRuntimeError(
            "ONNX Runtime is not installed; install the ml optional dependencies"
        ) from error

    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_EXTENDED
    options.add_session_config_entry("session.intra_op.allow_spinning", "0")
    options.add_session_config_entry("session.inter_op.allow_spinning", "0")
    try:
        return ort.InferenceSession(
            str(model_path),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
    except Exception as error:  # pragma: no cover - exact exception types depend on onnxruntime
        raise InferenceRuntimeError(f"cannot create ONNX Runtime session: {error}") from error


def _encode_utf8_bytes(text: str, max_bytes: int) -> tuple[list[list[int]], int, str]:
    if len(text) > MAX_TEXT_BYTES:
        raise InferenceInputError(f"input exceeds the global {MAX_TEXT_BYTES}-character precheck")
    raw = text.encode("utf-8")
    if len(raw) > MAX_TEXT_BYTES:
        raise InferenceInputError(f"input exceeds the global {MAX_TEXT_BYTES}-byte limit")
    if len(raw) > max_bytes:
        raise InferenceInputError(
            f"input is {len(raw)} UTF-8 bytes but this model allows at most {max_bytes}"
        )
    row = [value + 1 for value in raw]
    row.extend([0] * (max_bytes - len(row)))
    return [row], len(raw), hashlib.sha256(raw).hexdigest()


def _flatten_output(value: Any) -> list[float]:
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, tuple):
        value = list(value)
    if isinstance(value, list) and len(value) == 1 and isinstance(value[0], (list, tuple)):
        value = list(value[0])
    if not isinstance(value, list):
        raise InferenceRuntimeError("model output must be a one-dimensional logits vector")
    if not value or len(value) > MAX_OUTPUT_ELEMENTS:
        raise InferenceRuntimeError(
            f"model output must contain between 1 and {MAX_OUTPUT_ELEMENTS} elements"
        )
    result: list[float] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise InferenceRuntimeError("model logits must be finite numeric values")
        number = float(item)
        if not math.isfinite(number):
            raise InferenceRuntimeError("model logits must be finite numeric values")
        result.append(number)
    return result


def _softmax(logits: list[float]) -> list[float]:
    maximum = max(logits)
    exponentials = [math.exp(value - maximum) for value in logits]
    total = sum(exponentials)
    if not math.isfinite(total) or total <= 0:
        raise InferenceRuntimeError("cannot normalize model logits")
    return [value / total for value in exponentials]


def _validate_input_descriptor(descriptor: Any, input_name: str, max_bytes: int) -> None:
    if getattr(descriptor, "name", None) != input_name:
        raise InferenceRuntimeError("ONNX input name does not match the declared contract")
    if getattr(descriptor, "type", None) != "tensor(int64)":
        raise InferenceRuntimeError("ONNX input must be tensor(int64) for utf8-bytes-v1")
    shape = getattr(descriptor, "shape", None)
    if shape is None:
        return
    if not isinstance(shape, (list, tuple)) or len(shape) != 2:
        raise InferenceRuntimeError("ONNX input must have rank 2")
    first, second = shape
    if isinstance(first, int) and first != 1:
        raise InferenceRuntimeError("ONNX input batch dimension must allow a single item")
    if isinstance(second, int) and second != max_bytes:
        raise InferenceRuntimeError("ONNX input width does not match inference.max_bytes")


def _validate_output_descriptor(descriptor: Any, output_name: str, label_count: int) -> None:
    if getattr(descriptor, "name", None) != output_name:
        raise InferenceRuntimeError("ONNX output name does not match the declared contract")
    output_type = getattr(descriptor, "type", None)
    if output_type not in {"tensor(float)", "tensor(double)", None}:
        raise InferenceRuntimeError("ONNX logits output must be floating point")
    shape = getattr(descriptor, "shape", None)
    if shape is None:
        return
    if not isinstance(shape, (list, tuple)) or len(shape) not in {1, 2}:
        raise InferenceRuntimeError("ONNX logits output must have rank 1 or 2")
    last = shape[-1]
    if isinstance(last, int) and last != label_count:
        raise InferenceRuntimeError("ONNX output width does not match the declared label count")
    if len(shape) == 2 and isinstance(shape[0], int) and shape[0] != 1:
        raise InferenceRuntimeError("ONNX output batch dimension must allow a single item")


def run_inference(
    action: str,
    text: str,
    *,
    model_id: str | None = None,
    model_version: str | None = None,
    model_root: Path | str | None = None,
    session_factory: SessionFactory | None = None,
    array_factory: ArrayFactory | None = None,
    model_validator: ModelValidator | None = None,
) -> dict[str, Any]:
    if not isinstance(action, str) or not action:
        raise InferenceInputError("action must be a non-empty string")
    if not isinstance(text, str):
        raise InferenceInputError("text must be a string")

    try:
        model_dir, metadata = resolve_model_for_inference(
            action,
            model_id=model_id,
            model_version=model_version,
            model_root=model_root,
        )
    except ModelError as error:
        raise InferenceInputError(str(error)) from error

    contract = metadata.get("inference")
    if not isinstance(contract, dict):
        raise InferenceRuntimeError("selected model does not declare an executable inference contract")
    preprocessing = contract.get("preprocessing")
    output_contract = contract.get("output")
    if not isinstance(preprocessing, dict) or not isinstance(output_contract, dict):
        raise InferenceRuntimeError("selected model has an invalid inference contract")
    if preprocessing.get("kind") != "utf8-bytes-v1":
        raise InferenceRuntimeError("unsupported preprocessing contract")

    max_bytes = preprocessing.get("max_bytes")
    input_name = preprocessing.get("input_name")
    output_name = output_contract.get("name")
    labels = output_contract.get("labels")
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 1
        or max_bytes > MAX_TEXT_BYTES
        or not isinstance(input_name, str)
        or not input_name
        or not isinstance(output_name, str)
        or not output_name
        or not isinstance(labels, list)
        or len(labels) < 2
        or any(not isinstance(label, str) or not label for label in labels)
        or len(labels) > MAX_OUTPUT_ELEMENTS
    ):
        raise InferenceRuntimeError("selected model has an invalid inference contract")

    model_artifact = next(
        (item for item in metadata["artifacts"] if item.get("role") == "model"),
        None,
    )
    if not isinstance(model_artifact, dict):
        raise InferenceRuntimeError("selected model is missing its model artifact")
    model_path = model_dir / model_artifact["path"]

    validator = model_validator or _validate_single_file_onnx
    validator(model_path)
    encoded, input_bytes, input_sha256 = _encode_utf8_bytes(text, max_bytes)
    tensor = (array_factory or _default_array_factory)(encoded)
    session = (session_factory or _default_session_factory)(model_path)

    try:
        inputs = session.get_inputs()
        outputs = session.get_outputs()
    except Exception as error:
        raise InferenceRuntimeError(f"cannot inspect ONNX model I/O: {error}") from error
    if len(inputs) != 1:
        raise InferenceRuntimeError("ONNX model must expose exactly one input")
    if len(outputs) != 1:
        raise InferenceRuntimeError("ONNX model must expose exactly one output")
    _validate_input_descriptor(inputs[0], input_name, max_bytes)
    _validate_output_descriptor(outputs[0], output_name, len(labels))

    try:
        raw_outputs = session.run([output_name], {input_name: tensor})
    except Exception as error:
        raise InferenceRuntimeError(f"ONNX inference failed: {error}") from error
    if not isinstance(raw_outputs, list) or len(raw_outputs) != 1:
        raise InferenceRuntimeError("ONNX runtime returned an unexpected output set")
    logits = _flatten_output(raw_outputs[0])
    if len(logits) != len(labels):
        raise InferenceRuntimeError(
            "ONNX logits length does not match the declared label count"
        )
    probabilities = _softmax(logits)
    best_index = max(range(len(probabilities)), key=probabilities.__getitem__)

    return {
        "action": action,
        "model": {
            "id": metadata["id"],
            "version": metadata["version"],
            "backend": metadata["backend"],
            "package_digest": metadata["package_digest"],
        },
        "input": {
            "utf8_bytes": input_bytes,
            "sha256": input_sha256,
            "preprocessing": "utf8-bytes-v1",
            "max_bytes": max_bytes,
            "truncated": False,
        },
        "prediction": {
            "label": labels[best_index],
            "confidence": probabilities[best_index],
            "scores": [
                {"label": label, "score": probabilities[index]}
                for index, label in enumerate(labels)
            ],
        },
        "runtime": {
            "engine": "onnxruntime",
            "provider": "CPUExecutionProvider",
            "intra_op_threads": 1,
            "inter_op_threads": 1,
        },
        "evaluation_provenance": metadata["evaluation"],
    }
