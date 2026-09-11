from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any, Callable

from codetwin_ml.models import ModelError, resolve_model_for_inference

MAX_TEXT_BYTES = 65_536
MAX_OUTPUT_ELEMENTS = 256


class InferenceError(RuntimeError):
    """Base error for bounded local inference failures."""


class InferenceInputError(InferenceError):
    """Raised when an inference request violates the model input contract."""


class InferenceRuntimeError(InferenceError):
    """Raised when the local ONNX runtime cannot execute a verified model."""


SessionFactory = Callable[[Path], Any]
ArrayFactory = Callable[[list[list[int]]], Any]
ModelValidator = Callable[[Path], None]


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

    for tensor in model.graph.initializer:
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
    try:
        return ort.InferenceSession(
            str(model_path),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )
    except Exception as error:  # pragma: no cover - exact exception types depend on onnxruntime
        raise InferenceRuntimeError(f"cannot create ONNX Runtime session: {error}") from error


def _encode_utf8_bytes(text: str, max_bytes: int) -> tuple[list[list[int]], int, str]:
    raw = text.encode("utf-8")
    if len(raw) > max_bytes:
        raise InferenceInputError(
            f"input is {len(raw)} UTF-8 bytes but this model allows at most {max_bytes}"
        )
    if len(raw) > MAX_TEXT_BYTES:
        raise InferenceInputError(f"input exceeds the global {MAX_TEXT_BYTES}-byte limit")
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
        or not labels
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
    if len(inputs) != 1 or getattr(inputs[0], "name", None) != input_name:
        raise InferenceRuntimeError("ONNX input does not match the declared single-input contract")
    if getattr(inputs[0], "type", None) not in {None, "tensor(int64)"}:
        raise InferenceRuntimeError("ONNX input must be int64 for utf8-bytes-v1")
    if len(outputs) != 1 or getattr(outputs[0], "name", None) != output_name:
        raise InferenceRuntimeError("ONNX output does not match the declared single-output contract")

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
