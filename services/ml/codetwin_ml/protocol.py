from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from codetwin_ml.datasets import (
    DatasetError,
    dataset_status,
    list_datasets,
    prefetch_action,
    prefetch_all,
    prefetch_dataset,
    route_action,
)
from codetwin_ml.inference import (
    InferenceError,
    plan_inference,
    runtime_dependency_status,
)
from codetwin_ml.generation import generation_runtime_status
from codetwin_ml.isolated import run_isolated_generation, run_isolated_inference
from codetwin_ml.models import (
    ModelError,
    install_model,
    list_models,
    model_status,
    route_model,
)


class ProtocolError(ValueError):
    """Raised when a sidecar request violates the protocol contract."""


@dataclass(frozen=True, slots=True)
class Request:
    request_id: str
    method: str
    params: dict[str, Any]

    @classmethod
    def from_json(cls, payload: Any) -> "Request":
        if not isinstance(payload, dict):
            raise ProtocolError("request must be an object")
        request_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params", {})
        if not isinstance(request_id, str) or not request_id:
            raise ProtocolError("id must be a non-empty string")
        if not isinstance(method, str) or not method:
            raise ProtocolError("method must be a non-empty string")
        if not isinstance(params, dict):
            raise ProtocolError("params must be an object")
        return cls(request_id=request_id, method=method, params=params)


def _ok(request: Request, result: Any) -> dict[str, Any]:
    return {"id": request.request_id, "ok": True, "result": result}


def _error(request: Request, code: str, message: str) -> dict[str, Any]:
    return {"id": request.request_id, "ok": False, "error": {"code": code, "message": message}}


def _string_param(request: Request, key: str, *, required: bool = False) -> str | None:
    value = request.params.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{key} must be a non-empty string")
    return value


def _text_param(request: Request, key: str) -> str:
    value = request.params.get(key)
    if not isinstance(value, str):
        raise ProtocolError(f"{key} must be a string")
    return value


def _accepted_licenses(request: Request) -> list[str]:
    value = request.params.get("accepted_licenses", [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ProtocolError("accepted_licenses must be an array of non-empty strings")
    return value


def handle_request(request: Request) -> dict[str, Any]:
    try:
        if request.method == "health":
            return _ok(request, {"status": "ready", "protocol": 1})
        if request.method == "capabilities":
            catalog = list_datasets()
            models = list_models()
            dependencies = runtime_dependency_status()
            execution_models = [
                item
                for item in models["models"]
                if item.get("ready") and item.get("execution_supported")
            ]
            classifier_models = [
                item for item in execution_models
                if item.get("backend") == "onnx-classification-v1"
            ]
            generation_models = [
                item for item in execution_models
                if item.get("backend") == "llama-cpp-gguf-v1"
            ]
            inference_actions = (
                sorted({action for item in classifier_models for action in item.get("actions", [])})
                if dependencies["available"]
                else []
            )
            generation_runtime = generation_runtime_status()
            generation_actions = (
                sorted({action for item in generation_models for action in item.get("actions", [])})
                if generation_runtime.get("available")
                else []
            )
            return _ok(request, {
                "protocol": 1,
                "inference": inference_actions,
                "generation": generation_actions,
                "training": [],
                "models": {
                    "registry": True,
                    "installed": len(models["models"]),
                    "ready": sum(1 for item in models["models"] if item.get("ready")),
                    "execution_ready": len(execution_models),
                    "execution_implemented": models["execution_implemented"],
                    "backends": models["execution_backends"],
                    "runtime_dependencies": dependencies,
                    "generation_runtime": generation_runtime,
                },
                "datasets": {
                    "catalog_version": catalog["schema_version"],
                    "downloadable": True,
                    "actions": catalog["actions"],
                },
                "note": (
                    "Classifier actions require the bounded ONNX runtime. Generation actions require "
                    "an integrity-checked GGUF package plus a separately trusted llama.cpp CLI pinned "
                    "by CODETWIN_LLAMA_CLI_SHA256. Generated text is never auto-executed as a web payload."
                ),
            })
        if request.method == "datasets.list":
            return _ok(request, list_datasets())
        if request.method == "datasets.route":
            action = _string_param(request, "action", required=True)
            return _ok(request, route_action(action))
        if request.method == "datasets.status":
            dataset_id = _string_param(request, "dataset_id")
            return _ok(request, dataset_status(dataset_id))
        if request.method == "datasets.prefetch":
            accepted = _accepted_licenses(request)
            action = _string_param(request, "action")
            dataset_id = _string_param(request, "dataset_id")
            all_requested = request.params.get("all", False)
            if not isinstance(all_requested, bool):
                raise ProtocolError("all must be a boolean")
            selected = int(action is not None) + int(dataset_id is not None) + int(all_requested)
            if selected != 1:
                raise ProtocolError("datasets.prefetch requires exactly one of action, dataset_id, or all=true")
            if action is not None:
                return _ok(request, prefetch_action(action, accepted_licenses=accepted))
            if dataset_id is not None:
                return _ok(request, prefetch_dataset(dataset_id, accepted_licenses=accepted))
            return _ok(request, prefetch_all(accepted_licenses=accepted))
        if request.method == "models.list":
            return _ok(request, list_models())
        if request.method == "models.status":
            model_id = _string_param(request, "model_id")
            return _ok(request, model_status(model_id))
        if request.method == "models.route":
            action = _string_param(request, "action", required=True)
            return _ok(request, route_model(action))
        if request.method == "models.install":
            package_path = _string_param(request, "package_path", required=True)
            return _ok(
                request,
                install_model(package_path, accepted_licenses=_accepted_licenses(request)),
            )
        if request.method == "inference.plan":
            action = _string_param(request, "action", required=True)
            return _ok(request, plan_inference(action))
        if request.method == "inference.run":
            action = _string_param(request, "action", required=True)
            return _ok(
                request,
                run_isolated_inference(
                    action,
                    _text_param(request, "text"),
                    model_id=_string_param(request, "model_id"),
                    model_version=_string_param(request, "model_version"),
                ),
            )
        if request.method == "generation.run":
            action = _string_param(request, "action", required=True)
            return _ok(
                request,
                run_isolated_generation(
                    action,
                    _text_param(request, "text"),
                    model_id=_string_param(request, "model_id"),
                    model_version=_string_param(request, "model_version"),
                ),
            )

        return _error(request, "method_not_found", f"unsupported method: {request.method}")
    except ProtocolError:
        raise
    except DatasetError as error:
        return _error(request, "dataset_error", str(error))
    except ModelError as error:
        return _error(request, "model_error", str(error))
    except InferenceError as error:
        return _error(request, "inference_error", str(error))
