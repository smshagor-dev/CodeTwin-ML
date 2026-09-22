from __future__ import annotations

import json
import os
import sys
from typing import Any

WORKER_PROTOCOL_VERSION = 1
MAX_WORKER_REQUEST_BYTES = 131_072
POSIX_CPU_SECONDS = 10
POSIX_ADDRESS_SPACE_BYTES = 4 * 1024 * 1024 * 1024
POSIX_FILE_SIZE_BYTES = 16 * 1024 * 1024


def _write_response(payload: dict[str, Any]) -> int:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


def _error(code: str, message: str) -> dict[str, Any]:
    return {
        "protocol": WORKER_PROTOCOL_VERSION,
        "ok": False,
        "error": {"code": code, "message": message},
    }


def _cap_resource(resource_module: Any, resource_name: str, target: int) -> None:
    resource_id = getattr(resource_module, resource_name, None)
    if resource_id is None:
        return
    try:
        _soft, hard = resource_module.getrlimit(resource_id)
        infinity = resource_module.RLIM_INFINITY
        effective = target if hard == infinity else min(target, hard)
        resource_module.setrlimit(resource_id, (effective, effective))
    except (OSError, ValueError):
        return


def _apply_resource_limits() -> None:
    if os.name != "posix":
        return
    try:
        import resource
    except ImportError:
        return
    _cap_resource(resource, "RLIMIT_CPU", POSIX_CPU_SECONDS)
    _cap_resource(resource, "RLIMIT_AS", POSIX_ADDRESS_SPACE_BYTES)
    _cap_resource(resource, "RLIMIT_FSIZE", POSIX_FILE_SIZE_BYTES)


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_WORKER_REQUEST_BYTES + 1)
    if len(raw) > MAX_WORKER_REQUEST_BYTES:
        raise ValueError(f"worker request exceeds {MAX_WORKER_REQUEST_BYTES} bytes")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("worker request must be an object")
    if value.get("protocol") != WORKER_PROTOCOL_VERSION:
        raise ValueError("worker protocol mismatch")
    return value


def main() -> int:
    _apply_resource_limits()
    try:
        request = _read_request()
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return _write_response(_error("invalid_request", str(error)))

    operation = request.get("operation", "classification")
    action = request.get("action")
    text = request.get("text")
    model_id = request.get("model_id")
    model_version = request.get("model_version")
    if operation not in {"classification", "generation"}:
        return _write_response(_error("invalid_request", "operation is unsupported"))
    if not isinstance(action, str) or not action:
        return _write_response(_error("invalid_request", "action must be a non-empty string"))
    if not isinstance(text, str):
        return _write_response(_error("invalid_request", "text must be a string"))
    if model_id is not None and (not isinstance(model_id, str) or not model_id):
        return _write_response(_error("invalid_request", "model_id must be null or a non-empty string"))
    if model_version is not None and (not isinstance(model_version, str) or not model_version):
        return _write_response(
            _error("invalid_request", "model_version must be null or a non-empty string")
        )

    try:
        from codetwin_ml.inference import InferenceError, run_generation, run_inference
    except Exception as error:  # pragma: no cover - import failure is environment-specific
        return _write_response(_error("worker_internal_error", type(error).__name__))

    try:
        executor = run_generation if operation == "generation" else run_inference
        result = executor(
            action,
            text,
            model_id=model_id,
            model_version=model_version,
        )
    except InferenceError as error:
        return _write_response(_error("inference_error", str(error)))
    except Exception as error:  # pragma: no cover - last-resort worker boundary
        return _write_response(_error("worker_internal_error", type(error).__name__))

    return _write_response(
        {"protocol": WORKER_PROTOCOL_VERSION, "ok": True, "result": result}
    )


if __name__ == "__main__":
    raise SystemExit(main())
