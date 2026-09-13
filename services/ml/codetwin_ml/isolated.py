from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any

from codetwin_ml.inference import InferenceRuntimeError

WORKER_PROTOCOL_VERSION = 1
MAX_WORKER_REQUEST_BYTES = 131_072
MAX_WORKER_RESPONSE_BYTES = 1_048_576
WORKER_TIMEOUT_SECONDS = 15


def _sidecar_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def run_isolated_inference(
    action: str,
    text: str,
    *,
    model_id: str | None = None,
    model_version: str | None = None,
) -> dict[str, Any]:
    payload = {
        "protocol": WORKER_PROTOCOL_VERSION,
        "action": action,
        "text": text,
        "model_id": model_id,
        "model_version": model_version,
    }
    request = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(request) > MAX_WORKER_REQUEST_BYTES:
        raise InferenceRuntimeError(
            f"isolated inference request exceeds {MAX_WORKER_REQUEST_BYTES} bytes"
        )

    root = _sidecar_root()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root)
    kwargs: dict[str, Any] = {
        "input": request,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "cwd": str(root),
        "env": environment,
        "timeout": WORKER_TIMEOUT_SECONDS,
        "check": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    try:
        completed = subprocess.run(
            [sys.executable, "-m", "codetwin_ml.worker"],
            **kwargs,
        )
    except subprocess.TimeoutExpired as error:
        raise InferenceRuntimeError(
            f"isolated inference exceeded the {WORKER_TIMEOUT_SECONDS} second timeout"
        ) from error
    except OSError as error:
        raise InferenceRuntimeError(f"cannot start isolated inference worker: {error}") from error

    stdout = completed.stdout
    if not isinstance(stdout, (bytes, bytearray)):
        raise InferenceRuntimeError("isolated inference worker returned invalid stdout")
    if len(stdout) > MAX_WORKER_RESPONSE_BYTES:
        raise InferenceRuntimeError(
            f"isolated inference response exceeds {MAX_WORKER_RESPONSE_BYTES} bytes"
        )
    if completed.returncode != 0:
        raise InferenceRuntimeError(
            f"isolated inference worker exited with status {completed.returncode}"
        )

    try:
        response = json.loads(bytes(stdout).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InferenceRuntimeError("isolated inference worker returned invalid JSON") from error
    if not isinstance(response, dict) or response.get("protocol") != WORKER_PROTOCOL_VERSION:
        raise InferenceRuntimeError("isolated inference worker protocol mismatch")
    if response.get("ok") is True:
        result = response.get("result")
        if not isinstance(result, dict):
            raise InferenceRuntimeError("isolated inference worker result is invalid")
        return result
    if response.get("ok") is False:
        error = response.get("error")
        if isinstance(error, dict):
            code = error.get("code") if isinstance(error.get("code"), str) else "worker_error"
            message = (
                error.get("message")
                if isinstance(error.get("message"), str)
                else "isolated inference failed"
            )
            raise InferenceRuntimeError(f"{code}: {message}")
        raise InferenceRuntimeError("isolated inference worker returned an invalid error")
    raise InferenceRuntimeError("isolated inference worker response is missing ok")
