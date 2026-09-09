from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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


def handle_request(request: Request) -> dict[str, Any]:
    if request.method == "health":
        return {"id": request.request_id, "ok": True, "result": {"status": "ready", "protocol": 1}}
    if request.method == "capabilities":
        return {
            "id": request.request_id,
            "ok": True,
            "result": {
                "protocol": 1,
                "inference": [],
                "training": [],
                "note": "No model is reported until an evaluated artifact is installed.",
            },
        }
    return {
        "id": request.request_id,
        "ok": False,
        "error": {"code": "method_not_found", "message": f"unsupported method: {request.method}"},
    }
