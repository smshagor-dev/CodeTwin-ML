from __future__ import annotations

import json
import sys
from typing import Any

from codetwin_ml.protocol import ProtocolError, Request, handle_request


def process_line(line: str) -> dict[str, Any]:
    try:
        payload = json.loads(line)
        request = Request.from_json(payload)
        return handle_request(request)
    except (json.JSONDecodeError, ProtocolError) as error:
        return {"id": None, "ok": False, "error": {"code": "invalid_request", "message": str(error)}}


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        response = process_line(line)
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
