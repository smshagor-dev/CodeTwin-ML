"""Loopback-only OpenAI-compatible neural embeddings from a locally installed model.

Setup is explicit. No model download or remote code execution occurs in this server.
Example:
  python -m codetwin_ml.embedding_api --model-dir PATH --port 8765
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import threading
from typing import Any, Protocol, Sequence, cast

MAX_BODY_BYTES = 16_384
MAX_INPUTS = 8
MAX_TEXT_CHARS = 160


class EmbeddingModel(Protocol):
    def encode(
        self, sentences: Sequence[str], *, normalize_embeddings: bool, convert_to_numpy: bool
    ) -> Any: ...


class LocalEmbeddingService:
    """Provider-independent request validation and float vector conversion."""

    def __init__(self, model: EmbeddingModel, model_name: str) -> None:
        if not model_name or len(model_name) > 150:
            raise ValueError("Model name must be 1-150 characters")
        self.model = model
        self.model_name = model_name
        self.lock = threading.Lock()

    def embed(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"model", "input"}:
            raise ValueError("Only 'model' and 'input' fields are supported")
        if payload["model"] != self.model_name:
            raise ValueError("Embedding model identifier mismatch")
        inputs = payload["input"]
        if (
            not isinstance(inputs, list)
            or not (1 <= len(inputs) <= MAX_INPUTS)
            or any(
                not isinstance(text, str)
                or not text.strip()
                or len(text) > MAX_TEXT_CHARS
                for text in inputs
            )
        ):
            raise ValueError("Expected 1-8 short nonempty input strings")
        with self.lock:
            vectors = self.model.encode(
                inputs, normalize_embeddings=True, convert_to_numpy=True
            )
        if len(vectors) != len(inputs):
            raise ValueError("Local model returned an unexpected number of embeddings")
        result = []
        dimensions: int | None = None
        for index, vector in enumerate(vectors):
            elements = vector.tolist() if hasattr(vector, "tolist") else list(vector)
            values = [float(n) for n in elements]
            if not (16 <= len(values) <= 3072) or any(
                not math.isfinite(value) for value in values
            ):
                raise ValueError("Invalid local neural embedding vector")
            length = math.sqrt(sum(value * value for value in values))
            if length <= 1e-10:
                raise ValueError("Neural embedding must not be zero")
            values = [value / length for value in values]
            if dimensions is not None and dimensions != len(values):
                raise ValueError("Model returned mixed vector dimensions")
            dimensions = len(values)
            result.append({"object": "embedding", "index": index, "embedding": values})
        return {
            "object": "list",
            "model": self.model_name,
            "data": result,
            "usage": {"prompt_tokens": 0, "total_tokens": 0},
        }


def make_handler(service: LocalEmbeddingService) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/v1/embeddings":
                self.send_error(404)
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                if not 0 < content_length <= MAX_BODY_BYTES:
                    self.send_error(413)
                    return
                data = self.rfile.read(content_length)
                payload = json.loads(data)
                result = service.embed(payload)
                content = json.dumps(result, separators=(",", ":"), allow_nan=False).encode()
                self.send_response(200)
            except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
                content = b'{"error":{"message":"Invalid embedding request"}}'
                self.send_response(400)
            except Exception:
                content = b'{"error":{"message":"Local embedding inference failed"}}'
                self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self) -> None:
            if self.path != "/health":
                self.send_error(404)
                return
            content = b'{"status":"ready"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, format: str, *args: object) -> None:
            # Avoid accidentally logging input text or secret-bearing URLs.
            return

    return Handler


def load_model(model_dir: Path, device: str) -> EmbeddingModel:
    directory = model_dir.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("Embedding model must be a local directory")
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    # Imported only on user invocation. The app's normal Python tests remain dependency-light.
    from importlib import import_module

    # Optional heavyweight provider: only imported after explicit local launch.
    model = import_module("sentence_transformers").SentenceTransformer(
        str(directory),
        device=device,
        trust_remote_code=False,
        local_files_only=True,
    )
    return cast(EmbeddingModel, model)


def main() -> None:
    parser = argparse.ArgumentParser(description="CodeTwin offline neural embedding API")
    parser.add_argument("--model-dir", required=True, type=Path)
    parser.add_argument("--model-name", default="codetwin-local-embedding")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    arguments = parser.parse_args()
    if not 1024 <= arguments.port <= 65535:
        parser.error("Port must be 1024-65535")
    model = load_model(arguments.model_dir, arguments.device)
    service = LocalEmbeddingService(model, arguments.model_name)
    server = ThreadingHTTPServer(("127.0.0.1", arguments.port), make_handler(service))
    print(f"CodeTwin offline embeddings listening on http://127.0.0.1:{arguments.port}/v1/embeddings", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
