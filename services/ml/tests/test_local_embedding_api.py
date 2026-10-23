"""HTTP contract tests for the genuine local-model adapter (fake inference only).

A real pretrained model can be tested separately by starting the opt-in server.
"""
import http.client
import json
import pathlib
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from typing import Any, Sequence

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.embedding_api import LocalEmbeddingService, make_handler  # noqa: E402


class FakeEmbeddingModel:
    def encode(
        self,
        sentences: Sequence[str],
        *,
        normalize_embeddings: bool,
        convert_to_numpy: bool,
    ) -> list[list[float]]:
        assert normalize_embeddings and convert_to_numpy
        output = []
        for sentence in sentences:
            vector = [0.0] * 32
            vector[1 if "secrets" in sentence else 0] = 2.0
            output.append(vector)
        return output


class LocalEmbeddingServiceTests(unittest.TestCase):
    def test_vector_normalization_and_isolation(self) -> None:
        service = LocalEmbeddingService(FakeEmbeddingModel(), "local-pretrained")
        result = service.embed({"model": "local-pretrained", "input": [
            "review source", "review secrets",
        ]})
        self.assertEqual(result["data"][0]["index"], 0)
        self.assertEqual(result["data"][1]["index"], 1)
        self.assertEqual(result["data"][0]["embedding"][0], 1.0)
        self.assertEqual(result["data"][1]["embedding"][1], 1.0)
        self.assertEqual(len(result["data"][0]["embedding"]), 32)

        for bad in [
            {"model": "wrong-model", "input": ["source"]},
            {"model": "local-pretrained", "input": []},
            {"model": "local-pretrained", "input": [""], "url": "http://example.com"},
            {"model": "local-pretrained", "input": ["x" * 161]},
            {"model": "local-pretrained", "input": [7]},
        ]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                service.embed(bad)

    def test_openai_compatible_loopback_http_transport(self) -> None:
        service = LocalEmbeddingService(FakeEmbeddingModel(), "local-pretrained")
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(service))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=4)
            payload = json.dumps({
                "model": "local-pretrained",
                "input": ["security source", "security secrets"],
            })
            connection.request("POST", "/v1/embeddings", body=payload,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            result: dict[str, Any] = json.loads(response.read())
            self.assertEqual(result["model"], "local-pretrained")
            self.assertEqual(len(result["data"]), 2)
            self.assertEqual(result["data"][0]["embedding"][0], 1.0)
            self.assertEqual(result["data"][1]["embedding"][1], 1.0)
            connection.close()

            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=4)
            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["status"], "ready")
            connection.close()

            for forbidden_headers, expected in [
                ({"Content-Type": "application/json", "Origin": "https://example.org"}, 403),
                ({"Content-Type": "text/plain"}, 415),
            ]:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=4
                )
                connection.request(
                    "POST", "/v1/embeddings", body=payload, headers=forbidden_headers
                )
                response = connection.getresponse()
                self.assertEqual(response.status, expected)
                response.read()
                connection.close()
        finally:
            server.shutdown()
            thread.join(timeout=4)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
