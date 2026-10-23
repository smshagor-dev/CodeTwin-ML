"""Opt-in real pretrained embedding test; never downloads models during inference.

The ordinary CI runs only a skip. Set the opt-in flag and a local model
directory after explicitly downloading the trusted model yourself.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import unittest

from codetwin_ml.embedding_api import LocalEmbeddingService, load_model


class RealEmbeddingModelTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("CODETWIN_TEST_REAL_EMBEDDINGS") == "1",
        "requires explicit real pretrained model opt-in",
    )
    def test_real_model_determinism_and_distinct_vectors(self) -> None:
        directory = os.environ.get("CODETWIN_TEST_MODEL_DIR")
        if not directory:
            self.fail("Set CODETWIN_TEST_MODEL_DIR to an existing, preloaded model directory")
        model = load_model(Path(directory), "cpu")
        service = LocalEmbeddingService(model, "codetwin-local-embedding")
        result = service.embed({
            "model": "codetwin-local-embedding",
            "input": [
                "Security review of dependencies",
                "The orange cat sleeps on the sofa",
                "Security review of dependencies",
            ],
        })
        vectors = [entry["embedding"] for entry in result["data"]]
        self.assertEqual(len(vectors), 3)
        self.assertEqual(len(vectors[0]), len(vectors[1]))
        self.assertTrue(16 <= len(vectors[0]) <= 3072)
        for vector in vectors:
            self.assertTrue(all(math.isfinite(value) for value in vector))
            self.assertAlmostEqual(sum(value * value for value in vector), 1.0, places=4)
        self.assertAlmostEqual(
            sum(a * b for a, b in zip(vectors[0], vectors[2])), 1.0, places=4
        )
        self.assertLess(
            sum(a * b for a, b in zip(vectors[0], vectors[1])), 0.999
        )
        self.assertEqual(os.environ.get("HF_HUB_OFFLINE"), "1")
        self.assertEqual(os.environ.get("TRANSFORMERS_OFFLINE"), "1")


if __name__ == "__main__":
    unittest.main()
