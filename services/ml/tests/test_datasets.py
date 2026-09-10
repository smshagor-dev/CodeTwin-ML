import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_ml.datasets import (  # noqa: E402
    DatasetError,
    DatasetLicenseError,
    dataset_status,
    load_catalog,
    prefetch_dataset,
    route_action,
)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


class DatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.cache = self.root / "cache"
        self.catalog = self.root / "catalog.json"
        self.payload = b"parquet-fixture"
        digest = hashlib.sha256(self.payload).hexdigest()
        self.catalog.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "estimated_total_download_bytes": len(self.payload),
                    "datasets": [
                        {
                            "id": "fixture",
                            "name": "Fixture",
                            "repository": "example/fixture",
                            "revision": "abc123",
                            "license": "fixture-license",
                            "license_url": "https://example.invalid/license",
                            "license_acceptance_required": True,
                            "purpose": ["quality_assurance", "repair_verification"],
                            "download_bytes": len(self.payload),
                            "files": [
                                {
                                    "path": "data/train.parquet",
                                    "size_bytes": len(self.payload),
                                    "sha256": digest,
                                }
                            ],
                        }
                    ],
                    "routes": {
                        "quality_assurance": ["fixture"],
                        "repair_verification": ["fixture"],
                    },
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def opener(self, request, timeout=0):
        self.assertTrue(
            request.full_url.startswith(
                "https://huggingface.co/datasets/example/fixture/resolve/abc123/"
            )
        )
        self.assertGreater(timeout, 0)
        return FakeResponse(self.payload)

    def test_prefetch_verifies_and_reuses_cached_file(self) -> None:
        first = prefetch_dataset(
            "fixture",
            accepted_licenses=["fixture-license"],
            catalog_path=self.catalog,
            cache_root=self.cache,
            opener=self.opener,
        )
        self.assertEqual(first["downloaded_files"], 1)
        self.assertTrue(first["dataset"]["ready"])

        def must_not_download(*args, **kwargs):
            raise AssertionError("cache hit attempted a network download")

        second = prefetch_dataset(
            "fixture",
            accepted_licenses=["fixture-license"],
            catalog_path=self.catalog,
            cache_root=self.cache,
            opener=must_not_download,
        )
        self.assertEqual(second["downloaded_files"], 0)
        self.assertEqual(second["reused_files"], 1)
        status = dataset_status(
            "fixture", catalog_path=self.catalog, cache_root=self.cache
        )["datasets"][0]
        self.assertTrue(status["ready"])

    def test_required_license_must_be_explicitly_accepted(self) -> None:
        with self.assertRaises(DatasetLicenseError):
            prefetch_dataset(
                "fixture",
                catalog_path=self.catalog,
                cache_root=self.cache,
                opener=self.opener,
            )

    def test_route_order_is_catalog_order(self) -> None:
        result = route_action("quality_assurance", self.catalog)
        self.assertEqual([item["id"] for item in result["datasets"]], ["fixture"])

    def test_unknown_action_is_rejected(self) -> None:
        with self.assertRaises(DatasetError):
            route_action("unknown", self.catalog)

    def test_path_traversal_is_rejected_during_catalog_validation(self) -> None:
        data = json.loads(self.catalog.read_text(encoding="utf-8"))
        data["datasets"][0]["files"][0]["path"] = "../escape.parquet"
        self.catalog.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(DatasetError):
            load_catalog(self.catalog)


if __name__ == "__main__":
    unittest.main()
