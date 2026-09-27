import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]

_BUILDER_SPEC = importlib.util.spec_from_file_location(
    "build_openmindai_dataset_release",
    ROOT / "scripts" / "build_openmindai_dataset_release.py",
)
if _BUILDER_SPEC is None or _BUILDER_SPEC.loader is None:
    raise RuntimeError("could not load OpenMindAI Dataset release builder")
_BUILDER = importlib.util.module_from_spec(_BUILDER_SPEC)
_BUILDER_SPEC.loader.exec_module(_BUILDER)


class OpenMindAIDatasetReleaseTests(unittest.TestCase):
    def test_release_config_matches_catalog(self) -> None:
        catalog = json.loads((ROOT / "datasets" / "catalog.json").read_text(encoding="utf-8"))
        release = json.loads(
            (ROOT / "datasets" / "openmindai-release.json").read_text(encoding="utf-8")
        )

        self.assertEqual(catalog["brand"], "OpenMindAI Dataset")
        self.assertEqual(catalog["release_tag"], release["release_tag"])
        self.assertEqual(release["release_name"], "OpenMindAI Dataset v1.0.0")

        catalog_ids = {item["id"] for item in catalog["datasets"]}
        release_ids = {item["dataset_id"] for item in release["assets"]}
        self.assertEqual(catalog_ids, release_ids)
        self.assertEqual(len(release_ids), 4)

    def test_all_public_names_and_assets_use_openmindai_dataset_brand(self) -> None:
        catalog = json.loads((ROOT / "datasets" / "catalog.json").read_text(encoding="utf-8"))
        asset_names = set()
        for dataset in catalog["datasets"]:
            self.assertTrue(dataset["name"].startswith("OpenMindAI Dataset"))
            asset = dataset["release_asset"]
            self.assertTrue(asset.startswith("openmindai-dataset-"))
            self.assertTrue(asset.endswith(".zip"))
            self.assertNotIn(asset, asset_names)
            asset_names.add(asset)

    def test_release_source_integrity_requires_full_revision_size_and_sha256(self) -> None:
        release = {
            "assets": [
                {
                    "dataset_id": "fixture",
                    "display_name": "OpenMindAI Dataset - Fixture",
                    "asset_name": "openmindai-dataset-fixture-v1.0.0.zip",
                }
            ]
        }
        catalog = {
            "datasets": [
                {
                    "id": "fixture",
                    "revision": "abc1234",
                    "files": [
                        {
                            "path": "data/train.parquet",
                            "size_bytes": None,
                            "sha256": None,
                        }
                    ],
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "integrity metadata is incomplete"):
            _BUILDER.validate_release_source_integrity(catalog, release)

        catalog["datasets"][0]["revision"] = "a" * 40
        catalog["datasets"][0]["files"][0]["size_bytes"] = 123
        catalog["datasets"][0]["files"][0]["sha256"] = "b" * 64
        _BUILDER.validate_release_source_integrity(catalog, release)

    def test_windows_installer_requires_terms_and_integrity_verification(self) -> None:
        script = (
            ROOT
            / "apps"
            / "desktop"
            / "src-tauri"
            / "windows"
            / "install-openmindai-datasets.ps1"
        ).read_text(encoding="utf-8")
        hook = (
            ROOT / "apps" / "desktop" / "src-tauri" / "windows" / "hooks.nsh"
        ).read_text(encoding="utf-8")

        self.assertIn("AcceptDatasetTerms", script)
        self.assertIn("Get-FileHash -Algorithm SHA256", script)
        self.assertIn("openmindai-datasets-v1.0.0", script)
        self.assertIn("NSIS_HOOK_POSTINSTALL", hook)
        self.assertIn("IfSilent codetwin_dataset_skipped 0", hook)
        self.assertLess(
            hook.index("IfSilent codetwin_dataset_skipped 0"),
            hook.index("MB_YESNO"),
            "silent base installs must skip the dataset terms prompt before any acceptance UI",
        )
        self.assertIn("MB_YESNO", hook)
        self.assertIn("MB_RETRYCANCEL", hook)
        self.assertIn("IDRETRY codetwin_dataset_retry", hook)
        self.assertIn("IDCANCEL codetwin_dataset_skipped", hook)
        self.assertIn("openmindai-datasets-v1.0.0", hook)


if __name__ == "__main__":
    unittest.main()
