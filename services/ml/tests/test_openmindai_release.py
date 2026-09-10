import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


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
        self.assertIn("MB_YESNO", hook)
        self.assertIn("NSIS_HOOK_POSTINSTALL", hook)
        self.assertIn("openmindai-datasets-v1.0.0", hook)


if __name__ == "__main__":
    unittest.main()
