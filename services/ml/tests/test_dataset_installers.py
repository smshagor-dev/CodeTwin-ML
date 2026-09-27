import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import zipfile
from types import ModuleType
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[3]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSTALLER = _load("install_openmindai_datasets")
PINNER = _load("pin_hf_dataset")


class FakeResponse(io.BytesIO):
    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class FakeOpener:
    def __init__(self, routes: dict[str, bytes]) -> None:
        self.routes = routes
        self.urls: list[str] = []

    def __call__(self, request: Any, timeout: int = 0) -> FakeResponse:
        url = request.full_url
        self.urls.append(url)
        if url not in self.routes:
            raise OSError(f"no route for {url}")
        return FakeResponse(self.routes[url])


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, data in members.items():
            bundle.writestr(name, data)
    return buffer.getvalue()


IDS = ["alpha", "beta", "gamma", "delta"]
TAG = "openmindai-datasets-v1.0.0"
BASE = f"https://github.com/smshagor-dev/CodeTwin-ML/releases/download/{TAG}"


def _release(archives: dict[str, bytes]) -> dict[str, bytes]:
    assets = []
    routes: dict[str, bytes] = {}
    for dataset_id, archive in archives.items():
        name = f"openmindai-dataset-{dataset_id}-v1.0.0.zip"
        assets.append({
            "dataset_id": dataset_id,
            "display_name": f"OpenMindAI Dataset - {dataset_id}",
            "asset_name": name,
            "size_bytes": len(archive),
            "sha256": hashlib.sha256(archive).hexdigest(),
        })
        routes[f"{BASE}/{name}"] = archive
    manifest = {"schema_version": 1, "brand": "OpenMindAI Dataset", "release_tag": TAG, "assets": assets}
    routes[f"{BASE}/{INSTALLER.MANIFEST_NAME}"] = json.dumps(manifest).encode()
    return routes


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name) / "datasets"
        self.archives = {
            dataset_id: _zip({"rev1/data/test-00000-of-00001.parquet": dataset_id.encode()})
            for dataset_id in IDS
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_installs_all_assets_and_writes_state(self) -> None:
        state = INSTALLER.install(self.root, accept_terms=True, opener=FakeOpener(_release(self.archives)))
        self.assertEqual(state["dataset_count"], 4)
        for dataset_id in IDS:
            parquet = self.root / dataset_id / "rev1" / "data" / "test-00000-of-00001.parquet"
            self.assertEqual(parquet.read_bytes(), dataset_id.encode())
        saved = json.loads((self.root / INSTALLER.STATE_NAME).read_text())
        self.assertTrue(saved["dataset_terms_accepted"])
        leftovers = [p.name for p in self.root.parent.iterdir() if p.name.startswith(".openmindai-install-")]
        self.assertEqual(leftovers, [])

    def test_requires_terms(self) -> None:
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.install(self.root, accept_terms=False, opener=FakeOpener({}))
        self.assertEqual(INSTALLER.main(["--install-root", str(self.root)]), 2)

    def test_checksum_failure_keeps_previous_install(self) -> None:
        previous = self.root / "alpha" / "rev0"
        previous.mkdir(parents=True)
        (previous / "keep.txt").write_text("old")
        routes = _release(self.archives)
        name = "openmindai-dataset-gamma-v1.0.0.zip"
        routes[f"{BASE}/{name}"] = _zip({"rev1/data/test-00000-of-00001.parquet": b"GAMMA"})
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.install(self.root, accept_terms=True, opener=FakeOpener(routes), sleep=lambda _: None)
        self.assertEqual((previous / "keep.txt").read_text(), "old")
        self.assertFalse((self.root / "beta").exists())
        self.assertFalse((self.root / INSTALLER.STATE_NAME).exists())

    def test_rejects_path_traversal_archives(self) -> None:
        self.archives["beta"] = _zip({"../escape.txt": b"x"})
        with self.assertRaises(INSTALLER.InstallError) as raised:
            INSTALLER.install(self.root, accept_terms=True, opener=FakeOpener(_release(self.archives)))
        self.assertIn("unsafe path", str(raised.exception))
        self.assertFalse((self.root.parent / "escape.txt").exists())

    def test_rejects_unsafe_manifest(self) -> None:
        routes = _release(self.archives)
        manifest = json.loads(routes[f"{BASE}/{INSTALLER.MANIFEST_NAME}"])
        manifest["assets"][0]["asset_name"] = "../evil.zip"
        routes[f"{BASE}/{INSTALLER.MANIFEST_NAME}"] = json.dumps(manifest).encode()
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.install(self.root, accept_terms=True, opener=FakeOpener(routes))
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.install(self.root, accept_terms=True, release_tag="v1", opener=FakeOpener(routes))

    def test_download_retries_then_fails(self) -> None:
        opener = FakeOpener({})
        with self.assertRaises(INSTALLER.InstallError):
            INSTALLER.install(self.root, accept_terms=True, opener=opener, sleep=lambda _: None)
        self.assertEqual(len(opener.urls), 3)


SHA = "a" * 40


class PinTests(unittest.TestCase):
    def test_pins_lfs_and_small_files(self) -> None:
        small = b"id,code\n"
        big_hash = "b" * 64
        routes = {
            f"{PINNER.HUB}/api/datasets/owner/data/revision/main": json.dumps({"sha": SHA}).encode(),
            f"{PINNER.HUB}/api/datasets/owner/data/tree/{SHA}?recursive=true": json.dumps([
                {"type": "directory", "path": "data"},
                {"type": "file", "path": "data/test-00000-of-00001.parquet", "size": 134, "lfs": {"oid": big_hash, "size": 9000}},
                {"type": "file", "path": "data/meta.parquet", "size": len(small), "oid": "c" * 40},
                {"type": "file", "path": "README.md", "size": 10},
            ]).encode(),
            f"{PINNER.HUB}/datasets/owner/data/resolve/{SHA}/data/meta.parquet?download=true": small,
        }
        entry = PINNER.pin(
            "owner/data",
            dataset_id="owner_data",
            name="OpenMindAI Dataset - Owner",
            license_id="apache-2.0",
            license_url="https://www.apache.org/licenses/LICENSE-2.0",
            purposes=["vulnerability_detection"],
            include=["data/*.parquet"],
            task="vulnerability_detection",
            opener=FakeOpener(routes),
        )
        self.assertEqual(entry["revision"], SHA)
        self.assertFalse(entry["license_acceptance_required"])
        self.assertEqual(entry["benchmark"], {"task": "vulnerability_detection"})
        by_path = {item["path"]: item for item in entry["files"]}
        self.assertEqual(set(by_path), {"data/meta.parquet", "data/test-00000-of-00001.parquet"})
        self.assertEqual(by_path["data/test-00000-of-00001.parquet"]["size_bytes"], 9000)
        self.assertEqual(by_path["data/test-00000-of-00001.parquet"]["sha256"], big_hash)
        self.assertEqual(by_path["data/meta.parquet"]["sha256"], hashlib.sha256(small).hexdigest())
        self.assertEqual(entry["download_bytes"], 9000 + len(small))

    def test_rejects_bad_input(self) -> None:
        with self.assertRaises(PINNER.PinError):
            PINNER.pin("not-a-repo", dataset_id="x", name="n", license_id="mit", license_url="u",
                       purposes=["p"], include=["*"], opener=FakeOpener({}))
        routes = {f"{PINNER.HUB}/api/datasets/owner/data/revision/main": json.dumps({"sha": "nope"}).encode()}
        with self.assertRaises(PINNER.PinError):
            PINNER.pin("owner/data", dataset_id="x", name="n", license_id="mit", license_url="u",
                       purposes=["p"], include=["*"], opener=FakeOpener(routes))


if __name__ == "__main__":
    unittest.main()
