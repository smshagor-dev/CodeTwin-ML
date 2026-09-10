from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ML_ROOT = ROOT / "services" / "ml"
if str(ML_ROOT) not in sys.path:
    sys.path.insert(0, str(ML_ROOT))

from codetwin_ml.datasets import load_catalog, prefetch_dataset  # noqa: E402

CHUNK_BYTES = 1024 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_release_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1:
        raise ValueError("unsupported OpenMindAI dataset release schema")
    assets = value.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError("release config must contain assets")
    return value


def write_notice(dataset_root: Path, spec: dict[str, Any], display_name: str) -> None:
    lines = [
        display_name,
        "",
        f"Upstream dataset: https://huggingface.co/datasets/{spec['repository']}",
        f"Pinned revision: {spec['revision']}",
        f"License/terms identifier: {spec['license']}",
        f"Terms: {spec['license_url']}",
        "",
        "This release asset is a convenience mirror for computational use by CodeTwin ML.",
        "Upstream attribution and use restrictions remain applicable.",
    ]
    if str(spec["license"]).lower() == "c-uda":
        lines += [
            "",
            "C-UDA notice:",
            "Use is limited to computational use. Redistribution must preserve upstream",
            "credit/attribution and bind downstream recipients to the C-UDA terms.",
        ]
    if spec["id"] == "swe_bench_verified":
        lines += [
            "",
            "SWE-bench project notice:",
            "The SWE-bench project publishes its software and benchmark project under MIT.",
            "Issue, patch, repository, and other third-party material can retain upstream terms.",
        ]
    (dataset_root / "_OPENMINDAI_DATASET_NOTICE.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def archive_tree(source_root: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as output:
        for path in sorted(source_root.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(source_root).as_posix())


def build(output_dir: Path, release_config_path: Path) -> dict[str, Any]:
    release = load_release_config(release_config_path)
    catalog = load_catalog(ROOT / "datasets" / "catalog.json")
    catalog_by_id = {item["id"]: item for item in catalog["datasets"]}
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_assets: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="openmindai-datasets-") as temporary:
        cache_root = Path(temporary) / "cache"
        package_root = Path(temporary) / "packages"

        for asset in release["assets"]:
            dataset_id = asset["dataset_id"]
            spec = catalog_by_id.get(dataset_id)
            if spec is None:
                raise ValueError(f"release references unknown dataset: {dataset_id}")

            prefetch_dataset(
                dataset_id,
                accepted_licenses={"c-uda", "upstream-unspecified"},
                catalog_path=ROOT / "datasets" / "catalog.json",
                cache_root=cache_root,
            )

            source = cache_root / dataset_id / spec["revision"]
            staged_revision = package_root / dataset_id / spec["revision"]
            staged_revision.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, staged_revision)
            write_notice(staged_revision, spec, asset["display_name"])

            archive = output_dir / asset["asset_name"]
            archive_tree(package_root / dataset_id, archive)
            shutil.rmtree(package_root / dataset_id)

            manifest_assets.append(
                {
                    "dataset_id": dataset_id,
                    "display_name": asset["display_name"],
                    "asset_name": asset["asset_name"],
                    "size_bytes": archive.stat().st_size,
                    "sha256": sha256(archive),
                    "license": spec["license"],
                    "license_url": spec["license_url"],
                    "license_acceptance_required": bool(spec["license_acceptance_required"]),
                    "purpose": list(spec["purpose"]),
                    "source_repository": spec["repository"],
                    "source_revision": spec["revision"],
                }
            )

    manifest = {
        "schema_version": 1,
        "brand": "OpenMindAI Dataset",
        "release_tag": release["release_tag"],
        "release_name": release["release_name"],
        "catalog_schema_version": catalog["schema_version"],
        "assets": manifest_assets,
        "routes": catalog["routes"],
    }
    manifest_path = output_dir / release["manifest_asset"]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    checksums = output_dir / "openmindai-dataset-SHA256SUMS.txt"
    files = [manifest_path, *[output_dir / item["asset_name"] for item in release["assets"]]]
    checksums.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in files), encoding="utf-8"
    )

    notes = output_dir / "RELEASE_NOTES.md"
    total_bytes = sum(item["size_bytes"] for item in manifest_assets)
    notes.write_text(
        "# OpenMindAI Dataset v1.0.0\n\n"
        "Prebuilt CodeTwin ML dataset assets for install-time bootstrap and action-wise routing.\n\n"
        f"Packaged bytes: {total_bytes}\n\n"
        "The two CodeXGLUE assets are governed by C-UDA and are limited to computational use. "
        "Installers must obtain acceptance before installing those assets. Upstream attribution "
        "and license notices are embedded in every dataset package.\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build OpenMindAI Dataset GitHub release assets")
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "openmindai-datasets")
    parser.add_argument(
        "--release-config",
        type=Path,
        default=ROOT / "datasets" / "openmindai-release.json",
    )
    args = parser.parse_args()
    manifest = build(args.output, args.release_config)
    print(json.dumps({"release_tag": manifest["release_tag"], "assets": len(manifest["assets"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
