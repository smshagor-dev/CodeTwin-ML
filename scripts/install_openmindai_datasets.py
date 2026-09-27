#!/usr/bin/env python3
"""Install the OpenMindAI Dataset pack from a GitHub Release (macOS, Linux and Windows).

This is the cross-platform counterpart of the Windows installer hook
(`apps/desktop/src-tauri/windows/install-openmindai-datasets.ps1`). It follows the same steps:
download the release manifest, download every dataset archive, check each archive's size and
SHA-256, extract into a staging directory, and swap the whole set into place only after all
archives validate. It writes `openmindai-dataset-install-state.json` on success.

Two datasets use C-UDA (computational use only), so the terms must be accepted explicitly:

    python3 scripts/install_openmindai_datasets.py --accept-dataset-terms

The default install directory is the one the desktop app's Dataset Benchmarks tab looks in.
Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.request import Request, urlopen

DEFAULT_RELEASE_TAG = "openmindai-datasets-v1.0.0"
DEFAULT_REPOSITORY = "smshagor-dev/CodeTwin-ML"
MANIFEST_NAME = "openmindai-dataset-manifest-v1.0.0.json"
STATE_NAME = "openmindai-dataset-install-state.json"
EXPECTED_ASSETS = 4
USER_AGENT = "CodeTwin-ML-Installer/0.1"
CHUNK_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
TERMS_NOTICE = (
    "Two CodeXGLUE datasets use the C-UDA and are limited to computational use "
    "(https://spdx.org/licenses/C-UDA-1.0.html). SWE-bench tasks can contain third-party "
    "repository material under upstream terms. Upstream attribution and redistribution terms "
    "remain applicable."
)

Opener = Callable[..., Any]

REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TAG_PATTERN = re.compile(r"^openmindai-datasets-v[0-9]+\.[0-9]+\.[0-9]+$")
ASSET_PATTERN = re.compile(r"^openmindai-dataset-[A-Za-z0-9._-]+\.(zip|json|txt)$")
DATASET_ID_PATTERN = re.compile(r"^[a-z0-9_]+$")


class InstallError(RuntimeError):
    pass


def default_install_root() -> Path:
    """Matches `default_datasets_root` in the desktop app."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise InstallError("LOCALAPPDATA is not set; pass --install-root")
        return Path(base) / "CodeTwinML" / "datasets"
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "CodeTwinML" / "datasets"
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg and Path(xdg).is_absolute() else home / ".local" / "share"
    return base / "CodeTwinML" / "datasets"


def _safe_asset_name(name: object) -> str:
    if (
        not isinstance(name, str)
        or not ASSET_PATTERN.match(name)
        or ".." in name
        or "/" in name
        or "\\" in name
    ):
        raise InstallError(f"unsafe OpenMindAI Dataset asset name: {name!r}")
    return name


def _download(
    url: str,
    destination: Path,
    opener: Opener,
    *,
    attempts: int = 3,
    max_bytes: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    for attempt in range(1, attempts + 1):
        print(f"Downloading {url} (attempt {attempt}/{attempts})", flush=True)
        try:
            request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/octet-stream"})
            size = 0
            with opener(request, timeout=300) as response, destination.open("wb") as output:
                while True:
                    chunk = response.read(CHUNK_BYTES)
                    if not chunk:
                        break
                    size += len(chunk)
                    if max_bytes is not None and size > max_bytes:
                        raise InstallError(f"{url} is larger than {max_bytes} bytes")
                    output.write(chunk)
            return
        except InstallError:
            destination.unlink(missing_ok=True)
            raise
        except Exception as error:  # network errors are retried
            destination.unlink(missing_ok=True)
            if attempt >= attempts:
                raise InstallError(f"download failed: {url}: {error}") from error
            sleep(float(2**attempt))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(archive: Path, destination: Path) -> None:
    """Extracts after checking every member stays inside `destination` (no absolute paths,
    `..`, backslashes or symlinks)."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = member.filename
            parts = PurePosixPath(name).parts
            mode = member.external_attr >> 16
            if (
                not name
                or name.startswith("/")
                or "\\" in name
                or any(part in {"", ".", ".."} for part in parts)
                or (mode & 0o170000) == 0o120000
            ):
                raise InstallError(f"unsafe path in {archive.name}: {name!r}")
        bundle.extractall(destination)


def _load_manifest(path: Path, release_tag: str) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallError(f"unreadable release manifest: {error}") from error
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or manifest.get("brand") != "OpenMindAI Dataset"
    ):
        raise InstallError("unsupported OpenMindAI Dataset release manifest")
    if manifest.get("release_tag") != release_tag:
        raise InstallError("release manifest tag mismatch")
    assets = manifest.get("assets")
    if not isinstance(assets, list) or len(assets) != EXPECTED_ASSETS:
        raise InstallError(f"release must contain exactly {EXPECTED_ASSETS} dataset assets")
    for asset in assets:
        if not isinstance(asset, dict):
            raise InstallError("invalid asset entry in release manifest")
        _safe_asset_name(asset.get("asset_name"))
        dataset_id = asset.get("dataset_id")
        if not isinstance(dataset_id, str) or not DATASET_ID_PATTERN.match(dataset_id):
            raise InstallError(f"unsafe dataset id: {dataset_id!r}")
        if not str(asset.get("display_name", "")).startswith("OpenMindAI Dataset"):
            raise InstallError(f"dataset branding mismatch for {dataset_id}")
        if not isinstance(asset.get("size_bytes"), int) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", str(asset.get("sha256", ""))
        ):
            raise InstallError(f"missing size or SHA-256 for {dataset_id}")
    return manifest


def install(
    install_root: Path,
    *,
    accept_terms: bool,
    release_tag: str = DEFAULT_RELEASE_TAG,
    repository: str = DEFAULT_REPOSITORY,
    opener: Opener = urlopen,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if not accept_terms:
        raise InstallError("OpenMindAI Dataset terms must be accepted before installation")
    if not REPOSITORY_PATTERN.match(repository):
        raise InstallError("invalid release repository")
    if not TAG_PATTERN.match(release_tag):
        raise InstallError("invalid OpenMindAI Dataset release tag")

    release_base = f"https://github.com/{repository}/releases/download/{release_tag}"
    install_root.mkdir(parents=True, exist_ok=True)
    # Stage next to the install root so the final moves are same-filesystem renames.
    with tempfile.TemporaryDirectory(prefix=".openmindai-install-", dir=install_root.parent) as temporary:
        temp_root = Path(temporary)
        downloads, staging, backup = temp_root / "downloads", temp_root / "staging", temp_root / "backup"
        for directory in (downloads, staging, backup):
            directory.mkdir()

        manifest_path = downloads / MANIFEST_NAME
        _download(f"{release_base}/{MANIFEST_NAME}", manifest_path, opener, max_bytes=MAX_MANIFEST_BYTES, sleep=sleep)
        manifest = _load_manifest(manifest_path, release_tag)

        for asset in manifest["assets"]:
            name = asset["asset_name"]
            archive = downloads / name
            _download(f"{release_base}/{name}", archive, opener, max_bytes=asset["size_bytes"], sleep=sleep)
            if archive.stat().st_size != asset["size_bytes"]:
                raise InstallError(f"size mismatch for {name}")
            if _sha256(archive) != str(asset["sha256"]).lower():
                raise InstallError(f"SHA-256 mismatch for {name}")
            _extract(archive, staging / asset["dataset_id"])
            archive.unlink()

        replaced: list[str] = []
        try:
            for asset in manifest["assets"]:
                dataset_id = asset["dataset_id"]
                target = install_root / dataset_id
                if target.exists():
                    os.replace(target, backup / dataset_id)
                os.replace(staging / dataset_id, target)
                replaced.append(dataset_id)
        except OSError as error:
            for dataset_id in replaced:
                shutil.rmtree(install_root / dataset_id, ignore_errors=True)
            for dataset_id in [a["dataset_id"] for a in manifest["assets"]]:
                previous = backup / dataset_id
                if previous.exists() and not (install_root / dataset_id).exists():
                    os.replace(previous, install_root / dataset_id)
            raise InstallError(f"could not move datasets into place: {error}") from error

    state = {
        "schema_version": 1,
        "brand": "OpenMindAI Dataset",
        "release_tag": release_tag,
        "installed_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_count": len(manifest["assets"]),
        "dataset_terms_accepted": True,
        "assets": [
            {
                "dataset_id": asset["dataset_id"],
                "display_name": asset["display_name"],
                "asset_name": asset["asset_name"],
                "sha256": asset["sha256"],
            }
            for asset in manifest["assets"]
        ],
    }
    state_path = install_root / STATE_NAME
    partial = state_path.with_suffix(".json.part")
    partial.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.replace(partial, state_path)
    return state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--install-root", type=Path, help="default: the desktop app's dataset directory")
    parser.add_argument("--release-tag", default=DEFAULT_RELEASE_TAG)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument(
        "--accept-dataset-terms",
        action="store_true",
        help="accept the upstream dataset terms (C-UDA for the CodeXGLUE datasets)",
    )
    args = parser.parse_args(argv)
    if not args.accept_dataset_terms:
        print(TERMS_NOTICE, file=sys.stderr)
        print("Re-run with --accept-dataset-terms to download the dataset pack.", file=sys.stderr)
        return 2
    try:
        root = args.install_root or default_install_root()
        state = install(
            root,
            accept_terms=True,
            release_tag=args.release_tag,
            repository=args.repository,
        )
    except InstallError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"OpenMindAI Dataset installation complete: {root} ({state['dataset_count']} datasets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
