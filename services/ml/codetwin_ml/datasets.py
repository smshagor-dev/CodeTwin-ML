from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import quote
from urllib.request import Request as UrlRequest, urlopen

CATALOG_SCHEMA_VERSION = 1
USER_AGENT = "CodeTwin-ML/0.1 dataset-prefetch"
CHUNK_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 120

Opener = Callable[..., Any]


class DatasetError(RuntimeError):
    """Base error for dataset catalog, routing, download, or cache failures."""


class DatasetLicenseError(DatasetError):
    """Raised when an upstream dataset requires explicit license acceptance."""


class DatasetIntegrityError(DatasetError):
    """Raised when downloaded bytes do not match pinned catalog metadata."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_catalog_path() -> Path:
    override = os.environ.get("CODETWIN_DATASET_CATALOG")
    return Path(override) if override else _repo_root() / "datasets" / "catalog.json"


def default_cache_root() -> Path:
    override = os.environ.get("CODETWIN_DATASET_CACHE")
    return Path(override) if override else _repo_root() / "datasets" / "cache"


def load_catalog(path: Path | str | None = None) -> dict[str, Any]:
    catalog_path = Path(path) if path is not None else default_catalog_path()
    try:
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DatasetError(f"cannot load dataset catalog: {error}") from error

    if data.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise DatasetError("unsupported dataset catalog schema")
    datasets = data.get("datasets")
    routes = data.get("routes")
    if not isinstance(datasets, list) or not isinstance(routes, dict):
        raise DatasetError("dataset catalog must contain datasets and routes")

    seen: set[str] = set()
    for item in datasets:
        if not isinstance(item, dict):
            raise DatasetError("dataset entries must be objects")
        dataset_id = item.get("id")
        repository = item.get("repository")
        revision = item.get("revision")
        files = item.get("files")
        if (
            not isinstance(dataset_id, str)
            or not dataset_id
            or dataset_id in seen
            or not isinstance(repository, str)
            or "/" not in repository
            or not isinstance(revision, str)
            or not revision
            or not isinstance(files, list)
        ):
            raise DatasetError(f"invalid dataset entry: {dataset_id!r}")
        seen.add(dataset_id)
        for file_spec in files:
            if not isinstance(file_spec, dict) or not isinstance(file_spec.get("path"), str):
                raise DatasetError(f"invalid file entry for dataset: {dataset_id}")
            _safe_relative_path(file_spec["path"])

    for action, routed_ids in routes.items():
        if not isinstance(action, str) or not action or not isinstance(routed_ids, list):
            raise DatasetError("invalid dataset route")
        if any(dataset_id not in seen for dataset_id in routed_ids):
            raise DatasetError(f"route references unknown dataset: {action}")
    return data


def _dataset_map(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in catalog["datasets"]}


def _public_dataset(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": spec["id"],
        "name": spec["name"],
        "repository": spec["repository"],
        "revision": spec["revision"],
        "license": spec["license"],
        "license_url": spec["license_url"],
        "license_acceptance_required": bool(spec["license_acceptance_required"]),
        "purpose": list(spec["purpose"]),
        "download_bytes": spec["download_bytes"],
    }


def list_datasets(catalog_path: Path | str | None = None) -> dict[str, Any]:
    catalog = load_catalog(catalog_path)
    return {
        "schema_version": catalog["schema_version"],
        "estimated_total_download_bytes": catalog["estimated_total_download_bytes"],
        "actions": sorted(catalog["routes"]),
        "datasets": [_public_dataset(item) for item in catalog["datasets"]],
    }


def route_action(action: str, catalog_path: Path | str | None = None) -> dict[str, Any]:
    catalog = load_catalog(catalog_path)
    routed = catalog["routes"].get(action)
    if routed is None:
        raise DatasetError(f"unknown dataset action: {action}")
    datasets = _dataset_map(catalog)
    return {
        "action": action,
        "datasets": [_public_dataset(datasets[dataset_id]) for dataset_id in routed],
    }


def _safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise DatasetError(f"unsafe dataset path: {value}")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_provenance(dataset_root: Path) -> dict[str, Any]:
    path = dataset_root / "_codetwin_source.json"
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _provenance_hash(provenance: dict[str, Any], relative_path: str) -> str | None:
    files = provenance.get("files")
    if not isinstance(files, list):
        return None
    for item in files:
        if isinstance(item, dict) and item.get("path") == relative_path:
            value = item.get("sha256")
            return value if isinstance(value, str) and value else None
    return None


def _file_ready(target: Path, file_spec: dict[str, Any], provenance: dict[str, Any]) -> bool:
    if not target.is_file():
        return False
    expected_size = file_spec.get("size_bytes")
    if isinstance(expected_size, int) and target.stat().st_size != expected_size:
        return False
    expected_hash = file_spec.get("sha256")
    if not isinstance(expected_hash, str) or not expected_hash:
        expected_hash = _provenance_hash(provenance, file_spec["path"])
    if not isinstance(expected_hash, str) or not expected_hash:
        return False
    return _sha256(target) == expected_hash


def dataset_status(
    dataset_id: str | None = None,
    *,
    catalog_path: Path | str | None = None,
    cache_root: Path | str | None = None,
) -> dict[str, Any]:
    catalog = load_catalog(catalog_path)
    datasets = _dataset_map(catalog)
    if dataset_id is not None:
        if dataset_id not in datasets:
            raise DatasetError(f"unknown dataset: {dataset_id}")
        selected = [datasets[dataset_id]]
    else:
        selected = list(catalog["datasets"])
    root = Path(cache_root) if cache_root is not None else default_cache_root()

    results: list[dict[str, Any]] = []
    for spec in selected:
        dataset_root = root / spec["id"] / spec["revision"]
        provenance = _load_provenance(dataset_root)
        files = []
        ready_count = 0
        for file_spec in spec["files"]:
            relative = _safe_relative_path(file_spec["path"])
            target = dataset_root.joinpath(*relative.parts)
            ready = _file_ready(target, file_spec, provenance)
            ready_count += int(ready)
            files.append({
                "path": file_spec["path"],
                "ready": ready,
                "size_bytes": target.stat().st_size if target.is_file() else None,
            })
        results.append({
            "id": spec["id"],
            "revision": spec["revision"],
            "ready": ready_count == len(spec["files"]),
            "ready_files": ready_count,
            "total_files": len(spec["files"]),
            "files": files,
        })
    return {"cache_root": str(root), "datasets": results}


def _download_url(spec: dict[str, Any], relative_path: PurePosixPath) -> str:
    repository = quote(spec["repository"], safe="/")
    revision = quote(spec["revision"], safe="")
    path = "/".join(quote(part, safe="") for part in relative_path.parts)
    return f"https://huggingface.co/datasets/{repository}/resolve/{revision}/{path}?download=true"


def _accepted(accepted_licenses: set[str] | list[str] | tuple[str, ...] | None) -> set[str]:
    if accepted_licenses is None:
        return set()
    return {
        value.strip().lower()
        for value in accepted_licenses
        if isinstance(value, str) and value.strip()
    }


def prefetch_dataset(
    dataset_id: str,
    *,
    accepted_licenses: set[str] | list[str] | tuple[str, ...] | None = None,
    catalog_path: Path | str | None = None,
    cache_root: Path | str | None = None,
    opener: Opener = urlopen,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    catalog = load_catalog(catalog_path)
    datasets = _dataset_map(catalog)
    spec = datasets.get(dataset_id)
    if spec is None:
        raise DatasetError(f"unknown dataset: {dataset_id}")

    license_id = str(spec["license"]).lower()
    if spec["license_acceptance_required"] and license_id not in _accepted(accepted_licenses):
        raise DatasetLicenseError(
            f"{dataset_id} requires acceptance of {spec['license']} ({spec['license_url']})"
        )

    root = Path(cache_root) if cache_root is not None else default_cache_root()
    dataset_root = root / spec["id"] / spec["revision"]
    dataset_root.mkdir(parents=True, exist_ok=True)
    provenance = _load_provenance(dataset_root)
    downloaded_files: list[dict[str, Any]] = []
    downloaded = 0
    reused = 0

    for file_spec in spec["files"]:
        relative = _safe_relative_path(file_spec["path"])
        target = dataset_root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if _file_ready(target, file_spec, provenance):
            reused += 1
            downloaded_files.append({
                "path": file_spec["path"],
                "size_bytes": target.stat().st_size,
                "sha256": _sha256(target),
            })
            continue

        part = target.with_name(target.name + ".part")
        try:
            part.unlink(missing_ok=True)
            request = UrlRequest(_download_url(spec, relative), headers={"User-Agent": USER_AGENT})
            digest = hashlib.sha256()
            size = 0
            with opener(request, timeout=timeout_seconds) as response, part.open("wb") as output:
                while True:
                    chunk = response.read(CHUNK_BYTES)
                    if not chunk:
                        break
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
            actual_hash = digest.hexdigest()
            expected_size = file_spec.get("size_bytes")
            expected_hash = file_spec.get("sha256")
            if isinstance(expected_size, int) and size != expected_size:
                raise DatasetIntegrityError(
                    f"size mismatch for {dataset_id}/{file_spec['path']}: expected {expected_size}, got {size}"
                )
            if isinstance(expected_hash, str) and expected_hash and actual_hash != expected_hash:
                raise DatasetIntegrityError(f"sha256 mismatch for {dataset_id}/{file_spec['path']}")
            os.replace(part, target)
            downloaded += 1
            downloaded_files.append({
                "path": file_spec["path"],
                "size_bytes": size,
                "sha256": actual_hash,
            })
        except Exception:
            part.unlink(missing_ok=True)
            raise

    source_record = {
        "schema_version": 1,
        "dataset_id": spec["id"],
        "repository": spec["repository"],
        "revision": spec["revision"],
        "license": spec["license"],
        "license_url": spec["license_url"],
        "source": "huggingface",
        "files": downloaded_files,
    }
    provenance_path = dataset_root / "_codetwin_source.json"
    temporary_provenance = provenance_path.with_suffix(".json.part")
    temporary_provenance.write_text(
        json.dumps(source_record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_provenance, provenance_path)
    status = dataset_status(dataset_id, catalog_path=catalog_path, cache_root=root)["datasets"][0]
    return {
        "dataset": status,
        "downloaded_files": downloaded,
        "reused_files": reused,
        "source": source_record,
    }


def prefetch_action(
    action: str,
    *,
    accepted_licenses: set[str] | list[str] | tuple[str, ...] | None = None,
    catalog_path: Path | str | None = None,
    cache_root: Path | str | None = None,
    opener: Opener = urlopen,
) -> dict[str, Any]:
    route = route_action(action, catalog_path)
    return {
        "action": action,
        "results": [
            prefetch_dataset(
                item["id"],
                accepted_licenses=accepted_licenses,
                catalog_path=catalog_path,
                cache_root=cache_root,
                opener=opener,
            )
            for item in route["datasets"]
        ],
    }


def prefetch_all(
    *,
    accepted_licenses: set[str] | list[str] | tuple[str, ...] | None = None,
    catalog_path: Path | str | None = None,
    cache_root: Path | str | None = None,
    opener: Opener = urlopen,
) -> dict[str, Any]:
    catalog = load_catalog(catalog_path)
    return {
        "results": [
            prefetch_dataset(
                item["id"],
                accepted_licenses=accepted_licenses,
                catalog_path=catalog_path,
                cache_root=cache_root,
                opener=opener,
            )
            for item in catalog["datasets"]
        ]
    }
