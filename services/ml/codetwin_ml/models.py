from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from codetwin_ml.datasets import load_catalog

MODEL_SCHEMA_VERSION = 1
MODEL_METADATA_FILE = "_codetwin_model.json"
CHUNK_BYTES = 1024 * 1024
SUPPORTED_BACKENDS = frozenset({"onnx-classification-v1", "onnx-seq2seq-v1"})
EXECUTION_BACKENDS = frozenset({"onnx-classification-v1"})
MAX_EXECUTION_INPUT_BYTES = 65_536
MAX_EXECUTION_LABELS = 256
MAX_ONNX_MODEL_BYTES = 512 * 1024 * 1024
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ModelError(RuntimeError):
    """Base error for model package, registry, or routing failures."""


class ModelManifestError(ModelError):
    """Raised when a model package manifest violates the registry contract."""


class ModelIntegrityError(ModelError):
    """Raised when model package bytes do not match their manifest."""


class ModelLicenseError(ModelError):
    """Raised when a model package requires explicit license acceptance."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def default_model_root() -> Path:
    override = os.environ.get("CODETWIN_MODEL_CACHE")
    return Path(override) if override else _repo_root() / "models" / "cache"


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise ModelManifestError(f"{field} must match {_ID_PATTERN.pattern}")
    return value


def _safe_relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise ModelManifestError("model artifact path must be a string")
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ModelManifestError(f"unsafe model artifact path: {value!r}")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_package_file(package_root: Path, relative: PurePosixPath) -> Path:
    candidate = package_root.joinpath(*relative.parts)
    if candidate.is_symlink():
        raise ModelIntegrityError(f"model package artifact must not be a symlink: {relative}")
    if not candidate.is_file():
        raise ModelIntegrityError(f"model package artifact is missing: {relative}")
    try:
        root = package_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ModelIntegrityError(f"cannot resolve model package artifact {relative}: {error}") from error
    if resolved.parent != root and root not in resolved.parents:
        raise ModelIntegrityError(f"model package artifact escapes package root: {relative}")
    return resolved


def _validate_metrics(value: Any) -> dict[str, float]:
    if not isinstance(value, dict) or not value:
        raise ModelManifestError("evaluation metrics must be a non-empty object")
    result: dict[str, float] = {}
    for key, raw in value.items():
        if not isinstance(key, str) or not key:
            raise ModelManifestError("evaluation metric names must be non-empty strings")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(float(raw)):
            raise ModelManifestError(f"evaluation metric {key!r} must be a finite number")
        result[key] = float(raw)
    return result


def _validate_inference_contract(value: Any, backend: str, model_size: int) -> dict[str, Any] | None:
    if value is None:
        return None
    if backend not in EXECUTION_BACKENDS:
        raise ModelManifestError(f"backend does not support local execution yet: {backend}")
    if model_size > MAX_ONNX_MODEL_BYTES:
        raise ModelManifestError(
            f"executable ONNX model exceeds the {MAX_ONNX_MODEL_BYTES}-byte limit"
        )
    if not isinstance(value, dict):
        raise ModelManifestError("inference must be an object")

    preprocessing = value.get("preprocessing")
    output = value.get("output")
    if not isinstance(preprocessing, dict) or not isinstance(output, dict):
        raise ModelManifestError("inference requires preprocessing and output objects")
    if preprocessing.get("kind") != "utf8-bytes-v1":
        raise ModelManifestError("only utf8-bytes-v1 preprocessing is supported")
    input_name = preprocessing.get("input_name")
    max_bytes = preprocessing.get("max_bytes")
    if not isinstance(input_name, str) or not input_name or len(input_name) > 128:
        raise ModelManifestError("inference.preprocessing.input_name must be 1-128 characters")
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 1
        or max_bytes > MAX_EXECUTION_INPUT_BYTES
    ):
        raise ModelManifestError(
            f"inference.preprocessing.max_bytes must be between 1 and {MAX_EXECUTION_INPUT_BYTES}"
        )

    output_name = output.get("name")
    labels = output.get("labels")
    if not isinstance(output_name, str) or not output_name or len(output_name) > 128:
        raise ModelManifestError("inference.output.name must be 1-128 characters")
    if (
        not isinstance(labels, list)
        or len(labels) < 2
        or len(labels) > MAX_EXECUTION_LABELS
        or any(not isinstance(label, str) or not label or len(label) > 128 for label in labels)
        or len(set(labels)) != len(labels)
    ):
        raise ModelManifestError(
            f"inference.output.labels must contain 2-{MAX_EXECUTION_LABELS} unique labels"
        )
    return {
        "preprocessing": {
            "kind": "utf8-bytes-v1",
            "input_name": input_name,
            "max_bytes": max_bytes,
        },
        "output": {
            "name": output_name,
            "labels": list(labels),
        },
    }


def validate_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ModelManifestError("model manifest must be an object")
    if manifest.get("schema_version") != MODEL_SCHEMA_VERSION:
        raise ModelManifestError("unsupported model manifest schema")

    model_id = _safe_id(manifest.get("id"), "id")
    version = _safe_id(manifest.get("version"), "version")
    name = manifest.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ModelManifestError("name must be a non-empty string")

    backend = manifest.get("backend")
    if backend not in SUPPORTED_BACKENDS:
        raise ModelManifestError(f"unsupported model backend: {backend!r}")

    catalog = load_catalog()
    actions = manifest.get("actions")
    if (
        not isinstance(actions, list)
        or not actions
        or any(not isinstance(action, str) or not action for action in actions)
        or len(set(actions)) != len(actions)
    ):
        raise ModelManifestError("actions must be a non-empty array of unique strings")
    known_actions = set(catalog["routes"])
    unknown_actions = sorted(set(actions) - known_actions)
    if unknown_actions:
        raise ModelManifestError(f"model references unknown actions: {', '.join(unknown_actions)}")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ModelManifestError("artifacts must be a non-empty array")
    normalized_artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    model_paths: list[str] = []
    model_size = 0
    for item in artifacts:
        if not isinstance(item, dict):
            raise ModelManifestError("model artifacts must be objects")
        relative = _safe_relative_path(item.get("path"))
        path_text = relative.as_posix()
        if path_text in seen_paths:
            raise ModelManifestError(f"duplicate model artifact path: {path_text}")
        seen_paths.add(path_text)
        role = item.get("role")
        if not isinstance(role, str) or not role:
            raise ModelManifestError(f"artifact role is required for {path_text}")
        size_bytes = item.get("size_bytes")
        sha256 = item.get("sha256")
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
            raise ModelManifestError(f"invalid artifact size for {path_text}")
        if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256):
            raise ModelManifestError(f"invalid artifact sha256 for {path_text}")
        if role == "model":
            model_paths.append(path_text)
            model_size = size_bytes
        normalized_artifacts.append(
            {"role": role, "path": path_text, "size_bytes": size_bytes, "sha256": sha256}
        )
    if len(model_paths) != 1:
        raise ModelManifestError("artifacts must contain exactly one role=model entry")
    if backend.startswith("onnx-") and not model_paths[0].lower().endswith(".onnx"):
        raise ModelManifestError("ONNX backends require the role=model artifact to use a .onnx path")

    normalized_inference = _validate_inference_contract(
        manifest.get("inference"), backend, model_size
    )

    evaluation = manifest.get("evaluation")
    if not isinstance(evaluation, dict) or evaluation.get("status") != "passed":
        raise ModelManifestError("evaluation.status must be 'passed'")
    evaluated_at = evaluation.get("evaluated_at")
    if not isinstance(evaluated_at, str) or not evaluated_at:
        raise ModelManifestError("evaluation.evaluated_at is required")
    evaluations = evaluation.get("datasets")
    if not isinstance(evaluations, list) or not evaluations:
        raise ModelManifestError("evaluation.datasets must be a non-empty array")
    pinned_revisions = {item["id"]: item["revision"] for item in catalog["datasets"]}
    normalized_evaluations: list[dict[str, Any]] = []
    for item in evaluations:
        if not isinstance(item, dict):
            raise ModelManifestError("evaluation dataset entries must be objects")
        dataset_id = item.get("dataset_id")
        revision = item.get("revision")
        split = item.get("split")
        if dataset_id not in pinned_revisions:
            raise ModelManifestError(f"evaluation references unknown dataset: {dataset_id!r}")
        if revision != pinned_revisions[dataset_id]:
            raise ModelManifestError(
                f"evaluation revision for {dataset_id} does not match the pinned OpenMindAI Dataset revision"
            )
        if not isinstance(split, str) or not split:
            raise ModelManifestError("evaluation split must be a non-empty string")
        normalized_evaluations.append(
            {
                "dataset_id": dataset_id,
                "revision": revision,
                "split": split,
                "metrics": _validate_metrics(item.get("metrics")),
            }
        )
    evaluated_dataset_ids = {item["dataset_id"] for item in normalized_evaluations}
    for action in actions:
        routed_datasets = set(catalog["routes"][action])
        if evaluated_dataset_ids.isdisjoint(routed_datasets):
            raise ModelManifestError(
                f"evaluation datasets do not cover any OpenMindAI Dataset routed for action: {action}"
            )

    license_info = manifest.get("license")
    if not isinstance(license_info, dict):
        raise ModelManifestError("license must be an object")
    license_name = license_info.get("name")
    if not isinstance(license_name, str) or not license_name:
        raise ModelManifestError("license.name must be a non-empty string")
    acceptance_required = license_info.get("acceptance_required", False)
    if not isinstance(acceptance_required, bool):
        raise ModelManifestError("license.acceptance_required must be a boolean")
    license_url = license_info.get("url")
    if license_url is not None and (not isinstance(license_url, str) or not license_url):
        raise ModelManifestError("license.url must be null or a non-empty string")

    return {
        "schema_version": MODEL_SCHEMA_VERSION,
        "id": model_id,
        "name": name.strip(),
        "version": version,
        "backend": backend,
        "actions": list(actions),
        "artifacts": normalized_artifacts,
        "inference": normalized_inference,
        "evaluation": {
            "status": "passed",
            "evaluated_at": evaluated_at,
            "datasets": normalized_evaluations,
        },
        "license": {
            "name": license_name,
            "url": license_url,
            "acceptance_required": acceptance_required,
        },
    }


def load_package(package_path: Path | str) -> tuple[Path, dict[str, Any]]:
    root = Path(package_path)
    if root.is_symlink():
        raise ModelIntegrityError("model package root must not be a symlink")
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise ModelIntegrityError(f"cannot resolve model package: {error}") from error
    if not root.is_dir():
        raise ModelIntegrityError("model package path must be a directory")
    manifest_path = root / "model.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ModelManifestError("model package must contain a regular model.json")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ModelManifestError(f"cannot read model.json: {error}") from error
    manifest = validate_manifest(raw)
    for artifact in manifest["artifacts"]:
        relative = _safe_relative_path(artifact["path"])
        path = _canonical_package_file(root, relative)
        if path.stat().st_size != artifact["size_bytes"]:
            raise ModelIntegrityError(f"artifact size mismatch: {artifact['path']}")
        if _sha256(path) != artifact["sha256"]:
            raise ModelIntegrityError(f"artifact sha256 mismatch: {artifact['path']}")
    return root, manifest


def _package_digest(manifest: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return digest.hexdigest()


def _execution_supported(metadata: dict[str, Any]) -> bool:
    return metadata.get("backend") in EXECUTION_BACKENDS and isinstance(
        metadata.get("inference"), dict
    )


def _public_model(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": metadata["id"],
        "name": metadata["name"],
        "version": metadata["version"],
        "backend": metadata["backend"],
        "actions": list(metadata["actions"]),
        "package_digest": metadata["package_digest"],
        "installed_at": metadata["installed_at"],
        "evaluation": metadata["evaluation"],
        "license": metadata["license"],
        "inference": metadata.get("inference"),
        "integrity_verified": bool(metadata.get("integrity_verified", False)),
        "execution_supported": _execution_supported(metadata),
    }


def install_model(
    package_path: Path | str,
    *,
    accepted_licenses: list[str] | tuple[str, ...] = (),
    model_root: Path | str | None = None,
) -> dict[str, Any]:
    package_root, manifest = load_package(package_path)
    license_info = manifest["license"]
    if license_info["acceptance_required"] and license_info["name"] not in set(accepted_licenses):
        raise ModelLicenseError(
            f"model license acceptance required before install: {license_info['name']}"
        )

    root = Path(model_root) if model_root is not None else default_model_root()
    root.mkdir(parents=True, exist_ok=True)
    model_dir = root / manifest["id"]
    target = model_dir / manifest["version"]
    package_digest = _package_digest(manifest)

    existing = _load_metadata(target)
    if existing and existing.get("package_digest") == package_digest and _installed_ready(target, existing):
        return _public_model(existing)
    if target.exists():
        raise ModelIntegrityError(
            f"model target already exists with different or invalid contents: {manifest['id']} {manifest['version']}"
        )

    model_dir.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{manifest['version']}.", dir=model_dir))
    try:
        for artifact in manifest["artifacts"]:
            relative = _safe_relative_path(artifact["path"])
            source = _canonical_package_file(package_root, relative)
            destination = stage.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        metadata = {
            **manifest,
            "package_digest": package_digest,
            "installed_at": _utc_now(),
            "integrity_verified": True,
        }
        (stage / MODEL_METADATA_FILE).write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(stage, target)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return _public_model(metadata)


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_metadata(model_dir: Path) -> dict[str, Any]:
    metadata_path = model_dir / MODEL_METADATA_FILE
    if metadata_path.is_symlink() or not metadata_path.is_file():
        return {}
    try:
        value = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _installed_ready(model_dir: Path, metadata: dict[str, Any]) -> bool:
    try:
        manifest = validate_manifest(metadata)
    except ModelError:
        return False
    if manifest["id"] != model_dir.parent.name or manifest["version"] != model_dir.name:
        return False
    if metadata.get("package_digest") != _package_digest(manifest):
        return False
    if metadata.get("integrity_verified") is not True:
        return False
    try:
        for artifact in manifest["artifacts"]:
            relative = _safe_relative_path(artifact["path"])
            path = _canonical_package_file(model_dir, relative)
            if path.stat().st_size != artifact["size_bytes"] or _sha256(path) != artifact["sha256"]:
                return False
    except (OSError, ModelError):
        return False
    return True


def _ready_entries(model_root: Path | str | None = None) -> list[tuple[Path, dict[str, Any]]]:
    root = Path(model_root) if model_root is not None else default_model_root()
    entries: list[tuple[Path, dict[str, Any]]] = []
    if not root.is_dir():
        return entries
    model_dirs = sorted(
        (item for item in root.iterdir() if item.is_dir() and not item.is_symlink()),
        key=lambda path: path.name,
    )
    for model_dir in model_dirs:
        version_dirs = sorted(
            (item for item in model_dir.iterdir() if item.is_dir() and not item.is_symlink()),
            key=lambda path: path.name,
        )
        for version_dir in version_dirs:
            metadata = _load_metadata(version_dir)
            if not metadata or not _installed_ready(version_dir, metadata):
                continue
            normalized = validate_manifest(metadata)
            normalized.update(
                {
                    "package_digest": metadata["package_digest"],
                    "installed_at": metadata["installed_at"],
                    "integrity_verified": True,
                }
            )
            entries.append((version_dir, normalized))
    return entries


def list_models(*, model_root: Path | str | None = None) -> dict[str, Any]:
    ready_by_path = {path: metadata for path, metadata in _ready_entries(model_root)}
    root = Path(model_root) if model_root is not None else default_model_root()
    models: list[dict[str, Any]] = []
    if root.is_dir():
        model_dirs = sorted(
            (item for item in root.iterdir() if item.is_dir() and not item.is_symlink()),
            key=lambda path: path.name,
        )
        for model_dir in model_dirs:
            version_dirs = sorted(
                (item for item in model_dir.iterdir() if item.is_dir() and not item.is_symlink()),
                key=lambda path: path.name,
            )
            for version_dir in version_dirs:
                ready_metadata = ready_by_path.get(version_dir)
                if ready_metadata is not None:
                    public = _public_model(ready_metadata)
                    public["ready"] = True
                    models.append(public)
                    continue
                metadata = _load_metadata(version_dir)
                if not metadata:
                    continue
                models.append(
                    {
                        "id": metadata.get("id", model_dir.name),
                        "version": metadata.get("version", version_dir.name),
                        "integrity_verified": False,
                        "execution_supported": False,
                        "ready": False,
                    }
                )
    return {
        "schema_version": MODEL_SCHEMA_VERSION,
        "package_backends": sorted(SUPPORTED_BACKENDS),
        "execution_backends": sorted(EXECUTION_BACKENDS),
        "execution_implemented": True,
        "models": models,
    }


def model_status(
    model_id: str | None = None,
    *,
    model_root: Path | str | None = None,
) -> dict[str, Any]:
    inventory = list_models(model_root=model_root)
    models = inventory["models"]
    if model_id is not None:
        _safe_id(model_id, "model_id")
        models = [item for item in models if item.get("id") == model_id]
    return {
        "model_id": model_id,
        "installed": bool(models),
        "ready": any(item.get("ready") for item in models),
        "execution_ready": any(
            item.get("ready") and item.get("execution_supported") for item in models
        ),
        "models": models,
        "execution_implemented": True,
    }


def route_model(action: str, *, model_root: Path | str | None = None) -> dict[str, Any]:
    catalog = load_catalog()
    if action not in catalog["routes"]:
        raise ModelError(f"unknown model action: {action}")
    inventory = list_models(model_root=model_root)
    routed = [
        item
        for item in inventory["models"]
        if item.get("ready") and action in item.get("actions", [])
    ]
    routed.sort(key=lambda item: (item["id"], item["version"]))
    return {
        "action": action,
        "ready": bool(routed),
        "execution_ready": any(item.get("execution_supported") for item in routed),
        "models": routed,
        "execution_implemented": True,
    }


def resolve_model_for_inference(
    action: str,
    *,
    model_id: str | None = None,
    model_version: str | None = None,
    model_root: Path | str | None = None,
) -> tuple[Path, dict[str, Any]]:
    catalog = load_catalog()
    if action not in catalog["routes"]:
        raise ModelError(f"unknown model action: {action}")
    if model_id is not None:
        _safe_id(model_id, "model_id")
    if model_version is not None:
        _safe_id(model_version, "model_version")

    candidates = []
    for path, metadata in _ready_entries(model_root):
        if action not in metadata["actions"] or not _execution_supported(metadata):
            continue
        if model_id is not None and metadata["id"] != model_id:
            continue
        if model_version is not None and metadata["version"] != model_version:
            continue
        candidates.append((path, metadata))
    if not candidates:
        raise ModelError(f"no execution-ready model is installed for action: {action}")
    if len(candidates) > 1:
        raise ModelError(
            "multiple execution-ready models match; specify both model_id and model_version"
        )
    return candidates[0]


def inference_plan(action: str, *, model_root: Path | str | None = None) -> dict[str, Any]:
    model_route = route_model(action, model_root=model_root)
    dataset_catalog = load_catalog()
    dataset_ids = list(dataset_catalog["routes"][action])
    if model_route["execution_ready"]:
        status = "ready"
    elif model_route["ready"]:
        status = "model_ready_execution_pending"
    else:
        status = "model_unavailable"
    return {
        "action": action,
        "status": status,
        "models": model_route["models"],
        "dataset_provenance": dataset_ids,
        "execution_implemented": True,
        "note": (
            "Only integrity-checked models with an explicit bounded inference contract are execution-ready. "
            "Evaluation metrics are package provenance and are not independently reproduced at runtime."
        ),
    }
