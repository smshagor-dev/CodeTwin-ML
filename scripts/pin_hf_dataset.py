#!/usr/bin/env python3
"""Print a pinned `datasets/catalog.json` entry for a Hugging Face dataset.

Adding a dataset to CodeTwin means pinning an exact revision plus the size and SHA-256 of every
file, so the installer and the benchmark only ever read the bytes that were reviewed. This
helper resolves those pins from the Hugging Face Hub API:

    python3 scripts/pin_hf_dataset.py OWNER/NAME --id my_dataset \\
        --license apache-2.0 --license-url https://www.apache.org/licenses/LICENSE-2.0 \\
        --purpose vulnerability_detection --task vulnerability_detection --include 'data/*.parquet'

Review the dataset card and license yourself before adding the output to the catalog; the
`--license` value is what you verified, not something this script infers. Standard library only.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
from typing import Any, Callable
from urllib.parse import quote
from urllib.request import Request, urlopen

HUB = "https://huggingface.co"
USER_AGENT = "CodeTwin-ML/0.1 dataset-pin"
CHUNK_BYTES = 1024 * 1024
TASKS = ("vulnerability_detection", "repair_pairs", "secret_probe")

Opener = Callable[..., Any]

REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ID_PATTERN = re.compile(r"^[a-z0-9_]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PinError(RuntimeError):
    pass


def _get_json(url: str, opener: Opener) -> Any:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with opener(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def _hash_download(url: str, opener: Opener) -> tuple[int, str]:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    size = 0
    with opener(request, timeout=300) as response:
        while True:
            chunk = response.read(CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def pin(
    repository: str,
    *,
    dataset_id: str,
    name: str,
    license_id: str,
    license_url: str,
    purposes: list[str],
    include: list[str],
    revision: str = "main",
    task: str | None = None,
    default_language: str | None = None,
    opener: Opener = urlopen,
) -> dict[str, Any]:
    if not REPOSITORY_PATTERN.match(repository):
        raise PinError("repository must look like owner/name")
    if not ID_PATTERN.match(dataset_id):
        raise PinError("--id must be lowercase letters, digits and underscores")
    if task is not None and task not in TASKS:
        raise PinError(f"--task must be one of {', '.join(TASKS)}")

    quoted = quote(repository, safe="/")
    info = _get_json(f"{HUB}/api/datasets/{quoted}/revision/{quote(revision, safe='')}", opener)
    sha = info.get("sha") if isinstance(info, dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise PinError(f"could not resolve revision {revision!r} of {repository}")

    tree = _get_json(f"{HUB}/api/datasets/{quoted}/tree/{sha}?recursive=true", opener)
    if not isinstance(tree, list):
        raise PinError("unexpected tree listing from the Hub")
    files: list[dict[str, Any]] = []
    for item in tree:
        if not isinstance(item, dict) or item.get("type") != "file":
            continue
        path = item.get("path")
        if not isinstance(path, str) or not any(fnmatch.fnmatch(path, pattern) for pattern in include):
            continue
        if path.startswith("/") or ".." in path.split("/") or "\\" in path:
            raise PinError(f"unsafe path in listing: {path!r}")
        lfs = item.get("lfs") if isinstance(item.get("lfs"), dict) else None
        size = item.get("size")
        digest = lfs.get("oid") if lfs else None
        if lfs and isinstance(lfs.get("size"), int):
            size = lfs["size"]
        if not (isinstance(digest, str) and SHA256_PATTERN.match(digest)):
            # Small non-LFS files have only a git blob id; hash the bytes instead.
            url = f"{HUB}/datasets/{quoted}/resolve/{sha}/{quote(path)}?download=true"
            size, digest = _hash_download(url, opener)
        if not isinstance(size, int):
            raise PinError(f"no size for {path}")
        files.append({"path": path, "size_bytes": size, "sha256": digest})
    if not files:
        raise PinError(f"no files matched {include} at {sha}")
    files.sort(key=lambda file: str(file["path"]))

    entry: dict[str, Any] = {
        "id": dataset_id,
        "name": name,
        "release_asset": f"openmindai-dataset-{dataset_id.replace('_', '-')}-v1.0.0.zip",
        "repository": repository,
        "revision": sha,
        "license": license_id,
        "license_url": license_url,
        "license_acceptance_required": license_id.lower() not in {"mit", "apache-2.0", "cc-by-4.0", "cc0-1.0"},
        "purpose": purposes,
        "download_bytes": sum(item["size_bytes"] for item in files),
        "files": files,
    }
    if task:
        benchmark: dict[str, Any] = {"task": task}
        if default_language:
            benchmark["default_language"] = default_language
        entry["benchmark"] = benchmark
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pin a Hugging Face dataset for datasets/catalog.json")
    parser.add_argument("repository", help="owner/name on huggingface.co")
    parser.add_argument("--id", required=True, dest="dataset_id")
    parser.add_argument("--name", help="display name (default: OpenMindAI Dataset - <id>)")
    parser.add_argument("--revision", default="main", help="branch, tag or commit to pin")
    parser.add_argument("--license", required=True, dest="license_id", help="license you verified on the dataset card")
    parser.add_argument("--license-url", required=True)
    parser.add_argument("--purpose", action="append", required=True)
    parser.add_argument("--include", action="append", default=None, help="glob of files to pin (repeatable)")
    parser.add_argument("--task", choices=TASKS)
    parser.add_argument("--default-language")
    args = parser.parse_args(argv)
    try:
        entry = pin(
            args.repository,
            dataset_id=args.dataset_id,
            name=args.name or f"OpenMindAI Dataset - {args.dataset_id}",
            license_id=args.license_id,
            license_url=args.license_url,
            purposes=args.purpose,
            include=args.include or ["*.parquet", "**/*.parquet"],
            revision=args.revision,
            task=args.task,
            default_language=args.default_language,
        )
    except (PinError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(entry, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
