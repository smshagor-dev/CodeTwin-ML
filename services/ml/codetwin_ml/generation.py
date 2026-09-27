from __future__ import annotations

import ctypes
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any

from codetwin_ml.inference import InferenceInputError, InferenceRuntimeError
from codetwin_ml.models import ModelError, resolve_model_for_generation

MAX_PROMPT_BYTES = 65_536
MAX_GENERATION_BYTES = 262_144
GENERATION_TIMEOUT_SECONDS = 90
_SHA256_HEX = set("0123456789abcdefABCDEF")

_ENV_ALLOWLIST = (
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "LANG",
    "LC_ALL",
)


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _file_identity(path: pathlib.Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return (
        int(getattr(stat, "st_dev", 0)),
        int(getattr(stat, "st_ino", 0)),
        int(stat.st_size),
        int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))),
    )


def _attest_launch_file(
    path: pathlib.Path,
    expected_hash: str,
    *,
    expected_size: int | None,
    label: str,
) -> tuple[int, int, int, int]:
    if path.is_symlink() or not path.is_file():
        raise InferenceRuntimeError(f"{label} must be a regular non-symlink file")
    before = _file_identity(path)
    if expected_size is not None and before[2] != expected_size:
        raise InferenceRuntimeError(f"{label} size changed before launch")
    actual_hash = _sha256(path)
    after = _file_identity(path)
    if before != after:
        raise InferenceRuntimeError(f"{label} changed while its launch hash was being verified")
    if actual_hash.lower() != expected_hash.lower():
        raise InferenceRuntimeError(f"{label} hash changed before launch")
    return after


def _assert_identity_unchanged(
    path: pathlib.Path,
    expected: tuple[int, int, int, int],
    *,
    label: str,
) -> None:
    try:
        current = _file_identity(path)
    except OSError as error:
        raise InferenceRuntimeError(f"{label} disappeared during generation: {error}") from error
    if current != expected:
        raise InferenceRuntimeError(f"{label} changed during generation")


@contextmanager
def _windows_share_deny_write_delete(path: pathlib.Path) -> Iterator[None]:
    if sys.platform != "win32":
        yield
        return

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_normal = 0x00000080
    invalid_handle = ctypes.c_void_p(-1).value

    handle = create_file(
        str(path),
        generic_read,
        file_share_read,
        None,
        open_existing,
        file_attribute_normal,
        None,
    )
    if handle == invalid_handle:
        error = ctypes.get_last_error()
        raise InferenceRuntimeError(
            f"cannot lock trusted generation file against replacement: {path} (Win32 {error})"
        )
    try:
        yield
    finally:
        close_handle(handle)


def generation_runtime_status() -> dict[str, Any]:
    raw = os.environ.get("CODETWIN_LLAMA_CLI", "").strip()
    expected_hash = os.environ.get("CODETWIN_LLAMA_CLI_SHA256", "").strip()
    if not raw:
        return {
            "available": False,
            "engine": "llama.cpp",
            "reason": "CODETWIN_LLAMA_CLI is not configured",
        }
    path = pathlib.Path(raw)
    if not path.is_absolute():
        return {
            "available": False,
            "engine": "llama.cpp",
            "reason": "CODETWIN_LLAMA_CLI must be an absolute path",
        }
    if path.is_symlink() or not path.is_file():
        return {
            "available": False,
            "engine": "llama.cpp",
            "reason": "configured llama.cpp CLI must be a regular non-symlink file",
        }
    if len(expected_hash) != 64 or any(ch not in _SHA256_HEX for ch in expected_hash):
        return {
            "available": False,
            "engine": "llama.cpp",
            "reason": "CODETWIN_LLAMA_CLI_SHA256 must pin the trusted executable",
        }
    actual_hash = _sha256(path)
    if actual_hash.lower() != expected_hash.lower():
        return {
            "available": False,
            "engine": "llama.cpp",
            "reason": "configured llama.cpp CLI hash does not match the trusted SHA-256",
        }
    return {
        "available": True,
        "engine": "llama.cpp",
        "executable": str(path.resolve()),
        "sha256": actual_hash,
    }


def _trusted_llama_cli() -> tuple[pathlib.Path, str]:
    status = generation_runtime_status()
    if not status.get("available"):
        raise InferenceRuntimeError(str(status.get("reason", "llama.cpp runtime unavailable")))
    return pathlib.Path(status["executable"]), str(status["sha256"])


def run_generation(
    action: str,
    prompt: str,
    *,
    model_id: str | None = None,
    model_version: str | None = None,
    model_root: pathlib.Path | str | None = None,
) -> dict[str, Any]:
    if not isinstance(action, str) or not action:
        raise InferenceInputError("action must be a non-empty string")
    if not isinstance(prompt, str):
        raise InferenceInputError("prompt must be a string")
    prompt_bytes = prompt.encode("utf-8")
    if not prompt_bytes or len(prompt_bytes) > MAX_PROMPT_BYTES:
        raise InferenceInputError(
            f"generation prompt must contain 1-{MAX_PROMPT_BYTES} UTF-8 bytes"
        )

    try:
        model_dir, metadata = resolve_model_for_generation(
            action,
            model_id=model_id,
            model_version=model_version,
            model_root=model_root,
        )
    except ModelError as error:
        raise InferenceInputError(str(error)) from error

    contract = metadata.get("inference")
    generation = contract.get("generation") if isinstance(contract, dict) else None
    if not isinstance(generation, dict):
        raise InferenceRuntimeError("selected GGUF model has no generation contract")

    model_artifact = next(
        (item for item in metadata["artifacts"] if item.get("role") == "model"),
        None,
    )
    if not isinstance(model_artifact, dict):
        raise InferenceRuntimeError("selected GGUF model is missing its model artifact")
    model_path = (model_dir / model_artifact["path"]).resolve(strict=True)
    if model_path.suffix.lower() != ".gguf" or model_path.is_symlink():
        raise InferenceRuntimeError("selected model is not a regular GGUF file")

    cli, cli_hash = _trusted_llama_cli()
    max_new_tokens = int(generation["max_new_tokens"])
    context_tokens = int(generation["context_tokens"])
    temperature = float(generation["temperature"])
    top_p = float(generation["top_p"])

    environment = {
        key: value
        for key in _ENV_ALLOWLIST
        if (value := os.environ.get(key))
    }
    environment.update({
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NO_COLOR": "1",
    })

    # Keep source-bearing prompts out of the process command line. Besides avoiding
    # Windows' command-line length ceiling, this prevents prompt text from being
    # exposed through ordinary process-list inspection.
    with tempfile.TemporaryDirectory(prefix="codetwin-generation-") as temporary:
        prompt_path = pathlib.Path(temporary) / "prompt.txt"
        prompt_path.write_bytes(prompt_bytes)
        if os.name == "posix":
            prompt_path.chmod(0o600)

        command = [
            str(cli),
            "-m",
            str(model_path),
            "-f",
            str(prompt_path),
            "-n",
            str(max_new_tokens),
            "-c",
            str(context_tokens),
            "--temp",
            str(temperature),
            "--top-p",
            str(top_p),
            "--no-display-prompt",
            "--simple-io",
        ]
        with ExitStack() as launch_locks:
            launch_locks.enter_context(_windows_share_deny_write_delete(cli))
            launch_locks.enter_context(_windows_share_deny_write_delete(model_path))
            cli_identity = _attest_launch_file(
                cli,
                cli_hash,
                expected_size=None,
                label="trusted llama.cpp CLI",
            )
            model_identity = _attest_launch_file(
                model_path,
                str(model_artifact["sha256"]),
                expected_size=int(model_artifact["size_bytes"]),
                label="selected GGUF model",
            )

            with tempfile.TemporaryFile(prefix="codetwin-generation-output-") as output:
                kwargs: dict[str, Any] = {
                    "stdout": output,
                    "stderr": subprocess.DEVNULL,
                    "cwd": str(model_dir),
                    "env": environment,
                    "timeout": GENERATION_TIMEOUT_SECONDS,
                    "check": False,
                }
                if sys.platform == "win32":
                    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

                try:
                    completed = subprocess.run(command, **kwargs)
                except subprocess.TimeoutExpired as error:
                    raise InferenceRuntimeError(
                        f"local generation exceeded the {GENERATION_TIMEOUT_SECONDS} second timeout"
                    ) from error
                except OSError as error:
                    raise InferenceRuntimeError(
                        f"cannot start trusted llama.cpp CLI: {error}"
                    ) from error

                if completed.returncode != 0:
                    raise InferenceRuntimeError(
                        f"trusted llama.cpp CLI exited with status {completed.returncode}"
                    )
                _assert_identity_unchanged(
                    cli, cli_identity, label="trusted llama.cpp CLI"
                )
                _assert_identity_unchanged(
                    model_path, model_identity, label="selected GGUF model"
                )
                output_size = os.fstat(output.fileno()).st_size
                if output_size > MAX_GENERATION_BYTES:
                    raise InferenceRuntimeError(
                        f"generation output exceeds the {MAX_GENERATION_BYTES}-byte limit"
                    )
                output.seek(0)
                stdout = output.read(MAX_GENERATION_BYTES + 1)

    if len(stdout) > MAX_GENERATION_BYTES:
        raise InferenceRuntimeError(
            f"generation output exceeds the {MAX_GENERATION_BYTES}-byte limit"
        )
    try:
        text = bytes(stdout).decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise InferenceRuntimeError("generation output was not valid UTF-8") from error
    if not text:
        raise InferenceRuntimeError("generation output was empty")

    return {
        "action": action,
        "model": {
            "id": metadata["id"],
            "version": metadata["version"],
            "backend": metadata["backend"],
            "package_digest": metadata["package_digest"],
        },
        "input": {
            "utf8_bytes": len(prompt_bytes),
            "sha256": hashlib.sha256(prompt_bytes).hexdigest(),
            "preprocessing": "utf8-prompt-v1",
            "truncated": False,
        },
        "generation": {
            "text": text,
            "max_new_tokens": max_new_tokens,
            "context_tokens": context_tokens,
            "temperature": temperature,
            "top_p": top_p,
        },
        "runtime": {
            "engine": "llama.cpp",
            "executable_sha256": cli_hash,
            "network_access_requested": False,
            "uses_shell": False,
            "launch_integrity": (
                "windows_share_deny_write_delete"
                if os.name == "nt"
                else "prelaunch_sha256_plus_file_identity"
            ),
        },
        "evaluation_provenance": metadata["evaluation"],
    }
