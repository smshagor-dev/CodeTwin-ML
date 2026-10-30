"""Bounded subprocess output; desktop launches additionally own the complete process tree."""

from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from typing import cast

from codetwin_ml.inference import InferenceRuntimeError


def run_bounded(
    command: Sequence[str],
    *,
    cwd: str,
    env: Mapping[str, str],
    timeout: float,
    max_output: int,
    output_label: str,
    input: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Capture at most max_output + 1 bytes, terminating immediately on overflow.

    A standalone POSIX launch owns a session. Nested workers inherit that session,
    or the desktop's process group, so outer cleanup also reaches native engines.
    Windows desktop launches inherit the already assigned kill-on-close Job Object.
    """
    environment = dict(env)
    owns_group = os.name == "posix" and os.environ.get("CODETWIN_PROCESS_GROUP") != "1"
    if os.name == "posix":
        environment["CODETWIN_PROCESS_GROUP"] = "1"
    child = subprocess.Popen(
        list(command),
        cwd=cwd,
        env=environment,
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=owns_group,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0,
    )
    stdout = child.stdout
    if stdout is None:
        child.kill()
        child.wait()
        raise InferenceRuntimeError("subprocess output pipe is unavailable")
    output = bytearray()
    finished = threading.Event()
    overflow = threading.Event()
    errors: list[OSError] = []

    def read_output() -> None:
        try:
            while True:
                chunk = cast(io.BufferedReader, stdout).read1(
                    min(65_536, max_output + 1 - len(output))
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > max_output:
                    overflow.set()
                    break
        except OSError as error:
            errors.append(error)
        finally:
            finished.set()

    def write_input() -> None:
        stdin = child.stdin
        if stdin is None:
            return
        try:
            if input is not None:
                stdin.write(input)
                stdin.flush()
        except BrokenPipeError:
            pass
        except OSError as error:
            errors.append(error)
        finally:
            try:
                stdin.close()
            except BrokenPipeError:
                pass

    def terminate() -> None:
        # The platform check is redundant with owns_group but lets mypy narrow on Windows.
        if owns_group and sys.platform != "win32":
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif child.poll() is None:
            child.kill()

    reader = threading.Thread(target=read_output, daemon=True)
    writer = threading.Thread(target=write_input, daemon=True)
    reader.start()
    writer.start()
    deadline = time.monotonic() + timeout
    try:
        while True:
            if overflow.is_set():
                raise InferenceRuntimeError(f"{output_label} exceeds {max_output} bytes")
            if errors:
                raise InferenceRuntimeError(f"cannot communicate with subprocess: {errors[0]}")
            if child.poll() is not None:
                # Descendants must not keep the output pipe open after their owner exits.
                terminate()
                if finished.is_set():
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(command), timeout)
            finished.wait(min(remaining, 0.01)) if not finished.is_set() else time.sleep(
                min(remaining, 0.01)
            )
        if overflow.is_set():
            raise InferenceRuntimeError(f"{output_label} exceeds {max_output} bytes")
        if errors:
            raise InferenceRuntimeError(f"cannot communicate with subprocess: {errors[0]}")
        return subprocess.CompletedProcess(list(command), child.wait(), stdout=bytes(output))
    finally:
        terminate()
        child.wait()
        reader.join(timeout=1)
        writer.join(timeout=1)
        if not reader.is_alive():
            stdout.close()
