# ML Inference Worker Isolation

CodeTwin ML executes ONNX inference in a short-lived worker process rather than inside the long-lived JSON protocol process. This boundary is intended to contain hangs, reduce ambient credential exposure, and reduce the impact of pathological model graphs without presenting the worker as a complete cross-platform sandbox.

## Process model

`inference.run` remains the public sidecar protocol method. The protocol process validates the request shape, then calls the isolated worker client. The client starts the same trusted Python interpreter with:

```text
python -m codetwin_ml.worker
```

No shell is used. The worker receives exactly one bounded JSON request on standard input, executes at most one inference, emits one JSON response on standard output, and exits.

The worker does **not** inherit the full parent environment. The parent constructs a small allow-list containing only platform path/temp/locale values needed by the local runtime plus `CODETWIN_MODEL_CACHE`, then sets `PYTHONPATH` to the trusted CodeTwin ML sidecar root. Arbitrary parent variables such as GitHub/cloud/database tokens are not forwarded. Native math thread variables (`OMP_NUM_THREADS`, `OPENBLAS_NUM_THREADS`, `MKL_NUM_THREADS`, and `NUMEXPR_NUM_THREADS`) are forced to `1`.

The working directory is the trusted CodeTwin ML sidecar root; analyzed repository paths are not used to discover the worker module.

## Parent-enforced limits

The parent process applies:

- 15-second subprocess timeout;
- 131,072-byte serialized request limit;
- 1 MiB response limit;
- sanitized allow-listed environment rather than arbitrary parent-environment inheritance;
- single-thread hints for common native math runtimes;
- stderr suppression so arbitrary runtime diagnostics are not interpreted as prediction evidence;
- protocol version and result-shape checks.

Timeout, startup failure, non-zero exit, malformed JSON, protocol mismatch, oversized output, and structured worker errors all become deterministic `InferenceRuntimeError` failures. Worker stdout is captured to a temporary file and size-checked before it is read back, so the 1 MiB response limit is not merely a post-hoc in-memory check. No fallback in-process inference occurs.

## Worker-enforced limits

On POSIX systems the worker attempts to lower these process resource limits before importing ONNX Runtime:

- `RLIMIT_CPU`: 10 seconds;
- `RLIMIT_AS`: 4 GiB, when supported;
- `RLIMIT_FSIZE`: 16 MiB, when supported.

The implementation never raises an existing hard limit. Unsupported resource types or platform-specific failures leave only that individual limit unavailable.

The existing ONNX adapter restrictions still apply inside the worker: one verified single-file ONNX model, no ONNX external tensor data, CPU provider only, sequential execution, one intra-op thread, one inter-op thread, bounded input, bounded labels/output, and manifest-checked model I/O.

## Trusted sidecar identity

The desktop no longer treats an arbitrary configured Python executable and `services/ml` directory as trusted merely because they contain the expected entrypoint files.

Trust is established in two phases:

1. `ml_sidecar_identity` performs a **non-executing** inspection. It canonicalizes the configured Python executable and sidecar root, hashes the Python executable, and builds a deterministic digest over the bounded regular, non-symlink `.py` source tree.
2. Health, model inventory, classification and generation requests require the expected Python SHA-256 and sidecar source digest. Every request recomputes and compares those pins before launch.

The sidecar digest is domain-separated, path-aware, size-aware, deterministic, and bounded to 512 Python files / 16 MiB. Source symlinks are rejected rather than followed. Path changes clear the desktop trust state. Existing persisted pins are verified on reconnect; an identity change is rejected until the user explicitly forgets the old trust pin and trusts the new identity.

On Windows the desktop additionally keeps read-only handles to the pinned Python executable and all hashed sidecar Python source files for the request lifetime with write/delete sharing denied. The identity is re-attested again after the child exits before its response is accepted. On all platforms Python bytecode output is redirected to a fresh per-request cache directory, user-site imports are disabled, and the sidecar root is supplied explicitly through the sanitized environment.

These pins do **not** hash the entire Python installation, system site-packages, native extension modules, operating-system DLLs, or every transitive dependency. Those components remain part of the explicitly trusted local runtime boundary; the identity mechanism must not be described as a complete supply-chain sandbox.

## Windows desktop process-tree containment

When the desktop app starts the local ML sidecar on Windows, it creates the Python sidecar **suspended**, places it in a Job Object, and only then resumes its initial thread. The Job Object uses kill-on-close, an aggregate memory ceiling, an active-process limit, a bounded aggregate user-mode CPU-time budget, and terminate-on-unhandled-exception behavior. Because the inference worker and trusted llama.cpp CLI are descendants of that sidecar and no breakaway flag is requested, they remain in the same process-tree containment boundary.

Before assignment, CodeTwin also installs Windows Job Object basic UI restrictions that deny cross-job USER handles, clipboard read/write, desktop creation/switching, display/system-setting changes, global-atom access, and ExitWindows calls. If resource-limit setup, UI-restriction setup, Job Object assignment, suspended-thread discovery, or resume fails, the sidecar request fails closed. Timeout/error cleanup terminates the Job Object tree rather than only the immediate Python process.

## Native generation launch integrity

GGUF generation still requires an explicitly configured, SHA-256-pinned llama.cpp executable and a manifest-hashed installed GGUF artifact.

Immediately before generation, CodeTwin re-attests both files against their expected hashes and file identities. On Windows it additionally opens both the llama.cpp executable and GGUF model with read sharing only, denying write/delete sharing for the lifetime of the generation call. This closes the ordinary verify-then-replace window while the trusted native runtime and model are being launched and used. The file identities are checked again before accepting the generated result.

On non-Windows platforms CodeTwin performs pre-launch SHA-256 plus file-identity attestation and rejects ordinary identity changes observed during the call, but it does not claim an equivalent kernel-enforced share-deny lock.

## Platform boundary

The wall-clock timeout, environment sanitization, and process separation work on Windows as well as POSIX. Windows desktop launches add Job Object process-tree, memory, CPU-time and UI-surface containment around the sidecar and its descendants, while POSIX workers retain the resource-limit strategy described above. Neither path is a VM/container boundary, and the current native generation path explicitly reports `filesystem_isolation=false` and `network_isolation=false`.

For these reasons this layer is described as **worker isolation with bounded execution controls**, not a universal hard sandbox. Strongly untrusted third-party native runtimes still require a future OS-specific filesystem/network sandbox policy.

## Tests

Unit tests mock process launch to verify command construction, request serialization, timeout handling, non-zero exits, malformed and oversized responses, structured worker errors, and worker-environment sanitization without requiring ONNX Runtime. The environment regression test verifies that unrelated credential-like variables are not inherited while the explicit model-cache path remains available. Existing protocol tests exercise the public `inference.run` error path on a clean model cache.
