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

## Windows desktop process-tree containment

When the desktop app starts the local ML sidecar on Windows, it creates the Python sidecar **suspended**, places it in a Job Object, and only then resumes its initial thread. The Job Object uses kill-on-close, an aggregate memory ceiling, and an active-process limit. Because the inference worker and trusted llama.cpp CLI are descendants of that sidecar and no breakaway flag is requested, they remain in the same process-tree containment boundary.

If Job Object creation, configuration, assignment, suspended-thread discovery, or resume fails, the sidecar request fails closed. Timeout/error cleanup terminates the Job Object tree rather than only the immediate Python process.

## Native generation launch integrity

GGUF generation still requires an explicitly configured, SHA-256-pinned llama.cpp executable and a manifest-hashed installed GGUF artifact.

Immediately before generation, CodeTwin re-attests both files against their expected hashes and file identities. On Windows it additionally opens both the llama.cpp executable and GGUF model with read sharing only, denying write/delete sharing for the lifetime of the generation call. This closes the ordinary verify-then-replace window while the trusted native runtime and model are being launched and used. The file identities are checked again before accepting the generated result.

On non-Windows platforms CodeTwin performs pre-launch SHA-256 plus file-identity attestation and rejects ordinary identity changes observed during the call, but it does not claim an equivalent kernel-enforced share-deny lock.

## Platform boundary

The wall-clock timeout, environment sanitization, and process separation work on Windows as well as POSIX. Windows desktop launches now add Job Object process-tree/memory containment around the sidecar and its descendants, while POSIX workers retain the resource-limit strategy described above. Neither path is a VM/container boundary, and the current native generation path does not claim universal filesystem or network isolation.

For these reasons this layer is described as **worker isolation with bounded execution controls**, not a universal hard sandbox. Strongly untrusted third-party native runtimes still require a future OS-specific filesystem/network sandbox policy.

## Tests

Unit tests mock process launch to verify command construction, request serialization, timeout handling, non-zero exits, malformed and oversized responses, structured worker errors, and worker-environment sanitization without requiring ONNX Runtime. The environment regression test verifies that unrelated credential-like variables are not inherited while the explicit model-cache path remains available. Existing protocol tests exercise the public `inference.run` error path on a clean model cache.
