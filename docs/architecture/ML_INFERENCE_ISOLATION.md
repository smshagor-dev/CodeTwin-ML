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

Timeout, startup failure, non-zero exit, malformed JSON, protocol mismatch, oversized output, and structured worker errors all become deterministic `InferenceRuntimeError` failures. No fallback in-process inference occurs.

## Worker-enforced limits

On POSIX systems the worker attempts to lower these process resource limits before importing ONNX Runtime:

- `RLIMIT_CPU`: 10 seconds;
- `RLIMIT_AS`: 4 GiB, when supported;
- `RLIMIT_FSIZE`: 16 MiB, when supported.

The implementation never raises an existing hard limit. Unsupported resource types or platform-specific failures leave only that individual limit unavailable.

The existing ONNX adapter restrictions still apply inside the worker: one verified single-file ONNX model, no ONNX external tensor data, CPU provider only, sequential execution, one intra-op thread, one inter-op thread, bounded input, bounded labels/output, and manifest-checked model I/O.

## Platform boundary

The wall-clock timeout, environment sanitization, and process separation work on Windows as well as POSIX. The current Python implementation does not establish a Windows Job Object or another Windows kernel memory cap. POSIX `RLIMIT_AS` availability and behavior also vary by operating system.

For these reasons this layer is described as **worker isolation with bounded execution controls**, not a VM, container, seccomp sandbox, or universal hard memory sandbox. Strongly untrusted third-party models still require a future OS-specific sandbox policy.

## Tests

Unit tests mock process launch to verify command construction, request serialization, timeout handling, non-zero exits, malformed and oversized responses, structured worker errors, and worker-environment sanitization without requiring ONNX Runtime. The environment regression test verifies that unrelated credential-like variables are not inherited while the explicit model-cache path remains available. Existing protocol tests exercise the public `inference.run` error path on a clean model cache.
