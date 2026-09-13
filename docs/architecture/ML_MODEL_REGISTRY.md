# ML Model Registry Foundation

CodeTwin ML keeps model installation, model execution, and model evaluation as separate trust boundaries. The registry remains a local, data-only package system; a model package is never allowed to supply Python modules, shell commands, plugins, or executables that CodeTwin launches.

## Package contract

A model package is a directory containing `model.json` and checksum-pinned regular files. The manifest schema is versioned and records:

- a stable model id, display name, and version;
- an allow-listed package backend (`onnx-classification-v1` or `onnx-seq2seq-v1`);
- one or more CodeTwin actions such as `defect_detection`, `security_analysis`, or `repair_generation`;
- every packaged artifact with role, safe relative path, exact byte size, and SHA-256;
- evaluation provenance tied to the pinned OpenMindAI Dataset id and revision, split, timestamp, and finite numeric metrics;
- model license metadata and whether explicit acceptance is required;
- optionally, a reviewed bounded inference contract.

Exactly one artifact must have `role=model`. ONNX packages require that artifact to use a `.onnx` path. Package paths cannot be absolute, contain parent traversal, or use backslash-based alternate paths. The package root and artifacts must be regular files/directories rather than symlinks. Installed artifact bytes are copied into the local model cache only after size and SHA-256 verification.

## Evaluation boundary

`evaluation.status=passed` means the package declares completed evaluation metadata and references the exact dataset revisions pinned by CodeTwin. Every action claimed by a package must overlap at least one OpenMindAI Dataset route represented in the declared evaluation provenance. The registry validates the structure and provenance references, but it does not reproduce those metrics during installation. The metrics therefore remain package provenance, not an independently re-run CodeTwin benchmark result.

A future first-party training/evaluation pipeline must produce independently reproducible evaluation records before first-party model releases are described as CodeTwin-verified models.

## Installation and cache

The default cache is `models/cache`, which is excluded from Git. `CODETWIN_MODEL_CACHE` can point the sidecar to an application-managed model directory.

Installation is atomic at the model-version directory level:

1. validate `model.json`;
2. validate the declared license requirement;
3. verify every artifact size and SHA-256;
4. copy regular files into a staging directory;
5. persist normalized `_codetwin_model.json` registry metadata;
6. atomically move the staging directory into `<model-id>/<version>`.

If the same model/version is already present and still verifies, installation is idempotent. A conflicting or corrupted existing target is not overwritten silently. Installed metadata is also revalidated against its directory identity and current artifact bytes before the model is returned as ready.

## Action routing

Model actions must already exist in the OpenMindAI Dataset routing catalog. `models.route` only returns installed models whose current files still pass integrity checks and whose manifest explicitly contains the requested action.

Registry readiness, adapter support, and local runtime availability are distinct. A package can be valid and installed without an executable inference contract, and an executable package can be installed on a machine that does not yet have the optional ONNX runtime dependencies. `inference.plan` therefore returns one of:

- `model_unavailable` when no valid package is installed for the action;
- `model_ready_execution_pending` when a valid package exists but has no supported execution contract;
- `runtime_unavailable` when an execution-ready model exists but `numpy`, `onnx`, or `onnxruntime` is missing;
- `ready` when both the reviewed local adapter contract and the required runtime dependencies are available.

`capabilities.inference` advertises an action only in the final `ready` state.

## Execution boundary

The first executable adapter supports `onnx-classification-v1` with `utf8-bytes-v1` preprocessing. Execution is allowed only when the manifest contains the reviewed inference contract. `onnx-seq2seq-v1` remains registry-only in this baseline.

The registry still does not execute package code. The ONNX adapter loads only the verified model artifact through the allow-listed local runtime. The package cannot register custom native libraries, shell commands, Python modules, or repository scripts through the model contract.

See `ONNX_INFERENCE_RUNTIME.md` for the input/output contract, limits, provenance, dependency readiness, and remaining runtime-sandbox limitations.
