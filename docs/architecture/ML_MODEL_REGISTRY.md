# ML Model Registry Foundation

CodeTwin ML keeps model installation, model execution, and model evaluation as separate trust boundaries. This baseline implements a local, data-only model package registry. It does **not** execute an installed model and does not report predictions.

## Package contract

A model package is a directory containing `model.json` and checksum-pinned regular files. The manifest schema is versioned and records:

- a stable model id, display name, and version;
- an allow-listed data backend (`onnx-classification-v1` or `onnx-seq2seq-v1` in this baseline);
- one or more CodeTwin actions such as `defect_detection`, `security_analysis`, or `repair_generation`;
- every packaged artifact with role, safe relative path, exact byte size, and SHA-256;
- evaluation provenance tied to the pinned OpenMindAI Dataset id and revision, split, timestamp, and finite numeric metrics;
- model license metadata and whether explicit acceptance is required.

Exactly one artifact must have `role=model`. Package paths cannot be absolute, contain parent traversal, or use backslash-based alternate paths. The package root and artifacts must be regular files/directories rather than symlinks. Installed artifact bytes are copied into the local model cache only after size and SHA-256 verification.

## Evaluation boundary

`evaluation.status=passed` means the package declares completed evaluation metadata and references the exact dataset revisions pinned by CodeTwin. The registry validates the structure and provenance references, but it does not reproduce those metrics during installation. The metrics therefore remain package provenance, not an independently re-run CodeTwin benchmark result.

A future training/evaluation pipeline must produce independently reproducible evaluation records before first-party model releases are described as CodeTwin-verified models.

## Installation and cache

The default cache is `models/cache`, which is excluded from Git. `CODETWIN_MODEL_CACHE` can point the sidecar to an application-managed model directory.

Installation is atomic at the model-version directory level:

1. validate `model.json`;
2. validate the declared license requirement;
3. verify every artifact size and SHA-256;
4. copy regular files into a staging directory;
5. persist normalized `_codetwin_model.json` registry metadata;
6. atomically move the staging directory into `<model-id>/<version>`.

If the same model/version is already present and still verifies, installation is idempotent. A conflicting or corrupted existing target is not overwritten silently.

## Action routing

Model actions must already exist in the OpenMindAI Dataset routing catalog. `models.route` only returns installed models whose current files still pass integrity checks and whose manifest explicitly contains the requested action.

`inference.plan` combines that model readiness with the dataset ids routed for the action. It can return `model_unavailable` or `model_ready_execution_pending`. It never returns a prediction.

## Execution boundary

This baseline deliberately reports `execution_implemented=false`. Model packages cannot provide Python modules, shell commands, plugins, or executables that CodeTwin launches. No installed model file is imported or executed by the registry.

A later inference-runtime change must add a reviewed adapter with bounded inputs/outputs, resource limits, model-specific preprocessing, provenance, deterministic failure handling, and tests against real evaluated artifacts. Only then may `capabilities.inference` advertise executable prediction actions.
