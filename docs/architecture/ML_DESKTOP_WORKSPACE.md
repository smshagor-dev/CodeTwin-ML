# ML Desktop Workspace

The ML desktop workspace connects the Tauri application to CodeTwin's local Python ML sidecar without weakening the repository non-execution boundary.

## Explicit sidecar trust

The desktop does not search the analyzed repository, PATH-adjacent project folders, package scripts, or repository configuration for an executable ML command. The user supplies two explicit absolute paths:

- a regular Python executable;
- the trusted CodeTwin `services/ml` directory.

Both paths are canonicalized before use. Symlink executables, symlink sidecar roots, and symlink protocol entry files are rejected. The process is launched directly with `std::process::Command`; no shell is involved and the analyzed repository is never used as the process working directory.

Each desktop request starts the trusted sidecar as `python -m codetwin_ml.main` with the configured sidecar root as its working directory and `PYTHONPATH`. Requests and responses use the existing one-line JSON protocol. A request has a 15-second desktop-side timeout and a bounded response size. Stderr is not interpreted as model evidence.

## Indexed-file inference

The first desktop execution path is intentionally file-scoped. Before a source file is sent to the sidecar, CodeTwin:

1. loads the active indexed file and owning project from SQLite;
2. requires a safe project-relative path;
3. canonicalizes the project root and file path and rejects root escape;
4. rejects source symlinks;
5. rejects files larger than 65,536 bytes;
6. reads the current file bytes;
7. verifies current byte size and SHA-256 against the persisted index;
8. requires UTF-8 text.

If any check fails, inference does not run. This prevents an ML record from being attributed to stale or replaced source bytes.

The sidecar response is also checked before persistence. The returned action must equal the requested action, explicit model selectors must match the returned model identity, and the sidecar-reported input byte count and SHA-256 must equal the indexed file bytes.

## Persistence boundary

A successful result is converted to `MlInferenceObservation` and stored through `MlInferenceStore`. Raw source text is not stored in the CodeTwin database. The durable record contains model/package identity, input SHA-256 and byte count, label scores, runtime metadata, and evaluation provenance.

ML output remains separate from deterministic findings. The workspace does not automatically create, resolve, reprioritize, or change the confidence of a deterministic finding. Review links introduced by the ML provenance layer remain explicit relationships only.

## Workspace surface

The React workspace exposes:

- explicit sidecar Python/root configuration;
- health, capabilities, and installed-model inventory;
- project indexing and active indexed-file selection;
- action readiness planning;
- run-and-record inference for a hash-checked source file;
- persisted inference history and score/provenance inspection.

The workspace describes model confidence as model output rather than proof of a defect, vulnerability, or runtime incident.

## Remaining hardening

The ONNX execution adapter still runs inside the Python sidecar process. The desktop request timeout can kill a sidecar that does not terminate, but this is not a hard OS memory sandbox. Strongly untrusted third-party model execution still requires the separate isolated-worker/memory-policy hardening described in `ONNX_INFERENCE_RUNTIME.md`.
