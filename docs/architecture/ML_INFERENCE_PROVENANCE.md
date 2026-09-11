# ML Inference Provenance and Fusion Boundary

CodeTwin persists ML predictions as model evidence, not as deterministic findings. This layer exists so a later desktop bridge can record exactly what a local model returned without losing model, input-hash, runtime, or evaluation provenance.

## Persistence contract

Migration `0010_ml_inference_provenance.sql` adds `ml_inference_records` and `ml_finding_links`.

An inference record stores only bounded metadata:

- project and analysis-run identity;
- CodeTwin action;
- optional active indexed file identity plus the exact indexed content hash;
- SHA-256 and byte length of the exact inference input, not raw source text;
- preprocessing contract;
- model id, version, backend, and package digest;
- selected label, confidence, and the bounded probability vector;
- runtime metadata and declared evaluation provenance;
- creation time.

Raw input/source text is deliberately absent from the schema.

If an inference is attributed to an indexed file, persistence requires the caller to provide that file's current content hash. The record is rejected when the file is inactive, belongs to another project, or the hash is stale. This prevents a prediction over old bytes from being silently attached to current Digital Twin state.

## Validation

`MlInferenceStore` validates observations before opening the persistence transaction. The baseline enforces:

- SHA-256-shaped lowercase input/package/source hashes;
- at most 65,536 input bytes;
- at most 256 unique score labels;
- finite probabilities between 0 and 1;
- probabilities summing approximately to 1;
- selected confidence matching the selected label score;
- bounded runtime/evaluation JSON payloads;
- bounded identifiers and labels.

Each accepted observation receives a completed `analysis_runs` row with `run_kind=ml_inference` and an immutable `ml_inference_records` row.

## Deterministic/ML fusion boundary

The ML layer does **not** insert, resolve, change severity, or change confidence on rows in `findings`.

`ml_finding_links` can explicitly relate a persisted prediction to an existing finding using one of three review-only relationships:

- `supports_review`;
- `contradicts_review`;
- `related`.

Creating a link does not mutate the finding. This keeps deterministic evidence authoritative while still allowing a reviewer/UI to display model evidence beside it.

Automatic promotion of an ML prediction into a confirmed defect/security finding is intentionally out of scope. A later policy layer may propose review actions, but it must preserve model provenance and require an explicit evidence/risk policy rather than treating model confidence as proof.

## Query boundary

History and link queries are bounded. Current APIs support:

- record one validated observation;
- fetch one inference record;
- list recent project inference history with optional action filter;
- link an inference record to an existing same-project finding;
- list bounded ML links for a finding.

The later desktop/sidecar bridge should deserialize `inference.run` output into `MlInferenceObservation`, persist it only after source-hash verification, and never persist the raw source text that was sent to the model.
