# CodeTwin ML

**Local Software Digital Twin for Predictive Quality, Security, Reliability, and Verified Repair**

CodeTwin ML is a local-first engineering intelligence desktop application. It combines deterministic program analysis, project metadata, persisted evidence, bounded semantic enrichment, and measurable ML components into a durable Software Digital Twin.

## Current capability status

| Capability | Status |
| --- | --- |
| Monorepo + Tauri/React desktop shell | Implemented foundation |
| Local SQLite WAL + numbered migrations | Implemented |
| Project stack discovery | Implemented |
| Tree-sitter source indexing | Implemented baseline for TypeScript/TSX, JavaScript/JSX, Python, Rust, Go, C, C++, PHP |
| Persistent incremental file/symbol index | Implemented |
| Static import observations + deterministic local TS/JS resolution | Implemented baseline |
| Project/File/Symbol Digital Twin graph | Implemented baseline |
| Bounded dependency/impact queries | Implemented baseline |
| Source-backed symbol reference observations | Implemented baseline |
| Conservative same-file semantic symbol resolution | Implemented baseline |
| Explicit LSP semantic enrichment | Implemented baseline for configured TypeScript/JavaScript, Pyright, and Rust Analyzer servers |
| Deterministic code-quality findings | Implemented baseline for large definitions, deep declaration nesting, high local fan-out, and resolved-local dependency cycles |
| Deterministic AppSec review findings | Implemented baseline for hard-coded credential literals, dynamic execution primitives, weak hash primitives, and unsafe C/C++ string APIs |
| Deterministic database artifact analysis | Implemented baseline with desktop workspace for SQL/Prisma artifact inventory, destructive migration review, unscoped UPDATE/DELETE, SQLite foreign-key disable, and literal Prisma datasource URLs |
| Deterministic runtime reliability analysis | Implemented baseline with desktop workspace for Dockerfile/Compose artifact inventory, mutable image references, healthcheck review, and explicit no-restart policies |
| OpenMindAI Dataset catalog + action routing | Implemented foundation |
| Local ML model package registry + action readiness routing | Implemented foundation with SHA-256/size verification and evaluation provenance |
| Local ONNX classification inference adapter | Implemented bounded CPU adapter for packages declaring `utf8-bytes-v1`; no model weights are bundled |
| Isolated ML inference worker | Implemented process separation + 15-second timeout; POSIX resource limits are attempted, Windows hard memory cap remains planned |
| Runtime telemetry / live process tracing | Planned |
| ML finding persistence + deterministic/ML fusion | Planned |
| Verified repair workflow | Planned |

Planned capabilities are not presented as available results. Semantic graph relationships, quality findings, AppSec review findings, database review findings, and runtime reliability review findings are materialized only from concrete persisted evidence; ambiguous, unresolved, external, stale, skipped, or unverified runtime/exploitability claims are not converted into guessed facts. Installed ML packages are reported separately from executable inference capability: only integrity-checked packages with an explicit bounded inference contract can be advertised as executable. Package evaluation metrics remain provenance and are not claimed as independently reproduced by CodeTwin at runtime.

## Development

Prerequisites: Node.js 22+, Rust 1.82+, Python 3.12+, platform dependencies required by Tauri 2.

```bash
npm install
npm run typecheck
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python -m unittest discover -s services/ml/tests
```

The local ONNX adapter uses the optional Python ML dependencies (`numpy`, `onnx`, and `onnxruntime`) when real inference is requested. Unit tests inject a fake session and mock the worker boundary, so the normal Python test suite does not require those optional packages.

See `docs/development/SETUP.md`, `docs/architecture/DIGITAL_TWIN.md`, `docs/architecture/LSP_SEMANTIC_ENRICHMENT.md`, `docs/architecture/CODE_QUALITY_ANALYSIS.md`, `docs/architecture/SECURITY_ANALYSIS.md`, `docs/architecture/DATABASE_ANALYSIS.md`, `docs/architecture/RUNTIME_RELIABILITY.md`, `docs/architecture/ML_MODEL_REGISTRY.md`, `docs/architecture/ONNX_INFERENCE_RUNTIME.md`, and `docs/architecture/ML_INFERENCE_ISOLATION.md`.

## Privacy and security

Passive source indexing, Digital Twin persistence, deterministic code-quality analysis, deterministic AppSec analysis, deterministic database analysis, and deterministic runtime reliability analysis treat repositories as untrusted data and do not execute repository commands. Runtime reliability analysis reads only bounded Dockerfile/Compose artifacts and does not start containers, processes, services, health checks, or network probes; its findings describe configuration evidence rather than live availability. Database analysis reads only bounded SQL/Prisma artifacts, never opens the analyzed project's database, and never executes migrations or queries. Literal Prisma datasource values are redacted before persistence. AppSec source reads are restricted to active indexed files whose current bytes still match the persisted content hash; potential credential literals are redacted and are never persisted. LSP semantic enrichment is a separate explicit workflow: it requires project trust and a user-configured absolute external language-server executable. CodeTwin does not discover or execute a language server from the analyzed repository. The ML model registry treats packages as data only: it validates safe paths, license metadata, pinned evaluation provenance, byte sizes, and SHA-256 hashes, and it does not import or execute code from model packages. The ONNX adapter accepts only an integrity-checked single-file ONNX classification package with a bounded `utf8-bytes-v1` contract, rejects external-data tensors, runs CPU inference with one intra-op and one inter-op thread, rejects oversized inputs/outputs, and returns input hashes rather than persisting raw input text. `inference.run` executes inside a short-lived worker process with a parent-enforced 15-second timeout; POSIX CPU/address-space/file-size limits are attempted before ONNX Runtime is imported. This is not claimed as a complete cross-platform sandbox because Windows hard memory limits and stronger OS isolation are not yet implemented.
