# CodeTwin ML

**Local Software Digital Twin for Predictive Quality, Security, Reliability, ML-Assisted Review, and Verified Repair**

CodeTwin ML is a local-first engineering intelligence desktop application. It combines deterministic program analysis, persistent evidence, bounded semantic enrichment, local ML inference, passive QA discovery, and hash-verified repair workflows into a durable Software Digital Twin.

## Current capability status

| Capability | Status |
| --- | --- |
| Tauri/React desktop shell + unified evidence dashboard | Implemented baseline |
| Local SQLite WAL + numbered migrations | Implemented; migrations `0001`–`0016` are registered |
| Project stack discovery | Implemented |
| Tree-sitter source indexing | Implemented baseline for TypeScript/TSX, JavaScript/JSX, Python, Rust, Go, C, C++, PHP |
| Persistent incremental file/symbol index | Implemented |
| Static import observations + deterministic local TS/JS resolution | Implemented baseline |
| Project/File/Symbol Digital Twin graph | Implemented baseline |
| Bounded dependency/impact queries | Implemented baseline |
| Source-backed symbol reference observations | Implemented baseline |
| Conservative same-file semantic symbol resolution | Implemented baseline |
| Explicit LSP semantic enrichment | Implemented baseline for configured TypeScript/JavaScript, Pyright, and Rust Analyzer servers |
| Deterministic code-quality findings | Implemented baseline |
| Deterministic AppSec + web request-flow findings | Implemented baseline with durable finding lifecycle |
| Python web-security review | Implemented static CLI layer |
| Deterministic database artifact analysis | Implemented baseline with desktop workspace |
| Deterministic runtime reliability analysis | Implemented baseline with desktop workspace |
| Passive QA/test discovery | Implemented baseline with desktop workspace; does not claim test execution or coverage |
| Sandboxed QA/test execution | Hardening foundation implemented; **public execution remains disabled** until filesystem/read isolation, network denial, desktop isolation, and adversarial Windows validation are complete |
| OpenMindAI Dataset catalog + action routing | Implemented foundation; dataset installation is optional and integrity checked |
| Local ML model package registry | Implemented foundation with SHA-256/size verification and evaluation provenance |
| Local ONNX classification inference | Implemented bounded CPU adapter for packages declaring `utf8-bytes-v1`; no model weights are bundled |
| ML desktop workspace | Implemented trusted local sidecar workspace with model inventory, planning, bounded inference, persisted provenance, and review-only finding links |
| Verified Repair Lab | Implemented baseline for hash-pinned proposal, approval, re-indexed verification, and evidence history |
| Hash-guarded Apply & Rollback | Implemented baseline with live base-hash checks, staged replacement, app-data backups, reverse rollback, and explicit user confirmation |
| Runtime telemetry / live process tracing | Planned |
| Browser QA execution | Planned |
| Automatic repair generation / validation / PR automation | Planned |

### Evidence and execution truth

CodeTwin does not turn missing, stale, ambiguous, skipped, or failed evidence reads into guessed facts. The dashboard distinguishes unavailable evidence from a genuine zero result. Deterministic quality, security, database, runtime, and QA-discovery evidence is source-backed or persisted. Semantic enrichment is an explicit trusted workflow. ML outputs are model observations with provenance and remain separate from deterministic finding authority.

The local ONNX adapter can produce predictions only when a compatible integrity-verified model package is installed and the required local runtime dependencies are available. Registry installation alone does not imply executable readiness, and package evaluation metadata is provenance rather than a claim that CodeTwin independently reproduced the benchmark.

The Repair Lab and Apply & Rollback workflow can modify explicitly approved file replacements, but an applied change is not automatically verified. Verification requires a later re-indexed state, and a linked deterministic finding must be resolved by its originating analyzer before the repair plan can become `verified`.

QA execution remains deliberately disabled at the public service/desktop boundary. The Windows hardening path includes suspended Job Object assignment, a write-restricted low-integrity token, explicit inherited handles, bounded project mirroring, approval-bound project/runtime provenance, trusted-runner attestation, resource limits, cancellation, and LPAC readiness work. It still does not truthfully enforce all required filesystem-read and network isolation properties, so `filesystem_isolation` and `network_isolation` remain false.

## Development

Prerequisites: Node.js 22+, Rust 1.82+, Python 3.12+, and platform dependencies required by Tauri 2.

```bash
npm install
npm run typecheck
npm run test
npm run build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python -m unittest discover -s services/ml/tests -v
python -m unittest discover -s services/security/tests -v
python -m compileall -q services/ml/codetwin_ml services/security/codetwin_security
```

Important architecture references include:

- `docs/architecture/DIGITAL_TWIN.md`
- `docs/architecture/LSP_SEMANTIC_ENRICHMENT.md`
- `docs/architecture/CODE_QUALITY_ANALYSIS.md`
- `docs/architecture/SECURITY_ANALYSIS.md`
- `docs/architecture/WEB_SECURITY_REVIEW.md`
- `docs/architecture/DATABASE_ANALYSIS.md`
- `docs/architecture/RUNTIME_RELIABILITY.md`
- `docs/architecture/QA_TEST_DISCOVERY.md`
- `docs/architecture/QA_TEST_EXECUTION.md`
- `docs/architecture/ML_MODEL_REGISTRY.md`
- `docs/architecture/ONNX_INFERENCE_RUNTIME.md`
- `docs/architecture/ML_DESKTOP_WORKSPACE.md`
- `docs/architecture/VERIFIED_REPAIR_WORKFLOW.md`

## Privacy and security

Repositories are treated as untrusted input. Passive indexing, deterministic analyzers, database/runtime review, QA discovery, and repair proposal inspection do not execute repository commands. The static security layers do not crawl targets, send exploit payloads, connect to analyzed databases, or run target code. Secret-like security evidence is redacted before persistence where supported.

LSP semantic enrichment requires explicit trust and an externally configured language-server executable. CodeTwin does not discover a language server from the analyzed repository. The ML model registry treats package artifacts as data and does not permit package-provided shell hooks, Python plugins, repository commands, or arbitrary native libraries through the package contract. Executable ONNX inference runs in a bounded one-request worker and is not described as a complete cross-platform sandbox.

Repair application writes only explicitly approved replacement bytes plus CodeTwin-owned staging/backup data. It does not invoke shells, package managers, compilers, tests, hooks, language servers, or repository executables. Its multi-file staging and reverse rollback reduce mutation risk but are not described as a crash-proof filesystem transaction.

The optional OpenMindAI Dataset installer verifies release metadata, byte size, and SHA-256 before replacing the local dataset set. Declining or failing dataset installation no longer prevents installation of the base CodeTwin ML application; dataset-backed ML capabilities remain unavailable until a verified dataset package is installed.

See `SECURITY.md` for vulnerability reporting and the architecture documents for subsystem-specific trust boundaries.
