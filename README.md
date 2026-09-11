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
| OpenMindAI Dataset catalog + action routing | Implemented foundation |
| Security/database/runtime analyzers | Planned |
| ML inference models | Planned |
| Verified repair workflow | Planned |

Planned capabilities are not presented as available results. Semantic graph relationships and quality findings are materialized only from persisted evidence; ambiguous, unresolved, external, or stale observations are not converted into guessed local facts.

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

See `docs/development/SETUP.md`, `docs/architecture/DIGITAL_TWIN.md`, `docs/architecture/LSP_SEMANTIC_ENRICHMENT.md`, and `docs/architecture/CODE_QUALITY_ANALYSIS.md`.

## Privacy and security

Passive source indexing, Digital Twin persistence, and deterministic code-quality analysis treat repositories as untrusted data and do not execute repository commands. LSP semantic enrichment is a separate explicit workflow: it requires project trust and a user-configured absolute external language-server executable. CodeTwin does not discover or execute a language server from the analyzed repository.
