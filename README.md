# CodeTwin ML

**Local Software Digital Twin for Predictive Quality, Security, Reliability, and Verified Repair**

CodeTwin ML is a local-first engineering intelligence desktop application. It combines deterministic program analysis, project metadata, test and runtime evidence, security findings, database inspection, visual QA, and measurable ML components into a durable Software Digital Twin.

## Current capability status

| Capability | Status |
| --- | --- |
| Monorepo + Tauri/React desktop shell | Implemented foundation |
| Local SQLite schema + migrations | Implemented foundation |
| Project stack discovery | Implemented |
| Tree-sitter AST/source indexing | Implemented baseline for TypeScript/TSX, JavaScript/JSX, Python, Rust, Go, C, C++, PHP |
| Definition symbol extraction + content-hash incremental skip | Implemented baseline |
| Normalized analysis/finding domain types | Implemented foundation |
| Secure stdio ML sidecar protocol | Implemented foundation |
| LSP-enhanced symbol resolution | Planned next |
| Digital Twin graph materialization | Planned next |
| QA/security/database/runtime engines | Planned |
| Verified repair workflow | Planned |

Nothing marked planned is presented as available in the UI. The Tree-sitter baseline currently extracts definition tags; richer import/export/call/data-flow indexing will be added as separate tested capabilities.

## Development

Prerequisites: Node.js 22+, Rust 1.82+, Python 3.12+, platform dependencies required by Tauri 2.

```bash
npm install
npm run typecheck
cargo test --workspace
python -m unittest discover -s services/ml/tests
```

See `docs/development/SETUP.md` and `docs/architecture/OVERVIEW.md`.

## Privacy and security

Core analysis is designed to stay local. Repositories are treated as untrusted data and are never considered instructions to CodeTwin. External model usage is not enabled by this foundation.
