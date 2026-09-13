# Development Setup

## Windows priority target

Install Node.js 22+, Rust stable 1.82+, Python 3.12+, Microsoft C++ Build Tools, and the current Tauri 2 Windows prerequisites including WebView2.

From the repository root, run the validation surface that mirrors the repository CI as closely as possible:

```powershell
npm install --ignore-scripts
npm run typecheck
npm run test
npm run build
node --test fixtures/typescript-basic/tests/*.test.js

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

python -m unittest discover -s services/ml/tests -v
python -m unittest discover -s services/security/tests -v
python -m compileall -q services/ml/codetwin_ml services/security/codetwin_security
```

The repository does not currently contain `package-lock.json` or `Cargo.lock`. Do not fabricate them. After issue #48 is completed with real package-manager-generated lockfiles, development and CI instructions should switch to deterministic locked installs (`npm ci` and release-relevant Cargo commands with `--locked`).

For desktop development:

```powershell
npm --workspace @codetwin/desktop run dev
cargo tauri dev --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Linux and macOS require their platform Tauri prerequisites. Linux CI additionally installs the Tauri/WebKitGTK build dependencies before Rust clippy/tests. No GPU is required for the current foundation tests.

## Validation boundaries

A GitHub Actions job that never allocates a runner or executes steps is not a successful validation result. See `docs/development/RELEASE_GATES.md` for the release/merge evidence requirements.

Passive analyzers do not execute the analyzed repository. ML inference, semantic enrichment, QA execution, and repair application each have separate trust boundaries documented under `docs/architecture/` and must not be treated as interchangeable validation evidence.
