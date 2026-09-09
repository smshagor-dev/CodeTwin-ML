# Development Setup

## Windows priority target

Install Node.js 22+, Rust stable 1.82+, Python 3.12+, Microsoft C++ Build Tools, and the current Tauri 2 Windows prerequisites including WebView2.

From the repository root:

```powershell
npm install
cargo test --workspace
python -m unittest discover -s services/ml/tests
npm run typecheck
npm run build
```

For desktop development:

```powershell
npm --workspace @codetwin/desktop run dev
cargo tauri dev --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Linux and macOS require their platform Tauri prerequisites. No GPU is required for the foundation tests.
