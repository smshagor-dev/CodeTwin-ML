#!/usr/bin/env bash
# Runs portable CI gates; does not replace Windows QA or signed installer checks.
# Usage: scripts/check-all.sh            (all gates)
#        SKIP_DESKTOP=1 scripts/check-all.sh   (skip the Tauri crate, e.g. without GTK/WebKit)
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

exclude=()
if [[ "${SKIP_DESKTOP:-0}" == "1" ]]; then
  exclude=(--exclude codetwin-desktop)
fi

step "Rust format"
cargo fmt --all -- --check
step "Rust clippy"
cargo clippy --workspace "${exclude[@]}" --all-targets -- -D warnings
step "Rust tests"
cargo test --workspace "${exclude[@]}"
step "Measured loopback benchmark"
cargo test -p web-security-testing --test local_lab security_readiness_benchmark -- --ignored --nocapture
step "End-to-end smoke"
cargo run --release -q -p codetwin-core --example e2e_smoke -- .

step "Python lint / types / tests"
python -m ruff check services/ml/codetwin_ml services/ml/tests \
  services/security/codetwin_security services/security/tests scripts
MYPYPATH=services/ml:services/security python -m mypy \
  services/ml/codetwin_ml services/security/codetwin_security
python -m mypy scripts/install_openmindai_datasets.py scripts/pin_hf_dataset.py
python -m unittest discover -s services/ml/tests
python -m unittest discover -s services/security/tests
python -m compileall -q services/ml/codetwin_ml services/security/codetwin_security

step "Frontend"
npm ci --ignore-scripts
npm audit --audit-level=low
npm run typecheck
npm run test
npm run build
node --test fixtures/typescript-basic/tests/*.test.js

step "Browser controls (install with npx playwright install chromium)"
node scripts/security/verify-xss-contexts.cjs
node scripts/security/verify-cors-controls.cjs
node scripts/security/verify-desktop-routes.cjs

if [[ "${SKIP_DESKTOP:-0}" == "1" ]]; then
  printf '\nPortable gates passed; native desktop, Windows QA and signed installer are not verified.\n'
else
  printf '\nLocal gates passed; Windows QA and signed installer validation remain required.\n'
fi
