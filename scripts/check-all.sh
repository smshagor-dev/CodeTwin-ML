#!/usr/bin/env bash
# Runs every CI gate locally, so changes can be validated without GitHub Actions.
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
step "End-to-end smoke"
cargo run --release -q -p codetwin-core --example e2e_smoke -- .

step "Python lint / types / tests"
python -m ruff check services/ml/codetwin_ml services/ml/tests \
  services/security/codetwin_security services/security/tests
MYPYPATH=services/ml:services/security python -m mypy \
  services/ml/codetwin_ml services/security/codetwin_security
python -m unittest discover -s services/ml/tests
python -m unittest discover -s services/security/tests
python -m compileall -q services/ml/codetwin_ml services/security/codetwin_security

step "Frontend"
npm ci --ignore-scripts
npm run typecheck
npm run test
npm run build
node --test fixtures/typescript-basic/tests/*.test.js

printf '\nAll gates passed.\n'
