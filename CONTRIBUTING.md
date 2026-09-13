# Contributing

Use focused branches created from the current `main`, add tests with behavior changes, and keep documentation aligned with actual capability. Do not commit credentials, raw datasets, model weights, runtime databases, generated logs, or build output.

## Pull request safety

Before opening a pull request, update from the current `main` and inspect the final `main...branch` diff. A PR is not ready merely because GitHub reports it as mergeable.

For stacked pull requests, a child PR may target its parent feature branch while the stack is under review, but it must not be assumed to land on `main` automatically. After the parent merges, every remaining child must be retargeted or rebased onto the new `main`, its final diff must be rechecked, and required validation must run again. Never merge a child only into an obsolete feature branch and treat the feature as present on `main`.

Do not resolve a conflict by blindly choosing either side of a shared integration file. Preserve the current command registry, migrations, dashboard/workspace routing, QA/security boundaries, and any newer `main` functionality, then verify the resulting diff for accidental deletions.

## Required validation

Run the available formatting, lint, type-check, test, and build gates before merge:

```bash
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

CI must actually execute. A GitHub Actions job with `runner_id=0`, an empty runner name, or `steps=[]` is an infrastructure failure, not a passing validation result. Do not merge required code changes while the required CI gate has not executed successfully.

Keep safety capability claims conservative. In particular, do not promote QA execution, filesystem isolation, network isolation, verified repair, ML confidence, runtime telemetry, or exploitability beyond what the current implementation and executed validation prove.
