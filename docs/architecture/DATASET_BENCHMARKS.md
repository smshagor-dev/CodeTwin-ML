# Dataset benchmarks

CodeTwin scores its own deterministic analyzers against the pinned Hugging Face datasets in
`datasets/catalog.json` and writes a report. The goal is a repeatable quality signal: if a rule
change makes the security analyzer or the secret scanner worse on public labeled data, the report
shows it.

Crate: `crates/dataset-benchmark` (library, `codetwin-dataset-bench` CLI). Desktop: Security →
Dataset Benchmarks.

## Where the data comes from

Nothing in the benchmark downloads anything. It reads files that one of the installers put on
disk:

| Platform | Installer | Default directory |
| --- | --- | --- |
| Windows | NSIS post-install hook (`install-openmindai-datasets.ps1`), after the user accepts the dataset terms | `%LOCALAPPDATA%\CodeTwinML\datasets` |
| macOS | `python3 install_openmindai_datasets.py --accept-dataset-terms` (bundled in the app resources, also in `scripts/`) | `~/Library/Application Support/CodeTwinML/datasets` |
| Linux | same script | `$XDG_DATA_HOME/CodeTwinML/datasets` or `~/.local/share/CodeTwinML/datasets` |
| Development | `python scripts/prefetch_datasets.py` (straight from Hugging Face) | `datasets/cache` |

Both installers download the versioned GitHub Release pack, check every archive's size and
SHA-256 against the release manifest, extract into staging, reject archive members that escape
the target directory, and swap the whole set in only when all four archives validate. A failed
install leaves the previous one untouched.

The layout is `<root>/<dataset id>/<pinned revision>/<file>`. Before reading a split, the
benchmark hashes every file of that split and compares it to the catalog's size and SHA-256 pin.
A mismatch stops that dataset with `integrity_failed`; it is never scored.

## What is measured

Each catalog entry carries a `benchmark` profile:

| Dataset | Task | What the report shows |
| --- | --- | --- |
| Defect Detection (Devign, C) | `vulnerability_detection` | Confusion matrix, precision, recall, F1, per-rule precision, secret-scanner hits |
| Security Vulnerability (multi-language, CWE labels) | `vulnerability_detection` | The same, plus per-language and per-CWE recall, including whether the analyzer reported the same CWE |
| Code Refinement (Java buggy → fixed) | `repair_pairs` | Whether findings on the buggy side disappear after the fix and whether the fix introduces new ones (CodeXGLUE abstracts identifiers, so few security rules apply) |
| SWE-bench Verified (real patches) | `secret_probe` | Secret-scanner hits per 1,000 patches; on public patches these are almost all false positives |

A sample counts as flagged when the security analyzer reports any observation. Every report
includes the F1 of a detector that flags everything, so a score can be read against the trivial
baseline.

Samples are taken at an even stride across the split, up to the sample limit (default 2,000,
maximum 200,000). Samples over 256 KiB, unlabeled rows and languages the analyzer has no grammar
for are counted and skipped, never guessed. Java is supported, so the Code Refinement
(buggy → fixed Java) pairs are scored.

Column names are taken from the profile when given (Devign: `func`, `target`) and otherwise
matched against common Hugging Face names (`code`/`func`/`source`, `label`/`target`/`is_vulnerable`,
`cwe`/`cwe_id`, `language`/`lang`). If no match is found the dataset stops with
`schema_unrecognized` and the report lists the columns it saw, so the profile can be fixed in
the catalog.

## Reports

Each run writes `report.json` (schema version 1), `report.md` and a self-contained
`report.html` (no scripts, all text escaped). The desktop app stores runs under
`<app data>/benchmarks/<run id>/` and can save any of the three files elsewhere. Reports
contain metrics and rule ids only; no sample code and no secret values.

CLI:

```bash
cargo run --release -p dataset-benchmark --bin codetwin-dataset-bench -- \
  --datasets-root ~/.local/share/CodeTwinML/datasets --split test --max-samples 5000 --out bench-out
```

The CLI exits non-zero when no dataset could be evaluated.

## Adding a Hugging Face dataset

1. Read the dataset card and confirm the license yourself.
2. Pin it: `python3 scripts/pin_hf_dataset.py OWNER/NAME --id my_dataset --license <verified id>
   --license-url <url> --purpose vulnerability_detection --task vulnerability_detection
   --include 'data/*.parquet'`. The script resolves the branch to a commit and records the size and
   SHA-256 of every file (from the Hub's LFS metadata, or by hashing small files).
3. Add the printed entry to `datasets/catalog.json`, a route in `routes`, an asset in
   `datasets/openmindai-release.json`, and a row in `datasets/ATTRIBUTION.md`.
4. Publish a new dataset release tag and bump the tag in the installers. The installers expect
   exactly the number of assets in the release config.

Security-oriented datasets are used here only as labeled code for measuring detection. The
benchmark never executes sample code and never sends it anywhere.
