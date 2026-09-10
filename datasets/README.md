# CodeTwin ML Dataset Catalog

CodeTwin ML versions dataset metadata and routing rules in Git while caching raw dataset files locally.

| Dataset | Primary use | Approx. download |
| --- | --- | ---: |
| CodeXGLUE Defect Detection / Devign | defect, QA, security screening | 22.3 MB |
| CodeXGLUE Code Refinement | buggy-to-fixed repair learning | 20.8 MB |
| SWE-bench Verified | real repository repair verification | 2.1 MB |
| Code Security Vulnerability Dataset | CWE / vulnerability classification | 132 MB |
| **Total** | | **~177.2 MB** |

## Storage model

One upstream security training shard is approximately 105 MB, above GitHub's regular Git 100 MiB object limit. Therefore CodeTwin versions the pinned source catalog, checksums, licensing metadata, downloader, and routing logic while downloaded bytes live under `datasets/cache/`.

This also keeps the C-UDA datasets sourced directly from their publisher rather than redistributing those bytes through the CodeTwin repository.

A dataset is reported ready only after expected files are present. Published SHA-256 and byte counts are verified. For catalog files without a published checksum, CodeTwin computes SHA-256 after download, records it in `_codetwin_source.json`, and uses that provenance on later cache checks.

## Prefetch

```bash
python scripts/prefetch_datasets.py --dataset code_security_vulnerability
python scripts/prefetch_datasets.py --action security_analysis
python scripts/prefetch_datasets.py --action repair_verification --accept-license upstream-unspecified
python scripts/prefetch_datasets.py --all --accept-license c-uda --accept-license upstream-unspecified
```

C-UDA datasets require explicit `--accept-license c-uda`. SWE-bench Verified is marked `upstream-unspecified` because its dataset source used by this catalog does not declare a dataset license; review upstream terms before accepting it.

Downloaded files are stored as:

```text
datasets/cache/<dataset-id>/<pinned-revision>/<upstream-path>
```

## Action-wise routing

- `defect_detection` -> CodeXGLUE Defect Detection, Code Security Vulnerability Dataset
- `quality_assurance` -> CodeXGLUE Defect Detection, CodeXGLUE Code Refinement
- `security_analysis` -> Code Security Vulnerability Dataset, CodeXGLUE Defect Detection
- `cwe_classification` -> Code Security Vulnerability Dataset
- `repair_generation` -> CodeXGLUE Code Refinement, SWE-bench Verified
- `repair_verification` -> SWE-bench Verified
- `regression_repair` -> SWE-bench Verified, CodeXGLUE Code Refinement

The Python sidecar exposes `datasets.list`, `datasets.route`, `datasets.status`, and `datasets.prefetch`. Dataset availability does not imply an ML model is installed or evaluated; model capabilities remain disabled until a verified model artifact exists.

## Security boundary

The prefetcher builds URLs only from versioned Hugging Face repository metadata, pinned revisions, and validated relative paths. Request payloads cannot supply arbitrary URLs. Downloads use temporary `.part` files plus atomic replacement. Downloaded code, tests, package scripts, compilers, and language servers are never executed by the dataset manager.
