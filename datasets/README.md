# OpenMindAI Dataset for CodeTwin ML

CodeTwin ML uses a versioned **OpenMindAI Dataset** catalog for defect detection, quality assurance, security analysis, repair generation, and verified repair evaluation.

| OpenMindAI Dataset | Primary use | Approx. upstream download |
| --- | --- | ---: |
| OpenMindAI Dataset - Defect Detection | defect, QA, security screening | 22.3 MB |
| OpenMindAI Dataset - Code Refinement | buggy-to-fixed repair learning | 20.8 MB |
| OpenMindAI Dataset - Repair Verification | real repository repair verification | 2.1 MB |
| OpenMindAI Dataset - Security Vulnerability | CWE / vulnerability classification | 132 MB |
| **Total** | | **~177.2 MB** |

## GitHub Release distribution

The canonical dataset release tag is `openmindai-datasets-v1.0.0`. The release is built as four modular assets plus a machine-readable manifest and checksum file:

```text
openmindai-dataset-defect-detection-v1.0.0.zip
openmindai-dataset-code-refinement-v1.0.0.zip
openmindai-dataset-repair-verification-v1.0.0.zip
openmindai-dataset-security-vulnerability-v1.0.0.zip
openmindai-dataset-manifest-v1.0.0.json
openmindai-dataset-SHA256SUMS.txt
```

The release workflow downloads the pinned Hugging Face revisions, verifies catalog checksums where published, records provenance for every file, packages each dataset separately, computes SHA-256 for every release asset, and creates or updates the versioned GitHub Release.

Release assets are used instead of normal Git blobs. This keeps repository history small and avoids GitHub's normal per-object limit for the approximately 105 MB security training shard. GitHub Releases allow individual assets up to 2 GiB, which is appropriate for this dataset pack.

## Browser-style Windows installation

The Windows NSIS installer follows an online-bootstrap pattern similar to a browser installer. The application installer remains small. During the post-install stage it:

1. presents the dataset-use terms and requires acceptance;
2. downloads the versioned release manifest from GitHub Releases;
3. downloads all four OpenMindAI Dataset assets;
4. validates the declared byte size and SHA-256 of every archive;
5. extracts into a staging directory;
6. replaces the installed dataset set only after all four assets validate; and
7. writes `openmindai-dataset-install-state.json` after successful completion.

The Windows target directory is `%LOCALAPPDATA%\CodeTwinML\datasets`. Setup retries transient network failures and does not silently report success with a partial dataset installation.

## Licensing and attribution

The two CodeXGLUE datasets are distributed under C-UDA. Their use is limited to computational use, and redistribution must preserve upstream attribution and bind downstream recipients to the C-UDA terms. The installer therefore requires explicit dataset-terms acceptance before it downloads the release pack.

The security vulnerability dataset declares Apache-2.0. The SWE-bench project declares MIT for the project; issue, patch, repository, and other third-party task material can retain its original upstream terms. Every release archive embeds source repository, pinned revision, license/terms URL, and attribution notice.

## Developer prefetch

Direct Hugging Face prefetch remains available for development and recovery:

```bash
python scripts/prefetch_datasets.py --dataset code_security_vulnerability
python scripts/prefetch_datasets.py --action security_analysis
python scripts/prefetch_datasets.py --action repair_verification --accept-license upstream-unspecified
python scripts/prefetch_datasets.py --all --accept-license c-uda --accept-license upstream-unspecified
```

Raw developer downloads are ignored under `datasets/cache/`. The downloader builds URLs only from versioned catalog metadata, pinned revisions, and validated relative paths. Request payloads cannot inject arbitrary URLs. Temporary `.part` files and atomic replacement protect against partial downloads.

## Action-wise routing

- `defect_detection` -> Defect Detection, Security Vulnerability
- `quality_assurance` -> Defect Detection, Code Refinement
- `security_analysis` -> Security Vulnerability, Defect Detection
- `cwe_classification` -> Security Vulnerability
- `repair_generation` -> Code Refinement, Repair Verification
- `repair_verification` -> Repair Verification
- `regression_repair` -> Repair Verification, Code Refinement

The Python sidecar exposes `datasets.list`, `datasets.route`, `datasets.status`, and `datasets.prefetch`. Dataset availability does not imply an ML model is installed or evaluated; model capabilities remain disabled until a verified model artifact exists.
