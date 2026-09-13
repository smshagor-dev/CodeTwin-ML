# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner. Do not open a public issue containing exploit details, credentials, private repository content, proof-of-concept payloads, or sensitive logs.

A useful report should include the affected component, the exact CodeTwin ML version or commit, reproduction steps, expected versus observed behavior, security impact, and any relevant sanitized logs. Remove secrets and proprietary source before sharing evidence.

## Supported code

Security fixes are developed against the current `main` branch. Older branches, experimental feature branches, generated artifacts, local build output, and unmaintained forks should not be assumed to receive security fixes.

## Trust boundaries

CodeTwin treats analyzed repositories, source files, manifests, logs, model packages, datasets, language-server output, generated artifacts, and repair proposals as untrusted input unless a workflow explicitly requires a trusted external executable.

Passive indexing and deterministic analyzers must not execute repository commands. Semantic enrichment requires an explicitly configured external language-server executable. ML inference requires an explicitly configured local Python executable and sidecar root. QA execution remains blocked until its documented isolation requirements are satisfied. Repair application is a separate explicit mutation boundary and must preserve approval, hash preconditions, bounded writes, backup evidence, and independent post-state verification.

## Source and secret handling

The current implementation does not intentionally transmit analyzed source code to external services. Local workflows may pass source bytes to explicitly configured local processes where documented, such as the ML sidecar or trusted language server. Secret-like evidence should be redacted before persistence where supported.

Do not commit API keys, passwords, signing keys, private certificates, proprietary datasets, model weights with restricted redistribution terms, runtime databases, or sensitive logs to this repository.

## Security claims

Do not treat an indexed file, analyzer finding, ML prediction, QA execution plan, repair proposal, applied repair, or hash match as stronger evidence than the implementation actually provides. In particular:

- an ML prediction is not a confirmed deterministic finding;
- an approved QA plan is not a test result;
- a repair application is not verified until the repository is re-indexed and the relevant analyzer lifecycle confirms the post-state;
- disabled filesystem or network isolation must not be presented as enabled;
- CI jobs that never allocate a runner or execute steps are infrastructure failures, not successful validation.

## Dependency and supply-chain changes

Dependency updates, model packages, dataset releases, external runtimes, and CI actions should use pinned or otherwise reviewable provenance wherever practical. Integrity-sensitive artifacts should be size-checked and SHA-256 verified before use.
