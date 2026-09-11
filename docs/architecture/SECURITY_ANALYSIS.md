# AppSec Security Analysis

CodeTwin ML's first AppSec layer is deterministic and evidence-backed. It reads only files that already belong to the active persistent source index, verifies that the on-disk bytes still match the persisted SHA-256 content hash, parses the source with the supported Tree-sitter grammar, and persists review findings into the existing normalized findings/evidence model.

## Baseline rules

The initial rules are intentionally narrow and auditable:

- `security.hardcoded_credential_literal` — a credential-like identifier is assigned a non-placeholder string literal. The literal value is never stored in the finding, evidence summary, or metadata. CWE-798; OWASP A07:2021 mapping.
- `security.dynamic_code_execution` — `eval`/`exec`-style execution is present. This is a review finding, not proof that attacker-controlled input reaches the sink. CWE-95; OWASP A03:2021 mapping.
- `security.weak_cryptographic_hash` — MD5/SHA-1 use is observed. The finding explicitly requires usage-context review because checksum/non-security uses can be intentional. CWE-327; OWASP A02:2021 mapping.
- `security.unsafe_c_string_api` — an unbounded legacy C/C++ string API such as `gets`, `strcpy`, `strcat`, `sprintf`, or `vsprintf` is called. This is not proof of an overflow. CWE-120 review mapping.

## Source and trust boundary

Security analysis does not execute repository commands, package scripts, tests, compilers, hooks, shell commands, language servers, or model inference. It does not search the system for tools.

For every indexed file the analyzer:

1. rejects absolute and parent-traversal relative paths;
2. rejects symlink file targets and canonical paths escaping the indexed project root;
3. enforces the same 5 MiB source-size ceiling used by the source-indexing baseline;
4. requires a successfully parsed indexed file;
5. recomputes SHA-256 and requires equality with the persisted index hash before inspecting source;
6. treats UTF-8 or parse failures as incomplete coverage rather than security evidence.

The source text is transient analyzer input. Full source and credential literals are not persisted by this subsystem.

## Finding lifecycle

AppSec findings use `analyzer_key = appsec`, so their lifecycle never resolves or rewrites code-quality or future analyzer findings. Fingerprints are deterministic for a project/file/rule/anchor/location. A repeated observation refreshes the same finding and evidence. When a complete analysis run no longer observes a finding, it becomes `resolved` instead of being deleted.

Resolution is conservative. If any active indexed file is stale or skipped, `coverage_complete` is false and the run does not auto-resolve missing AppSec findings. This prevents an un-reindexed source change or parse failure from being misreported as a security fix.

## Persistence and queries

Migration `0007_security_analysis.sql` adds per-run AppSec metrics while reusing `analysis_runs`, `findings`, and `finding_evidence`. Findings persist CWE/OWASP mapping where the baseline rule has one, source line range, optional containing symbol, rule version, confidence, first/last seen time, and resolved state. Evidence persists the indexed content hash, redacted rule metadata, source URI, and location.

Queries are bounded to 500 findings/evidence records and 100 run-history entries. Analysis refuses projects beyond 20,000 active indexed files.

## Current limitations

The baseline does not claim taint flow, source-to-sink proof, SQL injection, command injection, XSS reachability, path traversal, authentication bypass, dependency CVEs, SAST completeness, secret validity, exploitability, or runtime compromise. Those require dedicated data-flow, dependency, configuration, or runtime evidence and will be introduced as separate tested analyzers.
