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

## Java rules and taint tracking

Java files are indexed and analysed like the other languages (ruleset `appsec-source-v3`). On top
of the shared hard-coded-credential rule, `crates/security-analyzer/src/java.rs` adds:

| Rule | What it matches | CWE |
| --- | --- | --- |
| `web.sql.request_to_query` | Request-tainted SQL built by `+`, `String.format`, `concat` reaching JDBC, JPA or `JdbcTemplate` | 89 |
| `java.sql.concatenated_query` | The same SQL building with no request input traced (review) | 89 |
| `web.command.request_to_process` / `java.command.dynamic_exec` | `Runtime.exec`, `ProcessBuilder` with tainted / non-literal commands | 78 |
| `web.xss.request_to_response` | Tainted, non-HTML-encoded data written through `getWriter()`/`getOutputStream()` | 79 |
| `web.path.request_to_file` | Tainted paths into `File*`, `Paths.get`, `Path.of`, `Files.*` | 22 |
| `web.ldap.request_to_filter` | Tainted LDAP search filters | 90 |
| `web.xpath.request_to_expression` | Tainted XPath `evaluate`/`compile` | 643 |
| `web.ssrf.request_url` | Tainted URL into `RestTemplate`, `WebClient`, `URI.create`, or a `URL` that is opened | 918 |
| `web.redirect.request_to_location`, `web.header.request_to_response` | Tainted `sendRedirect`, response headers | 601, 113 |
| `security.weak_cryptographic_hash`, `java.crypto.weak_cipher` | MD5/SHA-1 digests; DES, 3DES, RC2, RC4, Blowfish, ECB and bare `AES` ciphers | 327 |
| `java.deserialization.untrusted_stream` | `ObjectInputStream`, `XMLDecoder`, `XStream.fromXML` (review) | 502 |
| `java.xml.xxe_unhardened_parser` | XML parser factories with no XXE hardening anywhere in the file | 611 |
| `java.tls.hostname_verification_disabled`, `java.tls.trust_all_certificates` | Accept-all hostname verifiers, empty `checkServerTrusted` | 295 |
| `java.spring.csrf_disabled`, `java.cookie.not_secure` | Spring Security CSRF off (review), `setSecure(false)` | 352, 614 |
| `security.dynamic_code_execution` | `ScriptEngine.eval`, SpEL `parseExpression` with non-literal input | 95, 917 |

**Taint model.** Sources are servlet request accessors and Spring MVC / JAX-RS parameters
annotated as request input (`@RequestParam`, `@PathVariable`, `@RequestBody`, `@QueryParam`, …).
Each method is analysed flow-sensitively in statement order: reassignment replaces a value,
branches are analysed separately and joined, loops run twice, and conditions, ternaries and
`switch` selectors that fold to constants (int, char, string, boolean locals) skip dead branches.
Taint follows assignments, `+=`, arrays, `for`-each loops, collection and builder writes, map
reads with literal keys and list reads with literal indexes. Same-file helper methods are
summarised (does the return value carry parameter taint, and is it HTML-escaped), and request
values passed into same-file helpers seed those helpers' parameters. Numeric parsing removes
taint; HTML escaping (ESAPI, Spring `HtmlUtils`, commons-text, OWASP Encoder) removes it for XSS
only.

**Measured.** Against the OWASP Benchmark for Java v1.2 (2,740 labelled servlets; run
`cargo run --release -p security-analyzer --example owasp_benchmark -- <BenchmarkJava checkout>`),
counting only the confirmed request-to-sink rules for SQL and command injection:

| Category | TP | FP | TN | FN | TPR | FPR | Score |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cmdi | 115 | 0 | 125 | 11 | 91.3% | 0.0% | +91.3 |
| crypto | 97 | 0 | 116 | 33 | 74.6% | 0.0% | +74.6 |
| hash | 89 | 0 | 107 | 40 | 69.0% | 0.0% | +69.0 |
| ldapi | 24 | 0 | 32 | 3 | 88.9% | 0.0% | +88.9 |
| pathtraver | 118 | 0 | 135 | 15 | 88.7% | 0.0% | +88.7 |
| securecookie | 36 | 0 | 31 | 0 | 100.0% | 0.0% | +100.0 |
| sqli | 255 | 0 | 232 | 17 | 93.8% | 0.0% | +93.8 |
| xpathi | 14 | 0 | 20 | 1 | 93.3% | 0.0% | +93.3 |
| xss | 220 | 0 | 209 | 26 | 89.4% | 0.0% | +89.4 |

Average Benchmark score (TPR − FPR) over the 9 covered categories: **+87.7**. Not covered:
`trustbound` and `weakrand`. Missed `hash` and `crypto` cases read the algorithm name from a
properties file, which a single-file analysis cannot see. The review-level rules
(`java.sql.concatenated_query`, `java.command.dynamic_exec`) fire on every dynamic SQL string or
command by design, so they are excluded from the score.

Treat these numbers with care: the engine was developed while inspecting Benchmark cases, and
scores on a benchmark a tool was tuned against overstate real-world precision. On real code:
Spring PetClinic (50 Java files) produces no AppSec findings; OWASP WebGoat (431 Java files)
reports its intentional SQL injection lessons (9 confirmed), path traversal and Zip Slip lessons,
the SSRF lesson, deserialization gadgets, disabled CSRF and the lesson credentials, in about 1 s.

**Not modelled:** taint across files or through fields, reflection, framework-specific sources
beyond the annotations above (e.g. Struts, Play), sanitisers other than numeric parsing and HTML
escaping, and Kotlin/Scala/Groovy.

## Current limitations

Outside Java, request-to-sink rules only recognise request input that appears inside the sink
call itself (no data flow), and the baseline rules are review findings. No language claims
cross-file taint, authentication bypass, SAST completeness, secret validity, exploitability, or
runtime compromise.
