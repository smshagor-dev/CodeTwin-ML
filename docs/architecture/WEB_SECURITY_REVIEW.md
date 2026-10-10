# Web Security Review

CodeTwin ML has two complementary static web-security layers. The Rust deterministic analyzer operates on current hash-verified indexed source and persists findings into the shared Software Digital Twin lifecycle. The Python service performs broader bounded source/config review, including selected SQL/config artifacts that are not necessarily part of the source index. Neither layer imports, executes, starts, crawls, or exploits the analyzed application.

## Scope

The broader Python baseline identifies conservative source-backed evidence for:

- direct request-to-query SQL/ORM injection;
- second-order request taint that is later interpolated or passed as SQL text;
- explicitly unsafe ORM/raw-query APIs such as Prisma unsafe raw calls;
- request-controlled table, column, ordering, or other SQL identifier positions;
- database clients configured to allow multiple SQL statements per operation;
- dynamic SQL construction inside `.sql` artifacts using `EXEC`, `EXECUTE`, or `PREPARE`;
- database connection strings that explicitly disable transport protection;
- request-controlled HTTP response-header values that may permit header/CRLF injection;
- request-controlled raw HTML sinks that may indicate XSS;
- request-controlled outbound URLs that may indicate SSRF;
- request-controlled process execution that may indicate command injection;
- request-controlled filesystem paths that may indicate path traversal;
- unsafe deserialization of request-controlled values;
- wildcard CORS configuration;
- disabled or bypassed CSRF protection;
- insecure session-cookie attributes;
- disabled JWT signature verification;
- web debug mode enabled in source configuration.

The deterministic indexed-source analyzer additionally persists high-confidence direct request-flow findings for SQL/ORM sinks, unsafe raw SQL APIs, dynamic SQL identifier contexts, response-header injection, SSRF, and request-to-process execution alongside existing AppSec rules.

Findings include severity, confidence, CWE, OWASP category, source location, bounded evidence, and remediation text. Secret-like assignment values plus HTTP and supported database URL credentials are redacted before evidence is emitted.

## Desktop workspace and persistence

The desktop **Web Security** workspace reuses the existing `security_analysis` Tauri commands and the shared `findings` / `finding_evidence` lifecycle instead of creating a parallel finding store. A run first indexes the project, then the deterministic security analyzer reads only active indexed files whose current bytes still match the persisted content hash. Web rules use the `web.*` namespace, so the workspace can filter web/request-flow findings separately while still allowing the user to inspect all persisted AppSec findings.

Each persisted finding keeps first-seen, last-seen, run provenance, status, CWE/OWASP metadata, source line range, and redacted evidence. A complete later scan can resolve a previously open finding when the concrete observation is no longer present. Incomplete scans do not claim that unseen findings were fixed.

The desktop workspace exposes run history, open/resolved filtering, severity/confidence, and on-demand evidence inspection. It does not run the Python scanner as a child process and therefore does not introduce a new external-interpreter trust boundary. The Python service remains available as the broader static CLI layer for non-indexed configuration and SQL artifact review.

## SQL-injection hardening model

The SQL rules are deliberately defense-in-depth rather than a claim that source scanning can prove a database is secure.

A secure query path should:

1. keep SQL statement structure fixed;
2. bind all data values through prepared/parameterized APIs;
3. never accept raw SQL from a request;
4. map dynamic table, column, sort, and direction choices through fixed application allow-lists;
5. keep multi-statement client options disabled;
6. avoid dynamic SQL in stored procedures/migrations where possible;
7. use least-privilege database accounts;
8. require TLS for non-local database connections and verify the server identity;
9. keep credentials outside source and rotate them independently;
10. combine application checks with database constraints, transaction boundaries, backups, and audit logging.

The Python taint pass is intentionally bounded to 40 source lines. It tracks simple request-derived assignments and propagation through direct assignment, concatenation, f-strings/template interpolation, and `.format(...)`. A later query is reported only when the tainted value becomes SQL text or an unsafe SQL argument. Bound-parameter containers such as `execute("... ?", (user_id,))` are not reported by that taint rule.

The deterministic indexed-source rule is intentionally narrower: it reports direct request-controlled values that occur in the same database call, plus explicitly unsafe raw APIs. This gives the desktop a high-confidence persisted baseline while avoiding a claim that simple static heuristics fully model application taint flow.

## Header-injection hardening

The baseline recognizes direct and simple request flows into common response-header APIs. Applications should reject carriage-return/line-feed characters and, for sensitive headers such as `Location`, prefer a complete allow-list of acceptable values or destinations.

## Execution boundary

The analyzers do not send HTTP requests, crawl websites, brute-force authentication, submit payloads, connect to project databases, execute SQL, start browsers, invoke package scripts, import project modules, or run repository executables. They report static risk evidence rather than exploitability or confirmed compromise.

## Bounds

The Python repository traversal is limited to 20,000 candidate files, 1 MiB per file, depth 16, and a 40-line local taint-propagation window. Generated/vendor/cache directories are skipped. Symlinks, unreadable files, non-UTF-8 files, root escapes, and oversized candidates are skipped and mark scan coverage incomplete.

The deterministic desktop path inherits the indexed-source security analyzer bounds and verifies current bytes against the persistent source index before analysis.

Supported Python baseline source types are Python, JavaScript/JSX, TypeScript/TSX, PHP, and SQL plus selected web configuration files. The deterministic persisted source path supports the source languages indexed by CodeTwin and applies web request-flow rules only to Python, JavaScript/TypeScript, and PHP families.

## CLI

Run the broader Python review from the repository root:

```bash
python services/security/run.py /path/to/project --format text
python services/security/run.py /path/to/project --format json
python services/security/run.py /path/to/project --fail-on high
```

`--fail-on` is optional. It returns exit code 2 when a finding at or above the selected severity exists; it does not execute or attack the target application.

## Relationship to other analyzers

The deterministic Rust security analyzer owns durable indexed-source AppSec and web request-flow findings. The Rust database analyzer reviews SQL/Prisma artifacts for schema and migration risks. The Python web-security service adds broader request-to-sink, taint, ORM, SQL-injection, database-transport, header-injection, and configuration context without duplicating live runtime testing.


### Custom JavaScript discovery milestone

The crawler parses external JavaScript responses with a bounded custom lexer
(no execution or third-party scanner). It traverses single-literal-argument
`fetch()` and `axios.get()` calls using the existing scope, DNS pinning, rate limit,
request budget and crawl depth. Query parameter inventory comes from the actual
response. Root-relative and absolute URLs are supported. Calls in comments and
quoted strings, dynamic URLs, templates, escaped literals, request options and
non-GET calls are skipped. Source is capped at 1 MiB, 32,768 tokens and 256 calls;
truncated responses are not parsed. Sources containing ambiguous division/regex
syntax are conservatively skipped. Inline executable script elements and external scripts retain their owning document
URL, including the first base href, so relative fetch URLs resolve against the
document rather than the asset directory. Shared assets are fetched once and
reused for each discovered document (up to 256 owners). HTML comments and
non-executable data script types are skipped. JavaScript execution, runtime
rebinding and Axios custom base URLs are not resolved.
A static call is an endpoint candidate, not proof that the application executes it.

Boolean response comparisons now require complete responses on both sides.
Truncated identical prefixes or changed statuses cannot establish a confirmed
SQL injection through those comparisons. Local HTTP lab coverage verifies real
GET traversal, excluded/out-of-scope rejection, negative discovery cases and the
shared request cap. This is bounded coverage, not a claim of perfect detection.


### Milestone 3: method inventory and redirect provenance

Static method-only fetch options (`{method: 'POST'}` etc.) and single-argument
Axios method calls contribute method-specific endpoint inventory. Only GET
candidates are traversed during discovery. No request body or credentials are
inferred from JavaScript. Unknown/dynamic options are skipped. Existing active
execution policy remains responsible for separately authorized testing.
`window.fetch` and `globalThis.fetch` are supported; custom object fetch calls
are excluded. Unterminated literals/comments invalidate the source inventory.
Regex/division, runtime rebinding, custom Axios configuration and complex fetch
options remain unsupported and are conservatively skipped.

Script redirect aliases retain document ownership. Later documents can reuse
already parsed redirected assets without refetching them. Redirect traversal
still uses the configured redirect limit and scope policy. Local lab coverage
includes a document discovered after the redirected asset was parsed, actual
GET calls for both document bases, and POST/DELETE inventory with zero write
requests. The first base element with an href supplies the document base.


### Milestone 4: repeatable authorization-context comparison

Object-like GET endpoint comparison now requires two distinct, nonempty supplied
contexts. Header names are normalized and context ordering is ignored; bearer
and cookie whitespace follows transport normalization. Different contexts are
not proof of different principals or role membership.

Both baseline responses must be complete, successful, MIME-compatible and
byte-identical. HTML password-input login pages are excluded. Both contexts
are then re-requested, and all four complete responses must remain identical
before a Potential finding is recorded. Expired/denied sessions, changed primary
sessions, truncated responses and insufficient repeat-request budgets produce
no access-control finding. This does not infer the application's intended
object ownership policy or confirm IDOR. Successful JSON login/error envelopes
and runtime role mapping require application-specific policy evidence.

All four evidence records redact secrets from both supplied contexts, including
cross-context echoes. The same global rate/request budget and cancellation rules
apply to rechecks. Endpoints where origin policy strips the supplied credentials
are excluded from identity comparison. No login automation, credential refresh or identifier
enumeration is performed. Local lab tests cover valid repeats, identical tokens,
anonymous primary context, 401/403, a 200 login form, truncation, primary-session
expiry between requests, tight budgets and secret echoes.


### Milestone 5: conservative SQL confirmation controls

Boolean SQL comparison now requires complete, successful responses with the same
status and MIME type and compares full body hashes. Digits and whitespace are no
longer masked; content after 64 KiB is not ignored. This deliberately reduces
coverage for volatile pages rather than treating changed records/counts as
identical. A 403/429/500 or MIME change is not a boolean query differential.

Confirmation requires the initial true/false pair, a fresh unchanged baseline,
and a second logically equivalent predicate pair using different constants in
reverse order. All true controls must exactly match the baseline and both false
controls must match each other while differing from the baseline. Evidence
contains all six responses. An incomplete repeat retains at most the initial
Likely signal; cancellation propagates. Quote-error indicators remain Likely,
never Confirmed, and incomplete baseline/probe bodies cannot establish them.
No extraction, writes or timing probes were added.

Real local SQLite HTTP lab tests compare unsafe SQL construction with prepared
parameter binding. Additional negative controls cover WAF rejection, a fixed
first-payload response rule and baseline changes. These tests establish bounded
behavior, not universal SQL injection detection or proof against every WAF.
