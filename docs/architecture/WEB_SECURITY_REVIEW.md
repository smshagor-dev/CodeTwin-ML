# Python Web Security Review

CodeTwin ML includes a bounded Python static-analysis service for defensive web/API security review. It inspects repository source as untrusted data and never imports, executes, starts, or exploits the analyzed application.

## Scope

The baseline identifies conservative source-backed evidence for:

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

Findings include severity, confidence, CWE, OWASP category, source path/line, bounded evidence, and remediation text. Secret-like assignment values plus HTTP and supported database URL credentials are redacted before evidence is emitted.

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

The taint pass is intentionally bounded to 40 source lines. It tracks simple request-derived assignments and propagation through direct assignment, concatenation, f-strings/template interpolation, and `.format(...)`. A later query is reported only when the tainted value becomes SQL text or an unsafe SQL argument. Bound-parameter containers such as `execute("... ?", (user_id,))` are not reported by that taint rule.

## Header-injection hardening

The baseline also recognizes direct and simple tainted request flows into common response-header APIs. Applications should reject carriage-return/line-feed characters and, for sensitive headers such as `Location`, prefer a complete allow-list of acceptable values or destinations.

## Execution boundary

The analyzer does not send HTTP requests, crawl websites, brute-force authentication, submit payloads, connect to databases, execute SQL, start browsers, invoke package scripts, import project modules, or run repository executables. It therefore reports static risk evidence rather than exploitability or confirmed compromise.

## Bounds

Repository traversal is limited to 20,000 candidate files, 1 MiB per file, depth 16, and a 40-line local taint-propagation window. Generated/vendor/cache directories are skipped. Symlinks, unreadable files, non-UTF-8 files, root escapes, and oversized candidates are skipped and mark scan coverage incomplete.

Supported baseline source types are Python, JavaScript/JSX, TypeScript/TSX, PHP, and SQL plus selected web configuration files.

## CLI

Run from the repository root:

```bash
python services/security/run.py /path/to/project --format text
python services/security/run.py /path/to/project --format json
python services/security/run.py /path/to/project --fail-on high
```

`--fail-on` is optional. It returns exit code 2 when a finding at or above the selected severity exists; it does not execute or attack the target application.

## Relationship to other analyzers

The Rust AppSec analyzer remains responsible for generic deterministic source-security findings such as hard-coded credential literals and dangerous primitives. The Rust database analyzer reviews SQL/Prisma artifacts for schema and migration risks. The Python web-security service adds request-to-sink, taint, ORM, SQL-injection, database-transport, and header-injection context without duplicating live runtime testing.
