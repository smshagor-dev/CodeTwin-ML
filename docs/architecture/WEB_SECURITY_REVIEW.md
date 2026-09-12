# Python Web Security Review

CodeTwin ML includes a bounded Python static-analysis service for defensive web/API security review. It inspects repository source as untrusted data and never imports, executes, starts, or exploits the analyzed application.

## Scope

The baseline identifies conservative line-level evidence for:

- dynamic or request-controlled SQL/ORM queries that may indicate SQL injection;
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

Findings include severity, confidence, CWE, OWASP category, source path/line, bounded evidence, and remediation text. Secret-like assignment values and URL credentials are redacted before evidence is emitted.

## Execution boundary

The analyzer does not send HTTP requests, crawl websites, brute-force authentication, submit payloads, connect to databases, execute SQL, start browsers, invoke package scripts, import project modules, or run repository executables. It therefore reports static risk evidence rather than exploitability or confirmed compromise.

## Bounds

Repository traversal is limited to 20,000 candidate files, 1 MiB per file, and depth 16. Generated/vendor/cache directories are skipped. Symlinks, unreadable files, non-UTF-8 files, root escapes, and oversized candidates are skipped and mark scan coverage incomplete.

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

The Rust AppSec analyzer remains responsible for generic deterministic source-security findings such as hard-coded credential literals and dangerous primitives. The Python web-security service adds request-to-sink and web-framework/configuration context, including database injection review, without duplicating live runtime testing.
