from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

from .analyzer import (
    Finding,
    MAX_DEPTH,
    MAX_FILES,
    MAX_FILE_BYTES,
    REQUEST_INPUT,
    SKIP_DIRS,
    SUPPORTED_NAMES,
    SUPPORTED_SUFFIXES,
)

TAINT_WINDOW_LINES = 40
CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".php"}
SQL_SINK = r"(?:execute|executemany|query|raw|\$queryRawUnsafe|\$executeRawUnsafe|mysqli_query|->query)"

RULES: tuple[tuple[str, str, str, float, str, str, str, str, re.Pattern[str], frozenset[str] | None], ...] = (
    (
        "web.sql.orm_unsafe_raw",
        "database",
        "critical",
        0.99,
        "CWE-89",
        "A03:2021 Injection",
        "Request-controlled input reaches an explicitly unsafe ORM/raw-query API",
        "Replace unsafe raw-query APIs with parameterized/tagged APIs and bind every data value separately.",
        re.compile(
            r"(?:\$queryRawUnsafe|\$executeRawUnsafe|sequelize\.literal|knex\.raw|db\.raw)"
            r"\s*\([^\n;]*(?:" + REQUEST_INPUT + r")",
            re.IGNORECASE,
        ),
        frozenset({".js", ".jsx", ".ts", ".tsx"}),
    ),
    (
        "web.sql.dynamic_identifier",
        "database",
        "high",
        0.96,
        "CWE-89",
        "A03:2021 Injection",
        "Request-controlled value appears in a SQL identifier or ordering position",
        "Map user choices to a fixed allow-list of known table, column, sort, and direction identifiers.",
        re.compile(
            SQL_SINK
            + r"\s*\([^\n;]*(?:FROM|JOIN|ORDER\s+BY|GROUP\s+BY|UPDATE|INTO)\s+[^\n;]*(?:"
            + REQUEST_INPUT
            + r")",
            re.IGNORECASE,
        ),
        frozenset(CODE_SUFFIXES),
    ),
    (
        "web.sql.multistatement_enabled",
        "database",
        "high",
        0.98,
        "CWE-89",
        "A05:2021 Security Misconfiguration",
        "Database client allows multiple SQL statements in one request",
        "Keep multi-statement execution disabled and use one parameterized statement per operation.",
        re.compile(
            r"(?:multipleStatements|allowMultiQueries|multiStatements)\s*[:=]\s*(?:true|True)",
            re.IGNORECASE,
        ),
        frozenset({".js", ".jsx", ".ts", ".tsx", ".py"}),
    ),
    (
        "database.sql.dynamic_exec",
        "database",
        "high",
        0.91,
        "CWE-89",
        "A03:2021 Injection",
        "SQL artifact constructs dynamic SQL before EXEC/EXECUTE/PREPARE",
        "Avoid dynamic SQL when possible; allow-list identifiers and bind all data values.",
        re.compile(
            r"\b(?:EXEC(?:UTE)?(?:\s+IMMEDIATE)?|PREPARE)\b[^\n;]*(?:\+|\|\||CONCAT\s*\()",
            re.IGNORECASE,
        ),
        frozenset({".sql"}),
    ),
    (
        "database.sql.dynamic_prepare",
        "database",
        "medium",
        0.84,
        "CWE-89",
        "A03:2021 Injection",
        "SQL artifact prepares a statement from a variable expression",
        "Trace the prepared SQL source and prefer fixed statements with bound parameters.",
        re.compile(
            r"\bPREPARE\s+[A-Za-z_][A-Za-z0-9_]*\s+FROM\s+[@:$]?[A-Za-z_][A-Za-z0-9_]*",
            re.IGNORECASE,
        ),
        frozenset({".sql"}),
    ),
    (
        "web.database.connection_tls_disabled",
        "database",
        "high",
        0.96,
        "CWE-319",
        "A02:2021 Cryptographic Failures",
        "Database connection configuration explicitly disables transport protection",
        "Require TLS for non-local database connections and verify the server certificate/hostname.",
        re.compile(
            r"(?:DATABASE_URL|DB_URL|connectionString|connection_string)[^\n;]*"
            r"(?:sslmode\s*=\s*disable|ssl\s*=\s*false|ssl=false)",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "web.header.request_to_response",
        "header_injection",
        "high",
        0.93,
        "CWE-113",
        "A03:2021 Injection",
        "Request-controlled value appears to reach an HTTP response-header sink",
        "Reject CR/LF and preferably allow-list the complete header value or redirect target.",
        re.compile(
            r"(?:res\.(?:setHeader|header|set)\s*\(|header\s*\(|response\.headers\[[^\]]+\]\s*=)"
            r"[^\n;]*(?:" + REQUEST_INPUT + r")",
            re.IGNORECASE,
        ),
        frozenset(CODE_SUFFIXES),
    ),
)


def scan_injection_hardening(root: str | Path) -> tuple[Finding, ...]:
    root_path = Path(root).expanduser().resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError(f"repository root is not a directory: {root_path}")

    output: list[Finding] = []
    considered = 0
    for path in root_path.rglob("*"):
        try:
            relative = path.relative_to(root_path)
        except ValueError:
            continue
        if len(relative.parts) > MAX_DEPTH:
            continue
        if any(part in SKIP_DIRS for part in relative.parts[:-1]):
            continue
        if path.is_dir():
            continue
        if path.name not in SUPPORTED_NAMES and path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue

        considered += 1
        if considered > MAX_FILES:
            raise ValueError(f"injection hardening scan exceeds bounded file limit: {MAX_FILES}")

        try:
            if path.is_symlink():
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root_path):
                continue
            if resolved.stat().st_size > MAX_FILE_BYTES:
                continue
            source = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue

        suffix = resolved.suffix.lower()
        relative_path = resolved.relative_to(root_path).as_posix()
        output.extend(_scan_source(relative_path, suffix, source))

    unique = {
        (item.rule_id, item.relative_path, item.line, item.evidence): item
        for item in output
    }
    findings = sorted(
        unique.values(),
        key=lambda item: (item.relative_path, item.line, item.rule_id, item.fingerprint),
    )
    return tuple(findings)


def _scan_source(relative_path: str, suffix: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()

    for index, line in enumerate(lines, start=1):
        if _is_comment_only(line, suffix):
            continue
        for (
            rule_id,
            category,
            severity,
            confidence,
            cwe,
            owasp,
            summary,
            remediation,
            pattern,
            suffixes,
        ) in RULES:
            if suffixes is not None and suffix not in suffixes:
                continue
            if pattern.search(line):
                findings.append(
                    _finding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        confidence=confidence,
                        cwe=cwe,
                        owasp=owasp,
                        relative_path=relative_path,
                        line=index,
                        summary=summary,
                        evidence=_safe_excerpt(line),
                        remediation=remediation,
                    )
                )

    if suffix in CODE_SUFFIXES:
        findings.extend(_scan_tainted_flows(relative_path, suffix, lines))
    return findings


def _scan_tainted_flows(relative_path: str, suffix: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    tainted: dict[str, int] = {}
    assignment = re.compile(
        r"^\s*(?:(?:const|let|var)\s+)?(\$?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$",
        re.IGNORECASE,
    )
    request_re = re.compile(REQUEST_INPUT, re.IGNORECASE)
    sql_sink_re = re.compile(SQL_SINK + r"\s*\(", re.IGNORECASE)
    header_sink_re = re.compile(
        r"(?:res\.(?:setHeader|header|set)\s*\(|header\s*\(|response\.headers\[[^\]]+\]\s*=)",
        re.IGNORECASE,
    )

    for index, line in enumerate(lines, start=1):
        if _is_comment_only(line, suffix):
            continue

        for name, source_line in list(tainted.items()):
            if index - source_line > TAINT_WINDOW_LINES:
                del tainted[name]

        match = assignment.match(line)
        if match:
            variable, expression = match.groups()
            if request_re.search(expression):
                tainted[variable] = index
            else:
                propagated_from = next(
                    (
                        (name, source_line)
                        for name, source_line in tainted.items()
                        if name != variable and _expression_propagates_taint(expression, name)
                    ),
                    None,
                )
                if propagated_from is not None:
                    tainted[variable] = propagated_from[1]
                else:
                    tainted.pop(variable, None)

        for variable, source_line in tainted.items():
            if index == source_line:
                continue
            if not re.search(
                rf"(?<![A-Za-z0-9_$]){re.escape(variable)}(?![A-Za-z0-9_])",
                line,
            ):
                continue

            if sql_sink_re.search(line) and _unsafe_tainted_sql_use(line, variable):
                findings.append(
                    _finding(
                        rule_id="web.sql.tainted_variable_to_query",
                        category="database",
                        severity="critical",
                        confidence=0.94,
                        cwe="CWE-89",
                        owasp="A03:2021 Injection",
                        relative_path=relative_path,
                        line=index,
                        summary="Request-derived variable reaches dynamically composed SQL",
                        evidence=_safe_excerpt(line),
                        remediation=(
                            f"Variable `{variable}` originates from request input near line {source_line}. "
                            "Bind it as a data parameter; for identifiers use a fixed allow-list."
                        ),
                        fingerprint_extra=f"{variable}:{source_line}",
                    )
                )

            if header_sink_re.search(line) and _unsafe_tainted_argument_use(line, variable):
                findings.append(
                    _finding(
                        rule_id="web.header.tainted_value",
                        category="header_injection",
                        severity="high",
                        confidence=0.89,
                        cwe="CWE-113",
                        owasp="A03:2021 Injection",
                        relative_path=relative_path,
                        line=index,
                        summary="Request-derived variable reaches an HTTP response-header sink",
                        evidence=_safe_excerpt(line),
                        remediation=(
                            f"Variable `{variable}` originates from request input near line {source_line}. "
                            "Reject CR/LF and allow-list the complete header or redirect value."
                        ),
                        fingerprint_extra=f"{variable}:{source_line}",
                    )
                )

    return findings


def _unsafe_tainted_sql_use(line: str, variable: str) -> bool:
    escaped = re.escape(variable)
    dynamic_patterns = (
        rf"\{{\s*{escaped}\s*\}}",
        rf"\$\{{\s*{escaped}\s*\}}",
        rf"(?:\+|\.)\s*{escaped}\b",
        rf"\b{escaped}\s*(?:\+|\.)",
        rf"\.format\s*\([^)]*\b{escaped}\b",
    )
    if any(re.search(pattern, line) for pattern in dynamic_patterns):
        return True
    if re.search(SQL_SINK + rf"\s*\(\s*{escaped}\s*(?:,|\))", line, re.IGNORECASE):
        return True
    return bool(
        re.search(
            rf"mysqli_query\s*\([^,]+,\s*{escaped}\s*(?:,|\))",
            line,
            re.IGNORECASE,
        )
    )


def _expression_propagates_taint(expression: str, variable: str) -> bool:
    escaped = re.escape(variable)
    stripped = expression.strip().rstrip(";")
    if re.fullmatch(escaped, stripped):
        return True
    patterns = (
        rf"\{{\s*{escaped}\s*\}}",
        rf"\$\{{\s*{escaped}\s*\}}",
        rf"(?:\+|\.)\s*{escaped}\b",
        rf"\b{escaped}\s*(?:\+|\.)",
        rf"\.format\s*\([^)]*\b{escaped}\b",
    )
    return any(re.search(pattern, expression) for pattern in patterns)


def _unsafe_tainted_argument_use(line: str, variable: str) -> bool:
    escaped = re.escape(variable)
    return bool(
        re.search(rf"\(\s*{escaped}\s*(?:,|\))", line)
        or re.search(rf",\s*{escaped}\s*(?:,|\))", line)
        or re.search(rf"=\s*{escaped}\s*$", line)
    )


def _finding(
    *,
    rule_id: str,
    category: str,
    severity: str,
    confidence: float,
    cwe: str,
    owasp: str,
    relative_path: str,
    line: int,
    summary: str,
    evidence: str,
    remediation: str,
    fingerprint_extra: str = "",
) -> Finding:
    fingerprint = sha256(
        f"{rule_id}\0{relative_path}\0{line}\0{evidence}\0{fingerprint_extra}".encode("utf-8")
    ).hexdigest()
    return Finding(
        fingerprint=fingerprint,
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=confidence,
        cwe=cwe,
        owasp=owasp,
        relative_path=relative_path,
        line=line,
        summary=summary,
        evidence=evidence,
        remediation=remediation,
    )


def _is_comment_only(line: str, suffix: str) -> bool:
    stripped = line.lstrip()
    if suffix == ".py":
        return stripped.startswith("#")
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".php"}:
        return stripped.startswith("//") or stripped.startswith("*")
    if suffix == ".sql":
        return stripped.startswith("--")
    return False


def _safe_excerpt(line: str) -> str:
    excerpt = line.strip()
    excerpt = re.sub(
        r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)[\"'][^\"']*[\"']",
        r"\1\"<redacted>\"",
        excerpt,
    )
    excerpt = re.sub(
        r"(?i)((?:postgres(?:ql)?|mysql|mariadb)://[^:/\s]+:)[^@\s]+@",
        r"\1<redacted>@",
        excerpt,
    )
    excerpt = re.sub(r"(?i)(https?://[^:/\s]+:)[^@\s]+@", r"\1<redacted>@", excerpt)
    if len(excerpt) > 240:
        excerpt = excerpt[:237] + "..."
    return excerpt
