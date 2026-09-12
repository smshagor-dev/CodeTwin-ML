from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Iterable

MAX_FILES = 20_000
MAX_FILE_BYTES = 1_048_576
MAX_DEPTH = 16
SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".sql"}
SUPPORTED_NAMES = {"settings.py", "config.py", "package.json", "phpunit.xml", "phpunit.xml.dist"}
SKIP_DIRS = {
    ".git", "node_modules", "target", ".venv", "venv", "dist", "build", "coverage",
    ".next", ".turbo", ".cache", "vendor", "__pycache__",
}

REQUEST_INPUT = r"(?:request\.(?:args|form|json|values|GET|POST|query_params|path_params)|req\.(?:query|body|params)|ctx\.request|\$_(?:GET|POST|REQUEST)|params\[|request\[)"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    confidence: float
    cwe: str
    owasp: str
    summary: str
    remediation: str
    pattern: re.Pattern[str]
    suffixes: frozenset[str] | None = None
    requires_request_input: bool = False


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    cwe: str
    owasp: str
    relative_path: str
    line: int
    summary: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    root: str
    files_considered: int
    files_scanned: int
    files_skipped: int
    coverage_complete: bool
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "files_considered": self.files_considered,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "coverage_complete": self.coverage_complete,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        "web.sql.dynamic_query",
        "database",
        "high",
        0.96,
        "CWE-89",
        "A03:2021 Injection",
        "Potential SQL/ORM injection from dynamically constructed query text",
        "Use parameterized queries or prepared statements. Keep request-controlled data out of SQL text.",
        _compile(r"(?:execute|executemany|query|raw)\s*\(\s*(?:f[\"']|[^\n;]*(?:\+|\.format\(|%\s*\())"),
        frozenset({".py", ".js", ".jsx", ".ts", ".tsx"}),
        False,
    ),
    Rule(
        "web.sql.request_to_query",
        "database",
        "high",
        0.99,
        "CWE-89",
        "A03:2021 Injection",
        "Request-controlled value appears in a database query sink",
        "Bind the value as a query parameter and validate its expected type before use.",
        _compile(r"(?:execute|executemany|query|raw|mysqli_query|->query)\s*\([^\n;]*(?:" + REQUEST_INPUT + r")"),
        frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".php"}),
        False,
    ),
    Rule(
        "web.xss.request_to_html",
        "xss",
        "high",
        0.95,
        "CWE-79",
        "A03:2021 Injection",
        "Request-controlled content reaches a raw HTML rendering sink",
        "Use context-aware escaping/sanitization and framework-safe rendering APIs instead of raw HTML injection.",
        _compile(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(|echo\s+|print\s+)[^\n;]*(?:" + REQUEST_INPUT + r")"),
        frozenset({".js", ".jsx", ".ts", ".tsx", ".php"}),
        False,
    ),
    Rule(
        "web.ssrf.request_url",
        "ssrf",
        "high",
        0.94,
        "CWE-918",
        "A10:2021 SSRF",
        "Request-controlled URL appears to reach an outbound HTTP client",
        "Allow-list schemes/hosts, block private/link-local destinations, and avoid fetching arbitrary user-supplied URLs.",
        _compile(r"(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post|put|delete)|urllib\.request\.urlopen|fetch\s*\(|axios\.(?:get|post|put|delete))[^\n;]*(?:" + REQUEST_INPUT + r")"),
        frozenset({".py", ".js", ".jsx", ".ts", ".tsx"}),
        False,
    ),
    Rule(
        "web.command.request_to_process",
        "command_injection",
        "critical",
        0.97,
        "CWE-78",
        "A03:2021 Injection",
        "Request-controlled value appears to reach a process execution sink",
        "Avoid shell execution. Use fixed executable/argument arrays and strict allow-list validation.",
        _compile(r"(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|child_process\.(?:exec|execSync)|\bexecSync\s*\()[^\n;]*(?:" + REQUEST_INPUT + r")"),
        frozenset({".py", ".js", ".jsx", ".ts", ".tsx"}),
        False,
    ),
    Rule(
        "web.path.request_to_file",
        "path_traversal",
        "high",
        0.91,
        "CWE-22",
        "A01:2021 Broken Access Control",
        "Request-controlled path appears to reach a filesystem response/read sink",
        "Resolve against a fixed root, reject traversal, and allow-list expected file identifiers instead of raw paths.",
        _compile(r"(?:open\s*\(|send_file\s*\(|FileResponse\s*\(|fs\.(?:readFile|readFileSync)\s*\()[^\n;]*(?:" + REQUEST_INPUT + r")"),
        frozenset({".py", ".js", ".jsx", ".ts", ".tsx"}),
        False,
    ),
    Rule(
        "web.deserialize.untrusted",
        "unsafe_deserialization",
        "high",
        0.95,
        "CWE-502",
        "A08:2021 Software and Data Integrity Failures",
        "Request-controlled data appears to reach an unsafe deserialization primitive",
        "Use a safe data format such as JSON and avoid object deserialization of untrusted input.",
        _compile(r"(?:pickle\.(?:loads|load)|yaml\.load\s*\(|unserialize\s*\()[^\n;]*(?:" + REQUEST_INPUT + r")"),
        frozenset({".py", ".php"}),
        False,
    ),
    Rule(
        "web.cors.wildcard",
        "cors",
        "medium",
        0.98,
        "CWE-942",
        "A05:2021 Security Misconfiguration",
        "Wildcard CORS policy is configured",
        "Restrict allowed origins, methods, and credentials to the minimum trusted set.",
        _compile(r"(?:allow_origins\s*=\s*\[\s*[\"']\*[\"']|Access-Control-Allow-Origin[^\n]*\*|origin\s*:\s*[\"']\*[\"'])"),
        None,
        False,
    ),
    Rule(
        "web.csrf.disabled",
        "csrf",
        "medium",
        0.96,
        "CWE-352",
        "A01:2021 Broken Access Control",
        "CSRF protection appears disabled or bypassed",
        "Enable CSRF protection for browser-authenticated state-changing requests and limit exemptions to documented cases.",
        _compile(r"(?:@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|verify_csrf_token\s*=\s*False|csrf\s*:\s*false)"),
        None,
        False,
    ),
    Rule(
        "web.session.insecure_cookie",
        "session",
        "medium",
        0.98,
        "CWE-614",
        "A05:2021 Security Misconfiguration",
        "Session cookie security attribute appears disabled",
        "Require Secure and HttpOnly cookies and set an appropriate SameSite policy for the application.",
        _compile(r"(?:SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False|secure\s*:\s*false[^\n]*cookie)"),
        None,
        False,
    ),
    Rule(
        "web.jwt.verification_disabled",
        "authentication",
        "critical",
        0.99,
        "CWE-347",
        "A07:2021 Identification and Authentication Failures",
        "JWT signature verification appears disabled",
        "Verify signatures and issuer/audience/expiry claims with an explicit allowed algorithm list.",
        _compile(r"(?:verify_signature[\"']?\s*[:=]\s*False|jwt\.decode\([^\n]*verify\s*=\s*False|algorithms?\s*=\s*\[[\"']none[\"']\])"),
        None,
        False,
    ),
    Rule(
        "web.debug.enabled",
        "debug_exposure",
        "medium",
        0.96,
        "CWE-489",
        "A05:2021 Security Misconfiguration",
        "Web debug mode appears enabled",
        "Disable debug mode outside local development and avoid exposing interactive debuggers or verbose exception pages.",
        _compile(r"(?:app\.run\([^\n]*debug\s*=\s*True|\bDEBUG\s*=\s*True\b)"),
        frozenset({".py"}),
        False,
    ),
)


def scan_repository(root: str | Path) -> ScanResult:
    root_path = Path(root).expanduser().resolve(strict=True)
    if not root_path.is_dir():
        raise ValueError(f"repository root is not a directory: {root_path}")

    findings: list[Finding] = []
    considered = 0
    scanned = 0
    skipped = 0
    coverage_complete = True

    for path in _iter_candidates(root_path):
        considered += 1
        if considered > MAX_FILES:
            raise ValueError(f"web security scan exceeds bounded file limit: {MAX_FILES}")
        try:
            if path.is_symlink():
                skipped += 1
                coverage_complete = False
                continue
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root_path):
                skipped += 1
                coverage_complete = False
                continue
            size = resolved.stat().st_size
            if size > MAX_FILE_BYTES:
                skipped += 1
                coverage_complete = False
                continue
            source = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            skipped += 1
            coverage_complete = False
            continue

        scanned += 1
        relative = resolved.relative_to(root_path).as_posix()
        findings.extend(_scan_source(relative, resolved.suffix.lower(), source))

    findings.sort(key=lambda item: (item.relative_path, item.line, item.rule_id, item.fingerprint))
    return ScanResult(
        root=str(root_path),
        files_considered=considered,
        files_scanned=scanned,
        files_skipped=skipped,
        coverage_complete=coverage_complete,
        findings=tuple(findings),
    )


def _iter_candidates(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if len(relative.parts) > MAX_DEPTH:
            continue
        if any(part in SKIP_DIRS for part in relative.parts[:-1]):
            continue
        if path.is_dir():
            continue
        if path.name in SUPPORTED_NAMES or path.suffix.lower() in SUPPORTED_SUFFIXES:
            yield path


def _scan_source(relative_path: str, suffix: str, source: str) -> list[Finding]:
    output: list[Finding] = []
    lines = source.splitlines()
    for index, line in enumerate(lines, start=1):
        if _is_comment_only(line, suffix):
            continue
        for rule in RULES:
            if rule.suffixes is not None and suffix not in rule.suffixes:
                continue
            if not rule.pattern.search(line):
                continue
            if rule.requires_request_input and not re.search(REQUEST_INPUT, line, re.IGNORECASE):
                continue
            evidence = _safe_excerpt(line)
            fingerprint = sha256(
                f"{rule.rule_id}\0{relative_path}\0{index}\0{evidence}".encode("utf-8")
            ).hexdigest()
            output.append(
                Finding(
                    fingerprint=fingerprint,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    relative_path=relative_path,
                    line=index,
                    summary=rule.summary,
                    evidence=evidence,
                    remediation=rule.remediation,
                )
            )
    return output


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
    excerpt = re.sub(r"(?i)(https?://[^:/\s]+:)[^@\s]+@", r"\1<redacted>@", excerpt)
    if len(excerpt) > 240:
        excerpt = excerpt[:237] + "..."
    return excerpt
