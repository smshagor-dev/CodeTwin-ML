from __future__ import annotations

from pathlib import Path

from .analyzer import Finding, ScanResult, scan_repository as _scan_base
from .injection_hardening import scan_injection_hardening


def scan_repository(root: str | Path) -> ScanResult:
    base = _scan_base(root)
    extra = scan_injection_hardening(root)
    merged = {
        (item.rule_id, item.relative_path, item.line, item.evidence): item
        for item in (*base.findings, *extra)
    }
    findings: tuple[Finding, ...] = tuple(
        sorted(
            merged.values(),
            key=lambda item: (item.relative_path, item.line, item.rule_id, item.fingerprint),
        )
    )
    return ScanResult(
        root=base.root,
        files_considered=base.files_considered,
        files_scanned=base.files_scanned,
        files_skipped=base.files_skipped,
        coverage_complete=base.coverage_complete,
        findings=findings,
    )
