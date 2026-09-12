from __future__ import annotations

import argparse
import json
from pathlib import Path

from .combined import scan_repository

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codetwin-web-security",
        description="Static defensive web-security review for a local repository.",
    )
    parser.add_argument("root", type=Path, help="Repository root to inspect")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--fail-on",
        choices=("none", "medium", "high", "critical"),
        default="none",
        help="Return exit code 2 when a finding at or above this severity is present.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = scan_repository(args.root)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(
            f"Scanned {result.files_scanned}/{result.files_considered} candidate files "
            f"(coverage={'complete' if result.coverage_complete else 'incomplete'})."
        )
        if not result.findings:
            print("No supported web-security patterns were detected.")
        for finding in result.findings:
            print(
                f"[{finding.severity.upper()}] {finding.rule_id} "
                f"{finding.relative_path}:{finding.line} — {finding.summary}"
            )
            print(f"  Evidence: {finding.evidence}")
            print(f"  {finding.cwe}; {finding.owasp}")
            print(f"  Fix: {finding.remediation}")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(item.severity, 0) >= threshold for item in result.findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
