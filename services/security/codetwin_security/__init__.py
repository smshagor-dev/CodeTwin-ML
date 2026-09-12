"""Static web security review for untrusted repositories."""

from .analyzer import Finding, ScanResult, scan_repository

__all__ = ["Finding", "ScanResult", "scan_repository"]
