"""Consent-gated TLS certificate observations for one explicitly approved host.

Uses the platform trust store (or an explicitly supplied local CA for lab testing),
pins a revalidated DNS answer, never disables hostname checks, and emits no PEM.
This is a bounded certificate observation, not a cipher-suite sweep.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
from typing import Any


class TlsCheckError(ValueError):
    """Known, privacy-reduced failure category for a local certificate check."""


_BLOCKED_V4 = tuple(
    ipaddress.ip_network(block)
    for block in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
_BLOCKED_V6 = ipaddress.ip_network("2001:db8::/32")


def validate_host(raw: str) -> str:
    """Accept exactly one hostname or address; never a URL, CIDR or zone ID."""
    host = raw.strip().rstrip(".").lower()
    if not host or len(host) > 253 or any(char in host for char in "/\\:@%?#* "):
        # IPv6 literals are handled before rejecting their colon characters.
        try:
            return str(ipaddress.ip_address(host))
        except ValueError as error:
            raise TlsCheckError("invalid_target") from error
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host != "localhost" and "." not in host:
        raise TlsCheckError("invalid_target")
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise TlsCheckError("invalid_target")
    return host


def address_allowed(raw: str, allow_private: bool) -> bool:
    address = ipaddress.ip_address(raw)
    if address.is_unspecified or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        if any(address in net for net in _BLOCKED_V4):
            return False
    elif address in _BLOCKED_V6:
        return False
    if address.is_global:
        return True
    return allow_private and (
        address.is_private or address.is_loopback or address.is_link_local
    )


def resolve_target(host: str, port: int, allow_private: bool) -> tuple[str, ...]:
    try:
        addresses = {
            str(item[4][0])
            for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        }
    except OSError as error:
        raise TlsCheckError("dns_resolution_failed") from error
    if not addresses or len(addresses) > 16:
        raise TlsCheckError("dns_scope_failed")
    try:
        permitted = all(address_allowed(value, allow_private) for value in addresses)
    except ValueError as error:
        raise TlsCheckError("dns_scope_failed") from error
    if not permitted:
        raise TlsCheckError("address_out_of_scope")
    return tuple(sorted(addresses))


def validity_observation(
    cert: dict[str, Any], now: datetime | None = None
) -> dict[str, Any]:
    """Only read public certificate dates; never copy the certificate itself."""
    try:
        start = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc
        )
        end = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
        )
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        raise TlsCheckError("invalid_certificate_dates") from error
    reference = now if now is not None else datetime.now(timezone.utc)
    if start > reference or end <= reference:
        raise TlsCheckError("invalid_certificate_dates")
    remaining = (end - reference).total_seconds()
    return {
        "not_before_utc": start.isoformat(),
        "not_after_utc": end.isoformat(),
        "expires_in_days": max(0, int(remaining // 86400)),
        "expiry_state": "expiring_soon" if remaining <= 30 * 86400 else "valid",
    }


def check_certificate(
    host: str,
    port: int = 443,
    *,
    authorized: bool = False,
    allow_private: bool = False,
    timeout: float = 3.0,
    ca_file: Path | None = None,
) -> dict[str, Any]:
    """Validate exact identity and chain against a trusted CA via one TLS connection."""
    if not authorized:
        raise TlsCheckError("authorization_required")
    target = validate_host(host)
    if not 1 <= port <= 65535 or not 0.2 <= timeout <= 10.0:
        raise TlsCheckError("invalid_limits")
    # Scope all DNS results and ensure the answer is unchanged immediately
    # before connecting. Only the selected first address can be contacted.
    snapshot = resolve_target(target, port, allow_private)
    if resolve_target(target, port, allow_private) != snapshot:
        raise TlsCheckError("dns_answer_changed")
    try:
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except (OSError, ssl.SSLError) as error:
        raise TlsCheckError("trust_store_unavailable") from error
    try:
        with socket.create_connection((snapshot[0], port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            with context.wrap_socket(connection, server_hostname=target) as tls:
                certificate = tls.getpeercert()
                if not certificate:
                    raise TlsCheckError("certificate_unavailable")
                observations = validity_observation(certificate)
                cipher = tls.cipher()
                version = tls.version()
    except ssl.SSLCertVerificationError as error:
        raise TlsCheckError("certificate_verification_failed") from error
    except (ssl.SSLError, ConnectionError) as error:
        raise TlsCheckError("tls_handshake_failed") from error
    except (TimeoutError, socket.timeout) as error:
        raise TlsCheckError("timeout") from error
    except OSError as error:
        raise TlsCheckError("connection_failed") from error
    return {
        "status": "verified",
        "host": target,
        "port": port,
        "address": snapshot[0],
        "tls_version": version,
        "cipher_observed": cipher[0] if cipher is not None else None,
        "hostname_verified": True,
        "chain_verified": True,
        **observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="One-target trusted TLS certificate check")
    parser.add_argument("--host", required=True, help="Exact authorized DNS name or IP")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--authorized", action="store_true", help="I have permission to check this exact host and port")
    parser.add_argument("--allow-private", action="store_true", help="Permit loopback/private lab addresses")
    parser.add_argument("--ca-file", type=Path, help="Optional trusted lab CA bundle (never disables verification)")
    args = parser.parse_args()
    try:
        result = check_certificate(
            args.host, args.port, authorized=args.authorized,
            allow_private=args.allow_private, timeout=args.timeout,
            ca_file=args.ca_file,
        )
    except TlsCheckError as error:
        print(json.dumps({"status": "not_verified", "failure_kind": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
