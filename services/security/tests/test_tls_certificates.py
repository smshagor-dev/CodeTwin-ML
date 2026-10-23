"""Unit and local-loopback TLS verification tests (no external host accessed)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import shutil
import socket
import ssl
import sys
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codetwin_security.tls_certificates import (  # noqa: E402
    TlsCheckError,
    address_allowed,
    check_certificate,
    resolve_target,
    validate_host,
    validity_observation,
)


class TlsCertificateChecks(unittest.TestCase):
    def test_target_input_and_scope_are_strict(self) -> None:
        self.assertEqual(validate_host("Example.org."), "example.org")
        self.assertEqual(validate_host("::1"), "::1")
        for invalid in ("https://example.org", "example.org/path", "example.org:443",
                        "bad host", "10.0.0.0/8", "user@example.org", "devhost"):
            with self.subTest(invalid=invalid), self.assertRaises(TlsCheckError):
                validate_host(invalid)
        self.assertFalse(address_allowed("127.0.0.1", False))
        self.assertTrue(address_allowed("127.0.0.1", True))
        self.assertFalse(address_allowed("192.0.2.1", True))
        self.assertFalse(address_allowed("2001:db8::1", True))
        self.assertFalse(address_allowed("224.0.0.1", True))
        self.assertTrue(address_allowed("10.5.2.1", True))
        self.assertFalse(address_allowed("10.5.2.1", False))
        self.assertFalse(address_allowed(str(ipaddress.ip_address("0.0.0.0")), True))

    def test_missing_consent_fails_without_network_activity(self) -> None:
        with patch(
            "codetwin_security.tls_certificates.socket.getaddrinfo"
        ) as resolver:
            with self.assertRaisesRegex(TlsCheckError, "authorization_required"):
                check_certificate("example.org")
            resolver.assert_not_called()

    def test_resolution_rejects_entire_mixed_dns_answer(self) -> None:
        addresses = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443)),
        ]
        with patch(
            "codetwin_security.tls_certificates.socket.getaddrinfo",
            return_value=addresses,
        ):
            with self.assertRaisesRegex(TlsCheckError, "address_out_of_scope"):
                resolve_target("localhost", 443, True)

    def test_certificate_validity_boundaries(self) -> None:
        now = datetime(2026, 10, 23, tzinfo=timezone.utc)
        stamp = lambda moment: moment.strftime("%b %d %H:%M:%S %Y GMT")
        cert = {
            "notBefore": stamp(now - timedelta(days=1)),
            "notAfter": stamp(now + timedelta(days=2)),
        }
        summary = validity_observation(cert, now)
        self.assertEqual(summary["expiry_state"], "expiring_soon")
        self.assertGreater(summary["expires_in_days"], 0)
        cert["notAfter"] = stamp(now + timedelta(days=120))
        self.assertEqual(validity_observation(cert, now)["expiry_state"], "valid")
        cert["notAfter"] = stamp(now - timedelta(seconds=1))
        with self.assertRaisesRegex(TlsCheckError, "invalid_certificate_dates"):
            validity_observation(cert, now)
        cert["notAfter"] = "unparseable"
        with self.assertRaises(TlsCheckError):
            validity_observation(cert, now)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable not installed")
    def test_local_trusted_certificate_and_hostname_mismatch(self) -> None:
        # Generate a disposable lab certificate at runtime, without committing
        # private keys or bypassing platform hostname validation.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            cert = directory / "certificate.pem"
            key = directory / "private.key"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert), "-days", "2",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                ],
                check=True, timeout=25, capture_output=True,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)

            def serve_once(listener: socket.socket) -> None:
                try:
                    connection, _ = listener.accept()
                    with connection:
                        with context.wrap_socket(connection, server_side=True):
                            pass
                except (OSError, ssl.SSLError):
                    # The mismatch case terminates the handshake intentionally.
                    pass
                finally:
                    listener.close()

            def run_local_case(target: str) -> dict[str, object]:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(5)
                port = listener.getsockname()[1]
                thread = threading.Thread(target=serve_once, args=(listener,), daemon=True)
                thread.start()
                try:
                    result = check_certificate(
                        target, port, authorized=True,
                        allow_private=True, ca_file=cert, timeout=3.0,
                    )
                    return result
                finally:
                    thread.join(timeout=6)

            # localhost is resolved to loopback; IPv4 selection wins by
            # deterministic sorting, and the trusted SAN matches.
            verified = run_local_case("localhost")
            self.assertEqual(verified["status"], "verified")
            self.assertTrue(verified["hostname_verified"])
            self.assertTrue(verified["chain_verified"])
            self.assertIn(verified["tls_version"], ("TLSv1.2", "TLSv1.3"))
            self.assertEqual(verified["expiry_state"], "expiring_soon")
            with self.assertRaisesRegex(TlsCheckError, "certificate_verification_failed"):
                run_local_case("127.0.0.1")


if __name__ == "__main__":
    unittest.main()
