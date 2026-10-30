"""Independent signing and verification of exported CodeTwin workflow reports.

This deliberately shares no code with the desktop application: it uses the
Python `cryptography` Ed25519 implementation instead of Rust `ring`, so an
exported bundle can be checked by someone who does not trust CodeTwin itself.

Private keys stay with the operator. `sign` reads a PEM key file the operator
controls and prints only the public key and signature; the key is never
written, logged or sent anywhere. A valid trusted signature shows who issued a
report and that it is unmodified. It does not show that the findings are true.

    python scripts/workflow_report_signature.py keygen --out signer.pem
    python scripts/workflow_report_signature.py sign bundle.json --key signer.pem
    python scripts/workflow_report_signature.py verify bundle.json --trust <hex> [...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BUNDLE_FORMAT = "codetwin.signed-workflow-report-bundle.v1"
REPORT_FORMAT = "codetwin.signed-workflow-report.v1"
DOMAIN = b"CodeTwin-ML/workflow-report/ed25519/v1\0"
BUNDLE_FIELDS = {"format", "report_sha256", "report_json", "signatures"}
MAX_BUNDLE_BYTES = 8 * 1024 * 1024


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError(f"Duplicate JSON field: {key}")
        fields[key] = value
    return fields


def load_bundle(text: str) -> dict[str, Any]:
    bundle = json.loads(text, object_pairs_hook=_unique_fields)
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS:
        raise ValueError("Bundle must contain exactly the expected fields")
    if bundle["format"] != BUNDLE_FORMAT:
        raise ValueError(f"Unsupported bundle format: {bundle['format']!r}")
    if not isinstance(bundle["report_json"], str) or not isinstance(bundle["signatures"], list):
        raise ValueError("Bundle fields have the wrong types")
    return bundle


def signing_payload(report_sha256: str) -> bytes:
    digest = bytes.fromhex(report_sha256)
    if len(digest) != 32:
        raise ValueError("Report SHA-256 must be 32 bytes")
    return DOMAIN + digest


def check_integrity(bundle: dict[str, Any]) -> list[str]:
    """Problems with the report bytes themselves; empty when intact."""
    problems = []
    actual = hashlib.sha256(bundle["report_json"].encode("utf-8")).hexdigest()
    if actual != bundle["report_sha256"]:
        problems.append("report bytes do not match the recorded SHA-256")
    try:
        report = json.loads(bundle["report_json"], object_pairs_hook=_unique_fields)
    except ValueError as error:
        return problems + [f"report is not valid JSON: {error}"]
    if not isinstance(report, dict) or report.get("format") != REPORT_FORMAT:
        problems.append("report envelope has an unexpected format")
    return problems


def _public_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def verify(bundle: dict[str, Any], trusted_keys: list[str]) -> dict[str, Any]:
    trusted = {key.strip().lower() for key in trusted_keys}
    problems = check_integrity(bundle)
    results = []
    for entry in bundle["signatures"]:
        key_hex = str(entry.get("public_key_hex", "")).lower()
        state = "invalid"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
                bytes.fromhex(str(entry.get("signature_hex", ""))),
                signing_payload(bundle["report_sha256"]),
            )
            state = "trusted" if key_hex in trusted else "untrusted"
        except (InvalidSignature, ValueError):
            pass
        results.append({"public_key_hex": key_hex, "state": state})
    states = {result["state"] for result in results}
    if problems:
        verdict = "tampered"
    elif "invalid" in states:
        verdict = "invalid_signature"
    elif not results:
        verdict = "unsigned"
    elif "trusted" in states:
        verdict = "verified"
    else:
        verdict = "untrusted_signer"
    return {
        "verdict": verdict,
        "report_sha256": bundle["report_sha256"],
        "signatures": results,
        "problems": problems,
        "note": "A trusted signature proves origin and integrity, not that the findings are true.",
    }


def sign(bundle: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, str]:
    problems = check_integrity(bundle)
    if problems:
        raise ValueError("Refusing to sign a damaged report: " + "; ".join(problems))
    signature = private_key.sign(signing_payload(bundle["report_sha256"]))
    return {"public_key_hex": _public_hex(private_key.public_key()), "signature_hex": signature.hex()}


def _read_bundle(path: str) -> dict[str, Any]:
    data = Path(path).read_bytes()
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError("Bundle is larger than the supported maximum")
    return load_bundle(data.decode("utf-8"))


def _load_private_key(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key")
    return key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="create an operator signing key file")
    keygen.add_argument("--out", required=True)
    signer = commands.add_parser("sign", help="sign an exported bundle")
    signer.add_argument("bundle")
    signer.add_argument("--key", required=True)
    verifier = commands.add_parser("verify", help="verify an exported bundle")
    verifier.add_argument("bundle")
    verifier.add_argument("--trust", action="append", default=[], metavar="PUBLIC_KEY_HEX")
    args = parser.parse_args(argv)

    if args.command == "keygen":
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # O_EXCL: never overwrite an existing key; 0600 where the OS honours it.
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        print(json.dumps({"public_key_hex": _public_hex(key.public_key())}))
        return 0
    if args.command == "sign":
        print(json.dumps(sign(_read_bundle(args.bundle), _load_private_key(args.key))))
        return 0
    result = verify(_read_bundle(args.bundle), args.trust)
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
