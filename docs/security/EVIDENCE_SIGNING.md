# External review-evidence signing and policy custody

CodeTwin exports a domain-separated Ed25519 message for a **completed, verified**
security review. An independent signer signs those exact decoded bytes.
CodeTwin does not create, import, persist, or export the private signing key.
Keep the private key in a separately controlled hardware token, OS-protected
signing service, or other trusted signing environment. Never put it in SQLite,
the repository, a JSON envelope, a support ticket, or a chat.

## What verification actually establishes

A signed evidence bundle must be verified against an independently trusted
public key or signer policy, and against a fresh consistent SQLite snapshot.
A self-declared key in the bundle is not a trust anchor. A signature only
binds the signed manifest to the key; it does not prove that a human approved
the underlying review, that external tools were secure, or that the result is
complete.

For signer rotation/revocation, the stricter desktop verifier now requires
**three independent inputs**, in addition to the signed policy JSON:

1. A pinned Ed25519 authority public key (64 hex characters).
2. A positive minimum acceptable policy revision, maintained outside CodeTwin.
3. The SHA-256 of the **exact trusted signed policy envelope**, also maintained
   outside CodeTwin (64 hex characters).

All three must come from an authenticated channel separate from the imported
evidence and the SQLite database. CodeTwin does not maintain a protected
revision ledger or distribute trusted pins. If the operator reuses an old
external revision floor and digest, an older valid policy can still be
accepted. Rotate the digest and revision floor together when the authority
issues a new policy. Revoked signers are rejected under the supplied policy;
old signatures cannot be retroactively revoked without a current policy.

## Computing the exact-envelope pin

An administrator can calculate the digest on a **previously authenticated**
`signed-policy.json` file using Python 3. The hash covers the compact
UTF-8 JSON serialization of the typed envelope, in the same field order as
CodeTwin's Rust serializer, **not** the signing payload and not the
whitespace/field order of the original file.

```python
import hashlib
import json
from pathlib import Path

source = json.loads(Path("signed-policy.json").read_text(encoding="utf-8"))
policy = source["policy"]
typed = {
    "policy": {
        "format": policy["format"],
        "revision": policy["revision"],
        "signers": [
            {"public_key_hex": entry["public_key_hex"], "status": entry["status"]}
            for entry in policy["signers"]
        ],
    },
    "authority_public_key_hex": source["authority_public_key_hex"],
    "signature_hex": source["signature_hex"],
}
data = json.dumps(typed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
print(hashlib.sha256(data).hexdigest())
```

The policy administrator should verify the authority signature and policy
content, publish the digest and minimum revision over an independently
authenticated channel, and retain auditable approval records. The displayed
digest is only a comparison value: hashing an attacker-supplied envelope and
then trusting that same hash **does not authenticate** anything.

## Tests and limitations

```bash
cargo test -p codetwin-core native_evidence_signatures
```

Regression coverage checks matching pins, malformed and incorrect pins,
tampered signatures, and a genuinely authority-signed old policy rejected
after the independently supplied digest rotates. Verification remains
read-only; it does not trigger network scans, security tools, or changes to
review approval. SQLite remains the local evidence store, not a key vault.
