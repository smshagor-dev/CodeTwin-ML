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

The Ed25519 policy authority public key **must not appear among any evidence signer keys** in that policy, including revoked entries. The authenticated-policy verifier enforces this separation so that compromise of an evidence signing key cannot also act as policy approval authority. Deploy a distinct externally managed authority key; existing same-key policies must be reissued by an independent authority before verification.

All three must come from an authenticated channel separate from the imported
evidence and the SQLite database. CodeTwin does not maintain a protected
revision ledger or distribute trusted pins. If the operator reuses an old
external revision floor and digest, an older valid policy can still be
accepted. Rotate the digest and revision floor together when the authority
issues a new policy. Revoked signers are rejected under the supplied policy;
old signatures cannot be retroactively revoked without a current policy.

## Checking a proposed policy rotation

The desktop's `check_native_signer_policy_rotation` command (also exposed by
`workspaceApi.checkNativeSignerPolicyRotation`) performs a **read-only
preflight**. Supply the previously authenticated signed policy, its externally
held SHA-256 pin, the replacement signed policy and its independently
authenticated SHA-256 pin, the pinned authority public key, and the current
externally maintained positive revision floor. Each policy is limited to
16 KiB.

Both Ed25519 authority signatures and both exact-envelope pins must verify
under the **same** independently pinned authority. The previous policy must
meet the current revision floor, and the replacement revision must be
strictly higher. The command returns the proposed new revision floor only
after all checks succeed; it does not update any file, SQLite row, external
pin, hardware key, or policy. Changing the authority key requires a separate,
authenticated out-of-band procedure and is deliberately not handled here.

After independently approving a rotation, an external administrator must
atomically publish and protect the replacement pin and returned revision
floor in their own trusted system. Do not calculate either trusted pin from
unverified imported JSON. A successful preflight **does not provide durable
rollback protection**: stale or attacker-supplied external anchors can still
authorize stale policies. The application cannot verify the external
administrator's custody, approval, or distribution channel.

## Optional atomic publication of external anchor metadata (POSIX)

After the desktop's **read-only** rotation preflight succeeds, a separately
authorized administrator can use `scripts/publish_signer_trust_anchor.py`
to update the **public** revision and exact-envelope SHA-256 together in one
on-disk JSON record. This helper is not called by the desktop, never signs,
and never generates or stores private keys. The CLI now independently verifies
**both Ed25519 policy authority signatures**, key separation, policy revision
continuity, and both exact-envelope SHA-256 pins before attempting the update.
It requires Python 3 and the pinned `cryptography==46.0.4` dependency.
The administrator must still obtain **both pins** and the authority key
through independent authenticated channels *before* running it. `--approve` signals deliberate operator intent, not a
cryptographic or human-identity approval certificate.

Bootstrap `anchor.json` separately from previously authenticated values
in an administrator-owned directory **outside the checkout and SQLite data**,
with directory mode 0700 and file mode 0600. Its exact four fields are:

```json
{
  "format": "codetwin-external-signer-anchor-v1",
  "authority_public_key_hex": "<64 lowercase hex characters>",
  "minimum_revision": 4,
  "signed_policy_sha256_hex": "<64 lowercase hex characters>"
}
```

The stored revision must equal the current trusted policy revision. To
publish a previously checked replacement, use the **independently
authenticated** values, not hashes copied from an unverified import:

```bash
python scripts/publish_signer_trust_anchor.py \
  --anchor-file /trusted/private/anchor.json \
  --previous-signed-policy /trusted/input/previous-policy.json \
  --replacement-signed-policy /trusted/input/replacement-policy.json \
  --authority-public-key <independently-pinned-authority-key> \
  --expected-revision 4 \
  --expected-sha256 <independently-pinned-previous-digest> \
  --replacement-revision 5 \
  --replacement-sha256 <independently-pinned-replacement-digest> \
  --approve
```

The helper refuses missing approval, invalid authority signatures, pin mismatches,
policy-key reuse, stale compare-and-swap expectations, revision decreases,
unchanged digests, malformed data, symlinks, shared file
permissions and a nonprivate anchor directory. Rotation verification re-reads
both signed-policy inputs **byte-for-byte** after validating their signatures
and pins and rejects any change observed during that check, including a JSON
whitespace-only rewrite whose typed-envelope digest remains unchanged. The
independent SHA-256 pin still covers the canonical typed envelope, not the raw
file bytes. This is not an atomic snapshot:
a noncooperating or privileged writer can still replace a file after the
check, including before anchor publication. Cooperating publishers are
serialized with a persistent advisory lock. The lock file is opened nonblocking to reject
FIFO substitution without waiting for a pipe writer. Lock acquisition also
uses a nonblocking advisory lock: if another publisher holds the lock, the helper fails closed with a busy-lock
error rather than waiting indefinitely. An operator may retry after checking
the other publisher; no automatic retry or lock removal is performed.
After acquiring that lock,
the publisher checks that its opened lock inode and the lock pathname still
have matching ownership, permissions, size and timestamps. An observed lock
replacement or metadata mutation fails closed before updating the anchor.
The publisher preserves that initial lock metadata and **checks the opened
lock descriptor and lock pathname again after the signed-policy verification**,
immediately before attempting publication. An observed intervening lock
replacement or in-place metadata change is rejected without publishing.
This narrows accidental split-lock races, but an uncooperative or privileged
writer can still replace the lock pathname after the final check; these
point-in-time checks are not an atomic lock custody guarantee. Directory
custody remains an external administrator responsibility. The publisher also
remembers the private anchor directory device/inode before acquiring the lock and rechecks
that identity and directory permissions after acquiring the lock and again
immediately before replacement. A detected directory swap, symlink, or
permission relaxation fails closed. Lock-file creation may change directory
timestamps, so these directory identity checks deliberately compare only
device and inode; they do not constitute an atomic directory snapshot or
prevent a privileged writer from swapping the path after the final check.

The signed policy inputs are limited to 16 KiB each and read from regular
non-symlink files. Both signed-policy and anchor readers use nonblocking
opens, so an observed FIFO substitution between the pathname check and
open cannot stall the verifier waiting for a pipe writer; the subsequent
file-type check rejects the substituted inode. This is a bounded local
race hardening measure, not protection against privileged replacement. Signed-policy inputs must also not be group- or world-writable
(permissions such as 0600 or 0644 are accepted); the check is repeated on
the opened file descriptor. The reader also checks inode metadata again
after reading, rejecting observed changes to size, ownership, link count,
permissions, or modification/change timestamps, even if the JSON bytes are
restored. It now also compares the post-read pathname metadata with the
opened descriptor, rejecting observed inode replacements and symlink swaps
even if the replacement contains identical signed JSON bytes. This is a
best-effort race check, not a stable filesystem snapshot:
changes between checks or by a privileged writer may still escape detection.
The POSIX policy reader also rejects symlinks in any directory component
and requires the immediate parent directory to be owned by the current user
or root and not writable by group or others. It rechecks the parent inode,
owner, permissions and change timestamp after each bounded file read.
Keep policy files in a separately controlled, non-writable directory; a
world-writable immediate parent such as /tmp is deliberately rejected.
These checks do not authenticate the policy file owner, protect all ancestor
directories against replacement, guarantee an atomic path snapshot, or prevent
a privileged process from replacing files after verification. Verification is
performed before acquiring the anchor lock;
the pinned digests and compare-and-swap expectations bind the checked policy
to the published metadata. The authenticated CLI performs a second full
signature, revision, key-separation and pin check **while holding the
publication lock**, after confirming the current anchor and immediately before
writing its replacement. This detects a signed-policy swap between initial
preflight and acquiring the lock; a changed policy fails closed without
replacing the anchor. Independent policy files are not locked, so a privileged
or noncooperating writer can still replace them after the second check.
The publisher also records the validated current anchor inode metadata
and checks it again after staging the replacement, immediately before rename.
An observed inode swap or metadata rewrite (including identical JSON bytes)
fails closed without publishing. This narrows races with noncooperating
writers but is only a point-in-time check; it is not privileged rollback
protection or an atomic compare-and-swap across filesystem processes.
The replacement is written to a
private temporary file, flushed, atomically renamed over the old file, and
the directory is synced. Publication now opens and validates the private
directory's device/inode, then creates the temporary file, renames it, and
syncs **through that same directory descriptor**. A pathname swap after the
descriptor opens cannot redirect the rename into the swapped-in directory;
the publisher also checks the directory pathname after publication and
rejects observed changes. These checks are not atomic path custody: a
privileged writer may still move the original directory after the final
pre-rename check. The old directory can already contain the replacement
even when the post-publication check reports failure. An interrupted
operation can require administrator inspection; if durability fails *after*
rename, do not blindly retry or assume the old revision remains.

The public anchor reader checks its opened inode metadata (owner, mode,
link count, size, and modification/change timestamps) before and after the
bounded read, and checks that the anchor path still points to the same
metadata. It fails closed on observed in-place changes or path swaps.
This narrows read-time races but does not create an atomic filesystem snapshot:
a privileged or noncooperating writer can still change the anchor after
the final check or restore metadata between observations.

**Limitations:** This is POSIX-only, not a Windows ACL implementation or a
hardware-backed monotonic counter. The directory and all path components
must be administrator controlled; a privileged attacker or process able to
replace the directory can roll it back. File locking does not stop
noncooperating writers. Retain the authoritative anchor independently in a
protected external system and audit its changes. Never derive trusted
inputs from this file alone. Desktop evidence verification still requires
separately supplied current pins and revision, and will not automatically
trust the helper's output. An external publisher cannot prove that a policy
was approved or that the authority private key is safe.

Run its regression tests with:

```bash
python -m pip install 'cryptography==46.0.4'
python -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

## Read-only external anchor audit

Before trusting a published anchor, a separate administrator can check it
against independently authenticated **current** authority, revision and
exact-envelope digest values, and the corresponding signed policy:

```bash
python scripts/audit_signer_trust_anchor.py \
  --anchor-file /trusted/private/anchor.json \
  --signed-policy /trusted/input/current-policy.json \
  --authority-public-key <independently-pinned-authority-key> \
  --expected-revision 5 \
  --expected-sha256 <independently-pinned-current-digest>
```

This audit is read-only: it creates no lock file, does not modify the
anchor or SQLite, and does not invoke any security scans. It checks the
private POSIX anchor directory, the existing anchor record, the signed
policy's Ed25519 authority signature and signer-key separation, and
equality with **all three** independently trusted inputs. It re-reads
the anchor and the signed-policy file to detect changes observed during
the audit. The anchor re-read compares both parsed values and inode metadata
(including ownership, permissions, size and timestamps), rejecting observed
same-content inode swaps or in-place metadata changes. It also rechecks the
private directory device/inode between reads. The policy re-read compares exact
file bytes, while the audit also compares policy inode metadata (including
ownership, mode, size and timestamps) and parent-directory identity across
both reads. Observed identical-byte inode swaps, in-place metadata changes,
whitespace-only JSON rewrites or policy symlink swaps fail closed (exit code 2),
even when the typed-envelope digest remains the same. This is a point-in-time
comparison, not continuous filesystem monitoring. A stale anchor, changed
signed policy or mismatched independent pin is rejected. The command does not
establish that the independent inputs are authentic or fresh: they must
be delivered through a separately protected administrator channel.
It is a point-in-time consistency check, not a tamper-proof ledger,
hardware monotonic counter, filesystem snapshot or defense against a
privileged attacker who can replace files between reads. Do not
derive the expected revision or digest from the anchor being audited.

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
