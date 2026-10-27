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

Imported signed evidence envelopes and typed manifests reject unknown JSON
fields. Previously, an extra top-level or manifest claim could be silently
discarded by deserialization while the signature on the recognized fields
still verified. Rejecting such fields avoids presenting unsigned additions
as authenticated evidence. The nested specialist, receipt, handoff and
delegation JSON values remain part of the signed payload. Imported evidence
now rejects duplicate JSON object keys recursively within those values, too:
otherwise a duplicate nested claim could be collapsed by a generic JSON parser
into the original signed value while the raw document appeared to say more.
This validation applies when deserializing a signed evidence envelope into its
typed Rust representation; it does not authenticate an untrusted raw JSON
viewer or prove the truth of a specialist's report. A valid signature alone
still does not prove operator approval. A fresh SQLite evidence comparison
remains necessary.

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
16 KiB, enforced by both the bounded file reader and the shared JSON parser
(including direct parser calls). JSON nesting deeper than 64 levels within that byte limit is
rejected before decoding, independent of the Python recursion limit, rather
than allowing a decoder recursion exception
to escape the verification boundary. This is input hardening, not proof of
private signing-key custody or authenticity of external pins.

Both Ed25519 authority signatures and both exact-envelope pins must verify
under the **same** independently pinned authority. The previous policy must
meet the current revision floor, and the replacement revision must be
strictly higher. The command returns the proposed new revision floor only
after all checks succeed; it does not update any file, SQLite row, external
pin, hardware key, or policy. Changing the authority key requires a separate,
authenticated out-of-band procedure and is deliberately not handled here.

The Python rotation verifier rechecks the previous signed-policy bytes, inode metadata and parent path after rechecking the replacement input. This rejects an observed late previous-policy swap (including identical-byte inode replacement) while the replacement is being verified. These bounded reads are not an atomic snapshot and cannot establish independent signing-key custody or prevent privileged rollback.

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
The CLI and `publish_verified` are the authenticated publication entry
points. The internal `_publish_anchor` filesystem primitive now refuses
publication without a callable verification hook, and now requires the
hook to return **exactly `True`** at both verification checkpoints: under the
publisher lock and after staging. Returning `None`, `False`, or any other
value fails closed without replacing the prior anchor. The authenticated
`publish_verified` entry point's internal verification hook returns
`True` only after signed-policy checks complete successfully; the entry
point itself returns the published public anchor record. Direct calls to the internal primitive are
unsupported. A Python caller could supply a dishonest callback,
so this guard prevents accidental omission of verification, **not** malicious
code running with the administrator's filesystem privileges. The external
authority private key remains outside this application.

The administrator must still obtain **both pins** and the authority key
through independent authenticated channels *before* running it. `--approve` signals deliberate operator intent, not a
cryptographic or human-identity approval certificate.

The Python publication entry points (`publish_verified` and the internal
`_publish_anchor`) require `approved is True` exactly. Truthy values such as
`1`, `"yes"`, lists, or mappings are rejected before policy verification,
lock acquisition, or filesystem writes. This is strict input validation,
not independent proof of operator identity or authorization. The CLI
`--approve` flag produces a boolean, but external callers must also enforce
their own authenticated administrator approval process.

Bootstrap `anchor.json` separately from previously authenticated values
in an administrator-owned directory **outside the checkout and SQLite data**,
with directory mode 0700 and file mode 0600. The publisher and read-only
auditor now refuse an anchor path inside the detected CodeTwin source checkout
(including paths resolving into it), before creating a publisher lock. This
prevents accidental placement of public revision-floor state in the source
tree; it does **not** prove independent storage, prevent copying the anchor
elsewhere, or protect against privileged rollback. Keep the authoritative
revision and digest in a separately protected system, not only in this JSON
file. Its exact four fields are:

```json
{
  "format": "codetwin-external-signer-anchor-v1",
  "authority_public_key_hex": "<64 lowercase hex characters>",
  "minimum_revision": 4,
  "signed_policy_sha256_hex": "<64 lowercase hex characters>"
}
```

The read-only anchor audit rechecks signed-policy bytes, inode metadata and parent identity after its final anchor read to reject an observed late policy swap. These repeated observations are not an atomic filesystem snapshot and cannot protect against privileged rollback or prove external key custody.

The public anchor JSON is capped at 4096 bytes and rejects structural nesting deeper than 64 levels before decoding, including on runtimes with raised Python recursion limits. Malformed or excessively nested anchor input fails closed; this does not establish key custody or privileged rollback resistance.

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
  --independent-revision-floor 4 \
  --expected-sha256 <independently-pinned-previous-digest> \
  --replacement-revision 5 \
  --replacement-sha256 <independently-pinned-replacement-digest> \
  --approve
```

The authenticated publisher now requires `--independent-revision-floor`, a positive
u64 revision obtained from a separately protected administrator record. It
rejects a current anchor revision below that floor **before acquiring a lock**,
even if the older policy has a valid signature. The floor is supplied explicitly
at each invocation and is never written to SQLite or the repository. The
application cannot verify where the operator obtained the number: copying it
from the mutable anchor defeats rollback detection. Keep the floor in an
independently administered monotonic record and update that record after
verified publication. This CLI argument is required for existing automation
invoking the authenticated publisher; the internal filesystem primitive is
not a substitute for the authenticated entry point. This comparison is not a
hardware monotonic counter or privileged rollback defense.

The anchor publisher and read-only auditor require each ancestor directory
above the private anchor directory to be owned by the invoking user or root.
They also reject group- or world-writable ancestors, except root-owned
sticky shared directories such as /tmp. A private leaf directory alone is
not enough if an unrelated account can replace an ancestor. These are
point-in-time POSIX checks, not protection against privileged filesystem
changes or proof of independently controlled signing keys.

The publisher and read-only auditor also compare the device/inode, owner,
group and mode of **every anchor directory ancestor** across their bounded
operations, not only the private leaf directory. An observed ancestor identity
swap during staged publication or signature audit now fails closed. Ancestor
timestamps are omitted because unrelated activity in shared sticky directories
can change them. These observations do not provide an atomic filesystem
snapshot or prevent swaps by a privileged writer between checks.

The publisher additionally rejects a staged temporary trust-anchor inode with
multiple hard links, including a link present before the first staged metadata
snapshot or added during the final policy check. A second pathname could
otherwise modify the same staged inode independently of its temporary name.
The check is repeated before publication and after the bounded final read.
This detects observed link-count changes; it does not guarantee race-free
filesystem custody or establish external private signing-key custody.

The helper refuses missing approval, invalid authority signatures, pin mismatches,
policy-key reuse, stale compare-and-swap expectations, revision decreases,
unchanged digests, malformed data, symlinks, shared file
permissions and a nonprivate anchor directory. Signed-policy input files must
also be owned by the invoking administrator or root; a policy file owned by a
different unprivileged account is rejected before the publisher lock is created,
even when its Ed25519 signature is valid. This is local filesystem custody
hardening, not evidence of independent private-key custody or privileged
rollback resistance. Rotation verification re-reads
both signed-policy inputs **byte-for-byte** after validating their signatures
and pins and rejects any change observed during that check, including a JSON
whitespace-only rewrite whose typed-envelope digest remains unchanged. It also
compares both policy pathnames' inode metadata and immediate-parent identities
from before the first read through the final verification read. An observed
same-byte inode replacement or in-place metadata mutation fails closed, even
when the Ed25519 signature and typed-envelope digest still match. The
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
After staging and fsyncing the temporary anchor, the authenticated CLI
repeats the signed-policy signature, revision, key-separation and independent
pin verification once more before renaming. An observed late input change or
verification rejection leaves the previous anchor in place and cleans up the
temporary file. This adds a bounded observation, not an atomic snapshot or
privileged rollback protection; an uncooperative writer can still change
policy files after the last verification. The internal filesystem primitive
reuses its caller-supplied verification hook, which cannot prove the hook is
honest or that the authority private key has protected custody.
The publisher also retains an open descriptor for the staged temporary
public anchor and, immediately before rename, compares the staged inode's
metadata with the temporary pathname and re-reads the exact intended bytes.
Observed pathname substitution or in-place modification fails closed and
leaves the prior anchor unchanged. The publisher now repeats staged-file
descriptor and pathname metadata checks **after** the final bounded payload
read, detecting observed mode/inode changes or byte-identical pathname swaps
during that read. Two POSIX regressions cover these cases and require the old
anchor to remain unchanged. These are point-in-time checks, not an atomic
filesystem snapshot: changes after the final check can still escape detection,
and this is not protection against privileged rollback or proof of
independent external signing-key custody.
After that final bounded read, the publisher also rechecks the private
directory identity, persistent lock identity and metadata, and old anchor
identity and metadata immediately before rename. Two POSIX regressions
simulate lock-mode and old-anchor-mode changes during the staged read and
require fail-closed rejection with the previous anchor intact. These are
additional point-in-time observations, not atomic filesystem custody or
protection against a privileged writer after the last check.
The publisher also rechecks the same opened lock and pathname **after**
staging and fsyncing the temporary anchor, immediately before the rename.
Observed lock replacement or metadata mutation during staging fails closed
without replacing the previous anchor; the temporary file is cleaned up.
This extra observation does not make the advisory lock atomic or stop a
privileged writer from changing it after the final check.
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

Previous and replacement signed policies must be distinct filesystem inodes;
reusing one file or a hard-link alias fails closed before signature validation.
This prevents ambiguous sequential verification of two generations from one
mutable file, but it is not a filesystem snapshot or privileged rollback defense.
The signed policy inputs are limited to 16 KiB each and read from regular
non-symlink files. Both signed-policy and anchor readers use nonblocking
opens, so an observed FIFO substitution between the pathname check and
open cannot stall the verifier waiting for a pipe writer; the subsequent
file-type check rejects the substituted inode. The policy reader also
compares the full observed inode metadata from before opening to the opened
descriptor (including mode, owner, group, link count, size and timestamps).
A same-inode chmod or timestamp change between lstat and open fails closed,
even if both permission modes would otherwise be acceptable. The same
metadata fields are checked after the read and against the pathname; these
observations do not provide an atomic snapshot or privileged rollback defense.
This is a bounded local race hardening measure, not protection against privileged replacement. Signed-policy inputs must also not be group- or world-writable
(permissions such as 0600 or 0644 are accepted); the check is repeated on
the opened file descriptor. The reader also checks inode metadata again
after reading, rejecting observed changes to size, ownership, link count,
permissions, or modification/change timestamps, even if the JSON bytes are
restored. It now also compares the post-read pathname metadata with the
opened descriptor, rejecting observed inode replacements and symlink swaps
even if the replacement contains identical signed JSON bytes. This is a
best-effort race check, not a stable filesystem snapshot:
changes between checks or by a privileged writer may still escape detection.
The policy reader now records the device/inode, owner, group and mode of
every ancestor directory as well as the immediate parent's change timestamp
for the full verification or read-only audit. If a previously observed
ancestor identity changes between snapshots, verification fails closed even
when the immediate parent inode and signed-policy bytes appear unchanged.
Ancestor timestamps are deliberately excluded to avoid false failures when
other processes create files in shared sticky directories such as /tmp.
These are point-in-time observations, not a filesystem snapshot, proof of
independent key custody, or protection against a privileged path swap.

The POSIX policy reader also rejects symlinks in any directory component
and requires the immediate parent directory to be owned by the current user
or root and not writable by group or others. Ancestors must also be owned
by the invoking user or root and not be group- or world-writable, except
root-owned sticky shared directories such as /tmp (which prevent unrelated unprivileged users from
renaming entries they do not own). It rechecks the parent inode,
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
  --independent-revision-floor 5 \
  --expected-sha256 <independently-pinned-current-digest>
```

### Optional independently signed revision-floor checkpoint

The read-only audit can additionally verify a **public, externally signed**
revision-floor checkpoint. This is an opt-in second authority, not a replacement
for the independently supplied floor, exact signed-policy digest, or trusted
signer-policy authority. Supply all three additional arguments together:

```bash
python scripts/audit_signer_trust_anchor.py \
  --anchor-file /trusted/private/anchor.json \
  --signed-policy /trusted/input/current-policy.json \
  --authority-public-key <independently-pinned-policy-authority> \
  --expected-revision 5 --independent-revision-floor 5 \
  --expected-sha256 <independently-pinned-policy-envelope-sha256> \
  --floor-checkpoint-file /trusted/input/floor-checkpoint.json \
  --checkpoint-authority-public-key <independently-pinned-separate-floor-authority> \
  --checkpoint-sha256 <independently-pinned-exact-checkpoint-sha256> \
  --require-floor-checkpoint
```

For deployments that require the second authority, use
`--require-floor-checkpoint` on **every** audit invocation. The audit then
fails before reading the anchor when the checkpoint path, authority public
key, or exact digest pin is omitted. Without this flag the checkpoint remains
optional for backward compatibility, so operators must enforce the flag in
their deployment configuration. This prevents accidental omission, not an
attacker with permission to alter the invocation or independently pinned values.

The checkpoint is a JSON envelope with exactly `record`,
`authority_public_key_hex`, and `signature_hex`. The record has exactly
`format` (`codetwin-revision-floor-checkpoint-v1`),
`minimum_revision` (positive u64), and `signed_policy_sha256_hex`.
An independently managed Ed25519 checkpoint authority signs the bytes
`CodeTwin-ML/revision-floor/ed25519/v1` followed by a NUL byte and compact
UTF-8 JSON of the record in the field order listed above. The checkpoint
authority **must differ** from the signer-policy authority and from every
public evidence-signing key in the authenticated signer policy, including
revoked signers. Reusing an evidence signer as the checkpoint authority fails
the audit; this is key-role separation, **not** proof of independent private-key
custody or a hardware-backed monotonic floor. Its public key,
the checkpoint's exact-byte SHA-256, the independently retained floor and the
policy-envelope digest must all match. The checkpoint file is read-only,
size-bounded (16 KiB) with a 64-level structural JSON nesting limit before
decoding (quoted and escaped brackets are ignored), checked for unsafe
filesystem substitutions, and
rechecked at the audit return boundary. Both the verification-time and
final audit checkpoint re-reads now check path identity **before and after**
reading, so observed same-byte file substitutions immediately after a read
fail closed. After the final checkpoint re-read, the audit also
rechecks the anchor directory, public anchor identity and values, and the
signed-policy bytes and inode metadata. This rejects observed identical-byte
anchor or policy substitutions that occur during the final checkpoint read;
two regression tests inject these replacements. These are bounded filesystem
observations, not an atomic snapshot or proof of private signing-key custody.
Changes outside the checks, including privileged rollback after return, may
still escape detection. The independent revision floor and exact pins must
remain protected and current outside CodeTwin.

The checkpoint signing key stays in an independently controlled signer or
hardware-backed service. Never store its private material in this repository,
SQLite or the checkpoint JSON. A valid signature and matching supplied pins
do **not** establish the authenticity of the operator's independent channel,
key custody, a protected monotonic floor, or resistance to replay of an old
valid checkpoint when an attacker can also roll back its external pins.
The operator must advance and protect those independent pins after rotation.
The audit does not update the floor or create any signing keys.

The read-only auditor now requires a separately protected positive u64
revision floor, just like the authenticated publisher. If the independently
pinned current revision is below that floor, the audit fails before reading
any files, even when the anchor, signed policy, signature and stale exact pins
all agree. A floor below the pinned revision is allowed; the exact revision
and digest must still match. The floor must come from an authenticated,
independently maintained administrator record, never the anchor being audited.
This is a comparison against supplied values, not proof of their provenance,
a protected monotonic counter, or privileged rollback resistance. Existing
audit CLI callers must now supply `--independent-revision-floor`.

This audit is read-only: it creates no lock file, does not modify the
anchor or SQLite, and does not invoke any security scans. It checks the
private POSIX anchor directory, the existing anchor record, the signed
policy's Ed25519 authority signature and signer-key separation, and
equality with **all three** independently trusted inputs. It re-reads
the anchor and the signed-policy file to detect changes observed during
the audit. The anchor re-read compares both parsed values and inode metadata
(including ownership, permissions, size and timestamps), rejecting observed
same-content inode swaps or in-place metadata changes. It also rechecks the
private directory device/inode between reads and once more after the final
policy read, rejecting observed directory replacement or permission relaxation
even when the policy is stored elsewhere and the anchor bytes are unchanged.
After the final policy read, the audit also re-reads the anchor file and compares
its parsed values and inode metadata with the initial read. Observed anchor
rewrites or identical-content inode swaps during that last policy read fail
closed. It checks the private directory identity and permissions **again after**
that last anchor read, rejecting an observed directory replacement or
permission relaxation during the read itself. These observations do not
provide an atomic filesystem snapshot:
changes after the final check or between observations can still escape detection.
The policy re-read compares exact
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

### Failed-publication staged-file cleanup

When a publication fails before the rename, the POSIX publisher now checks
the staged pathname's device/inode against its still-open staging descriptor
before unlinking it. If a noncooperating writer has substituted another file
or symlink at the temporary pathname, cleanup leaves that unrelated entry
untouched rather than deleting it. The administrator should inspect and
remove any suspicious leftover staged pathname through an independently
trusted directory view; a failed publication does not authorize deletion of
unknown files. Regression tests cover both regular-file and symlink
substitution. Run `python -m unittest scripts.tests.test_publish_signer_trust_anchor`.

This is a best-effort, point-in-time cleanup guard, **not** a race-free
filesystem transaction. Same-UID or privileged writers may still swap
pathnames after metadata checks. Neither this check nor SQLite provides
external signing-key custody or rollback protection.

### Post-publication inode readback

The bounded trust-anchor reader rechecks pathname metadata after JSON decoding
and schema validation, not just during descriptor reads. An observed inode swap
or metadata mutation during decoding fails closed even when JSON bytes are
identical. These are point-in-time checks and do not prevent privileged or
same-UID races, nor prove external custody of the public anchor or private key.

After the POSIX anchor publisher renames its verified staged public record, it
compares the readback file's device and inode with the staged file's identity,
in addition to checking its parsed contents and directory ancestry. After
the bounded readback completes, the publisher rechecks the entire anchor
directory ancestry and the persistent publisher-lock inode/path metadata.
An observed late directory or lock substitution during readback fails closed,
even if the readback bytes match. These are point-in-time checks; they do not
prevent privileged or same-UID races or authenticate external custody.
An observed byte-identical pathname substitution after the rename now fails
instead of reporting successful publication. **This is detection, not rollback:** the
rename may already be durable when readback fails. The operator must treat a
readback failure as an indeterminate publication outcome, independently audit
the protected anchor and policy pins, and reconcile externally protected
revision-floor records before retrying. Noncooperating same-UID or privileged
writers can still race checks; this is not atomic filesystem custody or proof
of external private signing-key protection.

### Stable metadata readback after anchor publication

After renaming the staged public anchor, the publisher now compares the
readback file's device, inode, mode, owner, group, hard-link count, size, and
modification time with the staged descriptor's verified values. Creation/change
time (ctime) is deliberately excluded because rename may legitimately update
it. This detects observed same-inode chmod or mtime changes even when the
readback JSON and inode are unchanged. Two POSIX regression tests simulate
these post-rename mutations.

**Important:** A readback mismatch occurs after the rename and durability
sync; the new anchor may already be published. Treat the outcome as
indeterminate, audit the anchor and independently protected revision floor,
and reconcile external records before retrying. These metadata comparisons
are point-in-time observations, not atomic filesystem custody, privileged
rollback resistance, proof of administrator approval, or proof of external
private signing-key protection. Never store private keys in SQLite or the
repository.

## CI guard against accidentally tracked private keys

The Python CI job runs `python scripts/check_tracked_private_keys.py` on
**staged Git index blobs** for index-declared regular files and symlinks,
plus working-tree copies of regular files. Symlink targets are never
dereferenced; only their committed link text is inspected. Gitlinks
(submodules) fail closed because their index entries identify commits, not
inspectable blobs. A private-key header staged with `git add` remains
detectable even if the working-tree file
is subsequently overwritten with harmless text.
It rejects recognizable ASCII armor headers for private keys (including
PKCS#8, OpenSSH, RSA, EC, DSA and PGP private-key blocks), without printing
the contents. Both representations are streamed in bounded chunks. Missing or
unreadable Git index blobs, failed Git enumeration and unavailable tracked
regular files fail closed. A 64 MiB per-file limit applies independently to
staged blobs and working-tree regular files; oversized inputs fail closed
rather than being silently skipped. The cap bounds bytes read per file, not
whole-job runtime or subprocess execution time. Index reads use local
`git cat-file` and do not contact remote repositories. Run it locally before opening a pull request:

```bash
python scripts/check_tracked_private_keys.py
python -m unittest scripts.tests.test_check_tracked_private_keys
```

This is an **accidental-disclosure guard**, not a private-key vault, secret
scanner for arbitrary formats, or proof of cryptographic authenticity. It
cannot detect raw Ed25519 seeds, obfuscated or encrypted secret material,
untracked files, Git history, or files inside uninitialized submodules.
The guard reads Git index modes (not just working-tree file types): an
index-declared regular file replaced by a directory or symlink fails closed,
while genuine index-declared symlinks are not followed. Index-declared Gitlink
submodule directories are skipped; an unavailable or type-changed Gitlink
fails closed. Unmerged or malformed index entries also fail closed. These are
working-tree observations, not atomic protection against concurrent writers.
On POSIX systems the guard now opens tracked regular files with
`O_NOFOLLOW | O_NONBLOCK`, checks the opened descriptor against the
pre-open pathname metadata, and compares inode identity, permissions, owner,
link count, size, and timestamps again after reading and at the pathname.
Observed symlink swaps, FIFO substitutions, same-inode metadata mutations,
and identical-byte inode replacements fail closed. Platforms without
`O_NOFOLLOW` fail the guard rather than silently falling back to a
symlink-following open. These bounded checks do not establish an atomic
snapshot or prevent changes after the last check.
CI findings escape control characters in filenames to avoid log injection. Keep authority and evidence signing keys in separately administered
hardware or an OS-protected signing service; do not store them in Git, SQLite,
or CI variables unless an independently reviewed signing workflow explicitly
requires it. If a private key was ever committed, deleting the file is not
sufficient: revoke/rotate the exposed key and investigate Git history and
artifacts. A clean CI scan does not attest to external key custody.
