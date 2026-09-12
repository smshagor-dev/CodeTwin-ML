# Windows LPAC Readiness Boundary

CodeTwin treats repositories as untrusted data. The Windows QA execution path therefore does not promote a sandbox capability merely because an isolation API is available. This document records the first Less Privileged AppContainer (LPAC) integration step and, equally importantly, what it does not yet guarantee.

## Purpose

The existing Windows path already combines a write-restricted low-integrity primary token, detached project mirroring, exact trusted-runner attestation, Job Object containment, bounded handles, bounded output, resource limits, and approval-bound project/external provenance. Those controls still do not deny arbitrary host reads.

Windows AppContainer supplies a kernel-enforced additional principal for access checks. LPAC is the stricter AppContainer form because it opts out of the broad ALL APPLICATION PACKAGES access surface. This makes LPAC a suitable candidate for a future explicit-read sandbox, provided every required resource is deliberately granted and the real child process is actually created with that identity.

## Current readiness probe

The current slice adds a Windows-only preflight beneath the still-disabled public QA execution boundary. It uses a stable per-user AppContainer profile named `CodeTwinML.QA.RestrictedRunner.V1` with zero declared capabilities.

For an approved low-level plan, after project-manifest and declared external-surface revalidation and while the exact trusted-runner replacement lock is still held, CodeTwin:

1. creates or derives the stable AppContainer package SID;
2. creates a fresh existing write-restricted, low-integrity primary token;
3. prepares `SECURITY_CAPABILITIES` with that package SID and zero capability SIDs;
4. adds `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`;
5. adds `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` with `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`, selecting LPAC behavior;
6. creates the exact trusted runner with `CreateProcessAsUserW` and `CREATE_SUSPENDED` from the already generated detached mirror directory;
7. never resumes the child;
8. opens the suspended child's token and requires all of the following before accepting readiness evidence:
   - `TokenIsAppContainer` is true;
   - `TokenIsLessPrivilegedAppContainer` is true;
   - `IsTokenRestricted` is true;
   - `TokenRestrictedSids` still contains the exact `WinWriteRestrictedCodeSid` restricting SID used by the parent token;
   - the AppContainer SID exactly matches the expected profile SID;
   - the low-integrity label remains present;
   - `TokenCapabilities` contains zero capability SIDs;
9. terminates and waits for the still-suspended probe child;
10. fails closed on any profile, process-creation, token-attestation, termination, or wait error.

The restricted-SID list is returned by Windows as a variable-length `TOKEN_GROUPS` buffer. CodeTwin validates the reported entry count against the returned byte buffer and walks entries from the raw allocation base instead of indexing beyond the SDK's one-element trailing-array declaration. Malformed size/count relationships fail closed.

The probe child receives no repository arguments, is never resumed, and therefore does not execute repository code, package scripts, tests, interpreter initialization, compiler logic, or hooks.

## Cleanup and persistence

The LPAC profile is intentionally stable rather than created and deleted per run. The returned SID buffer is freed after each probe, while the per-user profile itself remains registered. Reusing one zero-capability profile avoids profile deletion races between concurrent readiness checks.

Every created probe process is guarded so that error paths terminate and wait for the suspended process before handles are released. An incomplete process/thread handle pair is also treated as an infrastructure failure and cleaned up rather than normalized.

## Capability truth

This is readiness evidence only.

The real production lower launcher still uses the existing write-restricted low-integrity token path and does not yet attach the LPAC process attributes. The readiness probe does not grant the AppContainer SID access to the approved external runtime roots, and it does not mutate arbitrary host runtime/toolchain ACLs.

Therefore:

- `filesystem_isolation` remains false;
- `network_isolation` remains false;
- the declared external read surface remains provenance evidence, not an enforced read allow-list;
- public QA execution remains disabled;
- there is no fallback from a failed LPAC readiness check to a weaker execution path.

Zero AppContainer capabilities are deliberately required, but CodeTwin does not yet promote network isolation from that fact because the actual resumed test process is not yet the attested LPAC child and adversarial Windows tests have not executed.

## Next enforcement step

The next Windows slice should make the resumed runner itself the attested LPAC child while preserving the existing suspended-before-Job-assignment ordering and explicit inherited-handle list. It must also give that child only the resources it needs without permanently weakening arbitrary host ACLs.

A safe direction is to stage required external runtime/toolchain material into generated per-run locations where CodeTwin owns the ACL lifecycle, grant the LPAC SID read/execute access to those generated trees, grant only the intended writable artifact/temp trees, and leave the original repository and unrelated host paths ungranted. Runner-specific path translation must be explicit and provenance-bound so Python, Rust, Go, Node, and PHP cannot silently fall back to ambient host stores.

Only after the actual resumed child is LPAC, undeclared read attempts are denied in adversarial tests, and teardown removes all temporary grants should filesystem read isolation be considered for capability promotion. Network isolation should remain independently gated until the real resumed child is verified to have no network capability and negative network tests pass.
