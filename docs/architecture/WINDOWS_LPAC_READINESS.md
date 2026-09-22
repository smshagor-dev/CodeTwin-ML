# Windows LPAC Readiness Boundary

CodeTwin treats repositories as untrusted data. The Windows QA execution path therefore does not promote a sandbox capability merely because an isolation API is available. This document records the Less Privileged AppContainer (LPAC) integration steps and, equally importantly, what they do not yet guarantee.

## Purpose

The existing Windows path combines a write-restricted low-integrity primary token, detached project mirroring, exact trusted-runner attestation, Job Object containment, bounded handles, bounded output, resource limits, and approval-bound project/external provenance. Those controls alone do not deny arbitrary host reads.

Windows AppContainer supplies a kernel-enforced additional principal for access checks. LPAC is the stricter AppContainer form because it opts out of the broad ALL APPLICATION PACKAGES access surface. This makes LPAC a suitable candidate for an explicit-read sandbox, provided every required resource is deliberately granted and the real child process is actually created with that identity.

## Suspended LPAC identity probe

The Windows-only preflight sits beneath the still-disabled public QA execution boundary. It uses a stable per-user AppContainer profile named `CodeTwinML.QA.RestrictedRunner.V1` with zero declared capabilities.

For an approved low-level plan, after project-manifest and declared external-surface revalidation and while the exact trusted-runner replacement lock is still held, CodeTwin:

1. creates or derives the stable AppContainer package SID;
2. creates a fresh existing write-restricted, low-integrity primary token;
3. prepares `SECURITY_CAPABILITIES` with that package SID and zero capability SIDs;
4. adds `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`;
5. adds `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` with `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`, selecting LPAC behavior;
6. creates the exact trusted runner with `CreateProcessAsUserW` and `CREATE_SUSPENDED` from the generated detached mirror directory;
7. never resumes the child;
8. opens the suspended child's token and requires `TokenIsAppContainer`, `TokenIsLessPrivilegedAppContainer`, `IsTokenRestricted`, the exact `WinWriteRestrictedCodeSid` restricting SID, the expected AppContainer SID, the low-integrity label, and zero token capability SIDs;
9. terminates and waits for the still-suspended probe child;
10. fails closed on any profile, process-creation, token-attestation, termination, or wait error.

The restricted-SID list is returned by Windows as a variable-length `TOKEN_GROUPS` buffer. CodeTwin validates the reported entry count against the returned byte buffer and walks entries from the raw allocation base instead of indexing beyond the SDK's one-element trailing-array declaration. Malformed size/count relationships fail closed.

The probe child receives no repository arguments, is never resumed, and therefore does not execute repository code, package scripts, tests, interpreter initialization, compiler logic, or hooks.

## Detached external execution bundle

The next readiness layer no longer assumes that an LPAC runner should read directly from arbitrary host runtime/toolchain directories. CodeTwin now stages the approved external read surface into a generated per-run tree under the already generated QA workspace at `lpac-external/`.

For every approved external root, bundle preparation:

1. canonicalizes the approved source root and requires it to remain the same approved path;
2. takes a fresh bounded source snapshot using the same domain-separated manifest format as external approval provenance;
3. requires file count, directory count, total bytes, and manifest SHA-256 to match the approved root evidence;
4. copies all approved regular files and empty directories into a deterministic generated root such as `root-00-runtime_root`;
5. revalidates every source file immediately before copying;
6. marks every copied regular file read-only;
7. rescans the original source after the copy and requires exact equality with the pre-copy snapshot;
8. independently rescans the generated destination and requires it to equal both the source snapshot and approved root evidence;
9. fails closed on symlinks, Windows reparse points, special entries, path escape, source drift, copy drift, count drift, byte drift, or hash drift.

The existing external-surface limits remain authoritative: at most 8 roots, 65,536 files, 16,384 directories, and 2 GiB of regular-file bytes. The bundle repeats those aggregate bounds rather than treating approved metadata as permission to allocate an unbounded copy.

The trusted runner must canonicalize inside exactly one approved external root. Its generated counterpart is derived by the same relative path inside that root, and the copied executable must independently match the approved runner SHA-256. Ambiguous runner mappings across overlapping declared roots fail closed.

This bundle is derived state. It is not inserted into the project manifest, and it never changes the original repository or host runtime trees. A preparation failure removes the generated bundle subtree through the enclosing generated-workspace lifecycle.

## Generated ACL staging

CodeTwin does not add persistent AppContainer ACEs to arbitrary Python, Rust, Go, Node, PHP, compiler, package-store, or other host directories.

Instead, ACL preparation is restricted to CodeTwin-generated paths. The stable LPAC package SID receives:

- read/execute access to the generated workspace root and project mirror;
- read/write/execute access to generated `artifacts/` and `temp/` directories;
- read/execute access to the generated external bundle and every copied runtime/toolchain entry.

The existing `WinWriteRestrictedCodeSid` receives explicit read/execute access to the generated external bundle so the write-restricted second access check can still succeed for intended runtime reads. Bundle files receive no write grant and remain read-only.

The original source repository and original external runtime/toolchain roots are never granted the LPAC package SID by this staging layer.

## Cleanup and persistence

The LPAC profile is intentionally stable rather than created and deleted per run. The returned SID buffer is freed after each use, while the per-user profile itself remains registered. Reusing one zero-capability profile avoids profile deletion races between concurrent readiness checks.

Every suspended probe process is guarded so error paths terminate and wait before handles are released. An incomplete process/thread handle pair is treated as an infrastructure failure rather than normalized.

The external execution bundle lives inside the generated QA workspace and is removed with that workspace. No bundle ACL is applied to host runtime roots, so teardown does not need to reverse host ACL mutations.

## Capability truth

The readiness probe remains defense-in-depth evidence, but it is no longer the production isolation boundary. The production launcher now resumes the copied, hash-verified runner from the generated LPAC bundle, creates that real child with the same zero-capability LPAC identity, attests its token before resume, assigns it to the Job Object before untrusted code runs, and has no weaker Windows execution fallback.

Current capability semantics are deliberately scoped:

- `filesystem_isolation=true` means the analyzed project and approved runtime/toolchain material used by the run are staged into CodeTwin-generated, ACL-bound paths and the real LPAC child executes from that generated surface. It is not a host-wide deny-all-read claim for Windows system objects.
- `network_isolation=true` requires a zero-capability LPAC child and a stable AppContainer profile with **no Windows loopback exemption**. CodeTwin verifies the exemption state during readiness and re-attests it immediately before the production child is created.
- CPU, memory, process-tree, timeout, output and cancellation controls are enforced by the production Job Object/launcher path.
- Windows execution fails closed if any required LPAC, ACL, provenance, loopback, Job Object, token or parser gate cannot be established.
- Non-Windows platforms remain planning-only.

## Remaining validation

Fresh adversarial Windows execution remains a release gate, not an inferred success. The matrix should include undeclared-host-read attempts, source-write denial, approved runtime reads, artifact/temp writes, direct and loopback network attempts, descendant process containment, runner replacement, inherited-handle escape attempts, cancellation, CPU/memory limits, timeouts and cleanup.

Runner-specific path translation must also be validated for Python, Rust, Go, Node and PHP so the child cannot silently fall back to an ambient package/toolchain store that was not part of the approved bundle. GitHub-hosted Windows jobs that fail before runner allocation do not satisfy this validation requirement.
