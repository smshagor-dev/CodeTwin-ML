# Authorized Network Assessment

CodeTwin's Security > Network Assessment provides a **bounded, single-target
network service inventory**. It is an implemented subset of network
security assessment, not a complete penetration-testing engine.

## Workflow

1. Enter **one** exact owned/authorized hostname or IP (no URL, CIDR, ranges or wildcard).
2. Select **1–16 unique TCP ports**, and a total time budget of 1–60 seconds.
3. Confirm ownership or written authorization. Separately enable private-network
   access for an approved local/staging target.
4. Prepare a review. CodeTwin records the normalized target, selected ports and
   complete initial DNS address snapshot in SQLite. Review this information.
5. Approve the plan, then start the scan. Neither opening the tab nor
   preparing a review starts TCP probing.
6. Per port, re-resolve the hostname, reject any address changes or blocked
   addresses, and use bounded TCP connect. After success on ports 443 or
   8443 only, optionally perform a single redirected-disabled HTTPS HEAD
   with system certificate validation and no proxy.
7. Persist per-port statuses (open, closed, timeout, unreachable),
   elapsed milliseconds, trust status, and scan completion/failure reason.
   A completed scan is **not** proof a target is secure.

## Security boundaries

- Target approval and the exact port list must match the stored plan.
- No model-generated or arbitrary shell execution; no Nmap, packet injection,
  exploit traffic, brute force, UDP probes or service-version guessing.
- DNS is rechecked per port and pinned via a chosen approved address.
  A changed or mixed unauthorized DNS response fails closed.
- Multicast, unspecified, documentation and selected reserved network addresses
  are rejected. Private/loopback/link-local addresses require explicit permission.
- At most 16 direct TCP connections plus selected HTTPS HEAD checks; no redirects,
  HTTP proxy, recursive discovery or CIDR sweeps.
- A scan may stop between probes on cancellation, time budget or DNS drift.
  Partial evidence is retained, and failures are never marked successful.
- TLS status indicates only whether one HTTPS request established trust using
  the platform trust store. It does not audit protocol versions, weak ciphers,
  HSTS, OCSP, certificate transparency or custom STARTTLS protocols.
- DNS output is resolved IP inventory, **not** a DNS posture audit: no
  SPF/DMARC/DNSSEC/zone-transfer testing.
- The built-in tests use only a locally created loopback listener; no live
  external network assessment is performed in CI.

## Implementation

- Rust: `crates/codetwin-core/src/network_assessment.rs`
- SQLite: `migrations/0038_network_assessment.sql`
- Tauri bridge: `apps/desktop/src-tauri/src/network_assessment_commands.rs`
- UI: `apps/desktop/src/workspace/security/NetworkAssessmentPanel.tsx`

Future extended network testing requires separate typed tools with confirmed
ownership, CIDR exclusions and egress enforcement, explicit scan-rate caps,
safe cancellation, service-specific protocol parsing, signed evidence and
independently verified physical/lab integration tests.
