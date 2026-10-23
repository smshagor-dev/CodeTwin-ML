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
   8443 only, perform at most one redirect-disabled HTTPS HEAD with system
   certificate validation and no proxy. On validated HTTPS responses, record
   only the response status and privacy-reduced header observations: HSTS
   max-age classification, CSP presence, nosniff and Referrer-Policy presence.
7. Persist per-port statuses (open, closed, timeout, unreachable),
   elapsed milliseconds, trust status, an optional small HTTPS posture JSON,
   and scan completion/failure reason.
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
  the platform trust store. Successful responses expose a small, bounded
  HTTPS-header posture record: HSTS max-age classification (only meaningful
  for DNS hostnames), presence of CSP, a valid nosniff token, and the presence
  of Referrer-Policy. A header absent from a HEAD response is **not observed**,
  not proof of vulnerability; the inspected path may differ from application
  routes. This does not audit protocol versions, weak ciphers, OCSP,
  certificate transparency, or custom STARTTLS protocols.
- DNS output is resolved IP inventory, **not** a DNS posture audit: no
  SPF/DMARC/DNSSEC/zone-transfer testing.
- The built-in tests use only a locally created loopback listener; no live
  external network assessment is performed in CI.

## Implementation

- Rust: `crates/codetwin-core/src/network_assessment.rs`
- SQLite: `migrations/0038_network_assessment.sql` and additive migration
  `migrations/0040_network_https_posture.sql`
- Tauri bridge: `apps/desktop/src-tauri/src/network_assessment_commands.rs`
- UI: `apps/desktop/src/workspace/security/NetworkAssessmentPanel.tsx`

Future extended network testing requires separate typed tools with confirmed
ownership, CIDR exclusions and egress enforcement, explicit scan-rate caps,
safe cancellation, service-specific protocol parsing, signed evidence and
independently verified physical/lab integration tests.

## HTTPS header observations

Migration 0040 adds a nullable `https_posture_json` column. Existing records
remain valid with no header data. Only the approved target and its pinned,
revalidated address are contacted on 443/8443, and at most one HTTPS HEAD
response is examined for each port. The response body and raw header values
are **not stored**. A failed TLS handshake yields `not_verified` without an
HTTPS header result. HSTS is marked not applicable to literal IPs. Neither an
HTTP 2xx response nor an observed header establishes a secure deployment.

## HTTPS diagnostic observations

Migration 0041 adds nullable `https_failure_kind` to the per-port probe ledger.
When an approved 443/8443 connection is open but the bounded HTTPS HEAD does
not succeed, CodeTwin records exactly one fixed diagnostic category:
`budget_exhausted`, `setup_failed`, `timeout`,
`connection_or_tls_failure`, or `request_failed`. No raw exception,
URL, HTTP response body, certificate bytes or unredacted transport error
is persisted. Historic probes have a null diagnostic, as do verified HTTPS
requests and ports without an HTTPS attempt.

These are **request outcomes, not certificate vulnerability findings**:
`connection_or_tls_failure` can mean an interrupted connection, protocol
mismatch, trust-chain failure, peer identity failure or other handshake error.
CodeTwin never bypasses certificate verification to diagnose a failure.
Successful HTTPS observations still mean one platform-trusted HEAD request,
not a complete certificate expiry, TLS version or cipher-suite assessment.

Changing the target, ports, budget or private-network option in the desktop
review clears the authorization checkbox. The separate Tool Library
private-network and DNS checks likewise require fresh confirmation when
their allowed scopes change.
