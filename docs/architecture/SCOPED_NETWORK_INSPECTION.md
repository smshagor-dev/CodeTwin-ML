# Authorized private-network service inspection

CodeTwin's Tool Library now exposes a **bounded TCP reachability** action for the host or lab network that the operator owns or is explicitly authorized to inspect. Unlike unrestricted terminal pentesting, it never spawns external commands, runs vulnerability payloads, or discovers unlisted hosts.

## Execution contract

- Operator checks explicit authorization in the Tool Library.
- Target is a literal IPv4/IPv6 loopback or private address and must exactly match the supplied allowlist. Public/multicast/unspecified/link-local/broadcast addresses are rejected. DNS names are deliberately unsupported, so DNS rebinding cannot expand this scope.
- Only 1–32 explicitly selected, unique TCP ports are inspected (no port 0), with 100–3000 ms connection timeouts, **one connection per port** and at most four simultaneous workers.
- Rust returns sorted `open`, `closed`, or `unreachable` connection observations. It neither fingerprint services nor identifies vulnerabilities. Results are written to a local SQLite run ledger after explicit authorization. The ledger stores a SHA-256 fingerprint of the approved scope, run state (running/completed/failed/interrupted), and hashed JSON evidence. Reads recompute the result hash, failing closed on tampering. A completed network inspection is **not** a confirmed vulnerability finding.
- Unit tests bind actual local TCP listeners, verify results, and exercise allowlist, authorization and port limits.

## Explicit limitations

This is a narrow, usable addition to CodeTwin's network testing surface. Full network pentesting remains future work: target-attested engagement storage, authenticated/signed scope enforcement, full DNS/DNSSEC assessment, TLS configuration inspection, UDP probes, privilege separation, scan cancellation, packet capture, service fingerprinting, evidence retention, and isolated worker proof still need implementation and review. Never present this module as a replacement for those facilities.

The original authorized Web/API scanner keeps its existing separate hostname/path/DNS controls. TCP inspection does not inherit permission to probe any website or external public server.

## Exact-name DNS verification

The Tool Library also provides an authorized resolver check. It requires an
explicit hostname allowlist and a complete exact list of expected private/
loopback IP addresses. It rejects IP literals, invalid names, missing consent,
public approved addresses, and any DNS response containing an unexpected IP.
No DNS crawling, wildcard expansion, subdomain brute forcing, or reverse
lookup is implemented. DNS observations remain screen-local; they are not
written to the TCP history ledger.

## Evidence and restart behavior

Migration `0038_network_inspection.sql` introduces an immutable-by-service
history of attempted TCP inspections and the result-integrity hashes.
One network scan can be active per desktop instance. Interrupted history
entries from a prior session become `interrupted` when the next run starts.
Completed history entries are retrievable in the Tool Library. SHA-256 checks
detect accidental or deliberate changes to stored result bytes relative to
the recorded hash; neither a cryptographic signature nor independent proof
of target ownership is implied.
