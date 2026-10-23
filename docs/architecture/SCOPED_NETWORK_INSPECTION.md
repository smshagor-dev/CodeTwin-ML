# Authorized private-network service inspection

CodeTwin's Tool Library now exposes a **bounded TCP reachability** action for the host or lab network that the operator owns or is explicitly authorized to inspect. Unlike unrestricted terminal pentesting, it never spawns external commands, runs vulnerability payloads, or discovers unlisted hosts.

## Execution contract

- Operator checks explicit authorization in the Tool Library.
- Target is a literal IPv4/IPv6 loopback or private address and must exactly match the supplied allowlist. Public/multicast/unspecified/link-local/broadcast addresses are rejected. DNS names are deliberately unsupported, so DNS rebinding cannot expand this scope.
- Only 1–32 explicitly selected, unique TCP ports are inspected (no port 0), with 100–3000 ms connection timeouts, **one connection per port** and at most four simultaneous workers.
- Rust returns sorted `open`, `closed`, or `unreachable` connection observations. It neither fingerprint services nor identifies vulnerabilities. These results are not persisted as authoritative findings.
- Unit tests bind actual local TCP listeners, verify results, and exercise allowlist, authorization and port limits.

## Explicit limitations

This is a narrow, usable addition to CodeTwin's network testing surface. Full network pentesting remains future work: target-attested engagement storage, persistent signed scope and audit, TLS configuration inspection, DNS assessment, UDP probes, privilege separation, scan cancellation, packet capture, service fingerprinting, evidence retention, and isolated worker proof still need implementation and review. Never present this module as a replacement for those facilities.

The original authorized Web/API scanner keeps its existing separate hostname/path/DNS controls. TCP inspection does not inherit permission to probe any website or external public server.
