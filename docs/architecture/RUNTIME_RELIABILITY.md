# Runtime Reliability Analysis

CodeTwin ML's first runtime-reliability layer is a passive configuration analyzer. It inventories bounded Dockerfile and Docker Compose artifacts and persists review findings derived from their text. It does not run the project, start containers, execute health checks, contact services, inspect a live orchestrator, or infer an outage from configuration alone.

## Evidence sources

The analyzer currently recognizes:

- `Dockerfile` and `Dockerfile.*`
- `docker-compose.yml` / `docker-compose.yaml`
- `compose.yml` / `compose.yaml`

Traversal is depth-bounded, does not follow symlinks, skips generated/vendor-style directories, rejects paths that canonicalize outside the project root, and limits each artifact to 2 MiB. A scan that cannot safely inspect every recognized artifact is marked `coverage_complete = false`.

## Baseline rules

`runtime.mutable_container_image` flags Docker/Compose image references that are not digest pinned and are either untagged or use the mutable `latest` tag. This is a reproducibility and rollout review signal, not proof that deployed bytes have changed.

`runtime.healthcheck_disabled` flags `HEALTHCHECK NONE` and Compose `healthcheck.disable: true`. External load balancers or orchestrators can still supply health monitoring.

`runtime.healthcheck_not_declared` flags Dockerfiles and image-backed Compose services that do not declare a local healthcheck. The finding explicitly records that external health monitoring is unknown.

`runtime.restart_disabled` flags Compose services with `restart: no`. This can be correct for jobs and one-shot workloads and therefore requires service-role review rather than automatic remediation.

## Persistence and lifecycle

Migration `0009_runtime_reliability.sql` adds project-scoped runtime artifact inventory and per-run metrics. Findings reuse the normalized `findings` / `finding_evidence` tables with `analyzer_key = runtime_reliability`.

Artifact identity is deterministic from project identity plus normalized relative path. Findings use deterministic fingerprints based on project, rule, artifact path identity, and analyzer-provided semantic anchor. Repeated runs refresh matching findings instead of creating arbitrary duplicates.

When coverage is complete, an observation that disappears is resolved and an artifact that disappears is marked inactive. When coverage is incomplete, previous open findings are preserved and missing artifacts are not deactivated because absence was not proven.

Persisted evidence records the artifact content hash and explicitly records `source_executed = false` and `live_runtime_observed = false`.

## Current limitations

This baseline does not provide live process/container telemetry, crash-loop detection, latency/SLO measurements, runtime memory/CPU leak detection, network reachability, Kubernetes probe analysis, deployment-state drift, incident correlation, log ingestion, tracing, or verified runtime repair. Those capabilities remain separate future subsystems and must not be inferred from the current configuration findings.
