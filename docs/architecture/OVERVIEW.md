# Architecture Overview

CodeTwin ML uses a Tauri 2 desktop shell with a React/TypeScript frontend. Privileged project access belongs to Rust services. ML inference and training are isolated behind a local sidecar protocol; the initial transport is newline-delimited JSON over stdio, so no unauthenticated localhost service is required.

The durable Software Digital Twin is stored in SQLite using normalized entities and relationships. Large artifacts such as future screenshots, traces, reports, coverage files, and verification logs live in a content-addressable artifact directory and are referenced by metadata rows rather than inserted as large database blobs.

## Trust boundaries

1. Desktop UI is not trusted to perform privileged filesystem operations directly.
2. Repository content is untrusted data.
3. Project execution will be routed through a sandbox engine before command execution is added.
4. ML sidecar requests use explicit schemas and do not inherit instructions from repository text.
5. External model providers are disabled until a future explicit opt-in implementation exists.

## Current executable path

The desktop command `discover_project` reads project metadata without executing package scripts or arbitrary repository commands. The result is rendered in the Project Overview foundation screen. The ML sidecar currently exposes protocol health/capability discovery only and deliberately reports no installed inference model.
