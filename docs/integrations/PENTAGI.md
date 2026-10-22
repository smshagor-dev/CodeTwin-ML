# PentAGI Go integration

CodeTwin ML's **Agents** workspace can control the upstream **PentAGI** autonomous security-testing engine. PentAGI remains a separate, self-hosted Go/Docker stack; CodeTwin's Tauri/Rust backend uses PentAGI's documented GraphQL API. No unreviewed PentAGI shell command is executed by the CodeTwin desktop process.

## Upstream source and attribution

The complete upstream PentAGI repository is pinned as a Git submodule at:

- Path: third_party/pentagi
- Project: https://github.com/vxcontrol/pentagi
- Pinned upstream commit: 843dfeb4bfc809c09d1bc5022e567c602d8fc9dd
- License: MIT, copyright (c) 2025 PentAGI Development Team. See third_party/pentagi/LICENSE after submodule checkout.
- The upstream project also includes EULA.md and notices and may have external cloud-service licensing restrictions. Review these separately.

To fetch its **actual Go source tree**:

    git clone --recurse-submodules https://github.com/smshagor-dev/CodeTwin-ML.git
    cd CodeTwin-ML

For an existing checkout:

    git submodule update --init --recursive third_party/pentagi

Do not copy PentAGI Go packages into the Rust crate or remove the original license. The upstream Go implementation is not reimplemented in Rust.

## Start the Go service

1. Install a supported Docker and Docker Compose runtime.
2. Follow **third_party/pentagi/README.md**, including its installer or Docker Compose instructions. PentAGI also requires a configured LLM provider (and optional search/embedding providers).
3. In the PentAGI web UI, create an API token using **Settings > API Tokens**.
4. Make the PentAGI HTTPS certificate trusted by the machine running CodeTwin; do not turn off TLS certificate verification.
5. Set both environment variables **before starting** CodeTwin desktop:

    CODETWIN_PENTAGI_URL=https://localhost:8443
    CODETWIN_PENTAGI_TOKEN=<your PentAGI API token>

On Windows PowerShell:

    $env:CODETWIN_PENTAGI_URL = "https://localhost:8443"
    $env:CODETWIN_PENTAGI_TOKEN = "<your PentAGI API token>"

The token is consumed exclusively by Rust. It is not serialized to the WebView or stored in CodeTwin SQLite. This connection is **opt-in**, and a missing token results in a disconnected status instead of a silent fallback.

HTTP is allowed only when the PentAGI origin is loopback (localhost, 127.0.0.1 or ::1), for local development. Remote PentAGI installations must use HTTPS. URL redirects are disabled.

## What the integration currently exposes

In **CodeTwin > Agents**:

- Check the upstream Go service's connectivity and discover configured LLM providers.
- Start an autonomous PentAGI flow with a declared URL, scoped testing objective and explicit authorization acknowledgement.
- List persisted flows and their lifecycle states.
- Stop active flows.
- Read tasks/subtasks, specialized agent activity and tool execution logs (last 100 shown).

PentAGI itself contains the primary, pentester, coder, installer, searcher, memorist, adviser, reflector, reporter and other agents, Docker-based security tools, persistent memory, optional Graphiti/Neo4j integration, observability and its own report-generation UI. Those capabilities live in **the upstream Go service** and are configured/used in PentAGI's own UI and APIs; CodeTwin's new interface does **not** yet replicate every PentAGI admin panel, report viewer, file manager or flow-assistant control.

## Security boundaries

- Only run assessments of infrastructure you own or have explicit written authorization to test.
- Explicit user acknowledgement and a single target URL are required before submitting a flow to PentAGI.
- **The target URL and prompt are not sufficient sandbox boundaries.** PentAGI's own egress filtering, Docker policies, target allowlists and rules of engagement must be enforced by its administrator. Do not expose PentAGI's powerful tool-execution API to untrusted users.
- Never grant Docker socket access to a remotely controlled user or mount the host filesystem into untrusted PentAGI tool containers.
- Use a test environment first, choose non-destructive test objectives and independently verify security findings.
- Configure appropriate resource limits, request ceilings and human approval in PentAGI itself. CodeTwin's existing guided-security request budget does not automatically control separate PentAGI flows.
- Keep the API token out of the repo, shell logs, screenshots and shared diagnostics. Rotate tokens if exposed.

## Troubleshooting

- **Not configured**: Set both environment variables in the environment that launched CodeTwin and restart it.
- **HTTP 401/403**: Check the PentAGI API token and its permissions.
- **TLS verification failed**: Install/recognize the PentAGI server's CA certificate. Do not disable verification.
- **GraphQL schema error**: Confirm your running Go service matches the pinned upstream version. PentAGI may change its GraphQL schema; update the Rust adapter only after checking compatibility.
- **No providers**: Enable a provider in the PentAGI backend and verify it from the upstream UI.
- **Cannot start a flow**: Confirm your target scope, authorization and provider selection and inspect PentAGI server logs.

## Build verification

Use your existing CI workflow after source changes:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace
    npm run typecheck
    npm run test
    npm run build

These checks validate local integration code. An end-to-end result also requires a real, configured PentAGI server and an authorized testing fixture.
