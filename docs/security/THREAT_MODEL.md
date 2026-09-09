# Threat Model

## Protected assets

Source code, credentials, local files outside an opened project, Git credentials, database credentials, model artifacts, analysis evidence, patches, reports, and developer feedback.

## Primary threats

- Malicious repository content and prompt injection.
- Dependency or package scripts attempting command execution.
- Path traversal and symlink escape from an approved workspace.
- Secret leakage through logs, reports, model context, or environment inheritance.
- Resource exhaustion, fork bombs, excessive output, and zombie process trees.
- Network exfiltration by untrusted project execution.
- Malicious plugins or model artifacts.
- Database credential exposure or destructive database queries.
- Supply-chain compromise of CodeTwin dependencies.

## Foundation controls

Repository discovery performs file inspection only and never runs repository commands. ML communication is stdio-based and schema-checked. SQLite foreign keys are enabled and schema changes are migration controlled. External inference is not configured by default.

Execution sandboxing, secure credential storage, plugin permission enforcement, and model artifact verification are required before those capabilities can be exposed as available.
