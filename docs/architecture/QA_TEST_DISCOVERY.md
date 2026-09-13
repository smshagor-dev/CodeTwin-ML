# QA Test Discovery

CodeTwin ML treats repository test configuration and test source files as untrusted data. This baseline inventories bounded test evidence without executing repository commands, package scripts, test runners, browsers, compilers, interpreters, or project hooks.

## Purpose

The QA discovery layer establishes durable evidence for later verification workflows. It answers conservative questions such as which supported test frameworks are evidenced by repository files, which test/config artifacts are present, and whether a later scan observed those artifacts again. It does not claim that any test passed, failed, executed, or covers a specific production path.

## Supported baseline evidence

The detector recognizes bounded evidence for:

- JavaScript/TypeScript Jest, Vitest, Playwright, and Cypress projects through conventional test paths, imports, config filenames, and `package.json` dependency/script metadata;
- Python pytest and unittest-style test files through conventional paths/names and source tokens;
- Rust built-in test modules/functions through `#[cfg(test)]`, `#[test]`, `#[tokio::test]`, and integration-test paths;
- Go `_test.go` files;
- PHPUnit-style PHP test paths/classes and PHPUnit configuration files.

Unknown-but-conventional JavaScript, Python, or PHP test files are preserved with an explicit `*_test_unknown` framework label instead of being assigned to a framework without evidence.

## Persistence model

Migration `0013_qa_test_discovery.sql` adds project-scoped QA artifact records and run metrics. Each persisted artifact is bound to:

- normalized project-relative path identity;
- artifact kind (`test_file` or `config_file`);
- framework label and evidence kind;
- exact SHA-256 content hash and byte size;
- the latest discovery run and active/inactive lifecycle.

A complete rescan can mark disappeared artifact identities inactive. An incomplete scan never uses missing evidence to deactivate prior artifacts.

## Desktop workspace

The desktop QA workspace exposes the passive discovery service through bounded Tauri commands. A user can index a project, trigger a discovery scan, inspect framework summaries, filter test/config evidence, and review discovery history. The workspace labels the boundary explicitly: discovered evidence is not a test execution result and does not imply pass/fail status or code coverage.

The Tauri bridge opens the application-managed SQLite database and calls the existing `QaDiscoveryService`; it does not launch repository processes or interpret package scripts. A process-local concurrency guard prevents overlapping QA discovery scans from the desktop command surface.

## Bounds and trust boundary

Discovery is read-only and bounded to 50,000 candidate files, 1 MiB per candidate, and traversal depth 16. Known generated/vendor/cache directories are skipped. Symlink candidates, unreadable files, oversized files, non-UTF-8 files, traversal failures, and root escapes make coverage incomplete rather than being treated as absent evidence.

The subsystem never runs `npm test`, `pytest`, `cargo test`, `go test`, PHPUnit, Playwright, Cypress, shell commands, package-manager commands, or repository executables. Framework discovery therefore represents static repository evidence only.

## Future execution boundary

A later test-execution subsystem must be separate and opt-in. It should require an isolated sandbox, explicit resource/time/network policy, immutable input provenance, bounded logs/artifacts, deterministic cancellation, and recorded runner/tool versions. Static QA discovery must remain usable without granting repository execution authority.
