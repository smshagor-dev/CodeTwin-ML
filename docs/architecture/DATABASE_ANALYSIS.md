# Deterministic Database Analysis

CodeTwin ML's first database-analysis layer is a passive repository review. It inventories bounded database artifacts and persists review findings only when concrete text in those artifacts supports them. It does not connect to the analyzed project's database and it never executes migrations, SQL, ORM commands, package scripts, compilers, tests, hooks, or shells.

## Artifact scope

The scanner walks the canonical project root without following symlinks, to a maximum depth of 8. Known generated/vendor directories are pruned. The current artifact set is deliberately narrow:

- `schema.prisma` as a Prisma schema artifact;
- UTF-8 `.sql` files as SQL schema/migration artifacts;
- SQL files under `migration`, `migrations`, or `migrate` paths (or with `migration` in the filename) are classified as migrations.

At most 10,000 candidate artifacts are considered and each artifact is limited to 2 MiB. Symlinked, unreadable, oversized, invalid-UTF-8, or traversal-error artifacts make the run coverage incomplete. A scan with incomplete coverage does not resolve old findings or mark unseen artifacts inactive.

## Persisted model

Migration `0008_database_analysis.sql` adds `database_artifacts` and `database_run_metrics`. Artifact identity is deterministic within a project and uses the normalized relative-path identity. The table stores kind, framework label when known, SHA-256 content hash, byte size, run linkage, timestamps, and active/inactive state. Full SQL/schema source is not copied into SQLite.

Database review findings reuse the normalized `findings` and `finding_evidence` tables with `analyzer_key = database_analysis`. Evidence records point to the relative artifact path, source range, artifact id/kind, and content hash. Literal Prisma datasource values are redacted before evidence is persisted.

## Baseline rules

`database.destructive_migration` flags `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE`, and `ALTER TABLE ... DROP COLUMN`. These operations can be valid; the finding asks for backup, compatibility, rollback, and retention review rather than claiming data loss occurred.

`database.unscoped_data_write` flags `UPDATE` or `DELETE` statements with no `WHERE` token outside SQL string literals/comments. Full-table writes can be intentional and are therefore review findings, not automatic failures.

`database.sqlite_foreign_keys_disabled` flags SQL artifacts that explicitly set `PRAGMA foreign_keys` to `OFF` or `0`. The finding does not claim the statement has executed on a live SQLite connection.

`database.literal_datasource_url` flags non-placeholder string-literal Prisma datasource fields (`url`, `directUrl`, or `shadowDatabaseUrl`). The literal itself is never persisted; evidence stores only field name, redacted length, and provenance metadata.

## Lifecycle and coverage

Every run records considered/analyzed/skipped artifact counts, SQL/Prisma artifact counts, observation counts, finding open/refresh/resolve counts, per-rule counts, duration, and whether coverage was complete. Finding fingerprints are deterministic from project, rule, normalized artifact path, and normalized observation anchor.

When a complete scan no longer observes a prior finding, that finding is resolved. When coverage is incomplete, missing evidence is treated as unknown rather than fixed. Likewise, artifact deletion becomes inactive only after a complete scan proves that the artifact is absent.

## Current boundary

This baseline does not claim live database state, migration ordering correctness across dialects, transaction safety, query-plan cost, index sufficiency, ORM relation correctness, SQL injection reachability, production credential validity, schema drift against a running database, lock behavior, runtime query frequency, or migration success/failure. Those require dedicated evidence sources and should not be inferred from passive repository text alone.

The Tauri layer exposes bounded commands for running analysis and listing artifacts, findings, evidence, rules, and history. A dedicated React database workspace is not yet claimed by this document.
