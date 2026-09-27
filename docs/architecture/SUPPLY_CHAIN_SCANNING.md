# Secret scanning and dependency vulnerability audit

Both analyzers run against an imported project folder, persist results in the shared
`findings` / `finding_evidence` tables, and follow the same lifecycle as the other
deterministic analyzers: findings are refreshed on every run and are marked resolved only
when a run had complete coverage and no longer observes them.

## Secret scanning

Crate: `crates/secret-scanner`; service: `SecretScanningService` (`analyzer_key =
'secret_scanning'`, category `secrets`, CWE-798).

- Scans every text file in the project, not only indexed source, so `.env`, key files,
  YAML and JSON configuration are covered. `.git`, `node_modules`, `target`, `vendor`,
  virtual environments and build output are skipped; binary files and files over 1 MiB are
  skipped and counted.
- Rules detect well-known credential formats (private keys, AWS, GitHub, GitLab, Slack,
  Stripe live keys, Google API keys, npm tokens, AI provider keys, JWTs, database/broker
  URLs with embedded passwords) plus two looser rules: secret-named assignments and
  committed `.env` files. The looser rules skip placeholders (`changeme`, `${VAR}`,
  `process.env…`), plain words, file paths and URLs; the assignment rule also requires the
  value to look machine-generated (Shannon entropy ≥ 3.5 bits/char).
- `.env.example`, `.env.sample` and similar templates are not reported.
- Matches in test, fixture, example and docs paths are reported with reduced confidence.
- A line containing `codetwin:ignore-secret` is skipped.

**Values are never persisted.** A finding stores a redacted preview (first 4 and last 2
characters, fully masked for short values) and a fingerprint derived from a
project-salted SHA-256 of the value, so the same secret moving within a file stays one
finding. The integration test checks every text column of the database for the raw value.

Not covered: git history. A secret that was committed and later deleted must still be
rotated; scan history with a dedicated tool before publishing a repository.

## Dependency vulnerability audit

Crate: `crates/dependency-audit`; service: `DependencyAuditService` (`analyzer_key =
'dependency_audit'`, category `dependency`, OWASP A06:2021).

### Inventory

Only exact, resolved versions are audited. Supported lockfiles:

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json` (v1–v3), `yarn.lock` (classic and berry), `pnpm-lock.yaml` (v5–v9), `bun.lock` |
| crates.io | `Cargo.lock` (registry packages only) |
| PyPI | `uv.lock` (registry packages), `poetry.lock`, `Pipfile.lock`, `requirements*.txt` (`==` pins) |
| Go | `go.mod` |
| Packagist | `composer.lock` |
| RubyGems | `Gemfile.lock` |

Unpinned requirements (`flask>=2`) are counted and shown, not guessed. Local path, git and
workspace packages are excluded because they are not published versions. A manifest that
cannot be parsed makes the run's coverage incomplete, so no finding is resolved on that run.

Not supported yet: Maven/Gradle, NuGet, Swift, Dart/pub, Bun's binary `bun.lockb`.

### Advisory sources

The caller always chooses the source explicitly:

- **Offline OSV directory** (no network). Download an ecosystem export such as
  `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`, extract it, and point
  the audit at the directory. Matching uses the record's enumerated `versions` first
  (`exact_version`, confidence 0.95) and otherwise evaluates `SEMVER`/`ECOSYSTEM` ranges
  locally (`range`, confidence 0.85). `GIT` ranges and withdrawn records are ignored.
- **Online, OSV.dev** (`https://api.osv.dev`). Requires explicit consent in the desktop app.
  Only package ecosystem, name and version are sent — no source code, file paths or project
  names. OSV evaluates versions server-side (`osv_api`, confidence 0.95). Fetched records
  are cached in `osv_advisories` and used as a fallback if a later fetch fails. If the batch
  query fails, the run fails and existing findings are left untouched.

### Findings

One finding per package version, manifest and advisory. The title uses the CVE alias when
one exists. Severity comes from the advisory's `database_specific.severity`, otherwise from
its CVSS v3 vector (computed with the CVSS 3.1 base-score formula), otherwise `medium`.
Evidence records the fixed versions, references, CVSS score, match basis and whether the
package is a development dependency.
