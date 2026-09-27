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

Values that are plainly stand-ins are skipped: template slots (`{password}`, `%s`,
`%(pw)s`, `${VAR}`) and bare words such as `secret`, `password` or `postgres`. Rust code after a
`#[cfg(test)]` line, `tests.rs` and `test_*.py` files count as test code.

## Secrets in git history

Service: `SecretHistoryService` (`analyzer_key = 'secret_history'`, run kind `secret_history`,
migration 0026). A credential that was committed and later deleted can still be read from any
clone, so it still has to be rotated.

- Runs `git log --all -p --unified=0` over up to 10,000 commits by default (configurable up to
  200,000) and scans only the lines each commit added, with the same rules as the working-tree
  scan. Added lines of one file in one commit are scanned together so multi-line private keys
  still match. Hunk line counts decide what is content, so added text that looks like a diff
  header is not misparsed.
- One finding per distinct value, however many commits or paths it appears in. Each finding
  records the commit that introduced it (oldest by commit time), the path and line there, how
  many commits contain it, up to 20 paths, and whether the value is **still in the current
  files**.
- Coverage is incomplete, and nothing is resolved, when the commit limit is hit or more than
  10,000 distinct values are found. Shallow clones are flagged: commits before the cut-off are
  not on disk and cannot be scanned. Changes over 1 MiB of added text are skipped and counted.
- Git runs with `--no-ext-diff`, `--no-textconv`, `--no-pager`, explicit `a/`/`b/` prefixes,
  `log.showSignature=false`, `core.fsmonitor=false`, no system config and no inherited
  `GIT_DIR`/`GIT_CONFIG_*`, and is killed after 10 minutes. An integration test plants an
  external diff, textconv filter, pager, GPG program and fsmonitor hook in a repository's config
  and checks none of them runs.

Measured: CodeTwin's own history (1,395 commits) in 0.6 s; Flask's full history (5,598 commits)
in 1.3 s, reporting two example `SECRET_KEY` values in `docs/config.rst` at reduced confidence.

Not covered: commits no ref reaches (reflog-only or dangling objects) and submodules.

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
