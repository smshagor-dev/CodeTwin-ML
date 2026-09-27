//! Secret scanning across git history.
//!
//! A credential that was committed and later deleted is still readable by anyone with a clone,
//! so it still has to be rotated. This analyzer walks the lines each commit added, runs the same
//! rules as the working-tree scan, and reports every distinct leaked value once, with the commit
//! that introduced it and whether it is still present in the current files.
//!
//! Git runs read-only with every configurable command path disabled (external diff, textconv,
//! pager, signature verification), so a hostile repository configuration cannot execute code.
//! Raw values stay in memory for the duration of the scan and are never persisted.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Read},
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{
    deterministic_id, normalize_relative_path,
    secret_scanning::{finish_run, is_skipped_dir, project_root, salted_digest},
    AnalysisStatus, Database,
};

const ANALYZER_KEY: &str = "secret_history";
const ANALYZER_VERSION: &str = "secret-history-v1";
pub const DEFAULT_MAX_COMMITS: usize = 10_000;
const MAX_COMMITS_LIMIT: usize = 200_000;
const MAX_CHANGE_BYTES: usize = 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_DISTINCT_VALUES: usize = 10_000;
const MAX_WORKING_FILE_BYTES: u64 = 1024 * 1024;
const MAX_LISTED_PATHS: usize = 20;
const GIT_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_QUERY: usize = 1_000;

#[derive(Debug, Error)]
pub enum SecretHistoryError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("project not found: {0}")]
    ProjectNotFound(String),
    #[error("project root is not a directory: {0}")]
    InvalidProjectRoot(String),
    #[error("the project is not a git repository (no .git at its root)")]
    NotARepository,
    #[error("git is not available: {0}")]
    GitUnavailable(String),
    #[error("git log failed: {0}")]
    GitFailed(String),
}

impl From<crate::secret_scanning::SecretScanError> for SecretHistoryError {
    fn from(error: crate::secret_scanning::SecretScanError) -> Self {
        use crate::secret_scanning::SecretScanError as E;
        match error {
            E::Sqlite(error) => Self::Sqlite(error),
            E::Io(error) => Self::Io(error),
            E::ProjectNotFound(id) => Self::ProjectNotFound(id),
            E::InvalidProjectRoot(root) => Self::InvalidProjectRoot(root),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHistorySummary {
    pub project_id: String,
    pub run_id: String,
    pub status: AnalysisStatus,
    pub coverage_complete: bool,
    pub commits_scanned: usize,
    pub commit_limit_reached: bool,
    /// The clone is shallow, so commits before its cut-off were never available to scan.
    pub shallow_clone: bool,
    pub file_changes_scanned: usize,
    pub file_changes_skipped: usize,
    pub observations: usize,
    pub still_in_working_tree: usize,
    pub findings_opened: usize,
    pub findings_refreshed: usize,
    pub findings_resolved: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretHistoryFindingRecord {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    /// Path where the value was first committed.
    pub relative_path: String,
    pub line: Option<usize>,
    pub redacted: String,
    pub introduced_commit: String,
    pub introduced_at: String,
    pub commit_count: usize,
    pub paths: Vec<String>,
    pub still_in_working_tree: bool,
    pub in_test_path: bool,
    pub remediation: String,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHistoryRunRecord {
    pub run_id: String,
    pub status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub coverage_complete: bool,
    pub commits_scanned: usize,
    pub commit_limit_reached: bool,
    pub shallow_clone: bool,
    pub observations: usize,
    pub still_in_working_tree: usize,
    pub findings_opened: usize,
    pub findings_resolved: usize,
}

// ---------------------------------------------------------------------------------------------
// `git log -p --unified=0` parsing

/// Lines one commit added to one file, joined so multi-line secrets (private keys) still match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedText {
    pub commit: String,
    pub committed_unix: i64,
    pub committed_at: String,
    pub path: String,
    pub text: String,
    /// `line_numbers[i]` is the line in the new file of line `i` of `text`.
    pub line_numbers: Vec<usize>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParseStats {
    pub commits: usize,
    pub changes: usize,
    pub oversize_changes: usize,
}

const COMMIT_MARKER: u8 = 0x01;

struct Pending {
    path: String,
    text: String,
    line_numbers: Vec<usize>,
    oversize: bool,
}

/// Parses output of `git log -p --unified=0 --format=%x01%H %ct %cI` and calls `visit` for every
/// (commit, file) that added text. Hunk line counts decide which lines are content, so an added
/// line that itself starts with `+++ ` or `diff --git` is not mistaken for a header.
pub fn parse_git_log<R: BufRead>(
    mut reader: R,
    mut visit: impl FnMut(AddedText),
) -> std::io::Result<ParseStats> {
    let mut stats = ParseStats::default();
    let mut commit = (String::new(), 0i64, String::new());
    let mut pending: Option<Pending> = None;
    let (mut old_left, mut new_left, mut new_line) = (0usize, 0usize, 0usize);
    let mut raw = Vec::new();

    let mut flush =
        |pending: &mut Option<Pending>, commit: &(String, i64, String), stats: &mut ParseStats| {
            if let Some(change) = pending.take() {
                if change.oversize {
                    stats.oversize_changes += 1;
                } else if !change.text.is_empty() {
                    stats.changes += 1;
                    visit(AddedText {
                        commit: commit.0.clone(),
                        committed_unix: commit.1,
                        committed_at: commit.2.clone(),
                        path: change.path,
                        text: change.text,
                        line_numbers: change.line_numbers,
                    });
                }
            }
        };

    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        if raw.last() == Some(&b'\n') {
            raw.pop();
        }
        if raw.last() == Some(&b'\r') {
            raw.pop();
        }

        if old_left > 0 || new_left > 0 {
            match raw.first() {
                Some(b'+') if new_left > 0 => {
                    new_left -= 1;
                    if let Some(change) = pending.as_mut() {
                        let content = &raw[1..];
                        if change.oversize || change.text.len() + content.len() > MAX_CHANGE_BYTES {
                            change.oversize = true;
                        } else {
                            let content = &content[..content.len().min(MAX_LINE_BYTES)];
                            change.text.push_str(&String::from_utf8_lossy(content));
                            change.text.push('\n');
                            change.line_numbers.push(new_line);
                        }
                    }
                    new_line += 1;
                    continue;
                }
                Some(b'-') if old_left > 0 => {
                    old_left -= 1;
                    continue;
                }
                Some(b'\\') => continue, // "\ No newline at end of file"
                _ => {
                    // Malformed or truncated hunk: fall through and treat as a header line.
                    old_left = 0;
                    new_left = 0;
                }
            }
        }
        if raw.first() == Some(&b'\\') {
            continue;
        }

        if raw.first() == Some(&COMMIT_MARKER) {
            flush(&mut pending, &commit, &mut stats);
            let header = String::from_utf8_lossy(&raw[1..]).to_string();
            let mut parts = header.splitn(3, ' ');
            let sha = parts.next().unwrap_or_default().to_string();
            let unix = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            let iso = parts.next().unwrap_or_default().to_string();
            commit = (sha, unix, iso);
            stats.commits += 1;
            continue;
        }
        if raw.starts_with(b"diff --git ") {
            flush(&mut pending, &commit, &mut stats);
            continue;
        }
        if let Some(target) = raw.strip_prefix(b"+++ ") {
            flush(&mut pending, &commit, &mut stats);
            pending = parse_target_path(target).map(|path| Pending {
                path,
                text: String::new(),
                line_numbers: Vec::new(),
                oversize: false,
            });
            continue;
        }
        if raw.starts_with(b"@@ ") {
            if let Some((old_count, new_start, new_count)) = parse_hunk_header(&raw) {
                old_left = old_count;
                new_left = new_count;
                new_line = new_start;
            }
        }
    }
    flush(&mut pending, &commit, &mut stats);
    Ok(stats)
}

/// `@@ -a[,b] +c[,d] @@` -> (b, c, d); a missing count means 1.
fn parse_hunk_header(line: &[u8]) -> Option<(usize, usize, usize)> {
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.split(' ');
    parts.next()?; // @@
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let count = |spec: &str| -> Option<(usize, usize)> {
        match spec.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((spec.parse().ok()?, 1)),
        }
    };
    let (_, old_count) = count(old)?;
    let (new_start, new_count) = count(new)?;
    Some((old_count, new_start, new_count))
}

/// `b/path`, `"b/pa\tth"` (C-quoted) or `/dev/null`.
fn parse_target_path(raw: &[u8]) -> Option<String> {
    let bytes = if raw.first() == Some(&b'"') && raw.len() >= 2 && raw.last() == Some(&b'"') {
        unquote_c(&raw[1..raw.len() - 1])?
    } else {
        raw.to_vec()
    };
    let path = String::from_utf8(bytes).ok()?;
    if path == "/dev/null" {
        return None;
    }
    path.strip_prefix("b/").map(str::to_string)
}

fn unquote_c(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if byte != b'\\' {
            out.push(byte);
            index += 1;
            continue;
        }
        let next = *raw.get(index + 1)?;
        let (value, used) = match next {
            b'n' => (b'\n', 2),
            b't' => (b'\t', 2),
            b'r' => (b'\r', 2),
            b'"' => (b'"', 2),
            b'\\' => (b'\\', 2),
            b'a' => (0x07, 2),
            b'b' => (0x08, 2),
            b'f' => (0x0c, 2),
            b'v' => (0x0b, 2),
            b'0'..=b'7' => {
                let digits = raw.get(index + 1..index + 4)?;
                let text = std::str::from_utf8(digits).ok()?;
                (u8::from_str_radix(text, 8).ok()?, 4)
            }
            _ => return None,
        };
        out.push(value);
        index += used;
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// Running git

fn git_log_command(root: &Path, max_commits: usize) -> Command {
    let mut command = Command::new("git");
    let root_text = root.to_string_lossy().to_string();
    for setting in [
        "core.quotePath=false".to_string(),
        "core.pager=cat".to_string(),
        "core.fsmonitor=false".to_string(),
        "core.hooksPath=/dev/null".to_string(),
        "diff.external=".to_string(),
        "log.showSignature=false".to_string(),
        "diff.relative=false".to_string(),
        format!("safe.directory={root_text}"),
    ] {
        command.arg("-c").arg(setting);
    }
    command
        .arg("-C")
        .arg(root)
        .args([
            "--no-pager",
            "log",
            "--all",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-relative",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "-p",
            "--unified=0",
            "--format=%x01%H %ct %cI",
        ])
        .arg(format!("--max-count={}", max_commits + 1))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_EXTERNAL_DIFF")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

struct GitScan {
    stats: ParseStats,
    commit_limit_reached: bool,
}

fn run_git_log(
    root: &Path,
    max_commits: usize,
    mut visit: impl FnMut(AddedText),
) -> Result<GitScan, SecretHistoryError> {
    let mut child = git_log_command(root, max_commits)
        .spawn()
        .map_err(|error| SecretHistoryError::GitUnavailable(error.to_string()))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = BufReader::new(stderr)
            .take(16 * 1024)
            .read_to_string(&mut text);
        text
    });
    let child = Arc::new(Mutex::new(child));
    let done = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let (child, done, timed_out) = (child.clone(), done.clone(), timed_out.clone());
        thread::spawn(move || {
            let deadline = Instant::now() + GIT_TIMEOUT;
            while !done.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    timed_out.store(true, Ordering::SeqCst);
                    if let Ok(mut child) = child.lock() {
                        let _ = child.kill();
                    }
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };

    // One extra commit is requested so hitting the limit is detectable; its changes are ignored.
    let mut seen_commits = 0usize;
    let mut current = String::new();
    let parsed = parse_git_log(BufReader::new(stdout), |change| {
        if change.commit != current {
            current = change.commit.clone();
            seen_commits += 1;
        }
        if seen_commits <= max_commits {
            visit(change);
        }
    });
    done.store(true, Ordering::SeqCst);
    let _ = watchdog.join();
    let status = child
        .lock()
        .map_err(|_| SecretHistoryError::GitFailed("git process lock poisoned".to_string()))?
        .wait()?;
    let stderr = stderr_reader.join().unwrap_or_default();
    if timed_out.load(Ordering::SeqCst) {
        return Err(SecretHistoryError::GitFailed(format!(
            "git log did not finish within {} seconds",
            GIT_TIMEOUT.as_secs()
        )));
    }
    let mut stats = parsed?;
    if !status.success() {
        return Err(SecretHistoryError::GitFailed(
            stderr.lines().next().unwrap_or("non-zero exit").to_string(),
        ));
    }
    let commit_limit_reached = stats.commits > max_commits;
    stats.commits = stats.commits.min(max_commits);
    Ok(GitScan {
        stats,
        commit_limit_reached,
    })
}

// ---------------------------------------------------------------------------------------------
// Aggregation

struct Leak {
    raw_value: String,
    rule_id: &'static str,
    title: &'static str,
    severity: &'static str,
    confidence: f64,
    remediation: &'static str,
    redacted: String,
    in_test_path: bool,
    introduced: (i64, String, String, String, usize), // unix, iso, commit, path, line
    commits: BTreeSet<String>,
    paths: BTreeSet<String>,
    still_in_working_tree: bool,
}

struct Collection {
    leaks: BTreeMap<String, Leak>,
    shallow_clone: bool,
    stats: ParseStats,
    commit_limit_reached: bool,
    skipped_changes: usize,
    value_limit_reached: bool,
}

/// `.git/shallow` exists in shallow clones; `.git` may also be a file pointing elsewhere
/// (worktrees, submodules), in which case git itself is asked.
fn is_shallow(root: &Path) -> bool {
    let git = root.join(".git");
    if git.is_dir() {
        return git.join("shallow").is_file();
    }
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-shallow-repository"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| output.stdout.starts_with(b"true"))
}

fn skipped_path(path: &str) -> bool {
    path.split('/').any(is_skipped_dir)
}

fn collect(
    project_id: &str,
    root: &Path,
    max_commits: usize,
) -> Result<Collection, SecretHistoryError> {
    let mut leaks: BTreeMap<String, Leak> = BTreeMap::new();
    let mut skipped_changes = 0usize;
    let mut value_limit_reached = false;
    let scan = run_git_log(root, max_commits, |change| {
        let Some(path) = normalize_relative_path(&change.path, false) else {
            skipped_changes += 1;
            return;
        };
        if skipped_path(&path) {
            skipped_changes += 1;
            return;
        }
        for observation in secret_scanner::scan_text(&path, &change.text) {
            let (start, end) = observation.secret_range;
            let value = &change.text[start..end];
            let digest = salted_digest(project_id, value);
            let line = change
                .line_numbers
                .get(observation.line.saturating_sub(1))
                .copied()
                .unwrap_or(observation.line);
            let introduced = (
                change.committed_unix,
                change.committed_at.clone(),
                change.commit.clone(),
                path.clone(),
                line,
            );
            if let Some(leak) = leaks.get_mut(&digest) {
                leak.commits.insert(change.commit.clone());
                leak.paths.insert(path.clone());
                leak.in_test_path &= observation.in_test_path;
                // Oldest commit wins; ties keep the first seen.
                if introduced.0 < leak.introduced.0 {
                    leak.introduced = introduced;
                }
                continue;
            }
            if leaks.len() >= MAX_DISTINCT_VALUES {
                value_limit_reached = true;
                continue;
            }
            leaks.insert(
                digest,
                Leak {
                    raw_value: value.to_string(),
                    rule_id: observation.rule_id,
                    title: observation.title,
                    severity: observation.severity.as_str(),
                    confidence: observation.confidence,
                    remediation: observation.remediation,
                    redacted: observation.redacted.clone(),
                    in_test_path: observation.in_test_path,
                    introduced,
                    commits: BTreeSet::from([change.commit.clone()]),
                    paths: BTreeSet::from([path.clone()]),
                    still_in_working_tree: false,
                },
            );
        }
    })?;

    for leak in leaks.values_mut() {
        leak.still_in_working_tree = leak.paths.iter().any(|path| {
            let file = root.join(path);
            fs::metadata(&file)
                .is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_WORKING_FILE_BYTES)
                && fs::read(&file)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .is_some_and(|text| text.contains(&leak.raw_value))
        });
    }
    Ok(Collection {
        leaks,
        shallow_clone: is_shallow(root),
        stats: scan.stats,
        commit_limit_reached: scan.commit_limit_reached,
        skipped_changes,
        value_limit_reached,
    })
}

// ---------------------------------------------------------------------------------------------
// Service

pub struct SecretHistoryService<'a> {
    database: &'a Database,
}

impl<'a> SecretHistoryService<'a> {
    pub const fn new(database: &'a Database) -> Self {
        Self { database }
    }

    pub fn scan_project(
        &self,
        project_id: &str,
        max_commits: usize,
    ) -> Result<SecretHistorySummary, SecretHistoryError> {
        let connection = self.database.connection();
        let root = project_root(connection, project_id)?;
        let root = fs::canonicalize(&root)?;
        if !root.is_dir() {
            return Err(SecretHistoryError::InvalidProjectRoot(
                root.display().to_string(),
            ));
        }
        if !root.join(".git").exists() {
            return Err(SecretHistoryError::NotARepository);
        }
        let max_commits = max_commits.clamp(1, MAX_COMMITS_LIMIT);
        let started = Instant::now();
        let run_id = new_run_id(project_id);
        let configuration_json = json!({
            "ruleset_version": secret_scanner::RULESET_VERSION,
            "max_commits": max_commits,
            "raw_secrets_persisted": false,
            "git_history_scanned": true,
            "repository_commands_executed": false,
            "git_command": "git log --all -p --unified=0 --no-ext-diff --no-textconv",
        })
        .to_string();
        connection.execute(
            "INSERT INTO analysis_runs(id, project_id, status, analyzer_version, started_at, configuration_json, run_kind) \
             VALUES (?1, ?2, 'running', ?3, CURRENT_TIMESTAMP, ?4, 'secret_history')",
            params![run_id, project_id, ANALYZER_VERSION, configuration_json],
        )?;
        let collection = match collect(project_id, &root, max_commits) {
            Ok(collection) => collection,
            Err(error) => {
                let _ = finish_run(
                    connection,
                    &run_id,
                    AnalysisStatus::Failed,
                    elapsed_ms(started),
                );
                return Err(error);
            }
        };
        let duration_ms = elapsed_ms(started);
        persist(connection, project_id, &run_id, &collection, duration_ms).inspect_err(|_| {
            let _ = finish_run(connection, &run_id, AnalysisStatus::Failed, duration_ms);
        })
    }

    pub fn list_findings(
        &self,
        project_id: &str,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SecretHistoryFindingRecord>, SecretHistoryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT f.id, f.sub_category, f.severity, COALESCE(f.confidence, 0), f.title, f.description, \
                    COALESCE(e.uri, ''), e.line_start, COALESCE(e.metadata_json, '{}'), f.status, \
                    f.first_seen, f.last_seen, f.resolved_at \
             FROM findings f LEFT JOIN finding_evidence e ON e.finding_id = f.id \
             WHERE f.project_id = ?1 AND f.analyzer_key = ?2 AND (?3 IS NULL OR f.status = ?3) \
             ORDER BY f.status = 'open' DESC, \
                      CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, \
                      f.last_seen DESC \
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![project_id, ANALYZER_KEY, status, bounded(limit)],
            |row| {
                let metadata: serde_json::Value =
                    serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or_default();
                let text = |key: &str| metadata[key].as_str().unwrap_or_default().to_string();
                Ok(SecretHistoryFindingRecord {
                    id: row.get(0)?,
                    rule_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    severity: row.get(2)?,
                    confidence: row.get(3)?,
                    title: row.get(4)?,
                    description: row.get(5)?,
                    relative_path: row.get(6)?,
                    line: row.get::<_, Option<i64>>(7)?.map(to_usize),
                    redacted: metadata["redacted"]
                        .as_str()
                        .unwrap_or("********")
                        .to_string(),
                    introduced_commit: text("introduced_commit"),
                    introduced_at: text("introduced_at"),
                    commit_count: metadata["commit_count"].as_u64().unwrap_or(0) as usize,
                    paths: metadata["paths"]
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                    still_in_working_tree: metadata["still_in_working_tree"]
                        .as_bool()
                        .unwrap_or(false),
                    in_test_path: metadata["in_test_path"].as_bool().unwrap_or(false),
                    remediation: text("remediation"),
                    status: row.get(9)?,
                    first_seen: row.get(10)?,
                    last_seen: row.get(11)?,
                    resolved_at: row.get(12)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn history(
        &self,
        project_id: &str,
        limit: usize,
    ) -> Result<Vec<SecretHistoryRunRecord>, SecretHistoryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT r.id, r.status, r.started_at, r.finished_at, r.duration_ms, \
                    COALESCE(m.coverage_complete, 0), COALESCE(m.commits_scanned, 0), \
                    COALESCE(m.commit_limit_reached, 0), COALESCE(m.observations, 0), \
                    COALESCE(m.still_in_working_tree, 0), COALESCE(m.findings_opened, 0), \
                    COALESCE(m.findings_resolved, 0), COALESCE(m.shallow_clone, 0) \
             FROM analysis_runs r LEFT JOIN secret_history_run_metrics m ON m.run_id = r.id \
             WHERE r.project_id = ?1 AND r.run_kind = 'secret_history' \
             ORDER BY r.started_at DESC, r.rowid DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![project_id, bounded(limit.min(100))], |row| {
            Ok(SecretHistoryRunRecord {
                run_id: row.get(0)?,
                status: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                duration_ms: row
                    .get::<_, Option<i64>>(4)?
                    .map(|value| value.max(0) as u64),
                coverage_complete: row.get::<_, i64>(5)? == 1,
                commits_scanned: to_usize(row.get(6)?),
                commit_limit_reached: row.get::<_, i64>(7)? == 1,
                shallow_clone: row.get::<_, i64>(12)? == 1,
                observations: to_usize(row.get(8)?),
                still_in_working_tree: to_usize(row.get(9)?),
                findings_opened: to_usize(row.get(10)?),
                findings_resolved: to_usize(row.get(11)?),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn persist(
    connection: &Connection,
    project_id: &str,
    run_id: &str,
    collection: &Collection,
    duration_ms: u64,
) -> Result<SecretHistorySummary, SecretHistoryError> {
    let coverage_complete = !collection.commit_limit_reached && !collection.value_limit_reached;
    let existing = existing_findings(connection, project_id)?;
    let fingerprints: BTreeMap<String, &Leak> = collection
        .leaks
        .iter()
        .map(|(digest, leak)| {
            (
                deterministic_id(
                    "secret-history-finding",
                    &[project_id, leak.rule_id, digest],
                ),
                leak,
            )
        })
        .collect();
    let findings_opened = fingerprints
        .keys()
        .filter(|fingerprint| !existing.contains_key(*fingerprint))
        .count();
    let findings_refreshed = fingerprints.len() - findings_opened;
    let findings_resolved = if coverage_complete {
        existing
            .iter()
            .filter(|(fingerprint, (_, status))| {
                status == "open" && !fingerprints.contains_key(*fingerprint)
            })
            .count()
    } else {
        0
    };
    let still_present = collection
        .leaks
        .values()
        .filter(|leak| leak.still_in_working_tree)
        .count();

    let transaction = connection.unchecked_transaction()?;
    if coverage_complete {
        transaction.execute(
            "UPDATE findings SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, last_run_id = ?2 \
             WHERE project_id = ?1 AND analyzer_key = ?3 AND status = 'open'",
            params![project_id, run_id, ANALYZER_KEY],
        )?;
    }
    for (fingerprint, leak) in &fingerprints {
        let finding_id = existing.get(fingerprint).map_or_else(
            || deterministic_id("finding", &[project_id, ANALYZER_KEY, fingerprint]),
            |(id, _)| id.clone(),
        );
        let (_, introduced_at, commit, path, line) = &leak.introduced;
        let short = &commit[..commit.len().min(12)];
        let presence = if leak.still_in_working_tree {
            "It is still present in the current files."
        } else {
            "It is no longer in the current files, but anyone with a clone can still read it."
        };
        let description = format!(
            "{} committed in {short} ({introduced_at}) at {path}:{line}; seen in {} commit(s). Preview: {}. {presence}",
            leak.title,
            leak.commits.len(),
            leak.redacted,
        );
        let confidence = if leak.in_test_path {
            leak.confidence.min(0.6)
        } else {
            leak.confidence
        };
        transaction.execute(
            "INSERT INTO findings( \
               id, project_id, run_id, category, sub_category, severity, confidence, title, description, \
               file_id, symbol_id, source_start_line, source_end_line, cwe, owasp, status, fingerprint, \
               rule_version, first_seen, last_seen, analyzer_key, last_run_id, resolved_at \
             ) VALUES (?1, ?2, ?3, 'secrets', ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9, ?9, 'CWE-798', \
                       'A07:2021 Identification and Authentication Failures', 'open', ?10, ?11, \
                       CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?12, ?3, NULL) \
             ON CONFLICT(project_id, fingerprint) DO UPDATE SET \
               run_id = excluded.run_id, severity = excluded.severity, confidence = excluded.confidence, \
               title = excluded.title, description = excluded.description, \
               source_start_line = excluded.source_start_line, source_end_line = excluded.source_end_line, \
               status = 'open', rule_version = excluded.rule_version, last_seen = CURRENT_TIMESTAMP, \
               last_run_id = excluded.last_run_id, resolved_at = NULL",
            params![
                finding_id,
                project_id,
                run_id,
                leak.rule_id,
                leak.severity,
                confidence,
                format!("{} in git history", leak.title),
                description,
                to_i64(*line),
                fingerprint,
                secret_scanner::RULESET_VERSION,
                ANALYZER_KEY,
            ],
        )?;
        transaction.execute(
            "DELETE FROM finding_evidence WHERE finding_id = ?1",
            [&finding_id],
        )?;
        transaction.execute(
            "INSERT INTO finding_evidence(id, finding_id, evidence_type, uri, line_start, line_end, summary, metadata_json) \
             VALUES (?1, ?2, 'secret_history_match', ?3, ?4, ?4, ?5, ?6)",
            params![
                deterministic_id("secret-history-evidence", &[&finding_id]),
                finding_id,
                path,
                to_i64(*line),
                format!("Redacted value: {} (commit {short})", leak.redacted),
                json!({
                    "rule_id": leak.rule_id,
                    "redacted": leak.redacted,
                    "introduced_commit": commit,
                    "introduced_at": introduced_at,
                    "commit_count": leak.commits.len(),
                    "paths": leak.paths.iter().take(MAX_LISTED_PATHS).collect::<Vec<_>>(),
                    "still_in_working_tree": leak.still_in_working_tree,
                    "in_test_path": leak.in_test_path,
                    "remediation": format!(
                        "{} Removing it from history (git filter-repo, BFG) does not help copies that were already cloned or forked, so rotate first.",
                        leak.remediation
                    ),
                    "raw_value_persisted": false,
                })
                .to_string(),
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO secret_history_run_metrics( \
           run_id, coverage_complete, commits_scanned, commit_limit_reached, file_changes_scanned, \
           file_changes_skipped, observations, still_in_working_tree, findings_opened, findings_refreshed, \
           findings_resolved, shallow_clone \
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            run_id,
            i64::from(coverage_complete),
            to_i64(collection.stats.commits),
            i64::from(collection.commit_limit_reached),
            to_i64(collection.stats.changes),
            to_i64(collection.stats.oversize_changes + collection.skipped_changes),
            to_i64(collection.leaks.len()),
            to_i64(still_present),
            to_i64(findings_opened),
            to_i64(findings_refreshed),
            to_i64(findings_resolved),
            i64::from(collection.shallow_clone),
        ],
    )?;
    finish_run(&transaction, run_id, AnalysisStatus::Completed, duration_ms)?;
    transaction.commit()?;

    Ok(SecretHistorySummary {
        project_id: project_id.to_string(),
        run_id: run_id.to_string(),
        status: AnalysisStatus::Completed,
        coverage_complete,
        commits_scanned: collection.stats.commits,
        commit_limit_reached: collection.commit_limit_reached,
        shallow_clone: collection.shallow_clone,
        file_changes_scanned: collection.stats.changes,
        file_changes_skipped: collection.stats.oversize_changes + collection.skipped_changes,
        observations: collection.leaks.len(),
        still_in_working_tree: still_present,
        findings_opened,
        findings_refreshed,
        findings_resolved,
        duration_ms,
    })
}

fn existing_findings(
    connection: &Connection,
    project_id: &str,
) -> Result<BTreeMap<String, (String, String)>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT fingerprint, id, status FROM findings WHERE project_id = ?1 AND analyzer_key = ?2",
    )?;
    let rows = statement.query_map(params![project_id, ANALYZER_KEY], |row| {
        Ok((row.get(0)?, (row.get(1)?, row.get(2)?)))
    })?;
    rows.collect()
}

fn new_run_id(project_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    deterministic_id("secret-history-run", &[project_id, &nanos.to_string()])
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn bounded(limit: usize) -> i64 {
    i64::try_from(limit.clamp(1, MAX_QUERY)).unwrap_or(1)
}

fn to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> (Vec<AddedText>, ParseStats) {
        let mut changes = Vec::new();
        let stats = parse_git_log(text.as_bytes(), |change| changes.push(change)).unwrap();
        (changes, stats)
    }

    #[test]
    fn parses_added_lines_with_new_file_line_numbers() {
        let log = "\x01aaa 1700000000 2023-11-14T22:13:20+00:00\n\
                   diff --git a/src/a.py b/src/a.py\n\
                   index 1..2 100644\n\
                   --- a/src/a.py\n\
                   +++ b/src/a.py\n\
                   @@ -3,0 +4,2 @@ def f():\n\
                   +x = 1\n\
                   ++++ b/not/a/header\n\
                   @@ -10 +11 @@\n\
                   -old\n\
                   +new\n\
                   \\ No newline at end of file\n\
                   diff --git a/gone.txt b/gone.txt\n\
                   deleted file mode 100644\n\
                   --- a/gone.txt\n\
                   +++ /dev/null\n\
                   @@ -1 +0,0 @@\n\
                   -bye\n\
                   \x01bbb 1600000000 2020-09-13T12:26:40+00:00\n\
                   diff --git \"a/sp ace\\tx\" \"b/sp ace\\tx\"\n\
                   --- /dev/null\n\
                   +++ \"b/sp ace\\tx\"\n\
                   @@ -0,0 +1 @@\n\
                   +k\n";
        let (changes, stats) = parse(log);
        assert_eq!(stats.commits, 2);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].commit, "aaa");
        assert_eq!(changes[0].committed_unix, 1_700_000_000);
        assert_eq!(changes[0].path, "src/a.py");
        assert_eq!(changes[0].text, "x = 1\n+++ b/not/a/header\nnew\n");
        assert_eq!(changes[0].line_numbers, vec![4, 5, 11]);
        assert_eq!(changes[1].path, "sp ace\tx");
        assert_eq!(changes[1].commit, "bbb");
    }

    #[test]
    fn oversize_changes_are_counted_not_scanned() {
        let big = "a".repeat(MAX_LINE_BYTES);
        let lines = MAX_CHANGE_BYTES / MAX_LINE_BYTES + 2;
        let mut log = format!("\x01c 1 x\n+++ b/big.js\n@@ -0,0 +1,{lines} @@\n");
        for _ in 0..lines {
            log.push('+');
            log.push_str(&big);
            log.push('\n');
        }
        let (changes, stats) = parse(&log);
        assert!(changes.is_empty());
        assert_eq!(stats.oversize_changes, 1);
    }

    #[test]
    fn hunk_headers_and_quoted_paths() {
        assert_eq!(parse_hunk_header(b"@@ -1 +1 @@"), Some((1, 1, 1)));
        assert_eq!(parse_hunk_header(b"@@ -0,0 +1,3 @@ ctx"), Some((0, 1, 3)));
        assert_eq!(parse_hunk_header(b"@@ garbage"), None);
        assert_eq!(
            parse_target_path(b"\"b/caf\\303\\251.txt\"").as_deref(),
            Some("café.txt")
        );
        assert_eq!(parse_target_path(b"/dev/null"), None);
        assert_eq!(parse_target_path(b"c/unexpected"), None);
    }

    #[test]
    fn git_command_disables_configurable_programs() {
        let command = git_log_command(Path::new("/repo"), 10);
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        for required in [
            "--no-ext-diff",
            "--no-textconv",
            "--no-pager",
            "diff.external=",
            "log.showSignature=false",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--max-count=11",
        ] {
            assert!(args.iter().any(|arg| arg == required), "missing {required}");
        }
    }
}
