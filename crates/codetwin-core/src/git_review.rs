//! Read-only repository review. No network, staging, filters, hooks or project execution.
use serde::Serialize;
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const FILE_LIMIT: u64 = 256 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct GitReviewError(String);

#[derive(Debug, Serialize)]
pub struct GitChange {
    pub path: String,
    pub original_path: Option<String>,
    pub staged: String,
    pub unstaged: String,
}

#[derive(Debug, Serialize)]
pub struct GitReviewStatus {
    pub branch: Option<String>,
    pub head: Option<String>,
    pub changes: Vec<GitChange>,
}

#[derive(Debug, Serialize)]
pub struct GitFileReview {
    pub path: String,
    pub staged_diff: String,
    pub unstaged_diff: String,
    pub untracked_content: Option<String>,
    pub notice: Option<String>,
}

fn error(value: impl ToString) -> GitReviewError {
    GitReviewError(value.to_string())
}

// Drain both pipes while retaining bounded output, so verbose failures cannot deadlock.
fn drain(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let keep = count.min((OUTPUT_LIMIT + 1).saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..keep]);
    }
    Ok(bytes)
}

fn git(
    root: &Path,
    arguments: &[&str],
    allow_missing_ref: bool,
) -> Result<Option<Vec<u8>>, GitReviewError> {
    // Diff/status may invoke clean or process filters even with --no-textconv.
    // Enumerate names only (never credential-bearing config values), then disable them.
    let keys = run_git(
        root,
        &[
            "config",
            "--null",
            "--name-only",
            "--get-regexp",
            r"^filter\..*\.(clean|smudge|process|required)$",
        ],
        true,
        &[],
    )?;
    let mut settings = Vec::new();
    if let Some(keys) = keys {
        for key in text(keys)?.split('\0').filter(|key| !key.is_empty()) {
            settings.push(format!(
                "{key}={}",
                if key.ends_with(".required") {
                    "false"
                } else {
                    ""
                }
            ));
        }
    }
    run_git(root, arguments, allow_missing_ref, &settings)
}

fn run_git(
    root: &Path,
    arguments: &[&str],
    allow_missing_ref: bool,
    settings: &[String],
) -> Result<Option<Vec<u8>>, GitReviewError> {
    let mut command = Command::new("git");
    for setting in settings {
        command.args(["-c", setting]);
    }
    for setting in [
        "core.fsmonitor=false",
        "core.pager=",
        "diff.external=",
        "diff.relative=false",
        "diff.submodule=short",
        "submodule.recurse=false",
    ] {
        command.args(["-c", setting]);
    }
    // Do not grant trust with safe.directory: Git's ownership checks remain in force.
    command
        .arg("-C")
        .arg(root)
        .args(["--no-pager", "--literal-pathspecs"])
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "")
        .env("PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_CEILING_DIRECTORIES",
    ] {
        command.env_remove(name);
    }
    let mut child = command.spawn().map_err(error)?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let out = thread::spawn(move || drain(stdout));
    let err = thread::spawn(move || drain(stderr));
    let start = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if start.elapsed() < Duration::from_secs(15) => {
                thread::sleep(Duration::from_millis(20))
            }
            result => {
                let _ = child.kill();
                let status = child.wait().map_err(error)?;
                if let Err(cause) = result {
                    return Err(error(cause));
                }
                break (status, true);
            }
        }
    };
    let stdout = out
        .join()
        .map_err(|_| error("Git output reader failed"))?
        .map_err(error)?;
    let stderr = err
        .join()
        .map_err(|_| error("Git error reader failed"))?
        .map_err(error)?;
    if timed_out {
        return Err(error("Git review exceeded its 15 second command limit"));
    }
    if stdout.len() > OUTPUT_LIMIT || stderr.len() > OUTPUT_LIMIT {
        return Err(error(
            "Git review exceeds the 2 MiB output limit; narrow the repository changes",
        ));
    }
    if !status.success() {
        if allow_missing_ref && status.code() == Some(1) {
            return Ok(None);
        }
        return Err(error(format!(
            "Git review failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        )));
    }
    Ok(Some(stdout))
}

fn text(bytes: Vec<u8>) -> Result<String, GitReviewError> {
    String::from_utf8(bytes).map_err(|_| error("Git review requires UTF-8 paths and output"))
}

fn required(root: &Path, args: &[&str]) -> Result<String, GitReviewError> {
    text(git(root, args, false)?.expect("required result"))
}

fn repository_root(root: &Path) -> Result<PathBuf, GitReviewError> {
    let root = fs::canonicalize(root).map_err(error)?;
    let top = required(&root, &["rev-parse", "--show-toplevel"])?;
    if fs::canonicalize(top.trim_end_matches(['\r', '\n'])).map_err(error)? != root {
        return Err(error("Add the Git repository root as a project; nested folders are not reviewed as their parent repository"));
    }
    Ok(root)
}

fn status_at(root: &Path) -> Result<GitReviewStatus, GitReviewError> {
    let branch = git(root, &["symbolic-ref", "--quiet", "--short", "HEAD"], true)?
        .map(text)
        .transpose()?
        .map(|value| value.trim_end().to_string());
    let head = git(root, &["rev-parse", "--verify", "--quiet", "HEAD"], true)?
        .map(text)
        .transpose()?
        .map(|value| value.trim_end().to_string());
    let raw = required(
        root,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=dirty",
        ],
    )?;
    let mut entries = raw.split('\0').filter(|entry| !entry.is_empty());
    let mut changes = Vec::new();
    while let Some(entry) = entries.next() {
        if entry.len() < 4 || !entry.is_char_boundary(3) {
            return Err(error("Malformed Git status"));
        }
        let code = entry.as_bytes();
        let original_path =
            if code[0] == b'R' || code[0] == b'C' || code[1] == b'R' || code[1] == b'C' {
                Some(
                    entries
                        .next()
                        .ok_or_else(|| error("Missing renamed path"))?
                        .to_string(),
                )
            } else {
                None
            };
        changes.push(GitChange {
            path: entry[3..].to_string(),
            original_path,
            staged: entry[..1].to_string(),
            unstaged: entry[1..2].to_string(),
        });
        if changes.len() > 500 {
            return Err(error(
                "More than 500 changed files; narrow the repository changes before review",
            ));
        }
    }
    Ok(GitReviewStatus {
        branch,
        head,
        changes,
    })
}

pub fn review_git_status(root: impl AsRef<Path>) -> Result<GitReviewStatus, GitReviewError> {
    status_at(&repository_root(root.as_ref())?)
}

pub fn review_git_file(
    root: impl AsRef<Path>,
    path: &str,
) -> Result<GitFileReview, GitReviewError> {
    let root = repository_root(root.as_ref())?;
    let status = status_at(&root)?;
    let change = status
        .changes
        .iter()
        .find(|change| change.path == path)
        .ok_or_else(|| error("File is no longer changed. Refresh Git changes."))?;
    let mut review = GitFileReview {
        path: path.to_string(),
        staged_diff: String::new(),
        unstaged_diff: String::new(),
        untracked_content: None,
        notice: None,
    };
    if change.staged == "?" {
        let candidate = root.join(path);
        // Never read an untracked symlink or traverse through a symlink outside the root.
        let metadata = fs::symlink_metadata(&candidate).map_err(error)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            review.notice =
                Some("Untracked symlink or non-regular file: content preview unavailable.".into());
        } else if !fs::canonicalize(&candidate)
            .map_err(error)?
            .starts_with(&root)
        {
            return Err(error("Untracked file resolves outside the repository"));
        } else if metadata.len() > FILE_LIMIT {
            review.notice = Some("Untracked file exceeds the 256 KiB preview limit.".into());
        } else {
            let mut bytes = Vec::new();
            fs::File::open(candidate)
                .map_err(error)?
                .take(FILE_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(error)?;
            if bytes.len() as u64 > FILE_LIMIT || bytes.contains(&0) {
                review.notice =
                    Some("Binary or oversized untracked file: content preview unavailable.".into());
            } else {
                match String::from_utf8(bytes) {
                    Ok(content) => review.untracked_content = Some(content),
                    Err(_) => {
                        review.notice =
                            Some("Non-UTF-8 untracked file: content preview unavailable.".into())
                    }
                }
            }
        }
    } else {
        let common = [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--no-relative",
            "--ignore-submodules=dirty",
        ];
        let paths = if let Some(original) = change.original_path.as_deref() {
            vec![path, original]
        } else {
            vec![path]
        };
        let mut staged = common.to_vec();
        staged.extend(["--cached", "--"]);
        staged.extend(&paths);
        review.staged_diff = required(&root, &staged)?;
        let mut unstaged = common.to_vec();
        unstaged.push("--");
        unstaged.extend(&paths);
        review.unstaged_diff = required(&root, &unstaged)?;
        if review.staged_diff.is_empty() && review.unstaged_diff.is_empty() {
            review.notice = Some(
                "No textual patch. This may be a conflict, mode-only change or submodule pointer change."
                    .into(),
            );
        }
    }
    Ok(review)
}
