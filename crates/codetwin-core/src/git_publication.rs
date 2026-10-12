//! Explicit, credential-in-memory GitHub publication. No Git network helpers.
use crate::git_review::{
    controlled_git_with_env, error, repository_root, required, GitReviewError,
};
use reqwest::{blocking::Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Clone, Deserialize, Serialize)]
pub struct GitPublishTarget {
    pub repository: String,
    pub branch: String,
    pub commit: String,
}
#[derive(Debug, Serialize)]
pub struct GitPublishReceipt {
    pub repository: String,
    pub branch: String,
    pub commit: String,
}

fn validate(target: &GitPublishTarget) -> Result<(), GitReviewError> {
    let parts: Vec<_> = target.repository.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|v| {
            v.is_empty()
                || v.len() > 100
                || *v == "."
                || *v == ".."
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(error("Enter a GitHub repository as owner/name"));
    }
    if target.branch.is_empty()
        || target.branch.len() > 120
        || target.branch.starts_with('-')
        || !target
            .branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        return Err(error("Invalid publication branch"));
    }
    if target.commit.len() != 40 || !target.commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error(
            "GitHub publication currently requires a full SHA-1 commit",
        ));
    }
    Ok(())
}
struct Api {
    client: Client,
    endpoint: String,
    token: String,
    started: Instant,
}
impl Api {
    fn new(token: &str) -> Result<Self, GitReviewError> {
        if token.len() < 10 || token.len() > 1024 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(error("Enter a GitHub token without whitespace"));
        }
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .connect_timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| error("Cannot initialize GitHub client"))?,
            endpoint: "https://api.github.com".into(),
            token: token.into(),
            started: Instant::now(),
        })
    }
    fn call(
        &self,
        method: Method,
        repo: &str,
        suffix: &[&str],
        body: Option<Value>,
        query: &[(&str, &str)],
        missing: bool,
    ) -> Result<Option<Value>, GitReviewError> {
        if self.started.elapsed() > Duration::from_secs(120) {
            return Err(error("GitHub operation exceeded its request budget. Verify remote state before retrying."));
        }
        let mut url =
            url::Url::parse(&self.endpoint).map_err(|_| error("Invalid GitHub endpoint"))?;
        let (owner, name) = repo
            .split_once('/')
            .ok_or_else(|| error("Invalid repository"))?;
        url.path_segments_mut()
            .map_err(|_| error("Invalid GitHub endpoint"))?
            .extend(["repos", owner, name])
            .extend(suffix);
        url.query_pairs_mut().extend_pairs(query.iter().copied());
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&self.token)
            .header("User-Agent", "CodeTwin-Desktop")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2026-03-10");
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().map_err(|_| {
            error("GitHub request failed; remote state may have changed. Verify before retrying.")
        })?;
        if missing && response.status().as_u16() == 404 {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(error(format!(
                "GitHub returned HTTP {}; verify permissions and remote state before retrying",
                response.status().as_u16()
            )));
        }
        let mut bytes = Vec::new();
        response
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("Cannot read GitHub response"))?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(error("GitHub response exceeded 2 MiB"));
        }
        Ok(Some(
            serde_json::from_slice(&bytes).map_err(|_| error("Invalid GitHub JSON response"))?,
        ))
    }
    fn object(
        &self,
        method: Method,
        repo: &str,
        suffix: &[&str],
        body: Option<Value>,
    ) -> Result<Value, GitReviewError> {
        self.call(method, repo, suffix, body, &[], false)?
            .ok_or_else(|| error("Missing GitHub response"))
    }
    fn branch(&self, target: &GitPublishTarget) -> Result<Option<String>, GitReviewError> {
        let value = self.call(
            Method::GET,
            &target.repository,
            &["git", "ref", "heads", &target.branch],
            None,
            &[],
            true,
        )?;
        value
            .map(|v| {
                v.pointer("/object/sha")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| error("Invalid remote branch response"))
            })
            .transpose()
    }
}
fn check_sha(value: &Value, expected: &str) -> Result<(), GitReviewError> {
    if value.get("sha").and_then(Value::as_str) != Some(expected) {
        return Err(error(
            "GitHub object hash differs from the reviewed local object; branch was not updated",
        ));
    }
    Ok(())
}
fn local(root: &Path, target: &GitPublishTarget) -> Result<(), GitReviewError> {
    validate(target)?;
    required(
        root,
        &["check-ref-format", &format!("refs/heads/{}", target.branch)],
    )?;
    if required(root, &["symbolic-ref", "--quiet", "HEAD"])?.trim_end()
        != format!("refs/heads/{}", target.branch)
        || required(root, &["rev-parse", "HEAD"])?.trim_end() != target.commit
    {
        return Err(error(
            "Branch or HEAD changed. Refresh Git changes before publication.",
        ));
    }
    Ok(())
}

pub fn publish_commit(
    root: impl AsRef<Path>,
    target: &GitPublishTarget,
    token: &str,
) -> Result<GitPublishReceipt, GitReviewError> {
    publish_with(&repository_root(root.as_ref())?, target, &Api::new(token)?)
}
fn publish_with(
    root: &Path,
    target: &GitPublishTarget,
    api: &Api,
) -> Result<GitPublishReceipt, GitReviewError> {
    local(root, target)?;
    let raw = required(root, &["cat-file", "commit", &target.commit])?;
    let (headers, message) = raw
        .split_once("\n\n")
        .ok_or_else(|| error("Malformed local commit"))?;
    let parents: Vec<_> = headers
        .lines()
        .filter_map(|l| l.strip_prefix("parent "))
        .collect();
    if parents.len() != 1
        || headers.lines().any(|l| {
            !["tree ", "parent ", "author ", "committer "]
                .iter()
                .any(|prefix| l.starts_with(prefix))
        })
    {
        return Err(error("Publish one unsigned single-parent commit with standard UTF-8 metadata; merge/signed/root commits are unsupported"));
    }
    if message.len() > 4096 {
        return Err(error("Publish a commit message of at most 4096 bytes"));
    }
    let parent = parents[0];
    let tree = required(root, &["rev-parse", &format!("{}^{{tree}}", target.commit)])?
        .trim_end()
        .to_string();
    let parent_tree = required(root, &["rev-parse", &format!("{parent}^{{tree}}")])?
        .trim_end()
        .to_string();
    let repository = api.object(Method::GET, &target.repository, &[], None)?;
    let default = repository
        .get("default_branch")
        .and_then(Value::as_str)
        .ok_or_else(|| error("Cannot determine the default branch"))?;
    if default == target.branch
        || repository
            .pointer("/permissions/push")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(error(
            "Publish to a non-default branch using a token with repository write permission",
        ));
    }
    let remote = api.branch(target)?;
    if remote.as_deref() == Some(&target.commit) {
        return Ok(GitPublishReceipt {
            repository: target.repository.clone(),
            branch: target.branch.clone(),
            commit: target.commit.clone(),
        });
    }
    if remote.is_some() && remote.as_deref() != Some(parent) {
        return Err(error(
            "Remote branch diverged; publication never forces an update",
        ));
    }
    let remote_parent = api.object(
        Method::GET,
        &target.repository,
        &["git", "commits", parent],
        None,
    )?;
    check_sha(&remote_parent, parent)?;
    if remote_parent.pointer("/tree/sha").and_then(Value::as_str) != Some(&parent_tree) {
        return Err(error("Remote parent tree differs from local history"));
    }
    let changed = required(
        root,
        &[
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            "-z",
            parent,
            &target.commit,
        ],
    )?;
    let paths: Vec<_> = changed.split('\0').filter(|p| !p.is_empty()).collect();
    if paths.is_empty() || paths.len() > 50 {
        return Err(error("Publish a commit with 1–50 changed paths"));
    }
    let mut entries = Vec::new();
    let mut total = 0;
    for path in paths {
        let record = required(root, &["ls-tree", "-z", &target.commit, "--", path])?;
        if record.is_empty() {
            let old = required(root, &["ls-tree", "-z", parent, "--", path])?;
            let mode = old
                .split(' ')
                .next()
                .ok_or_else(|| error("Missing deleted tree entry"))?;
            if !["100644", "100755"].contains(&mode) {
                return Err(error(
                    "Selected symlink/submodule/directory deletion is unsupported",
                ));
            }
            entries.push(json!({"path":path,"mode":mode,"type":"blob","sha":null}));
            continue;
        }
        let (metadata, actual) = record
            .trim_end_matches('\0')
            .split_once('\t')
            .ok_or_else(|| error("Malformed tree entry"))?;
        let parts: Vec<_> = metadata.split(' ').collect();
        if parts.len() != 3 || !["100644", "100755"].contains(&parts[0]) || actual != path {
            return Err(error(
                "Publish regular UTF-8 files; symlinks/submodules/directories are unsupported",
            ));
        }
        let bytes =
            controlled_git_with_env(root, &["cat-file", "blob", parts[2]], false, None, &[])?
                .expect("required blob");
        total += bytes.len();
        if bytes.len() > 256 * 1024 || total > 2 * 1024 * 1024 || bytes.contains(&0) {
            return Err(error(
                "Publication supports 256 KiB per UTF-8 file and 2 MiB total",
            ));
        }
        let content = String::from_utf8(bytes)
            .map_err(|_| error("Publication requires UTF-8 file content"))?;
        let blob = api.object(
            Method::POST,
            &target.repository,
            &["git", "blobs"],
            Some(json!({"content":content,"encoding":"utf-8"})),
        )?;
        check_sha(&blob, parts[2])?;
        entries.push(json!({"path":path,"mode":parts[0],"type":"blob","sha":parts[2]}));
    }
    let remote_tree = api.object(
        Method::POST,
        &target.repository,
        &["git", "trees"],
        Some(json!({"base_tree":parent_tree,"tree":entries})),
    )?;
    check_sha(&remote_tree, &tree)?;
    let metadata = required(
        root,
        &[
            "show",
            "-s",
            "--no-show-signature",
            "--format=%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI",
            &target.commit,
        ],
    )?;
    let fields: Vec<_> = metadata
        .trim_end_matches(['\r', '\n'])
        .split('\0')
        .collect();
    if fields.len() != 6 {
        return Err(error("Cannot read commit identity"));
    }
    let commit=api.object(Method::POST,&target.repository,&["git","commits"],Some(json!({"message":message,"tree":tree,"parents":[parent],"author":{"name":fields[0],"email":fields[1],"date":fields[2]},"committer":{"name":fields[3],"email":fields[4],"date":fields[5]}})))?;
    check_sha(&commit, &target.commit)?;
    local(root, target)?;
    if api.branch(target)? != remote {
        return Err(error(
            "Remote branch changed during upload; verify it before retrying",
        ));
    }
    if remote.is_some() {
        api.object(
            Method::PATCH,
            &target.repository,
            &["git", "refs", "heads", &target.branch],
            Some(json!({"sha":target.commit,"force":false})),
        )?;
    } else {
        api.object(
            Method::POST,
            &target.repository,
            &["git", "refs"],
            Some(json!({"ref":format!("refs/heads/{}",target.branch),"sha":target.commit})),
        )?;
    }
    if api.branch(target)?.as_deref() != Some(&target.commit) {
        return Err(error(
            "Publication response was uncertain. Verify the remote branch before retrying.",
        ));
    }
    Ok(GitPublishReceipt {
        repository: target.repository.clone(),
        branch: target.branch.clone(),
        commit: target.commit.clone(),
    })
}

pub fn open_draft_pr(
    root: impl AsRef<Path>,
    target: &GitPublishTarget,
    base: &str,
    title: &str,
    body: &str,
    token: &str,
) -> Result<String, GitReviewError> {
    let root = repository_root(root.as_ref())?;
    let api = Api::new(token)?;
    open_pr_with(&root, target, base, title, body, &api)
}
fn open_pr_with(
    root: &Path,
    target: &GitPublishTarget,
    base: &str,
    title: &str,
    body: &str,
    api: &Api,
) -> Result<String, GitReviewError> {
    local(root, target)?;
    if base == target.branch
        || base.is_empty()
        || base.len() > 120
        || !base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || title.trim().is_empty()
        || title.len() > 200
        || title.chars().any(char::is_control)
        || body.len() > 20000
        || body.contains('\0')
    {
        return Err(error(
            "Enter a distinct base branch, title and bounded PR description",
        ));
    }
    required(root, &["check-ref-format", &format!("refs/heads/{base}")])?;
    if api.branch(target)?.as_deref() != Some(&target.commit) {
        return Err(error(
            "Publish and verify this exact commit before opening a PR",
        ));
    }
    api.object(
        Method::GET,
        &target.repository,
        &["git", "ref", "heads", base],
        None,
    )?;
    let owner = target
        .repository
        .split('/')
        .next()
        .expect("validated owner");
    let head = format!("{owner}:{}", target.branch);
    let existing = api
        .call(
            Method::GET,
            &target.repository,
            &["pulls"],
            None,
            &[("state", "open"), ("head", &head), ("base", base)],
            false,
        )?
        .ok_or_else(|| error("Missing PR search"))?;
    let list = existing
        .as_array()
        .ok_or_else(|| error("Invalid PR search response"))?;
    let pr = if let Some(pr) = list.first() {
        pr.clone()
    } else {
        api.object(Method::POST,&target.repository,&["pulls"],Some(json!({"head":target.branch,"base":base,"title":title.trim(),"body":body,"draft":true})))?
    };
    let number = pr
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(|| error("Invalid PR response"))?;
    let url = format!("https://github.com/{}/pull/{number}", target.repository);
    let actual_url = pr
        .get("html_url")
        .and_then(Value::as_str)
        .ok_or_else(|| error("Missing PR URL"))?;
    let same_repo = |pointer: &str| {
        pr.pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(&target.repository))
    };
    if !actual_url.eq_ignore_ascii_case(&url)
        || !same_repo("/head/repo/full_name")
        || !same_repo("/base/repo/full_name")
        || pr.get("draft").and_then(Value::as_bool) != Some(true)
        || pr.get("state").and_then(Value::as_str) != Some("open")
        || pr.pointer("/head/sha").and_then(Value::as_str) != Some(&target.commit)
        || pr.pointer("/head/ref").and_then(Value::as_str) != Some(&target.branch)
        || pr.pointer("/base/ref").and_then(Value::as_str) != Some(base)
    {
        return Err(error("PR response does not match the reviewed repository, branch and commit; verify remote state"));
    }
    Ok(actual_url.to_string())
}

#[cfg(test)]
mod tests;
