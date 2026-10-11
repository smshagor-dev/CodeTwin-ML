//! Explicit staged snapshots. The real Git index is never written.
use crate::git_review::{
    controlled_git_with_env, error, repository_root, required, GitReviewError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitCommitRequest {
    pub branch: String,
    pub head: String,
    pub paths: Vec<String>,
    pub name: String,
    pub email: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct GitCommitPreview {
    pub request: GitCommitRequest,
    pub paths: Vec<String>,
    pub tree: String,
    pub patch: String,
    pub digest: String,
}

#[derive(Debug, Serialize)]
pub struct GitCommitReceipt {
    pub branch: String,
    pub parent: String,
    pub commit: String,
}

fn run(
    root: &Path,
    args: &[&str],
    environment: &[(String, String)],
    input: Option<Vec<u8>>,
) -> Result<Vec<u8>, GitReviewError> {
    Ok(controlled_git_with_env(root, args, false, input, environment)?.expect("required result"))
}

fn utf8(bytes: Vec<u8>) -> Result<String, GitReviewError> {
    String::from_utf8(bytes).map_err(|_| error("Selected commits require UTF-8 paths and text"))
}

fn identity(request: &GitCommitRequest) -> Result<(), GitReviewError> {
    if request.name.trim().is_empty()
        || request.name.len() > 100
        || request
            .name
            .chars()
            .any(|c| c.is_control() || "<>".contains(c))
    {
        return Err(error(
            "Enter an author name without control characters or angle brackets",
        ));
    }
    if request.email.len() > 254
        || !request.email.contains('@')
        || request
            .email
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>".contains(c))
    {
        return Err(error(
            "Enter an author email without whitespace or angle brackets",
        ));
    }
    if request.message.trim().is_empty()
        || request.message.len() > 4096
        || request
            .message
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(error("Enter a commit message of at most 4096 bytes"));
    }
    if request.paths.is_empty()
        || request.paths.len() > 50
        || request
            .paths
            .iter()
            .any(|p| p.is_empty() || p.contains('\0'))
    {
        return Err(error("Select 1–50 staged paths"));
    }
    Ok(())
}

fn idle(root: &Path) -> Result<(), GitReviewError> {
    for marker in [
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "rebase-merge",
        "rebase-apply",
        "sequencer",
    ] {
        let path = required(root, &["rev-parse", "--git-path", marker])?;
        if root.join(path.trim_end()).exists() {
            return Err(error(
                "Finish the merge, rebase, cherry-pick or revert externally before committing",
            ));
        }
    }
    if !required(root, &["ls-files", "--unmerged"])?.is_empty() {
        return Err(error("Resolve staged conflicts before committing"));
    }
    Ok(())
}

fn current(root: &Path, request: &GitCommitRequest) -> Result<(), GitReviewError> {
    let branch = required(root, &["symbolic-ref", "--quiet", "HEAD"])?;
    let head = required(root, &["rev-parse", "--verify", "HEAD"])?;
    if branch.trim_end() != format!("refs/heads/{}", request.branch)
        || head.trim_end() != request.head
    {
        return Err(error(
            "Branch or HEAD changed since review. Refresh Git changes.",
        ));
    }
    Ok(())
}

fn index(root: &Path) -> Result<Vec<u8>, GitReviewError> {
    run(root, &["ls-files", "--stage", "-z"], &[], None)
}

fn text_blob(root: &Path, oid: &str, total: &mut usize) -> Result<(), GitReviewError> {
    let bytes = run(root, &["cat-file", "blob", oid], &[], None)?;
    *total += bytes.len();
    if bytes.len() > 256 * 1024
        || *total > 2 * 1024 * 1024
        || bytes.contains(&0)
        || std::str::from_utf8(&bytes).is_err()
    {
        return Err(error("Selected commits support UTF-8 text up to 256 KiB per blob and 2 MiB combined old/new content"));
    }
    Ok(())
}

fn prepare(
    root: &Path,
    request: &GitCommitRequest,
) -> Result<(GitCommitPreview, Vec<u8>), GitReviewError> {
    identity(request)?;
    let mut canonical = request.clone();
    canonical.name = canonical.name.trim().to_string();
    canonical.message = canonical.message.trim().to_string();
    let request = &canonical;
    idle(root)?;
    current(root, request)?;
    let status = crate::review_git_status(root)?;
    let before = index(root)?;
    let mut entries = BTreeMap::new();
    for record in utf8(before.clone())?
        .split('\0')
        .filter(|entry| !entry.is_empty())
    {
        let (metadata, path) = record
            .split_once('\t')
            .ok_or_else(|| error("Malformed Git index"))?;
        let parts: Vec<_> = metadata.split(' ').collect();
        if parts.len() != 3 || parts[2] != "0" {
            return Err(error("Unmerged or malformed Git index"));
        }
        entries.insert(
            path.to_string(),
            (parts[0].to_string(), parts[1].to_string()),
        );
    }
    let mut paths = BTreeSet::new();
    for path in &request.paths {
        let change = status
            .changes
            .iter()
            .find(|change| &change.path == path)
            .filter(|change| change.staged != " " && change.staged != "?")
            .ok_or_else(|| error("Only currently staged changes can be selected"))?;
        if !paths.insert(path.clone()) {
            return Err(error("Duplicate selected path"));
        }
        if change.staged == "R" {
            if let Some(original) = &change.original_path {
                paths.insert(original.clone());
            }
        }
    }
    if paths.len() > 50 {
        return Err(error("Renamed paths expand beyond the 50-path limit"));
    }
    let scratch = tempfile::tempdir().map_err(error)?;
    let env = vec![(
        "GIT_INDEX_FILE".to_string(),
        scratch
            .path()
            .join("index")
            .to_str()
            .ok_or_else(|| error("Temporary index path is not UTF-8"))?
            .to_string(),
    )];
    run(root, &["read-tree", &request.head], &env, None)?;
    let mut records = Vec::new();
    let mut total = 0;
    for path in &paths {
        let old = utf8(run(
            root,
            &["ls-tree", "-z", &request.head, "--", path],
            &[],
            None,
        )?)?;
        if !old.is_empty() {
            let (metadata, actual) = old
                .trim_end_matches('\0')
                .split_once('\t')
                .ok_or_else(|| error("Malformed Git tree"))?;
            let parts: Vec<_> = metadata.split(' ').collect();
            if actual != path || parts.len() != 3 || !["100644", "100755"].contains(&parts[0]) {
                return Err(error(
                    "Selected symlinks, submodules and directories are not supported",
                ));
            }
            text_blob(root, parts[2], &mut total)?;
        }
        match entries.get(path) {
            Some((mode, oid)) => {
                if !["100644", "100755"].contains(&mode.as_str()) {
                    return Err(error("Selected symlinks and submodules are not supported"));
                }
                text_blob(root, oid, &mut total)?;
                records.extend_from_slice(format!("{mode} {oid}\t{path}\0").as_bytes());
            }
            None => records.extend_from_slice(
                format!("0 {}\t{path}\0", "0".repeat(request.head.len())).as_bytes(),
            ),
        }
    }
    run(
        root,
        &["update-index", "-z", "--index-info"],
        &env,
        Some(records),
    )?;
    let tree = utf8(run(root, &["write-tree"], &env, None)?)?
        .trim_end()
        .to_string();
    let patch = utf8(run(
        root,
        &[
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--no-relative",
            &request.head,
        ],
        &env,
        None,
    )?)?;
    if patch.is_empty() {
        return Err(error("The selected staged snapshot has no changes"));
    }
    current(root, request)?;
    if index(root)? != before {
        return Err(error(
            "Staging changed during review. Prepare a fresh preview.",
        ));
    }
    let paths: Vec<_> = paths.into_iter().collect();
    // Bind the displayed patch, complete logical index, identity, message, repository
    // and resulting tree. Apply recomputes all of this; supplied tree/patch are never trusted.
    let payload = serde_json::to_vec(&(root.to_str(), request, &paths, &tree, &patch, &before))
        .map_err(error)?;
    let digest = format!("{:x}", Sha256::digest(payload));
    Ok((
        GitCommitPreview {
            request: request.clone(),
            paths,
            tree,
            patch,
            digest,
        },
        before,
    ))
}

pub fn prepare_selected_commit(
    root: impl AsRef<Path>,
    request: &GitCommitRequest,
) -> Result<GitCommitPreview, GitReviewError> {
    let root = repository_root(root.as_ref())?;
    Ok(prepare(&root, request)?.0)
}

pub fn apply_selected_commit(
    root: impl AsRef<Path>,
    request: &GitCommitRequest,
    expected_digest: &str,
) -> Result<GitCommitReceipt, GitReviewError> {
    let root = repository_root(root.as_ref())?;
    let (preview, before) = prepare(&root, request)?;
    if expected_digest.len() != 64 || preview.digest != expected_digest {
        return Err(error(
            "Commit review is stale or changed. Prepare and review the selected snapshot again.",
        ));
    }
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error)?
        .as_secs();
    let mut env = Vec::new();
    for prefix in ["GIT_AUTHOR", "GIT_COMMITTER"] {
        env.push((format!("{prefix}_NAME"), preview.request.name.clone()));
        env.push((format!("{prefix}_EMAIL"), preview.request.email.clone()));
        env.push((format!("{prefix}_DATE"), format!("{seconds} +0000")));
    }
    let commit = utf8(run(
        &root,
        &[
            "commit-tree",
            "--no-gpg-sign",
            &preview.tree,
            "-p",
            &request.head,
        ],
        &env,
        Some(format!("{}\n", preview.request.message.trim()).into_bytes()),
    )?)?
    .trim_end()
    .to_string();
    idle(&root)?;
    current(&root, request)?;
    if index(&root)? != before {
        return Err(error(
            "Staging changed before commit. Prepare a fresh preview.",
        ));
    }
    // Explicitly update the reviewed branch, never retarget HEAD. Git's old-OID
    // compare-and-swap rejects concurrent commits; no real index write occurs.
    run(
        &root,
        &[
            "update-ref",
            "-m",
            "CodeTwin reviewed staged commit",
            &format!("refs/heads/{}", request.branch),
            &commit,
            &request.head,
        ],
        &[],
        None,
    )?;
    Ok(GitCommitReceipt {
        branch: request.branch.clone(),
        parent: request.head.clone(),
        commit,
    })
}
