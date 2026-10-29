use codetwin_core::{review_git_file, review_git_status};
use std::{fs, path::Path, process::Command};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    git(dir.path(), &["config", "user.name", "Fixture"]);
    git(
        dir.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    dir
}

#[test]
fn real_git_separates_staged_and_worktree_and_does_not_modify_index() {
    let dir = repository();
    let root = dir.path();
    fs::write(root.join("file.ts"), "original\n").unwrap();
    git(root, &["add", "file.ts"]);
    git(root, &["commit", "-m", "Initial"]);
    fs::write(root.join("file.ts"), "staged\n").unwrap();
    git(root, &["add", "file.ts"]);
    fs::write(root.join("file.ts"), "worktree\n").unwrap();
    // A wildcard-looking filename must be a literal pathspec, never all matching files.
    fs::write(root.join("[ab].ts"), "literal\n").unwrap();
    git(root, &["--literal-pathspecs", "add", "[ab].ts"]);
    let before = fs::read(root.join(".git/index")).unwrap();
    let head = git(root, &["rev-parse", "HEAD"]);
    let status = review_git_status(root).unwrap();
    assert_eq!(status.branch.as_deref(), Some("main"));
    assert_eq!(status.head.as_deref(), Some(head.trim()));
    let change = status
        .changes
        .iter()
        .find(|change| change.path == "file.ts")
        .unwrap();
    assert_eq!((&*change.staged, &*change.unstaged), ("M", "M"));
    let review = review_git_file(root, "file.ts").unwrap();
    assert!(review.staged_diff.contains("+staged"));
    assert!(review.unstaged_diff.contains("+worktree"));
    let literal = review_git_file(root, "[ab].ts").unwrap();
    assert!(literal.staged_diff.contains("+literal"));
    assert!(!literal.staged_diff.contains("worktree"));
    assert_eq!(before, fs::read(root.join(".git/index")).unwrap());
    assert_eq!(head, git(root, &["rev-parse", "HEAD"]));
    assert!(review_git_file(root, "../outside").is_err());
}

#[test]
fn unborn_untracked_binary_oversized_rename_and_detached_are_honest() {
    let dir = repository();
    let root = dir.path();
    fs::write(root.join("new space.ts"), "export const a = 1;\n").unwrap();
    fs::write(root.join("binary.bin"), [0, 1, 2]).unwrap();
    fs::write(root.join("big.txt"), vec![b'a'; 256 * 1024 + 1]).unwrap();
    assert!(review_git_status(root).unwrap().head.is_none());
    assert!(review_git_file(root, "new space.ts")
        .unwrap()
        .untracked_content
        .unwrap()
        .contains("export const"));
    assert!(review_git_file(root, "binary.bin")
        .unwrap()
        .notice
        .is_some());
    assert!(review_git_file(root, "big.txt").unwrap().notice.is_some());
    git(root, &["add", "new space.ts"]);
    git(root, &["commit", "-m", "Initial"]);
    git(root, &["mv", "new space.ts", "renamed space.ts"]);
    let status = review_git_status(root).unwrap();
    let change = status
        .changes
        .iter()
        .find(|change| change.path == "renamed space.ts")
        .unwrap();
    assert_eq!(change.original_path.as_deref(), Some("new space.ts"));
    let patch = review_git_file(root, "renamed space.ts")
        .unwrap()
        .staged_diff;
    assert!(patch.contains("new space.ts") && patch.contains("renamed space.ts"));
    git(root, &["checkout", "--detach"]);
    assert!(review_git_status(root).unwrap().branch.is_none());
    fs::create_dir(root.join("nested")).unwrap();
    assert!(review_git_status(root.join("nested")).is_err());
}

#[test]
fn external_diff_and_textconv_are_never_executed() {
    let dir = repository();
    let root = dir.path();
    fs::write(root.join("file.ts"), "original\n").unwrap();
    git(root, &["add", "file.ts"]);
    git(root, &["commit", "-m", "Initial"]);
    fs::write(root.join("file.ts"), "changed\n").unwrap();
    fs::write(
        root.join(".gitattributes"),
        "*.ts diff=unsafe filter=unsafe\n",
    )
    .unwrap();
    git(
        root,
        &[
            "config",
            "diff.external",
            "nonexistent-unsafe-external-diff",
        ],
    );
    git(
        root,
        &["config", "diff.unsafe.command", "nonexistent-unsafe-driver"],
    );
    git(
        root,
        &[
            "config",
            "diff.unsafe.textconv",
            "nonexistent-unsafe-textconv",
        ],
    );
    git(
        root,
        &["config", "core.fsmonitor", "nonexistent-unsafe-fsmonitor"],
    );
    git(
        root,
        &["config", "filter.unsafe.clean", "nonexistent-unsafe-clean"],
    );
    git(
        root,
        &[
            "config",
            "filter.unsafe.process",
            "nonexistent-unsafe-process",
        ],
    );
    git(root, &["config", "filter.unsafe.required", "true"]);
    let review = review_git_file(root, "file.ts").unwrap();
    assert!(review.unstaged_diff.contains("+changed"));
}

#[cfg(unix)]
#[test]
fn untracked_symlinks_never_reveal_external_content() {
    use std::os::unix::fs::symlink;
    let dir = repository();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("private"), "private-content").unwrap();
    symlink(outside.path().join("private"), dir.path().join("link")).unwrap();
    let review = review_git_file(dir.path(), "link").unwrap();
    assert!(review.untracked_content.is_none());
    assert!(review.notice.is_some());
}
