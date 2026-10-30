use codetwin_core::{create_reviewed_git_branch, review_git_status};
use std::{fs, path::Path, process::Command, sync::Arc};

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
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-b", "main"]);
    git(dir.path(), &["config", "user.name", "Fixture"]);
    git(
        dir.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    fs::write(dir.path().join("file.txt"), "original\n").unwrap();
    git(dir.path(), &["add", "file.txt"]);
    git(dir.path(), &["commit", "-m", "Initial"]);
    dir
}

#[test]
fn creates_reviewed_branch_without_switching_or_touching_index_and_worktree() {
    let dir = fixture();
    let root = dir.path();
    fs::write(root.join("file.txt"), "staged\n").unwrap();
    git(root, &["add", "file.txt"]);
    fs::write(root.join("file.txt"), "unstaged\n").unwrap();
    let index = fs::read(root.join(".git/index")).unwrap();
    let head = git(root, &["rev-parse", "HEAD"]);
    let receipt = create_reviewed_git_branch(root, "feature/review", &head).unwrap();
    assert_eq!(receipt.branch, "feature/review");
    assert_eq!(receipt.head, head);
    assert_eq!(git(root, &["rev-parse", "refs/heads/feature/review"]), head);
    assert_eq!(git(root, &["symbolic-ref", "--short", "HEAD"]), "main");
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
    assert_eq!(
        fs::read_to_string(root.join("file.txt")).unwrap(),
        "unstaged\n"
    );
    let change = review_git_status(root).unwrap().changes.remove(0);
    assert_eq!(
        (change.staged.as_str(), change.unstaged.as_str()),
        ("M", "M")
    );
}

#[test]
fn stale_head_existing_branch_and_malformed_input_do_not_write_refs() {
    let dir = fixture();
    let root = dir.path();
    let old = git(root, &["rev-parse", "HEAD"]);
    git(root, &["commit", "--allow-empty", "-m", "Advance"]);
    assert!(create_reviewed_git_branch(root, "feature/stale", &old).is_err());
    let head = git(root, &["rev-parse", "HEAD"]);
    for branch in [
        "main",
        "../outside",
        "-bad",
        "a..b",
        "a.lock",
        "a//b",
        "feature\ncreate refs/heads/injected",
        "a b",
        "",
    ] {
        assert!(
            create_reviewed_git_branch(root, branch, &head).is_err(),
            "{branch}"
        );
    }
    assert!(create_reviewed_git_branch(root, "valid", "bad\nprepare").is_err());
    assert_eq!(
        git(root, &["for-each-ref", "--format=%(refname)"]),
        "refs/heads/main"
    );
    git(root, &["checkout", "--detach"]);
    assert!(create_reviewed_git_branch(root, "detached", &head).is_err());
}

#[test]
fn concurrent_creation_has_exactly_one_success_and_never_overwrites() {
    let dir = Arc::new(fixture());
    let head = git(dir.path(), &["rev-parse", "HEAD"]);
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let dir = Arc::clone(&dir);
            let head = head.clone();
            std::thread::spawn(move || {
                create_reviewed_git_branch(dir.path(), "feature/race", &head).is_ok()
            })
        })
        .collect();
    let count = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().unwrap()))
        .sum::<usize>();
    assert_eq!(count, 1);
    assert_eq!(
        git(dir.path(), &["rev-parse", "refs/heads/feature/race"]),
        head
    );
}

#[test]
fn reference_transaction_hook_cannot_execute() {
    let dir = fixture();
    let root = dir.path();
    let head = git(root, &["rev-parse", "HEAD"]);
    let hook = root.join(".git/hooks/reference-transaction");
    fs::write(&hook, "#!/bin/sh\necho executed > hook-executed\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }
    create_reviewed_git_branch(root, "feature/no-hooks", &head).unwrap();
    assert!(!root.join("hook-executed").exists());
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/feature/no-hooks"]),
        head
    );
}
