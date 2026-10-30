use codetwin_core::{
    apply_selected_commit, prepare_selected_commit, review_git_status, GitCommitRequest,
};
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
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-b", "main"]);
    git(root, &["config", "user.name", "Fixture"]);
    git(root, &["config", "user.email", "fixture@example.invalid"]);
    for file in ["a.txt", "b.txt", "delete.txt", "rename.txt"] {
        fs::write(root.join(file), format!("initial {file}\n")).unwrap();
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-m", "Initial"]);
    dir
}
fn request(root: &Path, paths: &[&str]) -> GitCommitRequest {
    GitCommitRequest {
        branch: "main".into(),
        head: git(root, &["rev-parse", "HEAD"]),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        name: "Reviewed Author".into(),
        email: "author@example.invalid".into(),
        message: "Selected change\n\nReviewed snapshot".into(),
    }
}
fn stage(root: &Path, path: &str, value: &str) {
    fs::write(root.join(path), value).unwrap();
    git(root, &["--literal-pathspecs", "add", "--", path]);
}

#[test]
fn selected_staged_commit_preserves_unrelated_index_and_unstaged_edits() {
    let dir = fixture();
    let root = dir.path();
    stage(root, "a.txt", "selected staged\n");
    stage(root, "b.txt", "unrelated staged\n");
    fs::write(root.join("a.txt"), "selected unstaged\n").unwrap();
    let index = fs::read(root.join(".git/index")).unwrap();
    let mut request = request(root, &["a.txt"]);
    request.name = format!("  {}  ", request.name);
    request.message = format!(" \n{} \n", request.message);
    let preview = prepare_selected_commit(root, &request).unwrap();
    assert_eq!(preview.request.name, "Reviewed Author");
    assert_eq!(preview.request.message, request.message.trim());
    assert!(preview.patch.contains("+selected staged"));
    assert!(!preview.patch.contains("unrelated staged"));
    assert!(!preview.patch.contains("selected unstaged"));
    assert_eq!(git(root, &["rev-parse", "HEAD"]), request.head);
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
    let receipt = apply_selected_commit(root, &request, &preview.digest).unwrap();
    assert_eq!(git(root, &["rev-parse", "HEAD"]), receipt.commit);
    assert_eq!(git(root, &["show", "HEAD:a.txt"]), "selected staged");
    assert_eq!(git(root, &["show", "HEAD:b.txt"]), "initial b.txt");
    assert_eq!(
        git(root, &["show", "-s", "--format=%an <%ae>", "HEAD"]),
        "Reviewed Author <author@example.invalid>"
    );
    assert_eq!(
        git(root, &["show", "-s", "--format=%B", "HEAD"]),
        request.message.trim()
    );
    assert_eq!(git(root, &["rev-parse", "HEAD^"]), request.head);
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
    assert_eq!(
        fs::read_to_string(root.join("a.txt")).unwrap(),
        "selected unstaged\n"
    );
    let status = review_git_status(root).unwrap();
    assert_eq!(
        status
            .changes
            .iter()
            .find(|c| c.path == "a.txt")
            .unwrap()
            .staged,
        " "
    );
    assert_eq!(
        status
            .changes
            .iter()
            .find(|c| c.path == "b.txt")
            .unwrap()
            .staged,
        "M"
    );
    assert!(apply_selected_commit(root, &request, &preview.digest).is_err());
}

#[test]
fn staging_author_message_head_and_branch_changes_invalidate_review() {
    for change in [
        "selected",
        "unrelated",
        "author",
        "message",
        "head",
        "branch",
        "digest",
    ] {
        let dir = fixture();
        let root = dir.path();
        stage(root, "a.txt", "selected\n");
        let mut request = request(root, &["a.txt"]);
        let preview = prepare_selected_commit(root, &request).unwrap();
        let mut digest = preview.digest;
        match change {
            "selected" => stage(root, "a.txt", "changed\n"),
            "unrelated" => stage(root, "b.txt", "unrelated\n"),
            "author" => request.name = "Other Author".into(),
            "message" => request.message = "Other message".into(),
            "head" => {
                git(root, &["commit", "--allow-empty", "-m", "Advance"]);
            }
            "branch" => {
                git(root, &["switch", "-c", "other"]);
            }
            "digest" => digest = "0".repeat(64),
            _ => unreachable!(),
        }
        let head = git(root, &["rev-parse", "HEAD"]);
        let index = fs::read(root.join(".git/index")).unwrap();
        assert!(
            apply_selected_commit(root, &request, &digest).is_err(),
            "{change}"
        );
        assert_eq!(git(root, &["rev-parse", "HEAD"]), head);
        assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
    }
}

#[test]
fn literal_filenames_deletions_and_rename_original_are_exact() {
    let dir = fixture();
    let root = dir.path();
    stage(root, "[ab].txt", "literal\n");
    git(root, &["rm", "delete.txt"]);
    git(root, &["mv", "rename.txt", "renamed space.txt"]);
    let request = request(root, &["[ab].txt", "delete.txt", "renamed space.txt"]);
    let preview = prepare_selected_commit(root, &request).unwrap();
    assert!(preview.paths.contains(&"rename.txt".into()));
    apply_selected_commit(root, &request, &preview.digest).unwrap();
    assert_eq!(git(root, &["show", "HEAD:[ab].txt"]), "literal");
    assert_eq!(
        git(root, &["show", "HEAD:renamed space.txt"]),
        "initial rename.txt"
    );
    let tree = git(root, &["ls-tree", "--name-only", "HEAD"]);
    assert!(!tree.lines().any(|p| p == "delete.txt" || p == "rename.txt"));
}

#[test]
fn rejects_unstaged_binary_conflicts_operation_markers_and_invalid_identity() {
    let dir = fixture();
    let root = dir.path();
    fs::write(root.join("a.txt"), "unstaged\n").unwrap();
    assert!(prepare_selected_commit(root, &request(root, &["a.txt"])).is_err());
    stage(root, "a.txt", "valid\n");
    for marker in ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD"] {
        fs::write(root.join(".git").join(marker), "test").unwrap();
        assert!(prepare_selected_commit(root, &request(root, &["a.txt"])).is_err());
        fs::remove_file(root.join(".git").join(marker)).unwrap();
    }
    let mut req = request(root, &["a.txt"]);
    req.email = "author@example.invalid\nInjected".into();
    assert!(prepare_selected_commit(root, &req).is_err());
    fs::write(root.join("binary.bin"), [0, 1]).unwrap();
    git(root, &["add", "binary.bin"]);
    assert!(prepare_selected_commit(root, &request(root, &["binary.bin"])).is_err());
}

#[test]
fn hooks_signing_fsmonitor_and_clean_filters_never_execute() {
    let dir = fixture();
    let root = dir.path();
    stage(root, "a.txt", "selected\n");
    let helper = root.join(".git/hooks/reference-transaction");
    fs::write(
        &helper,
        "#!/bin/sh\necho executed > helper-executed\nexit 1\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    }
    git(root, &["config", "commit.gpgSign", "true"]);
    git(
        root,
        &["config", "gpg.program", "missing-codetwin-fixture-program"],
    );
    git(
        root,
        &[
            "config",
            "core.fsmonitor",
            "missing-codetwin-fixture-program",
        ],
    );
    git(
        root,
        &[
            "config",
            "filter.fixture.clean",
            "echo executed > helper-executed",
        ],
    );
    fs::write(root.join(".gitattributes"), "*.txt filter=fixture -diff\n").unwrap();
    let req = request(root, &["a.txt"]);
    let preview = prepare_selected_commit(root, &req).unwrap();
    assert!(preview.patch.contains("+selected"));
    apply_selected_commit(root, &req, &preview.digest).unwrap();
    assert!(!root.join("helper-executed").exists());
}

#[test]
fn concurrent_commit_has_one_success_and_preserves_real_index() {
    let dir = std::sync::Arc::new(fixture());
    let root = dir.path();
    stage(root, "a.txt", "selected\n");
    let req = request(root, &["a.txt"]);
    let preview = prepare_selected_commit(root, &req).unwrap();
    let index = fs::read(root.join(".git/index")).unwrap();
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let dir = std::sync::Arc::clone(&dir);
            let req = req.clone();
            let digest = preview.digest.clone();
            std::thread::spawn(move || apply_selected_commit(dir.path(), &req, &digest).is_ok())
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
    assert_eq!(git(root, &["rev-parse", "HEAD^"]), req.head);
}

#[test]
fn missing_promisor_objects_fail_without_fetching_or_remote_helpers() {
    let dir = fixture();
    let root = dir.path();
    stage(root, "a.txt", "selected\n");
    let req = request(root, &["a.txt"]);
    let oid = git(root, &["rev-parse", ":a.txt"]);
    fs::remove_file(root.join(".git/objects").join(&oid[..2]).join(&oid[2..])).unwrap();
    git(root, &["config", "extensions.partialClone", "fixture"]);
    git(root, &["config", "remote.fixture.promisor", "true"]);
    git(
        root,
        &[
            "config",
            "remote.fixture.url",
            "ext::sh -c 'echo executed > helper-executed'",
        ],
    );
    git(root, &["config", "protocol.ext.allow", "always"]);
    let cause = prepare_selected_commit(root, &req).unwrap_err().to_string();
    assert!(!cause.contains("fetch-pack"), "{cause}");
    assert!(!root.join("helper-executed").exists());
}

#[test]
fn selecting_a_copy_does_not_commit_its_unselected_modified_source() {
    let dir = fixture();
    let root = dir.path();
    stage(root, "source.txt", "first\nsecond\nthird\n");
    git(root, &["commit", "-m", "Add source"]);
    stage(root, "copy.txt", "first\nsecond\nthird\n");
    stage(root, "source.txt", "changed\nsecond\nthird\n");
    git(root, &["config", "status.renames", "copies"]);
    let status = review_git_status(root).unwrap();
    assert_eq!(
        status
            .changes
            .iter()
            .find(|c| c.path == "copy.txt")
            .unwrap()
            .staged,
        "C"
    );
    let req = request(root, &["copy.txt"]);
    let preview = prepare_selected_commit(root, &req).unwrap();
    assert_eq!(preview.paths, vec!["copy.txt"]);
    let index = fs::read(root.join(".git/index")).unwrap();
    apply_selected_commit(root, &req, &preview.digest).unwrap();
    assert_eq!(
        git(root, &["show", "HEAD:source.txt"]),
        "first\nsecond\nthird"
    );
    assert_eq!(
        git(root, &["show", "HEAD:copy.txt"]),
        "first\nsecond\nthird"
    );
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
    assert_eq!(
        review_git_status(root)
            .unwrap()
            .changes
            .iter()
            .find(|c| c.path == "source.txt")
            .unwrap()
            .staged,
        "M"
    );
}
