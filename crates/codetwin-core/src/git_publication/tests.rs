use super::*;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

fn git(root: &Path, args: &[&str], input: Option<Vec<u8>>, env: &[(String, String)]) -> String {
    let value = controlled_git_with_env(root, args, false, input, env)
        .unwrap()
        .unwrap();
    String::from_utf8(value).unwrap().trim_end().to_string()
}
fn fixture() -> (tempfile::TempDir, GitPublishTarget) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-b", "main"], None, &[]);
    git(root, &["config", "user.name", "Fixture"], None, &[]);
    git(
        root,
        &["config", "user.email", "fixture@example.invalid"],
        None,
        &[],
    );
    fs::write(root.join("selected.txt"), "original\n").unwrap();
    fs::write(root.join("unrelated.txt"), "original\n").unwrap();
    git(root, &["add", "."], None, &[]);
    git(root, &["commit", "-m", "Initial"], None, &[]);
    git(root, &["switch", "-c", "feature/publish"], None, &[]);
    fs::write(root.join("selected.txt"), "selected\nবাংলা\n").unwrap();
    git(root, &["add", "selected.txt"], None, &[]);
    let request = crate::GitCommitRequest {
        branch: "feature/publish".into(),
        head: git(root, &["rev-parse", "HEAD"], None, &[]),
        paths: vec!["selected.txt".into()],
        name: "Fixture Author".into(),
        email: "author@example.invalid".into(),
        message: "Reviewed commit\n\nBody".into(),
    };
    let preview = crate::prepare_selected_commit(root, &request).unwrap();
    let commit = crate::apply_selected_commit(root, &request, &preview.digest)
        .unwrap()
        .commit;
    (
        dir,
        GitPublishTarget {
            repository: "fixture/repo".into(),
            branch: "feature/publish".into(),
            commit,
        },
    )
}
#[derive(Default)]
struct State {
    remote: Option<String>,
    auth_fail: bool,
    wrong_hash: bool,
    default_target: bool,
    writes: usize,
    prs: usize,
    requests: usize,
    pr: Option<Value>,
}
struct Server {
    api: Api,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    _root: tempfile::TempDir,
}
impl Server {
    fn new(client: &Path) -> Self {
        let root = tempfile::tempdir().unwrap();
        // Real independent object database; every uploaded object is reconstructed
        // with Git plumbing from the REST payload, rather than echoing expected SHAs.
        let cloned = std::process::Command::new("git")
            .arg("-C")
            .arg(root.path())
            .args(["clone", "--no-hardlinks", "--"])
            .arg(client)
            .arg(".")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .output()
            .unwrap();
        assert!(
            cloned.status.success(),
            "{}",
            String::from_utf8_lossy(&cloned.stderr)
        );
        let parent = git(client, &["rev-parse", "HEAD^"], None, &[]);
        git(root.path(), &["switch", "-C", "main", &parent], None, &[]);
        git(root.path(), &["branch", "-D", "feature/publish"], None, &[]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut api = Api::new("fixture-token-only").unwrap();
        api.endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&state);
        let ended = Arc::clone(&stop);
        let path = root.path().to_path_buf();
        let worker = thread::spawn(move || {
            while !ended.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0; 8192];
                let (end, length) = loop {
                    let n = match stream.read(&mut buf) {
                        Ok(0) if bytes.is_empty() => break (0, 0),
                        Ok(n) => n,
                        Err(cause)
                            if bytes.is_empty()
                                && matches!(
                                    cause.kind(),
                                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                                ) =>
                        {
                            break (0, 0)
                        }
                        Err(cause) => panic!("Fixture request read failed: {cause}"),
                    };
                    assert!(n > 0, "Incomplete fixture request");
                    bytes.extend_from_slice(&buf[..n]);
                    assert!(bytes.len() < 3 * 1024 * 1024);
                    if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|n| n.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            break (end, length);
                        }
                    }
                };
                if end == 0 {
                    continue;
                }
                let headers = String::from_utf8_lossy(&bytes[..end]);
                assert!(headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer fixture-token-only"));
                let first = headers.lines().next().unwrap();
                let mut parts = first.split(' ');
                let method = parts.next().unwrap();
                let route = parts
                    .next()
                    .unwrap()
                    .split('?')
                    .next()
                    .unwrap()
                    .replace("%2F", "/");
                let body = if length > 0 {
                    serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap()
                } else {
                    Value::Null
                };
                let (status, value) = handle(&path, &shared, method, &route, &body);
                let body = value.to_string();
                write!(stream,"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        Self {
            api,
            state,
            stop,
            worker: Some(worker),
            _root: root,
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            // Preserve the original test failure instead of aborting from a
            // second panic while unwinding through fixture cleanup.
            if !thread::panicking() {
                assert!(result.is_ok(), "Fixture HTTP worker failed");
            }
        }
    }
}
fn handle(
    root: &Path,
    state: &Mutex<State>,
    method: &str,
    route: &str,
    body: &Value,
) -> (u16, Value) {
    let mut state = state.lock().unwrap();
    state.requests += 1;
    if state.auth_fail {
        return (
            401,
            json!({"message":"fixture-token-only must never appear in errors"}),
        );
    }
    let prefix = "/repos/fixture/repo";
    let path = route.strip_prefix(prefix).unwrap();
    if method == "GET" && path.is_empty() {
        return (
            200,
            json!({"default_branch":if state.default_target {"feature/publish"}else{"main"},"permissions":{"push":true}}),
        );
    }
    if method == "GET" && path == "/git/ref/heads/feature/publish" {
        return match &state.remote {
            Some(sha) => (200, json!({"object":{"sha":sha}})),
            None => (404, json!({})),
        };
    }
    if method == "GET" && path == "/git/ref/heads/main" {
        return (
            200,
            json!({"object":{"sha":git(root,&["rev-parse","main"],None,&[])}}),
        );
    }
    if method == "GET" && path.starts_with("/git/commits/") {
        let sha = path.trim_start_matches("/git/commits/");
        let tree = git(root, &["rev-parse", &format!("{sha}^{{tree}}")], None, &[]);
        return (200, json!({"sha":sha,"tree":{"sha":tree}}));
    }
    if method == "POST" && path == "/git/blobs" {
        assert_eq!(body["encoding"], "utf-8");
        let sha = git(
            root,
            &["hash-object", "-w", "--stdin"],
            Some(body["content"].as_str().unwrap().as_bytes().to_vec()),
            &[],
        );
        return (
            201,
            json!({"sha":if state.wrong_hash {"f".repeat(40)}else{sha}}),
        );
    }
    if method == "POST" && path == "/git/trees" {
        let temp = tempfile::tempdir().unwrap();
        let env = vec![(
            "GIT_INDEX_FILE".into(),
            temp.path().join("index").to_str().unwrap().into(),
        )];
        git(
            root,
            &["read-tree", body["base_tree"].as_str().unwrap()],
            None,
            &env,
        );
        let mut records = Vec::new();
        for entry in body["tree"].as_array().unwrap() {
            let mode = if entry["sha"].is_null() {
                "0"
            } else {
                entry["mode"].as_str().unwrap()
            };
            let sha = entry["sha"]
                .as_str()
                .unwrap_or("0000000000000000000000000000000000000000");
            records.extend_from_slice(
                format!("{mode} {sha}\t{}\0", entry["path"].as_str().unwrap()).as_bytes(),
            );
        }
        git(
            root,
            &["update-index", "-z", "--index-info"],
            Some(records),
            &env,
        );
        return (201, json!({"sha":git(root,&["write-tree"],None,&env)}));
    }
    if method == "POST" && path == "/git/commits" {
        let mut env = Vec::new();
        for (prefix, field) in [("GIT_AUTHOR", "author"), ("GIT_COMMITTER", "committer")] {
            for (key, json_key) in [("NAME", "name"), ("EMAIL", "email"), ("DATE", "date")] {
                env.push((
                    format!("{prefix}_{key}"),
                    body[field][json_key].as_str().unwrap().into(),
                ));
            }
        }
        let sha = git(
            root,
            &[
                "commit-tree",
                "--no-gpg-sign",
                body["tree"].as_str().unwrap(),
                "-p",
                body["parents"][0].as_str().unwrap(),
            ],
            Some(body["message"].as_str().unwrap().as_bytes().to_vec()),
            &env,
        );
        return (201, json!({"sha":sha}));
    }
    if (method == "POST" && path == "/git/refs")
        || (method == "PATCH" && path == "/git/refs/heads/feature/publish")
    {
        if method == "PATCH" {
            assert_eq!(body["force"], false);
        } else {
            assert_eq!(body["ref"], "refs/heads/feature/publish");
        }
        let sha = body["sha"].as_str().unwrap();
        git(
            root,
            &["update-ref", "refs/heads/feature/publish", sha],
            None,
            &[],
        );
        state.remote = Some(sha.into());
        state.writes += 1;
        return (200, json!({"object":{"sha":sha}}));
    }
    if method == "GET" && path == "/pulls" {
        return (200, json!(state.pr.clone().into_iter().collect::<Vec<_>>()));
    }
    if method == "POST" && path == "/pulls" {
        assert_eq!(body["draft"], true);
        state.prs += 1;
        let pr = json!({"number":1,"html_url":"https://github.com/fixture/repo/pull/1","draft":true,"state":"open","head":{"sha":state.remote,"ref":body["head"],"repo":{"full_name":"fixture/repo"}},"base":{"ref":body["base"],"repo":{"full_name":"fixture/repo"}}});
        state.pr = Some(pr.clone());
        return (201, pr);
    }
    panic!("Unexpected fixture request {method} {route}");
}

#[test]
fn real_git_objects_publish_exactly_once_and_draft_pr_is_separate_and_idempotent() {
    let (dir, target) = fixture();
    let server = Server::new(dir.path());
    let index = fs::read(dir.path().join(".git/index")).unwrap();
    let receipt = publish_with(dir.path(), &target, &server.api).unwrap();
    assert_eq!(receipt.commit, target.commit);
    assert_eq!(server.state.lock().unwrap().writes, 1);
    assert_eq!(server.state.lock().unwrap().prs, 0);
    publish_with(dir.path(), &target, &server.api).unwrap();
    assert_eq!(server.state.lock().unwrap().writes, 1);
    let url = open_pr_with(
        dir.path(),
        &target,
        "main",
        "Reviewed PR",
        "Body",
        &server.api,
    )
    .unwrap();
    assert_eq!(url, "https://github.com/fixture/repo/pull/1");
    open_pr_with(
        dir.path(),
        &target,
        "main",
        "Reviewed PR",
        "Body",
        &server.api,
    )
    .unwrap();
    assert_eq!(server.state.lock().unwrap().prs, 1);
    assert_eq!(fs::read(dir.path().join(".git/index")).unwrap(), index);
    assert_eq!(
        git(dir.path(), &["rev-parse", "HEAD"], None, &[]),
        target.commit
    );
}
#[test]
fn authentication_default_branch_divergence_and_hash_mismatch_never_update_refs() {
    let (dir, target) = fixture();
    for mode in ["auth", "default", "diverged", "hash"] {
        let server = Server::new(dir.path());
        {
            let mut state = server.state.lock().unwrap();
            match mode {
                "auth" => state.auth_fail = true,
                "default" => state.default_target = true,
                "diverged" => state.remote = Some("0".repeat(40)),
                "hash" => state.wrong_hash = true,
                _ => unreachable!(),
            }
        }
        let cause = publish_with(dir.path(), &target, &server.api)
            .unwrap_err()
            .to_string();
        assert!(!cause.contains("fixture-token-only"));
        let expected = match mode {
            "auth" => "HTTP 401",
            "default" => "non-default",
            "diverged" => "diverged",
            "hash" => "hash differs",
            _ => unreachable!(),
        };
        assert!(cause.contains(expected), "{mode}: {cause}");
        assert!(server.state.lock().unwrap().requests > 0);
        assert_eq!(server.state.lock().unwrap().writes, 0);
    }
}
#[test]
fn stale_local_target_and_unpublished_or_foreign_pr_are_rejected() {
    let (dir, mut target) = fixture();
    let server = Server::new(dir.path());
    assert!(open_pr_with(dir.path(), &target, "main", "Title", "Body", &server.api).is_err());
    let commit = target.commit.clone();
    target.commit = git(dir.path(), &["rev-parse", "HEAD^"], None, &[]);
    let count = server.state.lock().unwrap().requests;
    assert!(publish_with(dir.path(), &target, &server.api).is_err());
    assert_eq!(server.state.lock().unwrap().requests, count);
    target.commit = commit;
    publish_with(dir.path(), &target, &server.api).unwrap();
    open_pr_with(dir.path(), &target, "main", "Title", "Body", &server.api).unwrap();
    server.state.lock().unwrap().pr.as_mut().unwrap()["head"]["repo"]["full_name"] =
        json!("fixture/foreign");
    assert!(open_pr_with(dir.path(), &target, "main", "Title", "Body", &server.api).is_err());
    assert_eq!(server.state.lock().unwrap().prs, 1);
}

#[test]
fn existing_parent_branch_is_updated_without_force() {
    let (dir, target) = fixture();
    let server = Server::new(dir.path());
    let parent = git(dir.path(), &["rev-parse", "HEAD^"], None, &[]);
    git(
        server._root.path(),
        &["update-ref", "refs/heads/feature/publish", &parent],
        None,
        &[],
    );
    server.state.lock().unwrap().remote = Some(parent);
    publish_with(dir.path(), &target, &server.api).unwrap();
    assert_eq!(server.state.lock().unwrap().writes, 1);
    assert_eq!(
        git(
            server._root.path(),
            &["rev-parse", "refs/heads/feature/publish"],
            None,
            &[]
        ),
        target.commit
    );
}
