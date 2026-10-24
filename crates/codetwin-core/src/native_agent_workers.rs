//! Optional offline security scan in a pinned, isolated Docker worker.
//! The model never controls executable names, arguments, network, mounts or image tags.
use crate::{native_agents::NativeAgents, Database, WorkspaceService};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Read, Seek},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_RUN_SECONDS: u64 = 90;
const MAX_REPORT_BYTES: u64 = 2_000_000;
const MAX_REPORT_RESULTS: usize = 2_000;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Serialize, Deserialize)]
pub struct IsolatedScanReceipt {
    pub run_id: String,
    pub image_digest: String,
    pub report_sha256: String,
    pub vulnerability_count: usize,
    pub misconfiguration_count: usize,
    pub runtime_seconds: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IsolatedScanReadiness {
    pub configured: bool,
    pub detail: String,
}

struct WorkerSettings {
    docker: PathBuf,
    image: String,
    db_dir: PathBuf,
}

impl WorkerSettings {
    fn load() -> Result<Self, String> {
        let docker = env::var("CODETWIN_DOCKER_PATH").map_err(|_| {
            "Set CODETWIN_DOCKER_PATH to an absolute trusted Docker CLI executable".to_string()
        })?;
        let path = PathBuf::from(docker);
        if !path.is_absolute() || !path.is_file() {
            return Err("Docker executable must be an existing absolute file path".into());
        }
        let image = env::var("CODETWIN_TRIVY_IMAGE").map_err(|_| {
            "Set CODETWIN_TRIVY_IMAGE to a locally available image pinned by sha256 digest"
                .to_string()
        })?;
        let (_, digest) = image
            .rsplit_once("@sha256:")
            .ok_or("Worker image must be pinned by sha256 digest")?;
        if digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
            || image.contains(char::is_whitespace)
            || image.contains('\'')
            || image.starts_with('-')
        {
            return Err("Invalid trusted worker image digest".into());
        }
        let repository = image.split("@sha256:").next().unwrap_or_default();
        if repository.is_empty()
            || !repository
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | ':'))
        {
            return Err("Invalid pinned image repository".into());
        }
        let db = env::var("CODETWIN_TRIVY_DB_DIR").map_err(|_| {
            "Set CODETWIN_TRIVY_DB_DIR to the preloaded offline DB directory".to_string()
        })?;
        let db_dir = fs::canonicalize(db).map_err(err)?;
        if !db_dir.is_dir()
            || !db_dir.join("trivy.db").is_file()
            || !db_dir.join("metadata.json").is_file()
        {
            return Err("Offline vulnerability DB must contain trivy.db and metadata.json".into());
        }
        if !safe_mount_path(&db_dir) {
            return Err("Unsafe offline database mount path".into());
        }
        Ok(Self {
            docker: path,
            image,
            db_dir,
        })
    }
}

/// Return arguments for audit/testing: no untrusted CLI arguments, no network, no host write mounts.
fn container_user(output: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(output).map_err(err)?;
        if meta.uid() == 0 {
            return Err("Running container workers as the root host user is forbidden".into());
        }
        Ok(format!("{}:{}", meta.uid(), meta.gid()))
    }
    #[cfg(not(unix))]
    {
        let _ = output;
        Ok("65534:65534".into())
    }
}

fn safe_mount_path(path: &Path) -> bool {
    !path
        .to_string_lossy()
        .chars()
        .any(|c| c == ',' || c == '\n' || c == '\r')
}

fn build_args(
    settings: &WorkerSettings,
    project: &Path,
    output: &Path,
    name: &str,
    user: &str,
) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--pull=never".into(),
        "--name".into(),
        name.into(),
        "--network".into(),
        "none".into(),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--pids-limit=64".into(),
        "--memory=512m".into(),
        "--cpus=1".into(),
        format!("--user={user}"),
        "--tmpfs=/tmp:rw,noexec,nosuid,size=64m".into(),
        "--mount".into(),
        format!(
            "type=bind,src={},dst=/workspace,readonly",
            project.display()
        ),
        "--mount".into(),
        format!("type=bind,src={},dst=/out", output.display()),
        "--mount".into(),
        format!(
            "type=bind,src={},dst=/tmp/trivy/db,readonly",
            settings.db_dir.display()
        ),
        settings.image.clone(),
        "fs".into(),
        "--cache-dir".into(),
        "/tmp/trivy".into(),
        "--offline-scan".into(),
        "--skip-db-update".into(),
        "--skip-java-db-update".into(),
        "--skip-check-update".into(),
        "--scanners".into(),
        "vuln".into(),
        "--format".into(),
        "json".into(),
        "--output".into(),
        "/out/report.json".into(),
        "/workspace".into(),
    ]
}

pub struct IsolatedWorker<'a> {
    db: &'a Database,
}
impl<'a> IsolatedWorker<'a> {
    pub const fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn readiness() -> IsolatedScanReadiness {
        match WorkerSettings::load() {
            Ok(_) => IsolatedScanReadiness {
                configured:true,
                detail:"Pinned scanner, readable vulnerability DB, and Docker CLI configured. Docker daemon availability is checked when scanning.".into(),
            },
            Err(e)=>IsolatedScanReadiness {configured:false,detail:e},
        }
    }

    fn review_is_still_authorized(&self, run_id: &str) -> Result<bool, String> {
        let allowed: i64 = self
            .db
            .connection()
            .query_row(
                "SELECT CASE WHEN status='approved' AND cancel_requested=0 THEN 1 ELSE 0 END
             FROM native_agent_runs WHERE id=?1",
                [run_id],
                |row| row.get(0),
            )
            .map_err(err)?;
        Ok(allowed == 1)
    }

    /// Explicit user action; never called automatically by an AI role or prompted suggestion.
    pub fn scan(&self, run_id: &str, authorized: bool) -> Result<IsolatedScanReceipt, String> {
        if !authorized {
            return Err("Explicit authorization to scan this local project is required".into());
        }
        let settings = WorkerSettings::load()?;
        self.scan_with_settings(run_id, authorized, settings)
    }

    // The same guarded implementation runs under production Docker and a
    // local process contract fixture that cannot contact the Docker daemon.
    fn scan_with_settings(
        &self,
        run_id: &str,
        authorized: bool,
        settings: WorkerSettings,
    ) -> Result<IsolatedScanReceipt, String> {
        if !authorized {
            return Err("Explicit authorization to scan this local project is required".into());
        }
        let run = NativeAgents::new(self.db).get(run_id)?;
        if run.status != "approved" {
            return Err("Approve the native review before a separate container scan".into());
        }
        let project = WorkspaceService::new(self.db)
            .get_project(&run.project_id)
            .map_err(err)?
            .ok_or("Project not found")?;
        let root = fs::canonicalize(&project.root_path).map_err(err)?;
        if !root.is_dir() {
            return Err("Project root is not a directory".into());
        }
        let tmp = tempfile::tempdir().map_err(err)?;
        if !safe_mount_path(&root) || !safe_mount_path(tmp.path()) {
            return Err("Mount paths cannot contain Docker option separators".into());
        }
        let user = container_user(tmp.path())?;
        // Scope output storage to an isolated temporary directory only.
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(err)?
            .as_nanos();
        let name = format!("codetwin-scan-{:x}", stamp);
        let args = build_args(&settings, &root, tmp.path(), &name, &user);
        // Scope can be revoked while configuration is checked; fail closed
        // before starting an external worker.
        if !self.review_is_still_authorized(run_id)? {
            return Err("Review authorization was cancelled before worker launch".into());
        }
        let begin = Instant::now();
        let mut child = Command::new(&settings.docker)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Could not start isolated container: {e}"))?;
        let status = loop {
            // A cancelled review must stop the live Docker CLI, not merely
            // change SQLite status while the container keeps running.
            if !matches!(self.review_is_still_authorized(run_id), Ok(true)) {
                let _ = child.kill();
                let _ = child.wait();
                return match force_remove_container(&settings.docker, &name) {
                    Ok(()) => Err("Worker stopped after review authorization was revoked; container removal confirmed".into()),
                    Err(_) => Err("Worker stopped after authorization was revoked; container removal unconfirmed".into()),
                };
            }
            if let Some(status) = child.try_wait().map_err(err)? {
                break status;
            }
            if begin.elapsed() > Duration::from_secs(MAX_RUN_SECONDS) {
                let _ = child.kill();
                let _ = child.wait();
                // Docker CLI termination is not proof of daemon-side container removal.
                // Bound cleanup separately: Docker itself might be unresponsive.
                return match force_remove_container(&settings.docker, &name) {
                    Ok(()) => Err("Isolated scan exceeded 90-second execution deadline; container removal confirmed".into()),
                    Err(_) => Err("Isolated scan timed out; Docker container removal could not be confirmed".into()),
                };
            }
            thread::sleep(Duration::from_millis(150));
        };
        if !status.success() {
            // An unsuccessful client process is not enough to prove daemon cleanup.
            // Never report a successful scan if cleanup cannot be confirmed.
            let cleanup = force_remove_container(&settings.docker, &name);
            return Err(if cleanup.is_ok() {
                "Offline scanner exited unsuccessfully; container removal confirmed".into()
            } else {
                "Offline scanner exited unsuccessfully; container removal unconfirmed".into()
            });
        }
        // Also check after a successful child exit; consent can change
        // before reading or committing any resulting scan evidence.
        if !self.review_is_still_authorized(run_id)? {
            return Err("Review authorization was revoked before recording worker results".into());
        }
        let path = tmp.path().join("report.json");
        let bytes = read_scanner_report(&path)?;
        let (vulnerabilities, misconfigurations) = parse_offline_report(&bytes)?;
        Ok(IsolatedScanReceipt {
            run_id: run.id,
            image_digest: settings.image,
            report_sha256: format!("{:x}", Sha256::digest(&bytes)),
            vulnerability_count: vulnerabilities,
            misconfiguration_count: misconfigurations,
            runtime_seconds: begin.elapsed().as_secs(),
            warnings: vec![
                "Offline scan results are provisional; verify findings against source evidence."
                    .into(),
            ],
        })
    }
}

#[cfg(unix)]
fn opened_report_matches_path(path: &fs::Metadata, opened: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    path.dev() == opened.dev() && path.ino() == opened.ino()
}

/// Read only an ordinary file created by the finished worker in its private output
/// directory. Bound memory at the read boundary instead of trusting an earlier
/// size check: the untrusted report can change between metadata and read.
/// Unix verifies the opened file identity to reject symlink/replacement races.
fn read_scanner_report(path: &Path) -> Result<Vec<u8>, String> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| "Scanner returned no report".to_string())?;
    if !path_metadata.file_type().is_file() {
        return Err("Scanner report must be a regular file, not a symlink".into());
    }
    let file = fs::File::open(path).map_err(|_| "Could not open scanner report".to_string())?;
    let opened_metadata = file.metadata().map_err(err)?;
    if !opened_metadata.is_file() {
        return Err("Scanner report must be a regular file".into());
    }
    #[cfg(unix)]
    if !opened_report_matches_path(&path_metadata, &opened_metadata) {
        return Err("Scanner report changed while opening".into());
    }
    if opened_metadata.len() > MAX_REPORT_BYTES {
        return Err("Scanner report exceeded the 2 MB safety limit".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err("Scanner output exceeded safe limit".into());
    }
    Ok(bytes)
}

/// The report is an untrusted container output. Never truncate results silently;
/// an incomplete count is worse than a clearly failed scan.
fn parse_offline_report(bytes: &[u8]) -> Result<(usize, usize), String> {
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err("Scanner output exceeded safe limit".into());
    }
    let json: Value =
        serde_json::from_slice(bytes).map_err(|_| "Scanner returned invalid JSON".to_string())?;
    let reports = json
        .get("Results")
        .and_then(Value::as_array)
        .ok_or("Scanner report has no expected Results array")?;
    if reports.len() > MAX_REPORT_RESULTS {
        return Err("Scanner report exceeds the maximum supported result count".into());
    }
    let mut vulnerabilities = 0usize;
    let mut misconfigurations = 0usize;
    for item in reports {
        let object = item
            .as_object()
            .ok_or("Scanner result must be a JSON object")?;
        for (key, count) in [
            ("Vulnerabilities", &mut vulnerabilities),
            ("Misconfigurations", &mut misconfigurations),
        ] {
            match object.get(key) {
                Some(Value::Array(records)) => {
                    *count = count
                        .checked_add(records.len())
                        .ok_or("Scanner finding count overflow")?
                }
                None | Some(Value::Null) => {}
                _ => return Err("Scanner finding collection has an invalid JSON shape".into()),
            }
        }
    }
    Ok((vulnerabilities, misconfigurations))
}

/// Verify that the currently configured Docker daemon has no leftover
/// CodeTwin scanner containers. This is a read-only, bounded local CLI probe
/// and does not remove containers or trust an operator checkbox as evidence.
pub fn verify_no_leftover_containers() -> Result<(), String> {
    let executable = PathBuf::from(
        env::var("CODETWIN_DOCKER_PATH")
            .map_err(|_| "Configure the trusted Docker CLI before verifying cleanup")?,
    );
    if !executable.is_absolute() || !executable.is_file() {
        return Err("Cleanup check requires an existing absolute Docker executable".into());
    }
    verify_no_leftovers_with_cli(&executable)
}

fn verify_no_leftovers_with_cli(executable: &Path) -> Result<(), String> {
    // A temporary file avoids a pipe-buffer deadlock if Docker returns many
    // containers. Never persist or expose container names.
    let mut output = tempfile::tempfile().map_err(err)?;
    let stdout = output.try_clone().map_err(err)?;
    let mut child = Command::new(executable)
        .args([
            "ps",
            "--all",
            "--filter",
            "name=^/codetwin-scan-",
            "--format",
            "{{.Names}}",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Could not launch local Docker cleanup verification")?;
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() >= CLEANUP_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Docker cleanup verification timed out".into());
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Docker cleanup verification failed".into());
            }
        }
    };
    if !status.success() {
        return Err("Docker did not confirm the local scanner container list".into());
    }
    output.rewind().map_err(err)?;
    let mut names = Vec::new();
    output.take(16_385).read_to_end(&mut names).map_err(err)?;
    if names.len() > 16_384 {
        return Err("Docker scanner container list exceeded the verification limit".into());
    }
    if !names.is_empty() {
        return Err(
            "Scanner containers remain in the configured Docker daemon; remove them and verify again"
                .into(),
        );
    }
    Ok(())
}

/// Limit Docker cleanup duration even if the Docker daemon is unresponsive.
/// This does not prove cleanup if the CLI fails, so callers must surface that state.
fn force_remove_container(docker: &Path, name: &str) -> Result<(), String> {
    let mut child = Command::new(docker)
        .args(["rm", "-f", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Could not launch bounded Docker cleanup")?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err("Docker removal command did not confirm success".into())
                };
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Docker removal command failed to report status".into());
            }
            Ok(None) if start.elapsed() >= CLEANUP_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Docker removal command exceeded its deadline".into());
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn err(value: impl std::fmt::Display) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sandbox_args_disable_network_and_host_write() {
        let fake = WorkerSettings {
            docker: PathBuf::from("/opt/bin/docker"),
            image: format!("local/trivy@sha256:{}", "a".repeat(64)),
            db_dir: PathBuf::from("/tmp/trivy-db"),
        };
        let argv = build_args(
            &fake,
            Path::new("/source"),
            Path::new("/tmp/out"),
            "test",
            "1000:1000",
        );
        assert!(argv.windows(2).any(|p| p == ["--network", "none"]));
        assert!(argv
            .windows(2)
            .any(|p| p == ["--cap-drop=ALL", "--security-opt=no-new-privileges"]));
        assert!(argv.iter().any(|a| a.contains("dst=/workspace,readonly")));
        assert!(argv.iter().any(|a| a == "--pull=never"));
        assert!(argv
            .iter()
            .any(|a| a.contains("dst=/tmp/trivy/db,readonly")));
        assert!(argv.windows(2).any(|p| p == ["--cache-dir", "/tmp/trivy"]));
        assert!(argv.windows(2).any(|p| p == ["--scanners", "vuln"]));
        assert!(!argv.iter().any(|a| a == "--privileged"));
        assert!(argv.iter().any(|a| a == "--user=1000:1000"));
        assert!(!safe_mount_path(Path::new("/tmp/path,with-comma")));
    }
    #[test]
    fn offline_report_counts_all_findings_without_silent_truncation() {
        let report = br#"{"Results":[{"Vulnerabilities":[{},{}],"Misconfigurations":[{}]},{"Vulnerabilities":[{}]}]}"#;
        assert_eq!(parse_offline_report(report).unwrap(), (3, 1));
        assert_eq!(parse_offline_report(br#"{"Results":[]}"#).unwrap(), (0, 0));
        let overflow =
            serde_json::json!({"Results": vec![serde_json::json!({}); MAX_REPORT_RESULTS + 1]});
        assert!(parse_offline_report(overflow.to_string().as_bytes()).is_err());
    }

    #[test]
    fn offline_report_rejects_malformed_findings() {
        assert!(parse_offline_report(br#"{"Results":[{"Vulnerabilities":"untrusted"}]}"#).is_err());
        assert!(parse_offline_report(br#"{"Results":[null]}"#).is_err());
        assert!(parse_offline_report(br#"{"Results":{}}"#).is_err());
        assert!(parse_offline_report(b"not-json").is_err());
    }

    #[test]
    fn scanner_report_requires_a_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let report = temp.path().join("report.json");
        std::fs::write(&report, br#"{"Results":[]}"#).unwrap();
        assert_eq!(
            parse_offline_report(&read_scanner_report(&report).unwrap()).unwrap(),
            (0, 0)
        );
        assert!(read_scanner_report(temp.path()).is_err());
        // Even if the size changes after the metadata check, reading is
        // bounded to MAX_REPORT_BYTES + 1 and an oversized result fails.
        std::fs::write(&report, vec![b'x'; MAX_REPORT_BYTES as usize]).unwrap();
        assert_eq!(
            read_scanner_report(&report).unwrap().len(),
            MAX_REPORT_BYTES as usize
        );
        std::fs::write(&report, vec![b'x'; MAX_REPORT_BYTES as usize + 1]).unwrap();
        assert!(read_scanner_report(&report).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = temp.path().join("link.json");
            symlink(&report, &linked).unwrap();
            assert!(read_scanner_report(&linked).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn scanner_report_identity_checks_reject_file_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original.json");
        let other = temp.path().join("other.json");
        std::fs::write(&original, b"original").unwrap();
        std::fs::write(&other, b"other").unwrap();

        let path_metadata = std::fs::symlink_metadata(&original).unwrap();
        let opened_original = std::fs::File::open(&original).unwrap().metadata().unwrap();
        let opened_other = std::fs::File::open(&other).unwrap().metadata().unwrap();
        assert!(opened_report_matches_path(&path_metadata, &opened_original));
        assert!(!opened_report_matches_path(&path_metadata, &opened_other));
    }

    #[cfg(unix)]
    #[test]
    fn docker_cleanup_result_must_be_confirmed() {
        assert!(force_remove_container(Path::new("/bin/true"), "test").is_ok());
        assert!(force_remove_container(Path::new("/bin/false"), "test").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_docker_cleanup_verification_fails_closed() {
        let fixtures = tempfile::tempdir().unwrap();
        let script = fixtures.path().join("docker-fixture.sh");
        write_fixture_script(
            &script,
            "#!/bin/sh\n[ \"$1\" = ps ] && [ \"$2\" = --all ] || exit 8\nexit 0\n",
        );
        assert!(verify_no_leftovers_with_cli(&script).is_ok());
        write_fixture_script(&script, "#!/bin/sh\nprintf 'codetwin-scan-leftover\\n'\n");
        assert!(verify_no_leftovers_with_cli(&script).is_err());
        write_fixture_script(&script, "#!/bin/sh\nexit 9\n");
        assert!(verify_no_leftovers_with_cli(&script).is_err());
    }

    #[test]
    fn cleanup_deadline_is_bounded() {
        assert!(CLEANUP_TIMEOUT < Duration::from_secs(MAX_RUN_SECONDS));
    }

    #[test]
    fn cancelled_review_revokes_live_worker_permission() {
        let db = Database::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file.ts"), "export const test=true;").unwrap();
        let project = crate::ProjectIndexService::new(&db)
            .index_project(root.path())
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&db);
        let run = agents
            .create(&project, "Authorized scanner review", 10, 120)
            .unwrap();
        let worker = IsolatedWorker::new(&db);
        assert!(!worker.review_is_still_authorized(&run.id).unwrap());
        agents.approve(&run.id).unwrap();
        assert!(worker.review_is_still_authorized(&run.id).unwrap());
        agents.cancel(&run.id).unwrap();
        assert!(!worker.review_is_still_authorized(&run.id).unwrap());
    }

    #[test]
    fn cannot_scan_unapproved_run_or_run_without_authorization() {
        let db = Database::open_in_memory().unwrap();
        assert!(IsolatedWorker::new(&db).scan("missing", false).is_err());
        assert!(IsolatedWorker::new(&db).scan("missing", true).is_err());
    }
    #[cfg(unix)]
    fn fixture_settings(script: &Path, root: &Path) -> WorkerSettings {
        WorkerSettings {
            docker: script.to_path_buf(),
            image: format!("fixture/scanner@sha256:{}", "a".repeat(64)),
            db_dir: root.to_path_buf(),
        }
    }

    #[cfg(unix)]
    fn write_fixture_script(path: &Path, source: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, source).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn approved_worker_runs_offline_subprocess_and_persists_receipt() {
        // This runs a real test-controlled process, not a Docker daemon.
        // It tests actual Rust CLI arguments and the response/audit lifecycle.
        const SCRIPT: &str = r#"#!/bin/sh
set -eu
if [ "$1" = "rm" ]; then exit 0; fi
[ "$1" = "run" ] || exit 11
network=""
readonly=""
pull=""
output=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--network" ]; then network="$arg"; fi
  if [ "$arg" = "--read-only" ]; then readonly=yes; fi
  if [ "$arg" = "--pull=never" ]; then pull=yes; fi
  case "$arg" in
    type=bind,src=*,dst=/out)
      output=$(printf '%s' "$arg" | cut -d ',' -f 2 | cut -c5-)
      ;;
  esac
  previous="$arg"
done
[ "$network" = "none" ] && [ "$readonly" = "yes" ] &&
  [ "$pull" = "yes" ] && [ -n "$output" ] || exit 12
printf '%s\n' '{"Results":[{"Vulnerabilities":[{},{}],"Misconfigurations":[{}]}]}' > "$output/report.json"
"#;
        let fixtures = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("index.js"), "export const safe=true;").unwrap();
        let script = fixtures.path().join("offline-scanner-fixture.sh");
        write_fixture_script(&script, SCRIPT);
        let db = Database::open_in_memory().unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(source.path())
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&db);
        let run = agents
            .create(&project_id, "Approved local test", 10, 120)
            .unwrap();
        agents.approve(&run.id).unwrap();
        let audit = crate::native_worker_audit::WorkerAudit::new(&db);
        let ticket = audit.begin(&run.id).unwrap();
        let result = IsolatedWorker::new(&db).scan_with_settings(
            &run.id,
            true,
            fixture_settings(&script, fixtures.path()),
        );
        audit.finish(ticket, &result).unwrap();
        let receipt = result.unwrap();
        assert_eq!(receipt.vulnerability_count, 2);
        assert_eq!(receipt.misconfiguration_count, 1);
        assert_eq!(receipt.report_sha256.len(), 64);
        assert_eq!(audit.latest(&run.id).unwrap().unwrap().status, "success");
        assert!(!fixtures.path().join("report.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn revoked_review_stops_live_subprocess_and_records_cancellation() {
        // Two SQLite WAL connections coordinate cancellation while an actual
        // test-controlled subprocess runs; no external target or daemon.
        let fixtures = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("index.js"), "export const safe=true;").unwrap();
        let ready = fixtures.path().join("worker-ready");
        let script = fixtures.path().join("sleeping-scanner-fixture.sh");
        let template = r#"#!/bin/sh
set -eu
if [ "$1" = "rm" ]; then exit 0; fi
[ "$1" = "run" ] || exit 13
: > "__READY_FILE__"
exec sleep 15
"#;
        write_fixture_script(
            &script,
            &template.replace("__READY_FILE__", ready.to_str().unwrap()),
        );
        let database_path = fixtures.path().join("worker.sqlite3");
        let db = Database::open(&database_path).unwrap();
        let project_id = crate::ProjectIndexService::new(&db)
            .index_project(source.path())
            .unwrap()
            .project_id;
        let agents = NativeAgents::new(&db);
        let run = agents
            .create(&project_id, "Cancellable local test", 10, 120)
            .unwrap();
        agents.approve(&run.id).unwrap();
        let audit = crate::native_worker_audit::WorkerAudit::new(&db);
        let ticket = audit.begin(&run.id).unwrap();
        let run_id = run.id.clone();
        let settings = fixture_settings(&script, fixtures.path());
        let worker = std::thread::spawn(move || {
            let db = Database::open(&database_path).unwrap();
            let result = IsolatedWorker::new(&db).scan_with_settings(&run_id, true, settings);
            crate::native_worker_audit::WorkerAudit::new(&db)
                .finish(ticket, &result)
                .unwrap();
            result
        });

        for _ in 0..100 {
            if ready.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !ready.exists() {
            agents.cancel(&run.id).unwrap();
            let _ = worker.join();
            panic!("Test subprocess did not start before deadline");
        }
        agents.cancel(&run.id).unwrap();
        let failure = worker.join().unwrap().unwrap_err();
        assert!(failure.contains("authorization was revoked"));
        let saved = audit.latest(&run.id).unwrap().unwrap();
        assert_eq!(saved.status, "failed");
        assert_eq!(saved.error_code.as_deref(), Some("worker_cancelled"));
        assert!(saved.report_sha256.is_none());
        assert!(saved.vulnerability_count.is_none());
    }
}
