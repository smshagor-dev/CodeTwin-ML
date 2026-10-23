//! Optional offline security scan in a pinned, isolated Docker worker.
//! The model never controls executable names, arguments, network, mounts or image tags.
use crate::{native_agents::NativeAgents, Database, WorkspaceService};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
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

    /// Explicit user action; never called automatically by an AI role or prompted suggestion.
    pub fn scan(&self, run_id: &str, authorized: bool) -> Result<IsolatedScanReceipt, String> {
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
        let settings = WorkerSettings::load()?;
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
        let begin = Instant::now();
        let mut child = Command::new(&settings.docker)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Could not start isolated container: {e}"))?;
        let status = loop {
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
        let path = tmp.path().join("report.json");
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "Scanner returned no report".to_string())?;
        if !metadata.file_type().is_file() {
            return Err("Scanner report must be a regular file, not a symlink".into());
        }
        if metadata.len() > MAX_REPORT_BYTES {
            return Err("Scanner report exceeded the 2 MB safety limit".into());
        }
        let bytes = fs::read(&path).map_err(err)?;
        if bytes.len() as u64 > MAX_REPORT_BYTES {
            return Err("Scanner output exceeded safe limit".into());
        }
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

/// The report is an untrusted container output. Never truncate results silently;
/// an incomplete count is worse than a clearly failed scan.
fn parse_offline_report(bytes: &[u8]) -> Result<(usize, usize), String> {
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err("Scanner output exceeded safe limit".into());
    }
    let json: Value = serde_json::from_slice(bytes)
        .map_err(|_| "Scanner returned invalid JSON".to_string())?;
    let reports = json.get("Results").and_then(Value::as_array)
        .ok_or("Scanner report has no expected Results array")?;
    if reports.len() > MAX_REPORT_RESULTS {
        return Err("Scanner report exceeds the maximum supported result count".into());
    }
    let mut vulnerabilities = 0usize;
    let mut misconfigurations = 0usize;
    for item in reports {
        let object = item.as_object().ok_or("Scanner result must be a JSON object")?;
        for (key, count) in [
            ("Vulnerabilities", &mut vulnerabilities),
            ("Misconfigurations", &mut misconfigurations),
        ] {
            match object.get(key) {
                Some(Value::Array(records)) => *count = count
                    .checked_add(records.len())
                    .ok_or("Scanner finding count overflow")?,
                None | Some(Value::Null) => {}
                _ => return Err("Scanner finding collection has an invalid JSON shape".into()),
            }
        }
    }
    Ok((vulnerabilities, misconfigurations))
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
        let overflow = serde_json::json!({"Results": vec![serde_json::json!({}); MAX_REPORT_RESULTS + 1]});
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
    fn cleanup_deadline_is_bounded() {
        assert!(CLEANUP_TIMEOUT < Duration::from_secs(MAX_RUN_SECONDS));
    }

    #[test]
    fn cannot_scan_unapproved_run_or_run_without_authorization() {
        let db = Database::open_in_memory().unwrap();
        assert!(IsolatedWorker::new(&db).scan("missing", false).is_err());
        assert!(IsolatedWorker::new(&db).scan("missing", true).is_err());
    }
}
