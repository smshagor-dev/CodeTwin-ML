//! Optional offline security scan in a pinned, isolated Docker worker.
//! The model never controls executable names, arguments, network, mounts or image tags.
use crate::{native_agents::NativeAgents, Database, WorkspaceService};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs, path::{Path, PathBuf}, process::{Command, Stdio},
    thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_RUN_SECONDS: u64 = 90;
const MAX_REPORT_BYTES: u64 = 2_000_000;

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

struct WorkerSettings { docker: PathBuf, image: String }

impl WorkerSettings {
    fn load() -> Result<Self, String> {
        let docker = env::var("CODETWIN_DOCKER_PATH")
            .map_err(|_| "Set CODETWIN_DOCKER_PATH to an absolute trusted Docker CLI executable".to_string())?;
        let path = PathBuf::from(docker);
        if !path.is_absolute() || !path.is_file() {
            return Err("Docker executable must be an existing absolute file path".into());
        }
        let image=env::var("CODETWIN_TRIVY_IMAGE")
            .map_err(|_| "Set CODETWIN_TRIVY_IMAGE to a locally available image pinned by sha256 digest".to_string())?;
        let (_, digest)=image.rsplit_once("@sha256:")
            .ok_or("Worker image must be pinned by sha256 digest")?;
        if digest.len()!=64 || !digest.bytes().all(|b| b.is_ascii_hexdigit())
            || image.contains(char::is_whitespace) || image.contains('\'')
            || image.starts_with('-')
        {
            return Err("Invalid trusted worker image digest".into());
        }
        let repository=image.split("@sha256:").next().unwrap_or_default();
        if repository.is_empty() || !repository.chars().all(|c|
            c.is_ascii_alphanumeric() || matches!(c,'.' | '-' | '_' | '/' | ':' )
        ) {
            return Err("Invalid pinned image repository".into());
        }
        Ok(Self { docker:path, image })
    }
}

/// Return arguments for audit/testing: no untrusted CLI arguments, no network, no host write mounts.
fn build_args(settings: &WorkerSettings, project: &Path, output: &Path, name: &str) -> Vec<String> {
    vec![
        "run".into(), "--rm".into(), "--pull=never".into(),
        "--name".into(), name.into(),
        "--network".into(), "none".into(),
        "--read-only".into(), "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--pids-limit=64".into(), "--memory=512m".into(),
        "--cpus=1".into(), "--user=65534:65534".into(),
        "--tmpfs=/tmp:rw,noexec,nosuid,size=64m".into(),
        "--mount".into(), format!("type=bind,src={},dst=/workspace,readonly",project.display()),
        "--mount".into(), format!("type=bind,src={},dst=/out",output.display()),
        settings.image.clone(),
        "fs".into(), "--offline-scan".into(), "--skip-db-update".into(),
        "--format".into(), "json".into(), "--output".into(), "/out/report.json".into(),
        "/workspace".into(),
    ]
}

pub struct IsolatedWorker<'a> { db: &'a Database }
impl<'a> IsolatedWorker<'a> {
    pub const fn new(db: &'a Database) -> Self { Self {db} }

    pub fn readiness() -> IsolatedScanReadiness {
        match WorkerSettings::load() {
            Ok(_) => IsolatedScanReadiness {
                configured:true,
                detail:"Pinned offline worker configured. A local Docker daemon and preloaded scanner database are still required.".into(),
            },
            Err(e)=>IsolatedScanReadiness {configured:false,detail:e},
        }
    }

    /// Explicit user action; never called automatically by an AI role or prompted suggestion.
    pub fn scan(&self, run_id: &str, authorized: bool) -> Result<IsolatedScanReceipt,String> {
        if !authorized {return Err("Explicit authorization to scan this local project is required".into());}
        let run=NativeAgents::new(self.db).get(run_id)?;
        if run.status!="approved" {
            return Err("Approve the native review before a separate container scan".into());
        }
        let project=WorkspaceService::new(self.db).get_project(&run.project_id)
            .map_err(err)?.ok_or("Project not found")?;
        let root=fs::canonicalize(&project.root_path).map_err(err)?;
        if !root.is_dir() {return Err("Project root is not a directory".into());}
        let settings=WorkerSettings::load()?;
        let tmp=tempfile::tempdir().map_err(err)?;
        // Scope output storage to an isolated temporary directory only.
        let stamp=SystemTime::now().duration_since(UNIX_EPOCH).map_err(err)?.as_nanos();
        let name=format!("codetwin-scan-{:x}",stamp);
        let args=build_args(&settings,&root,tmp.path(),&name);
        let begin=Instant::now();
        let mut child=Command::new(&settings.docker)
            .args(&args)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().map_err(|e|format!("Could not start isolated container: {e}"))?;
        let status=loop {
            if let Some(status)=child.try_wait().map_err(err)? {break status;}
            if begin.elapsed()>Duration::from_secs(MAX_RUN_SECONDS) {
                let _=child.kill();
                let _=child.wait();
                // Killing the Docker client may not terminate the daemon's container.
                // Force-remove the uniquely named container before returning.
                let _=Command::new(&settings.docker)
                    .args(["rm","-f",&name])
                    .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                    .status();
                return Err("Isolated scan exceeded 90-second execution deadline".into());
            }
            thread::sleep(Duration::from_millis(150));
        };
        if !status.success() {
            return Err(format!("Offline scanner failed (exit status {status}); check Docker image and preloaded vulnerability database"));
        }
        let path=tmp.path().join("report.json");
        let metadata=fs::metadata(&path).map_err(|_| "Scanner returned no report".to_string())?;
        if metadata.len()>MAX_REPORT_BYTES {
            return Err("Scanner report exceeded the 2 MB safety limit".into());
        }
        let bytes=fs::read(&path).map_err(err)?;
        if bytes.len() as u64>MAX_REPORT_BYTES {
            return Err("Scanner output exceeded safe limit".into());
        }
        let json:Value=serde_json::from_slice(&bytes).map_err(|_| "Scanner returned invalid JSON".to_string())?;
        let reports=json.get("Results").and_then(Value::as_array)
            .ok_or("Scanner report has no expected Results array")?;
        let mut vulnerabilities=0usize;
        let mut misconfigurations=0usize;
        for item in reports.iter().take(2000) {
            vulnerabilities=vulnerabilities.saturating_add(
                item.get("Vulnerabilities").and_then(Value::as_array).map_or(0,Vec::len)
            );
            misconfigurations=misconfigurations.saturating_add(
                item.get("Misconfigurations").and_then(Value::as_array).map_or(0,Vec::len)
            );
        }
        Ok(IsolatedScanReceipt {
            run_id:run.id,image_digest:settings.image,
            report_sha256:format!("{:x}",Sha256::digest(&bytes)),
            vulnerability_count:vulnerabilities,
            misconfiguration_count:misconfigurations,
            runtime_seconds:begin.elapsed().as_secs(),
            warnings:vec!["Offline scan results are provisional; verify findings against source evidence.".into()],
        })
    }
}

fn err(value: impl std::fmt::Display) -> String {value.to_string()}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sandbox_args_disable_network_and_host_write() {
        let fake=WorkerSettings {
            docker:PathBuf::from("/opt/bin/docker"),
            image:format!("local/trivy@sha256:{}", "a".repeat(64)),
        };
        let argv=build_args(&fake,Path::new("/source"),Path::new("/tmp/out"),"test");
        assert!(argv.windows(2).any(|p|p==["--network","none"]));
        assert!(argv.windows(2).any(|p|p==["--cap-drop=ALL","--security-opt=no-new-privileges"]));
        assert!(argv.iter().any(|a|a.contains("dst=/workspace,readonly")));
        assert!(argv.iter().any(|a|a=="--pull=never"));
        assert!(!argv.iter().any(|a|a=="--privileged"));
    }
    #[test]
    fn cannot_scan_unapproved_run_or_run_without_authorization() {
        let db=Database::open_in_memory().unwrap();
        assert!(IsolatedWorker::new(&db).scan("missing",false).is_err());
        assert!(IsolatedWorker::new(&db).scan("missing",true).is_err());
    }
}
