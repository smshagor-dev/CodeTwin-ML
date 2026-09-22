use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    BoundedOutput, ExecutionPlanStatus, ExecutionRunStatus, SandboxCapabilities, TestExecutionPlan,
    MAX_TARGETS,
};

pub const MAX_EXECUTION_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBackendKind {
    PlanningOnly,
    WindowsJobObject,
    WindowsLpac,
}

impl ExecutionBackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanningOnly => "planning_only",
            Self::WindowsJobObject => "windows_job_object",
            Self::WindowsLpac => "windows_lpac",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendControls {
    pub job_object: bool,
    pub kill_on_job_close: bool,
    pub job_cpu_time_limit: bool,
    pub job_memory_limit: bool,
    pub bounded_wall_clock: bool,
    pub bounded_output: bool,
    pub sanitized_environment: bool,
    pub trusted_toolchain_hash: bool,
    pub input_hash_verification: bool,
    pub process_created_suspended: bool,
    pub process_assigned_before_resume: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBackendInfo {
    pub kind: ExecutionBackendKind,
    pub execution_available: bool,
    pub capabilities: SandboxCapabilities,
    pub controls: BackendControls,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionInputSnapshot {
    pub relative_path: String,
    pub sha256: String,
    pub byte_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawExecutionOutcome {
    pub status: ExecutionRunStatus,
    pub exit_code: Option<i32>,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    pub duration_ms: u64,
    pub backend: ExecutionBackendInfo,
    pub parser_completed: bool,
    pub tests_passed: Option<bool>,
}

#[derive(Debug, Error)]
pub enum BackendExecutionError {
    #[error("execution backend is unavailable on this platform")]
    BackendUnavailable,
    #[error("execution plan must be approved before launch")]
    PlanNotApproved,
    #[error("execution plan is blocked by required sandbox capabilities")]
    PlanBlocked,
    #[error("execution plan capabilities do not match the current backend")]
    CapabilityMismatch,
    #[error("shell-backed execution commands are forbidden")]
    ShellForbidden,
    #[error("invalid project root: {0}")]
    InvalidProjectRoot(String),
    #[error("unsafe execution input: {0}")]
    UnsafeInput(String),
    #[error("execution input is too large: {0}")]
    InputTooLarge(String),
    #[error("execution input snapshot is missing or stale: {0}")]
    StaleInput(String),
    #[error("trusted toolchain executable is invalid: {0}")]
    InvalidToolchain(String),
    #[error("trusted toolchain executable must be outside the analyzed repository")]
    ToolchainInsideProject,
    #[error("trusted toolchain SHA-256 is required before execution")]
    MissingToolchainHash,
    #[error("trusted toolchain SHA-256 no longer matches the approved plan")]
    ToolchainHashMismatch,
    #[error("Windows Job Object setup failed: {0}")]
    JobSetup(String),
    #[error("Windows Job Object assignment failed: {0}")]
    JobAssignment(String),
    #[error("Windows suspended process resume failed: {0}")]
    ProcessResume(String),
    #[error("Windows Job Object termination failed: {0}")]
    JobTermination(String),
    #[error("execution I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("bounded output reader did not finish after process termination")]
    OutputReaderTimeout,
    #[error("bounded output reader disconnected")]
    OutputReaderDisconnected,
}

pub fn current_backend_info() -> ExecutionBackendInfo {
    #[cfg(windows)]
    {
        ExecutionBackendInfo {
            kind: ExecutionBackendKind::WindowsLpac,
            execution_available: true,
            capabilities: SandboxCapabilities::fully_enforced(),
            controls: BackendControls {
                job_object: true,
                kill_on_job_close: true,
                job_cpu_time_limit: true,
                job_memory_limit: true,
                bounded_wall_clock: true,
                bounded_output: true,
                sanitized_environment: true,
                trusted_toolchain_hash: true,
                input_hash_verification: true,
                process_created_suspended: true,
                process_assigned_before_resume: true,
            },
            limitations: vec![
                "Filesystem isolation is scoped to the detached project mirror and copied approved runtime/toolchain material; it is not a host-wide deny-all-read claim for Windows system objects.".to_string(),
                "The actual runner is created suspended as a zero-capability LPAC child, assigned to the bounded Job Object before resume, and receives no ambient host PATH.".to_string(),
                "Network promotion is fail-closed when the LPAC profile has a Windows loopback exemption, including a re-attestation immediately before the production child is created.".to_string(),
                "Execution remains unavailable if LPAC creation, ACL preparation, provenance verification, network attestation, or runtime parsing cannot be proven for the requested plan.".to_string(),
            ],
        }
    }
    #[cfg(not(windows))]
    {
        ExecutionBackendInfo {
            kind: ExecutionBackendKind::PlanningOnly,
            execution_available: false,
            capabilities: SandboxCapabilities::planning_only(),
            controls: BackendControls {
                job_object: false,
                kill_on_job_close: false,
                job_cpu_time_limit: false,
                job_memory_limit: false,
                bounded_wall_clock: false,
                bounded_output: false,
                sanitized_environment: false,
                trusted_toolchain_hash: true,
                input_hash_verification: true,
                process_created_suspended: false,
                process_assigned_before_resume: false,
            },
            limitations: vec![
                "no OS-specific QA execution backend is implemented for this platform".to_string(),
            ],
        }
    }
}

pub fn snapshot_execution_inputs(
    project_root: impl AsRef<Path>,
    targets: &[String],
) -> Result<Vec<ExecutionInputSnapshot>, BackendExecutionError> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(BackendExecutionError::UnsafeInput(format!(
            "target count must be between 1 and {MAX_TARGETS}"
        )));
    }
    let root = canonical_project_root(project_root.as_ref())?;
    let mut snapshots = Vec::with_capacity(targets.len());
    for target in targets {
        let path = resolve_execution_input(&root, target)?;
        let metadata = fs::metadata(&path)?;
        if metadata.len() > MAX_EXECUTION_INPUT_BYTES {
            return Err(BackendExecutionError::InputTooLarge(target.clone()));
        }
        snapshots.push(ExecutionInputSnapshot {
            relative_path: target.clone(),
            sha256: sha256_file(&path)?,
            byte_size: metadata.len(),
        });
    }
    Ok(snapshots)
}

pub fn verify_execution_inputs(
    project_root: impl AsRef<Path>,
    targets: &[String],
    snapshots: &[ExecutionInputSnapshot],
) -> Result<(), BackendExecutionError> {
    let expected = snapshots
        .iter()
        .map(|item| (item.relative_path.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != targets.len() || snapshots.len() != targets.len() {
        return Err(BackendExecutionError::StaleInput(
            "snapshot set does not exactly match the approved target set".to_string(),
        ));
    }
    let root = canonical_project_root(project_root.as_ref())?;
    for target in targets {
        let Some(snapshot) = expected.get(target.as_str()) else {
            return Err(BackendExecutionError::StaleInput(target.clone()));
        };
        let path = resolve_execution_input(&root, target)?;
        let metadata = fs::metadata(&path)?;
        if metadata.len() != snapshot.byte_size || sha256_file(&path)? != snapshot.sha256 {
            return Err(BackendExecutionError::StaleInput(target.clone()));
        }
    }
    Ok(())
}

pub fn execute_approved_plan(
    plan: &TestExecutionPlan,
    project_root: impl AsRef<Path>,
    snapshots: &[ExecutionInputSnapshot],
    cancelled: &AtomicBool,
) -> Result<RawExecutionOutcome, BackendExecutionError> {
    if plan.status != ExecutionPlanStatus::Approved {
        return Err(BackendExecutionError::PlanNotApproved);
    }
    if !plan.blocking_reasons.is_empty() {
        return Err(BackendExecutionError::PlanBlocked);
    }
    if plan.command.uses_shell {
        return Err(BackendExecutionError::ShellForbidden);
    }
    let backend = current_backend_info();
    if !backend.execution_available {
        return Err(BackendExecutionError::BackendUnavailable);
    }
    if plan.capabilities != backend.capabilities {
        return Err(BackendExecutionError::CapabilityMismatch);
    }

    let root = canonical_project_root(project_root.as_ref())?;
    verify_toolchain(plan, &root)?;
    verify_execution_inputs(&root, &plan.request.targets, snapshots)?;

    // The generic backend is planning/verification-only on Windows. Production
    // Windows execution is exclusively routed through windows_project_mirror,
    // which launches the attested LPAC bundle. Never fall back to a plain Job
    // Object runner if that path is unavailable.
    let _ = (plan, root, snapshots, cancelled, backend);
    Err(BackendExecutionError::BackendUnavailable)
}

fn canonical_project_root(root: &Path) -> Result<PathBuf, BackendExecutionError> {
    let canonical = fs::canonicalize(root).map_err(|error| {
        BackendExecutionError::InvalidProjectRoot(format!("{}: {error}", root.display()))
    })?;
    if !canonical.is_dir() {
        return Err(BackendExecutionError::InvalidProjectRoot(
            canonical.display().to_string(),
        ));
    }
    Ok(canonical)
}

fn resolve_execution_input(
    root: &Path,
    target: &str,
) -> Result<PathBuf, BackendExecutionError> {
    crate::validate_target(target)
        .map_err(|_| BackendExecutionError::UnsafeInput(target.to_string()))?;
    let candidate = root.join(target);
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|_| BackendExecutionError::UnsafeInput(target.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackendExecutionError::UnsafeInput(target.to_string()));
    }
    let canonical = fs::canonicalize(&candidate)?;
    if !canonical.starts_with(root) {
        return Err(BackendExecutionError::UnsafeInput(target.to_string()));
    }
    Ok(canonical)
}

fn verify_toolchain(plan: &TestExecutionPlan, root: &Path) -> Result<(), BackendExecutionError> {
    if plan.command.program != plan.toolchain.executable_path {
        return Err(BackendExecutionError::InvalidToolchain(
            "command program differs from approved toolchain path".to_string(),
        ));
    }
    let executable = Path::new(&plan.toolchain.executable_path);
    if !executable.is_absolute() {
        return Err(BackendExecutionError::InvalidToolchain(
            "toolchain path is not absolute".to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(executable).map_err(|error| {
        BackendExecutionError::InvalidToolchain(format!("{}: {error}", executable.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackendExecutionError::InvalidToolchain(
            "toolchain must be a regular non-symlink file".to_string(),
        ));
    }
    let canonical = fs::canonicalize(executable)?;
    if canonical.starts_with(root) {
        return Err(BackendExecutionError::ToolchainInsideProject);
    }
    let Some(expected_hash) = plan.toolchain.sha256.as_deref() else {
        return Err(BackendExecutionError::MissingToolchainHash);
    };
    if expected_hash.len() != 64
        || !expected_hash.chars().all(|character| character.is_ascii_hexdigit())
    {
        return Err(BackendExecutionError::InvalidToolchain(
            "toolchain SHA-256 must be 64 hexadecimal characters".to_string(),
        ));
    }
    if !sha256_file(&canonical)?.eq_ignore_ascii_case(expected_hash) {
        return Err(BackendExecutionError::ToolchainHashMismatch);
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let bytes = digest.finalize();
    let mut output = String::with_capacity(64);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::AtomicBool,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        current_backend_info, execute_approved_plan, snapshot_execution_inputs,
        verify_execution_inputs, BackendExecutionError,
    };
    use crate::{
        build_execution_plan, ExecutionPlanStatus, SandboxCapabilities, SandboxPolicy,
        TestExecutionRequest, TestRunnerKind, TrustedToolchain,
    };

    fn temp_root() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos());
        let path = std::env::temp_dir().join(format!("codetwin-qa-backend-{nanos}"));
        fs::create_dir_all(path.join("tests")).expect("temp root");
        path
    }

    #[test]
    fn input_snapshot_detects_mutation() {
        let root = temp_root();
        let file = root.join("tests/test_api.py");
        fs::write(&file, "def test_ok():\n    assert True\n").expect("write");
        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&root, &targets).expect("snapshot");
        verify_execution_inputs(&root, &targets, &snapshots).expect("verify");
        fs::write(&file, "def test_ok():\n    assert False\n").expect("mutate");
        assert!(matches!(
            verify_execution_inputs(&root, &targets, &snapshots),
            Err(BackendExecutionError::StaleInput(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn backend_promotes_only_enforced_capabilities() {
        let info = current_backend_info();
        if cfg!(windows) {
            assert!(info.capabilities.process_isolation);
            assert!(info.capabilities.filesystem_isolation);
            assert!(info.capabilities.network_isolation);
            assert!(info.capabilities.cpu_limit);
            assert!(info.capabilities.memory_limit);
            assert!(info.capabilities.cancellation);
            assert!(info.controls.process_created_suspended);
            assert!(info.controls.process_assigned_before_resume);
        } else {
            assert!(!info.capabilities.process_isolation);
            assert!(!info.capabilities.filesystem_isolation);
            assert!(!info.capabilities.network_isolation);
            assert!(!info.capabilities.cpu_limit);
            assert!(!info.capabilities.memory_limit);
            assert!(!info.capabilities.cancellation);
        }
    }

    #[test]
    fn blocked_plan_cannot_reach_executor() {
        let plan = build_execution_plan(
            TestExecutionRequest {
                runner: TestRunnerKind::Pytest,
                targets: vec!["tests/test_api.py".to_string()],
                discovery_run_id: None,
            },
            TrustedToolchain {
                runner: TestRunnerKind::Pytest,
                executable_path: if cfg!(windows) {
                    "C:/trusted/python.exe".to_string()
                } else {
                    "/trusted/python".to_string()
                },
                version: "3.12".to_string(),
                sha256: Some("a".repeat(64)),
                trusted_by_user: true,
                declared_external_read_roots: Vec::new(),
            },
            SandboxPolicy::default(),
            SandboxCapabilities::planning_only(),
        )
        .expect("plan");
        assert_eq!(plan.status, ExecutionPlanStatus::Blocked);
        let root = temp_root();
        fs::write(root.join("tests/test_api.py"), "def test_ok(): pass\n").expect("write");
        let snapshots = snapshot_execution_inputs(&root, &plan.request.targets).expect("snapshot");
        assert!(matches!(
            execute_approved_plan(&plan, &root, &snapshots, &AtomicBool::new(false)),
            Err(BackendExecutionError::PlanNotApproved)
        ));
        let _ = fs::remove_dir_all(root);
    }
}
