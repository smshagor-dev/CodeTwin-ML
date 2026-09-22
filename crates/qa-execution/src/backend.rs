use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[cfg(windows)]
use std::{
    sync::{atomic::Ordering, mpsc},
    thread,
    time::{Duration, Instant},
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
    DockerHardened,
}

impl ExecutionBackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanningOnly => "planning_only",
            Self::WindowsJobObject => "windows_job_object",
            Self::DockerHardened => "docker_hardened",
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
            kind: ExecutionBackendKind::WindowsJobObject,
            execution_available: true,
            capabilities: SandboxCapabilities {
                process_isolation: true,
                filesystem_isolation: false,
                network_isolation: false,
                cpu_limit: true,
                memory_limit: true,
                cancellation: true,
            },
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
                "restricted-token/AppContainer identity isolation is not implemented".to_string(),
                "filesystem/write isolation is not implemented".to_string(),
                "network isolation is not implemented".to_string(),
                "the public QA service remains planning-only until all strict sandbox capabilities are enforced".to_string(),
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

    #[cfg(windows)]
    {
        execute_windows_job_object(plan, &root, cancelled, backend)
    }
    #[cfg(not(windows))]
    {
        let _ = (plan, root, snapshots, cancelled, backend);
        Err(BackendExecutionError::BackendUnavailable)
    }
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

#[cfg(windows)]
fn execute_windows_job_object(
    plan: &TestExecutionPlan,
    root: &Path,
    cancelled: &AtomicBool,
    backend: ExecutionBackendInfo,
) -> Result<RawExecutionOutcome, BackendExecutionError> {
    use std::{
        os::windows::{io::AsRawHandle, process::CommandExt},
        process::{Command, Stdio},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::CREATE_SUSPENDED,
        },
    };

    struct JobHandle(HANDLE);
    impl Drop for JobHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if handle.is_null() {
        return Err(BackendExecutionError::JobSetup(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let job = JobHandle(handle);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_JOB_TIME;
    limits.BasicLimitInformation.PerJobUserTimeLimit = i64::try_from(
        plan.policy.cpu_time_seconds.saturating_mul(10_000_000),
    )
    .map_err(|_| BackendExecutionError::JobSetup("CPU time limit overflow".to_string()))?;
    limits.JobMemoryLimit = usize::try_from(plan.policy.memory_bytes)
        .map_err(|_| BackendExecutionError::JobSetup("memory limit overflow".to_string()))?;
    let configured = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        return Err(BackendExecutionError::JobSetup(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let mut command = Command::new(&plan.command.program);
    command
        .args(&plan.command.args)
        .current_dir(root)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_SUSPENDED);
    for key in ["SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("CODETWIN_QA_EXECUTION", "windows_job_object")
        .env("PYTHONNOUSERSITE", "1")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("NO_COLOR", "1");

    let started = Instant::now();
    let mut child = command.spawn()?;
    let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) };
    if assigned == 0 {
        let error = std::io::Error::last_os_error().to_string();
        let _ = child.kill();
        let _ = child.wait();
        return Err(BackendExecutionError::JobAssignment(error));
    }
    if let Err(error) = resume_suspended_process(child.id()) {
        let _ = terminate_windows_job(job.0);
        let _ = child.wait();
        return Err(error);
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BackendExecutionError::Io(std::io::Error::other("stdout pipe missing")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BackendExecutionError::Io(std::io::Error::other("stderr pipe missing")))?;
    let stdout_budget = plan.policy.max_output_bytes / 2;
    let stderr_budget = plan.policy.max_output_bytes.saturating_sub(stdout_budget);
    let stdout_reader = spawn_bounded_reader(stdout, stdout_budget);
    let stderr_reader = spawn_bounded_reader(stderr, stderr_budget);

    let timeout = Duration::from_millis(plan.policy.timeout_ms);
    let mut status = ExecutionRunStatus::Completed;
    let mut exit_code = None;
    loop {
        if cancelled.load(Ordering::SeqCst) {
            terminate_windows_job(job.0)?;
            status = ExecutionRunStatus::Cancelled;
            break;
        }
        if started.elapsed() >= timeout {
            terminate_windows_job(job.0)?;
            status = ExecutionRunStatus::TimedOut;
            break;
        }
        if let Some(exit) = child.try_wait()? {
            exit_code = exit.code();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !matches!(status, ExecutionRunStatus::Completed) {
        let exit = child.wait()?;
        exit_code = exit.code();
    }

    let output_timeout = Duration::from_secs(1);
    let stdout = receive_bounded_output(stdout_reader, output_timeout)?;
    let stderr = receive_bounded_output(stderr_reader, output_timeout)?;

    Ok(RawExecutionOutcome {
        status,
        exit_code,
        stdout,
        stderr,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        backend,
        parser_completed: false,
        tests_passed: None,
    })
}

#[cfg(windows)]
fn resume_suspended_process(process_id: u32) -> Result<(), BackendExecutionError> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
                TH32CS_SNAPTHREAD,
            },
            Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    };

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(BackendExecutionError::ProcessResume(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let snapshot = OwnedHandle(snapshot);
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
        return Err(BackendExecutionError::ProcessResume(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let mut thread_ids = Vec::new();
    loop {
        if entry.th32OwnerProcessID == process_id {
            thread_ids.push(entry.th32ThreadID);
        }
        if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 {
            break;
        }
    }
    if thread_ids.len() != 1 {
        return Err(BackendExecutionError::ProcessResume(format!(
            "expected exactly one initial suspended thread for process {process_id}, found {}",
            thread_ids.len()
        )));
    }

    let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_ids[0]) };
    if thread.is_null() {
        return Err(BackendExecutionError::ProcessResume(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let thread = OwnedHandle(thread);
    let previous_suspend_count = unsafe { ResumeThread(thread.0) };
    if previous_suspend_count == u32::MAX {
        return Err(BackendExecutionError::ProcessResume(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if previous_suspend_count != 1 {
        return Err(BackendExecutionError::ProcessResume(format!(
            "unexpected initial thread suspend count {previous_suspend_count}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn terminate_windows_job(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), BackendExecutionError> {
    use windows_sys::Win32::System::JobObjects::TerminateJobObject;

    let terminated = unsafe { TerminateJobObject(handle, 1) };
    if terminated == 0 {
        return Err(BackendExecutionError::JobTermination(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn spawn_bounded_reader<R>(
    mut reader: R,
    max_bytes: usize,
) -> mpsc::Receiver<Result<BoundedOutput, std::io::Error>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| {
            let mut captured = Vec::with_capacity(max_bytes.min(64 * 1024));
            let mut original_bytes = 0usize;
            let mut buffer = [0u8; 8192];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                original_bytes = original_bytes.saturating_add(read);
                if captured.len() < max_bytes {
                    let remaining = max_bytes - captured.len();
                    captured.extend_from_slice(&buffer[..read.min(remaining)]);
                }
            }
            let lossy = String::from_utf8_lossy(&captured).into_owned();
            let text_bound = crate::bound_output(&lossy, max_bytes);
            Ok(BoundedOutput {
                text: text_bound.text,
                original_bytes,
                truncated: original_bytes > captured.len() || text_bound.truncated,
            })
        })();
        let _ = sender.send(result);
    });
    receiver
}

#[cfg(windows)]
fn receive_bounded_output(
    receiver: mpsc::Receiver<Result<BoundedOutput, std::io::Error>>,
    timeout: Duration,
) -> Result<BoundedOutput, BackendExecutionError> {
    match receiver.recv_timeout(timeout) {
        Ok(result) => result.map_err(BackendExecutionError::Io),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(BackendExecutionError::OutputReaderTimeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(BackendExecutionError::OutputReaderDisconnected)
        }
    }
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
            assert!(info.capabilities.cpu_limit);
            assert!(info.capabilities.memory_limit);
            assert!(info.capabilities.cancellation);
            assert!(info.controls.process_created_suspended);
            assert!(info.controls.process_assigned_before_resume);
        } else {
            assert!(!info.capabilities.process_isolation);
            assert!(!info.capabilities.cpu_limit);
            assert!(!info.capabilities.memory_limit);
            assert!(!info.capabilities.cancellation);
        }
        assert!(!info.capabilities.filesystem_isolation);
        assert!(!info.capabilities.network_isolation);
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
