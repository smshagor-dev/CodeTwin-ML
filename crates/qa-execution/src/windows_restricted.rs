use std::{
    collections::BTreeMap,
    ffi::{c_void, OsStr, OsString},
    fs::{self, File},
    io::Read,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{FromRawHandle, RawHandle},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, SetHandleInformation, ERROR_ALREADY_EXISTS, GENERIC_READ, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        CreateWellKnownSid, EqualSid, FreeSid, GetTokenInformation, IsTokenRestricted, PSID,
        SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        TokenAppContainerSid, TokenCapabilities, TokenIntegrityLevel, TokenIsAppContainer,
        TokenIsLessPrivilegedAppContainer, TokenRestrictedSids, WinLowLabelSid,
        WinWriteRestrictedCodeSid,
    },
    Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
            JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
            JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
            JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        },
        Pipes::CreatePipe,
        Threading::{
            CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
            WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
            PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
        },
        WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
    },
};

use crate::workspace::identity::create_windows_write_restricted_token;
use crate::workspace::DetachedExecutionWorkspace;
use crate::{
    bound_output, cleanup_detached_workspace, current_backend_info, BackendExecutionError,
    BoundedOutput, ExecutionInputSnapshot,
    ExecutionPlanStatus, ExecutionRunStatus, RawExecutionOutcome, TestExecutionPlan,
};

const POST_TERMINATION_WAIT_MS: u32 = 5_000;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const WINDOWS_COMMAND_LINE_LIMIT: usize = 32_767;
const LPAC_PROFILE_NAME: &str = "CodeTwinML.QA.RestrictedRunner.V1";
const LPAC_PROFILE_DISPLAY_NAME: &str = "CodeTwin ML QA Restricted Runner";
const LPAC_PROFILE_DESCRIPTION: &str =
    "Zero-capability Less Privileged AppContainer used for bounded QA execution.";

pub(crate) fn execute_lpac_bundle_plan(
    plan: &TestExecutionPlan,
    mirror_root: &Path,
    workspace: &DetachedExecutionWorkspace,
    bundled_runner: &Path,
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
    if !backend.execution_available || !backend.capabilities.filesystem_isolation
        || !backend.capabilities.network_isolation
    {
        return Err(BackendExecutionError::BackendUnavailable);
    }
    if plan.capabilities != backend.capabilities {
        return Err(BackendExecutionError::CapabilityMismatch);
    }

    let mirror_root = canonical_project_root(mirror_root)?;
    let workspace_root = canonical_project_root(Path::new(&workspace.root_path))?;
    let runner = fs::canonicalize(bundled_runner).map_err(|error| {
        BackendExecutionError::InvalidToolchain(format!(
            "cannot canonicalize bundled LPAC runner {}: {error}",
            bundled_runner.display()
        ))
    })?;
    if !runner.is_file() || !runner.starts_with(&workspace_root) {
        return Err(BackendExecutionError::InvalidToolchain(
            "bundled LPAC runner must be a regular file inside the detached workspace".to_string(),
        ));
    }

    let profile = AppContainerProfileSid::open_or_create()?;
    crate::windows_project_mirror::assert_lpac_profile_network_isolation(profile.sid())?;
    let token = create_windows_write_restricted_token()
        .map_err(|error| BackendExecutionError::JobSetup(format!("LPAC restricted token: {error}")))?;
    let job = configure_job(plan)?;
    let mut child = spawn_lpac_suspended(
        plan,
        &mirror_root,
        workspace,
        &runner,
        token.raw(),
        profile.sid(),
    )?;

    if let Err(error) = attest_production_lpac(child.process.raw(), profile.sid()) {
        child.terminate_before_job_assignment();
        return Err(error);
    }

    let assigned = unsafe { AssignProcessToJobObject(job.raw(), child.process.raw()) };
    if assigned == 0 {
        let error = std::io::Error::last_os_error().to_string();
        child.terminate_before_job_assignment();
        return Err(BackendExecutionError::JobAssignment(error));
    }

    let previous_suspend_count = unsafe { ResumeThread(child.thread.raw()) };
    if previous_suspend_count == u32::MAX {
        let error = std::io::Error::last_os_error().to_string();
        let _ = terminate_job_and_wait(job.raw(), child.process.raw());
        return Err(BackendExecutionError::ProcessResume(error));
    }
    if previous_suspend_count != 1 {
        let _ = terminate_job_and_wait(job.raw(), child.process.raw());
        return Err(BackendExecutionError::ProcessResume(format!(
            "unexpected initial LPAC thread suspend count {previous_suspend_count}"
        )));
    }
    child.thread.close_now();

    let stdout_budget = plan.policy.max_output_bytes / 2;
    let stderr_budget = plan.policy.max_output_bytes.saturating_sub(stdout_budget);
    let stdout_reader = spawn_bounded_reader(child.stdout.take_file(), stdout_budget);
    let stderr_reader = spawn_bounded_reader(child.stderr.take_file(), stderr_budget);

    let started = Instant::now();
    let timeout = Duration::from_millis(plan.policy.timeout_ms);
    let mut status = ExecutionRunStatus::Completed;
    let exit_code;

    loop {
        if cancelled.load(Ordering::SeqCst) {
            terminate_job_and_wait(job.raw(), child.process.raw())?;
            status = ExecutionRunStatus::Cancelled;
            exit_code = process_exit_code(child.process.raw())?;
            break;
        }
        if started.elapsed() >= timeout {
            terminate_job_and_wait(job.raw(), child.process.raw())?;
            status = ExecutionRunStatus::TimedOut;
            exit_code = process_exit_code(child.process.raw())?;
            break;
        }
        match unsafe { WaitForSingleObject(child.process.raw(), 0) } {
            WAIT_OBJECT_0 => {
                exit_code = process_exit_code(child.process.raw())?;
                break;
            }
            WAIT_TIMEOUT => thread::sleep(Duration::from_millis(20)),
            WAIT_FAILED => return Err(BackendExecutionError::Io(std::io::Error::last_os_error())),
            other => {
                return Err(BackendExecutionError::Io(std::io::Error::other(format!(
                    "unexpected WaitForSingleObject result {other}"
                ))))
            }
        }
    }

    drop(job);
    let stdout = receive_bounded_output(stdout_reader, OUTPUT_DRAIN_TIMEOUT)?;
    let stderr = receive_bounded_output(stderr_reader, OUTPUT_DRAIN_TIMEOUT)?;
    let (parser_completed, tests_passed) =
        parse_runner_result(plan.request.runner, status, exit_code, &stdout.text, &stderr.text);

    Ok(RawExecutionOutcome {
        status,
        exit_code: Some(exit_code),
        stdout,
        stderr,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        backend,
        parser_completed,
        tests_passed,
    })
}

#[allow(dead_code)]
pub(crate) fn execute_approved_plan(
    plan: &TestExecutionPlan,
    project_root: &Path,
    snapshots: &[ExecutionInputSnapshot],
    cancelled: &AtomicBool,
) -> Result<RawExecutionOutcome, BackendExecutionError> {
    // Legacy restricted-token execution is intentionally unreachable. Production
    // Windows QA execution must flow through the detached dependency-complete
    // mirror and execute_lpac_bundle_plan so filesystem and network isolation are
    // both enforced before the runner is resumed.
    let _ = (plan, project_root, snapshots, cancelled);
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    use std::fmt::Write as _;
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

#[allow(dead_code)]
struct WorkspaceGuard {
    workspace: Option<DetachedExecutionWorkspace>,
}

#[allow(dead_code)]
impl WorkspaceGuard {
    fn new(workspace: DetachedExecutionWorkspace) -> Self {
        Self {
            workspace: Some(workspace),
        }
    }

    fn workspace(&self) -> &DetachedExecutionWorkspace {
        self.workspace.as_ref().expect("workspace guard is active")
    }

    fn cleanup(&mut self) -> Result<(), BackendExecutionError> {
        if let Some(workspace) = self.workspace.take() {
            cleanup_detached_workspace(&workspace).map_err(|error| {
                BackendExecutionError::JobSetup(format!("detached workspace cleanup: {error}"))
            })?;
        }
        Ok(())
    }
}

impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        if let Some(workspace) = self.workspace.take() {
            let _ = cleanup_detached_workspace(&workspace);
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self, std::io::Error> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }

    fn close_now(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }

    fn take_file(&mut self) -> File {
        let raw = self.0;
        self.0 = std::ptr::null_mut();
        unsafe { File::from_raw_handle(raw as RawHandle) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        self.close_now();
    }
}

struct JobHandle(OwnedHandle);

impl JobHandle {
    fn raw(&self) -> HANDLE {
        self.0.raw()
    }
}

fn configure_job(plan: &TestExecutionPlan) -> Result<JobHandle, BackendExecutionError> {
    let job = JobHandle(OwnedHandle::new(unsafe {
        CreateJobObjectW(std::ptr::null(), std::ptr::null())
    })?);
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
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "JobObjectExtendedLimitInformation: {}",
            std::io::Error::last_os_error()
        )));
    }

    let ui_restrictions = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: qa_job_ui_limit_flags(),
    };
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectBasicUIRestrictions,
            (&ui_restrictions as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
            size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "JobObjectBasicUIRestrictions: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(job)
}

const fn qa_job_ui_limit_flags() -> u32 {
    JOB_OBJECT_UILIMIT_DESKTOP
        | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
        | JOB_OBJECT_UILIMIT_EXITWINDOWS
        | JOB_OBJECT_UILIMIT_GLOBALATOMS
        | JOB_OBJECT_UILIMIT_HANDLES
        | JOB_OBJECT_UILIMIT_READCLIPBOARD
        | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
        | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
}

struct RestrictedChild {
    process: OwnedHandle,
    thread: OwnedHandle,
    stdout: OwnedHandle,
    stderr: OwnedHandle,
}

impl RestrictedChild {
    fn terminate_before_job_assignment(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.process.raw(), 1);
            WaitForSingleObject(self.process.raw(), POST_TERMINATION_WAIT_MS);
        }
    }
}

#[allow(dead_code)]
fn spawn_restricted_suspended(
    plan: &TestExecutionPlan,
    root: &Path,
    workspace: &DetachedExecutionWorkspace,
    token: HANDLE,
) -> Result<RestrictedChild, BackendExecutionError> {
    let (stdout_read, stdout_write) = create_pipe_pair()?;
    let (stderr_read, stderr_write) = create_pipe_pair()?;
    let stdin = open_inheritable_null()?;

    let inherited_handles = [stdin.raw(), stdout_write.raw(), stderr_write.raw()];
    let attribute_list = ProcThreadAttributeList::with_handle_list(&inherited_handles)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.raw();
    startup.StartupInfo.hStdOutput = stdout_write.raw();
    startup.StartupInfo.hStdError = stderr_write.raw();
    startup.lpAttributeList = attribute_list.ptr;

    let application = wide_null(OsStr::new(plan.command.program.as_str()));
    let mut command_line = build_command_line(&plan.command.program, &plan.command.args)?;
    let current_directory = wide_null(root.as_os_str());
    let environment = build_environment_block(workspace);
    let mut process_info = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW;

    let created = unsafe {
        CreateProcessAsUserW(
            token,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags,
            environment.as_ptr().cast::<c_void>(),
            current_directory.as_ptr(),
            &startup.StartupInfo as *const STARTUPINFOW,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(BackendExecutionError::Io(std::io::Error::last_os_error()));
    }

    let process = OwnedHandle::new(process_info.hProcess)?;
    let thread = OwnedHandle::new(process_info.hThread)?;
    drop(attribute_list);
    drop(stdin);
    drop(stdout_write);
    drop(stderr_write);

    Ok(RestrictedChild {
        process,
        thread,
        stdout: stdout_read,
        stderr: stderr_read,
    })
}

fn spawn_lpac_suspended(
    plan: &TestExecutionPlan,
    root: &Path,
    workspace: &DetachedExecutionWorkspace,
    bundled_runner: &Path,
    token: HANDLE,
    appcontainer_sid: PSID,
) -> Result<RestrictedChild, BackendExecutionError> {
    let (stdout_read, stdout_write) = create_pipe_pair()?;
    let (stderr_read, stderr_write) = create_pipe_pair()?;
    let stdin = open_inheritable_null()?;
    let inherited_handles = [stdin.raw(), stdout_write.raw(), stderr_write.raw()];

    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: appcontainer_sid,
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let all_application_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let attribute_list = ProcThreadAttributeList::lpac_with_handle_list(
        &inherited_handles,
        &capabilities,
        &all_application_packages_policy,
    )?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.raw();
    startup.StartupInfo.hStdOutput = stdout_write.raw();
    startup.StartupInfo.hStdError = stderr_write.raw();
    startup.lpAttributeList = attribute_list.ptr;

    let runner_text = bundled_runner.to_string_lossy().into_owned();
    let application = wide_null(bundled_runner.as_os_str());
    let mut command_line = build_command_line(&runner_text, &plan.command.args)?;
    let current_directory = wide_null(root.as_os_str());
    let environment = build_lpac_environment_block(workspace, bundled_runner);
    let mut process_info = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW;

    let created = unsafe {
        CreateProcessAsUserW(
            token,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags,
            environment.as_ptr().cast::<c_void>(),
            current_directory.as_ptr(),
            &startup.StartupInfo as *const STARTUPINFOW,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(BackendExecutionError::Io(std::io::Error::last_os_error()));
    }

    let process = OwnedHandle::new(process_info.hProcess)?;
    let thread = OwnedHandle::new(process_info.hThread)?;
    drop(attribute_list);
    drop(stdin);
    drop(stdout_write);
    drop(stderr_write);

    Ok(RestrictedChild {
        process,
        thread,
        stdout: stdout_read,
        stderr: stderr_read,
    })
}

fn attest_production_lpac(
    process: HANDLE,
    expected_appcontainer_sid: PSID,
) -> Result<(), BackendExecutionError> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return Err(BackendExecutionError::JobSetup(format!(
            "OpenProcessToken(production LPAC): {}",
            std::io::Error::last_os_error()
        )));
    }
    let token = OwnedHandle::new(token)?;
    let is_appcontainer = token_bool(token.raw(), TokenIsAppContainer)?;
    let is_lpac = token_bool(token.raw(), TokenIsLessPrivilegedAppContainer)?;
    let restricted = unsafe { IsTokenRestricted(token.raw()) } != 0;
    let appcontainer_matches =
        token_appcontainer_sid_matches(token.raw(), expected_appcontainer_sid)?;
    let capabilities = token_capability_count(token.raw())?;
    let write_restricted = token_has_restricted_sid(token.raw())?;
    let low_integrity = token_has_low_integrity(token.raw())?;
    if !is_appcontainer
        || !is_lpac
        || !restricted
        || !write_restricted
        || !low_integrity
        || !appcontainer_matches
        || capabilities != 0
    {
        return Err(BackendExecutionError::JobSetup(
            "actual suspended QA child did not satisfy restricted low-integrity zero-capability LPAC identity"
                .to_string(),
        ));
    }
    Ok(())
}

fn token_bool(token: HANDLE, information_class: i32) -> Result<bool, BackendExecutionError> {
    let mut value = 0u32;
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            (&mut value as *mut u32).cast::<c_void>(),
            size_of::<u32>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "GetTokenInformation({information_class}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(value != 0)
}

fn token_information_buffer(
    token: HANDLE,
    information_class: i32,
) -> Result<Vec<usize>, BackendExecutionError> {
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            information_class,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(BackendExecutionError::JobSetup(format!(
            "GetTokenInformation({information_class}) returned no buffer size"
        )));
    }
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; words.max(1)];
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            storage.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "GetTokenInformation({information_class}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(storage)
}

fn token_appcontainer_sid_matches(
    token: HANDLE,
    expected: PSID,
) -> Result<bool, BackendExecutionError> {
    let storage = token_information_buffer(token, TokenAppContainerSid)?;
    let info = unsafe { &*(storage.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()) };
    if info.TokenAppContainer.is_null() {
        return Ok(false);
    }
    Ok(unsafe { EqualSid(info.TokenAppContainer, expected) } != 0)
}

fn token_capability_count(token: HANDLE) -> Result<u32, BackendExecutionError> {
    let storage = token_information_buffer(token, TokenCapabilities)?;
    let groups = unsafe { &*(storage.as_ptr().cast::<TOKEN_GROUPS>()) };
    Ok(groups.GroupCount)
}

fn token_has_restricted_sid(token: HANDLE) -> Result<bool, BackendExecutionError> {
    let mut expected = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut expected_len = expected.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinWriteRestrictedCodeSid,
            std::ptr::null_mut(),
            expected.as_mut_ptr().cast::<c_void>(),
            &mut expected_len,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "CreateWellKnownSid(WinWriteRestrictedCodeSid): {}",
            std::io::Error::last_os_error()
        )));
    }

    let storage = token_information_buffer(token, TokenRestrictedSids)?;
    let groups = unsafe { &*(storage.as_ptr().cast::<TOKEN_GROUPS>()) };
    let count = groups.GroupCount as usize;
    let entries_offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let entries_bytes = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .ok_or_else(|| {
            BackendExecutionError::JobSetup(
                "TokenRestrictedSids entry-byte count overflowed".to_string(),
            )
        })?;
    let required_bytes = entries_offset.checked_add(entries_bytes).ok_or_else(|| {
        BackendExecutionError::JobSetup(
            "TokenRestrictedSids buffer-size calculation overflowed".to_string(),
        )
    })?;
    let available_bytes = storage.len().saturating_mul(size_of::<usize>());
    if required_bytes > available_bytes {
        return Err(BackendExecutionError::JobSetup(format!(
            "TokenRestrictedSids reported {count} entries outside its returned buffer"
        )));
    }

    let entries = unsafe {
        storage
            .as_ptr()
            .cast::<u8>()
            .add(entries_offset)
            .cast::<SID_AND_ATTRIBUTES>()
    };
    for index in 0..count {
        let entry = unsafe { &*entries.add(index) };
        if !entry.Sid.is_null()
            && unsafe { EqualSid(entry.Sid, expected.as_mut_ptr().cast::<c_void>()) } != 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn token_has_low_integrity(token: HANDLE) -> Result<bool, BackendExecutionError> {
    let mut low_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut low_sid_len = low_sid.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLowLabelSid,
            std::ptr::null_mut(),
            low_sid.as_mut_ptr().cast::<c_void>(),
            &mut low_sid_len,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "CreateWellKnownSid(WinLowLabelSid): {}",
            std::io::Error::last_os_error()
        )));
    }

    let storage = token_information_buffer(token, TokenIntegrityLevel)?;
    let label = unsafe { &*(storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    if label.Label.Sid.is_null() {
        return Ok(false);
    }
    Ok(unsafe { EqualSid(label.Label.Sid, low_sid.as_mut_ptr().cast::<c_void>()) } != 0)
}

struct AppContainerProfileSid(PSID);

impl AppContainerProfileSid {
    fn open_or_create() -> Result<Self, BackendExecutionError> {
        let name = wide_null(OsStr::new(LPAC_PROFILE_NAME));
        let display = wide_null(OsStr::new(LPAC_PROFILE_DISPLAY_NAME));
        let description = wide_null(OsStr::new(LPAC_PROFILE_DESCRIPTION));
        let mut sid: PSID = std::ptr::null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid,
            )
        };
        if result >= 0 {
            if sid.is_null() {
                return Err(BackendExecutionError::JobSetup(
                    "CreateAppContainerProfile returned success without a SID".to_string(),
                ));
            }
            return Ok(Self(sid));
        }
        if result != hresult_from_win32(ERROR_ALREADY_EXISTS) {
            return Err(BackendExecutionError::JobSetup(format!(
                "CreateAppContainerProfile failed with HRESULT 0x{:08x}",
                result as u32
            )));
        }
        let derived =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if derived < 0 || sid.is_null() {
            return Err(BackendExecutionError::JobSetup(format!(
                "DeriveAppContainerSidFromAppContainerName failed with HRESULT 0x{:08x}",
                derived as u32
            )));
        }
        Ok(Self(sid))
    }

    const fn sid(&self) -> PSID {
        self.0
    }
}

impl Drop for AppContainerProfileSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeSid(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

const fn hresult_from_win32(code: u32) -> i32 {
    if code == 0 {
        0
    } else {
        (0x8007_0000u32 | (code & 0xffff)) as i32
    }
}

fn create_pipe_pair() -> Result<(OwnedHandle, OwnedHandle), std::io::Error> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let read = OwnedHandle::new(read)?;
    let write = OwnedHandle::new(write)?;
    if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((read, write))
}

fn open_inheritable_null() -> Result<OwnedHandle, std::io::Error> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let name = wide_null(OsStr::new("NUL"));
    OwnedHandle::new(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    })
}

struct ProcThreadAttributeList {
    _storage: Vec<usize>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl ProcThreadAttributeList {
    fn with_handle_list(handles: &[HANDLE]) -> Result<Self, std::io::Error> {
        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words.max(1)];
        let ptr = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeProcThreadAttributeList(ptr, 1, 0, &mut bytes) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let list = Self {
            _storage: storage,
            ptr,
        };
        if unsafe {
            UpdateProcThreadAttribute(
                list.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast::<c_void>(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(list)
    }
    fn lpac_with_handle_list(
        handles: &[HANDLE],
        capabilities: &SECURITY_CAPABILITIES,
        all_application_packages_policy: &u32,
    ) -> Result<Self, std::io::Error> {
        const ATTRIBUTE_COUNT: u32 = 3;
        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(
                std::ptr::null_mut(),
                ATTRIBUTE_COUNT,
                0,
                &mut bytes,
            );
        }
        if bytes == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words.max(1)];
        let ptr = storage.as_mut_ptr().cast::<c_void>();
        if unsafe {
            InitializeProcThreadAttributeList(ptr, ATTRIBUTE_COUNT, 0, &mut bytes)
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let list = Self {
            _storage: storage,
            ptr,
        };
        if unsafe {
            UpdateProcThreadAttribute(
                list.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast::<c_void>(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            UpdateProcThreadAttribute(
                list.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (capabilities as *const SECURITY_CAPABILITIES).cast::<c_void>(),
                size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            UpdateProcThreadAttribute(
                list.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                (all_application_packages_policy as *const u32).cast::<c_void>(),
                size_of::<u32>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(list)
    }

}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                DeleteProcThreadAttributeList(self.ptr);
            }
        }
    }
}

fn build_command_line(program: &str, args: &[String]) -> Result<Vec<u16>, BackendExecutionError> {
    let mut text = quote_windows_argument(program);
    for arg in args {
        text.push(' ');
        text.push_str(&quote_windows_argument(arg));
    }
    let mut wide = OsStr::new(text.as_str()).encode_wide().collect::<Vec<_>>();
    if wide.len() + 1 > WINDOWS_COMMAND_LINE_LIMIT {
        return Err(BackendExecutionError::InvalidToolchain(format!(
            "Windows command line exceeds {WINDOWS_COMMAND_LINE_LIMIT} UTF-16 code units"
        )));
    }
    wide.push(0);
    Ok(wide)
}

fn quote_windows_argument(argument: &str) -> String {
    let requires_quotes = argument.is_empty()
        || argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"');
    if !requires_quotes {
        return argument.to_string();
    }

    let mut output = String::with_capacity(argument.len() + 2);
    output.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                output.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                output.push('"');
                backslashes = 0;
            }
            _ => {
                output.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                output.push(character);
            }
        }
    }
    output.extend(std::iter::repeat_n('\\', backslashes * 2));
    output.push('"');
    output
}

fn build_environment_block(workspace: &DetachedExecutionWorkspace) -> Vec<u16> {
    let mut entries = BTreeMap::<String, OsString>::new();
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            entries.insert(key.to_string(), value);
        }
    }

    let temp = OsString::from(workspace.temp_path.as_str());
    let artifacts = Path::new(workspace.artifacts_path.as_str());
    entries.insert("TEMP".to_string(), temp.clone());
    entries.insert("TMP".to_string(), temp.clone());
    entries.insert("GOTMPDIR".to_string(), temp);
    entries.insert(
        "CARGO_TARGET_DIR".to_string(),
        artifacts.join("cargo-target").into_os_string(),
    );
    entries.insert(
        "GOCACHE".to_string(),
        artifacts.join("go-cache").into_os_string(),
    );
    entries.insert(
        "NPM_CONFIG_CACHE".to_string(),
        artifacts.join("npm-cache").into_os_string(),
    );
    entries.insert(
        "XDG_CACHE_HOME".to_string(),
        artifacts.join("cache").into_os_string(),
    );
    entries.insert(
        "CODETWIN_QA_EXECUTION".to_string(),
        OsString::from("windows_restricted_job_object"),
    );
    entries.insert("PYTHONNOUSERSITE".to_string(), OsString::from("1"));
    entries.insert("PYTHONDONTWRITEBYTECODE".to_string(), OsString::from("1"));
    entries.insert("NO_COLOR".to_string(), OsString::from("1"));
    entries.insert("CI".to_string(), OsString::from("1"));

    let mut ordered = entries.into_iter().collect::<Vec<_>>();
    ordered.sort_by_key(|entry| entry.0.to_ascii_uppercase());

    let mut block = Vec::new();
    for (key, value) in ordered {
        block.extend(OsStr::new(key.as_str()).encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn build_lpac_environment_block(
    workspace: &DetachedExecutionWorkspace,
    bundled_runner: &Path,
) -> Vec<u16> {
    let mut entries = BTreeMap::<String, OsString>::new();
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            entries.insert(key.to_string(), value);
        }
    }
    let temp = OsString::from(workspace.temp_path.as_str());
    let artifacts = Path::new(workspace.artifacts_path.as_str());
    entries.insert("TEMP".to_string(), temp.clone());
    entries.insert("TMP".to_string(), temp.clone());
    entries.insert("GOTMPDIR".to_string(), temp);
    entries.insert(
        "CARGO_TARGET_DIR".to_string(),
        artifacts.join("cargo-target").into_os_string(),
    );
    entries.insert(
        "GOCACHE".to_string(),
        artifacts.join("go-cache").into_os_string(),
    );
    entries.insert(
        "NPM_CONFIG_CACHE".to_string(),
        artifacts.join("npm-cache").into_os_string(),
    );
    entries.insert(
        "XDG_CACHE_HOME".to_string(),
        artifacts.join("cache").into_os_string(),
    );
    if let Some(parent) = bundled_runner.parent() {
        entries.insert("PATH".to_string(), parent.as_os_str().to_os_string());
    }
    entries.insert(
        "CODETWIN_QA_EXECUTION".to_string(),
        OsString::from("windows_zero_capability_lpac"),
    );
    entries.insert("PYTHONNOUSERSITE".to_string(), OsString::from("1"));
    entries.insert("PYTHONDONTWRITEBYTECODE".to_string(), OsString::from("1"));
    entries.insert("NO_COLOR".to_string(), OsString::from("1"));
    entries.insert("CI".to_string(), OsString::from("1"));

    let mut ordered = entries.into_iter().collect::<Vec<_>>();
    ordered.sort_by_key(|entry| entry.0.to_ascii_uppercase());
    let mut block = Vec::new();
    for (key, value) in ordered {
        block.extend(OsStr::new(key.as_str()).encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn parse_runner_result(
    runner: crate::TestRunnerKind,
    status: ExecutionRunStatus,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> (bool, Option<bool>) {
    if status != ExecutionRunStatus::Completed {
        return (false, None);
    }
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    let recognized = match runner {
        crate::TestRunnerKind::Pytest => {
            combined.contains(" passed")
                || combined.contains(" failed")
                || combined.contains(" error")
                || combined.contains("no tests ran")
        }
        crate::TestRunnerKind::RustCargoTest => combined.contains("test result:"),
        crate::TestRunnerKind::GoTest => {
            combined.contains("\npass")
                || combined.contains("\nfail")
                || combined.lines().any(|line| line.starts_with("ok\t") || line.starts_with("fail\t"))
        }
        crate::TestRunnerKind::Vitest => {
            combined.contains("test files") && (combined.contains("passed") || combined.contains("failed"))
        }
        crate::TestRunnerKind::Jest => {
            combined.contains("test suites:") && (combined.contains("passed") || combined.contains("failed"))
        }
        crate::TestRunnerKind::PhpUnit => {
            combined.contains("ok (") || combined.contains("failures!") || combined.contains("errors!")
        }
    };
    if !recognized {
        return (false, None);
    }
    (true, Some(exit_code == 0))
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn terminate_job_and_wait(job: HANDLE, process: HANDLE) -> Result<(), BackendExecutionError> {
    if unsafe { TerminateJobObject(job, 1) } == 0 {
        return Err(BackendExecutionError::JobTermination(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    match unsafe { WaitForSingleObject(process, POST_TERMINATION_WAIT_MS) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(BackendExecutionError::JobTermination(
            "process did not terminate within the bounded post-termination wait".to_string(),
        )),
        WAIT_FAILED => Err(BackendExecutionError::JobTermination(
            std::io::Error::last_os_error().to_string(),
        )),
        other => Err(BackendExecutionError::JobTermination(format!(
            "unexpected WaitForSingleObject result {other} after job termination"
        ))),
    }
}

fn process_exit_code(process: HANDLE) -> Result<i32, BackendExecutionError> {
    let mut code = 0u32;
    if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
        return Err(BackendExecutionError::Io(std::io::Error::last_os_error()));
    }
    Ok(i32::from_ne_bytes(code.to_ne_bytes()))
}

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
            let text_bound = bound_output(&lossy, max_bytes);
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
    use super::{build_command_line, build_environment_block, quote_windows_argument};
    use crate::DetachedExecutionWorkspace;

    #[test]
    fn windows_argument_quoting_handles_spaces_quotes_and_trailing_backslashes() {
        assert_eq!(quote_windows_argument("plain"), "plain");
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(quote_windows_argument("two words"), "\"two words\"");
        assert_eq!(quote_windows_argument("a\"b"), "\"a\\\"b\"");
        assert_eq!(
            quote_windows_argument("C:\\Program Files\\"),
            "\"C:\\Program Files\\\\\""
        );
    }

    #[test]
    fn command_line_is_nul_terminated() {
        let command = build_command_line(
            "C:\\Program Files\\Python\\python.exe",
            &["tests/test api.py".to_string()],
        )
        .expect("command line");
        assert_eq!(command.last(), Some(&0));
        assert_eq!(command.iter().filter(|value| **value == 0).count(), 1);
    }

    #[test]
    fn environment_is_double_nul_terminated_and_redirects_writes() {
        let workspace = DetachedExecutionWorkspace {
            root_path: "C:\\sandbox".to_string(),
            parent_path: "C:\\".to_string(),
            source_root: "D:\\repo".to_string(),
            inputs_path: "C:\\sandbox\\inputs".to_string(),
            artifacts_path: "C:\\sandbox\\artifacts".to_string(),
            temp_path: "C:\\sandbox\\temp".to_string(),
            files: Vec::new(),
            total_input_bytes: 0,
            source_files_read_only: true,
            dependency_complete: false,
            project_directories: Vec::new(),
            project_manifest_sha256: None,
        };
        let block = build_environment_block(&workspace);
        assert!(block.len() >= 2);
        assert_eq!(&block[block.len() - 2..], &[0, 0]);
        let text = String::from_utf16_lossy(&block);
        assert!(text.contains("CODETWIN_QA_EXECUTION=windows_restricted_job_object"));
        assert!(text.contains("TEMP=C:\\sandbox\\temp"));
        assert!(text.contains("CARGO_TARGET_DIR=C:\\sandbox\\artifacts\\cargo-target"));
    }
}
