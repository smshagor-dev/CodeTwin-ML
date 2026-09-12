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
        CloseHandle, SetHandleInformation, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Pipes::CreatePipe,
        Threading::{
            CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
            WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
        },
    },
};

use crate::workspace::identity::create_windows_write_restricted_token;
use crate::workspace::{probe_restricted_identity, DetachedExecutionWorkspace};
use crate::{
    bound_output, cleanup_detached_workspace, current_backend_info, prepare_detached_workspace,
    verify_execution_inputs, BackendExecutionError, BoundedOutput, ExecutionInputSnapshot,
    ExecutionPlanStatus, ExecutionRunStatus, RawExecutionOutcome, TestExecutionPlan,
};

const POST_TERMINATION_WAIT_MS: u32 = 5_000;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const WINDOWS_COMMAND_LINE_LIMIT: usize = 32_767;

pub(crate) fn execute_approved_plan(
    plan: &TestExecutionPlan,
    project_root: &Path,
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

    let root = canonical_project_root(project_root)?;
    verify_toolchain(plan, &root)?;
    verify_execution_inputs(&root, &plan.request.targets, snapshots)?;

    let workspace_parent = std::env::temp_dir();
    let workspace = prepare_detached_workspace(&root, &workspace_parent, snapshots)
        .map_err(|error| BackendExecutionError::JobSetup(format!("detached workspace: {error}")))?;
    let mut workspace_guard = WorkspaceGuard::new(workspace);
    let workspace = workspace_guard.workspace();

    let identity = probe_restricted_identity(workspace)
        .map_err(|error| BackendExecutionError::JobSetup(format!("restricted identity: {error}")))?;
    if !identity.restricted_primary_token_created
        || !identity.privileges_disabled
        || !identity.write_restricted
        || !identity.low_integrity
        || !identity.workspace_acl_applied
        || !identity.workspace_low_integrity_label
        || !identity.source_root_write_denied
        || !identity.staged_inputs_write_denied
        || !identity.artifacts_write_allowed
        || !identity.temp_write_allowed
        || identity.filesystem_isolation_promoted
        || identity.network_isolation_enforced
    {
        return Err(BackendExecutionError::JobSetup(
            "restricted identity readiness evidence did not match the required conservative contract"
                .to_string(),
        ));
    }

    let token = create_windows_write_restricted_token()
        .map_err(|error| BackendExecutionError::JobSetup(format!("restricted token: {error}")))?;
    let job = configure_job(plan)?;
    let mut child = spawn_restricted_suspended(plan, &root, workspace, token.raw())?;

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
            "unexpected initial thread suspend count {previous_suspend_count}"
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

    // Closing a KILL_ON_JOB_CLOSE job after the root runner exits terminates any surviving
    // descendants before pipe draining and workspace cleanup. This prevents detached children
    // from extending the execution lifetime or retaining writable workspace handles.
    drop(job);

    let stdout = receive_bounded_output(stdout_reader, OUTPUT_DRAIN_TIMEOUT)?;
    let stderr = receive_bounded_output(stderr_reader, OUTPUT_DRAIN_TIMEOUT)?;
    workspace_guard.cleanup()?;

    Ok(RawExecutionOutcome {
        status,
        exit_code: Some(exit_code),
        stdout,
        stderr,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        backend,
        parser_completed: false,
        tests_passed: None,
    })
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
    use std::fmt::Write as _;
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

struct WorkspaceGuard {
    workspace: Option<DetachedExecutionWorkspace>,
}

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
        return Err(BackendExecutionError::JobSetup(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(job)
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
