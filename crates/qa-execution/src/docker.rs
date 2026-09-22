use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::{
    cleanup_detached_workspace, prepare_dependency_complete_workspace,
    verify_external_read_surface, BackendControls, BackendExecutionError, BoundedOutput,
    ExecutionBackendInfo, ExecutionBackendKind, ExecutionRunStatus, RawExecutionOutcome,
    TestExecutionPlan, TestRunnerKind,
};

pub fn validate_pinned_container_image(image: &str) -> Result<(), BackendExecutionError> {
    let image = image.trim();
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return Err(BackendExecutionError::InvalidToolchain(
            "Docker image must be pinned as repository@sha256:<64-hex-digest>".to_string(),
        ));
    };
    if name.is_empty()
        || name.len() > 512
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'/' | b':' | b'_' | b'-')
        })
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(BackendExecutionError::InvalidToolchain(
            "Docker image reference is not a valid pinned digest".to_string(),
        ));
    }
    Ok(())
}

pub fn docker_backend_info(
    docker_executable: &str,
    image: &str,
) -> Result<ExecutionBackendInfo, BackendExecutionError> {
    validate_pinned_container_image(image)?;
    let docker = canonical_regular_file(docker_executable)?;
    let version = Command::new(&docker)
        .args(["version", "--format", "{{.Server.Version}}"])
        .env_clear()
        .output()?;
    if !version.status.success() || version.stdout.is_empty() {
        return Err(BackendExecutionError::BackendUnavailable);
    }
    let inspect = Command::new(&docker)
        .args(["image", "inspect", image, "--format", "{{json .RepoDigests}}"])
        .env_clear()
        .output()?;
    if !inspect.status.success() {
        return Err(BackendExecutionError::BackendUnavailable);
    }
    let repo_digests = String::from_utf8_lossy(&inspect.stdout);
    if !repo_digests.contains(image) {
        return Err(BackendExecutionError::InvalidToolchain(
            "local Docker image does not expose the approved repository digest".to_string(),
        ));
    }

    Ok(ExecutionBackendInfo {
        kind: ExecutionBackendKind::DockerHardened,
        execution_available: true,
        capabilities: crate::SandboxCapabilities::fully_enforced(),
        controls: BackendControls {
            job_object: false,
            kill_on_job_close: true,
            job_cpu_time_limit: true,
            job_memory_limit: true,
            bounded_wall_clock: true,
            bounded_output: true,
            sanitized_environment: true,
            trusted_toolchain_hash: true,
            input_hash_verification: true,
            process_created_suspended: false,
            process_assigned_before_resume: false,
        },
        limitations: vec![
            "Docker Desktop/Engine remains part of the trusted computing base.".to_string(),
            "The selected image must already exist locally; CodeTwin uses --pull=never.".to_string(),
            "Project files are mounted read-only; tests requiring source-tree writes must use /tmp or /artifacts.".to_string(),
        ],
    })
}

pub fn execute_approved_plan_in_docker(
    plan: &TestExecutionPlan,
    project_root: impl AsRef<Path>,
    snapshots: &[crate::ExecutionInputSnapshot],
    image: &str,
    cancelled: &AtomicBool,
) -> Result<RawExecutionOutcome, BackendExecutionError> {
    if plan.status != crate::ExecutionPlanStatus::Approved {
        return Err(BackendExecutionError::PlanNotApproved);
    }
    if !plan.blocking_reasons.is_empty()
        || plan.capabilities != crate::SandboxCapabilities::fully_enforced()
    {
        return Err(BackendExecutionError::PlanBlocked);
    }
    if plan.command.uses_shell {
        return Err(BackendExecutionError::ShellForbidden);
    }
    validate_pinned_container_image(image)?;

    let project_root = fs::canonicalize(project_root.as_ref())
        .map_err(|error| BackendExecutionError::InvalidProjectRoot(error.to_string()))?;
    let docker = verify_docker_toolchain(plan, &project_root)?;
    let backend = docker_backend_info(
        docker
            .to_str()
            .ok_or_else(|| BackendExecutionError::InvalidToolchain("Docker path is not UTF-8".to_string()))?,
        image,
    )?;
    crate::verify_execution_inputs(&project_root, &plan.request.targets, snapshots)?;
    let approved_surface = plan
        .approved_external_read_surface
        .as_ref()
        .ok_or(BackendExecutionError::PlanNotApproved)?;
    verify_external_read_surface(
        &plan.toolchain.declared_external_read_roots,
        approved_surface,
        &project_root,
    )
    .map_err(|error| BackendExecutionError::InvalidToolchain(error.to_string()))?;

    let workspace = prepare_dependency_complete_workspace(
        &project_root,
        std::env::temp_dir(),
        snapshots,
    )
    .map_err(|error| BackendExecutionError::InvalidProjectRoot(error.to_string()))?;
    let execution = (|| {
        if workspace.project_manifest_sha256.as_deref()
            != plan.approved_project_manifest_sha256.as_deref()
        {
            return Err(BackendExecutionError::StaleInput(
                "dependency-complete project mirror no longer matches approved manifest".to_string(),
            ));
        }

        let name = container_name();
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--pull=never".to_string(),
            "--name".to_string(),
            name.clone(),
            "--network".to_string(),
            "none".to_string(),
            "--read-only".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--pids-limit".to_string(),
            "128".to_string(),
            "--memory".to_string(),
            plan.policy.memory_bytes.to_string(),
            "--cpus".to_string(),
            "1.0".to_string(),
            "--user".to_string(),
            "65534:65534".to_string(),
            "--tmpfs".to_string(),
            "/tmp:rw,noexec,nosuid,nodev,size=67108864".to_string(),
            "--mount".to_string(),
            format!("type=bind,source={},target=/workspace,readonly", workspace.inputs_path),
            "--tmpfs".to_string(),
            "/artifacts:rw,nosuid,nodev,size=67108864".to_string(),
            "--workdir".to_string(),
            "/workspace".to_string(),
            "--env".to_string(),
            "CI=1".to_string(),
            "--env".to_string(),
            "HOME=/tmp".to_string(),
            image.to_string(),
        ];
        append_container_command(&mut args, plan);

        let mut command = Command::new(&docker);
        command
            .args(&args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut child = command.spawn()?;
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
        let stdout_reader = spawn_reader(stdout, stdout_budget);
        let stderr_reader = spawn_reader(stderr, stderr_budget);
        let timeout = Duration::from_millis(plan.policy.timeout_ms);
        let mut status = ExecutionRunStatus::Completed;
        let mut exit_code = None;

        loop {
            if cancelled.load(Ordering::SeqCst) {
                kill_container(&docker, &name);
                let _ = child.kill();
                status = ExecutionRunStatus::Cancelled;
                break;
            }
            if started.elapsed() >= timeout {
                kill_container(&docker, &name);
                let _ = child.kill();
                status = ExecutionRunStatus::TimedOut;
                break;
            }
            if let Some(exit) = child.try_wait()? {
                exit_code = exit.code();
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        if status != ExecutionRunStatus::Completed {
            let _ = child.wait();
        }

        let stdout = receive_reader(stdout_reader)?;
        let stderr = receive_reader(stderr_reader)?;
        let parser_completed = status == ExecutionRunStatus::Completed && exit_code.is_some();
        let tests_passed = if parser_completed {
            exit_code.map(|code| code == 0)
        } else {
            None
        };
        Ok(RawExecutionOutcome {
            status,
            exit_code,
            stdout,
            stderr,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            backend,
            parser_completed,
            tests_passed,
        })
    })();
    let cleanup = cleanup_detached_workspace(&workspace)
        .map_err(|error| BackendExecutionError::InvalidProjectRoot(error.to_string()));
    match (execution, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn append_container_command(args: &mut Vec<String>, plan: &TestExecutionPlan) {
    match plan.request.runner {
        TestRunnerKind::Pytest => {
            args.extend(["python".to_string(), "-m".to_string(), "pytest".to_string()]);
            args.extend(plan.command.args.iter().cloned());
        }
        TestRunnerKind::RustCargoTest => {
            args.push("cargo".to_string());
            args.extend(plan.command.args.iter().cloned());
        }
        TestRunnerKind::GoTest => {
            args.push("go".to_string());
            args.extend(plan.command.args.iter().cloned());
        }
        TestRunnerKind::Vitest => {
            args.push("./node_modules/.bin/vitest".to_string());
            args.extend(plan.command.args.iter().cloned());
        }
        TestRunnerKind::Jest => {
            args.push("./node_modules/.bin/jest".to_string());
            args.extend(plan.command.args.iter().cloned());
        }
        TestRunnerKind::PhpUnit => {
            args.push("./vendor/bin/phpunit".to_string());
            args.extend(plan.command.args.iter().cloned());
        }
    }
}

fn canonical_regular_file(path: &str) -> Result<PathBuf, BackendExecutionError> {
    let input = Path::new(path);
    if !input.is_absolute() {
        return Err(BackendExecutionError::InvalidToolchain(
            "Docker executable must be an absolute path".to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(input)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackendExecutionError::InvalidToolchain(
            "Docker executable must be a regular file".to_string(),
        ));
    }
    fs::canonicalize(input).map_err(Into::into)
}

fn verify_docker_toolchain(
    plan: &TestExecutionPlan,
    project_root: &Path,
) -> Result<PathBuf, BackendExecutionError> {
    let docker = canonical_regular_file(&plan.toolchain.executable_path)?;
    if docker.starts_with(project_root) {
        return Err(BackendExecutionError::ToolchainInsideProject);
    }
    let expected = plan
        .toolchain
        .sha256
        .as_deref()
        .ok_or(BackendExecutionError::MissingToolchainHash)?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackendExecutionError::ToolchainHashMismatch);
    }
    if sha256_file(&docker)? != expected.to_ascii_lowercase() {
        return Err(BackendExecutionError::ToolchainHashMismatch);
    }
    Ok(docker)
}

fn sha256_file(path: &Path) -> Result<String, BackendExecutionError> {
    let mut stream = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn container_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("codetwin-qa-{}-{nanos}", std::process::id())
}

fn kill_container(docker: &Path, name: &str) {
    let _ = Command::new(docker)
        .args(["kill", name])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn spawn_reader<R>(
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
            let text = String::from_utf8_lossy(&captured).into_owned();
            Ok(BoundedOutput {
                text,
                original_bytes,
                truncated: original_bytes > captured.len(),
            })
        })();
        let _ = sender.send(result);
    });
    receiver
}

fn receive_reader(
    receiver: mpsc::Receiver<Result<BoundedOutput, std::io::Error>>,
) -> Result<BoundedOutput, BackendExecutionError> {
    receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| BackendExecutionError::OutputReaderTimeout)?
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::validate_pinned_container_image;

    #[test]
    fn docker_image_must_be_digest_pinned() {
        assert!(validate_pinned_container_image(
            "ghcr.io/example/codetwin-python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_ok());
        assert!(validate_pinned_container_image("python:3.12").is_err());
        assert!(validate_pinned_container_image("latest").is_err());
    }
}
