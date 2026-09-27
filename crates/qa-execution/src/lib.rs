mod backend;
mod external_provenance;
#[cfg(windows)]
mod windows_project_mirror;
#[cfg(windows)]
mod windows_restricted;
pub mod workspace;

pub use backend::{
    snapshot_execution_inputs, verify_execution_inputs, BackendControls, BackendExecutionError,
    ExecutionBackendInfo, ExecutionBackendKind, ExecutionInputSnapshot, RawExecutionOutcome,
    MAX_EXECUTION_INPUT_BYTES,
};
pub use external_provenance::{
    capture_external_read_surface, validate_approved_external_read_surface_shape,
    validate_declared_external_read_roots, verify_external_read_surface,
    ApprovedExternalReadSurface, DeclaredExternalReadRoot, ExternalProvenanceError,
    ExternalReadRootEvidence, ExternalReadRootKind, MAX_EXTERNAL_READ_BYTES,
    MAX_EXTERNAL_READ_DIRECTORIES, MAX_EXTERNAL_READ_FILES, MAX_EXTERNAL_READ_ROOTS,
};
pub use workspace::{
    cleanup_detached_workspace, prepare_dependency_complete_workspace, prepare_detached_workspace,
    probe_restricted_identity, verify_dependency_complete_workspace, verify_detached_workspace,
    DetachedExecutionWorkspace, DetachedWorkspaceFile, RestrictedIdentityError,
    RestrictedIdentityEvidence, WorkspaceError, MAX_DETACHED_WORKSPACE_BYTES,
    MAX_PROJECT_MIRROR_BYTES, MAX_PROJECT_MIRROR_DIRECTORIES, MAX_PROJECT_MIRROR_FILES,
};

use std::{
    collections::BTreeSet,
    path::{Component, Path},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_TARGETS: usize = 128;
pub const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1000;
pub const MAX_CPU_SECONDS: u64 = 10 * 60;
pub const MAX_MEMORY_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestRunnerKind {
    Pytest,
    RustCargoTest,
    GoTest,
    Vitest,
    Jest,
    PhpUnit,
}

impl TestRunnerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pytest => "pytest",
            Self::RustCargoTest => "rust_cargo_test",
            Self::GoTest => "go_test",
            Self::Vitest => "vitest",
            Self::Jest => "jest",
            Self::PhpUnit => "php_unit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPlanStatus {
    Blocked,
    Planned,
    Approved,
}

impl ExecutionPlanStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Planned => "planned",
            Self::Approved => "approved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionRunStatus {
    Queued,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    InfrastructureError,
}

impl ExecutionRunStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::InfrastructureError => "infrastructure_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedToolchain {
    pub runner: TestRunnerKind,
    pub executable_path: String,
    pub version: String,
    pub sha256: Option<String>,
    pub trusted_by_user: bool,
    #[serde(default)]
    pub declared_external_read_roots: Vec<DeclaredExternalReadRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub timeout_ms: u64,
    pub cpu_time_seconds: u64,
    pub memory_bytes: u64,
    pub max_output_bytes: usize,
    pub max_targets: usize,
    pub require_process_isolation: bool,
    pub require_filesystem_isolation: bool,
    pub require_network_isolation: bool,
    pub require_cpu_limit: bool,
    pub require_memory_limit: bool,
    pub require_cancellation: bool,
    pub inherit_host_environment: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            timeout_ms: 120_000,
            cpu_time_seconds: 60,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            max_output_bytes: 512 * 1024,
            max_targets: 32,
            require_process_isolation: true,
            require_filesystem_isolation: true,
            require_network_isolation: true,
            require_cpu_limit: true,
            require_memory_limit: true,
            require_cancellation: true,
            inherit_host_environment: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    pub process_isolation: bool,
    pub filesystem_isolation: bool,
    pub network_isolation: bool,
    pub cpu_limit: bool,
    pub memory_limit: bool,
    pub cancellation: bool,
}

impl SandboxCapabilities {
    pub const fn planning_only() -> Self {
        Self {
            process_isolation: false,
            filesystem_isolation: false,
            network_isolation: false,
            cpu_limit: false,
            memory_limit: false,
            cancellation: false,
        }
    }

    pub const fn fully_enforced() -> Self {
        Self {
            process_isolation: true,
            filesystem_isolation: true,
            network_isolation: true,
            cpu_limit: true,
            memory_limit: true,
            cancellation: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestExecutionRequest {
    pub runner: TestRunnerKind,
    pub targets: Vec<String>,
    pub discovery_run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCommand {
    pub program: String,
    pub args: Vec<String>,
    pub uses_shell: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestExecutionPlan {
    pub status: ExecutionPlanStatus,
    pub blocking_reasons: Vec<String>,
    pub request: TestExecutionRequest,
    pub toolchain: TrustedToolchain,
    pub policy: SandboxPolicy,
    pub capabilities: SandboxCapabilities,
    pub command: ExecutionCommand,
    #[serde(default)]
    pub approved_project_manifest_sha256: Option<String>,
    #[serde(default)]
    pub approved_external_read_surface: Option<ApprovedExternalReadSurface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedOutput {
    pub text: String,
    pub original_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("at least one explicit test target is required")]
    NoTargets,
    #[error("test target count exceeds the bounded maximum of {0}")]
    TooManyTargets(usize),
    #[error("unsafe test target path: {0}")]
    UnsafeTarget(String),
    #[error("trusted toolchain runner does not match requested runner")]
    RunnerMismatch,
    #[error("runner executable must be an absolute path")]
    ExecutableNotAbsolute,
    #[error("runner executable has not been explicitly trusted")]
    ToolchainNotTrusted,
    #[error("runner version must not be empty")]
    MissingToolchainVersion,
    #[error("invalid external read roots: {0}")]
    InvalidExternalReadRoots(String),
    #[error("invalid sandbox policy: {0}")]
    InvalidPolicy(String),
    #[error("Rust cargo test targets must be conventional tests/*.rs files: {0}")]
    InvalidRustTarget(String),
}

pub fn current_backend_info() -> ExecutionBackendInfo {
    backend::current_backend_info()
}

pub fn build_execution_plan(
    request: TestExecutionRequest,
    toolchain: TrustedToolchain,
    policy: SandboxPolicy,
    capabilities: SandboxCapabilities,
) -> Result<TestExecutionPlan, PlanError> {
    validate_request(&request, &toolchain, &policy)?;
    let command = build_command(&request, &toolchain)?;
    let blocking_reasons = missing_capabilities(&policy, &capabilities);
    let status = if blocking_reasons.is_empty() {
        ExecutionPlanStatus::Planned
    } else {
        ExecutionPlanStatus::Blocked
    };
    Ok(TestExecutionPlan {
        status,
        blocking_reasons,
        request,
        toolchain,
        policy,
        capabilities,
        command,
        approved_project_manifest_sha256: None,
        approved_external_read_surface: None,
    })
}

pub fn execute_approved_plan(
    plan: &TestExecutionPlan,
    project_root: impl AsRef<Path>,
    snapshots: &[ExecutionInputSnapshot],
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<RawExecutionOutcome, BackendExecutionError> {
    if !strict_execution_policy(&plan.policy) {
        return Err(BackendExecutionError::PlanBlocked);
    }
    let backend_info = current_backend_info();
    let rebuilt = build_execution_plan(
        plan.request.clone(),
        plan.toolchain.clone(),
        plan.policy.clone(),
        backend_info.capabilities.clone(),
    )
    .map_err(|error| BackendExecutionError::InvalidToolchain(error.to_string()))?;
    if rebuilt.command != plan.command || rebuilt.capabilities != plan.capabilities {
        return Err(BackendExecutionError::CapabilityMismatch);
    }
    if !rebuilt.blocking_reasons.is_empty() {
        return Err(BackendExecutionError::PlanBlocked);
    }

    let project_root = project_root.as_ref();
    #[cfg(windows)]
    {
        windows_project_mirror::execute_approved_plan(plan, project_root, snapshots, cancelled)
    }
    #[cfg(not(windows))]
    {
        backend::execute_approved_plan(plan, project_root, snapshots, cancelled)
    }
}

pub fn bound_output(text: &str, max_bytes: usize) -> BoundedOutput {
    let original_bytes = text.len();
    if original_bytes <= max_bytes {
        return BoundedOutput {
            text: text.to_string(),
            original_bytes,
            truncated: false,
        };
    }
    let cutoff = text
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= max_bytes)
        .last()
        .unwrap_or(0);
    BoundedOutput {
        text: text[..cutoff].to_string(),
        original_bytes,
        truncated: true,
    }
}

pub const fn test_verdict(
    status: ExecutionRunStatus,
    parser_completed: bool,
    exit_code: Option<i32>,
) -> Option<bool> {
    if !matches!(status, ExecutionRunStatus::Completed) || !parser_completed {
        return None;
    }
    match exit_code {
        Some(code) => Some(code == 0),
        None => None,
    }
}

fn strict_execution_policy(policy: &SandboxPolicy) -> bool {
    policy.require_process_isolation
        && policy.require_filesystem_isolation
        && policy.require_network_isolation
        && policy.require_cpu_limit
        && policy.require_memory_limit
        && policy.require_cancellation
        && !policy.inherit_host_environment
}

fn validate_request(
    request: &TestExecutionRequest,
    toolchain: &TrustedToolchain,
    policy: &SandboxPolicy,
) -> Result<(), PlanError> {
    if request.targets.is_empty() {
        return Err(PlanError::NoTargets);
    }
    if policy.max_targets == 0 || policy.max_targets > MAX_TARGETS {
        return Err(PlanError::InvalidPolicy(format!(
            "max_targets must be between 1 and {MAX_TARGETS}"
        )));
    }
    if request.targets.len() > policy.max_targets {
        return Err(PlanError::TooManyTargets(policy.max_targets));
    }
    for target in &request.targets {
        validate_target(target)?;
    }
    if request.runner != toolchain.runner {
        return Err(PlanError::RunnerMismatch);
    }
    if !Path::new(&toolchain.executable_path).is_absolute() {
        return Err(PlanError::ExecutableNotAbsolute);
    }
    if !toolchain.trusted_by_user {
        return Err(PlanError::ToolchainNotTrusted);
    }
    if toolchain.version.trim().is_empty() {
        return Err(PlanError::MissingToolchainVersion);
    }
    validate_declared_external_read_roots(&toolchain.declared_external_read_roots)
        .map_err(|error| PlanError::InvalidExternalReadRoots(error.to_string()))?;
    validate_policy(policy)
}

fn validate_target(target: &str) -> Result<(), PlanError> {
    if target.trim().is_empty() || target.contains('\0') || target.contains('\\') {
        return Err(PlanError::UnsafeTarget(target.to_string()));
    }
    let path = Path::new(target);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PlanError::UnsafeTarget(target.to_string()));
    }
    Ok(())
}

fn validate_policy(policy: &SandboxPolicy) -> Result<(), PlanError> {
    if policy.timeout_ms == 0 || policy.timeout_ms > MAX_TIMEOUT_MS {
        return Err(PlanError::InvalidPolicy(format!(
            "timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"
        )));
    }
    if policy.cpu_time_seconds == 0 || policy.cpu_time_seconds > MAX_CPU_SECONDS {
        return Err(PlanError::InvalidPolicy(format!(
            "cpu_time_seconds must be between 1 and {MAX_CPU_SECONDS}"
        )));
    }
    if policy.memory_bytes == 0 || policy.memory_bytes > MAX_MEMORY_BYTES {
        return Err(PlanError::InvalidPolicy(format!(
            "memory_bytes must be between 1 and {MAX_MEMORY_BYTES}"
        )));
    }
    if policy.max_output_bytes == 0 || policy.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(PlanError::InvalidPolicy(format!(
            "max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}"
        )));
    }
    if policy.inherit_host_environment {
        return Err(PlanError::InvalidPolicy(
            "inherit_host_environment must remain false".to_string(),
        ));
    }
    Ok(())
}

fn missing_capabilities(policy: &SandboxPolicy, capabilities: &SandboxCapabilities) -> Vec<String> {
    let mut reasons = Vec::new();
    if policy.require_process_isolation && !capabilities.process_isolation {
        reasons.push("process isolation is not enforced by the selected backend".to_string());
    }
    if policy.require_filesystem_isolation && !capabilities.filesystem_isolation {
        reasons
            .push("filesystem/write isolation is not enforced by the selected backend".to_string());
    }
    if policy.require_network_isolation && !capabilities.network_isolation {
        reasons.push("network isolation is not enforced by the selected backend".to_string());
    }
    if policy.require_cpu_limit && !capabilities.cpu_limit {
        reasons.push("CPU limits are not enforced by the selected backend".to_string());
    }
    if policy.require_memory_limit && !capabilities.memory_limit {
        reasons.push("memory limits are not enforced by the selected backend".to_string());
    }
    if policy.require_cancellation && !capabilities.cancellation {
        reasons.push("reliable cancellation is not enforced by the selected backend".to_string());
    }
    reasons
}

fn build_command(
    request: &TestExecutionRequest,
    toolchain: &TrustedToolchain,
) -> Result<ExecutionCommand, PlanError> {
    let mut args = Vec::new();
    match request.runner {
        TestRunnerKind::Pytest => args.extend(request.targets.iter().cloned()),
        TestRunnerKind::Vitest => {
            args.push("run".to_string());
            args.extend(request.targets.iter().cloned());
        }
        TestRunnerKind::Jest | TestRunnerKind::PhpUnit => {
            args.extend(request.targets.iter().cloned());
        }
        TestRunnerKind::RustCargoTest => {
            args.push("test".to_string());
            let mut names = BTreeSet::new();
            for target in &request.targets {
                let path = Path::new(target);
                let first_component = path
                    .components()
                    .next()
                    .and_then(|item| item.as_os_str().to_str());
                if path.extension().and_then(|value| value.to_str()) != Some("rs")
                    || first_component != Some("tests")
                {
                    return Err(PlanError::InvalidRustTarget(target.clone()));
                }
                let Some(name) = path.file_stem().and_then(|value| value.to_str()) else {
                    return Err(PlanError::InvalidRustTarget(target.clone()));
                };
                names.insert(name.to_string());
            }
            for name in names {
                args.push("--test".to_string());
                args.push(name);
            }
        }
        TestRunnerKind::GoTest => {
            args.push("test".to_string());
            let mut packages = BTreeSet::new();
            for target in &request.targets {
                let path = Path::new(target);
                let parent = if path.extension().and_then(|value| value.to_str()) == Some("go") {
                    path.parent().unwrap_or_else(|| Path::new("."))
                } else {
                    path
                };
                let text = parent.to_string_lossy().replace('\\', "/");
                let package = if text == "." {
                    "./".to_string()
                } else if text.starts_with("./") {
                    text
                } else {
                    format!("./{text}")
                };
                packages.insert(package);
            }
            args.extend(packages);
        }
    }
    Ok(ExecutionCommand {
        program: toolchain.executable_path.clone(),
        args,
        uses_shell: false,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        bound_output, build_execution_plan, execute_approved_plan, test_verdict,
        ExecutionPlanStatus, ExecutionRunStatus, PlanError, SandboxCapabilities, SandboxPolicy,
        TestExecutionRequest, TestRunnerKind, TrustedToolchain,
    };

    fn toolchain(runner: TestRunnerKind) -> TrustedToolchain {
        TrustedToolchain {
            runner,
            executable_path: if cfg!(windows) {
                "C:/trusted/bin/runner.exe".into()
            } else {
                "/trusted/bin/runner".into()
            },
            version: "1.0.0".into(),
            sha256: Some("a".repeat(64)),
            trusted_by_user: true,
            declared_external_read_roots: Vec::new(),
        }
    }

    #[test]
    fn planning_only_backend_blocks_execution() {
        let plan = build_execution_plan(
            TestExecutionRequest {
                runner: TestRunnerKind::Pytest,
                targets: vec!["tests/test_api.py".into()],
                discovery_run_id: Some("qa-run".into()),
            },
            toolchain(TestRunnerKind::Pytest),
            SandboxPolicy::default(),
            SandboxCapabilities::planning_only(),
        )
        .expect("plan");
        assert_eq!(plan.status, ExecutionPlanStatus::Blocked);
        assert_eq!(plan.blocking_reasons.len(), 6);
        assert!(!plan.command.uses_shell);
        assert!(plan.approved_project_manifest_sha256.is_none());
        assert!(plan.approved_external_read_surface.is_none());
    }

    #[test]
    fn fully_enforced_backend_produces_no_shell_plan() {
        let plan = build_execution_plan(
            TestExecutionRequest {
                runner: TestRunnerKind::Vitest,
                targets: vec!["src/widget.test.ts".into()],
                discovery_run_id: None,
            },
            toolchain(TestRunnerKind::Vitest),
            SandboxPolicy::default(),
            SandboxCapabilities::fully_enforced(),
        )
        .expect("plan");
        assert_eq!(plan.status, ExecutionPlanStatus::Planned);
        assert_eq!(
            plan.command.args,
            vec!["run".to_string(), "src/widget.test.ts".to_string()]
        );
        assert!(!plan.command.uses_shell);
        assert!(plan.approved_project_manifest_sha256.is_none());
        assert!(plan.approved_external_read_surface.is_none());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)] // reads as "default, minus each floor"
    fn relaxed_policy_cannot_bypass_execution_capability_floor() {
        let mut policy = SandboxPolicy::default();
        policy.require_process_isolation = false;
        policy.require_filesystem_isolation = false;
        policy.require_network_isolation = false;
        policy.require_cpu_limit = false;
        policy.require_memory_limit = false;
        policy.require_cancellation = false;
        let mut plan = build_execution_plan(
            TestExecutionRequest {
                runner: TestRunnerKind::Pytest,
                targets: vec!["tests/test_api.py".into()],
                discovery_run_id: None,
            },
            toolchain(TestRunnerKind::Pytest),
            policy,
            SandboxCapabilities::planning_only(),
        )
        .expect("relaxed plan");
        plan.status = ExecutionPlanStatus::Approved;
        let result =
            execute_approved_plan(&plan, ".", &[], &std::sync::atomic::AtomicBool::new(false));
        assert!(matches!(
            result,
            Err(super::BackendExecutionError::PlanBlocked)
        ));
    }

    #[test]
    fn rejects_path_traversal_and_untrusted_toolchain() {
        let error = build_execution_plan(
            TestExecutionRequest {
                runner: TestRunnerKind::Pytest,
                targets: vec!["../outside.py".into()],
                discovery_run_id: None,
            },
            toolchain(TestRunnerKind::Pytest),
            SandboxPolicy::default(),
            SandboxCapabilities::fully_enforced(),
        )
        .expect_err("unsafe target");
        assert_eq!(error, PlanError::UnsafeTarget("../outside.py".into()));

        let mut untrusted = toolchain(TestRunnerKind::Pytest);
        untrusted.trusted_by_user = false;
        let error = build_execution_plan(
            TestExecutionRequest {
                runner: TestRunnerKind::Pytest,
                targets: vec!["tests/test_api.py".into()],
                discovery_run_id: None,
            },
            untrusted,
            SandboxPolicy::default(),
            SandboxCapabilities::fully_enforced(),
        )
        .expect_err("untrusted toolchain");
        assert_eq!(error, PlanError::ToolchainNotTrusted);
    }

    #[test]
    fn bounds_output_on_utf8_boundary() {
        let result = bound_output("abЖcd", 4);
        assert_eq!(result.text, "abЖ");
        assert_eq!(result.original_bytes, 6);
        assert!(result.truncated);
    }

    #[test]
    fn verdict_requires_completed_execution_and_parser() {
        assert_eq!(
            test_verdict(ExecutionRunStatus::Completed, true, Some(0)),
            Some(true)
        );
        assert_eq!(
            test_verdict(ExecutionRunStatus::Completed, true, Some(1)),
            Some(false)
        );
        assert_eq!(
            test_verdict(ExecutionRunStatus::Completed, false, Some(0)),
            None
        );
        assert_eq!(
            test_verdict(ExecutionRunStatus::TimedOut, true, Some(1)),
            None
        );
        assert_eq!(
            test_verdict(ExecutionRunStatus::InfrastructureError, true, Some(1)),
            None
        );
    }
}
