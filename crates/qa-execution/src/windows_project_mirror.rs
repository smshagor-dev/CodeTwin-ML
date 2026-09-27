use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[path = "windows_lpac_bundle.rs"]
mod bundle;
#[path = "windows_lpac.rs"]
mod lpac;
#[path = "windows_toolchain_guard.rs"]
mod toolchain_guard;

pub(crate) use lpac::assert_lpac_profile_network_isolation;

use crate::{
    cleanup_detached_workspace, prepare_dependency_complete_workspace, probe_restricted_identity,
    verify_external_read_surface, BackendExecutionError, DetachedExecutionWorkspace,
    ExecutionInputSnapshot, RawExecutionOutcome, TestExecutionPlan,
};

pub(crate) fn execute_approved_plan(
    plan: &TestExecutionPlan,
    project_root: &Path,
    snapshots: &[ExecutionInputSnapshot],
    cancelled: &AtomicBool,
) -> Result<RawExecutionOutcome, BackendExecutionError> {
    let expected_manifest = plan
        .approved_project_manifest_sha256
        .as_deref()
        .ok_or_else(|| {
            BackendExecutionError::JobSetup(
                "approved execution plan is missing its project manifest binding".to_string(),
            )
        })?;
    if expected_manifest.len() != 64
        || !expected_manifest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(BackendExecutionError::JobSetup(
            "approved project manifest SHA-256 is malformed".to_string(),
        ));
    }
    let approved_external_surface =
        plan.approved_external_read_surface
            .as_ref()
            .ok_or_else(|| {
                BackendExecutionError::JobSetup(
                    "approved execution plan is missing its external read-surface binding"
                        .to_string(),
                )
            })?;

    let workspace_parent = std::env::temp_dir();
    let workspace = prepare_dependency_complete_workspace(
        project_root,
        &workspace_parent,
        snapshots,
    )
    .map_err(|error| {
        BackendExecutionError::JobSetup(format!("dependency-complete project mirror: {error}"))
    })?;
    let mut guard = ProjectMirrorGuard::new(workspace);
    let workspace = guard.workspace();

    if !workspace.dependency_complete {
        return Err(BackendExecutionError::JobSetup(
            "dependency-complete project mirror did not retain its completeness evidence"
                .to_string(),
        ));
    }
    let actual_manifest = workspace
        .project_manifest_sha256
        .as_deref()
        .ok_or_else(|| {
            BackendExecutionError::JobSetup(
                "dependency-complete project mirror did not retain its manifest digest".to_string(),
            )
        })?;
    if actual_manifest != expected_manifest {
        return Err(BackendExecutionError::JobSetup(format!(
            "approved project manifest mismatch: expected {expected_manifest}, prepared {actual_manifest}"
        )));
    }

    let _toolchain_guard =
        toolchain_guard::lock_and_attest_external_read_surface(plan, project_root)?;
    verify_external_read_surface(
        &plan.toolchain.declared_external_read_roots,
        approved_external_surface,
        project_root,
    )
    .map_err(|error| {
        BackendExecutionError::JobSetup(format!("external read-surface provenance: {error}"))
    })?;

    let identity = probe_restricted_identity(workspace).map_err(|error| {
        BackendExecutionError::JobSetup(format!("project-mirror restricted identity: {error}"))
    })?;
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
            "project mirror identity evidence did not match the required conservative contract"
                .to_string(),
        ));
    }

    let lpac_bundle =
        bundle::prepare_lpac_execution_bundle(plan, approved_external_surface, workspace)?;
    if !lpac_bundle.evidence().satisfies_readiness_contract()
        || !lpac_bundle
            .root_path()
            .starts_with(Path::new(&workspace.root_path))
        || !lpac_bundle.runner_path().is_file()
    {
        return Err(BackendExecutionError::JobSetup(
            "detached LPAC execution bundle did not satisfy the required readiness contract"
                .to_string(),
        ));
    }

    let mirror_root = PathBuf::from(&workspace.inputs_path);
    let lpac_readiness = lpac::probe_suspended_lpac_readiness(plan, &mirror_root)?;
    if !lpac_readiness.satisfies_readiness_contract() {
        return Err(BackendExecutionError::JobSetup(
            "LPAC readiness evidence did not match the required conservative contract".to_string(),
        ));
    }

    let outcome = crate::windows_restricted::execute_lpac_bundle_plan(
        plan,
        &mirror_root,
        workspace,
        lpac_bundle.runner_path(),
        cancelled,
    )?;
    guard.cleanup()?;
    Ok(outcome)
}

struct ProjectMirrorGuard {
    workspace: Option<DetachedExecutionWorkspace>,
}

impl ProjectMirrorGuard {
    fn new(workspace: DetachedExecutionWorkspace) -> Self {
        Self {
            workspace: Some(workspace),
        }
    }

    fn workspace(&self) -> &DetachedExecutionWorkspace {
        self.workspace
            .as_ref()
            .expect("project mirror guard is active")
    }

    fn cleanup(&mut self) -> Result<(), BackendExecutionError> {
        if let Some(workspace) = self.workspace.take() {
            cleanup_detached_workspace(&workspace).map_err(|error| {
                BackendExecutionError::JobSetup(format!("project mirror cleanup: {error}"))
            })?;
        }
        Ok(())
    }
}

impl Drop for ProjectMirrorGuard {
    fn drop(&mut self) {
        if let Some(workspace) = self.workspace.take() {
            let _ = cleanup_detached_workspace(&workspace);
        }
    }
}
