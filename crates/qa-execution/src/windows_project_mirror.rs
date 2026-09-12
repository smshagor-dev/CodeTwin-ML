use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use crate::{
    cleanup_detached_workspace, prepare_dependency_complete_workspace, probe_restricted_identity,
    BackendExecutionError, DetachedExecutionWorkspace, ExecutionInputSnapshot, RawExecutionOutcome,
    TestExecutionPlan,
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

    let workspace_parent = std::env::temp_dir();
    let workspace =
        prepare_dependency_complete_workspace(project_root, &workspace_parent, snapshots).map_err(
            |error| {
                BackendExecutionError::JobSetup(format!(
                    "dependency-complete project mirror: {error}"
                ))
            },
        )?;
    let mut guard = ProjectMirrorGuard::new(workspace);
    let workspace = guard.workspace();

    if !workspace.dependency_complete {
        return Err(BackendExecutionError::JobSetup(
            "dependency-complete project mirror did not retain its completeness evidence"
                .to_string(),
        ));
    }
    let actual_manifest = workspace.project_manifest_sha256.as_deref().ok_or_else(|| {
        BackendExecutionError::JobSetup(
            "dependency-complete project mirror did not retain its manifest digest".to_string(),
        )
    })?;
    if actual_manifest != expected_manifest {
        return Err(BackendExecutionError::JobSetup(format!(
            "approved project manifest mismatch: expected {expected_manifest}, prepared {actual_manifest}"
        )));
    }

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

    let mirror_root = PathBuf::from(&workspace.inputs_path);
    let outcome = crate::windows_restricted::execute_approved_plan(
        plan,
        &mirror_root,
        snapshots,
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
