use std::{
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{verify_execution_inputs, ExecutionInputSnapshot, MAX_TARGETS};

pub mod identity;
pub mod project_mirror;
pub use identity::{
    probe_restricted_identity, RestrictedIdentityError, RestrictedIdentityEvidence,
};
pub use project_mirror::{
    prepare_dependency_complete_workspace, verify_dependency_complete_workspace,
    MAX_PROJECT_MIRROR_BYTES, MAX_PROJECT_MIRROR_DIRECTORIES, MAX_PROJECT_MIRROR_FILES,
};

pub const MAX_DETACHED_WORKSPACE_BYTES: u64 = 64 * 1024 * 1024;
const WORKSPACE_PREFIX: &str = "codetwin-qa-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedWorkspaceFile {
    pub relative_path: String,
    pub sha256: String,
    pub byte_size: u64,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedExecutionWorkspace {
    pub root_path: String,
    pub parent_path: String,
    pub source_root: String,
    pub inputs_path: String,
    pub artifacts_path: String,
    pub temp_path: String,
    pub files: Vec<DetachedWorkspaceFile>,
    pub total_input_bytes: u64,
    pub source_files_read_only: bool,
    pub dependency_complete: bool,
    #[serde(default)]
    pub project_directories: Vec<String>,
    #[serde(default)]
    pub project_manifest_sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("invalid workspace source root: {0}")]
    InvalidSourceRoot(String),
    #[error("invalid workspace parent: {0}")]
    InvalidWorkspaceParent(String),
    #[error("workspace parent must be outside the analyzed repository")]
    WorkspaceInsideSource,
    #[error("workspace input set must contain between 1 and {MAX_TARGETS} files")]
    InvalidInputCount,
    #[error("detached workspace input bytes exceed the bounded maximum of {MAX_DETACHED_WORKSPACE_BYTES}")]
    WorkspaceTooLarge,
    #[error("project mirror exceeds the bounded maximum byte size")]
    ProjectMirrorTooLarge,
    #[error("project mirror exceeds the bounded file-count limit")]
    ProjectFileLimitExceeded,
    #[error("project mirror exceeds the bounded directory-count limit")]
    ProjectDirectoryLimitExceeded,
    #[error("unsupported project filesystem entry: {0}")]
    UnsupportedProjectEntry(String),
    #[error("project source snapshot changed: {0}")]
    ProjectSnapshotChanged(String),
    #[error("detached project mirror verification failed: {0}")]
    ProjectMirrorMismatch(String),
    #[error("workspace input snapshot verification failed: {0}")]
    SnapshotVerification(String),
    #[error("workspace copy verification failed: {0}")]
    CopyVerification(String),
    #[error("workspace cleanup target failed safety validation: {0}")]
    UnsafeCleanup(String),
    #[error("workspace I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub fn prepare_detached_workspace(
    source_root: impl AsRef<Path>,
    workspace_parent: impl AsRef<Path>,
    snapshots: &[ExecutionInputSnapshot],
) -> Result<DetachedExecutionWorkspace, WorkspaceError> {
    if snapshots.is_empty() || snapshots.len() > MAX_TARGETS {
        return Err(WorkspaceError::InvalidInputCount);
    }

    let source_root = canonical_directory(source_root.as_ref(), true)?;
    let workspace_parent = canonical_directory(workspace_parent.as_ref(), false)?;
    if workspace_parent.starts_with(&source_root) {
        return Err(WorkspaceError::WorkspaceInsideSource);
    }

    let targets = snapshots
        .iter()
        .map(|snapshot| snapshot.relative_path.clone())
        .collect::<Vec<_>>();
    verify_execution_inputs(&source_root, &targets, snapshots)
        .map_err(|error| WorkspaceError::SnapshotVerification(error.to_string()))?;

    let total_input_bytes = snapshots.iter().try_fold(0u64, |total, snapshot| {
        total
            .checked_add(snapshot.byte_size)
            .ok_or(WorkspaceError::WorkspaceTooLarge)
    })?;
    if total_input_bytes > MAX_DETACHED_WORKSPACE_BYTES {
        return Err(WorkspaceError::WorkspaceTooLarge);
    }

    let root = create_unique_workspace(&workspace_parent)?;
    let inputs = root.join("inputs");
    let artifacts = root.join("artifacts");
    let temp = root.join("temp");
    fs::create_dir(&inputs)?;
    fs::create_dir(&artifacts)?;
    fs::create_dir(&temp)?;

    let result = copy_snapshotted_inputs(&source_root, &inputs, snapshots).and_then(|files| {
        let workspace = DetachedExecutionWorkspace {
            root_path: path_text(&root),
            parent_path: path_text(&workspace_parent),
            source_root: path_text(&source_root),
            inputs_path: path_text(&inputs),
            artifacts_path: path_text(&artifacts),
            temp_path: path_text(&temp),
            files,
            total_input_bytes,
            source_files_read_only: true,
            dependency_complete: false,
            project_directories: Vec::new(),
            project_manifest_sha256: None,
        };
        verify_detached_workspace(&workspace)?;
        Ok(workspace)
    });

    if result.is_err() {
        let _ = fs::remove_dir_all(&root);
    }
    result
}

pub fn verify_detached_workspace(
    workspace: &DetachedExecutionWorkspace,
) -> Result<(), WorkspaceError> {
    if workspace.dependency_complete {
        return verify_dependency_complete_workspace(workspace);
    }
    if !workspace.project_directories.is_empty() || workspace.project_manifest_sha256.is_some() {
        return Err(WorkspaceError::CopyVerification(
            "exact-input staging must not carry a project-mirror manifest".to_string(),
        ));
    }

    let root = fs::canonicalize(&workspace.root_path)?;
    let parent = fs::canonicalize(&workspace.parent_path)?;
    let source = fs::canonicalize(&workspace.source_root)?;
    if root.parent() != Some(parent.as_path())
        || !workspace_name_is_safe(&root)
        || root.starts_with(&source)
    {
        return Err(WorkspaceError::CopyVerification(
            "detached workspace root failed containment checks".to_string(),
        ));
    }

    let inputs = fs::canonicalize(&workspace.inputs_path)?;
    if !inputs.starts_with(&root) || inputs != root.join("inputs") {
        return Err(WorkspaceError::CopyVerification(
            "inputs directory escaped the detached workspace".to_string(),
        ));
    }

    let mut total = 0u64;
    for file in &workspace.files {
        crate::validate_target(&file.relative_path).map_err(|_| {
            WorkspaceError::CopyVerification(format!(
                "unsafe copied input path {}",
                file.relative_path
            ))
        })?;
        let candidate = inputs.join(&file.relative_path);
        let metadata = fs::symlink_metadata(&candidate)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(WorkspaceError::CopyVerification(file.relative_path.clone()));
        }
        let canonical = fs::canonicalize(&candidate)?;
        if !canonical.starts_with(&inputs)
            || metadata.len() != file.byte_size
            || sha256_file(&canonical)? != file.sha256
            || !metadata.permissions().readonly()
        {
            return Err(WorkspaceError::CopyVerification(file.relative_path.clone()));
        }
        total = total
            .checked_add(metadata.len())
            .ok_or(WorkspaceError::WorkspaceTooLarge)?;
    }

    if total != workspace.total_input_bytes || total > MAX_DETACHED_WORKSPACE_BYTES {
        return Err(WorkspaceError::CopyVerification(
            "detached workspace byte total changed".to_string(),
        ));
    }
    Ok(())
}

pub fn cleanup_detached_workspace(
    workspace: &DetachedExecutionWorkspace,
) -> Result<(), WorkspaceError> {
    let root = fs::canonicalize(&workspace.root_path)?;
    let parent = fs::canonicalize(&workspace.parent_path)?;
    let source = fs::canonicalize(&workspace.source_root)?;
    if root.parent() != Some(parent.as_path())
        || root.starts_with(&source)
        || !workspace_name_is_safe(&root)
    {
        return Err(WorkspaceError::UnsafeCleanup(path_text(&root)));
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

fn copy_snapshotted_inputs(
    source_root: &Path,
    inputs_root: &Path,
    snapshots: &[ExecutionInputSnapshot],
) -> Result<Vec<DetachedWorkspaceFile>, WorkspaceError> {
    let mut files = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        crate::validate_target(&snapshot.relative_path).map_err(|_| {
            WorkspaceError::SnapshotVerification(snapshot.relative_path.clone())
        })?;
        let source = source_root.join(&snapshot.relative_path);
        let source_metadata = fs::symlink_metadata(&source)?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            return Err(WorkspaceError::SnapshotVerification(
                snapshot.relative_path.clone(),
            ));
        }
        let source = fs::canonicalize(source)?;
        if !source.starts_with(source_root)
            || source_metadata.len() != snapshot.byte_size
            || sha256_file(&source)? != snapshot.sha256
        {
            return Err(WorkspaceError::SnapshotVerification(
                snapshot.relative_path.clone(),
            ));
        }

        let destination = inputs_root.join(&snapshot.relative_path);
        let Some(destination_parent) = destination.parent() else {
            return Err(WorkspaceError::CopyVerification(
                snapshot.relative_path.clone(),
            ));
        };
        fs::create_dir_all(destination_parent)?;
        fs::copy(&source, &destination)?;
        let mut permissions = fs::metadata(&destination)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&destination, permissions)?;

        let metadata = fs::metadata(&destination)?;
        if metadata.len() != snapshot.byte_size || sha256_file(&destination)? != snapshot.sha256 {
            return Err(WorkspaceError::CopyVerification(
                snapshot.relative_path.clone(),
            ));
        }
        files.push(DetachedWorkspaceFile {
            relative_path: snapshot.relative_path.clone(),
            sha256: snapshot.sha256.clone(),
            byte_size: snapshot.byte_size,
            read_only: true,
        });
    }
    Ok(files)
}

pub(crate) fn create_unique_workspace(parent: &Path) -> Result<PathBuf, WorkspaceError> {
    for attempt in 0..8u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let name = format!(
            "{WORKSPACE_PREFIX}{}-{nanos}-{attempt}",
            std::process::id()
        );
        let candidate = parent.join(name);
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(WorkspaceError::Io(error)),
        }
    }
    Err(WorkspaceError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique detached QA workspace",
    )))
}

pub(crate) fn canonical_directory(
    path: &Path,
    source: bool,
) -> Result<PathBuf, WorkspaceError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        if source {
            WorkspaceError::InvalidSourceRoot(format!("{}: {error}", path.display()))
        } else {
            WorkspaceError::InvalidWorkspaceParent(format!("{}: {error}", path.display()))
        }
    })?;
    if !canonical.is_dir() {
        return if source {
            Err(WorkspaceError::InvalidSourceRoot(path_text(&canonical)))
        } else {
            Err(WorkspaceError::InvalidWorkspaceParent(path_text(&canonical)))
        };
    }
    Ok(canonical)
}

pub(crate) fn workspace_name_is_safe(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(WORKSPACE_PREFIX))
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
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

pub(crate) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        cleanup_detached_workspace, prepare_detached_workspace, verify_detached_workspace,
        WorkspaceError,
    };
    use crate::snapshot_execution_inputs;

    fn temp_directory(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!("codetwin-{label}-{nanos}"));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    #[test]
    fn detached_workspace_copies_exact_hash_pinned_inputs_read_only() {
        let source = temp_directory("workspace-source");
        let parent = temp_directory("workspace-parent");
        fs::create_dir_all(source.join("tests")).expect("tests");
        fs::write(source.join("tests/test_api.py"), "def test_ok():\n    assert True\n")
            .expect("source");
        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&source, &targets).expect("snapshots");
        let workspace =
            prepare_detached_workspace(&source, &parent, &snapshots).expect("workspace");
        assert!(!workspace.dependency_complete);
        assert!(workspace.source_files_read_only);
        assert!(workspace.project_directories.is_empty());
        assert!(workspace.project_manifest_sha256.is_none());
        verify_detached_workspace(&workspace).expect("verify");
        let staged = std::path::Path::new(&workspace.inputs_path).join("tests/test_api.py");
        assert!(fs::metadata(staged).expect("metadata").permissions().readonly());
        cleanup_detached_workspace(&workspace).expect("cleanup");
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn detached_workspace_detects_manifest_hash_tampering() {
        let source = temp_directory("workspace-mutation-source");
        let parent = temp_directory("workspace-mutation-parent");
        fs::create_dir_all(source.join("tests")).expect("tests");
        fs::write(source.join("tests/test_api.py"), "print('safe')\n").expect("source");
        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&source, &targets).expect("snapshots");
        let mut workspace =
            prepare_detached_workspace(&source, &parent, &snapshots).expect("workspace");
        workspace.files[0].sha256 = "0".repeat(64);
        assert!(matches!(
            verify_detached_workspace(&workspace),
            Err(WorkspaceError::CopyVerification(_))
        ));
        workspace.files[0].sha256 = snapshots[0].sha256.clone();
        cleanup_detached_workspace(&workspace).expect("cleanup");
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn workspace_parent_inside_source_is_rejected() {
        let source = temp_directory("workspace-containment");
        let parent = source.join("cache");
        fs::create_dir_all(&parent).expect("parent");
        fs::create_dir_all(source.join("tests")).expect("tests");
        fs::write(source.join("tests/test_api.py"), "pass\n").expect("source");
        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&source, &targets).expect("snapshots");
        assert!(matches!(
            prepare_detached_workspace(&source, &parent, &snapshots),
            Err(WorkspaceError::WorkspaceInsideSource)
        ));
        let _ = fs::remove_dir_all(source);
    }
}
