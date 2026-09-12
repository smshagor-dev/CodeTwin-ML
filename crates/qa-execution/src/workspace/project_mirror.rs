use std::{
    collections::BTreeMap,
    fs,
    path::Path,
};

use sha2::{Digest, Sha256};

use super::{
    canonical_directory, create_unique_workspace, path_text, sha256_file, workspace_name_is_safe,
    DetachedExecutionWorkspace, DetachedWorkspaceFile, WorkspaceError,
};
use crate::{verify_execution_inputs, ExecutionInputSnapshot, MAX_TARGETS};

pub const MAX_PROJECT_MIRROR_FILES: usize = 8_192;
pub const MAX_PROJECT_MIRROR_DIRECTORIES: usize = 4_096;
pub const MAX_PROJECT_MIRROR_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectFileSnapshot {
    relative_path: String,
    sha256: String,
    byte_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectTreeSnapshot {
    directories: Vec<String>,
    files: Vec<ProjectFileSnapshot>,
    total_bytes: u64,
}

pub fn prepare_dependency_complete_workspace(
    source_root: impl AsRef<Path>,
    workspace_parent: impl AsRef<Path>,
    approved_targets: &[ExecutionInputSnapshot],
) -> Result<DetachedExecutionWorkspace, WorkspaceError> {
    if approved_targets.is_empty() || approved_targets.len() > MAX_TARGETS {
        return Err(WorkspaceError::InvalidInputCount);
    }

    let source_root = canonical_directory(source_root.as_ref(), true)?;
    let workspace_parent = canonical_directory(workspace_parent.as_ref(), false)?;
    if workspace_parent.starts_with(&source_root) {
        return Err(WorkspaceError::WorkspaceInsideSource);
    }

    let targets = approved_targets
        .iter()
        .map(|snapshot| snapshot.relative_path.clone())
        .collect::<Vec<_>>();
    verify_execution_inputs(&source_root, &targets, approved_targets)
        .map_err(|error| WorkspaceError::SnapshotVerification(error.to_string()))?;

    let snapshot = snapshot_project_tree(&source_root)?;
    verify_approved_targets_in_snapshot(&snapshot, approved_targets)?;

    let root = create_unique_workspace(&workspace_parent)?;
    let inputs = root.join("inputs");
    let artifacts = root.join("artifacts");
    let temp = root.join("temp");
    fs::create_dir(&inputs)?;
    fs::create_dir(&artifacts)?;
    fs::create_dir(&temp)?;

    let result = copy_project_tree(&source_root, &inputs, &snapshot).and_then(|files| {
        let manifest_sha256 = project_manifest_sha256(&snapshot);
        let workspace = DetachedExecutionWorkspace {
            root_path: path_text(&root),
            parent_path: path_text(&workspace_parent),
            source_root: path_text(&source_root),
            inputs_path: path_text(&inputs),
            artifacts_path: path_text(&artifacts),
            temp_path: path_text(&temp),
            files,
            total_input_bytes: snapshot.total_bytes,
            source_files_read_only: true,
            dependency_complete: true,
            project_directories: snapshot.directories.clone(),
            project_manifest_sha256: Some(manifest_sha256),
        };
        verify_dependency_complete_workspace(&workspace)?;
        Ok(workspace)
    });

    if result.is_err() {
        let _ = fs::remove_dir_all(&root);
    }
    result
}

pub fn verify_dependency_complete_workspace(
    workspace: &DetachedExecutionWorkspace,
) -> Result<(), WorkspaceError> {
    if !workspace.dependency_complete {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "workspace does not claim project-local dependency completeness".to_string(),
        ));
    }
    if !workspace.source_files_read_only {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "dependency-complete workspace must keep mirrored project files read-only".to_string(),
        ));
    }

    let root = fs::canonicalize(&workspace.root_path)?;
    let parent = fs::canonicalize(&workspace.parent_path)?;
    let source = fs::canonicalize(&workspace.source_root)?;
    if root.parent() != Some(parent.as_path())
        || !workspace_name_is_safe(&root)
        || root.starts_with(&source)
    {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "project mirror root failed containment checks".to_string(),
        ));
    }

    let inputs = fs::canonicalize(&workspace.inputs_path)?;
    let artifacts = fs::canonicalize(&workspace.artifacts_path)?;
    let temp = fs::canonicalize(&workspace.temp_path)?;
    if inputs != root.join("inputs")
        || artifacts != root.join("artifacts")
        || temp != root.join("temp")
        || !inputs.starts_with(&root)
        || !artifacts.starts_with(&root)
        || !temp.starts_with(&root)
    {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "project mirror workspace directories escaped their generated root".to_string(),
        ));
    }

    let expected = snapshot_from_workspace_manifest(workspace)?;
    if expected.files.len() > MAX_PROJECT_MIRROR_FILES {
        return Err(WorkspaceError::ProjectFileLimitExceeded);
    }
    if expected.directories.len() > MAX_PROJECT_MIRROR_DIRECTORIES {
        return Err(WorkspaceError::ProjectDirectoryLimitExceeded);
    }
    if expected.total_bytes > MAX_PROJECT_MIRROR_BYTES {
        return Err(WorkspaceError::ProjectMirrorTooLarge);
    }

    let expected_manifest = project_manifest_sha256(&expected);
    if workspace.project_manifest_sha256.as_deref() != Some(expected_manifest.as_str()) {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "project mirror manifest digest changed".to_string(),
        ));
    }

    let source_snapshot = snapshot_project_tree(&source)?;
    if source_snapshot != expected {
        return Err(WorkspaceError::ProjectSnapshotChanged(
            "source project tree no longer matches the prepared full-tree manifest".to_string(),
        ));
    }

    let mirror_snapshot = snapshot_project_tree(&inputs)?;
    if mirror_snapshot != expected {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "detached project mirror no longer matches its full-tree manifest".to_string(),
        ));
    }

    for file in &workspace.files {
        let mirrored = inputs.join(&file.relative_path);
        if !fs::metadata(&mirrored)?.permissions().readonly() {
            return Err(WorkspaceError::ProjectMirrorMismatch(format!(
                "mirrored project file is not read-only: {}",
                file.relative_path
            )));
        }
    }
    Ok(())
}

fn verify_approved_targets_in_snapshot(
    snapshot: &ProjectTreeSnapshot,
    approved_targets: &[ExecutionInputSnapshot],
) -> Result<(), WorkspaceError> {
    let files = snapshot
        .files
        .iter()
        .map(|file| (file.relative_path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    for approved in approved_targets {
        let Some(file) = files.get(approved.relative_path.as_str()) else {
            return Err(WorkspaceError::SnapshotVerification(
                approved.relative_path.clone(),
            ));
        };
        if file.byte_size != approved.byte_size || file.sha256 != approved.sha256 {
            return Err(WorkspaceError::SnapshotVerification(
                approved.relative_path.clone(),
            ));
        }
    }
    Ok(())
}

fn snapshot_from_workspace_manifest(
    workspace: &DetachedExecutionWorkspace,
) -> Result<ProjectTreeSnapshot, WorkspaceError> {
    let mut directories = workspace.project_directories.clone();
    directories.sort();
    directories.dedup();
    if directories.len() != workspace.project_directories.len() {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "project directory manifest contains duplicates".to_string(),
        ));
    }
    for directory in &directories {
        crate::validate_target(directory).map_err(|_| {
            WorkspaceError::ProjectMirrorMismatch(format!(
                "unsafe project directory path in manifest: {directory}"
            ))
        })?;
    }

    let mut files = Vec::with_capacity(workspace.files.len());
    for file in &workspace.files {
        crate::validate_target(&file.relative_path).map_err(|_| {
            WorkspaceError::ProjectMirrorMismatch(format!(
                "unsafe project file path in manifest: {}",
                file.relative_path
            ))
        })?;
        if !file.read_only {
            return Err(WorkspaceError::ProjectMirrorMismatch(format!(
                "project mirror manifest does not require read-only file: {}",
                file.relative_path
            )));
        }
        files.push(ProjectFileSnapshot {
            relative_path: file.relative_path.clone(),
            sha256: file.sha256.clone(),
            byte_size: file.byte_size,
        });
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if files
        .windows(2)
        .any(|pair| pair[0].relative_path == pair[1].relative_path)
    {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "project file manifest contains duplicates".to_string(),
        ));
    }

    let total_bytes = files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.byte_size)
            .ok_or(WorkspaceError::ProjectMirrorTooLarge)
    })?;
    if total_bytes != workspace.total_input_bytes {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "project mirror byte total changed".to_string(),
        ));
    }

    Ok(ProjectTreeSnapshot {
        directories,
        files,
        total_bytes,
    })
}

fn snapshot_project_tree(root: &Path) -> Result<ProjectTreeSnapshot, WorkspaceError> {
    let canonical_root = fs::canonicalize(root)?;
    if !canonical_root.is_dir() {
        return Err(WorkspaceError::InvalidSourceRoot(path_text(&canonical_root)));
    }

    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    let mut pending = vec![(canonical_root.clone(), String::new())];

    while let Some((directory, prefix)) = pending.pop() {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| {
                WorkspaceError::UnsupportedProjectEntry(
                    "project paths must be valid Unicode for deterministic mirroring".to_string(),
                )
            })?;
            entries.push((name, entry.path()));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        for (name, path) in entries {
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            crate::validate_target(&relative).map_err(|_| {
                WorkspaceError::UnsupportedProjectEntry(format!(
                    "unsafe project path cannot be mirrored: {relative}"
                ))
            })?;

            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
                return Err(WorkspaceError::UnsupportedProjectEntry(format!(
                    "symbolic links and reparse-point entries are not supported in a dependency-complete mirror: {relative}"
                )));
            }

            let canonical = fs::canonicalize(&path)?;
            if !canonical.starts_with(&canonical_root) {
                return Err(WorkspaceError::UnsupportedProjectEntry(format!(
                    "project entry escaped the canonical source root: {relative}"
                )));
            }

            if metadata.is_dir() {
                directories.push(relative.clone());
                if directories.len() > MAX_PROJECT_MIRROR_DIRECTORIES {
                    return Err(WorkspaceError::ProjectDirectoryLimitExceeded);
                }
                pending.push((canonical, relative));
            } else if metadata.is_file() {
                if files.len() >= MAX_PROJECT_MIRROR_FILES {
                    return Err(WorkspaceError::ProjectFileLimitExceeded);
                }
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .ok_or(WorkspaceError::ProjectMirrorTooLarge)?;
                if total_bytes > MAX_PROJECT_MIRROR_BYTES {
                    return Err(WorkspaceError::ProjectMirrorTooLarge);
                }
                files.push(ProjectFileSnapshot {
                    relative_path: relative,
                    sha256: sha256_file(&canonical)?,
                    byte_size: metadata.len(),
                });
            } else {
                return Err(WorkspaceError::UnsupportedProjectEntry(format!(
                    "special filesystem entries are not supported in a dependency-complete mirror: {relative}"
                )));
            }
        }
    }

    directories.sort();
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(ProjectTreeSnapshot {
        directories,
        files,
        total_bytes,
    })
}

fn copy_project_tree(
    source_root: &Path,
    inputs_root: &Path,
    snapshot: &ProjectTreeSnapshot,
) -> Result<Vec<DetachedWorkspaceFile>, WorkspaceError> {
    let mut directories = snapshot.directories.clone();
    directories.sort_by(|left, right| {
        let left_depth = left.matches('/').count();
        let right_depth = right.matches('/').count();
        left_depth.cmp(&right_depth).then_with(|| left.cmp(right))
    });
    for relative in directories {
        fs::create_dir_all(inputs_root.join(relative))?;
    }

    let mut copied = Vec::with_capacity(snapshot.files.len());
    for file in &snapshot.files {
        let source = source_root.join(&file.relative_path);
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.file_type().is_symlink()
            || metadata_is_reparse_point(&metadata)
            || !metadata.is_file()
        {
            return Err(WorkspaceError::ProjectSnapshotChanged(
                file.relative_path.clone(),
            ));
        }
        let source = fs::canonicalize(source)?;
        if !source.starts_with(source_root)
            || metadata.len() != file.byte_size
            || sha256_file(&source)? != file.sha256
        {
            return Err(WorkspaceError::ProjectSnapshotChanged(
                file.relative_path.clone(),
            ));
        }

        let destination = inputs_root.join(&file.relative_path);
        let Some(parent) = destination.parent() else {
            return Err(WorkspaceError::ProjectMirrorMismatch(
                file.relative_path.clone(),
            ));
        };
        fs::create_dir_all(parent)?;
        fs::copy(&source, &destination)?;
        let mut permissions = fs::metadata(&destination)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&destination, permissions)?;

        let copied_metadata = fs::symlink_metadata(&destination)?;
        if copied_metadata.file_type().is_symlink()
            || metadata_is_reparse_point(&copied_metadata)
            || !copied_metadata.is_file()
            || copied_metadata.len() != file.byte_size
            || sha256_file(&destination)? != file.sha256
            || !copied_metadata.permissions().readonly()
        {
            return Err(WorkspaceError::ProjectMirrorMismatch(
                file.relative_path.clone(),
            ));
        }
        copied.push(DetachedWorkspaceFile {
            relative_path: file.relative_path.clone(),
            sha256: file.sha256.clone(),
            byte_size: file.byte_size,
            read_only: true,
        });
    }

    let source_after_copy = snapshot_project_tree(source_root)?;
    if &source_after_copy != snapshot {
        return Err(WorkspaceError::ProjectSnapshotChanged(
            "source project changed while the detached mirror was being copied".to_string(),
        ));
    }
    let mirror_after_copy = snapshot_project_tree(inputs_root)?;
    if &mirror_after_copy != snapshot {
        return Err(WorkspaceError::ProjectMirrorMismatch(
            "detached project mirror differs from the source manifest after copy".to_string(),
        ));
    }
    Ok(copied)
}

fn project_manifest_sha256(snapshot: &ProjectTreeSnapshot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codetwin-project-mirror-v1\0");
    for directory in &snapshot.directories {
        digest.update(b"D\0");
        digest.update(directory.as_bytes());
        digest.update(b"\0");
    }
    for file in &snapshot.files {
        digest.update(b"F\0");
        digest.update(file.relative_path.as_bytes());
        digest.update(b"\0");
        digest.update(file.byte_size.to_le_bytes());
        digest.update(b"\0");
        digest.update(file.sha256.as_bytes());
        digest.update(b"\0");
    }
    let bytes = digest.finalize();
    hex_digest(&bytes)
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        prepare_dependency_complete_workspace, verify_dependency_complete_workspace,
    };
    use crate::{cleanup_detached_workspace, snapshot_execution_inputs};

    fn temp_directory(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!("codetwin-{label}-{nanos}"));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    #[test]
    fn dependency_complete_workspace_mirrors_full_project_and_empty_directories() {
        let source = temp_directory("project-mirror-source");
        let parent = temp_directory("project-mirror-parent");
        fs::create_dir_all(source.join("tests")).expect("tests");
        fs::create_dir_all(source.join("src")).expect("src");
        fs::create_dir_all(source.join("fixtures/empty")).expect("empty fixture");
        fs::write(source.join("tests/test_api.py"), "def test_ok():\n    assert True\n")
            .expect("test");
        fs::write(source.join("src/app.py"), "VALUE = 1\n").expect("source");
        fs::write(source.join("pyproject.toml"), "[project]\nname='demo'\n").expect("config");

        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&source, &targets).expect("snapshots");
        let workspace = prepare_dependency_complete_workspace(&source, &parent, &snapshots)
            .expect("dependency-complete workspace");

        assert!(workspace.dependency_complete);
        assert!(workspace.project_manifest_sha256.is_some());
        assert!(workspace
            .project_directories
            .iter()
            .any(|path| path == "fixtures/empty"));
        let inputs = std::path::Path::new(&workspace.inputs_path);
        assert!(inputs.join("src/app.py").is_file());
        assert!(inputs.join("pyproject.toml").is_file());
        assert!(inputs.join("fixtures/empty").is_dir());
        verify_dependency_complete_workspace(&workspace).expect("verify");

        cleanup_detached_workspace(&workspace).expect("cleanup");
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn dependency_complete_workspace_detects_source_change_after_copy() {
        let source = temp_directory("project-mirror-source-change");
        let parent = temp_directory("project-mirror-parent-change");
        fs::create_dir_all(source.join("tests")).expect("tests");
        fs::write(source.join("tests/test_api.py"), "print('ok')\n").expect("test");
        fs::write(source.join("module.py"), "VALUE = 1\n").expect("module");
        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&source, &targets).expect("snapshots");
        let workspace = prepare_dependency_complete_workspace(&source, &parent, &snapshots)
            .expect("dependency-complete workspace");

        fs::write(source.join("module.py"), "VALUE = 2\n").expect("mutate source");
        assert!(verify_dependency_complete_workspace(&workspace).is_err());

        cleanup_detached_workspace(&workspace).expect("cleanup");
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn dependency_complete_workspace_detects_extra_mirror_file() {
        let source = temp_directory("project-mirror-source-extra");
        let parent = temp_directory("project-mirror-parent-extra");
        fs::create_dir_all(source.join("tests")).expect("tests");
        fs::write(source.join("tests/test_api.py"), "print('ok')\n").expect("test");
        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&source, &targets).expect("snapshots");
        let workspace = prepare_dependency_complete_workspace(&source, &parent, &snapshots)
            .expect("dependency-complete workspace");

        fs::write(
            std::path::Path::new(&workspace.inputs_path).join("unexpected.txt"),
            "unexpected",
        )
        .expect("extra mirror file");
        assert!(verify_dependency_complete_workspace(&workspace).is_err());

        cleanup_detached_workspace(&workspace).expect("cleanup");
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(parent);
    }
}
