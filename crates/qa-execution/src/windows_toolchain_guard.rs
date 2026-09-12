use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ};

use crate::{BackendExecutionError, TestExecutionPlan};

/// Holds a non-write/non-delete-sharing handle to the exact trusted runner image.
///
/// The guard is deliberately kept alive across the lower-level Windows launch call. Rust's
/// default Windows file sharing permits concurrent write/delete/rename, so hashing a runner and
/// immediately closing the file would leave a path-replacement window before CreateProcessAsUserW
/// re-opens the image. `FILE_SHARE_READ` keeps subsequent readers possible while denying new
/// write/delete opens for the lifetime of this guard.
pub(super) struct LockedToolchainGuard {
    _locked_executable: File,
}

pub(super) fn lock_and_attest_external_read_surface(
    plan: &TestExecutionPlan,
    project_root: &Path,
) -> Result<LockedToolchainGuard, BackendExecutionError> {
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

    let source_root = canonical_directory(project_root, "project root")?;
    let metadata = fs::symlink_metadata(executable).map_err(|error| {
        BackendExecutionError::InvalidToolchain(format!("{}: {error}", executable.display()))
    })?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
    {
        return Err(BackendExecutionError::InvalidToolchain(
            "toolchain must be a regular non-reparse file".to_string(),
        ));
    }

    let canonical_executable = fs::canonicalize(executable).map_err(|error| {
        BackendExecutionError::InvalidToolchain(format!("{}: {error}", executable.display()))
    })?;
    if canonical_executable.starts_with(&source_root) {
        return Err(BackendExecutionError::ToolchainInsideProject);
    }
    let Some(toolchain_root) = canonical_executable.parent() else {
        return Err(BackendExecutionError::InvalidToolchain(
            "trusted toolchain executable has no parent directory".to_string(),
        ));
    };
    let toolchain_root = canonical_directory(toolchain_root, "toolchain root")?;
    if toolchain_root.starts_with(&source_root) {
        return Err(BackendExecutionError::ToolchainInsideProject);
    }

    let windows_root = canonical_system_root("SYSTEMROOT", &source_root)?;
    let win_dir = canonical_system_root("WINDIR", &source_root)?;
    if !same_windows_path(&windows_root, &win_dir) {
        return Err(BackendExecutionError::InvalidToolchain(
            "SYSTEMROOT and WINDIR resolve to different Windows roots".to_string(),
        ));
    }

    let Some(expected_hash) = plan.toolchain.sha256.as_deref() else {
        return Err(BackendExecutionError::MissingToolchainHash);
    };
    if !valid_sha256(expected_hash) {
        return Err(BackendExecutionError::InvalidToolchain(
            "toolchain SHA-256 must be 64 hexadecimal characters".to_string(),
        ));
    }

    let mut locked_executable = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&canonical_executable)
        .map_err(|error| {
            BackendExecutionError::InvalidToolchain(format!(
                "could not lock trusted runner {} against write/delete replacement: {error}",
                canonical_executable.display()
            ))
        })?;

    let locked_metadata = locked_executable.metadata().map_err(|error| {
        BackendExecutionError::InvalidToolchain(format!(
            "could not inspect locked trusted runner {}: {error}",
            canonical_executable.display()
        ))
    })?;
    if !locked_metadata.is_file() {
        return Err(BackendExecutionError::InvalidToolchain(
            "locked trusted runner is not a regular file".to_string(),
        ));
    }

    let actual_hash = sha256_locked_file(&mut locked_executable)?;
    if !actual_hash.eq_ignore_ascii_case(expected_hash) {
        return Err(BackendExecutionError::ToolchainHashMismatch);
    }

    Ok(LockedToolchainGuard {
        _locked_executable: locked_executable,
    })
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, BackendExecutionError> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        BackendExecutionError::InvalidToolchain(format!("{label} {}: {error}", path.display()))
    })?;
    if !canonical.is_dir() {
        return Err(BackendExecutionError::InvalidToolchain(format!(
            "{label} is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn canonical_system_root(
    variable: &str,
    project_root: &Path,
) -> Result<PathBuf, BackendExecutionError> {
    let Some(value) = std::env::var_os(variable) else {
        return Err(BackendExecutionError::InvalidToolchain(format!(
            "required Windows system-root variable {variable} is missing"
        )));
    };
    let root = canonical_directory(Path::new(&value), variable)?;
    if root.starts_with(project_root) {
        return Err(BackendExecutionError::InvalidToolchain(format!(
            "{variable} resolves inside the analyzed repository"
        )));
    }
    Ok(root)
}

fn same_windows_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_locked_file(file: &mut File) -> Result<String, BackendExecutionError> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))?;

    let bytes = digest.finalize();
    let mut output = String::with_capacity(64);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::valid_sha256;

    #[test]
    fn validates_sha256_shape() {
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(valid_sha256(&"F".repeat(64)));
        assert!(!valid_sha256(&"g".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
    }
}
