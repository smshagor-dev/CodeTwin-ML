use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_EXTERNAL_READ_ROOTS: usize = 8;
pub const MAX_EXTERNAL_READ_FILES: usize = 65_536;
pub const MAX_EXTERNAL_READ_DIRECTORIES: usize = 16_384;
pub const MAX_EXTERNAL_READ_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReadRootKind {
    RuntimeRoot,
    StandardLibrary,
    CompilerSysroot,
    ToolchainSupport,
    PackageStore,
    ExtensionDirectory,
}

impl ExternalReadRootKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeRoot => "runtime_root",
            Self::StandardLibrary => "standard_library",
            Self::CompilerSysroot => "compiler_sysroot",
            Self::ToolchainSupport => "toolchain_support",
            Self::PackageStore => "package_store",
            Self::ExtensionDirectory => "extension_directory",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredExternalReadRoot {
    pub kind: ExternalReadRootKind,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReadRootEvidence {
    pub kind: ExternalReadRootKind,
    pub canonical_path: String,
    pub manifest_sha256: String,
    pub file_count: u64,
    pub directory_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedExternalReadSurface {
    pub sha256: String,
    pub roots: Vec<ExternalReadRootEvidence>,
}

#[derive(Debug, Error)]
pub enum ExternalProvenanceError {
    #[error("at least one explicit external read root is required before approval")]
    NoDeclaredRoots,
    #[error("external read root count exceeds the bounded maximum of {MAX_EXTERNAL_READ_ROOTS}")]
    TooManyRoots,
    #[error("invalid external read root declaration: {0}")]
    InvalidDeclaration(String),
    #[error("external read root must remain outside the analyzed repository: {0}")]
    RootInsideProject(String),
    #[error("unsupported external filesystem entry: {0}")]
    UnsupportedEntry(String),
    #[error("external read surface exceeds the bounded file-count limit")]
    FileLimitExceeded,
    #[error("external read surface exceeds the bounded directory-count limit")]
    DirectoryLimitExceeded,
    #[error("external read surface exceeds the bounded byte limit")]
    ByteLimitExceeded,
    #[error("external read surface changed from its approved provenance")]
    SurfaceChanged,
    #[error("invalid approved external read surface: {0}")]
    InvalidEvidence(String),
    #[error("external read provenance I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileEvidence {
    relative_path: String,
    sha256: String,
    byte_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeEvidence {
    directories: Vec<String>,
    files: Vec<FileEvidence>,
    total_bytes: u64,
}

#[derive(Default)]
struct SurfaceBudget {
    files: usize,
    directories: usize,
    bytes: u64,
}

pub fn validate_declared_external_read_roots(
    roots: &[DeclaredExternalReadRoot],
) -> Result<(), ExternalProvenanceError> {
    if roots.len() > MAX_EXTERNAL_READ_ROOTS {
        return Err(ExternalProvenanceError::TooManyRoots);
    }
    let mut seen = BTreeSet::new();
    for root in roots {
        if root.path.trim().is_empty() || root.path.contains('\0') {
            return Err(ExternalProvenanceError::InvalidDeclaration(
                "external read root path must not be empty or contain NUL".to_string(),
            ));
        }
        let path = Path::new(&root.path);
        if !path.is_absolute() {
            return Err(ExternalProvenanceError::InvalidDeclaration(format!(
                "external read root must be absolute: {}",
                root.path
            )));
        }
        let key = declaration_key(root);
        if !seen.insert(key) {
            return Err(ExternalProvenanceError::InvalidDeclaration(format!(
                "duplicate external read root declaration: {}",
                root.path
            )));
        }
    }
    Ok(())
}

pub fn capture_external_read_surface(
    roots: &[DeclaredExternalReadRoot],
    project_root: impl AsRef<Path>,
) -> Result<ApprovedExternalReadSurface, ExternalProvenanceError> {
    if roots.is_empty() {
        return Err(ExternalProvenanceError::NoDeclaredRoots);
    }
    validate_declared_external_read_roots(roots)?;

    let project_root = canonical_directory(project_root.as_ref(), "project root")?;
    let mut budget = SurfaceBudget::default();
    let mut evidence = Vec::with_capacity(roots.len());
    let mut canonical_seen = BTreeSet::new();

    for declared in roots {
        let original = Path::new(&declared.path);
        let metadata = fs::symlink_metadata(original)?;
        if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
            return Err(ExternalProvenanceError::UnsupportedEntry(format!(
                "external read root is a symlink/reparse point: {}",
                original.display()
            )));
        }
        let canonical = canonical_directory(original, "external read root")?;
        if canonical.starts_with(&project_root) {
            return Err(ExternalProvenanceError::RootInsideProject(
                canonical.display().to_string(),
            ));
        }
        let canonical_text = path_text(&canonical);
        let canonical_key = canonical_path_key(&canonical_text);
        if !canonical_seen.insert(canonical_key) {
            return Err(ExternalProvenanceError::InvalidDeclaration(format!(
                "multiple declarations resolve to the same external root: {canonical_text}"
            )));
        }

        let tree = snapshot_tree(&canonical, &mut budget)?;
        if tree.files.is_empty() {
            return Err(ExternalProvenanceError::InvalidDeclaration(format!(
                "external read root contains no regular files: {canonical_text}"
            )));
        }
        evidence.push(ExternalReadRootEvidence {
            kind: declared.kind,
            canonical_path: canonical_text,
            manifest_sha256: tree_manifest_sha256(&tree),
            file_count: u64::try_from(tree.files.len()).unwrap_or(u64::MAX),
            directory_count: u64::try_from(tree.directories.len()).unwrap_or(u64::MAX),
            total_bytes: tree.total_bytes,
        });
    }

    evidence.sort_by(|left, right| evidence_sort_key(left).cmp(&evidence_sort_key(right)));
    let surface = ApprovedExternalReadSurface {
        sha256: surface_sha256(&evidence),
        roots: evidence,
    };
    validate_approved_external_read_surface_shape(&surface)?;
    Ok(surface)
}

pub fn verify_external_read_surface(
    roots: &[DeclaredExternalReadRoot],
    approved: &ApprovedExternalReadSurface,
    project_root: impl AsRef<Path>,
) -> Result<(), ExternalProvenanceError> {
    validate_approved_external_read_surface_shape(approved)?;
    let current = capture_external_read_surface(roots, project_root)?;
    if &current != approved {
        return Err(ExternalProvenanceError::SurfaceChanged);
    }
    Ok(())
}

pub fn validate_approved_external_read_surface_shape(
    surface: &ApprovedExternalReadSurface,
) -> Result<(), ExternalProvenanceError> {
    if !valid_sha256(&surface.sha256) {
        return Err(ExternalProvenanceError::InvalidEvidence(
            "surface digest is not a SHA-256 value".to_string(),
        ));
    }
    if surface.roots.is_empty() || surface.roots.len() > MAX_EXTERNAL_READ_ROOTS {
        return Err(ExternalProvenanceError::InvalidEvidence(
            "surface root count is outside the bounded range".to_string(),
        ));
    }

    let mut canonical_seen = BTreeSet::new();
    let mut total_files = 0u64;
    let mut total_directories = 0u64;
    let mut total_bytes = 0u64;
    for root in &surface.roots {
        if !valid_sha256(&root.manifest_sha256)
            || root.file_count == 0
            || root.canonical_path.trim().is_empty()
            || !Path::new(&root.canonical_path).is_absolute()
        {
            return Err(ExternalProvenanceError::InvalidEvidence(format!(
                "invalid evidence for external root {}",
                root.canonical_path
            )));
        }
        if !canonical_seen.insert(canonical_path_key(&root.canonical_path)) {
            return Err(ExternalProvenanceError::InvalidEvidence(
                "approved external surface contains duplicate roots".to_string(),
            ));
        }
        total_files = total_files
            .checked_add(root.file_count)
            .ok_or(ExternalProvenanceError::FileLimitExceeded)?;
        total_directories = total_directories
            .checked_add(root.directory_count)
            .ok_or(ExternalProvenanceError::DirectoryLimitExceeded)?;
        total_bytes = total_bytes
            .checked_add(root.total_bytes)
            .ok_or(ExternalProvenanceError::ByteLimitExceeded)?;
    }
    if total_files > u64::try_from(MAX_EXTERNAL_READ_FILES).unwrap_or(u64::MAX) {
        return Err(ExternalProvenanceError::FileLimitExceeded);
    }
    if total_directories > u64::try_from(MAX_EXTERNAL_READ_DIRECTORIES).unwrap_or(u64::MAX) {
        return Err(ExternalProvenanceError::DirectoryLimitExceeded);
    }
    if total_bytes > MAX_EXTERNAL_READ_BYTES {
        return Err(ExternalProvenanceError::ByteLimitExceeded);
    }

    let mut roots = surface.roots.clone();
    roots.sort_by(|left, right| evidence_sort_key(left).cmp(&evidence_sort_key(right)));
    if roots != surface.roots || surface_sha256(&roots) != surface.sha256 {
        return Err(ExternalProvenanceError::InvalidEvidence(
            "surface digest/order does not match its root evidence".to_string(),
        ));
    }
    Ok(())
}

fn snapshot_tree(
    root: &Path,
    budget: &mut SurfaceBudget,
) -> Result<TreeEvidence, ExternalProvenanceError> {
    let mut directories = Vec::new();
    let mut files = BTreeMap::new();
    let mut root_bytes = 0u64;
    let mut pending = vec![(root.to_path_buf(), String::new())];

    while let Some((directory, prefix)) = pending.pop() {
        let mut entries = BTreeMap::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| {
                ExternalProvenanceError::UnsupportedEntry(
                    "external read paths must be valid Unicode for deterministic provenance"
                        .to_string(),
                )
            })?;
            entries.insert(name, entry.path());
        }

        for (name, path) in entries {
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if relative.contains('\0') || relative.contains('\\') {
                return Err(ExternalProvenanceError::UnsupportedEntry(relative));
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
                return Err(ExternalProvenanceError::UnsupportedEntry(format!(
                    "symlink/reparse-point entry: {relative}"
                )));
            }
            let canonical = fs::canonicalize(&path)?;
            if !canonical.starts_with(root) {
                return Err(ExternalProvenanceError::UnsupportedEntry(format!(
                    "external entry escaped its canonical root: {relative}"
                )));
            }

            if metadata.is_dir() {
                budget.directories = budget
                    .directories
                    .checked_add(1)
                    .ok_or(ExternalProvenanceError::DirectoryLimitExceeded)?;
                if budget.directories > MAX_EXTERNAL_READ_DIRECTORIES {
                    return Err(ExternalProvenanceError::DirectoryLimitExceeded);
                }
                directories.push(relative.clone());
                pending.push((canonical, relative));
            } else if metadata.is_file() {
                budget.files = budget
                    .files
                    .checked_add(1)
                    .ok_or(ExternalProvenanceError::FileLimitExceeded)?;
                if budget.files > MAX_EXTERNAL_READ_FILES {
                    return Err(ExternalProvenanceError::FileLimitExceeded);
                }
                budget.bytes = budget
                    .bytes
                    .checked_add(metadata.len())
                    .ok_or(ExternalProvenanceError::ByteLimitExceeded)?;
                root_bytes = root_bytes
                    .checked_add(metadata.len())
                    .ok_or(ExternalProvenanceError::ByteLimitExceeded)?;
                if budget.bytes > MAX_EXTERNAL_READ_BYTES {
                    return Err(ExternalProvenanceError::ByteLimitExceeded);
                }
                files.insert(
                    relative.clone(),
                    FileEvidence {
                        relative_path: relative,
                        sha256: sha256_file(&canonical)?,
                        byte_size: metadata.len(),
                    },
                );
            } else {
                return Err(ExternalProvenanceError::UnsupportedEntry(format!(
                    "special filesystem entry: {relative}"
                )));
            }
        }
    }

    directories.sort();
    Ok(TreeEvidence {
        directories,
        files: files.into_values().collect(),
        total_bytes: root_bytes,
    })
}

fn tree_manifest_sha256(tree: &TreeEvidence) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codetwin-external-read-root-v1\0");
    for directory in &tree.directories {
        digest.update(b"D\0");
        digest.update(directory.as_bytes());
        digest.update(b"\0");
    }
    for file in &tree.files {
        digest.update(b"F\0");
        digest.update(file.relative_path.as_bytes());
        digest.update(b"\0");
        digest.update(file.byte_size.to_le_bytes());
        digest.update(b"\0");
        digest.update(file.sha256.as_bytes());
        digest.update(b"\0");
    }
    hex_digest(digest.finalize().as_ref())
}

fn surface_sha256(roots: &[ExternalReadRootEvidence]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codetwin-external-read-surface-v1\0");
    for root in roots {
        digest.update(b"R\0");
        digest.update(root.kind.as_str().as_bytes());
        digest.update(b"\0");
        digest.update(root.canonical_path.as_bytes());
        digest.update(b"\0");
        digest.update(root.manifest_sha256.as_bytes());
        digest.update(b"\0");
        digest.update(root.file_count.to_le_bytes());
        digest.update(root.directory_count.to_le_bytes());
        digest.update(root.total_bytes.to_le_bytes());
        digest.update(b"\0");
    }
    hex_digest(digest.finalize().as_ref())
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, ExternalProvenanceError> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(ExternalProvenanceError::InvalidDeclaration(format!(
            "{label} is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
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
    Ok(hex_digest(digest.finalize().as_ref()))
}

fn declaration_key(root: &DeclaredExternalReadRoot) -> String {
    format!("{}\0{}", root.kind.as_str(), canonical_path_key(&root.path))
}

fn evidence_sort_key(root: &ExternalReadRootEvidence) -> (ExternalReadRootKind, String) {
    (root.kind, canonical_path_key(&root.canonical_path))
}

fn canonical_path_key(value: &str) -> String {
    if cfg!(windows) {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
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
        capture_external_read_surface, verify_external_read_surface, DeclaredExternalReadRoot,
        ExternalProvenanceError, ExternalReadRootKind,
    };

    fn temp_directory(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!("codetwin-{label}-{nanos}"));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    #[test]
    fn captures_and_revalidates_declared_external_tree() {
        let project = temp_directory("external-project");
        let runtime = temp_directory("external-runtime");
        fs::create_dir_all(runtime.join("Lib/pkg")).expect("stdlib dirs");
        fs::write(runtime.join("Lib/os.py"), "VALUE = 1\n").expect("stdlib file");
        fs::write(runtime.join("Lib/pkg/mod.py"), "VALUE = 2\n").expect("pkg file");
        let roots = vec![DeclaredExternalReadRoot {
            kind: ExternalReadRootKind::RuntimeRoot,
            path: runtime.to_string_lossy().into_owned(),
        }];

        let approved = capture_external_read_surface(&roots, &project).expect("capture");
        assert_eq!(approved.sha256.len(), 64);
        assert_eq!(approved.roots.len(), 1);
        assert_eq!(approved.roots[0].file_count, 2);
        verify_external_read_surface(&roots, &approved, &project).expect("verify");

        fs::write(runtime.join("Lib/os.py"), "VALUE = 3\n").expect("mutate runtime");
        assert!(matches!(
            verify_external_read_surface(&roots, &approved, &project),
            Err(ExternalProvenanceError::SurfaceChanged)
        ));

        let _ = fs::remove_dir_all(project);
        let _ = fs::remove_dir_all(runtime);
    }

    #[test]
    fn empty_external_declaration_fails_closed() {
        let project = temp_directory("external-empty-project");
        assert!(matches!(
            capture_external_read_surface(&[], &project),
            Err(ExternalProvenanceError::NoDeclaredRoots)
        ));
        let _ = fs::remove_dir_all(project);
    }
}
