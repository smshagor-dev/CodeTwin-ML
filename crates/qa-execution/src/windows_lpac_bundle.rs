use std::{
    collections::BTreeMap,
    ffi::c_void,
    fmt::Write as _,
    fs::{self, File},
    io::Read,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HLOCAL, LocalFree},
    Security::{
        ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, FreeSid,
        OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE,
        WinWriteRestrictedCodeSid,
        Authorization::{
            EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
            TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W, SetEntriesInAclW,
            SetNamedSecurityInfoW,
        },
        Isolation::{CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName},
    },
    Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    },
};

use crate::{
    validate_approved_external_read_surface_shape, ApprovedExternalReadSurface,
    BackendExecutionError, DetachedExecutionWorkspace, ExternalReadRootEvidence,
    TestExecutionPlan, MAX_EXTERNAL_READ_BYTES, MAX_EXTERNAL_READ_DIRECTORIES,
    MAX_EXTERNAL_READ_FILES, MAX_EXTERNAL_READ_ROOTS,
};

const BUNDLE_DIRECTORY_NAME: &str = "lpac-external";
const LPAC_PROFILE_NAME: &str = "CodeTwinML.QA.RestrictedRunner.V1";
const LPAC_PROFILE_DISPLAY_NAME: &str = "CodeTwin ML QA Restricted Runner";
const LPAC_PROFILE_DESCRIPTION: &str =
    "Zero-capability Less Privileged AppContainer used to attest QA sandbox composition.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LpacExecutionBundleEvidence {
    pub root_count: usize,
    pub file_count: u64,
    pub directory_count: u64,
    pub total_bytes: u64,
    pub approved_roots_verified: bool,
    pub source_stable_during_copy: bool,
    pub destination_manifests_verified: bool,
    pub copied_files_read_only: bool,
    pub runner_mapped_from_single_approved_root: bool,
    pub runner_hash_verified: bool,
    pub appcontainer_acl_applied: bool,
    pub write_restricted_acl_applied: bool,
    pub production_launcher_uses_bundle: bool,
}

impl LpacExecutionBundleEvidence {
    pub(crate) const fn satisfies_readiness_contract(&self) -> bool {
        self.root_count > 0
            && self.root_count <= MAX_EXTERNAL_READ_ROOTS
            && self.file_count > 0
            && self.file_count <= MAX_EXTERNAL_READ_FILES as u64
            && self.directory_count <= MAX_EXTERNAL_READ_DIRECTORIES as u64
            && self.total_bytes <= MAX_EXTERNAL_READ_BYTES
            && self.approved_roots_verified
            && self.source_stable_during_copy
            && self.destination_manifests_verified
            && self.copied_files_read_only
            && self.runner_mapped_from_single_approved_root
            && self.runner_hash_verified
            && self.appcontainer_acl_applied
            && self.write_restricted_acl_applied
            && self.production_launcher_uses_bundle
    }
}

#[derive(Debug)]
pub(crate) struct LpacExecutionBundle {
    root_path: PathBuf,
    runner_path: PathBuf,
    evidence: LpacExecutionBundleEvidence,
}

impl LpacExecutionBundle {
    pub(crate) fn root_path(&self) -> &Path {
        &self.root_path
    }

    pub(crate) fn runner_path(&self) -> &Path {
        &self.runner_path
    }

    pub(crate) fn evidence(&self) -> &LpacExecutionBundleEvidence {
        &self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundleFileSnapshot {
    relative_path: String,
    sha256: String,
    byte_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundleTreeSnapshot {
    directories: Vec<String>,
    files: Vec<BundleFileSnapshot>,
    total_bytes: u64,
}

#[derive(Debug)]
struct CopiedRoot {
    destination: PathBuf,
    snapshot: BundleTreeSnapshot,
}

pub(crate) fn prepare_lpac_execution_bundle(
    plan: &TestExecutionPlan,
    approved: &ApprovedExternalReadSurface,
    workspace: &DetachedExecutionWorkspace,
) -> Result<LpacExecutionBundle, BackendExecutionError> {
    validate_approved_external_read_surface_shape(approved).map_err(|error| {
        BackendExecutionError::JobSetup(format!(
            "LPAC external bundle approved evidence: {error}"
        ))
    })?;

    let workspace_root = fs::canonicalize(&workspace.root_path).map_err(|error| {
        BackendExecutionError::JobSetup(format!(
            "LPAC external bundle workspace root: {error}"
        ))
    })?;
    let source_project = fs::canonicalize(&workspace.source_root).map_err(|error| {
        BackendExecutionError::JobSetup(format!(
            "LPAC external bundle project root: {error}"
        ))
    })?;
    if workspace_root.starts_with(&source_project) {
        return Err(BackendExecutionError::JobSetup(
            "LPAC external bundle workspace unexpectedly resides inside the analyzed repository"
                .to_string(),
        ));
    }

    let bundle_root = workspace_root.join(BUNDLE_DIRECTORY_NAME);
    if bundle_root.exists() {
        return Err(BackendExecutionError::JobSetup(
            "LPAC external bundle directory already exists".to_string(),
        ));
    }
    fs::create_dir(&bundle_root)?;

    let result = prepare_bundle_inner(plan, approved, workspace, &bundle_root);
    if result.is_err() {
        let _ = fs::remove_dir_all(&bundle_root);
    }
    result
}

fn prepare_bundle_inner(
    plan: &TestExecutionPlan,
    approved: &ApprovedExternalReadSurface,
    workspace: &DetachedExecutionWorkspace,
    bundle_root: &Path,
) -> Result<LpacExecutionBundle, BackendExecutionError> {
    let runner_source = canonical_regular_file(Path::new(&plan.toolchain.executable_path), "runner")?;
    let expected_runner_hash = plan
        .toolchain
        .sha256
        .as_deref()
        .ok_or(BackendExecutionError::MissingToolchainHash)?;
    if !valid_sha256(expected_runner_hash) {
        return Err(BackendExecutionError::InvalidToolchain(
            "trusted runner SHA-256 must be 64 hexadecimal characters".to_string(),
        ));
    }

    let mut copied_roots = Vec::with_capacity(approved.roots.len());
    let mut runner_destinations = Vec::new();
    let mut aggregate_files = 0u64;
    let mut aggregate_directories = 0u64;
    let mut aggregate_bytes = 0u64;

    for (index, evidence) in approved.roots.iter().enumerate() {
        let source_root = canonical_directory(Path::new(&evidence.canonical_path), "approved root")?;
        if !path_text(&source_root).eq_ignore_ascii_case(&evidence.canonical_path) {
            return Err(BackendExecutionError::JobSetup(format!(
                "LPAC external bundle root canonical path drifted: {}",
                evidence.canonical_path
            )));
        }

        let source_before = snapshot_tree(&source_root)?;
        require_snapshot_matches_evidence(&source_before, evidence, "source before copy")?;

        aggregate_files = aggregate_files
            .checked_add(u64::try_from(source_before.files.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                BackendExecutionError::JobSetup("LPAC bundle file count overflow".to_string())
            })?;
        aggregate_directories = aggregate_directories
            .checked_add(u64::try_from(source_before.directories.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                BackendExecutionError::JobSetup("LPAC bundle directory count overflow".to_string())
            })?;
        aggregate_bytes = aggregate_bytes
            .checked_add(source_before.total_bytes)
            .ok_or_else(|| {
                BackendExecutionError::JobSetup("LPAC bundle byte count overflow".to_string())
            })?;
        enforce_aggregate_bounds(aggregate_files, aggregate_directories, aggregate_bytes)?;

        let destination =
            bundle_root.join(format!("root-{index:02}-{}", evidence.kind.as_str()));
        fs::create_dir(&destination)?;
        copy_tree(&source_root, &destination, &source_before)?;

        let source_after = snapshot_tree(&source_root)?;
        if source_after != source_before {
            return Err(BackendExecutionError::JobSetup(format!(
                "LPAC external bundle source changed during copy: {}",
                evidence.canonical_path
            )));
        }
        require_snapshot_matches_evidence(&source_after, evidence, "source after copy")?;

        let destination_snapshot = snapshot_tree(&destination)?;
        require_snapshot_matches_evidence(&destination_snapshot, evidence, "detached copy")?;
        if destination_snapshot != source_before {
            return Err(BackendExecutionError::JobSetup(format!(
                "LPAC external bundle detached copy does not match source manifest: {}",
                evidence.canonical_path
            )));
        }
        for file in &destination_snapshot.files {
            if !fs::metadata(destination.join(&file.relative_path))?
                .permissions()
                .readonly()
            {
                return Err(BackendExecutionError::JobSetup(format!(
                    "LPAC external bundle copied file is not read-only: {}",
                    file.relative_path
                )));
            }
        }

        if runner_source.starts_with(&source_root) {
            let relative = runner_source.strip_prefix(&source_root).map_err(|error| {
                BackendExecutionError::JobSetup(format!(
                    "LPAC external bundle runner mapping failed: {error}"
                ))
            })?;
            if relative.as_os_str().is_empty() {
                return Err(BackendExecutionError::JobSetup(
                    "trusted runner unexpectedly resolves to an external root directory"
                        .to_string(),
                ));
            }
            runner_destinations.push(destination.join(relative));
        }

        copied_roots.push(CopiedRoot {
            destination,
            snapshot: destination_snapshot,
        });
    }

    if runner_destinations.len() != 1 {
        return Err(BackendExecutionError::JobSetup(format!(
            "trusted runner must map into exactly one approved external root, found {} mappings",
            runner_destinations.len()
        )));
    }
    let runner_path = canonical_regular_file(&runner_destinations[0], "bundled runner")?;
    if !sha256_file(&runner_path)?.eq_ignore_ascii_case(expected_runner_hash) {
        return Err(BackendExecutionError::ToolchainHashMismatch);
    }

    apply_generated_acl_contract(workspace, bundle_root, &copied_roots)?;

    Ok(LpacExecutionBundle {
        root_path: fs::canonicalize(bundle_root)?,
        runner_path,
        evidence: LpacExecutionBundleEvidence {
            root_count: copied_roots.len(),
            file_count: aggregate_files,
            directory_count: aggregate_directories,
            total_bytes: aggregate_bytes,
            approved_roots_verified: true,
            source_stable_during_copy: true,
            destination_manifests_verified: true,
            copied_files_read_only: true,
            runner_mapped_from_single_approved_root: true,
            runner_hash_verified: true,
            appcontainer_acl_applied: true,
            write_restricted_acl_applied: true,
            production_launcher_uses_bundle: true,
        },
    })
}

fn copy_tree(
    source_root: &Path,
    destination_root: &Path,
    snapshot: &BundleTreeSnapshot,
) -> Result<(), BackendExecutionError> {
    let mut directories = snapshot.directories.clone();
    directories.sort_by_key(|relative| (relative.matches('/').count(), relative.clone()));
    for relative in directories {
        fs::create_dir_all(destination_root.join(relative))?;
    }

    for file in &snapshot.files {
        let source = source_root.join(&file.relative_path);
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !metadata.is_file()
            || metadata.len() != file.byte_size
        {
            return Err(BackendExecutionError::JobSetup(format!(
                "LPAC external bundle source entry changed before copy: {}",
                file.relative_path
            )));
        }
        let source = fs::canonicalize(source)?;
        if !source.starts_with(source_root) || sha256_file(&source)? != file.sha256 {
            return Err(BackendExecutionError::JobSetup(format!(
                "LPAC external bundle source hash changed before copy: {}",
                file.relative_path
            )));
        }

        let destination = destination_root.join(&file.relative_path);
        let parent = destination.parent().ok_or_else(|| {
            BackendExecutionError::JobSetup(format!(
                "LPAC external bundle destination has no parent: {}",
                file.relative_path
            ))
        })?;
        fs::create_dir_all(parent)?;
        fs::copy(&source, &destination)?;
        let mut permissions = fs::metadata(&destination)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&destination, permissions)?;

        let copied = fs::symlink_metadata(&destination)?;
        if copied.file_type().is_symlink()
            || copied.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !copied.is_file()
            || copied.len() != file.byte_size
            || sha256_file(&destination)? != file.sha256
            || !copied.permissions().readonly()
        {
            return Err(BackendExecutionError::JobSetup(format!(
                "LPAC external bundle destination verification failed: {}",
                file.relative_path
            )));
        }
    }
    Ok(())
}

fn snapshot_tree(root: &Path) -> Result<BundleTreeSnapshot, BackendExecutionError> {
    let root = canonical_directory(root, "snapshot root")?;
    let mut directories = Vec::new();
    let mut files = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut pending = vec![(root.clone(), String::new())];

    while let Some((directory, prefix)) = pending.pop() {
        let mut entries = BTreeMap::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| {
                BackendExecutionError::JobSetup(
                    "LPAC external bundle paths must be valid Unicode".to_string(),
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
                return Err(BackendExecutionError::JobSetup(format!(
                    "LPAC external bundle contains an unsafe path: {relative}"
                )));
            }

            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(BackendExecutionError::JobSetup(format!(
                    "LPAC external bundle rejects symlink/reparse entry: {relative}"
                )));
            }
            let canonical = fs::canonicalize(&path)?;
            if !canonical.starts_with(&root) {
                return Err(BackendExecutionError::JobSetup(format!(
                    "LPAC external bundle entry escaped its root: {relative}"
                )));
            }

            if metadata.is_dir() {
                directories.push(relative.clone());
                if directories.len() > MAX_EXTERNAL_READ_DIRECTORIES {
                    return Err(BackendExecutionError::JobSetup(
                        "LPAC external bundle exceeds directory bound".to_string(),
                    ));
                }
                pending.push((canonical, relative));
            } else if metadata.is_file() {
                if files.len() >= MAX_EXTERNAL_READ_FILES {
                    return Err(BackendExecutionError::JobSetup(
                        "LPAC external bundle exceeds file bound".to_string(),
                    ));
                }
                total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
                    BackendExecutionError::JobSetup(
                        "LPAC external bundle byte count overflow".to_string(),
                    )
                })?;
                if total_bytes > MAX_EXTERNAL_READ_BYTES {
                    return Err(BackendExecutionError::JobSetup(
                        "LPAC external bundle exceeds byte bound".to_string(),
                    ));
                }
                files.insert(
                    relative.clone(),
                    BundleFileSnapshot {
                        relative_path: relative,
                        sha256: sha256_file(&canonical)?,
                        byte_size: metadata.len(),
                    },
                );
            } else {
                return Err(BackendExecutionError::JobSetup(format!(
                    "LPAC external bundle rejects special filesystem entry: {relative}"
                )));
            }
        }
    }

    directories.sort();
    Ok(BundleTreeSnapshot {
        directories,
        files: files.into_values().collect(),
        total_bytes,
    })
}

fn require_snapshot_matches_evidence(
    snapshot: &BundleTreeSnapshot,
    evidence: &ExternalReadRootEvidence,
    label: &str,
) -> Result<(), BackendExecutionError> {
    let file_count = u64::try_from(snapshot.files.len()).unwrap_or(u64::MAX);
    let directory_count = u64::try_from(snapshot.directories.len()).unwrap_or(u64::MAX);
    let manifest = tree_manifest_sha256(snapshot);
    if file_count != evidence.file_count
        || directory_count != evidence.directory_count
        || snapshot.total_bytes != evidence.total_bytes
        || manifest != evidence.manifest_sha256
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "LPAC external bundle {label} does not match approved root {}",
            evidence.canonical_path
        )));
    }
    Ok(())
}

fn tree_manifest_sha256(snapshot: &BundleTreeSnapshot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codetwin-external-read-root-v1\0");
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
    hex_digest(digest.finalize().as_ref())
}

fn enforce_aggregate_bounds(
    files: u64,
    directories: u64,
    bytes: u64,
) -> Result<(), BackendExecutionError> {
    if files > u64::try_from(MAX_EXTERNAL_READ_FILES).unwrap_or(u64::MAX)
        || directories > u64::try_from(MAX_EXTERNAL_READ_DIRECTORIES).unwrap_or(u64::MAX)
        || bytes > MAX_EXTERNAL_READ_BYTES
    {
        return Err(BackendExecutionError::JobSetup(
            "LPAC external bundle exceeds approved aggregate bounds".to_string(),
        ));
    }
    Ok(())
}

fn apply_generated_acl_contract(
    workspace: &DetachedExecutionWorkspace,
    bundle_root: &Path,
    copied_roots: &[CopiedRoot],
) -> Result<(), BackendExecutionError> {
    let appcontainer_sid = AppContainerProfileSid::open_or_create()?;
    let mut restricting_sid = write_restricted_sid()?;
    let restricting_sid = restricting_sid.as_mut_ptr().cast::<c_void>();

    let workspace_root = Path::new(&workspace.root_path);
    let inputs = Path::new(&workspace.inputs_path);
    let artifacts = Path::new(&workspace.artifacts_path);
    let temp = Path::new(&workspace.temp_path);

    let read_execute = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    let write_directory = FILE_GENERIC_READ
        | FILE_GENERIC_WRITE
        | FILE_GENERIC_EXECUTE
        | FILE_DELETE_CHILD
        | DELETE;

    grant_sid(workspace_root, appcontainer_sid.sid(), read_execute, true)?;
    grant_sid(inputs, appcontainer_sid.sid(), read_execute, true)?;
    grant_sid(artifacts, appcontainer_sid.sid(), write_directory, true)?;
    grant_sid(temp, appcontainer_sid.sid(), write_directory, true)?;
    for file in &workspace.files {
        grant_sid(
            &inputs.join(&file.relative_path),
            appcontainer_sid.sid(),
            read_execute,
            false,
        )?;
    }

    grant_sid(bundle_root, appcontainer_sid.sid(), read_execute, true)?;
    grant_sid(bundle_root, restricting_sid, read_execute, true)?;
    for copied in copied_roots {
        grant_sid(&copied.destination, appcontainer_sid.sid(), read_execute, true)?;
        grant_sid(&copied.destination, restricting_sid, read_execute, true)?;
        for directory in &copied.snapshot.directories {
            let path = copied.destination.join(directory);
            grant_sid(&path, appcontainer_sid.sid(), read_execute, true)?;
            grant_sid(&path, restricting_sid, read_execute, true)?;
        }
        for file in &copied.snapshot.files {
            let path = copied.destination.join(&file.relative_path);
            grant_sid(&path, appcontainer_sid.sid(), read_execute, false)?;
            grant_sid(&path, restricting_sid, read_execute, false)?;
        }
    }
    Ok(())
}

fn grant_sid(
    path: &Path,
    sid: PSID,
    access_mask: u32,
    inherit: bool,
) -> Result<(), BackendExecutionError> {
    struct LocalMemory(HLOCAL);
    impl Drop for LocalMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    let mut path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut old_dacl: *mut ACL = std::ptr::null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let get_code = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_dacl,
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if get_code != ERROR_SUCCESS {
        return Err(BackendExecutionError::JobSetup(format!(
            "GetNamedSecurityInfoW({}) returned {get_code}",
            path.display()
        )));
    }
    let _security_descriptor = LocalMemory(security_descriptor as HLOCAL);

    let inheritance = if inherit {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };
    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid as *mut u16,
        },
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    let acl_code = unsafe { SetEntriesInAclW(1, &explicit, old_dacl, &mut new_dacl) };
    if acl_code != ERROR_SUCCESS || new_dacl.is_null() {
        return Err(BackendExecutionError::JobSetup(format!(
            "SetEntriesInAclW({}) returned {acl_code}",
            path.display()
        )));
    }
    let new_dacl_memory = LocalMemory(new_dacl as HLOCAL);
    let set_code = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        )
    };
    drop(new_dacl_memory);
    if set_code != ERROR_SUCCESS {
        return Err(BackendExecutionError::JobSetup(format!(
            "SetNamedSecurityInfoW({}) returned {set_code}",
            path.display()
        )));
    }
    Ok(())
}

struct AppContainerProfileSid(PSID);

impl AppContainerProfileSid {
    fn open_or_create() -> Result<Self, BackendExecutionError> {
        let name = wide_null(LPAC_PROFILE_NAME);
        let display = wide_null(LPAC_PROFILE_DISPLAY_NAME);
        let description = wide_null(LPAC_PROFILE_DESCRIPTION);
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
                    "CreateAppContainerProfile(bundle ACL) returned success without a SID"
                        .to_string(),
                ));
            }
            return Ok(Self(sid));
        }
        if result != hresult_from_win32(ERROR_ALREADY_EXISTS) {
            return Err(BackendExecutionError::JobSetup(format!(
                "CreateAppContainerProfile(bundle ACL) failed with HRESULT 0x{:08x}",
                result as u32
            )));
        }
        let derived = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if derived < 0 || sid.is_null() {
            return Err(BackendExecutionError::JobSetup(format!(
                "DeriveAppContainerSidFromAppContainerName(bundle ACL) failed with HRESULT 0x{:08x}",
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
            unsafe {
                FreeSid(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

fn write_restricted_sid() -> Result<Vec<u8>, BackendExecutionError> {
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = sid.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinWriteRestrictedCodeSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast::<c_void>(),
            &mut sid_len,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "CreateWellKnownSid(WinWriteRestrictedCodeSid, bundle ACL): {}",
            std::io::Error::last_os_error()
        )));
    }
    sid.truncate(sid_len as usize);
    Ok(sid)
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf, BackendExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        BackendExecutionError::JobSetup(format!("LPAC external bundle {label}: {error}"))
    })?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "LPAC external bundle {label} is not a regular non-reparse file"
        )));
    }
    Ok(fs::canonicalize(path)?)
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, BackendExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        BackendExecutionError::JobSetup(format!("LPAC external bundle {label}: {error}"))
    })?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_dir()
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "LPAC external bundle {label} is not a regular non-reparse directory"
        )));
    }
    Ok(fs::canonicalize(path)?)
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

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

const fn hresult_from_win32(code: u32) -> i32 {
    if code == 0 {
        0
    } else {
        (0x8007_0000u32 | (code & 0xffff)) as i32
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
