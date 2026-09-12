use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{verify_detached_workspace, DetachedExecutionWorkspace};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestrictedIdentityEvidence {
    pub platform: String,
    pub restricted_primary_token_created: bool,
    pub privileges_disabled: bool,
    pub write_restricted: bool,
    pub low_integrity: bool,
    pub workspace_acl_applied: bool,
    pub workspace_low_integrity_label: bool,
    pub source_root_write_denied: bool,
    pub staged_inputs_write_denied: bool,
    pub artifacts_write_allowed: bool,
    pub temp_write_allowed: bool,
    pub executor_uses_restricted_token: bool,
    pub filesystem_isolation_promoted: bool,
    pub network_isolation_enforced: bool,
}

#[derive(Debug, Error)]
pub enum RestrictedIdentityError {
    #[error("restricted Windows identity is unavailable on this platform")]
    UnsupportedPlatform,
    #[error("detached workspace verification failed: {0}")]
    InvalidWorkspace(String),
    #[error("Windows restricted-token setup failed: {0}")]
    TokenSetup(String),
    #[error("Windows restricted-token verification failed: {0}")]
    TokenVerification(String),
    #[error("Windows workspace ACL setup failed for {path}: {message}")]
    WorkspaceAcl { path: String, message: String },
    #[error("Windows workspace integrity-label setup failed for {path}: {message}")]
    WorkspaceIntegrityLabel { path: String, message: String },
    #[error("Windows restricted-token access probe failed for {path}: {message}")]
    AccessProbe { path: String, message: String },
    #[error("restricted token unexpectedly retained write access to the analyzed repository root")]
    SourceWriteAllowed,
    #[error("restricted token unexpectedly retained write access to staged read-only inputs")]
    InputsWriteAllowed,
    #[error("restricted token cannot write to the detached artifacts directory")]
    ArtifactsWriteDenied,
    #[error("restricted token cannot write to the detached temp directory")]
    TempWriteDenied,
    #[error("failed to revert Windows thread impersonation: {0}")]
    ImpersonationRevert(String),
}

pub fn probe_restricted_identity(
    workspace: &DetachedExecutionWorkspace,
) -> Result<RestrictedIdentityEvidence, RestrictedIdentityError> {
    verify_detached_workspace(workspace)
        .map_err(|error| RestrictedIdentityError::InvalidWorkspace(error.to_string()))?;

    #[cfg(windows)]
    {
        probe_windows_restricted_identity(workspace)
    }
    #[cfg(not(windows))]
    {
        let _ = workspace;
        Err(RestrictedIdentityError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
pub(crate) struct WindowsRestrictedToken(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl WindowsRestrictedToken {
    pub(crate) const fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for WindowsRestrictedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
pub(crate) fn create_windows_write_restricted_token(
) -> Result<WindowsRestrictedToken, RestrictedIdentityError> {
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{
            CreateRestrictedToken, CreateWellKnownSid, GetLengthSid, IsTokenRestricted,
            SetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_MANDATORY_LABEL,
            DISABLE_MAX_PRIVILEGE, SECURITY_MAX_SID_SIZE, SE_GROUP_INTEGRITY,
            TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
            TokenIntegrityLevel, WRITE_RESTRICTED, WinLowLabelSid, WinWriteRestrictedCodeSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    let mut base_token: HANDLE = std::ptr::null_mut();
    let desired_access =
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;
    if unsafe { OpenProcessToken(GetCurrentProcess(), desired_access, &mut base_token) } == 0 {
        return Err(RestrictedIdentityError::TokenSetup(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let base_token = Handle(base_token);

    let mut restricting_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut restricting_sid_len = restricting_sid.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinWriteRestrictedCodeSid,
            std::ptr::null_mut(),
            restricting_sid.as_mut_ptr().cast::<c_void>(),
            &mut restricting_sid_len,
        )
    } == 0
    {
        return Err(RestrictedIdentityError::TokenSetup(format!(
            "CreateWellKnownSid(WinWriteRestrictedCodeSid): {}",
            std::io::Error::last_os_error()
        )));
    }
    let restricting_sid_ptr = restricting_sid.as_mut_ptr().cast::<c_void>();
    let restricting_entry = SID_AND_ATTRIBUTES {
        Sid: restricting_sid_ptr,
        Attributes: 0,
    };

    let mut restricted_token: HANDLE = std::ptr::null_mut();
    let flags = DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED;
    if unsafe {
        CreateRestrictedToken(
            base_token.0,
            flags,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            1,
            &restricting_entry,
            &mut restricted_token,
        )
    } == 0
    {
        return Err(RestrictedIdentityError::TokenSetup(format!(
            "CreateRestrictedToken: {}",
            std::io::Error::last_os_error()
        )));
    }
    let restricted_token = WindowsRestrictedToken(restricted_token);

    if unsafe { IsTokenRestricted(restricted_token.raw()) } == 0 {
        return Err(RestrictedIdentityError::TokenVerification(
            "IsTokenRestricted returned false after adding a restricting SID".to_string(),
        ));
    }

    let mut low_sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut low_sid_len = low_sid.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinLowLabelSid,
            std::ptr::null_mut(),
            low_sid.as_mut_ptr().cast::<c_void>(),
            &mut low_sid_len,
        )
    } == 0
    {
        return Err(RestrictedIdentityError::TokenSetup(format!(
            "CreateWellKnownSid(WinLowLabelSid): {}",
            std::io::Error::last_os_error()
        )));
    }
    let low_sid_ptr = low_sid.as_mut_ptr().cast::<c_void>();
    let mut mandatory_label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low_sid_ptr,
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    let token_label_len = u32::try_from(std::mem::size_of::<TOKEN_MANDATORY_LABEL>())
        .unwrap_or(u32::MAX)
        .saturating_add(unsafe { GetLengthSid(low_sid_ptr) });
    if unsafe {
        SetTokenInformation(
            restricted_token.raw(),
            TokenIntegrityLevel,
            (&mut mandatory_label as *mut TOKEN_MANDATORY_LABEL).cast::<c_void>(),
            token_label_len,
        )
    } == 0
    {
        return Err(RestrictedIdentityError::TokenSetup(format!(
            "SetTokenInformation(TokenIntegrityLevel): {}",
            std::io::Error::last_os_error()
        )));
    }

    if !token_has_low_integrity(restricted_token.raw(), low_sid_ptr)? {
        return Err(RestrictedIdentityError::TokenVerification(
            "restricted token did not retain the requested low integrity label".to_string(),
        ));
    }

    Ok(restricted_token)
}

#[cfg(windows)]
fn token_has_low_integrity(
    token: windows_sys::Win32::Foundation::HANDLE,
    expected_low_sid: windows_sys::Win32::Security::PSID,
) -> Result<bool, RestrictedIdentityError> {
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TOKEN_MANDATORY_LABEL, TokenIntegrityLevel,
    };

    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(RestrictedIdentityError::TokenVerification(format!(
            "GetTokenInformation(TokenIntegrityLevel) size query: {}",
            std::io::Error::last_os_error()
        )));
    }
    let word = std::mem::size_of::<usize>();
    let words = (needed as usize).div_ceil(word);
    let mut storage = vec![0usize; words.max(1)];
    if unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(RestrictedIdentityError::TokenVerification(format!(
            "GetTokenInformation(TokenIntegrityLevel): {}",
            std::io::Error::last_os_error()
        )));
    }
    let label = unsafe { &*(storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    Ok(unsafe { EqualSid(label.Label.Sid, expected_low_sid) } != 0)
}

#[cfg(windows)]
fn probe_windows_restricted_identity(
    workspace: &DetachedExecutionWorkspace,
) -> Result<RestrictedIdentityEvidence, RestrictedIdentityError> {
    use std::path::Path;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    };

    let token = create_windows_write_restricted_token()?;
    let mut restricting_sid = windows_write_restricted_sid()?;
    let restricting_sid_ptr = restricting_sid.as_mut_ptr().cast();

    apply_workspace_security_contract(workspace, restricting_sid_ptr)?;

    let source_root = Path::new(&workspace.source_root);
    let inputs = Path::new(&workspace.inputs_path);
    let artifacts = Path::new(&workspace.artifacts_path);
    let temp = Path::new(&workspace.temp_path);

    if unsafe { windows_sys::Win32::Security::ImpersonateLoggedOnUser(token.raw()) } == 0 {
        return Err(RestrictedIdentityError::TokenVerification(format!(
            "ImpersonateLoggedOnUser: {}",
            std::io::Error::last_os_error()
        )));
    }

    let directory_mutation_rights = [
        FILE_ADD_FILE,
        FILE_ADD_SUBDIRECTORY,
        FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_EA,
        FILE_DELETE_CHILD,
        DELETE,
        WRITE_DAC,
        WRITE_OWNER,
    ];
    let file_mutation_rights = [
        FILE_WRITE_DATA,
        FILE_APPEND_DATA,
        FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_EA,
        DELETE,
        WRITE_DAC,
        WRITE_OWNER,
    ];
    let workspace_write_rights = FILE_ADD_FILE
        | FILE_ADD_SUBDIRECTORY
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA
        | FILE_DELETE_CHILD;

    let access_result = (|| {
        let source_root_write =
            path_has_any_access(source_root, &directory_mutation_rights, true)?;
        let inputs_directory_write =
            path_has_any_access(inputs, &directory_mutation_rights, true)?;
        let mut staged_input_write = false;
        for file in &workspace.files {
            let staged = inputs.join(&file.relative_path);
            if path_has_any_access(&staged, &file_mutation_rights, false)? {
                staged_input_write = true;
                break;
            }
        }
        let artifacts_write = path_has_access(artifacts, workspace_write_rights, true)?;
        let temp_write = path_has_access(temp, workspace_write_rights, true)?;
        Ok::<_, RestrictedIdentityError>((
            source_root_write,
            inputs_directory_write || staged_input_write,
            artifacts_write,
            temp_write,
        ))
    })();

    if unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
        return Err(RestrictedIdentityError::ImpersonationRevert(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let (source_root_write, inputs_write, artifacts_write, temp_write) = access_result?;
    if source_root_write {
        return Err(RestrictedIdentityError::SourceWriteAllowed);
    }
    if inputs_write {
        return Err(RestrictedIdentityError::InputsWriteAllowed);
    }
    if !artifacts_write {
        return Err(RestrictedIdentityError::ArtifactsWriteDenied);
    }
    if !temp_write {
        return Err(RestrictedIdentityError::TempWriteDenied);
    }

    Ok(RestrictedIdentityEvidence {
        platform: "windows".to_string(),
        restricted_primary_token_created: true,
        privileges_disabled: true,
        write_restricted: true,
        low_integrity: true,
        workspace_acl_applied: true,
        workspace_low_integrity_label: true,
        source_root_write_denied: true,
        staged_inputs_write_denied: true,
        artifacts_write_allowed: true,
        temp_write_allowed: true,
        executor_uses_restricted_token: false,
        filesystem_isolation_promoted: false,
        network_isolation_enforced: false,
    })
}

#[cfg(windows)]
fn windows_write_restricted_sid() -> Result<Vec<u8>, RestrictedIdentityError> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinWriteRestrictedCodeSid,
    };

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
        return Err(RestrictedIdentityError::TokenSetup(format!(
            "CreateWellKnownSid(WinWriteRestrictedCodeSid): {}",
            std::io::Error::last_os_error()
        )));
    }
    sid.truncate(sid_len as usize);
    Ok(sid)
}

#[cfg(windows)]
fn apply_workspace_security_contract(
    workspace: &DetachedExecutionWorkspace,
    restricting_sid: windows_sys::Win32::Security::PSID,
) -> Result<(), RestrictedIdentityError> {
    use std::path::Path;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    let root = Path::new(&workspace.root_path);
    let inputs = Path::new(&workspace.inputs_path);
    let artifacts = Path::new(&workspace.artifacts_path);
    let temp = Path::new(&workspace.temp_path);

    grant_restricted_sid(
        root,
        restricting_sid,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        true,
    )?;
    grant_restricted_sid(
        inputs,
        restricting_sid,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        true,
    )?;
    grant_restricted_sid(
        artifacts,
        restricting_sid,
        FILE_GENERIC_READ
            | FILE_GENERIC_WRITE
            | FILE_GENERIC_EXECUTE
            | FILE_DELETE_CHILD
            | DELETE,
        true,
    )?;
    grant_restricted_sid(
        temp,
        restricting_sid,
        FILE_GENERIC_READ
            | FILE_GENERIC_WRITE
            | FILE_GENERIC_EXECUTE
            | FILE_DELETE_CHILD
            | DELETE,
        true,
    )?;

    apply_low_integrity_label(root)?;
    apply_low_integrity_label(inputs)?;
    apply_low_integrity_label(artifacts)?;
    apply_low_integrity_label(temp)?;

    for file in &workspace.files {
        let staged = inputs.join(&file.relative_path);
        grant_restricted_sid(
            &staged,
            restricting_sid,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            false,
        )?;
        apply_low_integrity_label(&staged)?;
    }
    Ok(())
}

#[cfg(windows)]
fn grant_restricted_sid(
    path: &std::path::Path,
    restricting_sid: windows_sys::Win32::Security::PSID,
    access_mask: u32,
    inherit: bool,
) -> Result<(), RestrictedIdentityError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree},
        Security::{
            ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
            PSECURITY_DESCRIPTOR,
            Authorization::{
                EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT,
                TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W, SetEntriesInAclW,
                SetNamedSecurityInfoW,
            },
        },
    };

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
        return Err(RestrictedIdentityError::WorkspaceAcl {
            path: path.display().to_string(),
            message: format!("GetNamedSecurityInfoW returned {get_code}"),
        });
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
            ptstrName: restricting_sid as *mut u16,
        },
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    let acl_code = unsafe { SetEntriesInAclW(1, &explicit, old_dacl, &mut new_dacl) };
    if acl_code != ERROR_SUCCESS {
        return Err(RestrictedIdentityError::WorkspaceAcl {
            path: path.display().to_string(),
            message: format!("SetEntriesInAclW returned {acl_code}"),
        });
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
        return Err(RestrictedIdentityError::WorkspaceAcl {
            path: path.display().to_string(),
            message: format!("SetNamedSecurityInfoW returned {set_code}"),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn apply_low_integrity_label(
    path: &std::path::Path,
) -> Result<(), RestrictedIdentityError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::{
            ACL, GetSecurityDescriptorSacl, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                SE_FILE_OBJECT, SetNamedSecurityInfoW,
            },
        },
    };

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

    let sddl_text = if path.is_dir() {
        "S:(ML;OICI;NW;;;LW)"
    } else {
        "S:(ML;;NW;;;LW)"
    };
    let sddl = sddl_text
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut security_descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(RestrictedIdentityError::WorkspaceIntegrityLabel {
            path: path.display().to_string(),
            message: format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    let security_descriptor_memory = LocalMemory(security_descriptor as HLOCAL);

    let mut sacl_present = 0;
    let mut sacl_defaulted = 0;
    let mut sacl: *mut ACL = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorSacl(
            security_descriptor,
            &mut sacl_present,
            &mut sacl,
            &mut sacl_defaulted,
        )
    } == 0
        || sacl_present == 0
        || sacl.is_null()
    {
        return Err(RestrictedIdentityError::WorkspaceIntegrityLabel {
            path: path.display().to_string(),
            message: "converted low-integrity descriptor did not contain a mandatory-label SACL"
                .to_string(),
        });
    }

    let mut path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let set_code = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            sacl,
        )
    };
    drop(security_descriptor_memory);
    if set_code != 0 {
        return Err(RestrictedIdentityError::WorkspaceIntegrityLabel {
            path: path.display().to_string(),
            message: format!(
                "SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION) returned {set_code}"
            ),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn path_has_any_access(
    path: &std::path::Path,
    rights: &[u32],
    directory: bool,
) -> Result<bool, RestrictedIdentityError> {
    for right in rights {
        if path_has_access(path, *right, directory)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn path_has_access(
    path: &std::path::Path,
    desired_access: u32,
    directory: bool,
) -> Result<bool, RestrictedIdentityError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        },
    };

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        0
    };
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error().map(|value| value as u32) {
            Some(ERROR_ACCESS_DENIED) => Ok(false),
            _ => Err(RestrictedIdentityError::AccessProbe {
                path: path.display().to_string(),
                message: error.to_string(),
            }),
        };
    }
    unsafe {
        CloseHandle(handle);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        cleanup_detached_workspace, prepare_detached_workspace, snapshot_execution_inputs,
    };

    use super::probe_restricted_identity;
    #[cfg(not(windows))]
    use super::RestrictedIdentityError;

    fn temp_directory(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!("codetwin-identity-{label}-{nanos}"));
        fs::create_dir_all(&path).expect("temp directory");
        path
    }

    #[test]
    fn identity_probe_never_claims_filesystem_isolation_before_launcher_wiring() {
        let source = temp_directory("source");
        let parent = temp_directory("parent");
        fs::create_dir_all(source.join("tests")).expect("tests");
        fs::write(source.join("tests/test_api.py"), "def test_ok():\n    assert True\n")
            .expect("source");
        let targets = vec!["tests/test_api.py".to_string()];
        let snapshots = snapshot_execution_inputs(&source, &targets).expect("snapshots");
        let workspace =
            prepare_detached_workspace(&source, &parent, &snapshots).expect("workspace");

        #[cfg(windows)]
        {
            let evidence = probe_restricted_identity(&workspace).expect("identity probe");
            assert!(evidence.restricted_primary_token_created);
            assert!(evidence.privileges_disabled);
            assert!(evidence.write_restricted);
            assert!(evidence.low_integrity);
            assert!(evidence.source_root_write_denied);
            assert!(evidence.staged_inputs_write_denied);
            assert!(evidence.artifacts_write_allowed);
            assert!(evidence.temp_write_allowed);
            assert!(!evidence.executor_uses_restricted_token);
            assert!(!evidence.filesystem_isolation_promoted);
            assert!(!evidence.network_isolation_enforced);
        }
        #[cfg(not(windows))]
        {
            assert!(matches!(
                probe_restricted_identity(&workspace),
                Err(RestrictedIdentityError::UnsupportedPlatform)
            ));
        }

        cleanup_detached_workspace(&workspace).expect("cleanup");
        let _ = fs::remove_dir_all(source);
        let _ = fs::remove_dir_all(parent);
    }
}
