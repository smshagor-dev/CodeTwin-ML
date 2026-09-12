use std::{
    ffi::{c_void, OsStr},
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::Path,
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        CreateWellKnownSid, EqualSid, FreeSid, GetTokenInformation, IsTokenRestricted, PSID,
        SECURITY_CAPABILITIES, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        TokenAppContainerSid, TokenCapabilities, TokenIntegrityLevel, TokenIsAppContainer,
        TokenIsLessPrivilegedAppContainer, TokenRestrictedSids, WinLowLabelSid,
        WinWriteRestrictedCodeSid,
    },
    Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    },
    System::{
        Threading::{
            CreateProcessAsUserW, DeleteProcThreadAttributeList,
            InitializeProcThreadAttributeList, OpenProcessToken, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
            EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
        },
        WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
    },
};

use crate::workspace::identity::create_windows_write_restricted_token;
use crate::{BackendExecutionError, TestExecutionPlan};

const LPAC_PROFILE_NAME: &str = "CodeTwinML.QA.RestrictedRunner.V1";
const LPAC_PROFILE_DISPLAY_NAME: &str = "CodeTwin ML QA Restricted Runner";
const LPAC_PROFILE_DESCRIPTION: &str =
    "Zero-capability Less Privileged AppContainer used to attest QA sandbox composition.";
const PROBE_TERMINATION_WAIT_MS: u32 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LpacLaunchReadinessEvidence {
    pub child_is_appcontainer: bool,
    pub child_is_lpac: bool,
    pub child_is_restricted: bool,
    pub write_restricted_sid_present: bool,
    pub child_low_integrity: bool,
    pub package_sid_matches: bool,
    pub capability_count: u32,
    pub child_never_resumed: bool,
    pub production_launcher_uses_lpac: bool,
    pub filesystem_read_allowlist_enforced: bool,
    pub network_isolation_promoted: bool,
}

impl LpacLaunchReadinessEvidence {
    pub(crate) const fn satisfies_readiness_contract(&self) -> bool {
        self.child_is_appcontainer
            && self.child_is_lpac
            && self.child_is_restricted
            && self.write_restricted_sid_present
            && self.child_low_integrity
            && self.package_sid_matches
            && self.capability_count == 0
            && self.child_never_resumed
            && !self.production_launcher_uses_lpac
            && !self.filesystem_read_allowlist_enforced
            && !self.network_isolation_promoted
    }
}

pub(crate) fn probe_suspended_lpac_readiness(
    plan: &TestExecutionPlan,
    current_directory: &Path,
) -> Result<LpacLaunchReadinessEvidence, BackendExecutionError> {
    if plan.command.program != plan.toolchain.executable_path {
        return Err(BackendExecutionError::InvalidToolchain(
            "LPAC readiness command differs from the approved toolchain path".to_string(),
        ));
    }
    if !current_directory.is_dir() {
        return Err(BackendExecutionError::JobSetup(
            "LPAC readiness current directory is not a directory".to_string(),
        ));
    }

    let profile = LpacProfileSid::open_or_create()?;
    let token = create_windows_write_restricted_token().map_err(|error| {
        BackendExecutionError::JobSetup(format!("LPAC readiness restricted token: {error}"))
    })?;

    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid(),
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let all_application_packages_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let attributes =
        ProcThreadAttributeList::lpac(&capabilities, &all_application_packages_policy)?;

    let application = wide_null(OsStr::new(plan.command.program.as_str()));
    let quoted_program = format!("\"{}\"", plan.command.program);
    let mut command_line = wide_null(OsStr::new(quoted_program.as_str()));
    let current_directory = wide_null(current_directory.as_os_str());

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.ptr;

    let mut process_info = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;
    let created = unsafe {
        CreateProcessAsUserW(
            token.raw(),
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            std::ptr::null(),
            current_directory.as_ptr(),
            &startup.StartupInfo as *const STARTUPINFOW,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(BackendExecutionError::JobSetup(format!(
            "CreateProcessAsUserW(LPAC readiness): {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut child = SuspendedProbeChild::new(process_info.hProcess, process_info.hThread)?;
    let evidence = attest_child_token(child.process.raw(), profile.sid())?;
    if !evidence.satisfies_readiness_contract() {
        return Err(BackendExecutionError::JobSetup(
            "suspended LPAC child token did not satisfy the conservative readiness contract"
                .to_string(),
        ));
    }
    child.terminate()?;
    Ok(evidence)
}

struct LpacProfileSid(PSID);

impl LpacProfileSid {
    fn open_or_create() -> Result<Self, BackendExecutionError> {
        let name = wide_null(OsStr::new(LPAC_PROFILE_NAME));
        let display = wide_null(OsStr::new(LPAC_PROFILE_DISPLAY_NAME));
        let description = wide_null(OsStr::new(LPAC_PROFILE_DESCRIPTION));
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
                    "CreateAppContainerProfile returned success without a SID".to_string(),
                ));
            }
            return Ok(Self(sid));
        }

        if result != hresult_from_win32(ERROR_ALREADY_EXISTS) {
            return Err(BackendExecutionError::JobSetup(format!(
                "CreateAppContainerProfile failed with HRESULT 0x{:08x}",
                result as u32
            )));
        }

        let derived =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if derived < 0 || sid.is_null() {
            return Err(BackendExecutionError::JobSetup(format!(
                "DeriveAppContainerSidFromAppContainerName failed with HRESULT 0x{:08x}",
                derived as u32
            )));
        }
        Ok(Self(sid))
    }

    const fn sid(&self) -> PSID {
        self.0
    }
}

impl Drop for LpacProfileSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeSid(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    const fn from_valid(handle: HANDLE) -> Self {
        Self(handle)
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct SuspendedProbeChild {
    process: OwnedHandle,
    _thread: OwnedHandle,
    terminated: bool,
}

impl SuspendedProbeChild {
    fn new(process: HANDLE, thread: HANDLE) -> Result<Self, BackendExecutionError> {
        if process.is_null() || thread.is_null() {
            if !process.is_null() {
                unsafe {
                    TerminateProcess(process, 1);
                    WaitForSingleObject(process, PROBE_TERMINATION_WAIT_MS);
                    CloseHandle(process);
                }
            }
            if !thread.is_null() {
                unsafe {
                    CloseHandle(thread);
                }
            }
            return Err(BackendExecutionError::JobSetup(
                "CreateProcessAsUserW(LPAC readiness) returned an incomplete process/thread handle pair"
                    .to_string(),
            ));
        }
        Ok(Self {
            process: OwnedHandle::from_valid(process),
            _thread: OwnedHandle::from_valid(thread),
            terminated: false,
        })
    }

    fn terminate(&mut self) -> Result<(), BackendExecutionError> {
        if self.terminated {
            return Ok(());
        }
        if unsafe { TerminateProcess(self.process.raw(), 1) } == 0 {
            return Err(BackendExecutionError::JobSetup(format!(
                "TerminateProcess(LPAC readiness): {}",
                std::io::Error::last_os_error()
            )));
        }
        match unsafe { WaitForSingleObject(self.process.raw(), PROBE_TERMINATION_WAIT_MS) } {
            WAIT_OBJECT_0 => {
                self.terminated = true;
                Ok(())
            }
            WAIT_TIMEOUT => Err(BackendExecutionError::JobSetup(
                "suspended LPAC readiness child did not terminate within the bounded wait"
                    .to_string(),
            )),
            WAIT_FAILED => Err(BackendExecutionError::JobSetup(format!(
                "WaitForSingleObject(LPAC readiness): {}",
                std::io::Error::last_os_error()
            ))),
            other => Err(BackendExecutionError::JobSetup(format!(
                "unexpected LPAC readiness wait result {other}"
            ))),
        }
    }
}

impl Drop for SuspendedProbeChild {
    fn drop(&mut self) {
        if !self.terminated {
            unsafe {
                TerminateProcess(self.process.raw(), 1);
                WaitForSingleObject(self.process.raw(), PROBE_TERMINATION_WAIT_MS);
            }
        }
    }
}

fn attest_child_token(
    process: HANDLE,
    expected_appcontainer_sid: PSID,
) -> Result<LpacLaunchReadinessEvidence, BackendExecutionError> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(BackendExecutionError::JobSetup(format!(
            "OpenProcessToken(LPAC readiness): {}",
            std::io::Error::last_os_error()
        )));
    }
    if token.is_null() {
        return Err(BackendExecutionError::JobSetup(
            "OpenProcessToken(LPAC readiness) returned a null token handle".to_string(),
        ));
    }
    let token = OwnedHandle::from_valid(token);

    let child_is_appcontainer = token_bool(token.raw(), TokenIsAppContainer)?;
    let child_is_lpac = token_bool(token.raw(), TokenIsLessPrivilegedAppContainer)?;
    let child_is_restricted = unsafe { IsTokenRestricted(token.raw()) } != 0;
    let write_restricted_sid_present = token_has_restricted_sid(token.raw())?;
    let child_low_integrity = token_has_low_integrity(token.raw())?;
    let package_sid_matches =
        token_appcontainer_sid_matches(token.raw(), expected_appcontainer_sid)?;
    let capability_count = token_capability_count(token.raw())?;

    Ok(LpacLaunchReadinessEvidence {
        child_is_appcontainer,
        child_is_lpac,
        child_is_restricted,
        write_restricted_sid_present,
        child_low_integrity,
        package_sid_matches,
        capability_count,
        child_never_resumed: true,
        production_launcher_uses_lpac: false,
        filesystem_read_allowlist_enforced: false,
        network_isolation_promoted: false,
    })
}

fn token_bool(
    token: HANDLE,
    information_class: i32,
) -> Result<bool, BackendExecutionError> {
    let mut value = 0u32;
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            (&mut value as *mut u32).cast::<c_void>(),
            size_of::<u32>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "GetTokenInformation({information_class}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(value != 0)
}

fn token_appcontainer_sid_matches(
    token: HANDLE,
    expected: PSID,
) -> Result<bool, BackendExecutionError> {
    let storage = token_information_buffer(token, TokenAppContainerSid)?;
    let info = unsafe { &*(storage.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()) };
    if info.TokenAppContainer.is_null() {
        return Ok(false);
    }
    Ok(unsafe { EqualSid(info.TokenAppContainer, expected) } != 0)
}

fn token_capability_count(token: HANDLE) -> Result<u32, BackendExecutionError> {
    let storage = token_information_buffer(token, TokenCapabilities)?;
    let groups = unsafe { &*(storage.as_ptr().cast::<TOKEN_GROUPS>()) };
    Ok(groups.GroupCount)
}

fn token_has_restricted_sid(token: HANDLE) -> Result<bool, BackendExecutionError> {
    let mut expected = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut expected_len = expected.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            WinWriteRestrictedCodeSid,
            std::ptr::null_mut(),
            expected.as_mut_ptr().cast::<c_void>(),
            &mut expected_len,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "CreateWellKnownSid(WinWriteRestrictedCodeSid): {}",
            std::io::Error::last_os_error()
        )));
    }

    let storage = token_information_buffer(token, TokenRestrictedSids)?;
    let groups = unsafe { &*(storage.as_ptr().cast::<TOKEN_GROUPS>()) };
    let count = groups.GroupCount as usize;
    let entries_offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let entries_bytes = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .ok_or_else(|| {
            BackendExecutionError::JobSetup(
                "TokenRestrictedSids entry-byte count overflowed".to_string(),
            )
        })?;
    let required_bytes = entries_offset.checked_add(entries_bytes).ok_or_else(|| {
        BackendExecutionError::JobSetup(
            "TokenRestrictedSids buffer-size calculation overflowed".to_string(),
        )
    })?;
    let available_bytes = storage.len().saturating_mul(size_of::<usize>());
    if required_bytes > available_bytes {
        return Err(BackendExecutionError::JobSetup(format!(
            "TokenRestrictedSids reported {count} entries outside its returned buffer"
        )));
    }

    let entries = unsafe {
        storage
            .as_ptr()
            .cast::<u8>()
            .add(entries_offset)
            .cast::<SID_AND_ATTRIBUTES>()
    };
    for index in 0..count {
        let entry = unsafe { &*entries.add(index) };
        if !entry.Sid.is_null()
            && unsafe { EqualSid(entry.Sid, expected.as_mut_ptr().cast::<c_void>()) } != 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn token_has_low_integrity(token: HANDLE) -> Result<bool, BackendExecutionError> {
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
        return Err(BackendExecutionError::JobSetup(format!(
            "CreateWellKnownSid(WinLowLabelSid): {}",
            std::io::Error::last_os_error()
        )));
    }

    let storage = token_information_buffer(token, TokenIntegrityLevel)?;
    let label = unsafe { &*(storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    Ok(unsafe { EqualSid(label.Label.Sid, low_sid.as_mut_ptr().cast::<c_void>()) } != 0)
}

fn token_information_buffer(
    token: HANDLE,
    information_class: i32,
) -> Result<Vec<usize>, BackendExecutionError> {
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            information_class,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(BackendExecutionError::JobSetup(format!(
            "GetTokenInformation({information_class}) reported a zero-sized result: {}",
            std::io::Error::last_os_error()
        )));
    }
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0usize; words.max(1)];
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            storage.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(BackendExecutionError::JobSetup(format!(
            "GetTokenInformation({information_class}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(storage)
}

struct ProcThreadAttributeList {
    _storage: Vec<usize>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl ProcThreadAttributeList {
    fn lpac(
        capabilities: &SECURITY_CAPABILITIES,
        all_application_packages_policy: &u32,
    ) -> Result<Self, BackendExecutionError> {
        const ATTRIBUTE_COUNT: u32 = 2;
        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(
                std::ptr::null_mut(),
                ATTRIBUTE_COUNT,
                0,
                &mut bytes,
            );
        }
        if bytes == 0 {
            return Err(BackendExecutionError::JobSetup(format!(
                "InitializeProcThreadAttributeList(LPAC size): {}",
                std::io::Error::last_os_error()
            )));
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words.max(1)];
        let ptr = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeProcThreadAttributeList(ptr, ATTRIBUTE_COUNT, 0, &mut bytes) } == 0 {
            return Err(BackendExecutionError::JobSetup(format!(
                "InitializeProcThreadAttributeList(LPAC): {}",
                std::io::Error::last_os_error()
            )));
        }

        let list = Self {
            _storage: storage,
            ptr,
        };
        if unsafe {
            UpdateProcThreadAttribute(
                list.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (capabilities as *const SECURITY_CAPABILITIES).cast::<c_void>(),
                size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(BackendExecutionError::JobSetup(format!(
                "UpdateProcThreadAttribute(SECURITY_CAPABILITIES): {}",
                std::io::Error::last_os_error()
            )));
        }
        if unsafe {
            UpdateProcThreadAttribute(
                list.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                (all_application_packages_policy as *const u32).cast::<c_void>(),
                size_of::<u32>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(BackendExecutionError::JobSetup(format!(
                "UpdateProcThreadAttribute(ALL_APPLICATION_PACKAGES_POLICY): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(list)
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                DeleteProcThreadAttributeList(self.ptr);
            }
        }
    }
}

const fn hresult_from_win32(code: u32) -> i32 {
    if code == 0 {
        0
    } else {
        (0x8007_0000u32 | (code & 0xffff)) as i32
    }
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::hresult_from_win32;
    use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;

    #[test]
    fn maps_already_exists_to_win32_hresult() {
        assert_eq!(hresult_from_win32(ERROR_ALREADY_EXISTS) as u32, 0x8007_00b7);
    }
}
