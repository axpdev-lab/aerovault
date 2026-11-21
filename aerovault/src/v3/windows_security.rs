// SPDX-License-Identifier: MPL-2.0
//! Bounded DACL capture for recoverable two-file publication on Windows.
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

const DACL: u32 = 4;
const OWNER: u32 = 1;
const PROTECTED_DACL: u32 = 0x8000_0000;
const UNPROTECTED_DACL: u32 = 0x2000_0000;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetFileSecurityW(
        path: *const u16,
        info: u32,
        descriptor: *mut c_void,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        value: *mut c_void,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn EqualSid(left: *const c_void, right: *const c_void) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *const c_void,
        present: *mut i32,
        acl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorControl(
        descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetAclInformation(
        acl: *const c_void,
        information: *mut AclSize,
        size: u32,
        class: u32,
    ) -> i32;
    fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn GetSecurityDescriptorOwner(
        descriptor: *const c_void,
        owner: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        path: *mut u16,
        object_type: u32,
        info: u32,
        owner: *const c_void,
        group: *const c_void,
        dacl: *const c_void,
        sacl: *const c_void,
    ) -> u32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor: *const c_void,
        revision: u32,
        info: u32,
        text: *mut *mut u16,
        len: *mut u32,
    ) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        class: u32,
        information: *mut c_void,
        size: u32,
    ) -> i32;
}

#[repr(C)]
#[derive(Default)]
struct FileCompressionInfo {
    compressed_file_size: i64,
    compression_format: u16,
    compression_unit_shift: u8,
    chunk_shift: u8,
    cluster_shift: u8,
    reserved: [u8; 3],
}

pub(super) fn allocated_file_bytes(file: &std::fs::File) -> std::io::Result<u64> {
    use std::os::windows::io::AsRawHandle;

    const FILE_COMPRESSION_INFO_CLASS: u32 = 8;
    let mut info = FileCompressionInfo::default();
    // SAFETY: the live handle and initialized output buffer have the Win32 ABI layout.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_COMPRESSION_INFO_CLASS,
            (&mut info as *mut FileCompressionInfo).cast(),
            std::mem::size_of::<FileCompressionInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    u64::try_from(info.compressed_file_size).map_err(|_| std::io::ErrorKind::InvalidData.into())
}

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
struct AclSize {
    count: u32,
    in_use: u32,
    free: u32,
}

/// Compare all ACE bytes and DACL protection, independently of SDDL formatting
/// and Windows' informational auto-inheritance control flags.
fn protected_aces(sddl: &str) -> Result<Vec<Vec<u8>>, String> {
    access_aces(sddl, true)
}

fn access_aces(sddl: &str, protected: bool) -> Result<Vec<Vec<u8>>, String> {
    if sddl.len() > 65536 || sddl.contains('\0') {
        return Err("Invalid bounded DACL text".into());
    }
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let descriptor = Local(descriptor);
    let mut control = 0u16;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
        || (protected && control & 0x1000 == 0)
    {
        return Err("Private directory DACL is not protected".into());
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
    {
        return Err("Private directory has no restrictive DACL".into());
    }
    let mut size = AclSize {
        count: 0,
        in_use: 0,
        free: 0,
    };
    if unsafe { GetAclInformation(acl, &mut size, std::mem::size_of::<AclSize>() as u32, 2) } == 0
        || size.count > 4096
        || size.in_use > 65536
    {
        return Err("Private directory ACL exceeds bounds".into());
    }
    let mut aces = Vec::with_capacity(size.count as usize);
    for index in 0..size.count {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            return Err("Cannot inspect private directory ACE".into());
        }
        // Windows validated this ACE; its first four bytes are ACE_HEADER.
        let header = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), 4) };
        let len = u16::from_le_bytes([header[2], header[3]]) as usize;
        if len < 4 || len > size.in_use as usize {
            return Err("Invalid private directory ACE size".into());
        }
        aces.push(unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), len) }.to_vec());
    }
    Ok(aces)
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn capture(path: &Path) -> Result<String, String> {
    let path = wide(path);
    capture_security(|descriptor, size, needed| unsafe {
        GetFileSecurityW(path.as_ptr(), OWNER | DACL, descriptor, size, needed)
    })
}

fn capture_security(read: impl Fn(*mut c_void, u32, *mut u32) -> i32) -> Result<String, String> {
    let mut needed = 0;
    read(std::ptr::null_mut(), 0, &mut needed);
    if needed == 0 || needed > 65536 {
        return Err(format!(
            "Cannot capture bounded file DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    // DWORD-aligned storage for the self-relative descriptor returned by Windows.
    let mut descriptor = vec![0u32; (needed as usize).div_ceil(4)];
    if read(descriptor.as_mut_ptr().cast(), needed, &mut needed) == 0 {
        return Err(format!(
            "Read file DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    encode_security(descriptor.as_ptr().cast())
}

fn encode_security(descriptor: *const c_void) -> Result<String, String> {
    let mut text = std::ptr::null_mut();
    let mut len = 0;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            OWNER | DACL,
            &mut text,
            &mut len,
        )
    } == 0
    {
        return Err(format!(
            "Encode file DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let owned = Local(text.cast());
    if len == 0 || len > 65536 {
        return Err("File DACL text exceeds limit".to_string());
    }
    // Windows returns the buffer capacity in WCHARs, not the string length.
    // Only the prefix through the first NUL is initialized string content.
    unsafe { decode_sddl_buffer(owned.0.cast::<u16>(), len as usize) }
}

fn verify_current_owner(sddl: &str) -> Result<(), String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    const QUERY: u32 = 8;
    const TOKEN_OWNER: u32 = 4;
    let mut raw_token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), QUERY, &mut raw_token) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut needed = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TOKEN_OWNER,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed < std::mem::size_of::<*mut c_void>() as u32 || needed > 65536 {
        return Err("Cannot determine the current Windows token owner".into());
    }
    let mut owner = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TOKEN_OWNER,
            owner.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let expected = unsafe { owner.as_ptr().cast::<*mut c_void>().read() };
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let descriptor = Local(descriptor);
    let mut actual = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut actual, &mut defaulted) } == 0
        || actual.is_null()
        || expected.is_null()
        || unsafe { EqualSid(actual, expected) } == 0
    {
        return Err("strip journal object belongs to a different Windows owner".into());
    }
    Ok(())
}

const PRIVATE_DIRECTORY_DACL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)";

pub(super) fn verify_private_journal_directory(path: &Path) -> Result<(), String> {
    let actual = capture(path)?;
    verify_current_owner(&actual)?;
    if protected_aces(&actual)? != protected_aces(PRIVATE_DIRECTORY_DACL)? {
        return Err("strip journal directory has an unexpected DACL".into());
    }
    Ok(())
}

pub(super) fn verify_journal_input(file: &std::fs::File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            1,
            OWNER | DACL,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(format!(
            "Read strip journal input security: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    let descriptor = Local(descriptor);
    let actual = encode_security(descriptor.0)?;
    verify_current_owner(&actual)?;
    let mut aces = access_aces(&actual, false)?;
    for ace in &mut aces {
        ace[1] &= !0x10; // INHERITED_ACE
    }
    if aces != access_aces("D:(A;;FA;;;OW)(A;;FA;;;SY)", false)? {
        return Err("strip journal input has an unexpected DACL".into());
    }
    Ok(())
}

/// Read a Windows-allocated, NUL-terminated SDDL string within its buffer bound.
/// The caller guarantees readable initialized units through the first NUL.
unsafe fn decode_sddl_buffer(text: *const u16, capacity: usize) -> Result<String, String> {
    if text.is_null() || capacity == 0 || capacity > 65536 {
        return Err("Invalid bounded file DACL buffer".into());
    }
    let mut units = Vec::new();
    for index in 0..capacity {
        let unit = unsafe { text.add(index).read() };
        if unit == 0 {
            return String::from_utf16(&units).map_err(|e| e.to_string());
        }
        units.push(unit);
    }
    Err("Unterminated file DACL buffer".into())
}

/// Seal inheritance while a file is staged under a different parent. After
/// publication restore the original inheritance setting at its original parent.
pub(crate) fn apply(path: &Path, sddl: &str, staging: bool) -> Result<(), String> {
    if sddl.len() > 65536 || sddl.contains('\0') {
        return Err("Invalid bounded file DACL text".to_string());
    }
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(format!(
            "Decode file DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let owned = Local(descriptor);
    let flags = sddl
        .split("D:")
        .nth(1)
        .unwrap_or("")
        .split('(')
        .next()
        .unwrap_or("");
    let protection = if staging || flags.contains('P') {
        PROTECTED_DACL
    } else {
        UNPROTECTED_DACL
    };
    // Owner Rights ACEs depend on the owner SID as well as DACL bytes. Restore
    // that context too; inability to set the original owner refuses publication.
    let owner = if sddl.starts_with("O:") { OWNER } else { 0 };
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let mut owner_sid = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(owned.0, &mut present, &mut dacl, &mut defaulted) } == 0
        || present == 0
        || (owner != 0
            && unsafe { GetSecurityDescriptorOwner(owned.0, &mut owner_sid, &mut defaulted) } == 0)
    {
        return Err("Cannot decode original Windows security descriptor".to_string());
    }
    let error = unsafe {
        SetNamedSecurityInfoW(
            wide(path).as_mut_ptr(),
            1,
            owner | DACL | protection,
            owner_sid,
            std::ptr::null(),
            dacl,
            std::ptr::null(),
        )
    };
    if error != 0 {
        return Err(format!(
            "Apply file DACL: {}",
            std::io::Error::from_raw_os_error(error as i32)
        ));
    }
    Ok(())
}

/// Create with the restrictive DACL atomically, before another principal can
/// open the directory under an inherited permissive ACL.
pub(super) fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let text: Vec<u16> = PRIVATE_DIRECTORY_DACL
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let owned = Local(descriptor);
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: owned.0,
        inherit_handle: 0,
    };
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Refuse filesystems that do not preserve the requested security. The
    // directory is still empty; no vault or rollback bytes have been written.
    let verified = capture(path).and_then(|actual| {
        let actual = protected_aces(&actual)?;
        let expected = protected_aces(PRIVATE_DIRECTORY_DACL)?;
        if actual == expected {
            Ok(())
        } else {
            Err("Private directory ACEs differ from requested access".into())
        }
    });
    if let Err(error) = verified {
        let _ = std::fs::remove_dir(path);
        return Err(std::io::Error::other(format!(
            "Filesystem did not preserve private directory DACL: {error}"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn guest_effective_rights(path: &Path) -> Result<u32, String> {
    #[repr(C)]
    struct Trustee {
        multiple: *mut c_void,
        operation: u32,
        form: u32,
        kind: u32,
        name: *mut u16,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSidToSidW(text: *const u16, sid: *mut *mut c_void) -> i32;
        fn GetEffectiveRightsFromAclW(
            acl: *const c_void,
            trustee: *const Trustee,
            rights: *mut u32,
        ) -> u32;
    }
    let text: Vec<u16> = capture(path)?.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let descriptor = Local(descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
    {
        return Err("Test requires a real DACL".to_string());
    }
    let guest: Vec<u16> = "S-1-5-32-546".encode_utf16().chain(Some(0)).collect();
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(guest.as_ptr(), &mut sid) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let sid = Local(sid);
    let trustee = Trustee {
        multiple: std::ptr::null_mut(),
        operation: 0,
        form: 0,
        kind: 5,
        name: sid.0.cast(),
    };
    let mut rights = 0;
    let error = unsafe { GetEffectiveRightsFromAclW(acl, &trustee, &mut rights) };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32).to_string());
    }
    Ok(rights)
}

#[cfg(test)]
mod tests {
    use super::{capture, decode_sddl_buffer, protected_aces};

    #[test]
    fn allocated_file_bytes_reports_only_the_backed_part_of_a_sparse_file() {
        use std::ffi::c_void;
        use std::io::Write;
        use std::os::windows::io::AsRawHandle;
        use std::ptr::null_mut;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                file: *mut c_void,
                code: u32,
                input: *mut c_void,
                input_len: u32,
                output: *mut c_void,
                output_len: u32,
                returned: *mut u32,
                overlapped: *mut c_void,
            ) -> i32;
        }

        const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;
        let mut file = tempfile::tempfile().unwrap();
        let mut returned = 0;
        // SAFETY: the file is live and writable. This synchronous request
        // marks the test file sparse and takes no input or output buffer.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_SPARSE,
                null_mut(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        file.set_len(128 * 1024 * 1024).unwrap();
        file.write_all(b"backed byte range").unwrap();
        file.sync_all().unwrap();
        let backed = super::allocated_file_bytes(&file).unwrap();
        assert!(
            backed > 0 && backed < 1024 * 1024,
            "{backed} allocated bytes"
        );
    }

    #[test]
    fn captured_sddl_ends_at_first_nul_within_api_capacity() {
        let sddl = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)";
        let mut buffer: Vec<u16> = sddl.encode_utf16().collect();
        buffer.extend([0, 0, 0xd800]);
        assert_eq!(
            unsafe { decode_sddl_buffer(buffer.as_ptr(), buffer.len()) }.unwrap(),
            sddl
        );
        let unterminated: Vec<u16> = sddl.encode_utf16().collect();
        assert!(unsafe { decode_sddl_buffer(unterminated.as_ptr(), unterminated.len()) }.is_err());
        let captured = capture(&std::env::temp_dir()).unwrap();
        assert!(!captured.contains('\0'));
        assert!(captured.starts_with("O:"));
    }

    #[test]
    fn private_dacl_comparison_ignores_formatting_but_rejects_access_changes() {
        let expected = protected_aces("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)").unwrap();
        assert_eq!(
            expected,
            protected_aces("D:PAI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)").unwrap()
        );
        assert_ne!(
            expected,
            protected_aces("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FR;;;BG)").unwrap()
        );
        assert_ne!(
            expected,
            protected_aces("D:P(A;OICI;FR;;;OW)(A;OICI;FA;;;SY)").unwrap()
        );
        assert!(protected_aces("D:AI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)").is_err());
    }
}

/// Replace repaired content while Windows carries destination ACL/inheritance
/// in the same operation. No fallible ACL-finalization step follows commit.
pub(crate) fn persist_repair(
    tmp: tempfile::NamedTempFile,
    target: &Path,
    private: &mut super::strip_transaction::PrivateDir,
) -> Result<(), String> {
    #[cfg(test)]
    if FAIL_REPAIR_REPLACE.with(|f| f.replace(false)) {
        return Err("Injected repair ACL merge failure before replacement".into());
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            target: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *mut c_void,
            reserved: *mut c_void,
        ) -> i32;
    }
    // Place the sealed, protected replacement in the actual destination
    // directory so Windows merges inheritance in the final parent context.
    let parent = super::vault::output_parent_dir(target);
    let sibling = tempfile::Builder::new()
        .prefix(".aerorepair-publish-")
        .tempfile_in(parent)
        .map_err(|e| e.to_string())?
        .into_temp_path();
    let file = tmp.persist(&sibling).map_err(|e| e.to_string())?;
    drop(file);
    let replacement = sibling.keep().map_err(|e| e.to_string())?;
    let backup = private.path().join("original");
    let target_wide = wide(target);
    let replacement_wide = wide(&replacement);
    let backup_wide = wide(&backup);
    #[cfg(test)]
    if FAIL_REPAIR_WITH_ORIGINAL_INTACT.with(|f| f.replace(false)) {
        return Err(recover_repair_failure(
            target,
            &replacement,
            &backup,
            private,
            &std::io::Error::from_raw_os_error(1176),
        ));
    }
    #[cfg(test)]
    if FAIL_REPAIR_AFTER_BACKUP.with(|f| f.replace(false)) {
        std::fs::rename(target, &backup)
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&replacement);
            })
            .map_err(|e| e.to_string())?;
        return Err(recover_repair_failure(
            target,
            &replacement,
            &backup,
            private,
            &std::io::Error::from_raw_os_error(1177),
        ));
    }
    let result = unsafe {
        ReplaceFileW(
            target_wide.as_ptr(),
            replacement_wide.as_ptr(),
            backup_wide.as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return Err(recover_repair_failure(
            target,
            &replacement,
            &backup,
            private,
            &error,
        ));
    }
    Ok(())
}

fn recover_repair_failure(
    target: &Path,
    replacement: &Path,
    backup: &Path,
    private: &mut super::strip_transaction::PrivateDir,
    error: &std::io::Error,
) -> String {
    // A partial failure can move the old file aside. Restore it without
    // clobbering a newer path. If restoration is impossible, keep both copies.
    match (target.try_exists(), backup.try_exists()) {
        (Ok(false), Ok(true)) if std::fs::hard_link(backup, target).is_ok() => {}
        (Ok(true), Ok(false)) if error.raw_os_error() != Some(1177) => {}
        _ => {
            let recovery_dir = private.keep();
            let retained = recovery_dir.join("replacement");
            let retained = if std::fs::rename(replacement, &retained).is_ok() {
                &retained
            } else {
                replacement
            };
            return format!(
                "Repair replacement failed: {error}. Preserve the recovery directory {} and replacement {}",
                recovery_dir.display(),
                retained.display()
            );
        }
    }
    let _ = std::fs::remove_file(replacement);
    format!("Repair replacement including destination ACL merge failed: {error}")
}

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_REPAIR_REPLACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static FAIL_REPAIR_AFTER_BACKUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(crate) static FAIL_REPAIR_WITH_ORIGINAL_INTACT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
