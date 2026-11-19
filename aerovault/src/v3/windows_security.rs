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
        || control & 0x1000 == 0
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
    let mut needed = 0;
    unsafe {
        GetFileSecurityW(
            path.as_ptr(),
            OWNER | DACL,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 || needed > 65536 {
        return Err(format!(
            "Cannot capture bounded file DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    // DWORD-aligned storage for the self-relative descriptor returned by Windows.
    let mut descriptor = vec![0u32; (needed as usize).div_ceil(4)];
    if unsafe {
        GetFileSecurityW(
            path.as_ptr(),
            OWNER | DACL,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(format!(
            "Read file DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut text = std::ptr::null_mut();
    let mut len = 0;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.as_ptr().cast(),
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
    let text: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
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
        let expected = protected_aces("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)")?;
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
pub(crate) fn persist_repair(tmp: tempfile::NamedTempFile, target: &Path) -> Result<(), String> {
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
    let target = wide(target);
    let (file, replacement) = tmp.keep().map_err(|e| e.to_string())?;
    drop(file);
    let replacement_wide = wide(&replacement);
    let result = unsafe {
        ReplaceFileW(
            target.as_ptr(),
            replacement_wide.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        let _ = std::fs::remove_file(replacement);
        return Err(format!(
            "Repair replacement including destination ACL merge failed: {error}"
        ));
    }
    Ok(())
}
#[cfg(test)]
thread_local! { pub(crate) static FAIL_REPAIR_REPLACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
