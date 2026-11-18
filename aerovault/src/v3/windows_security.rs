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

pub(super) fn capture(path: &Path) -> Result<String, String> {
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
    let units = unsafe { std::slice::from_raw_parts(owned.0.cast::<u16>(), len as usize) };
    let units = units.strip_suffix(&[0]).unwrap_or(units);
    String::from_utf16(units).map_err(|e| e.to_string())
}

/// Seal inheritance while a file is staged under a different parent. After
/// publication restore the original inheritance setting at its original parent.
pub(super) fn apply(path: &Path, sddl: &str, staging: bool) -> Result<(), String> {
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
    match capture(path) {
        Ok(actual) if actual.split("D:").nth(1) == Some("P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)") => {
            Ok(())
        }
        _ => {
            let _ = std::fs::remove_dir(path);
            Err(std::io::Error::other(
                "Filesystem did not preserve private directory DACL",
            ))
        }
    }
}

#[cfg(test)]
pub(super) fn guest_effective_rights(path: &Path) -> Result<u32, String> {
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
