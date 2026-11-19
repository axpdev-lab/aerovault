// SPDX-License-Identifier: MPL-2.0
//! Bounded access-ACL capture for private replacement files.
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn name(path: &Path) -> Result<std::ffi::CString, String> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
pub(crate) fn capture(path: &Path) -> Result<Vec<u8>, String> {
    let path = name(path)?;
    let mut data = vec![0u8; 4097];
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            data.as_mut_ptr().cast(),
            4096,
        )
    };
    if n < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
            return Ok(vec![0]);
        }
        return Err(format!("Cannot capture bounded access ACL: {error}"));
    }
    data.truncate(n as usize);
    data.insert(0, 1);
    Ok(data)
}

#[cfg(target_os = "linux")]
pub(crate) fn apply(path: &Path, data: &[u8]) -> Result<(), String> {
    let path = name(path)?;
    let result = match data.split_first() {
        Some((0, [])) => unsafe {
            libc::removexattr(path.as_ptr(), c"system.posix_acl_access".as_ptr())
        },
        Some((1, tail)) if !tail.is_empty() && tail.len() <= 4096 => unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                tail.as_ptr().cast(),
                tail.len(),
                0,
            )
        },
        _ => return Err("Invalid bounded access ACL in recovery state".into()),
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if data == [0] && matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
            return Ok(());
        }
        return Err(format!("Cannot preserve access ACL: {error}"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::{c_char, c_int, c_void};
    pub(super) const EXTENDED: c_int = 0x100;
    unsafe extern "C" {
        pub(super) fn acl_get_file(path: *const c_char, kind: c_int) -> *mut c_void;
        pub(super) fn acl_to_text(acl: *mut c_void, len: *mut isize) -> *mut c_char;
        pub(super) fn acl_from_text(text: *const c_char) -> *mut c_void;
        pub(super) fn acl_set_file(path: *const c_char, kind: c_int, acl: *mut c_void) -> c_int;
        fn acl_free(data: *mut c_void) -> c_int;
    }
    pub(super) struct Owned(pub(super) *mut c_void);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe {
                acl_free(self.0);
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn capture(path: &Path) -> Result<Vec<u8>, String> {
    let path = name(path)?;
    let acl = unsafe { darwin::acl_get_file(path.as_ptr(), darwin::EXTENDED) };
    if acl.is_null() {
        return Err(format!(
            "Cannot capture access ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let acl = darwin::Owned(acl);
    let mut len = 0;
    let text = unsafe { darwin::acl_to_text(acl.0, &mut len) };
    if text.is_null() {
        return Err(format!(
            "Cannot encode access ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let _text = darwin::Owned(text.cast());
    if !(0..=4096).contains(&len) {
        return Err("Access ACL exceeds recovery bound".into());
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(text) }.to_bytes();
    if bytes.len() > 4096 {
        return Err("Access ACL exceeds recovery bound".into());
    }
    Ok(bytes.to_vec())
}

#[cfg(target_os = "macos")]
pub(crate) fn apply(path: &Path, data: &[u8]) -> Result<(), String> {
    if data.len() > 4096 {
        return Err("Access ACL exceeds recovery bound".into());
    }
    let path = name(path)?;
    let text = std::ffi::CString::new(data).map_err(|e| e.to_string())?;
    let acl = unsafe { darwin::acl_from_text(text.as_ptr()) };
    if acl.is_null() {
        return Err("Invalid access ACL in recovery state".into());
    }
    let acl = darwin::Owned(acl);
    if unsafe { darwin::acl_set_file(path.as_ptr(), darwin::EXTENDED, acl.0) } != 0 {
        return Err(format!(
            "Cannot preserve access ACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn capture(_: &Path) -> Result<Vec<u8>, String> {
    Err("Access ACL preservation is unavailable on this platform".into())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn apply(_: &Path, _: &[u8]) -> Result<(), String> {
    Err("Access ACL preservation is unavailable on this platform".into())
}
