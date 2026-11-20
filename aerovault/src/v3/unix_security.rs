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
    capture_linux(|data, len| unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            data,
            len,
        )
    })
}

#[cfg(target_os = "linux")]
fn capture_linux(read: impl FnOnce(*mut libc::c_void, usize) -> isize) -> Result<Vec<u8>, String> {
    let mut data = vec![0u8; 4097];
    let n = read(data.as_mut_ptr().cast(), 4096);
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
pub(super) fn capture_fd(file: &std::fs::File) -> Result<Vec<u8>, String> {
    use std::os::fd::AsRawFd;
    capture_linux(|data, len| unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            data,
            len,
        )
    })
}

#[cfg(target_os = "linux")]
pub(super) fn copy_extraction_acl(
    source: &std::fs::File,
    target: &std::fs::File,
) -> std::io::Result<()> {
    use std::{io, os::fd::AsRawFd};
    let name = c"system.posix_acl_access";
    let data = capture_fd(source).map_err(io::Error::other)?;
    let fd = target.as_raw_fd();
    if data == [0] {
        if unsafe { libc::fremovexattr(fd, name.as_ptr()) } != 0 {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
                return Err(error);
            }
        }
    } else if unsafe {
        libc::fsetxattr(
            fd,
            name.as_ptr(),
            data[1..].as_ptr().cast(),
            data.len() - 1,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    use std::io;

    // Darwin's <sys/fcntl.h> filesec property and removal sentinel.
    const FILESEC_ACL: c_int = 5;
    const FILESEC_REMOVE_ACL: *const c_void = std::ptr::without_provenance(1);
    pub(super) const EXTENDED: c_int = 0x100;
    unsafe extern "C" {
        fn filesec_init() -> *mut c_void;
        fn filesec_free(filesec: *mut c_void);
        #[cfg_attr(target_arch = "x86_64", link_name = "statx_np$INODE64")]
        fn statx_np(path: *const c_char, metadata: *mut libc::stat, filesec: *mut c_void) -> c_int;
        #[cfg_attr(target_arch = "x86_64", link_name = "fstatx_np$INODE64")]
        fn fstatx_np(fd: c_int, metadata: *mut libc::stat, filesec: *mut c_void) -> c_int;
        fn filesec_query_property(
            filesec: *mut c_void,
            property: c_int,
            valid: *mut c_int,
        ) -> c_int;
        fn filesec_get_property(filesec: *mut c_void, property: c_int, value: *mut c_void)
            -> c_int;
        fn filesec_set_property(
            filesec: *mut c_void,
            property: c_int,
            value: *const c_void,
        ) -> c_int;
        fn chmodx_np(path: *const c_char, filesec: *mut c_void) -> c_int;
        fn fchmodx_np(fd: c_int, filesec: *mut c_void) -> c_int;
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

    struct FileSec(*mut c_void);

    impl FileSec {
        fn new() -> io::Result<Self> {
            let filesec = unsafe { filesec_init() };
            if filesec.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(filesec))
        }
    }

    impl Drop for FileSec {
        fn drop(&mut self) {
            unsafe { filesec_free(self.0) };
        }
    }

    pub(super) fn capture(path: &std::ffi::CStr) -> io::Result<Option<Owned>> {
        let filesec = FileSec::new()?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // statx_np resolves the path and fetches security in the same call.
        // Only ENOENT from the subsequent property lookup means no ACL.
        if unsafe { statx_np(path.as_ptr(), metadata.as_mut_ptr(), filesec.0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        read_acl(&filesec)
    }

    fn read_acl(filesec: &FileSec) -> io::Result<Option<Owned>> {
        let mut acl: *mut c_void = std::ptr::null_mut();
        let value = std::ptr::from_mut(&mut acl).cast();
        if unsafe { filesec_get_property(filesec.0, FILESEC_ACL, value) } != 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if std::ptr::eq(acl.cast_const(), FILESEC_REMOVE_ACL) {
            return Ok(None);
        }
        Ok(Some(Owned(acl)))
    }

    pub(super) fn clear(path: &std::ffi::CStr) -> io::Result<()> {
        if capture(path)?.is_none() {
            return Ok(());
        }
        let filesec = FileSec::new()?;
        // acl_delete_file_np is unsupported in Darwin libc. chmodx_np with
        // the filesec removal sentinel removes inherited entries as well.
        if unsafe { filesec_set_property(filesec.0, FILESEC_ACL, FILESEC_REMOVE_ACL) } != 0
            || unsafe { chmodx_np(path.as_ptr(), filesec.0) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn file_has_acl(fd: c_int) -> io::Result<bool> {
        let filesec = FileSec::new()?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let mut valid = 0;
        if unsafe { fstatx_np(fd, metadata.as_mut_ptr(), filesec.0) } != 0
            || unsafe { filesec_query_property(filesec.0, FILESEC_ACL, &mut valid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(valid != 0)
    }

    pub(super) fn clear_file_acl(fd: c_int) -> io::Result<()> {
        if !file_has_acl(fd)? {
            return Ok(());
        }
        let filesec = FileSec::new()?;
        if unsafe { filesec_set_property(filesec.0, FILESEC_ACL, FILESEC_REMOVE_ACL) } != 0
            || unsafe { fchmodx_np(fd, filesec.0) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if file_has_acl(fd)? {
            return Err(io::Error::other(
                "Extraction stage still has an inherited access ACL",
            ));
        }
        Ok(())
    }

    pub(super) fn copy_file_acl(source: c_int, target: c_int) -> io::Result<()> {
        let filesec = FileSec::new()?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { fstatx_np(source, metadata.as_mut_ptr(), filesec.0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let Some(acl) = read_acl(&filesec)? else {
            return clear_file_acl(target);
        };
        let destination = FileSec::new()?;
        if unsafe {
            filesec_set_property(
                destination.0,
                FILESEC_ACL,
                std::ptr::from_ref(&acl.0).cast(),
            )
        } != 0
            || unsafe { fchmodx_np(target, destination.0) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub(super) fn clear_extraction_acl(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    darwin::clear_file_acl(file.as_raw_fd())
}

#[cfg(target_os = "macos")]
pub(super) fn copy_extraction_acl(
    source: &std::fs::File,
    target: &std::fs::File,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    darwin::copy_file_acl(source.as_raw_fd(), target.as_raw_fd())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(super) fn copy_extraction_acl(_: &std::fs::File, _: &std::fs::File) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(target_os = "macos")]
pub(crate) fn capture(path: &Path) -> Result<Vec<u8>, String> {
    let path = name(path)?;
    let Some(acl) =
        darwin::capture(&path).map_err(|e| format!("Cannot capture access ACL: {e}"))?
    else {
        return Ok(Vec::new());
    };
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
    if data.is_empty() {
        return darwin::clear(&path).map_err(|e| format!("Cannot clear access ACL: {e}"));
    }
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{apply, capture};

    #[test]
    fn round9_macos_access_acl_round_trips_absence_and_inherited_entries() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        assert!(capture(&plain).is_err());
        assert!(apply(&plain, &[]).is_err());
        std::fs::write(&plain, b"plain").unwrap();
        let no_acl = capture(&plain).unwrap();
        assert!(no_acl.is_empty());

        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow list,file_inherit,only_inherit"])
            .arg(dir.path())
            .status()
            .unwrap();
        assert!(status.success());
        let child = dir.path().join("child");
        std::fs::write(&child, b"child").unwrap();
        let inherited = capture(&child).unwrap();
        assert!(!inherited.is_empty());

        apply(&plain, &inherited).unwrap();
        assert_eq!(capture(&plain).unwrap(), inherited);
        apply(&child, &no_acl).unwrap();
        assert_eq!(capture(&child).unwrap(), no_acl);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn capture(_: &Path) -> Result<Vec<u8>, String> {
    Err("Access ACL preservation is unavailable on this platform".into())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn apply(_: &Path, _: &[u8]) -> Result<(), String> {
    Err("Access ACL preservation is unavailable on this platform".into())
}
