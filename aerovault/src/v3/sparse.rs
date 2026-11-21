// SPDX-License-Identifier: MPL-2.0
//! Logical data ranges in ordinary and sparse files.
use std::fs::File;
use std::io;
use std::ops::Range;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn data_range(file: &File, start: u64, end: u64) -> io::Result<Option<Range<u64>>> {
    use std::os::fd::AsRawFd;

    let seek = |offset, whence| {
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: the file is live and the absolute offset is representable.
        let found = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
        if found >= 0 {
            return Ok(Some(found as u64));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENXIO) {
            return Ok(None);
        }
        Err(error)
    };
    if start >= end {
        return Ok(None);
    }
    let Some(data) = seek(start, libc::SEEK_DATA)? else {
        return Ok(None);
    };
    let hole = seek(data, libc::SEEK_HOLE)?.ok_or(io::ErrorKind::InvalidData)?;
    if data < start || hole <= data || hole > end {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(data..hole))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(super) fn data_range(_file: &File, _start: u64, _end: u64) -> io::Result<Option<Range<u64>>> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(windows)]
pub(super) use windows::{data_range, mark_sparse_if_supported};

#[cfg(windows)]
mod windows {
    use super::{io, File, Range};
    use std::ffi::c_void;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;

    const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x200;
    const FILE_SUPPORTS_SPARSE_FILES: u32 = 0x40;
    const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;
    const FSCTL_QUERY_ALLOCATED_RANGES: u32 = 0x0009_40CF;
    const ERROR_MORE_DATA: i32 = 234;

    #[repr(C)]
    struct AllocatedRange {
        offset: i64,
        length: i64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            file: *mut c_void,
            code: u32,
            input: *const c_void,
            input_len: u32,
            output: *mut c_void,
            output_len: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn GetVolumeInformationByHandleW(
            file: *mut c_void,
            volume_name: *mut u16,
            volume_name_len: u32,
            serial: *mut u32,
            max_component: *mut u32,
            flags: *mut u32,
            filesystem_name: *mut u16,
            filesystem_name_len: u32,
        ) -> i32;
    }

    pub(in crate::v3) fn data_range(
        file: &File,
        start: u64,
        end: u64,
    ) -> io::Result<Option<Range<u64>>> {
        if start >= end {
            return Ok(None);
        }
        // A compressed ordinary file still has complete logical coverage.
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_SPARSE_FILE == 0 {
            return Ok(Some(start..end));
        }
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        let input = AllocatedRange {
            offset: i64::try_from(start).map_err(|_| invalid())?,
            length: i64::try_from(end - start).map_err(|_| invalid())?,
        };
        let mut output = AllocatedRange {
            offset: 0,
            length: 0,
        };
        let size = std::mem::size_of::<AllocatedRange>() as u32;
        let mut returned = 0;
        // SAFETY: the file is live and both synchronous I/O buffers have
        // the Win32 layout and stay valid for the duration of this call.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&input as *const AllocatedRange).cast(),
                size,
                (&mut output as *mut AllocatedRange).cast(),
                size,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_MORE_DATA) || returned != size {
                return Err(error);
            }
        }
        if returned == 0 {
            return Ok(None);
        }
        if returned != size {
            return Err(invalid());
        }
        let offset = u64::try_from(output.offset).map_err(|_| invalid())?;
        let length = u64::try_from(output.length).map_err(|_| invalid())?;
        let first = offset.max(start);
        let last = offset.checked_add(length).ok_or_else(invalid)?.min(end);
        if first >= last {
            return Err(invalid());
        }
        Ok(Some(first..last))
    }

    pub(in crate::v3) fn mark_sparse_if_supported(file: &File) -> io::Result<bool> {
        let mut flags = 0;
        // SAFETY: the handle and flags output are live. Unused outputs are null.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                file.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                null_mut(),
                0,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & FILE_SUPPORTS_SPARSE_FILES == 0 {
            return Ok(false);
        }
        let mut returned = 0;
        // SAFETY: the live file is writable. This synchronous request does
        // not require input or output buffers.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(true)
    }
}
