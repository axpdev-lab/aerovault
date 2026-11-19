// SPDX-License-Identifier: MPL-2.0
//! Temporary extraction files tied to the verified destination directory.

use std::{fs::File, io, path::Path};

#[cfg(unix)]
mod platform {
    use super::*;
    use rand::RngCore;
    use std::{
        ffi::{CStr, CString, OsStr},
        os::unix::{
            ffi::OsStrExt,
            fs::OpenOptionsExt,
            io::{AsRawFd, FromRawFd},
        },
    };

    pub(crate) fn pin(path: &Path) -> io::Result<Vec<File>> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        Ok(vec![file])
    }

    fn name(leaf: &OsStr) -> io::Result<CString> {
        CString::new(leaf.as_bytes()).map_err(io::Error::other)
    }

    pub(crate) struct Stage {
        directory: File,
        name: CString,
        file: File,
    }

    impl Stage {
        pub(crate) fn new(directory: &File, _: &Path) -> io::Result<Self> {
            let directory = directory.try_clone()?;
            for _ in 0..128 {
                let mut random = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut random);
                let leaf = name(OsStr::new(&format!(
                    ".aerovault-v3-{}",
                    hex::encode(random)
                )))?;
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        leaf.as_ptr(),
                        libc::O_RDWR
                            | libc::O_CLOEXEC
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW,
                        0o600_i32,
                    )
                };
                if fd < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        continue;
                    }
                    return Err(error);
                }
                // openat returned a new file descriptor owned by this stage.
                let file = unsafe { File::from_raw_fd(fd) };
                let stage = Self {
                    directory,
                    name: leaf,
                    file,
                };
                #[cfg(target_os = "macos")]
                crate::v3::unix_security::clear_extraction_acl(&stage.file)?;
                return Ok(stage);
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Cannot reserve private extraction stage",
            ))
        }

        pub(crate) fn file(&self) -> &File {
            &self.file
        }

        pub(crate) fn verify(&self) -> io::Result<()> {
            use std::os::unix::fs::MetadataExt;
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let current = unsafe { File::from_raw_fd(fd) }.metadata()?;
            let opened = self.file.metadata()?;
            if !current.is_file() || (current.dev(), current.ino()) != (opened.dev(), opened.ino())
            {
                return Err(io::Error::other("Extraction staging file changed"));
            }
            Ok(())
        }

        pub(crate) fn publish(&mut self, target: &Path, overwrite: bool) -> io::Result<()> {
            let target = name(
                target
                    .file_name()
                    .ok_or_else(|| io::Error::other("Missing output basename"))?,
            )?;
            let directory = self.directory.as_raw_fd();
            if overwrite {
                let result = unsafe {
                    libc::renameat(directory, self.name.as_ptr(), directory, target.as_ptr())
                };
                return if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                };
            }
            rename_noclobber(directory, &self.name, &target)
        }
    }

    impl Drop for Stage {
        fn drop(&mut self) {
            if self.verify().is_ok() {
                unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) };
            }
        }
    }

    fn rename_noclobber(directory: libc::c_int, source: &CStr, dest: &CStr) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let renamed = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                directory,
                source.as_ptr(),
                directory,
                dest.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let renamed = unsafe {
            libc::renameatx_np(
                directory,
                source.as_ptr(),
                directory,
                dest.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if renamed == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::ENOTSUP | libc::EINVAL)
            ) {
                return Err(error);
            }
        }
        // Filesystems without an atomic no-replace rename can atomically
        // create a hard link. The stage's normal cleanup removes the old name.
        let linked =
            unsafe { libc::linkat(directory, source.as_ptr(), directory, dest.as_ptr(), 0) };
        if linked == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    #[test]
    fn extraction_stage_clears_inherited_access_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow list,file_inherit,only_inherit"])
            .arg(dir.path())
            .status()
            .unwrap();
        assert!(status.success());
        let capture = crate::v3::unix_security::capture;
        let ordinary = dir.path().join("ordinary");
        std::fs::File::create(&ordinary).unwrap();
        assert!(!capture(&ordinary).unwrap().is_empty());

        let pinned = pin(dir.path()).unwrap();
        let mut stage = Stage::new(&pinned[0], dir.path()).unwrap();
        let staged = dir.path().join(stage.name.to_str().unwrap());
        assert_eq!(stage.file().metadata().unwrap().len(), 0);
        assert!(capture(&staged).unwrap().is_empty());
        let published = dir.path().join("published");
        stage.publish(&published, false).unwrap();
        assert!(capture(&published).unwrap().is_empty());
    }
}

#[cfg(not(unix))]
mod platform {
    use super::*;

    pub(crate) fn pin(path: &Path) -> io::Result<Vec<File>> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ_WRITE: u32 = 0x3;
            const FILE_TRAVERSE: u32 = 0x20;
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            // Deny delete sharing on the directory and its ancestry while
            // path-based creation and publication are in progress. Traverse
            // access participates in share checks without listing entries.
            path.ancestors()
                .enumerate()
                .take_while(|(i, path)| *i == 0 || path.parent().is_some())
                .map(|(_, ancestor)| {
                    std::fs::OpenOptions::new()
                        .access_mode(FILE_TRAVERSE)
                        .share_mode(FILE_SHARE_READ_WRITE)
                        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                        .open(ancestor)
                })
                .collect()
        }
        #[cfg(not(windows))]
        Ok(vec![File::open(path)?])
    }

    pub(crate) struct Stage {
        temp: Option<tempfile::NamedTempFile>,
        identity: same_file::Handle,
    }

    impl Stage {
        pub(crate) fn new(_: &File, path: &Path) -> io::Result<Self> {
            let temp = tempfile::Builder::new()
                .prefix(".aerovault-v3-")
                .tempfile_in(path)?;
            let identity = same_file::Handle::from_file(temp.as_file().try_clone()?)?;
            Ok(Self {
                temp: Some(temp),
                identity,
            })
        }

        pub(crate) fn file(&self) -> &File {
            self.temp.as_ref().expect("unpublished stage").as_file()
        }

        pub(crate) fn verify(&self) -> io::Result<()> {
            let current = same_file::Handle::from_path(
                self.temp.as_ref().expect("unpublished stage").path(),
            )?;
            if current != self.identity {
                return Err(io::Error::other("Extraction staging file changed"));
            }
            Ok(())
        }

        pub(crate) fn publish(&mut self, target: &Path, overwrite: bool) -> io::Result<()> {
            let temp = self.temp.take().expect("unpublished stage");
            let result = if overwrite {
                temp.persist(target)
            } else {
                temp.persist_noclobber(target)
            };
            match result {
                Ok(_) => Ok(()),
                Err(error) => {
                    self.temp = Some(error.file);
                    Err(error.error)
                }
            }
        }
    }
}

pub(super) use platform::{pin, Stage};
