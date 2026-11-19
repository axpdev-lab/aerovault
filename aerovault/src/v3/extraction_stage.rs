// SPDX-License-Identifier: MPL-2.0
//! Temporary extraction files tied to the verified destination directory.

use std::{fs::File, io, path::Path};

#[cfg(unix)]
mod platform {
    use super::*;
    use rand::RngCore;
    use std::io::Read;
    use std::{
        ffi::{CStr, CString, OsStr},
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
        published: bool,
    }

    enum Replacement {
        Exchange,
        Backup(CString, Identity),
    }

    type Identity = (libc::dev_t, libc::ino_t);

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
                    published: false,
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
            self.verify_leaf(&self.name)
        }

        fn verify_leaf(&self, leaf: &CStr) -> io::Result<()> {
            let opened = stat(|metadata| unsafe { libc::fstat(self.file.as_raw_fd(), metadata) })?;
            if identity_at(self.directory.as_raw_fd(), leaf)? != identity(&opened) {
                return Err(io::Error::other("Extraction staging file changed"));
            }
            Ok(())
        }

        fn backup_original(
            &self,
            target: &CStr,
            original: Identity,
        ) -> io::Result<(CString, Identity)> {
            let directory = self.directory.as_raw_fd();
            let backup = CString::new([self.name.to_bytes(), b".previous"].concat())
                .map_err(io::Error::other)?;
            match link(directory, target, &backup) {
                Ok(()) => Ok((backup, original)),
                Err(error)
                    if unsupported_rename(&error)
                        || matches!(error.raw_os_error(), Some(libc::EPERM | libc::EMLINK)) =>
                {
                    self.copy_original(target, original)
                }
                Err(error) => Err(error),
            }
        }

        fn copy_original(
            &self,
            target: &CStr,
            original: Identity,
        ) -> io::Result<(CString, Identity)> {
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    target.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let source = unsafe { File::from_raw_fd(fd) };
            let opened = stat(|metadata| unsafe { libc::fstat(fd, metadata) })?;
            if opened.st_mode & libc::S_IFMT != libc::S_IFREG || identity(&opened) != original {
                return Err(io::Error::other("Original extraction destination changed"));
            }
            let before = source.metadata()?;
            let mut backup = Self::new(&self.directory, Path::new(""))?;
            let copied = io::copy(&mut (&source).take(before.len()), &mut &backup.file)?;
            copy_permissions(&source, &backup.file, &before)?;
            backup.file.sync_all()?;
            let after = source.metadata()?;
            if copied != before.len()
                || before.len() != after.len()
                || before.modified()? != after.modified()?
                || (before.ctime(), before.ctime_nsec()) != (after.ctime(), after.ctime_nsec())
                || identity_at(self.directory.as_raw_fd(), target)? != original
            {
                return Err(io::Error::other(
                    "Original extraction destination changed while copied",
                ));
            }
            let backup_identity = identity_at(self.directory.as_raw_fd(), &backup.name)?;
            // Transfer responsibility for retaining or removing the backup
            // name to the publication path.
            backup.published = true;
            Ok((std::mem::take(&mut backup.name), backup_identity))
        }

        pub(crate) fn publish(
            &mut self,
            target: &Path,
            overwrite: bool,
            check_parent: impl Fn() -> io::Result<()>,
        ) -> io::Result<()> {
            let target = name(
                target
                    .file_name()
                    .ok_or_else(|| io::Error::other("Missing output basename"))?,
            )?;
            let directory = self.directory.as_raw_fd();
            self.verify()?;
            check_parent()?;
            if !overwrite {
                rename_noclobber(directory, &self.name, &target)?;
                if let Err(error) = check_parent() {
                    if self.verify_leaf(&target).is_ok() {
                        let _ = unlink(directory, &target);
                    }
                    return Err(error);
                }
                self.published = true;
                return Ok(());
            }

            // Retain the original output until the post-rename containment
            // check. A parent move can occur inside either rename syscall.
            let original = stat_at(directory, &target)?;
            if original.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(io::Error::other(
                    "Extraction destination is no longer a regular file",
                ));
            }
            let original = identity(&original);
            let replacement = match rename_exchange(directory, &self.name, &target) {
                Ok(()) => Replacement::Exchange,
                Err(error) if unsupported_rename(&error) => {
                    let (backup, backup_identity) = self.backup_original(&target, original)?;
                    let replace = check_parent().and_then(|()| {
                        if identity_at(directory, &target)? != original
                            || identity_at(directory, &backup)? != backup_identity
                        {
                            return Err(io::Error::other(
                                "Original extraction destination changed",
                            ));
                        }
                        rename(directory, &self.name, &target)
                    });
                    if let Err(error) = replace {
                        if identity_at(directory, &backup).is_ok_and(|id| id == backup_identity) {
                            let _ = unlink(directory, &backup);
                        }
                        return Err(error);
                    }
                    Replacement::Backup(backup, backup_identity)
                }
                Err(error) => return Err(error),
            };
            let (backup, backup_identity) = match &replacement {
                Replacement::Exchange => (&self.name, original),
                Replacement::Backup(backup, identity) => (backup, *identity),
            };
            let verify_original = || {
                if identity_at(directory, backup)? != backup_identity {
                    return Err(io::Error::other("Original extraction destination changed"));
                }
                Ok(())
            };
            if let Err(error) = check_parent() {
                let restored = self
                    .verify_leaf(&target)
                    .and_then(|()| verify_original())
                    .and_then(|()| match &replacement {
                        Replacement::Exchange => rename_exchange(directory, backup, &target),
                        Replacement::Backup(..) => rename(directory, backup, &target),
                    });
                return Err(match restored {
                    Ok(()) => error,
                    Err(restore) => io::Error::other(format!(
                        "{error}. Cannot restore the original destination: {restore}. \
                         Retained recovery name {} in the validated directory",
                        backup.to_string_lossy()
                    )),
                });
            }
            self.published = true;
            verify_original()
                .and_then(|()| unlink(directory, backup))
                .map_err(|error| {
                    io::Error::other(format!(
                        "Destination published. Cannot remove the previous output {}: {error}",
                        backup.to_string_lossy()
                    ))
                })
        }
    }

    impl Drop for Stage {
        fn drop(&mut self) {
            if !self.published {
                let _ = self.file.set_len(0);
            }
            if !self.name.as_bytes().is_empty() && self.verify().is_ok() {
                let _ = unlink(self.directory.as_raw_fd(), &self.name);
            }
        }
    }

    fn copy_permissions(
        source: &File,
        backup: &File,
        original: &std::fs::Metadata,
    ) -> io::Result<()> {
        let staged = backup.metadata()?;
        if (staged.uid(), staged.gid()) != (original.uid(), original.gid()) {
            unix_result(unsafe {
                libc::fchown(backup.as_raw_fd(), original.uid(), original.gid())
            })?;
        }
        let mode = original.permissions().mode() & 0o7777;
        if backup.metadata()?.permissions().mode() & 0o7777 != mode {
            backup.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        crate::v3::unix_security::copy_extraction_acl(source, backup)?;
        let applied = backup.metadata()?;
        if (applied.uid(), applied.gid(), applied.mode() & 0o7777)
            != (original.uid(), original.gid(), mode)
        {
            return Err(io::Error::other(
                "Cannot preserve original extraction permissions",
            ));
        }
        Ok(())
    }

    fn stat(read: impl FnOnce(*mut libc::stat) -> libc::c_int) -> io::Result<libc::stat> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        unix_result(read(metadata.as_mut_ptr()))?;
        Ok(unsafe { metadata.assume_init() })
    }

    fn stat_at(directory: libc::c_int, name: &CStr) -> io::Result<libc::stat> {
        stat(|metadata| unsafe {
            libc::fstatat(
                directory,
                name.as_ptr(),
                metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }

    fn identity(metadata: &libc::stat) -> Identity {
        (metadata.st_dev, metadata.st_ino)
    }

    fn identity_at(directory: libc::c_int, name: &CStr) -> io::Result<Identity> {
        stat_at(directory, name).map(|metadata| identity(&metadata))
    }

    fn unix_result(result: libc::c_int) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn rename(directory: libc::c_int, source: &CStr, dest: &CStr) -> io::Result<()> {
        unix_result(unsafe { libc::renameat(directory, source.as_ptr(), directory, dest.as_ptr()) })
    }

    fn link(directory: libc::c_int, source: &CStr, dest: &CStr) -> io::Result<()> {
        #[cfg(test)]
        if FORBID_LINK_AND_EXCHANGE.get() {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        unix_result(unsafe {
            libc::linkat(directory, source.as_ptr(), directory, dest.as_ptr(), 0)
        })
    }

    fn unlink(directory: libc::c_int, leaf: &CStr) -> io::Result<()> {
        unix_result(unsafe { libc::unlinkat(directory, leaf.as_ptr(), 0) })
    }

    fn unsupported_rename(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::Unsupported
            || matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::ENOTSUP | libc::EINVAL)
            )
    }

    fn rename_exchange(directory: libc::c_int, source: &CStr, dest: &CStr) -> io::Result<()> {
        #[cfg(test)]
        if FORBID_LINK_AND_EXCHANGE.get() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        exchange(directory, source, dest)
    }

    #[cfg(target_os = "linux")]
    fn exchange(directory: libc::c_int, source: &CStr, dest: &CStr) -> io::Result<()> {
        unix_result(unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                directory,
                source.as_ptr(),
                directory,
                dest.as_ptr(),
                libc::RENAME_EXCHANGE,
            ) as libc::c_int
        })
    }

    #[cfg(target_os = "macos")]
    fn exchange(directory: libc::c_int, source: &CStr, dest: &CStr) -> io::Result<()> {
        unix_result(unsafe {
            libc::renameatx_np(
                directory,
                source.as_ptr(),
                directory,
                dest.as_ptr(),
                libc::RENAME_SWAP,
            )
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn exchange(_: libc::c_int, _: &CStr, _: &CStr) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
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
            if !unsupported_rename(&error) {
                return Err(error);
            }
        }
        // Filesystems without an atomic no-replace rename can atomically
        // create a hard link. The stage's normal cleanup removes the old name.
        link(directory, source, dest)
    }

    #[cfg(test)]
    thread_local! {
        static FORBID_LINK_AND_EXCHANGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn extraction_replaces_and_restores_without_exchange_or_hard_links() {
        use std::io::Write;

        for moved in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let parent = fixture.path().join("destination");
            let moved_parent = fixture.path().join("moved");
            std::fs::create_dir(&parent).unwrap();
            let target = parent.join("file");
            let original = b"original USB drive output";
            let payload = b"new extracted bytes";
            std::fs::write(&target, original).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
            let pinned = pin(&parent).unwrap();
            let mut stage = Stage::new(&pinned[0], &parent).unwrap();
            stage.file().write_all(payload).unwrap();
            FORBID_LINK_AND_EXCHANGE.set(true);
            let checks = std::cell::Cell::new(0);
            let result = stage.publish(&target, true, || {
                checks.set(checks.get() + 1);
                if moved && checks.get() == 2 {
                    // Move after the fallback's last pre-rename check.
                    std::fs::rename(&parent, &moved_parent).unwrap();
                    return Ok(());
                }
                if parent.is_dir() {
                    return Ok(());
                }
                Err(io::Error::other("validated output directory changed"))
            });
            FORBID_LINK_AND_EXCHANGE.set(false);
            drop(stage);
            let parent = if moved {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("directory changed"));
                let restored = moved_parent.join("file");
                let metadata = restored.metadata().unwrap();
                assert_eq!(metadata.mode() & 0o777, 0o640);
                assert_eq!(std::fs::read(restored).unwrap(), original);
                moved_parent
            } else {
                result.unwrap();
                assert_eq!(std::fs::read(target).unwrap(), payload);
                parent
            };
            assert_eq!(std::fs::read_dir(parent).unwrap().count(), 1);
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
        stage.publish(&published, false, || Ok(())).unwrap();
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

        pub(crate) fn publish(
            &mut self,
            target: &Path,
            overwrite: bool,
            check_parent: impl Fn() -> io::Result<()>,
        ) -> io::Result<()> {
            self.verify()?;
            check_parent()?;
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
