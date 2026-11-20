// SPDX-License-Identifier: MPL-2.0
//! Recoverable publication of a non-forced strip and its refreshed sidecar.
//!
//! Prepared files and rollback copies live on disk. A small, synced journal is
//! made visible before either rename. An interrupted publication is rolled back
//! on the next open/write; a completed pair only needs journal cleanup. Recovery
//! never replaces a generation outside the recorded old/new pair.
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::vault::output_parent_dir;
#[cfg(not(windows))]
use super::vault::persist_over;
use crate::lock::WriteLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Generation {
    len: u64,
    hash: [u8; 32],
}

pub(super) fn generation(path: &Path) -> Result<Generation, String> {
    let file = crate::source::open_regular_no_follow(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let expected = file.metadata().map_err(|e| e.to_string())?.len();
    hash_generation(file, expected)
}

fn hash_generation(mut file: fs::File, expected: u64) -> Result<Generation, String> {
    let mut reader = Read::by_ref(&mut file).take(expected);
    let mut hash = blake3::Hasher::new();
    let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    let mut len = 0u64;
    loop {
        let n = reader.read(&mut *buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        len = len
            .checked_add(n as u64)
            .ok_or("generation length overflow")?;
    }
    if len != expected || file.read(&mut buf[..1]).map_err(|e| e.to_string())? != 0 {
        return Err("generation changed length while hashing".into());
    }
    Ok(Generation {
        len,
        hash: *hash.finalize().as_bytes(),
    })
}

fn generation_if_present(path: &Path) -> Result<Option<Generation>, String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
        Ok(_) => generation(path).map(Some),
    }
}

pub(super) fn recorded_generation(
    path: &Path,
    candidates: &[Option<Generation>],
) -> Result<Option<Generation>, String> {
    let file = match crate::source::open_regular_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read {}: {error}", path.display())),
    };
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    if !candidates
        .iter()
        .flatten()
        .any(|candidate| candidate.len == len)
    {
        return Err(format!(
            "unexpected recovery length {len} for {}",
            path.display()
        ));
    }
    hash_generation(file, len).map(Some)
}

pub(super) fn journal_path(source: &Path) -> PathBuf {
    let lock = crate::lock::lock_path(source);
    let hash = blake3::hash(lock.file_name().unwrap_or_default().as_encoded_bytes());
    source.with_file_name(format!(".{}.aerostrip", hash.to_hex()))
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SavedPermissions {
    unix_mode: Option<u32>,
    #[serde(default)]
    unix_acl: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_owner_group: Option<(u32, u32)>,
    readonly: bool,
    #[serde(default)]
    windows_dacl: Option<String>,
}
impl SavedPermissions {
    pub(crate) fn capture(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.is_file() {
            return Err("Cannot capture security of a non-regular file".into());
        }
        let p = metadata.permissions();
        #[cfg(unix)]
        let (unix_mode, unix_owner_group) = {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            (
                Some(p.mode() & 0o777),
                Some((metadata.uid(), metadata.gid())),
            )
        };
        #[cfg(not(unix))]
        let (unix_mode, unix_owner_group) = (None, None);
        Ok(Self {
            unix_mode,
            unix_owner_group,
            #[cfg(unix)]
            unix_acl: Some(super::unix_security::capture(path)?),
            #[cfg(not(unix))]
            unix_acl: None,
            readonly: p.readonly(),
            #[cfg(windows)]
            windows_dacl: Some(super::windows_security::capture(path)?),
            #[cfg(not(windows))]
            windows_dacl: None,
        })
    }

    fn capture_if_present(path: &Path) -> Result<Option<Self>, String> {
        if path.try_exists().map_err(|e| e.to_string())? {
            Self::capture(path).map(Some)
        } else {
            Ok(None)
        }
    }
    /// Capture how a new file would be created in its actual destination
    /// directory, using an empty probe rather than exposing staged vault bytes.
    fn new_destination(path: &Path) -> Result<Option<Self>, String> {
        if path.try_exists().map_err(|e| e.to_string())? {
            return Ok(None);
        }
        #[cfg(windows)]
        {
            let probe = tempfile::Builder::new()
                .prefix(".aerovault-security-")
                .tempfile_in(output_parent_dir(path))
                .map_err(|e| e.to_string())?;
            Self::capture(probe.path()).map(Some)
        }
        #[cfg(not(windows))]
        {
            Ok(None)
        }
    }

    pub(crate) fn apply(&self, path: &Path) -> Result<(), String> {
        #[cfg(windows)]
        super::windows_security::apply(
            path,
            self.windows_dacl.as_deref().ok_or(
                "Recovery journal lacks the original Windows DACL; manual recovery required",
            )?,
            true,
        )?;
        #[cfg(unix)]
        if let Some(mode) = self.unix_mode {
            use std::os::{
                fd::AsRawFd,
                unix::fs::{MetadataExt, PermissionsExt},
            };
            let acl = self.unix_acl.as_deref().ok_or(
                "Recovery journal lacks the original access ACL; manual recovery required",
            )?;
            if let Some((uid, gid)) = self.unix_owner_group {
                let stage =
                    crate::source::open_regular_no_follow(path).map_err(|e| e.to_string())?;
                let metadata = stage.metadata().map_err(|e| e.to_string())?;
                if (metadata.uid(), metadata.gid()) != (uid, gid) {
                    if unsafe { libc::fchown(stage.as_raw_fd(), uid, gid) } != 0 {
                        return Err(format!(
                            "Cannot preserve file owner and group: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    let metadata = stage.metadata().map_err(|e| e.to_string())?;
                    if (metadata.uid(), metadata.gid()) != (uid, gid) {
                        return Err(
                            "File owner and group preservation could not be verified".into()
                        );
                    }
                }
            }
            super::unix_security::apply(path, acl)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
                .map_err(|e| e.to_string())?;
            if super::unix_security::capture(path)? != acl {
                return Err(
                    "Access ACL preservation could not be verified; originals left unchanged"
                        .into(),
                );
            }
            return Ok(());
        }
        let mut permissions = fs::metadata(path).map_err(|e| e.to_string())?.permissions();
        permissions.set_readonly(self.readonly);
        fs::set_permissions(path, permissions).map_err(|e| e.to_string())
    }
    fn published(&self, path: &Path) -> Result<(), String> {
        #[cfg(windows)]
        super::windows_security::apply(
            path,
            self.windows_dacl
                .as_deref()
                .ok_or("Recovery journal lacks the original Windows DACL")?,
            false,
        )?;
        #[cfg(not(windows))]
        let _ = path;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    source_name: Vec<u8>,
    old_vault: Option<Generation>,
    new_vault: Generation,
    old_sidecar: Option<Generation>,
    new_sidecar: Generation,
    #[serde(default)]
    old_vault_permissions: Option<SavedPermissions>,
    #[serde(default)]
    old_sidecar_permissions: Option<SavedPermissions>,
    #[serde(default)]
    new_vault_permissions: Option<SavedPermissions>,
    #[serde(default)]
    new_sidecar_permissions: Option<SavedPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staged_vault_dacl: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staged_sidecar_dacl: Option<[u8; 32]>,
}

pub(crate) struct PrivateDir {
    path: PathBuf,
}
impl PrivateDir {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(windows)]
    pub(crate) fn keep(&mut self) -> PathBuf {
        std::mem::take(&mut self.path)
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn private_dir(parent: &Path, prefix: &str) -> Result<PrivateDir, String> {
    #[cfg(windows)]
    let path = {
        use rand::RngCore;
        let mut created = None;
        for _ in 0..128 {
            let mut random = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut random);
            let path = parent.join(format!("{prefix}{}", hex::encode(random)));
            match super::windows_security::create_private_directory(&path) {
                Ok(()) => {
                    created = Some(path);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Create private transaction directory: {e}")),
            }
        }
        created.ok_or("Could not reserve private transaction directory")?
    };
    #[cfg(not(windows))]
    let path = {
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        builder
            .tempdir_in(parent)
            .map_err(|e| e.to_string())?
            .keep()
    };
    let dir = PrivateDir { path };
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        // A 0700 directory can still inherit an ACL grant. Clear it while the
        // directory is empty, before it is allowed to hold any vault bytes.
        super::unix_security::apply(dir.path(), &[])?;
        let mode = fs::metadata(dir.path())
            .map_err(|e| e.to_string())?
            .permissions()
            .mode();
        if mode & 0o077 != 0 || !super::unix_security::capture(dir.path())?.is_empty() {
            return Err("Private transaction directory is accessible to other principals".into());
        }
        if fs::read_dir(dir.path())
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
        {
            return Err("Private transaction directory changed during creation".into());
        }
    }
    Ok(dir)
}

fn private_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn sync_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("sync directory {}: {e}", path.display()))?;
    #[cfg(not(unix))]
    let _ = path; // Synced, closed files and atomic rename cover process interruption.
    Ok(())
}

/// Copy with fixed scratch storage, retaining the exact generation check. The
/// prepared directory is private; targets are fresh files, never reused paths.
pub(super) fn copy_file(source: &Path, target: &Path) -> Result<Generation, String> {
    copy_file_capped(source, target, u64::MAX)
}

pub(super) fn copy_file_capped(
    source: &Path,
    target: &Path,
    limit: u64,
) -> Result<Generation, String> {
    let mut copied = 0u64;
    let mut input = crate::source::open_regular_no_follow(source).map_err(|e| e.to_string())?;
    let mut output = private_options().open(target).map_err(|e| e.to_string())?;
    let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    loop {
        let n = input.read(&mut *buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        copied = copied
            .checked_add(n as u64)
            .ok_or("Recovery copy length overflow")?;
        if copied > limit {
            return Err("Recovery input grew beyond its validated copy bound".into());
        }
        output.write_all(&buf[..n]).map_err(|e| e.to_string())?;
    }
    output.sync_all().map_err(|e| e.to_string())?;
    generation(target)
}

fn replace_from(
    mut input: fs::File,
    target: &Path,
    expected: Generation,
    target_before: Generation,
) -> Result<(), String> {
    let private = private_dir(output_parent_dir(target), ".aerostrip-restore-")?;
    #[cfg(windows)]
    let mut private = private;
    let mut temp = tempfile::Builder::new()
        .prefix("replacement-")
        .tempfile_in(private.path())
        .map_err(|e| e.to_string())?;
    let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    let mut remaining = expected.len;
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        input.read_exact(&mut buf[..n]).map_err(|e| e.to_string())?;
        temp.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        remaining -= n as u64;
    }
    if input.read(&mut buf[..1]).map_err(|e| e.to_string())? != 0 {
        return Err("strip rollback copy grew while being read".into());
    }
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    #[cfg(all(test, target_os = "macos"))]
    if let Some(inspect) = INSPECT_ROLLBACK_STAGE.with(|h| h.borrow_mut().take()) {
        inspect(temp.path());
    }
    if generation(temp.path())? != expected {
        return Err("strip rollback copy changed while being read".to_string());
    }
    if recorded_generation(target, &[Some(target_before)])? != Some(target_before) {
        return Err(
            "strip target changed while preparing rollback; newer file left untouched".to_string(),
        );
    }
    // Rolling back content must not roll back a later operator restriction.
    // Capture current security under the destination guard and carry
    // that context onto the restored bytes, including incomplete finalization.
    let permissions = SavedPermissions::capture(target)?;
    permissions.apply(temp.path())?;
    // Backups remain private: permissions are restored only on the replacement.
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    super::windows_security::persist_repair(temp, target, &mut private)?;
    #[cfg(not(windows))]
    persist_over(temp, target).map_err(|e| e.to_string())?;
    sync_dir(output_parent_dir(target))
}

#[cfg(all(test, target_os = "macos"))]
type InspectRollbackStage = Box<dyn FnOnce(&Path)>;

#[cfg(all(test, target_os = "macos"))]
thread_local! {
    static INSPECT_ROLLBACK_STAGE: std::cell::RefCell<Option<InspectRollbackStage>> =
        const { std::cell::RefCell::new(None) };
}

fn cleanup(path: &Path) -> Result<(), String> {
    // Remove the recovery marker atomically before garbage collection. A crash
    // can leave a private GC directory, never a half-deleted active journal.
    let gc = private_dir(output_parent_dir(path), ".aerostrip-gc-")?;
    fs::remove_dir(gc.path()).map_err(|e| e.to_string())?;
    fs::rename(path, gc.path()).map_err(|e| e.to_string())?;
    #[cfg(test)]
    let injected = FAIL_CLEANUP_SYNC.with(|fail| fail.replace(false));
    #[cfg(not(test))]
    let injected = false;
    let synced = if injected {
        Err("injected journal retirement sync failure".to_string())
    } else {
        sync_dir(output_parent_dir(path))
    };
    if let Err(error) = synced {
        let mut gc = gc;
        let retained = std::mem::take(&mut gc.path);
        return Err(format!("journal retirement sync failed ({error}); relocated journal and rollback copies retained at {}", retained.display()));
    }
    drop(gc);
    Ok(())
}

// A journal is local filesystem state. Preserve native names without lossy
// conversion; decoding must still produce exactly one ordinary basename.
fn native_name(path: &Path) -> Vec<u8> {
    let name = path.file_name().unwrap_or_default();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        name.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        name.encode_wide().flat_map(u16::to_le_bytes).collect()
    }
}

fn recorded_source(parent: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(bytes.to_vec())
    };
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        let (pairs, remainder) = bytes.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err("invalid strip journal source name".to_string());
        }
        let units: Vec<u16> = pairs.iter().map(|b| u16::from_le_bytes(*b)).collect();
        std::ffi::OsString::from_wide(&units)
    };
    let leaf = Path::new(&name);
    let mut components = leaf.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err("invalid strip journal source basename".to_string());
    }
    Ok(parent.join(leaf))
}

fn same_existing_file(a: &Path, b: &Path) -> bool {
    let (Ok(a_meta), Ok(b_meta)) = (fs::symlink_metadata(a), fs::symlink_metadata(b)) else {
        return false;
    };
    if !a_meta.is_file() || !b_meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a_meta.dev() == b_meta.dev() && a_meta.ino() == b_meta.ino()
    }
    #[cfg(windows)]
    {
        matches!((fs::canonicalize(a), fs::canonicalize(b)), (Ok(a), Ok(b)) if a == b)
    }
}

fn conflict(path: &Path, reason: &str) -> String {
    format!("pending strip transaction conflicts ({reason}); files left untouched; preserve the vault, sidecar and rollback directory {}, then follow the pending-strip conflict procedure in AEROVAULT-V3-SPEC.md before reopening", path.display())
}

pub(super) struct TrustedJournal<'a> {
    path: &'a Path,
    directory: same_file::Handle,
    #[cfg(windows)]
    pins: Vec<fs::File>,
    #[cfg(unix)]
    opened: fs::File,
}

impl<'a> TrustedJournal<'a> {
    pub(super) fn open(path: &'a Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err("strip transaction path is not a regular directory".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("strip transaction directory is a reparse point".into());
            }
        }
        let mut pins = super::extraction_stage::pin(path).map_err(|e| e.to_string())?;
        let opened = pins.remove(0);
        let directory =
            same_file::Handle::from_file(opened.try_clone().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        validate_private_journal_directory(path, &opened)?;
        #[cfg(windows)]
        super::windows_security::verify_private_journal_directory(path)?;
        #[cfg(windows)]
        pins.push(opened);
        let journal = Self {
            path,
            directory,
            #[cfg(windows)]
            pins,
            #[cfg(unix)]
            opened,
        };
        journal.recheck()?;
        Ok(journal)
    }

    fn recheck(&self) -> Result<(), String> {
        let current = super::extraction_stage::directory_identity(self.path)
            .map_err(|e| format!("strip journal directory unavailable: {e}"))?;
        if current != self.directory {
            return Err("strip journal directory changed".into());
        }
        Ok(())
    }

    pub(super) fn open_input(&self, name: &str) -> Result<fs::File, String> {
        #[cfg(unix)]
        let file = {
            use std::os::fd::{AsRawFd, FromRawFd};
            let leaf = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
            let fd = unsafe {
                libc::openat(
                    self.opened.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o022 != 0
                || metadata.nlink() != 1
            {
                return Err(
                    "strip journal input does not have trusted ownership and access".into(),
                );
            }
            file
        };
        #[cfg(windows)]
        let file = {
            let path = self.path.join(name);
            let file = crate::source::open_regular_no_follow(&path).map_err(|e| e.to_string())?;
            super::windows_security::verify_journal_input(&file)?;
            file
        };
        #[cfg(not(any(windows, unix)))]
        let file = crate::source::open_regular_no_follow(&self.path.join(name))
            .map_err(|e| e.to_string())?;
        self.recheck()?;
        Ok(file)
    }

    fn backup(&self, name: &str, expected: Option<Generation>) -> Result<Option<fs::File>, String> {
        let Some(expected) = expected else {
            if self.path.join(name).exists() {
                return Err("unexpected strip rollback material; files left untouched".into());
            }
            return Ok(None);
        };
        let mut file = self.open_input(name)?;
        if file.metadata().map_err(|e| e.to_string())?.len() != expected.len
            || hash_generation(file.try_clone().map_err(|e| e.to_string())?, expected.len)?
                != expected
        {
            return Err("strip rollback generation check failed; files left untouched".into());
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        Ok(Some(file))
    }

    fn retire(self) -> Result<(), String> {
        self.recheck()?;
        let path = self.path;
        #[cfg(windows)]
        let (journal_handle, ancestors) = {
            let mut pins = self.pins;
            (pins.pop(), pins)
        };
        #[cfg(windows)]
        {
            drop(self.directory);
            drop(journal_handle);
            let result = cleanup(path);
            drop(ancestors);
            result.map_err(|e| format!("Retire verified strip journal: {e}"))
        }
        #[cfg(not(windows))]
        cleanup(path)
    }
}

#[cfg(unix)]
fn validate_private_journal_directory(path: &Path, opened: &fs::File) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let user = unsafe { libc::geteuid() };
    let metadata = opened.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.uid() != user || metadata.mode() & 0o077 != 0 {
        return Err(
            "strip journal directory does not have trusted ownership and private access".into(),
        );
    }
    #[cfg(target_os = "macos")]
    if !super::unix_security::capture(path)?.is_empty() {
        return Err("strip journal directory has an extended access ACL".into());
    }
    validate_journal_ancestry(output_parent_dir(path))
}

#[cfg(unix)]
fn validate_journal_ancestry(parent: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let user = unsafe { libc::geteuid() };
    // An untrusted parent must not be able to replace the checked journal entry.
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if !metadata.is_dir()
            || (metadata.uid() != user && metadata.uid() != 0)
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err("strip journal ancestry permits replacement by another principal".into());
        }
        #[cfg(target_os = "macos")]
        if super::unix_security::capture(ancestor)?
            .split(|&b| b == b'\n')
            .any(mac_acl_may_mutate)
        {
            return Err("strip journal ancestry grants additional access through an ACL".into());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_publication_parent(source: &Path) -> Result<PathBuf, String> {
    let parent = fs::canonicalize(output_parent_dir(source)).map_err(|e| e.to_string())?;
    validate_journal_ancestry(&parent)
        .map_err(|e| format!("Cannot publish a recoverable vault/sidecar pair: {e}"))?;
    Ok(parent)
}

#[cfg(target_os = "macos")]
fn mac_acl_may_mutate(ace: &[u8]) -> bool {
    let mut fields = ace.rsplit(|&b| b == b':');
    let permissions = fields.next().unwrap_or_default();
    let flags = fields.next().unwrap_or_default();
    let mut flags = flags.split(|&b| b == b',');
    flags.next() == Some(b"allow".as_slice())
        && !flags.any(|flag| flag == b"only_inherit")
        && permissions.split(|&b| b == b',').any(|p| {
            !matches!(
                p,
                b"" | b"list"
                    | b"search"
                    | b"read"
                    | b"execute"
                    | b"readattr"
                    | b"readextattr"
                    | b"readsecurity"
                    | b"synchronize"
            )
        })
}

fn read_journal(trusted: &TrustedJournal<'_>) -> Result<Journal, String> {
    let mut file = trusted.open_input("journal.json")?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 4096 {
        return Err("strip journal exceeds size limit".to_string());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("strip journal exceeds size limit".into());
    }
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid strip journal: {e}"))?;
    if !matches!(journal.version, 1..=4) {
        return Err("unsupported strip journal version".into());
    }
    Ok(journal)
}

fn load(trusted: &TrustedJournal<'_>, source: &Path) -> Result<(Journal, PathBuf), String> {
    let journal = read_journal(trusted)?;
    let recorded = recorded_source(output_parent_dir(source), &journal.source_name)?;
    if native_name(source) != journal.source_name && !same_existing_file(source, &recorded) {
        return Err(
            "strip journal belongs to a different source name; reopen its original path"
                .to_string(),
        );
    }
    Ok((journal, recorded))
}

#[derive(Debug, PartialEq, Eq)]
enum RecoveryOutcome {
    Original,
    Stripped,
}

fn recover_locked(source: &Path, path: &Path, lock: &WriteLock) -> Result<RecoveryOutcome, String> {
    if !lock.covers_namespace(source) {
        return Err("strip source lock namespace changed".to_string());
    }
    let trusted = TrustedJournal::open(path).map_err(|e| conflict(path, &e))?;
    let (journal, recorded) = load(&trusted, source).map_err(|e| conflict(path, &e))?;
    let source = recorded.as_path();
    if !lock.covers_namespace(source) {
        return Err("strip recorded source lock namespace changed".to_string());
    }
    let sidecar = super::ec::default_sidecar_path(source);
    let vault_now = recorded_generation(source, &[journal.old_vault, Some(journal.new_vault)])
        .map_err(|e| conflict(path, &format!("vault unavailable: {e}")))?;
    let sidecar_now =
        recorded_generation(&sidecar, &[journal.old_sidecar, Some(journal.new_sidecar)])
            .map_err(|e| conflict(path, &format!("sidecar unavailable: {e}")))?;
    // Publishing a generation consumes its staged entry. A matching
    // destination while the entry is still present came from another writer.
    // This evidence remains in the journal across recovery attempts.
    for (staged, old, new, current) in [
        ("new-vault", journal.old_vault, journal.new_vault, vault_now),
        (
            "new-sidecar",
            journal.old_sidecar,
            journal.new_sidecar,
            sidecar_now,
        ),
    ] {
        if current == old || current != Some(new) {
            continue;
        }
        match fs::symlink_metadata(path.join(staged)) {
            Ok(_) => {
                return Err(conflict(
                    path,
                    &format!("destination matches unpublished staged content ({staged})"),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(conflict(path, &format!("cannot verify {staged}: {error}"))),
        }
    }
    let original_pair = vault_now == journal.old_vault && sidecar_now == journal.old_sidecar;
    if original_pair
        && path
            .join("rollback-intent")
            .try_exists()
            .map_err(|e| e.to_string())?
    {
        trusted.retire()?;
        return Ok(RecoveryOutcome::Original);
    }
    if original_pair && path.join("new-vault").exists() && path.join("new-sidecar").exists() {
        trusted.retire()?;
        return Ok(RecoveryOutcome::Original);
    }
    if vault_now == Some(journal.new_vault) && sidecar_now == Some(journal.new_sidecar) {
        // A crash can occur just after rename and before inheritance restoration.
        trusted.recheck()?;
        restore_published_permissions(source, &sidecar, &journal, path)?;
        trusted.retire()?;
        return Ok(RecoveryOutcome::Stripped);
    }
    if original_pair {
        return Err(conflict(
            path,
            "original bytes match after a replacement; security finalization is ambiguous",
        ));
    }
    if ![journal.old_vault, Some(journal.new_vault)].contains(&vault_now)
        || ![journal.old_sidecar, Some(journal.new_sidecar)].contains(&sidecar_now)
    {
        return Err(conflict(path, "newer or damaged vault or sidecar"));
    }
    // Verify both copies before replacing either original.
    let mut old_vault = trusted
        .backup("old-vault", journal.old_vault)
        .map_err(|e| conflict(path, &format!("vault rollback input: {e}")))?;
    let mut old_sidecar = trusted
        .backup("old-sidecar", journal.old_sidecar)
        .map_err(|e| conflict(path, &format!("sidecar rollback input: {e}")))?;
    trusted.recheck()?;
    let rollback = path.join("rollback-intent");
    if !rollback.try_exists().map_err(|e| e.to_string())? {
        let file = private_options()
            .open(rollback)
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        sync_dir(path)?;
    }
    if vault_now != journal.old_vault {
        restore_original(old_vault.take(), source, journal.old_vault, vault_now)
            .map_err(|e| format!("Restore verified original vault: {e}"))?;
    }
    if sidecar_now != journal.old_sidecar {
        restore_original(
            old_sidecar.take(),
            &sidecar,
            journal.old_sidecar,
            sidecar_now,
        )
        .map_err(|e| format!("Restore verified original sidecar: {e}"))?;
    }
    // Windows can deny moving the containing directory while an untouched
    // rollback input still has an open handle.
    drop((old_vault, old_sidecar));
    #[cfg(test)]
    if let Some(hook) = AFTER_ROLLBACK_RESTORE.with(|h| h.borrow_mut().take()) {
        hook();
    }
    trusted.retire()?;
    Ok(RecoveryOutcome::Original)
}

fn restore_original(
    backup: Option<fs::File>,
    target: &Path,
    original: Option<Generation>,
    current: Option<Generation>,
) -> Result<(), String> {
    if let Some(original) = original {
        return replace_from(
            backup.ok_or("rollback backup unexpectedly absent")?,
            target,
            original,
            current.ok_or("rollback target unexpectedly absent")?,
        );
    }
    // Absence is an original state too. Remove only the exact recorded new
    // generation; preserve any later file as a recovery conflict.
    if recorded_generation(target, &[current])? != current {
        return Err("strip target changed before restoring absence".into());
    }
    if current.is_some() {
        fs::remove_file(target).map_err(|e| e.to_string())?;
        sync_dir(output_parent_dir(target))?;
    }
    Ok(())
}

fn restore_published_permissions(
    source: &Path,
    sidecar: &Path,
    journal: &Journal,
    marker: &Path,
) -> Result<(), String> {
    // Old journals did not durably record the start of security publication.
    // Missing completion markers cannot distinguish an unapplied descriptor
    // from a later operator restriction after application.
    #[cfg(windows)]
    if journal.version < 3 {
        for (staged, done) in [
            ("new-vault", "vault-security-done"),
            ("new-sidecar", "sidecar-security-done"),
        ] {
            if !marker
                .join(staged)
                .try_exists()
                .map_err(|e| e.to_string())?
                && !marker.join(done).try_exists().map_err(|e| e.to_string())?
            {
                return Err(conflict(marker, "legacy security publication is ambiguous"));
            }
        }
    }
    if !marker
        .join("new-vault")
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        finish_security(
            source,
            journal
                .new_vault_permissions
                .as_ref()
                .or(journal.old_vault_permissions.as_ref()),
            marker,
            "vault-security-done",
            journal.staged_vault_dacl,
        )?;
    }
    if !marker
        .join("new-sidecar")
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        finish_security(
            sidecar,
            journal
                .new_sidecar_permissions
                .as_ref()
                .or(journal.old_sidecar_permissions.as_ref()),
            marker,
            "sidecar-security-done",
            journal.staged_sidecar_dacl,
        )?;
    }
    Ok(())
}

// On Windows, sync intent before applying security and completion afterwards.
// An interrupted application is ambiguous: recovery must retain current security
// and recovery material rather than overwrite a later operator restriction.
fn finish_security(
    path: &Path,
    permissions: Option<&SavedPermissions>,
    journal: &Path,
    marker: &str,
    staged_dacl: Option<[u8; 32]>,
) -> Result<(), String> {
    let done = journal.join(marker);
    if done.try_exists().map_err(|e| e.to_string())? {
        return Ok(());
    }
    // Unix publication has no security write: modes were applied while staged.
    // A start marker left by an earlier version cannot make it ambiguous.
    #[cfg(windows)]
    {
        let started = journal.join(format!("{marker}-started"));
        if started.try_exists().map_err(|e| e.to_string())? {
            return Err(conflict(
                journal,
                "security publication was interrupted; current permissions retained",
            ));
        }
        if staged_dacl != Some(dacl_digest(path)?) {
            return Err(conflict(
                journal,
                "published Windows DACL differs from the recorded stage or the journal lacks its descriptor",
            ));
        }
        match private_options().open(&started) {
            Ok(file) => file.sync_all().map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(conflict(
                    journal,
                    "security publication was interrupted; current permissions retained",
                ));
            }
            Err(e) => return Err(e.to_string()),
        }
        sync_dir(journal)?;
    }
    #[cfg(not(windows))]
    let _ = staged_dacl;
    publish_security(path, permissions)?;
    #[cfg(test)]
    if marker == "vault-security-done" {
        if let Some(hook) = AFTER_VAULT_SECURITY_APPLY.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    #[cfg(test)]
    if marker == "sidecar-security-done" {
        if let Some(hook) = AFTER_SIDECAR_SECURITY_APPLY.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
    let file = private_options().open(&done).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    sync_dir(journal)
}

fn publish_security(path: &Path, permissions: Option<&SavedPermissions>) -> Result<(), String> {
    #[cfg(windows)]
    if permissions.is_none() {
        return Err(
            "Recovery journal lacks the intended Windows DACL; manual recovery required".into(),
        );
    }
    if let Some(permissions) = permissions {
        permissions.published(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn dacl_digest(path: &Path) -> Result<[u8; 32], String> {
    let descriptor = super::windows_security::capture(path)?;
    Ok(*blake3::hash(descriptor.as_bytes()).as_bytes())
}

/// Readers stay lock-free unless a pending strip needs recovery. Writers use
/// recover_under_guard after acquiring their source guard, including after waits.
pub(crate) fn recover_if_pending(source: &Path) -> Result<(), String> {
    let source = crate::lock::anchored(source).map_err(|e| e.to_string())?;
    // Readers may use a leaf link or a Windows short name. Find the original
    // transaction there; writes still reject leaf links before recovery.
    let source = if std::fs::symlink_metadata(&source).is_ok_and(|m| m.file_type().is_symlink())
        || cfg!(windows) && source.exists()
    {
        std::fs::canonicalize(&source).map_err(|e| e.to_string())?
    } else {
        source
    };
    let path = journal_path(&source);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    #[cfg(test)]
    if let Some(hook) = BEFORE_PENDING_JOURNAL_READ.with(|h| h.borrow_mut().take()) {
        hook();
    }
    let journal = match TrustedJournal::open(&path).and_then(|trusted| read_journal(&trusted)) {
        Ok(journal) => journal,
        Err(_) => {
            // Publication may have retired the directory after our optimistic
            // existence check. Recheck under the source guard; persistent bad
            // journals still fail there rather than being silently ignored.
            let lock = crate::lock::acquire_without_recovery(&source).map_err(|e| e.to_string())?;
            return recover_under_guard(&lock);
        }
    };
    let recorded = recorded_source(output_parent_dir(&source), &journal.source_name)?;
    if native_name(&source) != journal.source_name && !same_existing_file(&source, &recorded) {
        // Distinct case-sensitive files can share a folded lock/journal key.
        // A read must not recover or wait for the other file's transaction.
        return Ok(());
    }
    let lock = crate::lock::acquire_without_recovery(&source).map_err(|e| e.to_string())?;
    recover_under_guard(&lock)
}

pub(crate) fn recover_under_guard(lock: &WriteLock) -> Result<(), String> {
    let source = lock.source_path();
    let path = journal_path(source);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    if !lock.covers_namespace(source) {
        return Err("pending strip recovery requires a real source lock".to_string());
    }
    let sidecar = super::ec::default_sidecar_path(source);
    let _sidecar = crate::lock::acquire(&sidecar).map_err(|e| e.to_string())?;
    recover_locked(source, &path, lock).map(|_| ())
}

/// The caller has prepared old/new vault and sidecar files in a private temp
/// directory under the source parent, while holding both namespace guards.
pub(super) fn publish(source: &Path, prepared: PrivateDir, lock: &WriteLock) -> Result<(), String> {
    #[cfg(unix)]
    let trusted_parent = validate_publication_parent(source)?;
    let sidecar = super::ec::default_sidecar_path(source);
    let journal = Journal {
        version: 4,
        source_name: native_name(source),
        staged_vault_dacl: None,
        staged_sidecar_dacl: None,
        new_vault_permissions: SavedPermissions::new_destination(source)?,
        new_sidecar_permissions: SavedPermissions::new_destination(&sidecar)?,
        old_vault: generation_if_present(&prepared.path().join("old-vault"))?,
        new_vault: generation(&prepared.path().join("new-vault"))?,
        old_sidecar: generation_if_present(&prepared.path().join("old-sidecar"))?,
        new_sidecar: generation(&prepared.path().join("new-sidecar"))?,
        old_vault_permissions: SavedPermissions::capture_if_present(source)?,
        old_sidecar_permissions: SavedPermissions::capture_if_present(&sidecar)?,
    };
    if !lock.covers_namespace(source)
        || generation_if_present(source)? != journal.old_vault
        || generation_if_present(&sidecar)? != journal.old_sidecar
    {
        return Err(
            "vault or sidecar changed while preparing strip; originals left unchanged".to_string(),
        );
    }
    // Both new files stay behind the private directory while their original
    // DACLs/modes are installed. Refuse before journal publication on failure.
    if let Some(p) = &journal.old_vault_permissions {
        p.apply(&prepared.path().join("new-vault"))?;
    }
    if let Some(p) = &journal.old_sidecar_permissions {
        p.apply(&prepared.path().join("new-sidecar"))?;
    }
    #[cfg(windows)]
    let journal = Journal {
        staged_vault_dacl: Some(dacl_digest(&prepared.path().join("new-vault"))?),
        staged_sidecar_dacl: Some(dacl_digest(&prepared.path().join("new-sidecar"))?),
        ..journal
    };
    let encoded = serde_json::to_vec(&journal).map_err(|e| e.to_string())?;
    if encoded.len() > 4096 {
        return Err("strip journal exceeds size limit; originals left unchanged".to_string());
    }
    let mut file = private_options()
        .open(prepared.path().join("journal.json"))
        .map_err(|e| e.to_string())?;
    file.write_all(&encoded).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    sync_dir(prepared.path())?;
    let path = journal_path(source);
    if path.exists() {
        return Err("pending strip transaction already exists; reopen vault first".to_string());
    }
    #[cfg(test)]
    if let Some(hook) = BEFORE_STRIP_JOURNAL.with(|h| h.borrow_mut().take()) {
        hook();
    }
    #[cfg(unix)]
    validate_journal_ancestry(&trusted_parent)
        .map_err(|e| format!("Cannot publish a recoverable vault/sidecar pair: {e}"))?;
    fs::rename(prepared.path(), &path).map_err(|e| format!("publish strip journal: {e}"))?;
    sync_dir(output_parent_dir(source))?;
    #[cfg(test)]
    if let Some(hook) = AFTER_STRIP_JOURNAL.with(|h| h.borrow_mut().take()) {
        hook();
    }
    let result = (|| {
        if SavedPermissions::capture_if_present(source)? != journal.old_vault_permissions {
            return Err("Original vault security changed before publication".into());
        }
        if recorded_generation(source, &[journal.old_vault])? != journal.old_vault {
            return Err("Original vault content changed before publication".into());
        }
        fs::rename(path.join("new-vault"), source).map_err(|e| e.to_string())?;
        finish_security(
            source,
            journal
                .new_vault_permissions
                .as_ref()
                .or(journal.old_vault_permissions.as_ref()),
            &path,
            "vault-security-done",
            journal.staged_vault_dacl,
        )?;
        sync_dir(output_parent_dir(source))?;
        #[cfg(test)]
        if let Some(hook) = AFTER_STRIP_VAULT.with(|h| h.borrow_mut().take()) {
            hook();
        }
        if SavedPermissions::capture_if_present(&sidecar)? != journal.old_sidecar_permissions {
            return Err("Original sidecar security changed before publication".into());
        }
        if recorded_generation(&sidecar, &[journal.old_sidecar])? != journal.old_sidecar {
            return Err("Original sidecar content changed before publication".into());
        }
        fs::rename(path.join("new-sidecar"), &sidecar).map_err(|e| e.to_string())?;
        #[cfg(test)]
        if let Some(hook) = AFTER_STRIP_SECOND_RENAME.with(|h| h.borrow_mut().take()) {
            hook();
        }
        finish_security(
            &sidecar,
            journal
                .new_sidecar_permissions
                .as_ref()
                .or(journal.old_sidecar_permissions.as_ref()),
            &path,
            "sidecar-security-done",
            journal.staged_sidecar_dacl,
        )?;
        #[cfg(test)]
        if FAIL_FINAL_SYNC.with(|fail| fail.replace(false)) {
            return Err("injected final directory sync failure".to_string());
        }
        sync_dir(output_parent_dir(source))?;
        #[cfg(test)]
        if let Some(hook) = AFTER_STRIP_SIDECAR.with(|h| h.borrow_mut().take()) {
            hook();
        }
        Ok::<_, String>(())
    })();
    if let Err(error) = result {
        return Err(match recover_locked(source, &path, lock) {
            Ok(RecoveryOutcome::Original) => format!("Could not publish stripped vault and sidecar ({error}); original vault restored"),
            Ok(RecoveryOutcome::Stripped) => format!("Strip publication completed, but final durability sync failed ({error}); stripped vault and refreshed sidecar remain, journal retired"),
            Err(restore) => format!("Could not publish strip ({error}); recovery pending ({restore}); active journal, if still present: {}; preserve any relocated recovery material named above", path.display()),
        });
    }
    cleanup(&path)
}

#[cfg(test)]
thread_local! {
    pub(super) static AFTER_ROLLBACK_RESTORE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_VAULT_SECURITY_APPLY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static BEFORE_PENDING_JOURNAL_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_SIDECAR_SECURITY_APPLY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static FAIL_CLEANUP_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static FAIL_FINAL_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static BEFORE_STRIP_JOURNAL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_STRIP_JOURNAL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_STRIP_VAULT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_STRIP_SECOND_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_STRIP_SIDECAR: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn round9_macos_private_directory_clears_inherited_acl_before_copy() {
        let dir = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("/bin/chmod")
            .args([
                "+a",
                "everyone allow readsecurity,file_inherit,directory_inherit,only_inherit"
            ])
            .arg(dir.path())
            .status()
            .unwrap()
            .success());
        let ordinary = tempfile::tempdir_in(dir.path()).unwrap();
        assert!(!super::super::unix_security::capture(ordinary.path())
            .unwrap()
            .is_empty());
        let original = dir.path().join("plaintext");
        fs::write(&original, b"plaintext before strip").unwrap();
        super::super::unix_security::apply(&original, &[]).unwrap();
        let prepared = private_dir(dir.path(), ".aerostrip-prepare-").unwrap();
        let backup = prepared.path().join("old-vault");
        assert!(super::super::unix_security::capture(prepared.path())
            .unwrap()
            .is_empty());
        copy_file(&original, &backup).unwrap();
        assert!(super::super::unix_security::capture(&backup)
            .unwrap()
            .is_empty());
        assert_eq!(fs::read(&backup).unwrap(), b"plaintext before strip");
        fs::write(&original, b"new plaintext").unwrap();
        let inspected = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = inspected.clone();
        INSPECT_ROLLBACK_STAGE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |staged| {
                let acl = super::super::unix_security::capture;
                assert!(acl(staged.parent().unwrap()).unwrap().is_empty());
                assert!(acl(staged).unwrap().is_empty());
                assert_eq!(fs::read(staged).unwrap(), b"plaintext before strip");
                observed.set(true);
            }));
        });
        replace_from(
            crate::source::open_regular_no_follow(&backup).unwrap(),
            &original,
            generation(&backup).unwrap(),
            generation(&original).unwrap(),
        )
        .unwrap();
        assert!(inspected.get());
        assert_eq!(fs::read(original).unwrap(), b"plaintext before strip");
    }
    #[cfg(unix)]
    #[test]
    fn recovery_rejects_unrecorded_sparse_length_before_hashing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sidecar");
        fs::write(&path, b"recorded sidecar").unwrap();
        let original = generation(&path).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(64 * 1024 * 1024 * 1024)
            .unwrap();
        let error = recorded_generation(&path, &[Some(original)]).unwrap_err();
        assert!(error.contains("unexpected recovery length"), "{error}");
    }

    #[test]
    fn strip_publication_keeps_byte_only_edits_at_both_rename_boundaries() {
        for (edit_before_vault, matches_stage) in
            [(true, false), (false, false), (true, true), (false, true)]
        {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source.aerozip");
            let sidecar = super::super::ec::default_sidecar_path(&source);
            fs::write(&source, b"vault old").unwrap();
            fs::write(&sidecar, b"sidecar old").unwrap();
            let prepared = private_dir(dir.path(), ".prepared-").unwrap();
            copy_file(&source, &prepared.path().join("old-vault")).unwrap();
            copy_file(&sidecar, &prepared.path().join("old-sidecar")).unwrap();
            fs::write(prepared.path().join("new-vault"), b"vault new").unwrap();
            fs::write(prepared.path().join("new-sidecar"), b"sidecar new").unwrap();
            let target = if edit_before_vault { &source } else { &sidecar };
            let edited: &[u8] = match (edit_before_vault, matches_stage) {
                (true, false) => b"vault ext",
                (false, false) => b"sidecar ext",
                (true, true) => b"vault new",
                (false, true) => b"sidecar new",
            };
            let path = target.clone();
            let slot = if edit_before_vault {
                &AFTER_STRIP_JOURNAL
            } else {
                &AFTER_STRIP_VAULT
            };
            slot.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || fs::write(path, edited).unwrap()))
            });
            let lock = crate::lock::acquire_without_recovery(&source).unwrap();
            let error = publish(&source, prepared, &lock).unwrap_err();
            assert!(
                error.contains("content changed before publication"),
                "{error}"
            );
            assert!(journal_path(&source).is_dir());
            assert_eq!(fs::read(target).unwrap(), edited);
            let staged = if edit_before_vault {
                "new-vault"
            } else {
                "new-sidecar"
            };
            assert!(journal_path(&source).join(staged).is_file());
            let until_retry = (fs::read(&source).unwrap(), fs::read(&sidecar).unwrap());
            for _ in 0..2 {
                let error = recover_under_guard(&lock).unwrap_err();
                if matches_stage {
                    assert!(
                        error.contains("matches unpublished staged content"),
                        "{error}"
                    );
                }
                assert_eq!(fs::read(&source).unwrap(), until_retry.0);
                assert_eq!(fs::read(&sidecar).unwrap(), until_retry.1);
                assert!(journal_path(&source).join(staged).is_file());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_ancestry_refuses_pair_before_publication_and_reopens_original() {
        use super::super::{
            ec::RecoveryPlacement,
            vault::{CreateOptionsV3, VaultV3},
        };
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        let source = shared.join("source.aerovault");
        let sidecar = super::super::ec::default_sidecar_path(&source);
        let password = "existing-password-123";
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&source, password),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        let old_vault = fs::read(&source).unwrap();
        let old_sidecar = fs::read(&sidecar).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();

        let mut opened = VaultV3::open(&source, password).unwrap();
        let error = VaultV3::change_password(&mut opened, "different-password-123").unwrap_err();
        assert!(
            error.contains("Cannot publish a recoverable vault/sidecar pair"),
            "{error}"
        );
        drop(opened);
        assert!(!journal_path(&source).exists());
        assert_eq!(fs::read(&source).unwrap(), old_vault);
        assert_eq!(fs::read(&sidecar).unwrap(), old_sidecar);
        assert!(VaultV3::open(&source, password).is_ok());
        assert!(VaultV3::open(&source, "different-password-123").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pair_creation_makes_missing_parents_private() {
        use super::super::{
            ec::RecoveryPlacement,
            vault::{CreateOptionsV3, VaultV3},
        };
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let parent = dir.path().join("new");
        let nested = parent.join("nested");
        let source = nested.join("source.aerovault");
        let password = "new-directories-test-password";
        VaultV3::create_with_error_correction(
            &CreateOptionsV3::new(&source, password),
            RecoveryPlacement::Detached,
            20,
        )
        .unwrap();
        for created in [parent, nested] {
            assert_eq!(created.metadata().unwrap().permissions().mode() & 0o077, 0);
        }
        assert!(super::super::ec::default_sidecar_path(&source).is_file());
        assert!(VaultV3::open(&source, password).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejected_pair_creation_leaves_no_locks_or_recovery_files() {
        use super::super::{
            ec::RecoveryPlacement,
            vault::{CreateOptionsV3, VaultV3},
        };
        use std::os::unix::fs::PermissionsExt;

        for mode in [0o775, 0o777] {
            let dir = tempfile::tempdir().unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
            let source = dir.path().join("shared.aerovault");
            let error = VaultV3::create_with_error_correction(
                &CreateOptionsV3::new(&source, "shared-group-test-password"),
                RecoveryPlacement::Detached,
                20,
            )
            .unwrap_err();
            assert!(error.contains("ancestry permits replacement"), "{error}");
            assert!(dir.path().read_dir().unwrap().next().is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn automatic_recovery_rejects_untrusted_shared_journal_without_writing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        let source = shared.join("source.aerozip");
        let sidecar = super::super::ec::default_sidecar_path(&source);
        fs::write(&source, b"source unchanged").unwrap();
        fs::write(&sidecar, b"sidecar unchanged").unwrap();
        let journal = journal_path(&source);
        fs::create_dir(&journal).unwrap();
        fs::write(journal.join("journal.json"), b"untrusted origin").unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o777)).unwrap();
        let error = recover_if_pending(&source).unwrap_err();
        assert!(
            error.contains("trusted ownership and private access"),
            "{error}"
        );
        assert_eq!(fs::read(&source).unwrap(), b"source unchanged");
        assert_eq!(fs::read(&sidecar).unwrap(), b"sidecar unchanged");
        assert!(journal.is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn automatic_recovery_rejects_foreign_owner_fixture() {
        use std::os::unix::fs::MetadataExt;
        let Some(shared) = std::env::var_os("AEROVAULT_TEST_FOREIGN_JOURNAL_ROOT") else {
            return;
        };
        let shared = PathBuf::from(shared);
        let incoming = shared.join("incoming");
        assert_ne!(incoming.metadata().unwrap().uid(), unsafe {
            libc::geteuid()
        });
        let source = shared.join("source.aerozip");
        let sidecar = super::super::ec::default_sidecar_path(&source);
        fs::write(&source, b"trusted vault bytes").unwrap();
        fs::write(&sidecar, b"trusted sidecar bytes").unwrap();
        let journal = journal_path(&source);
        fs::rename(incoming, &journal).unwrap();
        let error = recover_if_pending(&source).unwrap_err();
        assert!(
            error.contains("trusted ownership and private access"),
            "{error}"
        );
        assert_eq!(fs::read(&source).unwrap(), b"trusted vault bytes");
        assert_eq!(fs::read(&sidecar).unwrap(), b"trusted sidecar bytes");
        assert!(journal.is_dir());
        eprintln!("Foreign journal owner refused with both destination generations unchanged");
    }

    #[test]
    fn journal_source_names_are_native_and_cannot_escape_the_parent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("界.aerovault");
        assert_eq!(
            recorded_source(dir.path(), &native_name(&path)).unwrap(),
            path
        );
        assert!(recorded_source(dir.path(), &[]).is_err());
        for name in ["../escape", "/escape", ".", ".."] {
            // Encode the complete hostile input, not Path::file_name().
            #[cfg(unix)]
            let encoded = name.as_bytes().to_vec();
            #[cfg(windows)]
            let encoded: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            assert!(recorded_source(dir.path(), &encoded).is_err(), "{name}");
        }
    }
    #[cfg(unix)]
    #[test]
    fn round7f_unix_incomplete_security_marker_does_not_change_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("published");
        fs::write(&path, b"published content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let original = SavedPermissions::capture(&path).unwrap();
        let journal = private_dir(dir.path(), ".aerostrip-test-").unwrap();
        fs::write(journal.path().join("sidecar-security-done-started"), b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        finish_security(
            &path,
            Some(&original),
            journal.path(),
            "sidecar-security-done",
            None,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&path).unwrap(), b"published content");
        assert!(journal.path().join("sidecar-security-done").is_file());
        assert!(journal
            .path()
            .join("sidecar-security-done-started")
            .exists());
        finish_security(
            &path,
            Some(&original),
            journal.path(),
            "sidecar-security-done",
            None,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn equal_normalized_names_do_not_prove_file_identity() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("one.aerovault");
        let b = dir.path().join("two.aerovault");
        fs::write(&a, b"identical bytes").unwrap();
        fs::write(&b, b"identical bytes").unwrap();
        assert!(!same_existing_file(&a, &b));
        assert!(same_existing_file(&a, &a));
    }
    #[cfg(unix)]
    #[test]
    fn review_strip_preparation_is_private_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let prepared = private_dir(root.path(), ".aerostrip-prepare-").unwrap();
        assert_eq!(
            fs::metadata(prepared.path()).unwrap().permissions().mode() & 0o077,
            0
        );
        let original = root.path().join("private.aerozip");
        fs::write(&original, b"private plaintext").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        let backup = prepared.path().join("old-vault");
        copy_file(&original, &backup).unwrap();
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(fs::read(backup).unwrap(), b"private plaintext");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn round8_access_acl_survives_inherited_grants_publication_and_rollback() {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        fn set(path: &Path, default: bool, uid: u32, rights: u16) {
            let mut bytes = 2u32.to_le_bytes().to_vec();
            for (tag, perm, id) in [
                (1u16, 7u16, u32::MAX),
                (2, rights, uid),
                (4, 4, u32::MAX),
                (16, 4, u32::MAX),
                (32, 0, u32::MAX),
            ] {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&perm.to_le_bytes());
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            let attr = if default {
                c"system.posix_acl_default"
            } else {
                c"system.posix_acl_access"
            };
            assert_eq!(
                unsafe {
                    libc::setxattr(
                        path.as_ptr(),
                        attr.as_ptr(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        0,
                    )
                },
                0,
                "{}",
                std::io::Error::last_os_error()
            );
        }
        fn named_read(path: &Path, uid: u32) -> u16 {
            let acl = super::super::unix_security::capture(path).unwrap();
            if acl == [0] {
                return 0;
            }
            let mut mask = 7;
            let mut named = 0;
            for x in acl[5..].as_chunks::<8>().0 {
                let tag = u16::from_le_bytes(x[..2].try_into().unwrap());
                let perm = u16::from_le_bytes(x[2..4].try_into().unwrap());
                let id = u32::from_le_bytes(x[4..8].try_into().unwrap());
                if tag == 16 {
                    mask = perm;
                }
                if tag == 2 && id == uid {
                    named = perm;
                }
            }
            named & mask & 4
        }
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o711)).unwrap();
        // Use a mapped identity even in the isolated user namespace. Native CI
        // also runs the same named-entry and mask checks without that boundary.
        let uid = unsafe { libc::getuid() };
        let source = dir.path().join("original");
        fs::write(&source, b"original plaintext").unwrap();
        set(&source, false, uid, 0);
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();
        let saved = SavedPermissions::capture(&source).unwrap();
        assert_eq!(named_read(&source, uid), 0);
        set(dir.path(), true, uid, 4);
        let stage = private_dir(dir.path(), ".aerostrip-acl-").unwrap();
        let replacement = stage.path().join("replacement");
        fs::write(&replacement, b"replacement plaintext").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            named_read(&replacement, uid),
            4,
            "fixture inherited grant must be enabled by mode restoration alone"
        );
        saved.apply(&replacement).unwrap();
        assert_eq!(named_read(&replacement, uid), 0);
        assert_eq!(
            super::super::unix_security::capture(&replacement).unwrap(),
            saved.unix_acl.clone().unwrap()
        );
        fs::rename(&replacement, &source).unwrap();
        assert_eq!(named_read(&source, uid), 0);
        let backup = stage.path().join("old");
        fs::write(&backup, b"original plaintext").unwrap();
        replace_from(
            crate::source::open_regular_no_follow(&backup).unwrap(),
            &source,
            generation(&backup).unwrap(),
            generation(&source).unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"original plaintext");
        assert_eq!(named_read(&source, uid), 0);
        let ordinary = dir.path().join("mode-only");
        fs::write(&ordinary, b"ordinary").unwrap();
        super::super::unix_security::apply(&ordinary, &[0]).unwrap();
        fs::set_permissions(&ordinary, fs::Permissions::from_mode(0o640)).unwrap();
        let mode_only = SavedPermissions::capture(&ordinary).unwrap();
        let next = stage.path().join("mode-stage");
        fs::write(&next, b"ordinary").unwrap();
        mode_only.apply(&next).unwrap();
        assert_eq!(super::super::unix_security::capture(&next).unwrap(), [0]);
    }
}
