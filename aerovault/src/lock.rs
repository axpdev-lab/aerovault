// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Cross-process write lock for a vault.
//!
//! Every write replaces the vault (or its `.aerocorrect` sidecar) by rename,
//! so a lock on the vault file itself would be lost with the file it locks.
//! Writers instead take an exclusive OS lock (`flock` / `LockFileEx`) on a
//! separate, stable `<vault>.aerolock` next to the vault, and hold it from the
//! moment they read the state they will write (for a v3 handle opened
//! earlier, from the check that the file is still the one it read) until the
//! rename is done. Readers normally take no lock; pending strip recovery does. Tools that rewrite any file or
//! write its `.aerocorrect` (`correct repair`, `correct gen`) read it without
//! the lock, then take the lock of that file, vault or not, for their write,
//! and write only if it still holds the bytes they read
//! (`error_correction::sync::write_if_unchanged`), so a vault created or saved
//! at that path meanwhile is not lost.
//!
//! The OS drops the lock when the holder exits or crashes, so there is no
//! stale-lock cleanup. The `<vault>.aerolock` file itself is left in place on
//! purpose: deleting or replacing it would let two writers lock two different
//! files. So no write of this crate replaces a file whose name ends with
//! `.aerolock` ([`refuse_lock_file_name`], at every commit point), and on
//! Windows the lock file is opened without delete sharing, so no other program
//! can replace or delete it while a writer holds or waits for it.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a writer waits for another writer before giving up.
const WAIT: Duration = Duration::from_secs(30);

const POLL: Duration = Duration::from_millis(10);

/// The wait a test sets with [`set_short_wait_for_this_thread`].
#[cfg(test)]
pub(crate) const TEST_SHORT_WAIT: Duration = Duration::from_millis(300);

#[cfg(test)]
thread_local! {
    static TEST_WAIT: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Test seam: a test that expects a refusal makes this thread give up after
/// [`TEST_SHORT_WAIT`] instead of the full wait. Every other test keeps the
/// full wait, so slow work inside another holder's lock cannot time it out.
#[cfg(test)]
pub(crate) fn set_short_wait_for_this_thread() {
    TEST_WAIT.with(|w| w.set(Some(TEST_SHORT_WAIT)));
}

#[cfg(test)]
thread_local! {
    static TRACE: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Test seam: record that `event` happened on this thread ("lock", "derive",
/// "temp", "generation", "decode"), so a test can check the order of steps.
#[cfg(test)]
pub(crate) fn trace(event: &'static str) {
    TRACE.with(|t| t.borrow_mut().push(event));
}

/// Test seam: the events recorded on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_trace() -> Vec<&'static str> {
    TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

fn wait() -> Duration {
    #[cfg(test)]
    if let Some(wait) = TEST_WAIT.with(|w| w.get()) {
        return wait;
    }
    WAIT
}

/// Held while a write is in progress; dropping it releases the lock.
#[derive(Debug)]
pub(crate) struct WriteLock {
    /// `None` only for a read-only export from media with no creatable lock.
    _file: Option<File>,
    path: PathBuf,
    source: PathBuf,
}

#[cfg(all(test, unix))]
pub(crate) fn test_unlocked_export_guard() -> WriteLock {
    WriteLock {
        _file: None,
        path: PathBuf::new(),
        source: PathBuf::new(),
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static ON_LOCK_CONTENTION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// The suffix of every lock file, reserved: no write replaces such a file.
const LOCK_SUFFIX: &str = ".aerolock";

/// Normalize the basename and append the lock suffix, using a bounded digest when it
/// would exceed 255 native units (bytes on Unix, UTF-16 units on Windows).
/// Case and canonically equivalent Unicode variants share the digest.
pub(crate) fn lock_path(vault: &Path) -> PathBuf {
    use unicode_casefold::UnicodeCaseFold;
    use unicode_normalization::UnicodeNormalization;
    let basename = vault.file_name().unwrap_or_default();
    // Normalize before deciding whether to hash too: equivalent Unicode names
    // can cross the suffix-length boundary in their original spellings.
    let normalized = basename.to_str().map(|name| {
        name.chars()
            .filter(|&c| !ignored_in_names(c))
            .collect::<String>()
            .trim_end_matches(['.', ' '])
            .nfc()
            // Pinned Unicode tables make the digest independent of the Rust
            // toolchain's changing Unicode/case tables (MSRV and stable agree).
            .case_fold()
            .nfc()
            .collect::<String>()
    });
    let normalized_name = normalized
        .as_deref()
        .map(std::ffi::OsStr::new)
        .unwrap_or(basename);
    if name_units(normalized_name) + LOCK_SUFFIX.len() > 255 {
        let digest = blake3::hash(normalized_name.as_encoded_bytes());
        return vault.with_file_name(format!(".{}{LOCK_SUFFIX}", digest.to_hex()));
    }
    // Use the same spelling on both sides of the length boundary. Otherwise
    // an ignored-character alias could switch a short original spelling to
    // a folded spelling that the filesystem does not itself consider equal.
    let mut name = normalized_name.to_os_string();
    name.push(LOCK_SUFFIX);
    vault.with_file_name(name)
}

/// Filename limits count native units, not Unicode scalar values.
fn name_units(name: &std::ffi::OsStr) -> usize {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        name.encode_wide().count()
    }
    #[cfg(not(windows))]
    {
        name.as_encoded_bytes().len()
    }
}

/// Refuse a write that would replace `dest` when its name is the name of a
/// lock file: replacing the lock file of a vault while a writer holds it would
/// let a second writer lock the new file and save at the same time. On Windows
/// an existing `dest` is also checked under its real name, so a short (8.3)
/// name of a lock file is refused too.
pub(crate) fn refuse_lock_file_name(dest: &Path) -> io::Result<()> {
    #[cfg(windows)]
    let real_name = std::fs::canonicalize(dest)
        .ok()
        .and_then(|real| real.file_name().map(|n| n.to_os_string()));
    #[cfg(not(windows))]
    let real_name: Option<std::ffi::OsString> = None;
    let names_lock_file = [dest.file_name(), real_name.as_deref()]
        .into_iter()
        .flatten()
        .any(|name| is_lock_file_name(&name.to_string_lossy()));
    if names_lock_file {
        return Err(io::Error::other(format!(
            "{}: names a vault lock file (*{LOCK_SUFFIX}); it is never written over",
            dest.display()
        )));
    }
    Ok(())
}

/// Refuse to create the directory `dir` when its name is a lock file name: a
/// directory at a vault's lock path blocks every write of that vault. Used by
/// extraction, whose directory names come from the vault.
pub(crate) fn refuse_lock_named_dir(dir: &Path) -> io::Result<()> {
    if is_lock_file_name(&dir.file_name().unwrap_or_default().to_string_lossy()) {
        return Err(io::Error::other(format!(
            "{}: a directory cannot take a vault lock file name (*{LOCK_SUFFIX})",
            dir.display()
        )));
    }
    Ok(())
}

/// True if `name` ends with the lock suffix as a file system that ignores
/// case (Windows, macOS), trailing dots and spaces (Windows) or the
/// characters HFS+ ignores in names would see it, so no other spelling of a
/// lock file name gets through. Lowercasing with Unicode rules also maps the
/// Kelvin sign (U+212A), which macOS treats as `K`, to `k`.
pub(crate) fn is_lock_file_name(name: &str) -> bool {
    let visible: String = name.chars().filter(|&c| !ignored_in_names(c)).collect();
    visible
        .trim_end_matches(['.', ' '])
        .to_lowercase()
        .ends_with(LOCK_SUFFIX)
}

/// The characters HFS+ ignores in file names (and U+200B, zero width space).
fn ignored_in_names(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{206A}'..='\u{206F}' | '\u{FEFF}')
}

/// The path whose name the lock file takes. On Unix, the vault path itself. On
/// Windows one file answers to several names: trailing dots and spaces are
/// dropped and a short (8.3) name stands for the long one (case needs nothing:
/// the lock file names differ only in case, so they are one file). So an
/// existing vault takes its lock name from its real name, and a path that does
/// not exist yet and ends in a dot or a space is refused: the file it would
/// create has another name. When the real name cannot be read (some network
/// or RAM-disk drivers do not report it), the given name is used without its
/// trailing dots and spaces (a short name then still locks its own file).
#[cfg(windows)]
fn windows_name_query(vault: &Path) -> io::Result<PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let mut leaf: Vec<u16> = vault
        .file_name()
        .unwrap_or_default()
        .encode_wide()
        .collect();
    while leaf
        .last()
        .is_some_and(|c| *c == u16::from(b'.') || *c == u16::from(b' '))
    {
        leaf.pop();
    }
    if leaf.is_empty() {
        return Err(io::Error::other(
            "file name cannot consist only of dots or spaces",
        ));
    }
    Ok(vault.with_file_name(std::ffi::OsString::from_wide(&leaf)))
}

#[cfg(windows)]
fn lock_name_source(vault: &Path) -> io::Result<PathBuf> {
    let query = windows_name_query(vault)?;
    match std::fs::canonicalize(&query) {
        Ok(real) => Ok(match real.file_name() {
            Some(name) => vault.with_file_name(name),
            None => vault.to_path_buf(),
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let name = vault.file_name().unwrap_or_default().to_string_lossy();
            if name.ends_with(['.', ' ']) {
                return Err(io::Error::other(format!(
                    "{}: a file name cannot end with a dot or a space on Windows",
                    vault.display()
                )));
            }
            Ok(vault.to_path_buf())
        }
        Err(_) => {
            let name = vault.file_name().unwrap_or_default().to_string_lossy();
            let trimmed = name.trim_end_matches(['.', ' ']);
            Ok(if trimmed.is_empty() {
                vault.to_path_buf()
            } else {
                vault.with_file_name(trimmed)
            })
        }
    }
}

#[cfg(not(windows))]
fn lock_name_source(vault: &Path) -> io::Result<PathBuf> {
    Ok(vault.to_path_buf())
}

/// Resolve the actual namespace leaf, retaining a symbolic link itself.
fn namespace_name_source(vault: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    let query = windows_name_query(vault)?;
    #[cfg(windows)]
    if std::fs::symlink_metadata(&query).is_ok_and(|m| m.file_type().is_symlink()) {
        use std::os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle};
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetFinalPathNameByHandleW(
                handle: *mut std::ffi::c_void,
                path: *mut u16,
                size: u32,
                flags: u32,
            ) -> u32;
        }
        // OPEN_REPARSE_POINT returns the link object. Normalized names from
        // that handle resolve short aliases without resolving the link target.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000 | 0x0200_0000)
            .open(&query)?;
        let mut name = vec![0u16; 32768];
        // SAFETY: file owns a live handle; name is writable for the supplied
        // length. The API writes UTF-16 units and returns their initialized count.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                name.as_mut_ptr(),
                name.len() as u32,
                0,
            )
        };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize >= name.len() {
            return Err(io::Error::other(
                "destination namespace path exceeds Windows limit",
            ));
        }
        name.truncate(len as usize);
        let actual = PathBuf::from(std::ffi::OsString::from_wide(&name));
        return actual
            .file_name()
            .map(|leaf| vault.with_file_name(leaf))
            .ok_or_else(|| io::Error::other("destination namespace has no basename"));
    }
    lock_name_source(vault)
}

/// Take the write lock of `vault`, waiting up to 30 seconds for another
/// writer. Errors say why: the lock file could not be created or opened,
/// the lock could not be taken, or another writer kept it too long.
///
/// A replacing write requires a real lock even when directory permissions
/// currently forbid replacement: permissions can change before the rename.
/// Only [`acquire_for_export`] permits an unlocked read of read-only media.
///
/// A `vault` path that is itself a symbolic link is refused: a writer going
/// through the link and one using its target would lock two different files,
/// and the rename would replace the link with a regular file, leaving two
/// diverging copies. So is a `vault` path that names a lock file
/// ([`refuse_lock_file_name`]) and, on Windows, a new path ending in a dot or
/// a space ([`lock_name_source`]). On Windows a lock file that another
/// program holds open with delete access is waited for like a held lock.
pub(crate) fn acquire(vault: &Path) -> io::Result<WriteLock> {
    recover_acquired(acquire_without_recovery(vault)?)
}

pub(crate) fn acquire_without_recovery(vault: &Path) -> io::Result<WriteLock> {
    acquire_with_policy(vault, false, false)
}

fn recover_acquired(lock: WriteLock) -> io::Result<WriteLock> {
    // A strip can publish its journal while this writer waits. Recovery must
    // inspect it under the guard we just acquired, never reacquire that guard.
    crate::v3::strip_transaction::recover_under_guard(&lock).map_err(io::Error::other)?;
    Ok(lock)
}

/// A read-only export may lack a source lock on read-only media. A pending
/// strip still requires a real guard and writable media to recover safely.
pub(crate) fn acquire_for_export(vault: &Path) -> io::Result<WriteLock> {
    recover_acquired(acquire_with_policy(vault, true, false)?)
}

fn acquire_with_policy(
    vault: &Path,
    allow_unlocked_read: bool,
    replace_leaf_link: bool,
) -> io::Result<WriteLock> {
    refuse_lock_file_name(vault)?;
    let source = anchored(vault)?;
    if !replace_leaf_link
        && std::fs::symlink_metadata(&source).is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err(io::Error::other(format!(
            "{} is a symbolic link: writing through it would replace the link and \
             lock a different file than a writer using its target; use the target path",
            vault.display()
        )));
    }
    let source = namespace_name_source(&source)?;
    let path = lock_path(&source);
    let deadline = Instant::now() + wait();
    let file = loop {
        match open_lock_file(&path) {
            Ok(Some(file)) => break file,
            Ok(None) if allow_unlocked_read => {
                return Ok(WriteLock {
                    _file: None,
                    path,
                    source,
                })
            }
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "cannot create vault lock file {}; refusing an unlocked write",
                        path.display()
                    ),
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(POLL)
            }
            Err(e) => return Err(e),
        }
    };
    loop {
        match file.try_lock() {
            Ok(()) => {
                #[cfg(test)]
                trace("lock");
                return Ok(WriteLock {
                    _file: Some(file),
                    path,
                    source,
                });
            }
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                #[cfg(test)]
                if let Some(hook) = ON_LOCK_CONTENTION.with(|h| h.borrow_mut().take()) {
                    hook();
                }
                std::thread::sleep(POLL);
            }
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "vault is locked by another writer ({}); retry when it has finished",
                        path.display()
                    ),
                ))
            }
            Err(TryLockError::Error(e)) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("lock vault lock file {}: {e}", path.display()),
                ))
            }
        }
    }
}

/// The directory holding `path` (`.` for a bare file name).
fn parent_or_dot(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[derive(PartialEq, Eq)]
enum FileIdentity {
    #[cfg(unix)]
    Inode(u64, u64),
    Path(PathBuf, std::ffi::OsString),
}

/// Refuse `out` when it names a lock file or is `source` itself (the file
/// being read, or the link passed to read it). When `out` is a symbolic link
/// to `source`, the rename replaces the link and not `source`, so only a link
/// that is `source` itself is refused. On Unix an existing `out` is also
/// compared with `source` by device and inode, so a hard link of `source` or
/// another case on a case-insensitive file system is refused too (on Windows
/// `canonicalize` resolves case and short names; a hard link is a separate
/// name, as for vault writes).
pub(crate) fn refuse_destination(out: &Path, source: &Path) -> io::Result<()> {
    refuse_lock_file_name(out)?;
    let out_is_link = std::fs::symlink_metadata(out).is_ok_and(|m| m.file_type().is_symlink());
    let key = |p: &Path, follow_leaf: bool| -> Option<FileIdentity> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = if follow_leaf {
                std::fs::metadata(p)
            } else {
                std::fs::symlink_metadata(p)
            };
            if let Ok(m) = meta {
                return Some(FileIdentity::Inode(m.dev(), m.ino()));
            }
        }
        if follow_leaf {
            if let Ok(real) = std::fs::canonicalize(p) {
                return Some(FileIdentity::Path(real, std::ffi::OsString::new()));
            }
        }
        let dir = std::fs::canonicalize(parent_or_dot(p))
            .unwrap_or_else(|_| parent_or_dot(p).to_path_buf());
        let leaf = p.file_name()?;
        #[cfg(windows)]
        let leaf = std::ffi::OsString::from(
            leaf.to_string_lossy()
                .trim_end_matches(['.', ' '])
                .to_lowercase(),
        );
        #[cfg(not(windows))]
        let leaf = leaf.to_os_string();
        Some(FileIdentity::Path(dir, leaf))
    };
    if let (Some(a), Some(b)) = (key(out, !out_is_link), key(source, !out_is_link)) {
        if a == b {
            return Err(io::Error::other(format!(
                "{}: the output is the file it is built from; choose another output path",
                out.display()
            )));
        }
    }
    Ok(())
}

/// Ask the destination filesystem, independently of the bounded lock spelling.
/// In particular HFS+ permits multibyte names longer than 255 UTF-8 bytes.
pub(crate) fn destination_can_exist(out: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(out) {
        Ok(_) => Ok(true),
        Err(e) if name_too_long(&e) || cfg!(windows) && e.raw_os_error() == Some(123) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

fn name_too_long(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ENAMETOOLONG)
    }
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(206)
    } // ERROR_FILENAME_EXCED_RANGE
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        false
    }
}

/// Pin a parent directory before taking a lock or selecting an output. Preserve
/// the leaf: replacing a leaf symlink must not accidentally write its target.
pub(crate) fn anchored(path: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    let verbatim = matches!(path.components().next(), Some(std::path::Component::Prefix(p))
        if matches!(p.kind(), std::path::Prefix::Verbatim(_) | std::path::Prefix::VerbatimDisk(_) | std::path::Prefix::VerbatimUNC(_, _)));
    #[cfg(windows)]
    if verbatim
        && path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(['.', ' ']))
    {
        return Err(io::Error::other(
            "ambiguous verbatim Windows leaf ending in a dot or space is refused",
        ));
    }
    // Path::file_name normalizes these suffixes away. A directory spelling
    // must never become a replacing write to the preceding regular file.
    let raw = path.as_os_str().as_encoded_bytes();
    if raw.ends_with(b"/")
        || raw.ends_with(b"/.")
        || cfg!(windows) && (raw.ends_with(b"\\") || raw.ends_with(b"\\."))
    {
        return Err(io::Error::other(
            "file path ends in a directory separator or dot component",
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("file path has no basename"))?;
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let mut units: Vec<u16> = name.encode_wide().collect();
        if !verbatim {
            while matches!(units.last(), Some(0x20 | 0x2e)) {
                units.pop();
            }
        }
        if units.is_empty() {
            return Err(io::Error::other(
                "Windows file basename is empty after normalization",
            ));
        }
        std::ffi::OsString::from_wide(&units)
    };
    #[cfg(windows)]
    let name = name.as_os_str();
    let pinned = std::fs::canonicalize(parent_or_dot(path))?.join(name);
    #[cfg(windows)]
    if !verbatim && name != path.file_name().unwrap() {
        match std::fs::symlink_metadata(&pinned) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::other(
                    "new Windows path ends in a dot or a space; use its normalized basename",
                ))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(pinned)
}

impl WriteLock {
    pub(crate) fn source_path(&self) -> &Path {
        &self.source
    }

    /// Match an ingestion candidate to the held lock by open-file identity.
    pub(crate) fn holds_file(&self, path: &Path) -> io::Result<bool> {
        let Some(file) = &self._file else {
            return Ok(false);
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = file.metadata()?;
            let candidate = std::fs::metadata(path)?;
            Ok(candidate.is_file()
                && held.dev() == candidate.dev()
                && held.ino() == candidate.ino())
        }
        #[cfg(not(unix))]
        {
            let held = same_file::Handle::from_file(file.try_clone()?)?;
            Ok(held == same_file::Handle::from_path(path)?)
        }
    }

    /// Only a real guard of this very lock file can cover a second namespace.
    /// Never reconstruct the held path through the caller's mutable aliases.
    pub(crate) fn covers_namespace(&self, source: &Path) -> bool {
        let Some(file) = &self._file else {
            return false;
        };
        let Ok(path) = anchored(source).and_then(|p| namespace_name_source(&p)) else {
            return false;
        };
        let path = lock_path(&path);
        if path != self.path {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match (file.metadata(), std::fs::symlink_metadata(&path)) {
                (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino() && b.is_file(),
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            true
        } // Windows lock handles deny delete sharing.
    }
}

/// Take the write lock of `out`, a destination the caller named for a file
/// built from `held` (already locked by the caller): `export-parity --out`,
/// `correct gen --out`. A vault at `out` is then replaced only while none of
/// its writers holds its lock. Leaf links are replaced under their own namespace
/// guard without following their targets. `None` only when the real source
/// guard already covers that normalized namespace. Refused when `out`
/// names a lock file or is `held` itself, before any missing parent folder of
/// `out` is created.
pub(crate) fn acquire_destination(
    out: &Path,
    held: &Path,
    source_guard: &WriteLock,
) -> io::Result<Option<WriteLock>> {
    refuse_destination(out, held)?;
    if !destination_can_exist(out)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination basename is invalid for the destination filesystem",
        ));
    }
    if source_guard._file.is_some() && !source_guard.covers_namespace(held) {
        return Err(io::Error::other(
            "source lock namespace changed; retry operation",
        ));
    }
    if source_guard.covers_namespace(out) {
        return Ok(None);
    }
    std::fs::create_dir_all(parent_or_dot(out))?;
    recover_acquired(acquire_with_policy(out, false, true)?).map(Some)
}

/// Open (or create) the lock file without following a symbolic link (or, on
/// Windows, a reparse point) at its path, and refuse anything that is not a
/// regular file (a link, a directory, a FIFO, a device). The check is on the
/// opened handle, so nothing can be swapped in between the check and the open.
///
/// A lock file this process may not write (created by another user) is
/// opened read-only: an exclusive lock needs no write access. `None`: there
/// is no lock file and it cannot be created here.
fn open_lock_file(path: &Path) -> io::Result<Option<File>> {
    let file = match open_no_follow(path, true) {
        Ok(file) => file,
        Err(e) if is_sharing_violation(&e) => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "vault lock file {} is in use by another program; retry when it has closed it",
                    path.display()
                ),
            ))
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            match open_no_follow(path, false) {
                Ok(file) => file,
                Err(missing) if missing.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(open_error(path, e)),
            }
        }
        Err(e) => return Err(open_error(path, e)),
    };
    let meta = file.metadata().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("inspect vault lock file {}: {e}", path.display()),
        )
    })?;
    // On Windows `is_file` is false for a symbolic link or junction (a
    // name-surrogate reparse point) and true for other reparse points such as
    // cloud-sync placeholders, which are ordinary files to lock.
    if !meta.is_file() {
        return Err(io::Error::other(format!(
            "vault lock file {}: is not a regular file; remove it",
            path.display()
        )));
    }
    Ok(Some(file))
}

/// True for the Windows error of an open refused by another handle's sharing
/// mode (ERROR_SHARING_VIOLATION): this process opens the lock file without
/// delete sharing, so a program holding it open with delete access (a sync or
/// backup tool) refuses the open until it closes it.
fn is_sharing_violation(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(32)
}

/// Open `path` read-write (creating it) or read-only, never through a link.
fn open_no_follow(path: &Path, write: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(write)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: opening a FIFO planted at the path must not wait for a
        // peer (POSIX leaves O_RDWR on a FIFO undefined; Linux does not wait).
        // It has no effect on a regular file or on the lock itself.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        // No FILE_SHARE_DELETE: while any writer has the lock file open
        // (holding or waiting), nothing can rename over it or delete it.
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    options.open(path)
}

/// The open error, named; a symbolic link at the path (which the open
/// refused to follow) is said as such.
fn open_error(path: &Path, e: io::Error) -> io::Error {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        io::Error::other(format!(
            "vault lock file {}: is a symbolic link; remove it",
            path.display()
        ))
    } else {
        io::Error::new(
            e.kind(),
            format!("open vault lock file {}: {e}", path.display()),
        )
    }
}

/// Test cleanup: remove a vault and its lock file, and check both are gone.
#[cfg(test)]
pub(crate) fn remove_vault_and_lock(vault: &Path) {
    let _ = std::fs::remove_file(vault);
    let _ = std::fs::remove_file(lock_path(vault));
    let mut sidecar = vault.as_os_str().to_os_string();
    sidecar.push(".aerocorrect");
    let _ = std::fs::remove_file(lock_path(Path::new(&sidecar)));
    assert!(!vault.exists(), "vault left behind: {}", vault.display());
    assert!(
        !lock_path(vault).exists(),
        "lock file left behind: {}",
        lock_path(vault).display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aerovault-lock-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn review_aliases_share_lock_across_length_cutoff() {
        let name = format!("{}.aerozip", "ß".repeat(116));
        let alias = format!("{}\u{200c}\u{200c}\u{200c}.aerozip", "ß".repeat(116));
        assert_eq!(lock_path(Path::new(&name)), lock_path(Path::new(&alias)));
        assert_eq!(
            lock_path(Path::new("VAULT.aerozip")),
            lock_path(Path::new("vault.aerozip"))
        );
        assert_eq!(
            lock_path(Path::new("vault.aerozip. ")),
            lock_path(Path::new("vault.aerozip"))
        );
        #[cfg(target_os = "macos")]
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(&name);
            let alias_path = dir.path().join(&alias);
            std::fs::write(&path, b"vault").unwrap();
            if alias_path.exists() {
                set_short_wait_for_this_thread();
                let held = acquire(&path).unwrap();
                assert!(acquire(&alias_path).is_err());
                drop(held);
            }
        }
    }

    #[test]
    fn review_long_lock_names_are_bounded_and_normalized() {
        let upper = PathBuf::from("K".repeat(247));
        let lower = PathBuf::from("k".repeat(247));
        assert_eq!(lock_path(&upper), lock_path(&lower));
        assert_eq!(
            lock_path(Path::new(&"Σ".repeat(247))),
            lock_path(Path::new(&"ς".repeat(247)))
        );
        assert_ne!(lock_path(&lower), lock_path(Path::new(&"x".repeat(247))));
        assert!(name_units(lock_path(&lower).file_name().unwrap()) <= 255);
        assert_eq!(
            lock_path(Path::new(&"é".repeat(127))),
            lock_path(Path::new(&"e\u{301}".repeat(127)))
        );
        #[cfg(unix)]
        assert_eq!(
            lock_path(Path::new(&"K".repeat(84))),
            lock_path(Path::new(&"k".repeat(84)))
        );
    }

    #[test]
    fn second_writer_waits_then_gets_a_clear_error() {
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        let held = acquire(&vault).unwrap();
        let started = Instant::now();
        let err = acquire(&vault).unwrap_err();
        assert!(
            err.to_string().contains("locked by another writer"),
            "{err}"
        );
        assert!(
            started.elapsed() >= TEST_SHORT_WAIT,
            "gave up before the wait"
        );
        assert!(started.elapsed() < TEST_SHORT_WAIT * 20, "hung");
        drop(held);
        acquire(&vault).unwrap();
        assert!(lock_path(&vault).exists(), "the lock file stays");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_only_folder_without_a_lock_file_has_nothing_to_lock() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            // Running as root: the folder is writable anyway.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let res = acquire_for_export(&vault);
        assert!(acquire(&vault).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(res.unwrap()._file.is_none());
        assert!(!lock_path(&vault).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_this_user_cannot_write_is_still_locked() {
        // A lock file another user created (0644) must not lock this user out.
        use std::os::unix::fs::PermissionsExt;
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        drop(acquire(&vault).unwrap());
        let lock = lock_path(&vault);
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
        if OpenOptions::new().write(true).open(&lock).is_ok() {
            // Running as root: the file is writable anyway.
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let held = acquire(&vault).unwrap();
        assert!(held._file.is_some());
        let err = acquire(&vault).unwrap_err();
        assert!(
            err.to_string().contains("locked by another writer"),
            "{err}"
        );
        drop(held);
        acquire(&vault).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_lock_file_is_refused() {
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        // Dangling: following it would create the target.
        let target = dir.join("elsewhere");
        std::os::unix::fs::symlink(&target, lock_path(&vault)).unwrap();
        let err = acquire(&vault).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!target.exists(), "the link was followed");
        // Pointing at an existing file: following it would lock that file.
        std::fs::remove_file(lock_path(&vault)).unwrap();
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, lock_path(&vault)).unwrap();
        let err = acquire(&vault).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_vault_path_is_refused() {
        let dir = scratch();
        let target = dir.join("real.aerovault");
        std::fs::write(&target, b"vault").unwrap();
        let link = dir.join("link.aerovault");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = acquire(&link).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!lock_path(&link).exists());
        acquire(&target).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lock_file_names_are_never_written_over() {
        for name in [
            "v.aerovault.aerolock",
            "V.AEROVAULT.AeroLock",
            "v.aerolock.",
            "v.aerolock . ",
            ".aerolock",
            // Kelvin sign for the final k (one file with `.aerolock` on macOS).
            "v.aeroloc\u{212A}",
            // Characters HFS+ ignores in names.
            "v.aero\u{200C}lock",
            "v.aerolock\u{FEFF}",
            "v.aerolock\u{200B}.",
        ] {
            let err = refuse_lock_file_name(Path::new(name)).unwrap_err();
            assert!(err.to_string().contains("vault lock file"), "{name}: {err}");
        }
        for name in ["Cargo.lock", "v.aerolock.bak", "v.aerovault", "aerolock"] {
            refuse_lock_file_name(Path::new(name)).unwrap();
        }
        // A write that would replace a lock file never takes a lock of its own.
        let dir = scratch();
        let lock_file = lock_path(&dir.join("v.aerovault"));
        let err = acquire(&lock_file).unwrap_err();
        assert!(err.to_string().contains("vault lock file"), "{err}");
        assert!(!lock_path(&lock_file).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn every_windows_name_of_a_vault_locks_one_lock_file() {
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        std::fs::write(&vault, b"vault").unwrap();
        let held = acquire(&vault).unwrap();
        for alias in [
            "v.aerovault.",
            "v.aerovault ",
            "V.AEROVAULT",
            "v.aerovault. .",
        ] {
            let err = acquire(&dir.join(alias)).unwrap_err();
            assert!(
                err.to_string().contains("locked by another writer"),
                "{alias}: {err}"
            );
        }
        drop(held);
        // A new vault cannot be named with a trailing dot or space: the file
        // created would be `n.aerovault`, locked under another lock file name.
        let err = acquire(&dir.join("n.aerovault.")).unwrap_err();
        assert!(err.to_string().contains("dot or a space"), "{err}");
        // The real name of an existing lock file is a lock file name too.
        assert!(refuse_lock_file_name(&dir.join("v.aerovault.aerolock.")).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn a_lock_file_held_open_with_delete_access_is_waited_for() {
        // A sync or backup tool that holds the lock file open with delete
        // access makes the open fail with a sharing violation: the writer
        // waits as for a held lock, then says what is in the way.
        use std::os::windows::fs::OpenOptionsExt;
        set_short_wait_for_this_thread();
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        drop(acquire(&vault).unwrap());
        const DELETE: u32 = 0x0001_0000;
        const GENERIC_READ: u32 = 0x8000_0000;
        let tool = OpenOptions::new()
            .access_mode(DELETE | GENERIC_READ)
            .share_mode(0x1 | 0x2 | 0x4)
            .open(lock_path(&vault))
            .unwrap();
        let started = Instant::now();
        let err = acquire(&vault).unwrap_err();
        assert!(
            err.to_string().contains("in use by another program"),
            "{err}"
        );
        assert!(
            started.elapsed() >= TEST_SHORT_WAIT,
            "gave up before the wait"
        );
        drop(tool);
        acquire(&vault).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn a_held_lock_file_cannot_be_replaced_or_deleted() {
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        let held = acquire(&vault).unwrap();
        let other = dir.join("other");
        std::fs::write(&other, b"x").unwrap();
        assert!(std::fs::rename(&other, lock_path(&vault)).is_err());
        assert!(std::fs::remove_file(lock_path(&vault)).is_err());
        drop(held);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn directory_at_the_lock_path_names_the_cause() {
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        std::fs::create_dir(lock_path(&vault)).unwrap();
        let err = acquire(&vault).unwrap_err();
        assert!(err.to_string().contains("vault lock file"), "{err}");
        assert!(!err.to_string().contains("another writer"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_at_the_lock_path_is_refused_without_hanging() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = scratch();
        let vault = dir.join("v.aerovault");
        let fifo = CString::new(lock_path(&vault).as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let v = vault.clone();
        std::thread::spawn(move || tx.send(acquire(&v).map(drop)).ok());
        let res = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("opening a FIFO at the lock path hung");
        let err = res.unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
    #[test]
    fn review_ignored_characters_are_removed_before_trailing_trim() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("v.aerovault.");
        let b = dir.path().join("v.aerovault.\u{200c}");
        assert_eq!(lock_path(&a), lock_path(&b));
        #[cfg(unix)]
        {
            set_short_wait_for_this_thread();
            let _guard = acquire(&a).unwrap();
            let error = acquire(&b).unwrap_err();
            assert!(
                error.to_string().contains("locked by another writer"),
                "{error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn review_destination_reuse_checks_the_guard_identity() {
        use std::os::unix::fs::symlink;
        set_short_wait_for_this_thread();
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let alias = dir.path().join("alias");
        symlink(&a, &alias).unwrap();
        let held = alias.join("source");
        let out = b.join("SOURCE");
        let guard = acquire(&held).unwrap();
        let _other = acquire(&out).unwrap();
        std::fs::remove_file(&alias).unwrap();
        symlink(&b, &alias).unwrap();
        let error = acquire_destination(&out, &held, &guard).unwrap_err();
        assert!(error.to_string().contains("namespace changed"), "{error}");
    }

    #[test]
    fn review_destination_length_uses_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("界".repeat(90));
        match std::fs::write(&path, b"valid") {
            Ok(()) => {
                assert!(destination_can_exist(&path).unwrap());
                let _guard = acquire(&path).unwrap();
            }
            Err(error) => {
                assert!(name_too_long(&error), "{error}");
                assert!(!destination_can_exist(&path).unwrap());
            }
        }
        let invalid = dir.path().join("x".repeat(1000));
        assert!(!destination_can_exist(&invalid).unwrap());
    }
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires the dedicated HFS+ CI image"]
    fn review_hfs_ignored_suffix_aliases_contend() {
        use std::os::unix::fs::MetadataExt;
        let root = std::env::var_os("AEROVAULT_TEST_HFS_ROOT")
            .expect("run with the dedicated HFS+ image mounted");
        let dir = tempfile::tempdir_in(root).unwrap();
        let a = dir.path().join("v.aerovault.");
        let b = dir.path().join("v.aerovault.\u{200c}");
        std::fs::write(&a, b"one file").unwrap();
        assert_eq!(
            std::fs::metadata(&a).unwrap().ino(),
            std::fs::metadata(&b).unwrap().ino()
        );
        set_short_wait_for_this_thread();
        let _guard = acquire(&a).unwrap();
        assert!(acquire(&b)
            .unwrap_err()
            .to_string()
            .contains("locked by another writer"));
    }
    #[cfg(unix)]
    #[test]
    fn review_symbolic_destination_keeps_its_own_guard_through_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        let out = dir.path().join("out");
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&target, b"target untouched").unwrap();
        std::os::unix::fs::symlink(&target, &out).unwrap();
        let source_guard = acquire(&source).unwrap();
        let destination = acquire_destination(&out, &source, &source_guard)
            .unwrap()
            .expect("symbolic destination needs a real guard");
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"exported").unwrap();
        std::fs::rename(&staged, &out).unwrap();
        set_short_wait_for_this_thread();
        assert!(acquire(&out)
            .unwrap_err()
            .to_string()
            .contains("locked by another writer"));
        assert!(acquire_destination(&out, &source, &source_guard)
            .unwrap_err()
            .to_string()
            .contains("locked by another writer"));
        assert_eq!(std::fs::read(&target).unwrap(), b"target untouched");
        drop(destination);
        assert!(acquire(&out).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn review_windows_namespace_resolves_link_without_following_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("a-long-symbolic-destination");
        std::fs::write(&target, b"untouched").unwrap();
        if let Err(e) = std::os::windows::fs::symlink_file(&target, &link) {
            if e.raw_os_error() == Some(1314) {
                eprintln!("Windows symlink privilege unavailable");
                return;
            }
            panic!("cannot prepare symbolic destination: {e}");
        }
        let resolved = namespace_name_source(&link).unwrap();
        assert_eq!(resolved.file_name(), link.file_name());
        let source = dir.path().join("source");
        std::fs::write(&source, b"source").unwrap();
        let source_guard = acquire(&source).unwrap();
        let dest = acquire_destination(&link, &source, &source_guard)
            .unwrap()
            .unwrap();
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"replacement").unwrap();
        std::fs::rename(&staged, &link).unwrap();
        set_short_wait_for_this_thread();
        assert!(acquire(&link)
            .unwrap_err()
            .to_string()
            .contains("locked by another writer"));
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        drop(dest);
    }

    #[test]
    fn review_directory_suffix_never_replaces_the_shorter_vault_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.aerovault");
        crate::vault::Vault::create(crate::vault::CreateOptions::new(&path, "test-password-123"))
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        for suffix in ["/", "/."] {
            let mut spelling = path.as_os_str().to_os_string();
            spelling.push(suffix);
            let bad = PathBuf::from(spelling);
            assert!(
                crate::vault::Vault::create(crate::vault::CreateOptions::new(
                    &bad,
                    "test-password-123"
                ))
                .is_err()
            );
            assert!(
                crate::v3::VaultV3::create(&crate::v3::CreateOptionsV3::new_plaintext(&bad))
                    .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        let ordinary = dir.path().join("ordinary.aerozip");
        crate::v3::VaultV3::create(&crate::v3::CreateOptionsV3::new_plaintext(&ordinary)).unwrap();
        assert!(crate::v3::VaultV3::open_plaintext(&ordinary).is_ok());
    }
    #[cfg(windows)]
    #[test]
    fn round7_windows_verbatim_leaf_cannot_replace_trimmed_neighbor() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        for legacy in [false, true] {
            let neighbor = root.join(if legacy {
                "legacy.aerovault"
            } else {
                "v3.aerovault"
            });
            let literal = neighbor.with_file_name(format!(
                "{}.",
                neighbor.file_name().unwrap().to_string_lossy()
            ));
            std::fs::write(&neighbor, b"keep neighbor").unwrap();
            std::fs::write(&literal, b"keep literal").unwrap();
            let error = if legacy {
                crate::Vault::create(crate::CreateOptions::new(&literal, "test-password-123"))
                    .map(|_| ())
                    .unwrap_err()
                    .to_string()
            } else {
                crate::v3::VaultV3::create(&crate::v3::CreateOptionsV3::new(
                    &literal,
                    "test-password-123",
                ))
                .map(|_| ())
                .unwrap_err()
            };
            assert!(error.contains("verbatim"), "{error}");
            assert_eq!(std::fs::read(&neighbor).unwrap(), b"keep neighbor");
            assert_eq!(std::fs::read(&literal).unwrap(), b"keep literal");
        }
        eprintln!("Windows verbatim create: both literal and trimmed-neighbor bytes preserved");
    }
    #[cfg(windows)]
    #[test]
    fn round7_windows_round8_ordinary_dotted_aliases_open_and_links_refuse_create() {
        const PW: &str = "test-password-123";
        let dir = tempfile::tempdir().unwrap();
        let normal = PathBuf::from(
            dir.path()
                .to_str()
                .unwrap()
                .strip_prefix(r"\\?\")
                .unwrap_or(dir.path().to_str().unwrap()),
        );
        for legacy in [false, true] {
            let path = normal.join(if legacy {
                "legacy.aerovault"
            } else {
                "v3.aerovault"
            });
            if legacy {
                crate::Vault::create(crate::CreateOptions::new(&path, PW)).unwrap();
            } else {
                crate::v3::VaultV3::create(&crate::v3::CreateOptionsV3::new(&path, PW)).unwrap();
            }
            let dotted =
                path.with_file_name(format!("{}.", path.file_name().unwrap().to_string_lossy()));
            if legacy {
                assert!(crate::Vault::open(&dotted, PW).is_ok());
            } else {
                assert!(crate::v3::VaultV3::open(&dotted, PW).is_ok());
            }
            let link = normal.join(if legacy {
                "legacy-link.aerovault"
            } else {
                "v3-link.aerovault"
            });
            if let Err(e) = std::os::windows::fs::symlink_file(&path, &link) {
                if e.raw_os_error() == Some(1314) {
                    eprintln!("Windows symbolic-link privilege unavailable; dotted symlink subcase unavailable");
                    continue;
                }
                panic!("cannot create symbolic fixture: {e}");
            }
            let alias =
                link.with_file_name(format!("{}.", link.file_name().unwrap().to_string_lossy()));
            let before = std::fs::read(&path).unwrap();
            let error = if legacy {
                crate::Vault::create(crate::CreateOptions::new(&alias, PW))
                    .map(|_| ())
                    .unwrap_err()
                    .to_string()
            } else {
                crate::v3::VaultV3::create(&crate::v3::CreateOptionsV3::new(&alias, PW))
                    .map(|_| ())
                    .unwrap_err()
            };
            assert!(error.contains("symbolic link"), "{error}");
            assert!(std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(std::fs::read(&path).unwrap(), before);
            eprintln!("Windows dotted symlink refusal exercised for legacy={legacy}");
        }
    }
}
