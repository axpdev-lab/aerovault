// SPDX-License-Identifier: MPL-2.0
//! Recoverable publication of a non-forced strip and its refreshed sidecar.
//!
//! Prepared files and rollback copies live on disk. A small, synced journal is
//! made visible before either rename. An interrupted publication is rolled back
//! on the next open/write; a completed pair only needs journal cleanup. Recovery
//! never replaces a generation outside the recorded old/new pair.
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::vault::{output_parent_dir, persist_over};
use crate::lock::WriteLock;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Generation {
    len: u64,
    hash: [u8; 32],
}

pub(super) fn generation(path: &Path) -> Result<Generation, String> {
    let mut file = crate::source::open_regular_no_follow(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut hash = blake3::Hasher::new();
    let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    let mut len = 0u64;
    loop {
        let n = file.read(&mut *buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        len = len
            .checked_add(n as u64)
            .ok_or("generation length overflow")?;
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

pub(super) fn journal_path(source: &Path) -> PathBuf {
    let lock = crate::lock::lock_path(source);
    let hash = blake3::hash(lock.file_name().unwrap_or_default().as_encoded_bytes());
    source.with_file_name(format!(".{}.aerostrip", hash.to_hex()))
}

#[derive(Serialize, Deserialize)]
struct SavedPermissions {
    unix_mode: Option<u32>,
    readonly: bool,
    #[serde(default)]
    windows_dacl: Option<String>,
}
impl SavedPermissions {
    fn capture(path: &Path) -> Result<Self, String> {
        let p = fs::metadata(path).map_err(|e| e.to_string())?.permissions();
        #[cfg(unix)]
        let unix_mode = {
            use std::os::unix::fs::PermissionsExt;
            Some(p.mode() & 0o777)
        };
        #[cfg(not(unix))]
        let unix_mode = None;
        Ok(Self {
            unix_mode,
            readonly: p.readonly(),
            #[cfg(windows)]
            windows_dacl: Some(super::windows_security::capture(path)?),
            #[cfg(not(windows))]
            windows_dacl: None,
        })
    }
    fn apply(&self, path: &Path) -> Result<(), String> {
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
            use std::os::unix::fs::PermissionsExt;
            return fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))
                .map_err(|e| e.to_string());
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
}

pub(super) struct PrivateDir {
    path: PathBuf,
}
impl PrivateDir {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(super) fn private_dir(parent: &Path, prefix: &str) -> Result<PrivateDir, String> {
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
    Ok(PrivateDir { path })
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
    let mut input = crate::source::open_regular_no_follow(source).map_err(|e| e.to_string())?;
    let mut output = private_options().open(target).map_err(|e| e.to_string())?;
    let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    loop {
        let n = input.read(&mut *buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n]).map_err(|e| e.to_string())?;
    }
    output.sync_all().map_err(|e| e.to_string())?;
    generation(target)
}

fn replace_from(
    source: &Path,
    target: &Path,
    expected: Generation,
    target_before: Generation,
    permissions: Option<&SavedPermissions>,
) -> Result<(), String> {
    if generation(source)? != expected {
        return Err("strip rollback copy failed its generation check".to_string());
    }
    let mut input = crate::source::open_regular_no_follow(source).map_err(|e| e.to_string())?;
    let private = private_dir(output_parent_dir(target), ".aerostrip-restore-")?;
    let mut temp = tempfile::Builder::new()
        .prefix("replacement-")
        .tempfile_in(private.path())
        .map_err(|e| e.to_string())?;
    let mut buf = zeroize::Zeroizing::new([0u8; 64 * 1024]);
    loop {
        let n = input.read(&mut *buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        temp.write_all(&buf[..n]).map_err(|e| e.to_string())?;
    }
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    if generation(temp.path())? != expected {
        return Err("strip rollback copy changed while being read".to_string());
    }
    if generation(target)? != target_before {
        return Err(
            "strip target changed while preparing rollback; newer file left untouched".to_string(),
        );
    }
    if let Some(permissions) = permissions {
        permissions.apply(temp.path())?;
    }
    // Backups remain private: permissions are restored only on the replacement.
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    persist_over(temp, target).map_err(|e| e.to_string())?;
    if let Some(permissions) = permissions {
        permissions.published(target)?;
    }
    sync_dir(output_parent_dir(target))
}

fn cleanup(path: &Path) -> Result<(), String> {
    // Remove the recovery marker atomically before garbage collection. A crash
    // can leave a private GC directory, never a half-deleted active journal.
    let gc = private_dir(output_parent_dir(path), ".aerostrip-gc-")?;
    fs::remove_dir(gc.path()).map_err(|e| e.to_string())?;
    fs::rename(path, gc.path()).map_err(|e| e.to_string())?;
    sync_dir(output_parent_dir(path))?;
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

fn load(path: &Path, source: &Path) -> Result<(Journal, PathBuf), String> {
    if !fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_dir()
    {
        return Err("strip transaction path is not a regular directory".to_string());
    }
    let p = path.join("journal.json");
    let mut file = crate::source::open_regular_no_follow(&p).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 4096 {
        return Err("strip journal exceeds size limit".to_string());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid strip journal: {e}"))?;
    let recorded = recorded_source(output_parent_dir(source), &journal.source_name)?;
    if !matches!(journal.version, 1 | 2)
        || (native_name(source) != journal.source_name && !same_existing_file(source, &recorded))
    {
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
    let (journal, recorded) = load(path, source)?;
    let source = recorded.as_path();
    if !lock.covers_namespace(source) {
        return Err("strip recorded source lock namespace changed".to_string());
    }
    let sidecar = super::ec::default_sidecar_path(source);
    let vault_now = generation_if_present(source)
        .map_err(|e| conflict(path, &format!("vault unavailable: {e}")))?;
    let sidecar_now = generation_if_present(&sidecar)
        .map_err(|e| conflict(path, &format!("sidecar unavailable: {e}")))?;
    if vault_now == Some(journal.new_vault) && sidecar_now == Some(journal.new_sidecar) {
        // A crash can occur just after rename and before inheritance restoration.
        restore_published_permissions(source, &sidecar, &journal)?;
        cleanup(path)?;
        return Ok(RecoveryOutcome::Stripped);
    }
    if vault_now == journal.old_vault && sidecar_now == journal.old_sidecar {
        restore_published_permissions(source, &sidecar, &journal)?;
        cleanup(path)?;
        return Ok(RecoveryOutcome::Original);
    }
    if ![journal.old_vault, Some(journal.new_vault)].contains(&vault_now)
        || ![journal.old_sidecar, Some(journal.new_sidecar)].contains(&sidecar_now)
    {
        return Err(conflict(path, "newer or damaged vault or sidecar"));
    }
    // Verify both copies before replacing either original.
    if generation_if_present(&path.join("old-vault"))? != journal.old_vault
        || generation_if_present(&path.join("old-sidecar"))? != journal.old_sidecar
    {
        return Err("strip rollback generation check failed; files left untouched".to_string());
    }
    if vault_now != journal.old_vault {
        restore_original(
            &path.join("old-vault"),
            source,
            journal.old_vault,
            vault_now,
            journal.old_vault_permissions.as_ref(),
        )?;
    }
    if sidecar_now != journal.old_sidecar {
        restore_original(
            &path.join("old-sidecar"),
            &sidecar,
            journal.old_sidecar,
            sidecar_now,
            journal.old_sidecar_permissions.as_ref(),
        )?;
    }
    cleanup(path)?;
    Ok(RecoveryOutcome::Original)
}

fn restore_original(
    backup: &Path,
    target: &Path,
    original: Option<Generation>,
    current: Option<Generation>,
    permissions: Option<&SavedPermissions>,
) -> Result<(), String> {
    if let Some(original) = original {
        return replace_from(
            backup,
            target,
            original,
            current.ok_or("rollback target unexpectedly absent")?,
            permissions,
        );
    }
    // Absence is an original state too. Remove only the exact recorded new
    // generation; preserve any later file as a recovery conflict.
    if generation_if_present(target)? != current {
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
) -> Result<(), String> {
    if let Some(permissions) = &journal.old_vault_permissions {
        permissions.published(source)?;
    }
    if let Some(permissions) = &journal.old_sidecar_permissions {
        permissions.published(sidecar)?;
    }
    Ok(())
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
    let sidecar = super::ec::default_sidecar_path(source);
    let journal = Journal {
        version: 2,
        source_name: native_name(source),
        old_vault: generation_if_present(&prepared.path().join("old-vault"))?,
        new_vault: generation(&prepared.path().join("new-vault"))?,
        old_sidecar: generation_if_present(&prepared.path().join("old-sidecar"))?,
        new_sidecar: generation(&prepared.path().join("new-sidecar"))?,
        old_vault_permissions: if source.exists() {
            Some(SavedPermissions::capture(source)?)
        } else {
            None
        },
        old_sidecar_permissions: if sidecar.exists() {
            Some(SavedPermissions::capture(&sidecar)?)
        } else {
            None
        },
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
    fs::rename(prepared.path(), &path).map_err(|e| format!("publish strip journal: {e}"))?;
    sync_dir(output_parent_dir(source))?;
    #[cfg(test)]
    if let Some(hook) = AFTER_STRIP_JOURNAL.with(|h| h.borrow_mut().take()) {
        hook();
    }
    let result = (|| {
        fs::rename(path.join("new-vault"), source).map_err(|e| e.to_string())?;
        if let Some(p) = &journal.old_vault_permissions {
            p.published(source)?;
        }
        sync_dir(output_parent_dir(source))?;
        #[cfg(test)]
        if let Some(hook) = AFTER_STRIP_VAULT.with(|h| h.borrow_mut().take()) {
            hook();
        }
        fs::rename(path.join("new-sidecar"), &sidecar).map_err(|e| e.to_string())?;
        if let Some(p) = &journal.old_sidecar_permissions {
            p.published(&sidecar)?;
        }
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
            Err(restore) => format!("Could not publish strip ({error}); recovery pending ({restore}); rollback copies retained in {}", path.display()),
        });
    }
    cleanup(&path)
}

#[cfg(test)]
thread_local! {
    pub(super) static FAIL_FINAL_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static BEFORE_STRIP_JOURNAL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_STRIP_JOURNAL: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_STRIP_VAULT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    pub(super) static AFTER_STRIP_SIDECAR: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
