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
    #[serde(default)]
    unix_acl: Option<Vec<u8>>,
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
            let acl = self.unix_acl.as_deref().ok_or(
                "Recovery journal lacks the original access ACL; manual recovery required",
            )?;
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
    source: &Path,
    target: &Path,
    expected: Generation,
    target_before: Generation,
) -> Result<(), String> {
    if generation(source)? != expected {
        return Err("strip rollback copy failed its generation check".to_string());
    }
    let mut input = crate::source::open_regular_no_follow(source).map_err(|e| e.to_string())?;
    let private = private_dir(output_parent_dir(target), ".aerostrip-restore-")?;
    #[cfg(windows)]
    let mut private = private;
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
    #[cfg(all(test, target_os = "macos"))]
    if let Some(inspect) = INSPECT_ROLLBACK_STAGE.with(|h| h.borrow_mut().take()) {
        inspect(temp.path());
    }
    if generation(temp.path())? != expected {
        return Err("strip rollback copy changed while being read".to_string());
    }
    if generation(target)? != target_before {
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

fn read_journal(path: &Path) -> Result<Journal, String> {
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
    if !matches!(journal.version, 1..=4) {
        return Err("unsupported strip journal version".into());
    }
    Ok(journal)
}

fn load(path: &Path, source: &Path) -> Result<(Journal, PathBuf), String> {
    let journal = read_journal(path)?;
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
    let original_pair = vault_now == journal.old_vault && sidecar_now == journal.old_sidecar;
    if original_pair
        && path
            .join("rollback-intent")
            .try_exists()
            .map_err(|e| e.to_string())?
    {
        cleanup(path)?;
        return Ok(RecoveryOutcome::Original);
    }
    if original_pair && path.join("new-vault").exists() && path.join("new-sidecar").exists() {
        cleanup(path)?;
        return Ok(RecoveryOutcome::Original);
    }
    if vault_now == Some(journal.new_vault) && sidecar_now == Some(journal.new_sidecar) {
        // A crash can occur just after rename and before inheritance restoration.
        restore_published_permissions(source, &sidecar, &journal, path)?;
        cleanup(path)?;
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
    if generation_if_present(&path.join("old-vault"))? != journal.old_vault
        || generation_if_present(&path.join("old-sidecar"))? != journal.old_sidecar
    {
        return Err("strip rollback generation check failed; files left untouched".to_string());
    }
    let rollback = path.join("rollback-intent");
    if !rollback.try_exists().map_err(|e| e.to_string())? {
        let file = private_options()
            .open(rollback)
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        sync_dir(path)?;
    }
    if vault_now != journal.old_vault {
        restore_original(
            &path.join("old-vault"),
            source,
            journal.old_vault,
            vault_now,
        )?;
    }
    if sidecar_now != journal.old_sidecar {
        restore_original(
            &path.join("old-sidecar"),
            &sidecar,
            journal.old_sidecar,
            sidecar_now,
        )?;
    }
    #[cfg(test)]
    if let Some(hook) = AFTER_ROLLBACK_RESTORE.with(|h| h.borrow_mut().take()) {
        hook();
    }
    cleanup(path)?;
    Ok(RecoveryOutcome::Original)
}

fn restore_original(
    backup: &Path,
    target: &Path,
    original: Option<Generation>,
    current: Option<Generation>,
) -> Result<(), String> {
    if let Some(original) = original {
        return replace_from(
            backup,
            target,
            original,
            current.ok_or("rollback target unexpectedly absent")?,
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
    let journal = match read_journal(&path) {
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
    fs::rename(prepared.path(), &path).map_err(|e| format!("publish strip journal: {e}"))?;
    sync_dir(output_parent_dir(source))?;
    #[cfg(test)]
    if let Some(hook) = AFTER_STRIP_JOURNAL.with(|h| h.borrow_mut().take()) {
        hook();
    }
    let result = (|| {
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
            &backup,
            &original,
            generation(&backup).unwrap(),
            generation(&original).unwrap(),
        )
        .unwrap();
        assert!(inspected.get());
        assert_eq!(fs::read(original).unwrap(), b"plaintext before strip");
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
            &backup,
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
