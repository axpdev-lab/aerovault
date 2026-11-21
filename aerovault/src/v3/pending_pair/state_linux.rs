// SPDX-License-Identifier: MPL-2.0
//! Select a private Linux journal root and locate interrupted work across XDG changes.

use super::{absolute_directory, configured_root, source_key, state_root, TrustedJournal};
use crate::v3::pending_pair::fresh::ensure_private_root;
use crate::v3::strip_transaction::{check_journal_ancestry, writable_ancestor, AncestryError};
use crate::v3::vault::output_parent_dir;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn home_root() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let path = absolute_directory(&home)?.join(".aerovault-state/journals");
    Some(path.components().collect())
}

fn default_root() -> Option<PathBuf> {
    let path = state_root(None, std::env::var_os("HOME").as_deref()).ok()?;
    Some(path.components().collect())
}

fn describe(error: AncestryError) -> String {
    format!("AeroVault private state rejected. {}", error.into_message())
}

fn validate_home() -> Result<(), String> {
    let home = std::env::var_os("HOME");
    let home = home
        .as_deref()
        .and_then(absolute_directory)
        .ok_or("Set HOME to an absolute private home directory")?;
    let rejection = |reason| format!("HOME {} rejected. {reason}", home.display());
    check_journal_ancestry(home).map_err(|error| rejection(error.into_message()))?;
    let mode = fs::symlink_metadata(home)
        .map_err(|error| rejection(error.to_string()))?
        .mode();
    if mode & 0o022 != 0 {
        return Err(rejection(writable_ancestor(home, mode)));
    }
    Ok(())
}

fn ensure_alternate(root: &Path) -> Result<(), String> {
    let private = output_parent_dir(root);
    if present(private, true)? {
        TrustedJournal::open(private)?;
    }
    ensure_private_root(root).map_err(AncestryError::into_message)?;
    TrustedJournal::open(private)?;
    Ok(())
}

pub(in crate::v3) fn select_root() -> Result<PathBuf, String> {
    let preferred: PathBuf = configured_root()?.components().collect();
    match ensure_private_root(&preferred) {
        Ok(()) => Ok(preferred),
        Err(AncestryError::Writable(reason)) => {
            let rejection = describe(AncestryError::Writable(reason));
            validate_home().map_err(|error| format!("{rejection}. {error}"))?;
            let alternate = home_root().ok_or_else(|| rejection.clone())?;
            ensure_alternate(&alternate).map_err(|other| {
                format!(
                    "{rejection}. Alternative {} also rejected. {other}",
                    alternate.display()
                )
            })?;
            Ok(alternate)
        }
        Err(error) => Err(describe(error)),
    }
}

pub(in crate::v3) fn validate_active_root(root: &Path) -> Result<(), String> {
    if home_root().as_deref() == Some(root) {
        validate_home()?;
        TrustedJournal::open(output_parent_dir(root))?;
    }
    TrustedJournal::open(root)?;
    Ok(())
}

fn present(path: &Path, known: bool) -> Result<bool, String> {
    Ok(inspect_path(path, known)?.is_some())
}

fn inspect_path(path: &Path, known: bool) -> Result<Option<fs::Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        // An unused search root can be unavailable. A located journal still
        // has to pass all trust checks before recovery.
        Err(error)
            if !known
                && (matches!(
                    error.kind(),
                    ErrorKind::PermissionDenied | ErrorKind::NotADirectory
                ) || error.raw_os_error() == Some(libc::ELOOP)) =>
        {
            Ok(None)
        }
        Err(error) => Err(format!(
            "Inspect private recovery path {} ({error})",
            path.display()
        )),
    }
}

pub(in crate::v3) fn pending_location(source: &Path) -> Result<Option<PathBuf>, String> {
    lookup_location(source, true)
}

pub(super) fn lookup_location(
    source: &Path,
    require_recovery: bool,
) -> Result<Option<PathBuf>, String> {
    let mut roots: Vec<PathBuf> = [configured_root().ok(), default_root(), home_root()]
        .into_iter()
        .flatten()
        .map(|path| path.components().collect())
        .collect();
    roots.sort_unstable();
    roots.dedup();

    let key = source_key(source).to_hex();
    let mut pending: Option<(PathBuf, fs::Metadata)> = None;
    for root in roots {
        let candidate = root.join(key.as_str());
        let Some(metadata) = inspect_path(&candidate, false)? else {
            continue;
        };
        if require_recovery
            && !present(
                &candidate.join(crate::v3::pending_pair::fresh::RECORD),
                true,
            )?
            && !present(
                &candidate.join(crate::v3::pending_pair::update::RECORD),
                true,
            )?
            && !present(
                &candidate.join(crate::v3::pending_pair::update::PREPARATION),
                true,
            )?
        {
            continue;
        }
        if let Some((prior, previous)) = &pending {
            if !metadata.is_dir()
                || !previous.is_dir()
                || (metadata.dev(), metadata.ino()) != (previous.dev(), previous.ino())
            {
                return Err(format!(
                    "Conflicting private pair journals at {} and {}. Preserve both for recovery",
                    prior.display(),
                    candidate.display()
                ));
            }
            // An alias is only evidence that a directory was counted twice.
            // Recovery must still use a spelling that passes the trust checks.
            if validate_active_root(&root)
                .and_then(|()| TrustedJournal::open(&candidate))
                .is_err()
            {
                continue;
            }
        }
        pending = Some((candidate, metadata));
    }
    Ok(pending.map(|(path, _)| path))
}
