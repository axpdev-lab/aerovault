// SPDX-License-Identifier: MPL-2.0
//! Select a private Linux journal root and locate interrupted work across XDG changes.

use super::{absolute_directory, configured_root, source_key, state_root, TrustedJournal};
use crate::v3::pending_pair::fresh::{ensure_private_root, write_input};
use crate::v3::strip_transaction::{
    check_journal_ancestry, private_dir, sync_dir, writable_ancestor, AncestryError,
};
use crate::v3::vault::output_parent_dir;
use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::{ffi::OsStringExt, fs::MetadataExt};
use std::path::{Path, PathBuf};

const LOCATION_LIMIT: u64 = 4096;

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

pub(in crate::v3) fn validate_home() -> Result<(), String> {
    let home = std::env::var_os("HOME");
    let home = home.as_deref().and_then(absolute_directory).ok_or(
        "AeroVault private state rejected. Set HOME to an absolute private home directory",
    )?;
    let rejection = |reason| {
        format!(
            "AeroVault private state rejected. HOME {} rejected. {reason}",
            home.display()
        )
    };
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
    validate_home()?;
    let preferred: PathBuf = configured_root()?.components().collect();
    match ensure_private_root(&preferred) {
        Ok(()) => Ok(preferred),
        Err(AncestryError::Writable(reason)) => {
            let rejection = describe(AncestryError::Writable(reason));
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
    validate_home()?;
    if home_root().as_deref() == Some(root) {
        TrustedJournal::open(output_parent_dir(root))?;
    }
    TrustedJournal::open(root)?;
    Ok(())
}

fn location_name(source: &Path) -> String {
    format!(".location-{}", source_key(source).to_hex())
}

fn present(path: &Path, known: bool) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        // An optional search root can be misconfigured even for ordinary
        // containers. A recorded root must remain readable or recovery stops.
        Err(error)
            if !known
                && matches!(
                    error.kind(),
                    ErrorKind::PermissionDenied | ErrorKind::NotADirectory
                ) =>
        {
            Ok(false)
        }
        Err(error) => Err(format!(
            "Inspect private recovery path {} ({error})",
            path.display()
        )),
    }
}

fn registered_root(anchor: &Path, source: &Path) -> Result<Option<PathBuf>, String> {
    let name = location_name(source);
    if !present(&anchor.join(&name), false)? {
        return Ok(None);
    }
    TrustedJournal::open(output_parent_dir(anchor))?;
    let journal = TrustedJournal::open(anchor)?;
    let mut raw = Vec::new();
    // A concurrently completed operation may have removed the locator
    // since the optimistic lookup. The source lock serializes mutations.
    let input = match journal.open_input(&name) {
        Ok(input) => input,
        Err(_) if !present(&anchor.join(&name), true)? => return Ok(None),
        Err(error) => return Err(error),
    };
    input
        .take(LOCATION_LIMIT + 1)
        .read_to_end(&mut raw)
        .map_err(|error| format!("Read private recovery location ({error})"))?;
    if raw.len() as u64 > LOCATION_LIMIT || raw.contains(&0) {
        return Err("Invalid private recovery location length or path".into());
    }
    let native = OsString::from_vec(raw);
    absolute_directory(&native)
        .map(Path::to_owned)
        .map(Some)
        .ok_or("Private recovery location must be an absolute path".into())
}

/// A locator is written only for a journal using the fallback already selected
/// for this operation. It supplements the fixed search roots.
pub(in crate::v3) fn remember_location(source: &Path, root: &Path) -> Result<(), String> {
    if home_root().as_deref() != Some(root) {
        return Ok(());
    }
    validate_active_root(root)?;
    let anchor = root;
    let prepared = private_dir(anchor, ".location-prepare-")?;
    let raw = root.as_os_str().as_encoded_bytes();
    if raw.len() as u64 > LOCATION_LIMIT {
        return Err("Private recovery location exceeds its size limit".into());
    }
    write_input(prepared.path(), "root", raw)?;
    fs::rename(
        prepared.path().join("root"),
        anchor.join(location_name(source)),
    )
    .map_err(|error| format!("Publish private recovery location ({error})"))?;
    sync_dir(anchor)
}

pub(in crate::v3) fn forget_location(source: &Path) -> Result<(), String> {
    let Some(anchor) = home_root() else {
        return Ok(());
    };
    let locator = anchor.join(location_name(source));
    if present(&locator, true)? {
        TrustedJournal::open(output_parent_dir(&anchor))?;
        TrustedJournal::open(&anchor)?;
        fs::remove_file(&locator)
            .map_err(|error| format!("Retire private recovery location ({error})"))?;
        sync_dir(&anchor)?;
    }
    Ok(())
}

pub(in crate::v3) fn pending_location(source: &Path) -> Result<Option<PathBuf>, String> {
    lookup_location(source, true)
}

pub(super) fn lookup_location(
    source: &Path,
    require_recovery: bool,
) -> Result<Option<PathBuf>, String> {
    let anchor = home_root();
    let registered = match anchor.as_deref() {
        Some(anchor) => registered_root(anchor, source)?,
        None => None,
    };
    let mut roots: Vec<PathBuf> = [
        configured_root().ok(),
        default_root(),
        anchor,
        registered.clone(),
    ]
    .into_iter()
    .flatten()
    .map(|path| path.components().collect())
    .collect();
    roots.sort_unstable();
    roots.dedup();

    let key = source_key(source).to_hex();
    let mut pending: Option<PathBuf> = None;
    for root in roots {
        let candidate = root.join(key.as_str());
        let known = registered.as_deref() == Some(root.as_path());
        if present(&candidate, known)? {
            if require_recovery
                && !present(
                    &candidate.join(crate::v3::pending_pair::fresh::RECORD),
                    true,
                )?
                && !present(
                    &candidate.join(crate::v3::pending_pair::update::RECORD),
                    true,
                )?
            {
                continue;
            }
            if let Some(prior) = pending {
                return Err(format!(
                    "Conflicting private pair journals at {} and {}. Preserve both for recovery",
                    prior.display(),
                    candidate.display()
                ));
            }
            pending = Some(candidate);
        }
    }
    Ok(pending)
}
