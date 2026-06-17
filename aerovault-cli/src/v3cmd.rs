//! AEROVAULT3 container CLI surface (`aerovault vault ...`).
//!
//! Drives the crate's [`aerovault::v3`] sync API: create / list / add / extract /
//! the tree-mutation ops, and the rev-4 Error-Correction subset
//! (`scrub` / `repair` / `export-parity` / `strip-parity`). Every command honors
//! the global `--json` flag for machine-readable output. The legacy AEROVAULT2
//! container lives on the top-level commands (`create`, `list`, ...); this group
//! is AEROVAULT3 only.

// SPDX-License-Identifier: GPL-3.0-only

use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde_json::json;
use zeroize::Zeroize;

use aerovault::v3::{CreateOptionsV3, EntryInfo, OpenVaultV3, RecoveryPlacement, VaultV3};

use crate::{format_size, print_json, read_password, spinner};

/// Default rev-4 Error-Correction overhead (matches the crate default; the crate
/// clamps to its `[MIN, MAX]` window regardless).
const EC_DEFAULT_PCT: u32 = 20;

type CliResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum VaultCommands {
    /// Create a new empty AEROVAULT3 container.
    Create {
        /// Path for the new vault file.
        path: PathBuf,

        /// Container format. Only `v3` (AEROVAULT3) is created by this group;
        /// the legacy AEROVAULT2 container lives on the top-level `create`.
        #[arg(short = 'V', long = "format", default_value = "v3")]
        format: String,

        /// zstd compression level recorded on the container (default: 9).
        #[arg(long, default_value = "9")]
        zstd_level: i32,

        /// Add Reed-Solomon Error Correction (rev. 4): embedded | detached | both.
        #[arg(long = "error-correction", visible_alias = "ec")]
        error_correction: Option<String>,

        /// Error-Correction overhead percentage (5-50, default: 20). Only used
        /// with `--error-correction`.
        #[arg(long = "ec-pct", default_value_t = EC_DEFAULT_PCT)]
        ec_pct: u32,
    },

    /// Open a vault and list its contents.
    #[command(visible_alias = "ls")]
    List {
        /// Path to the vault file.
        path: PathBuf,

        /// Show sizes in human-readable format.
        #[arg(short = 'H', long)]
        human: bool,
    },

    /// Add files to a vault.
    Add {
        /// Path to the vault file.
        vault: PathBuf,

        /// Files to add.
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Target directory inside the vault.
        #[arg(long, default_value = "")]
        dir: String,
    },

    /// Recursively add a directory tree to a vault.
    AddDir {
        /// Path to the vault file.
        vault: PathBuf,

        /// Source directory on disk.
        source: PathBuf,

        /// Target prefix inside the vault (default: the vault root).
        #[arg(long)]
        prefix: Option<String>,
    },

    /// Extract entries from a vault.
    Extract {
        /// Path to the vault file.
        vault: PathBuf,

        /// Output directory (default: current directory).
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Specific entry to extract (omit for all).
        #[arg(short, long)]
        entry: Option<String>,
    },

    /// Create a directory inside a vault.
    Mkdir {
        /// Path to the vault file.
        vault: PathBuf,

        /// Directory name (e.g. "docs/notes").
        name: String,
    },

    /// Delete an entry from a vault.
    #[command(name = "rm")]
    Remove {
        /// Path to the vault file.
        vault: PathBuf,

        /// Entry name to delete.
        name: String,

        /// Recursively delete a non-empty directory subtree.
        #[arg(short, long)]
        recursive: bool,
    },

    /// Rename an entry in place.
    Rename {
        /// Path to the vault file.
        vault: PathBuf,

        /// Current entry name.
        from: String,

        /// New basename (single path segment).
        to: String,
    },

    /// Move an entry to another vault path.
    #[command(visible_alias = "mv")]
    Move {
        /// Path to the vault file.
        vault: PathBuf,

        /// Source entry path.
        from: String,

        /// Destination entry path.
        to: String,
    },

    /// Copy an entry to another vault path.
    #[command(visible_alias = "cp")]
    Copy {
        /// Path to the vault file.
        vault: PathBuf,

        /// Source entry path.
        from: String,

        /// Destination entry path.
        to: String,
    },

    /// Show vault information and recovery surfaces.
    Info {
        /// Path to the vault file.
        path: PathBuf,
    },

    /// Change vault password.
    #[command(name = "change-password", visible_alias = "passwd")]
    ChangePassword {
        /// Path to the vault file.
        path: PathBuf,
    },

    /// Check whether a file is an AEROVAULT3 container.
    Check {
        /// Path to check.
        path: PathBuf,
    },

    /// Verify every stored block against the manifest (read-only damage report).
    Scrub {
        /// Path to the vault file.
        path: PathBuf,
    },

    /// Repair damaged blocks from Error-Correction parity (all-or-nothing).
    Repair {
        /// Path to the vault file.
        path: PathBuf,

        /// Report what would be repaired without writing anything.
        #[arg(long)]
        dry_run: bool,

        /// Explicit parity source (default: detached sidecar, then embedded).
        #[arg(long)]
        parity: Option<PathBuf>,
    },

    /// Write a detached `.aerocorrect` recovery file for an existing vault.
    ExportParity {
        /// Path to the vault file.
        path: PathBuf,

        /// Output sidecar path (default: `<vault>.aerocorrect`).
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },

    /// Drop the embedded Error-Correction extension on the next seal.
    StripParity {
        /// Path to the vault file.
        path: PathBuf,

        /// Drop recovery even when no detached sidecar exists.
        #[arg(long)]
        force: bool,
    },
}

pub fn run(command: VaultCommands, json: bool) -> CliResult {
    match command {
        VaultCommands::Create {
            path,
            format,
            zstd_level,
            error_correction,
            ec_pct,
        } => cmd_create(
            &path,
            &format,
            zstd_level,
            error_correction.as_deref(),
            ec_pct,
            json,
        ),
        VaultCommands::List { path, human } => cmd_list(&path, human, json),
        VaultCommands::Add { vault, files, dir } => cmd_add(&vault, &files, &dir, json),
        VaultCommands::AddDir {
            vault,
            source,
            prefix,
        } => cmd_add_dir(&vault, &source, prefix.as_deref(), json),
        VaultCommands::Extract {
            vault,
            output,
            entry,
        } => cmd_extract(&vault, &output, entry.as_deref(), json),
        VaultCommands::Mkdir { vault, name } => cmd_mkdir(&vault, &name, json),
        VaultCommands::Remove {
            vault,
            name,
            recursive,
        } => cmd_remove(&vault, &name, recursive, json),
        VaultCommands::Rename { vault, from, to } => cmd_rename(&vault, &from, &to, json),
        VaultCommands::Move { vault, from, to } => cmd_move(&vault, &from, &to, json),
        VaultCommands::Copy { vault, from, to } => cmd_copy(&vault, &from, &to, json),
        VaultCommands::Info { path } => cmd_info(&path, json),
        VaultCommands::ChangePassword { path } => cmd_change_password(&path, json),
        VaultCommands::Check { path } => cmd_check(&path, json),
        VaultCommands::Scrub { path } => cmd_scrub(&path, json),
        VaultCommands::Repair {
            path,
            dry_run,
            parity,
        } => cmd_repair(&path, dry_run, parity.as_deref(), json),
        VaultCommands::ExportParity { path, out } => cmd_export_parity(&path, out.as_deref(), json),
        VaultCommands::StripParity { path, force } => cmd_strip_parity(&path, force, json),
    }
}

/// Open a vault, wiping the prompted password from memory before returning.
fn unlock(path: &Path) -> Result<OpenVaultV3, Box<dyn std::error::Error>> {
    let mut password = read_password("Password: ")?;
    let pb = spinner("Unlocking vault...");
    let result = VaultV3::open(path, &password);
    password.zeroize();
    pb.finish_and_clear();
    Ok(result?)
}

fn cmd_create(
    path: &Path,
    format: &str,
    zstd_level: i32,
    error_correction: Option<&str>,
    ec_pct: u32,
    json: bool,
) -> CliResult {
    if !format.trim().eq_ignore_ascii_case("v3") {
        return Err(format!(
            "this group creates AEROVAULT3 only (got --format {format}); use the top-level `create` for the legacy AEROVAULT2 container"
        )
        .into());
    }

    let mut password = read_password("Password: ")?;
    let mut confirm = read_password("Confirm password: ")?;
    if password != confirm {
        confirm.zeroize();
        password.zeroize();
        return Err("passwords do not match".into());
    }
    confirm.zeroize();

    let placement = match error_correction {
        Some(p) => Some(RecoveryPlacement::parse(p)?),
        None => None,
    };

    let pb = spinner("Creating vault...");
    let opts = CreateOptionsV3::new(path, password.clone()).with_zstd_level(zstd_level);
    password.zeroize();

    let result = match placement {
        Some(p) => VaultV3::create_with_error_correction(&opts, p, ec_pct),
        None => VaultV3::create(&opts),
    };
    result?;
    pb.finish_and_clear();

    let ec_str = placement.map(placement_str);
    if json {
        print_json(&json!({
            "status": "created",
            "path": path.display().to_string(),
            "format": "AEROVAULT3",
            "revision": if placement.is_some() { 4 } else { 3 },
            "zstd_level": zstd_level,
            "error_correction": ec_str,
            "error_correction_pct": placement.map(|_| ec_pct),
        }))?;
    } else {
        println!("Vault created");
        println!("  Path: {}", path.display());
        println!(
            "  Format: AEROVAULT3 (rev. {})",
            if placement.is_some() { 4 } else { 3 }
        );
        println!("  Compression: zstd level {zstd_level}");
        match ec_str {
            Some(p) => println!("  Error correction: {p} ({ec_pct}% overhead)"),
            None => println!("  Error correction: none"),
        }
    }
    Ok(())
}

fn cmd_list(path: &Path, human: bool, json: bool) -> CliResult {
    let vault = unlock(path)?;
    let entries = VaultV3::list(&vault);

    if json {
        let items: Vec<_> = entries
            .iter()
            .map(|e| {
                json!({
                    "path": e.path,
                    "size": e.size,
                    "is_dir": e.is_dir,
                    "modified": e.modified,
                })
            })
            .collect();
        print_json(&json!({ "entries": items, "count": entries.len() }))?;
        return Ok(());
    }

    if entries.is_empty() {
        println!("(empty vault)");
        return Ok(());
    }

    println!("{:<8} {:<12} {:<22} NAME", "TYPE", "SIZE", "MODIFIED");
    println!("{}", "-".repeat(62));
    for entry in &entries {
        println!(
            "{:<8} {:<12} {:<22} {}",
            if entry.is_dir { "DIR" } else { "FILE" },
            size_cell(entry, human),
            entry.modified,
            entry.path
        );
    }
    println!("\n{} entries", entries.len());
    Ok(())
}

fn size_cell(entry: &EntryInfo, human: bool) -> String {
    if entry.is_dir {
        "-".to_string()
    } else if human {
        format_size(entry.size)
    } else {
        entry.size.to_string()
    }
}

fn cmd_add(vault: &Path, files: &[PathBuf], dir: &str, json: bool) -> CliResult {
    let mut v = unlock(vault)?;
    let pb = spinner("Adding files...");
    if dir.is_empty() {
        let sources: Vec<(PathBuf, String)> = files
            .iter()
            .map(|f| {
                let name = f
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (f.clone(), name)
            })
            .collect();
        VaultV3::add_files(&mut v, &sources)?;
    } else {
        VaultV3::add_files_to_dir(&mut v, files, dir)?;
    }
    pb.finish_and_clear();

    let added = files.len();
    if json {
        print_json(&json!({ "status": "added", "files": added, "dir": dir }))?;
    } else {
        println!("{added} file(s) added");
    }
    Ok(())
}

fn cmd_add_dir(vault: &Path, source: &Path, prefix: Option<&str>, json: bool) -> CliResult {
    let mut v = unlock(vault)?;
    let pb = spinner("Adding directory...");
    let (files, dirs) = VaultV3::add_directory(&mut v, source, prefix)?;
    pb.finish_and_clear();

    if json {
        print_json(&json!({ "status": "added", "files": files, "directories": dirs }))?;
    } else {
        println!("{files} file(s), {dirs} directory(ies) added");
    }
    Ok(())
}

fn cmd_extract(vault: &Path, output: &Path, entry: Option<&str>, json: bool) -> CliResult {
    let v = unlock(vault)?;
    if let Some(name) = entry {
        let pb = spinner("Extracting...");
        let dest = VaultV3::extract_entry(&v, name, output)?;
        pb.finish_and_clear();
        if json {
            print_json(
                &json!({ "status": "extracted", "entry": name, "path": dest.display().to_string() }),
            )?;
        } else {
            println!("Extracted to {}", dest.display());
        }
    } else {
        let pb = spinner("Extracting all...");
        let count = VaultV3::extract_all(&v, output)?;
        pb.finish_and_clear();
        if json {
            print_json(
                &json!({ "status": "extracted", "files": count, "output": output.display().to_string() }),
            )?;
        } else {
            println!("{count} entries extracted to {}", output.display());
        }
    }
    Ok(())
}

fn cmd_mkdir(vault: &Path, name: &str, json: bool) -> CliResult {
    let mut v = unlock(vault)?;
    VaultV3::create_directory(&mut v, name)?;
    if json {
        print_json(&json!({ "status": "created", "directory": name }))?;
    } else {
        println!("Directory created: {name}");
    }
    Ok(())
}

fn cmd_remove(vault: &Path, name: &str, recursive: bool, json: bool) -> CliResult {
    let mut v = unlock(vault)?;
    let removed = if recursive {
        VaultV3::delete_entries(&mut v, std::slice::from_ref(&name.to_string()), true)?
    } else {
        VaultV3::delete_entry(&mut v, name)?
    };
    if json {
        print_json(&json!({ "status": "deleted", "entry": name, "removed": removed }))?;
    } else {
        println!(
            "Deleted: {name} ({removed} entr{} removed)",
            if removed == 1 { "y" } else { "ies" }
        );
    }
    Ok(())
}

fn cmd_rename(vault: &Path, from: &str, to: &str, json: bool) -> CliResult {
    let mut v = unlock(vault)?;
    VaultV3::rename_entry(&mut v, from, to)?;
    report_move("renamed", from, to, json)
}

fn cmd_move(vault: &Path, from: &str, to: &str, json: bool) -> CliResult {
    let mut v = unlock(vault)?;
    VaultV3::move_entry(&mut v, from, to)?;
    report_move("moved", from, to, json)
}

fn cmd_copy(vault: &Path, from: &str, to: &str, json: bool) -> CliResult {
    let mut v = unlock(vault)?;
    VaultV3::copy_entry(&mut v, from, to)?;
    report_move("copied", from, to, json)
}

fn report_move(status: &str, from: &str, to: &str, json: bool) -> CliResult {
    if json {
        print_json(&json!({ "status": status, "from": from, "to": to }))?;
    } else {
        println!("{}: {from} -> {to}", capitalize(status));
    }
    Ok(())
}

fn cmd_info(path: &Path, json: bool) -> CliResult {
    let peek = VaultV3::peek(path)?;
    let recovery = VaultV3::recovery_status(path)?;
    let vault = unlock(path)?;
    let entries = VaultV3::list(&vault);
    let total: u64 = entries.iter().map(|e| e.size).sum();
    let dirs = entries.iter().filter(|e| e.is_dir).count();
    let files = entries.len() - dirs;

    if json {
        print_json(&json!({
            "format": "AEROVAULT3",
            "version": peek.version,
            "file_len": peek.file_len,
            "data_len": peek.data_len,
            "manifest_len": peek.manifest_len,
            "files": files,
            "directories": dirs,
            "total_original_size": total,
            "error_correction": {
                "embedded": recovery.embedded,
                "detached": recovery.detached,
                "any": recovery.any,
                "manifest_parity": recovery.manifest_parity,
                "header_parity": recovery.header_parity,
            },
        }))?;
        return Ok(());
    }

    println!("Format: AEROVAULT3 (on-disk version {})", peek.version);
    println!("File size: {}", format_size(peek.file_len));
    println!("Data section: {}", format_size(peek.data_len));
    println!("Manifest: {}", format_size(peek.manifest_len));
    println!("Files: {files}");
    println!("Directories: {dirs}");
    println!("Total original size: {}", format_size(total));
    println!(
        "Error correction: {}",
        if recovery.any {
            let mut parts = Vec::new();
            if recovery.embedded {
                parts.push("embedded");
            }
            if recovery.detached {
                parts.push("detached sidecar");
            }
            parts.join(" + ")
        } else {
            "none".to_string()
        }
    );
    Ok(())
}

fn cmd_change_password(path: &Path, json: bool) -> CliResult {
    let mut old_password = read_password("Current password: ")?;
    let pb = spinner("Unlocking vault...");
    let opened = VaultV3::open(path, &old_password);
    old_password.zeroize();
    pb.finish_and_clear();
    let mut vault = opened?;

    let mut new_password = read_password("New password: ")?;
    let mut confirm = read_password("Confirm new password: ")?;
    if new_password != confirm {
        confirm.zeroize();
        new_password.zeroize();
        return Err("passwords do not match".into());
    }
    confirm.zeroize();

    let pb = spinner("Changing password...");
    let result = VaultV3::change_password(&mut vault, &new_password);
    new_password.zeroize();
    result?;
    pb.finish_and_clear();

    if json {
        print_json(&json!({ "status": "password_changed", "path": path.display().to_string() }))?;
    } else {
        println!("Password changed");
    }
    Ok(())
}

fn cmd_check(path: &Path, json: bool) -> CliResult {
    let is_v3 = VaultV3::is_vault_v3(path);
    if json {
        print_json(&json!({ "path": path.display().to_string(), "aerovault3": is_v3 }))?;
    } else if is_v3 {
        println!("{}: AEROVAULT3 container", path.display());
    } else {
        println!("{}: not an AEROVAULT3 container", path.display());
    }
    if !is_v3 {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_scrub(path: &Path, json: bool) -> CliResult {
    let vault = unlock(path)?;
    let pb = spinner("Scrubbing...");
    let damaged = VaultV3::scrub(&vault);
    pb.finish_and_clear();

    if json {
        let items: Vec<_> = damaged
            .iter()
            .map(|d| {
                json!({
                    "chunk_id": d.record.id,
                    "block_index": d.record.block_index,
                    "on_disk_start": d.on_disk_start,
                    "on_disk_len": d.on_disk_len,
                })
            })
            .collect();
        print_json(&json!({
            "verified": damaged.is_empty(),
            "damaged_blocks": items,
            "damaged_count": damaged.len(),
        }))?;
    } else if damaged.is_empty() {
        println!("Verified: all blocks match the manifest");
    } else {
        println!("Corruption detected in {} block(s):", damaged.len());
        for d in &damaged {
            println!(
                "  block {} (chunk {}) at offset {}",
                d.record.block_index, d.record.id, d.on_disk_start
            );
        }
        println!("Run `vault repair` to recover from Error-Correction parity.");
    }
    if !damaged.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_repair(path: &Path, dry_run: bool, parity: Option<&Path>, json: bool) -> CliResult {
    let mut vault = unlock(path)?;
    let pb = spinner(if dry_run {
        "Checking repair..."
    } else {
        "Repairing..."
    });
    let (repaired, source) = VaultV3::repair(&mut vault, dry_run, parity)?;
    pb.finish_and_clear();

    if json {
        print_json(&json!({
            "status": if dry_run { "dry_run" } else { "repaired" },
            "repaired_blocks": repaired,
            "parity_source": source.as_str(),
            "dry_run": dry_run,
        }))?;
    } else if repaired == 0 {
        println!("No repair needed: all blocks already verify");
    } else if dry_run {
        println!(
            "{repaired} block(s) would be repaired from {} parity (dry run, nothing written)",
            source.as_str()
        );
    } else {
        println!(
            "Repaired {repaired} block(s) from {} parity",
            source.as_str()
        );
    }
    Ok(())
}

fn cmd_export_parity(path: &Path, out: Option<&Path>, json: bool) -> CliResult {
    let mut password = read_password("Password: ")?;
    let pb = spinner("Exporting parity...");
    let result = VaultV3::export_parity(path, &password, out);
    password.zeroize();
    pb.finish_and_clear();
    let result = result?;

    if json {
        print_json(&json!({
            "status": "exported",
            "path": result.path.display().to_string(),
            "shards": result.shards,
            "bytes_protected": result.bytes_protected,
            "overhead_pct": result.overhead_pct,
            "payload_len": result.payload_len,
            "file_len": result.file_len,
            "header_parity_len": result.header_parity_len,
            "manifest_parity_len": result.manifest_parity_len,
        }))?;
    } else {
        println!(
            "Wrote {} ({}, {:.1}% overhead, {} shards protecting {})",
            result.path.display(),
            format_size(result.file_len),
            result.overhead_pct,
            result.shards,
            format_size(result.bytes_protected),
        );
    }
    Ok(())
}

fn cmd_strip_parity(path: &Path, force: bool, json: bool) -> CliResult {
    let mut password = read_password("Password: ")?;
    let pb = spinner("Stripping embedded parity...");
    let result = VaultV3::strip_parity(path, &password, force);
    password.zeroize();
    pb.finish_and_clear();
    let result = result?;

    if json {
        print_json(&json!({
            "status": "stripped",
            "detached_sidecar_present": result.sidecar_present,
            "sidecar_path": result.sidecar_path.display().to_string(),
        }))?;
    } else {
        println!("Embedded Error-Correction parity removed");
        if result.sidecar_present {
            println!(
                "  Detached recovery remains: {}",
                result.sidecar_path.display()
            );
        } else {
            println!("  Warning: no detached recovery remains for this vault");
        }
    }
    Ok(())
}

fn placement_str(p: RecoveryPlacement) -> &'static str {
    match p {
        RecoveryPlacement::Embedded => "embedded",
        RecoveryPlacement::Detached => "detached",
        RecoveryPlacement::Both => "both",
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
