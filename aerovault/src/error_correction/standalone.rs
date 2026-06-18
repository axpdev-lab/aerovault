use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use super::sidecar::{
    aerocorrect_windows, validate_window_tiling_iter, AeroCorrectSegment, AeroCorrectSidecar,
    AeroCorrectSidecarReader, AEROCORRECT_WINDOW_SIZE,
};
use super::{
    compute_error_correction_shards_grid, error_correction_grid, reconstruct_from_error_correction,
};

/// Default per-file cap for standalone Error Correction. Generation and repair stream
/// in windows, but the cap keeps accidental huge explicit runs bounded for CLI users.
pub(crate) const STANDALONE_EC_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

const HASH_READ_CHUNK: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct StandaloneEcGeneratedSidecar {
    pub(crate) sidecar_bytes: Vec<u8>,
    pub(crate) file_size: u64,
    pub(crate) shards: u64,
    pub(crate) overhead_pct: f64,
    pub(crate) sidecar_len: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum StandaloneEcGenerateResult {
    Generated(StandaloneEcGeneratedSidecar),
    SkippedTooLarge { file_size: u64, max_file_size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandaloneEcRepairResult {
    Verified,
    Repaired { recovered_shards: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StandaloneVerifyResult {
    Verified,
    NeedsRepair,
}

fn finalize_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash_file_streaming(path: &Path) -> Result<[u8; 32], String> {
    let mut file =
        File::open(path).map_err(|e| format!("open {} for hashing: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_READ_CHUNK];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {} for hashing: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(finalize_sha256(hasher))
}

fn generated_from(
    sidecar: AeroCorrectSidecar,
    file_size: u64,
    shards: u64,
    avec_payload_len: u64,
) -> StandaloneEcGeneratedSidecar {
    let sidecar_bytes = sidecar.to_bytes();
    let overhead_pct = if file_size > 0 {
        (avec_payload_len as f64 / file_size as f64) * 100.0
    } else {
        0.0
    };
    StandaloneEcGeneratedSidecar {
        sidecar_len: sidecar_bytes.len() as u64,
        sidecar_bytes,
        file_size,
        shards,
        overhead_pct,
    }
}

pub(crate) fn generate_sidecar_for_file_capped(
    rel_path: &str,
    path: &Path,
    pct: u32,
    max_file_size: u64,
) -> Result<StandaloneEcGenerateResult, String> {
    generate_sidecar_for_file_capped_windowed(
        rel_path,
        path,
        pct,
        max_file_size,
        AEROCORRECT_WINDOW_SIZE,
    )
}

/// Stream a file into a deterministic `.aerocorrect` sidecar. The relative path is
/// accepted for caller diagnostics only; the sidecar binds solely to content SHA-256.
fn generate_sidecar_for_file_capped_windowed(
    _rel_path: &str,
    path: &Path,
    pct: u32,
    max_file_size: u64,
    window: u64,
) -> Result<StandaloneEcGenerateResult, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("read metadata for {}: {e}", path.display()))?;
    let file_size = metadata.len();
    if file_size > max_file_size {
        return Ok(StandaloneEcGenerateResult::SkippedTooLarge {
            file_size,
            max_file_size,
        });
    }

    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let (k, p) = error_correction_grid(pct);
    let mut hasher = Sha256::new();
    let mut segments = Vec::new();
    let mut total_shards = 0u64;
    let mut total_avec = 0u64;

    for (off, len) in aerocorrect_windows(file_size, window) {
        let window_len =
            usize::try_from(len).map_err(|_| format!("window length {len} exceeds usize"))?;
        let mut buf = vec![0u8; window_len];
        file.read_exact(&mut buf).map_err(|e| {
            format!(
                "read Error Correction source window at {off} (+{len}) of {}: {e}",
                path.display()
            )
        })?;
        hasher.update(&buf);
        let (avec_bytes, shards, _protected, _overhead) =
            compute_error_correction_shards_grid(&[&buf], k, p);
        total_shards += shards;
        total_avec += avec_bytes.len() as u64;
        segments.push(AeroCorrectSegment {
            window_offset: off,
            window_len: len,
            avec_bytes,
        });
    }

    let file_sha256 = finalize_sha256(hasher);
    let sidecar = AeroCorrectSidecar::new(file_sha256, file_size, segments);
    Ok(StandaloneEcGenerateResult::Generated(generated_from(
        sidecar,
        file_size,
        total_shards,
        total_avec,
    )))
}

fn validate_reader_for_path(
    rel_path: &str,
    path: &Path,
    reader: &AeroCorrectSidecarReader,
) -> Result<[u8; 32], String> {
    let expected = reader.content_sha256;
    reader.verify_binding(&expected).map_err(|e| {
        format!("aerocorrect sidecar for {rel_path} is internally inconsistent: {e}")
    })?;
    let file_size = std::fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if reader.total_len != file_size {
        return Err(format!(
            "aerocorrect sidecar total length {} != file length {file_size} for {rel_path}",
            reader.total_len
        ));
    }
    validate_window_tiling_iter(
        reader
            .segments()
            .iter()
            .map(|s| (s.window_offset, s.window_len)),
        file_size,
    )
    .map_err(|e| format!("aerocorrect sidecar for {rel_path}: {e}"))?;
    Ok(expected)
}

pub(crate) fn verify_standalone_file_streamed(
    rel_path: &str,
    path: &Path,
    sidecar_path: &Path,
) -> Result<StandaloneVerifyResult, String> {
    let reader = AeroCorrectSidecarReader::open(sidecar_path)?;
    let expected = validate_reader_for_path(rel_path, path, &reader)?;
    if hash_file_streaming(path)? == expected {
        Ok(StandaloneVerifyResult::Verified)
    } else {
        Ok(StandaloneVerifyResult::NeedsRepair)
    }
}

/// Repair a standalone file from an on-disk `.aerocorrect` sidecar. The sidecar's
/// content SHA-256 is the expected good hash and the reconstruction TARGET. The
/// original file is replaced only after every window has been repaired and the full
/// repaired stream hashes back to that expected value.
///
/// Trust model (audit M3): the sidecar's declared content hash is the reconstruction
/// target, so a *bare* `.aerocorrect` repair reconstructs toward WHATEVER the sidecar
/// declares. This makes standalone `correct` an INTEGRITY tool (recover the content the
/// sidecar was made for), not an AUTHENTICITY one (prove that content is the one you
/// want). A planted sidecar for attacker-chosen same-length content would drive the
/// repair toward that content and report success. Where a higher layer authenticates
/// (the vault path re-verifies against the header-MAC / manifest `cipher_hash`), this
/// is moot. For the bare CLI, pass `expect_sha256` (an out-of-band good hash, e.g.
/// `--expect-sha256`) to anchor authenticity: a sidecar whose declared hash differs is
/// refused before any write.
pub(crate) fn verify_repair_standalone_file_streamed(
    rel_path: &str,
    path: &Path,
    sidecar_path: &Path,
    expect_sha256: Option<&[u8; 32]>,
) -> Result<StandaloneEcRepairResult, String> {
    let mut reader = AeroCorrectSidecarReader::open(sidecar_path)?;
    let expected = validate_reader_for_path(rel_path, path, &reader)?;
    // M3 authenticity anchor: if the caller supplied an out-of-band expected hash,
    // refuse a sidecar that declares a different target before touching the file.
    if let Some(anchor) = expect_sha256 {
        if anchor != &expected {
            return Err(format!(
                "aerocorrect sidecar for {rel_path} declares a content hash that does not match the expected (anchored) hash; refusing repair"
            ));
        }
    }
    if hash_file_streaming(path)? == expected {
        return Ok(StandaloneEcRepairResult::Verified);
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        format!(
            "create Error Correction repair temp in {}: {e}",
            parent.display()
        )
    })?;
    let mut src = File::open(path)
        .map_err(|e| format!("open Error Correction target {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut recovered_shards = 0usize;

    {
        let mut out = std::io::BufWriter::new(tmp.as_file());
        let segment_count = reader.segments().len();
        for idx in 0..segment_count {
            let window_len = usize::try_from(reader.segments()[idx].window_len)
                .map_err(|_| format!("window {idx} length exceeds usize"))?;
            let avec = reader.read_segment_avec(idx)?;
            let mut buf = vec![0u8; window_len];
            src.read_exact(&mut buf).map_err(|e| {
                format!(
                    "read Error Correction target window {}: {e}",
                    path.display()
                )
            })?;
            let mut blocks = vec![buf];
            recovered_shards += reconstruct_from_error_correction(&mut blocks, &avec)?;
            hasher.update(&blocks[0]);
            out.write_all(&blocks[0]).map_err(|e| {
                format!("write Error Correction repair temp {}: {e}", path.display())
            })?;
        }
        out.flush()
            .map_err(|e| format!("flush Error Correction repair temp {}: {e}", path.display()))?;
    }

    if finalize_sha256(hasher) != expected {
        return Err("Error Correction repair failed post-repair SHA-256 verification".to_string());
    }
    // Release the read handle on the target before persisting. On Windows, renaming the
    // repaired temp onto a file that still has a live read handle fails with
    // ERROR_ACCESS_DENIED (os error 5), which left the original corrupt and the repair
    // non-functional on the primary desktop OS (audit M1). The reconstruct loop above is
    // the only reader of `src`, so the handle is safe to drop here.
    drop(src);
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(tmp.path(), meta.permissions());
    }
    // On a persist failure, recover the NamedTempFile from the error and delete it so a
    // decrypted-plaintext `.tmp*` is never left beside the target (audit M1 plaintext-at-rest).
    tmp.persist(path).map_err(|e| {
        let msg = format!(
            "persist repaired Error Correction target {}: {}",
            path.display(),
            e.error
        );
        let _ = e.file.close();
        msg
    })?;
    Ok(StandaloneEcRepairResult::Repaired { recovered_shards })
}

#[cfg(test)]
mod tests {
    use super::super::sidecar::estimate_windowed_sidecar_len;
    use super::*;

    fn sample_data(len: usize) -> Vec<u8> {
        let mut seed = *blake3::hash(b"aerovault-standalone-ec-seed").as_bytes();
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            seed = *blake3::hash(&seed).as_bytes();
            out.extend_from_slice(&seed);
        }
        out.truncate(len);
        out
    }

    #[test]
    fn generation_repairs_multiple_windows_streaming() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let sidecar_path = dir.path().join("payload.bin.aerocorrect");
        std::fs::write(&path, &data).unwrap();

        let generated = match generate_sidecar_for_file_capped_windowed(
            "payload.bin",
            &path,
            20,
            STANDALONE_EC_MAX_FILE_SIZE,
            window,
        )
        .unwrap()
        {
            StandaloneEcGenerateResult::Generated(g) => g,
            other => panic!("should generate, got {other:?}"),
        };
        assert_eq!(
            generated.sidecar_len,
            estimate_windowed_sidecar_len(data.len() as u64, 20, window)
        );
        assert!(generated.sidecar_len > data.len() as u64 / 10);
        std::fs::write(&sidecar_path, &generated.sidecar_bytes).unwrap();

        let mut corrupt = data.clone();
        for off in [5_000usize, 50_000, 100_000, 130_000] {
            corrupt[off] ^= 0xA5;
        }
        std::fs::write(&path, &corrupt).unwrap();

        let result = verify_repair_standalone_file_streamed("payload.bin", &path, &sidecar_path, None)
            .expect("streamed repair should succeed");
        assert!(matches!(result, StandaloneEcRepairResult::Repaired { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), data);

        assert_eq!(
            verify_standalone_file_streamed("payload.bin", &path, &sidecar_path).unwrap(),
            StandaloneVerifyResult::Verified
        );
    }

    /// Audit M1 regression: on Windows the target read handle used to be held across
    /// `persist`, which failed the rename (os error 5) and left a decrypted-plaintext
    /// `.tmp*` beside the target. After the fix the repair must succeed, restore the
    /// original bytes, and leave no temp artifact in the directory.
    #[test]
    fn repair_restores_and_leaves_no_temp_artifact() {
        let window = 40_000u64;
        let data = sample_data(135_000);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let sidecar_path = dir.path().join("payload.bin.aerocorrect");
        std::fs::write(&path, &data).unwrap();

        let generated = match generate_sidecar_for_file_capped_windowed(
            "payload.bin",
            &path,
            20,
            STANDALONE_EC_MAX_FILE_SIZE,
            window,
        )
        .unwrap()
        {
            StandaloneEcGenerateResult::Generated(g) => g,
            other => panic!("should generate, got {other:?}"),
        };
        std::fs::write(&sidecar_path, &generated.sidecar_bytes).unwrap();

        let mut corrupt = data.clone();
        for off in [5_000usize, 50_000, 100_000, 130_000] {
            corrupt[off] ^= 0xA5;
        }
        std::fs::write(&path, &corrupt).unwrap();

        let result = verify_repair_standalone_file_streamed("payload.bin", &path, &sidecar_path, None)
            .expect("streamed repair should succeed on every OS");
        assert!(matches!(result, StandaloneEcRepairResult::Repaired { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), data, "repair must restore bytes");

        // No leftover temp file (NamedTempFile prefix or any stray entry) beside the target.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "payload.bin" && n != "payload.bin.aerocorrect")
            .collect();
        assert!(
            leftovers.is_empty(),
            "repair must not leave a temp artifact, found: {leftovers:?}"
        );
    }

    #[test]
    fn foreign_sidecar_repair_fails_closed() {
        let data = sample_data(80_000);
        let other = sample_data(80_000)
            .into_iter()
            .map(|b| b ^ 0x33)
            .collect::<Vec<_>>();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        let other_path = dir.path().join("other.bin");
        let sidecar_path = dir.path().join("other.bin.aerocorrect");
        std::fs::write(&path, &data).unwrap();
        std::fs::write(&other_path, &other).unwrap();

        let generated = match generate_sidecar_for_file_capped(
            "other.bin",
            &other_path,
            20,
            STANDALONE_EC_MAX_FILE_SIZE,
        )
        .unwrap()
        {
            StandaloneEcGenerateResult::Generated(g) => g,
            other => panic!("should generate, got {other:?}"),
        };
        std::fs::write(&sidecar_path, &generated.sidecar_bytes).unwrap();

        let before = std::fs::read(&path).unwrap();
        let err = verify_repair_standalone_file_streamed("payload.bin", &path, &sidecar_path, None)
            .expect_err("foreign sidecar must fail closed");
        assert!(err.contains("post-repair SHA-256"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
