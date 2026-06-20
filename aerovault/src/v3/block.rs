//! AEROVAULT3 block + file assembly. The data section is a sequence of
//! `[block_len: u64 LE][ciphertext]` records starting at `DATA_OFFSET`; the file
//! is `header | data | encrypted manifest | extension dir JSON | extension
//! payloads`, with all offsets/lengths recorded in the (MAC-covered) header.
//! Byte-for-byte port of the app `build_file_bytes` / section reader.

// SPDX-License-Identifier: GPL-3.0-only

use std::io::{Read, Seek, SeekFrom};

use super::constants::{
    DATA_OFFSET, ERROR_CORRECTION_ALGORITHM_ID, ERROR_CORRECTION_ALGORITHM_VERSION,
    ERROR_CORRECTION_EXTENSION_ID, ERROR_CORRECTION_META_EXTENSION_ID, HEADER_SIZE, MAC_SIZE,
};
use super::format::VaultHeaderV3;
use super::manifest::{
    encrypt_manifest, manifest_is_plaintext, serialize_manifest_plaintext, ExtensionEntryV3,
    VaultManifestV3,
};
use crate::aerocrypt::KEY_SIZE;
use crate::error_correction::{
    compute_error_correction_shards_grid, manifest_error_correction_grid,
};

/// Read a `[offset, offset+len)` window from `reader`, rejecting `len > cap`
/// before allocating (DoS guard).
pub fn read_section<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    len: u64,
    cap: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    if len > cap {
        return Err(format!("{label} too large: {len} bytes"));
    }
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Seek {label}: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| format!("Read {label}: {e}"))?;
    Ok(buf)
}

/// Assemble the full on-disk container bytes.
///
/// `extension_payloads` is the raw payload area; each entry's `offset`/`length`
/// are relative to it. Offsets are recomputed here, then the header MAC is
/// stamped over the finished header. The Error-Correction-metadata extension
/// auto-injection (when a data-parity extension is present) is wired in T6;
/// rev. 3 containers carry no extensions, so the output is
/// `header | data | manifest | "[]" | (empty)`.
pub fn build_file_bytes(
    mut header: VaultHeaderV3,
    mac_key: &[u8; KEY_SIZE],
    master_key: &[u8; KEY_SIZE],
    manifest: &VaultManifestV3,
    extensions: &[ExtensionEntryV3],
    extension_payloads: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    // The manifest blob is encrypted on the standard lane and stored as plaintext
    // JSON on the `.aerozip` lane (#7). Either way it is the blob the header
    // offsets address and Error Correction protects below; the variable name is
    // historical. `manifest_is_plaintext` (the `crypt` wrapper) is the single
    // source of truth, so this matches the header's FLAG_PLAINTEXT_CONTENT.
    let encrypted_manifest = if manifest_is_plaintext(manifest) {
        serialize_manifest_plaintext(manifest)?
    } else {
        encrypt_manifest(master_key, manifest)?
    };

    // GAP-4 (rev. 4): when Error Correction is enabled (the data-block parity
    // extension is present), also protect the locator. The per-block cipher_hash
    // that scrub reads lives inside the encrypted manifest, so a corrupted
    // manifest would leave scrub with no map to repair from. Compute a fixed-rate
    // Reed-Solomon parity over the encrypted manifest bytes (manifest treated as
    // one block) and store it as a second non-critical extension, rebuilt on
    // every seal. It is located via the MAC-verified header (whose offsets
    // survive a manifest hit), so repair can rebuild the manifest before reading
    // any cipher_hash. build_file_bytes is the sole author: any inbound
    // ERROR_CORRECTION_META_EXTENSION_ID is dropped and recomputed here.
    let mut extensions: Vec<ExtensionEntryV3> = extensions
        .iter()
        .filter(|e| e.extension_id != ERROR_CORRECTION_META_EXTENSION_ID)
        .cloned()
        .collect();
    let mut extension_payloads = extension_payloads.to_vec();
    if extensions
        .iter()
        .any(|e| e.extension_id == ERROR_CORRECTION_EXTENSION_ID)
    {
        let (k, p) = manifest_error_correction_grid(manifest.error_correction_pct);
        let (meta_payload, _shards, _prot, _ov) =
            compute_error_correction_shards_grid(&[&encrypted_manifest], k, p);
        extensions.push(ExtensionEntryV3 {
            extension_id: ERROR_CORRECTION_META_EXTENSION_ID.to_string(),
            algorithm_id: ERROR_CORRECTION_ALGORITHM_ID.to_string(),
            algorithm_version: ERROR_CORRECTION_ALGORITHM_VERSION,
            critical: false,
            offset: extension_payloads.len() as u64,
            length: meta_payload.len() as u64,
        });
        extension_payloads.extend_from_slice(&meta_payload);
    }

    let extension_dir =
        serde_json::to_vec(&extensions).map_err(|e| format!("Extension serialize: {e}"))?;

    header.data_offset = DATA_OFFSET;
    header.data_len = data.len() as u64;
    header.manifest_offset = DATA_OFFSET + header.data_len;
    header.manifest_len = encrypted_manifest.len() as u64;
    header.extension_dir_offset = header.manifest_offset + header.manifest_len;
    header.extension_dir_len = extension_dir.len() as u64;
    header.extension_payload_offset = header.extension_dir_offset + header.extension_dir_len;
    header.extension_payload_len = extension_payloads.len() as u64;
    header.header_mac = [0u8; MAC_SIZE];
    header.header_mac = header.compute_mac(mac_key)?;

    let mut out = Vec::with_capacity(
        HEADER_SIZE
            + data.len()
            + encrypted_manifest.len()
            + extension_dir.len()
            + extension_payloads.len(),
    );
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&encrypted_manifest);
    out.extend_from_slice(&extension_dir);
    out.extend_from_slice(&extension_payloads);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aerocrypt::{random_array, SALT_SIZE, WRAPPED_KEY_SIZE};
    use crate::v3::format::{read_u64, VaultHeaderV3};
    use crate::v3::manifest::empty_manifest;
    use std::io::Cursor;

    fn blank_header() -> VaultHeaderV3 {
        VaultHeaderV3 {
            flags: 0,
            salt: [0x01; SALT_SIZE],
            wrapped_master_key: [0x02; WRAPPED_KEY_SIZE],
            wrapped_mac_key: [0x03; WRAPPED_KEY_SIZE],
            data_offset: 0,
            data_len: 0,
            manifest_offset: 0,
            manifest_len: 0,
            extension_dir_offset: 0,
            extension_dir_len: 0,
            extension_payload_offset: 0,
            extension_payload_len: 0,
            wrapper_header_version: 1,
            header_mac: [0u8; MAC_SIZE],
        }
    }

    #[test]
    fn assembly_layout_and_reopen() {
        let master = random_array::<KEY_SIZE>();
        let mac = random_array::<KEY_SIZE>();
        let manifest = empty_manifest(9);
        let data = vec![0xABu8; 4096];

        let bytes =
            build_file_bytes(blank_header(), &mac, &master, &manifest, &[], &[], &data).unwrap();

        // Header offsets describe the real layout.
        let h = VaultHeaderV3::from_bytes(&bytes).unwrap();
        assert_eq!(h.data_offset, DATA_OFFSET);
        assert_eq!(h.data_len, 4096);
        assert_eq!(h.manifest_offset, DATA_OFFSET + 4096);
        assert_eq!(h.extension_dir_offset, h.manifest_offset + h.manifest_len);
        // Empty extension dir is the 2-byte "[]".
        assert_eq!(h.extension_dir_len, 2);
        assert_eq!(h.extension_payload_len, 0);
        assert!(h.verify_mac(&mac).is_ok());

        // The recorded extension-dir window really is "[]".
        let dir_start = h.extension_dir_offset as usize;
        assert_eq!(&bytes[dir_start..dir_start + 2], b"[]");

        // read_section round-trips the data block.
        let mut cur = Cursor::new(&bytes);
        let got = read_section(&mut cur, h.data_offset, h.data_len, u64::MAX, "data").unwrap();
        assert_eq!(got, data);

        // total length is exactly header+data+manifest+dir+payload.
        let expected = HEADER_SIZE as u64
            + h.data_len
            + h.manifest_len
            + h.extension_dir_len
            + h.extension_payload_len;
        assert_eq!(bytes.len() as u64, expected);
        let _ = read_u64(&bytes, 128);
    }
}
