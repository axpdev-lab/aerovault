//! AEROVAULT3 1024-byte header: layout, serialize/deserialize, HMAC-SHA512
//! integrity, and the base-KEK -> (master KEK, MAC KEK) derivation. Byte-for-byte
//! port of the AeroFTP app (`aerovault_v3.rs`). The exact field offsets and the
//! "MAC over the full header with the MAC field zeroed" rule are part of the
//! on-disk contract (T5).

// SPDX-License-Identifier: GPL-3.0-only

use hmac::{Hmac, Mac};
use sha2::Sha512;

use super::constants::{
    AEROVZ_MAC_IKM, HEADER_MAC_OFFSET, HEADER_SIZE, HKDF_AEROVZ_MAC, HKDF_MAC, HKDF_MASTER,
    MAC_SIZE, MAGIC, VERSION,
};
use crate::aerocrypt::{hkdf_expand, KEY_SIZE, SALT_SIZE, WRAPPED_KEY_SIZE};

pub(crate) fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().expect("slice length"))
}

pub(crate) fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// The fixed 1024-byte AEROVAULT3 header.
#[derive(Debug, Clone)]
pub struct VaultHeaderV3 {
    pub flags: u8,
    pub salt: [u8; SALT_SIZE],
    pub wrapped_master_key: [u8; WRAPPED_KEY_SIZE],
    pub wrapped_mac_key: [u8; WRAPPED_KEY_SIZE],
    pub data_offset: u64,
    pub data_len: u64,
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub extension_dir_offset: u64,
    pub extension_dir_len: u64,
    pub extension_payload_offset: u64,
    pub extension_payload_len: u64,
    pub wrapper_header_version: u16,
    pub header_mac: [u8; MAC_SIZE],
}

impl VaultHeaderV3 {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..10].copy_from_slice(MAGIC);
        buf[10] = VERSION;
        buf[11] = self.flags;
        buf[12..44].copy_from_slice(&self.salt);
        buf[44..84].copy_from_slice(&self.wrapped_master_key);
        buf[84..124].copy_from_slice(&self.wrapped_mac_key);
        buf[124..128].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        write_u64(&mut buf, 128, self.data_offset);
        write_u64(&mut buf, 136, self.data_len);
        write_u64(&mut buf, 144, self.manifest_offset);
        write_u64(&mut buf, 152, self.manifest_len);
        write_u64(&mut buf, 160, self.extension_dir_offset);
        write_u64(&mut buf, 168, self.extension_dir_len);
        write_u64(&mut buf, 176, self.extension_payload_offset);
        write_u64(&mut buf, 184, self.extension_payload_len);
        buf[192..194].copy_from_slice(&self.wrapper_header_version.to_le_bytes());
        buf[HEADER_MAC_OFFSET..HEADER_MAC_OFFSET + MAC_SIZE].copy_from_slice(&self.header_mac);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < HEADER_SIZE {
            return Err("AeroVault v3 header is truncated".to_string());
        }
        if &data[0..10] != MAGIC {
            return Err("Not an AeroVault v3 file".to_string());
        }
        if data[10] != VERSION {
            return Err(format!("Unsupported AeroVault v3 version: {}", data[10]));
        }
        let header_len = u32::from_le_bytes(data[124..128].try_into().expect("slice length"));
        if header_len != HEADER_SIZE as u32 {
            return Err(format!("Invalid AeroVault v3 header length: {header_len}"));
        }
        if data[194..HEADER_MAC_OFFSET].iter().any(|b| *b != 0) {
            return Err("AeroVault v3 reserved header bytes are not zero".to_string());
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[12..44]);
        let mut wrapped_master_key = [0u8; WRAPPED_KEY_SIZE];
        wrapped_master_key.copy_from_slice(&data[44..84]);
        let mut wrapped_mac_key = [0u8; WRAPPED_KEY_SIZE];
        wrapped_mac_key.copy_from_slice(&data[84..124]);
        let mut header_mac = [0u8; MAC_SIZE];
        header_mac.copy_from_slice(&data[HEADER_MAC_OFFSET..HEADER_MAC_OFFSET + MAC_SIZE]);

        Ok(Self {
            flags: data[11],
            salt,
            wrapped_master_key,
            wrapped_mac_key,
            data_offset: read_u64(data, 128),
            data_len: read_u64(data, 136),
            manifest_offset: read_u64(data, 144),
            manifest_len: read_u64(data, 152),
            extension_dir_offset: read_u64(data, 160),
            extension_dir_len: read_u64(data, 168),
            extension_payload_offset: read_u64(data, 176),
            extension_payload_len: read_u64(data, 184),
            wrapper_header_version: u16::from_le_bytes(
                data[192..194].try_into().expect("slice length"),
            ),
            header_mac,
        })
    }

    pub fn compute_mac(&self, mac_key: &[u8; KEY_SIZE]) -> Result<[u8; MAC_SIZE], String> {
        let mut bytes = self.to_bytes();
        bytes[HEADER_MAC_OFFSET..HEADER_MAC_OFFSET + MAC_SIZE].fill(0);
        let mut hmac = <Hmac<Sha512> as Mac>::new_from_slice(mac_key)
            .map_err(|e| format!("HMAC init failed: {e}"))?;
        hmac.update(&bytes);
        let mut out = [0u8; MAC_SIZE];
        out.copy_from_slice(&hmac.finalize().into_bytes());
        Ok(out)
    }

    pub fn verify_mac(&self, mac_key: &[u8; KEY_SIZE]) -> Result<(), String> {
        let mut bytes = self.to_bytes();
        bytes[HEADER_MAC_OFFSET..HEADER_MAC_OFFSET + MAC_SIZE].fill(0);
        let mut hmac = <Hmac<Sha512> as Mac>::new_from_slice(mac_key)
            .map_err(|e| format!("HMAC init failed: {e}"))?;
        hmac.update(&bytes);
        hmac.verify_slice(&self.header_mac)
            .map_err(|_| "AeroVault v3 header MAC mismatch".to_string())
    }
}

/// The fixed PUBLIC header-integrity MAC key for the plaintext (`.aerovz`)
/// lane. There is no password, so the header HMAC is keyed by this deterministic
/// public key: it makes the header tamper-evident (and lets the standard
/// `verify_mac` path run unchanged) without implying any confidentiality.
pub fn aerovz_mac_key() -> Result<[u8; KEY_SIZE], String> {
    hkdf_expand::<KEY_SIZE>(AEROVZ_MAC_IKM, HKDF_AEROVZ_MAC)
}

/// Derive `(master KEK, MAC KEK)` from the Argon2id base KEK via HKDF-SHA256.
pub fn derive_keks(base_kek: &[u8; KEY_SIZE]) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE]), String> {
    Ok((
        hkdf_expand::<KEY_SIZE>(base_kek, HKDF_MASTER)?,
        hkdf_expand::<KEY_SIZE>(base_kek, HKDF_MAC)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_header() -> VaultHeaderV3 {
        VaultHeaderV3 {
            flags: 0,
            salt: [0x01; SALT_SIZE],
            wrapped_master_key: [0x02; WRAPPED_KEY_SIZE],
            wrapped_mac_key: [0x03; WRAPPED_KEY_SIZE],
            data_offset: 1024,
            data_len: 4096,
            manifest_offset: 5120,
            manifest_len: 256,
            extension_dir_offset: 5376,
            extension_dir_len: 2,
            extension_payload_offset: 5378,
            extension_payload_len: 0,
            wrapper_header_version: 1,
            header_mac: [0u8; MAC_SIZE],
        }
    }

    #[test]
    fn header_round_trip_and_layout() {
        let h = fixed_header();
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        assert_eq!(&bytes[0..10], MAGIC);
        assert_eq!(bytes[10], VERSION);
        assert_eq!(read_u64(&bytes, 128), 1024); // data_offset
        assert_eq!(read_u64(&bytes, 152), 256); // manifest_len
        assert_eq!(u16::from_le_bytes(bytes[192..194].try_into().unwrap()), 1);
        // reserved region is zero.
        assert!(bytes[194..HEADER_MAC_OFFSET].iter().all(|b| *b == 0));
        let back = VaultHeaderV3::from_bytes(&bytes).unwrap();
        assert_eq!(back.salt, h.salt);
        assert_eq!(back.manifest_offset, h.manifest_offset);
        assert_eq!(back.extension_dir_len, 2);
    }

    #[test]
    fn mac_detects_tamper() {
        let mut h = fixed_header();
        let mac_key = [0x09u8; KEY_SIZE];
        h.header_mac = h.compute_mac(&mac_key).unwrap();
        assert!(h.verify_mac(&mac_key).is_ok());
        // Flip a metadata byte -> MAC must reject.
        let mut bytes = h.to_bytes();
        bytes[136] ^= 0x01; // data_len
        let tampered = VaultHeaderV3::from_bytes(&bytes).unwrap();
        assert!(tampered.verify_mac(&mac_key).is_err());
        // Wrong key -> reject.
        assert!(h.verify_mac(&[0x0au8; KEY_SIZE]).is_err());
    }

    #[test]
    fn from_bytes_rejects_bad_magic_and_reserved() {
        let mut bytes = fixed_header().to_bytes();
        bytes[0] = b'X';
        assert!(VaultHeaderV3::from_bytes(&bytes).is_err());
        let mut bytes = fixed_header().to_bytes();
        bytes[300] = 0x01; // dirty reserved
        assert!(VaultHeaderV3::from_bytes(&bytes).is_err());
    }

    #[test]
    fn golden_header_bytes_frozen() {
        // A header with the MAC field zeroed is fully determined by its fields.
        // Freeze its BLAKE3 so an accidental layout change is caught even without
        // the app fixture (the app fixture proves equality in T5).
        let bytes = fixed_header().to_bytes();
        let digest = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(
            digest, "77cecd7ba9f74fe3683e99d2ff7774915d00914e55bdf059d63df0915d92e9d3",
            "AEROVAULT3 header layout drifted"
        );
    }
}
