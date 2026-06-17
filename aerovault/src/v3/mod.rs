//! AEROVAULT3 container (product revision 3, and revision 4 with the
//! `.aerocorrect` Error Correction extension).
//!
//! This module ports the AEROVAULT3 container that the AeroFTP application
//! implements (`src-tauri/src/aerovault_v3.rs`) into the crate as the single
//! source of truth, byte-for-byte. The legacy `AEROVAULT2` container
//! (`crate::vault`) is untouched and stays read/write for existing vaults.
//!
//! Build order (crate rev. 4 migration):
//! - T2 `chunking` + `packing`: deterministic content pipeline (this commit).
//! - T3 `format` + `manifest` + `block`: on-disk layout (next).
//! - T4 `VaultV3`: the sync vault API.
//! - T6 `ec`: Error Correction wiring (rev. 4).

// SPDX-License-Identifier: GPL-3.0-only

pub mod chunking;
pub mod constants;
pub mod packing;

pub use chunking::{chunk_ranges_with, gear_table, keyed_chunk_id, CdcBounds};
