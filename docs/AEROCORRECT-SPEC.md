# AeroCorrect Detached Error Correction Specification

**Format**: `.aerocorrect`
**Version**: 1
**Status**: Stable for AeroVault 0.5.0 / AeroFTP v4
**Date**: 2026-06-12

---

## 1. Purpose

`.aerocorrect` is a detached Reed-Solomon parity sidecar for any byte stream. It protects the bytes of the target file without embedding anything into that file, so the same format can repair `.aerovault` containers, synced files, or arbitrary standalone files.

The sidecar binds to the SHA-256 of the protected content. It does not bind to a path, vault salt, account, or provider-specific identity. Higher layers may add those checks, but the sidecar format itself is content-addressed.

---

## 2. Sidecar Layout

All multi-byte integers are little-endian.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | `magic` | ASCII `AEROCORR` |
| 8 | 1 | `version` | `1` |
| 9 | 32 | `binding_id` | BLAKE3 domain hash of `content_sha256` |
| 41 | 32 | `content_sha256` | SHA-256 of the protected byte stream |
| 73 | 8 | `total_len` | Protected stream length in bytes |
| 81 | 4 | `segment_count` | Number of protected windows |
| 85 | variable | `segments[]` | Segment directory and AVEC parity payloads |
| EOF-32 | 32 | `checksum` | BLAKE3 hash of every byte before this checksum |

Each segment is:

| Size | Field | Description |
|------|-------|-------------|
| 8 | `window_offset` | Offset in the protected byte stream |
| 8 | `window_len` | Number of protected bytes in this window |
| 8 | `avec_len` | Length of the AVEC payload |
| `avec_len` | `avec_bytes` | Reed-Solomon parity payload for this window |

Segments MUST tile the protected stream exactly: start at offset 0, be contiguous and ordered, and cover exactly `total_len`. A zero-length file is represented by one segment `(0, 0)` with an empty AVEC payload.

---

## 3. Binding And Integrity

`binding_id = BLAKE3("aerocorrect-binding-v1" || content_sha256)`.

Readers MUST verify:

- magic and version
- whole-sidecar checksum over the body
- `segment_count > 0`
- segment directory bounds before allocating or seeking
- segment tiling against `total_len`
- `binding_id` matches `content_sha256`

For standalone repair, `content_sha256` is the expected good hash. A repair MUST only replace the original after the repaired stream hashes to `content_sha256`; otherwise the original file must be left untouched.

---

## 4. AVEC Payload

Each window stores one AVEC payload. The AVEC payload is the fixed-grid Reed-Solomon v2 format used by AeroFTP v4:

| Size | Field |
|------|-------|
| 4 | magic `AVEC` |
| 2 | version `2` |
| 2 | data shard count `K` |
| 2 | parity shard count `P` |
| 4 | shard size `S` |
| 8 | protected window length |
| 10 | reserved zero bytes |
| variable | data shard checksums |
| variable | parity shard checksums |
| variable | parity shard bytes |

Shard checksums are the first 16 bytes of BLAKE3 over each zero-padded shard. They localize damage so reconstruction erases only mismatched shards and routes around corrupted parity.

---

## 5. Error Correction Levels

CLI levels map to storage-overhead targets:

| Level | Target | Reed-Solomon grid |
|-------|--------|-------------------|
| `low` | 7% | approximately `K=14, P=1` |
| `medium` | 15% | approximately `K=13, P=2` |
| `quartile` | 25% | `K=8, P=2` |
| `high` | 30% | approximately `K=7, P=2` |
| numeric | 5-50% | clamped into the supported range |

The exact grid is stored in each AVEC payload, so readers reconstruct from the payload metadata rather than from a CLI-level assumption.

---

## 6. Streaming Requirement

Implementations SHOULD generate and repair in bounded windows. The reference implementation uses 64 MiB windows and reads sidecar parity on demand, so memory is bounded to one plaintext window plus that window's parity payload and small hash buffers.

---

## 7. Compatibility

The format is shared with AeroFTP v4. A sidecar produced by AeroFTP for a standalone file must verify and repair with this crate, and a sidecar produced by this crate is byte-identical for the same file and overhead level.
