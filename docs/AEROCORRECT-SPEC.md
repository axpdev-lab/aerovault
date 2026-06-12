# AeroCorrect Detached Error Correction Specification

**Format**: `.aerocorrect`
**Version**: 2 (self-healing); version 1 still parsed for read-back
**Status**: Stable for AeroVault 0.5.0 / AeroFTP v4
**Date**: 2026-06-12

---

## 1. Purpose

`.aerocorrect` is a detached Reed-Solomon parity sidecar for any byte stream. It protects the bytes of the target file without embedding anything into that file, so the same format can repair `.aerovault` containers, synced files, or arbitrary standalone files.

The sidecar binds to the SHA-256 of the protected content. It does not bind to a path, vault salt, account, or provider-specific identity. Higher layers may add those checks, but the sidecar format itself is content-addressed.

Format **v2 is self-healing**: the small metadata that locates everything is stored redundantly, so a lightly-corrupted sidecar still recovers instead of being rejected wholesale. Version 1 sidecars (the pre-#276 wholesale-checksum framing) are still parsed for read-back; new sidecars are always written as v2.

---

## 2. Sidecar Layout (v2)

All multi-byte integers are little-endian.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | `magic` | ASCII `AEROCORR` |
| 8 | 1 | `version` | `2` |
| 9 | 4 | `segment_count` (slot 1) | Number of protected windows |
| 13 | 4 | `segment_count` (slot 2) | Identical replica |
| 17 | 4 | `segment_count` (slot 3) | Identical replica |
| 21 | `DIR_LEN` | directory copy 1 | The locator (see below) |
| 21+`DIR_LEN` | 32 | `blake3(copy 1)` | Per-copy checksum |
| ... | `DIR_LEN` | directory copy 2 | Identical replica |
| ... | 32 | `blake3(copy 2)` | Per-copy checksum |
| ... | `DIR_LEN` | directory copy 3 | Identical replica |
| ... | 32 | `blake3(copy 3)` | Per-copy checksum |
| ... | variable | `parity region` | Every segment's AVEC payload, concatenated in segment order |

`segment_count` is written into **three fixed 4-byte slots** so the directory-copy boundaries themselves survive a stray bit flip; the value is recovered by byte-majority across the three slots.

One **directory copy** (the locator) is:

| Size | Field | Description |
|------|-------|-------------|
| 8 | `total_len` | Protected stream length in bytes |
| 32 | `binding_id` | BLAKE3 domain hash of `content_sha256` |
| 32 | `content_sha256` | SHA-256 of the protected byte stream |
| per segment: | | |
| 8 | `window_offset` | Offset in the protected byte stream |
| 8 | `window_len` | Number of protected bytes in this window |
| 8 | `avec_len` | Length of this window's AVEC payload in the parity region |
| 32 | `geometry_header_copy` | Copy of this AVEC payload's 32-byte geometry header |

`DIR_LEN = 72 + segment_count * 56`. The locator is tiny (well under 1 KiB even for a 1 GiB file at 64 MiB windows) which is why triplicating it is cheap.

Segments MUST tile the protected stream exactly: start at offset 0, be contiguous and ordered, and cover exactly `total_len`. A zero-length file is represented by one segment `(0, 0)` with an empty AVEC payload.

The parity region carries **no wholesale envelope checksum**. Every Reed-Solomon shard (data and parity) already carries its own checksum, so a rotted shard is treated as an erasure and routed around at repair time (Section 4).

---

## 3. Self-Healing And Locator Recovery

A reader recovers the locator from the three directory copies as follows:

1. Recover `segment_count` by byte-majority across its three slots and derive `DIR_LEN`. The total locator region is bounded (a forged `segment_count` cannot make a streaming reader buffer more than a fixed 64 MiB cap) before any allocation.
2. Take any directory copy whose stored `blake3` checksum matches its bytes; an intact copy heals a damaged sibling.
3. If no single copy verifies, reconstruct the locator by **byte-majority** across the three copies, then validate the result against the `binding_id` / `content_sha256` relation. A reconstruction that does not satisfy the binding is rejected.
4. Each segment's `geometry_header_copy` from the locator heals a possibly-rotted geometry header inside its AVEC payload before reconstruction; the per-shard checksums then cover the rest of the payload.

If the locator is damaged beyond this budget the read fails closed (no guess is persisted).

---

## 4. Binding And Integrity

`binding_id = BLAKE3("aerocorrect-binding-v1" || content_sha256)`.

Readers MUST verify:

- magic and version
- `segment_count` (majority across the three slots) and the directory-region bounds before allocating or seeking
- at least one directory copy via its per-copy checksum, or a binding-validated byte-majority reconstruction
- segment tiling against `total_len`
- `binding_id` matches `content_sha256`

For standalone repair, `content_sha256` is the expected good hash. A repair MUST only replace the original after the repaired stream hashes to `content_sha256`; otherwise the original file must be left untouched. This fail-closed re-verify is what lets a foreign or corrupt sidecar only ever make a repair *fail*, never overwrite good data.

---

## 5. AVEC Payload

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

The first 32 bytes (magic through reserved) are the **geometry header**, a copy of which is kept in each directory copy (Section 2) so a rotted in-payload header is healed before reconstruction. Shard checksums are the first 16 bytes of BLAKE3 over each zero-padded shard. They localize damage so reconstruction erases only mismatched shards and routes around corrupted parity.

---

## 6. Error Correction Levels

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

## 7. Streaming Requirement

Implementations SHOULD generate and repair in bounded windows. The reference implementation uses 64 MiB windows and reads sidecar parity on demand, so memory is bounded to one plaintext window plus that window's parity payload and small hash buffers.

---

## 8. Compatibility

The format is shared with AeroFTP v4. A sidecar produced by AeroFTP for a standalone file must verify and repair with this crate, and a sidecar produced by this crate is byte-identical for the same file and overhead level. Version 1 sidecars (single non-replicated directory, wholesale checksum over the body) remain readable; all new sidecars are written as v2.
