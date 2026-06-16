# AeroVault Format Specification (v3 container, v4 = v3 + EC)

**Current version**: v4 (= v3 container + Reed-Solomon Error Correction)
**Container format major**: 3 (magic `AEROVAULT3`, `format = 3`)
**Status**: Shipped (crate `aerovault` 0.5.0)
**Date**: 2026-06-16
**Authors**: axpdev-lab

> **Versioning convention.** AeroVault **v4 is v3 + Error Correction, and it is the current version.**
> v4 is not a new on-disk container major: the container stays v3 (magic `AEROVAULT3`, `format = 3`),
> and "v4" is the convention name for a v3 container that also carries the non-critical Reed-Solomon EC
> wrapper, as an embedded extension and/or the detached `.aerocorrect` sidecar. A plain v3 reader still
> opens a v4 container; the EC layer only adds bit-rot recovery on top. This document specifies the v3
> container in full (sections 1-10) and the EC layer that makes it v4 (section 11).

> **Roadmap attribution.** The wrapper-stack design this format implements (the wrapper-versus-step taxonomy, the corrected AES-256-GCM-SIV avalanche framing, algorithm versioning as a forward-compatibility clause, the small-file-packing model and the chunking trade analysis) is a sustained community design contribution by **Ehud Kirsh** in the AeroFTP [COMMUNITY ROADMAP thread (issue #162)](https://github.com/axpdev-lab/aeroftp/issues/162). The conversation shaped both the v3 architecture and this specification.

---

## 1. Purpose

AeroVault v3 is the first wrapper-stack vault format. It keeps the single-file `.aerovault` portability of v2 while adding compressed, content-addressed chunks and a forward-compatible extension directory for future recovery data.

The v3 design is intentionally shaped so that AeroVault v4 can be "v3 plus Error Correction", not a second incompatible archive format.

## 2. Wrapper Pipeline

The canonical v3 write pipeline is:

```text
plaintext files
  -> logical packing / small-file batching
  -> content-defined chunking
       -> keyed BLAKE3 chunk id
  -> zstd compress each chunk/frame
  -> AES-256-GCM-SIV encrypt each compressed chunk
  -> manifest + block table
  -> optional extension blocks (Error Correction in v4)
```

The ordering is deliberate:

- `packing` concatenates files smaller than the small-file threshold (v3 default: the CDC minimum, 256 KiB) into shared packs before chunking, so a tree of tiny files still yields multi-MiB chunks. The pack carries no per-file framing: the manifest is the index. Each packed file records the chunks that cover its byte span and `pack_offset`, the offset of its first byte inside the first covering chunk. Files at or above the threshold take the per-file path (`pack_offset` absent, equivalent to offset 0);
- chunking precedes compression so deduplication, resume, and future range semantics stay chunk-aligned;
- compression is per chunk/frame so a reader can decompress one logical block without inflating the whole archive;
- encryption is last among v3 data-transforming wrappers;
- Error Correction is not part of v3, but the container has the extension slot v4 will use.

## 3. Wrapper And Algorithm IDs

Every wrapper layer has both an algorithm id and an algorithm version. Readers dispatch on these fields rather than on the container version alone.

| Wrapper | v3 default | Version |
|---|---|---|
| `packing` | `small-file-batching` | `1` |
| `chunking` | `gear-cdc` | `1` |
| `chunk_id` | `blake3-keyed-128` | `1` |
| `compression` | `zstd` | `1` |
| `crypt` | `aes-256-gcm-siv` | `1` |
| `cipher_hash` | `blake3-256` | `1` |
| `ecc` | absent in v3 | reserved |

The `chunking` wrapper carries an optional `bounds` object recording the
content-defined-chunking parameters the writer used:

```json
"chunking": { "algorithm_id": "gear-cdc", "algorithm_version": 1,
              "bounds": { "min": 262144, "avg": 1048576, "max": 4194304 } }
```

`avg` MUST be a power of two. A reader uses the recorded `bounds`; when the
field is absent (pre-GAP-5 v3 vaults, or any non-`chunking` wrapper) it falls
back to the const defaults `min = 256 KiB, avg = 1 MiB, max = 4 MiB`, which
keeps every existing vault byte-identical. Bounds only affect the write path
(chunk boundaries and therefore chunk ids); extraction never re-chunks.

The default zstd level and CDC bounds are profile based:

| Profile | Level | CDC min / avg / max | Intended use |
|---|---:|---|---|
| `fast` | 3 | 256 KiB / 1 MiB / 4 MiB | quick local work |
| `balanced` | 9 | 256 KiB / 1 MiB / 4 MiB | default v3 vaults |
| `archive` | 19 | 1 MiB / 4 MiB / 16 MiB | cold storage / export |

`archive` widens the per-chunk zstd window for ratio at the cost of
finer-grained dedup; the wrapper-id/version surface is unchanged so older v3
readers that predate GAP-5 still dispatch correctly (they just apply the const
bounds, which is wrong only for `archive` vaults and is a forward-compat
limitation noted here rather than a silent corruption: ids would differ on a
re-add, never on extraction).

### Cryptographic primitives

The crypt wrapper and the key hierarchy use the following primitives. Readers dispatch on the manifest algorithm ids above; the standards are listed here for audit reference.

| Layer | Algorithm | Standard | Role |
|---|---|---|---|
| Content encryption | AES-256-GCM-SIV | RFC 8452 | Nonce-misuse-resistant AEAD over each compressed chunk |
| Filename encryption | AES-256-SIV | RFC 5297 | Deterministic, so the same plaintext name maps to the same ciphertext without leaking name structure |
| Master-key wrapping | AES-256-KW | RFC 3394 | Wraps the per-vault master and MAC keys in the header |
| Key derivation | Argon2id | RFC 9106 | Memory-hard KDF (128 MiB, t=4, p=4), above the OWASP 2024 baseline |
| Optional cascade | ChaCha20-Poly1305 | RFC 8439 | Defense-in-depth second cipher (paranoid mode, inheritable from v2) |
| Header integrity | HMAC-SHA512 | RFC 4231 | MAC over the 1024-byte header, so metadata tampering is caught before any key is used |

The per-file chunk binding (the v3 `file_id` plus the chunk index and count, section 7) is carried as AAD on the content AEAD and on the optional cascade, so a chunk cannot be spliced across files or reordered.

## 4. File Layout

All multi-byte integers are little-endian.

```text
offset 0
┌─────────────────────────────────────┐
│ Header (1024 bytes)                 │
├─────────────────────────────────────┤
│ Encrypted chunk blocks              │
│   [block_len:u64][cipher_block:N]   │
│   ...                               │
├─────────────────────────────────────┤
│ Encrypted manifest                  │
├─────────────────────────────────────┤
│ Extension directory JSON            │
├─────────────────────────────────────┤
│ Extension payloads (v4+)            │
└─────────────────────────────────────┘
```

The data section always starts immediately after the header. This keeps existing encrypted blocks stable when the manifest grows: a writer can rebuild the header and manifest without shifting the data section.

## 5. Header

The fixed header is 1024 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 10 | magic: `AEROVAULT3` |
| 10 | 1 | format major: `3` |
| 11 | 1 | header flags |
| 12 | 32 | Argon2id salt |
| 44 | 40 | AES-256-KW wrapped master key |
| 84 | 40 | AES-256-KW wrapped MAC key |
| 124 | 4 | header length (`1024`) |
| 128 | 8 | data offset |
| 136 | 8 | data length |
| 144 | 8 | manifest offset |
| 152 | 8 | manifest length |
| 160 | 8 | extension directory offset |
| 168 | 8 | extension directory length |
| 176 | 8 | extension payload offset |
| 184 | 8 | extension payload length |
| 192 | 2 | wrapper header version |
| 194 | 2 | reserved |
| 196 | 764 | reserved, zero-filled |
| 960 | 64 | HMAC-SHA512 over the full header with bytes 960..1024 zeroed |

Readers MUST reject unknown non-zero reserved fields until a future spec assigns them.

## 6. Extension Directory

The extension directory is a UTF-8 JSON array. v3 writers emit `[]`.

```json
[
  {
    "extension_id": "error-correction.reed-solomon",
    "algorithm_id": "reed-solomon",
    "algorithm_version": 1,
    "critical": false,
    "offset": 123,
    "length": 456
  }
]
```

Unknown non-critical extensions are skipped. Unknown critical extensions make the vault unsupported. This is the v3/v4 compatibility contract: v4 Error Correction is expected to be a non-critical extension for data extraction and a critical extension only for workflows that promise repair guarantees.

## 7. Manifest

The manifest is AES-256-GCM-SIV encrypted. Its plaintext is JSON:

```json
{
  "format": 3,
  "created": "2026-05-11T00:00:00Z",
  "modified": "2026-05-11T00:00:00Z",
  "wrappers": {
    "packing": { "algorithm_id": "small-file-batching", "algorithm_version": 1 },
    "chunking": { "algorithm_id": "gear-cdc", "algorithm_version": 1 },
    "chunk_id": { "algorithm_id": "blake3-keyed-128", "algorithm_version": 1 },
    "compression": { "algorithm_id": "zstd", "algorithm_version": 1, "level": 9 },
    "crypt": { "algorithm_id": "aes-256-gcm-siv", "algorithm_version": 1 },
    "cipher_hash": { "algorithm_id": "blake3-256", "algorithm_version": 1 }
  },
  "entries": [],
  "chunks": {}
}
```

`entries` describe user-visible files and directories. Each file entry carries `path`, `size`, `modified`, `is_dir`, `chunks` (the ordered chunk ids that contain its bytes) and an optional `pack_offset`. `pack_offset` is the byte offset of the file inside the concatenation of its listed chunks; when absent the file owns its chunks whole from offset 0 (the per-file path and all pre-packing v3 vaults). `chunks` is keyed by the 128-bit keyed-BLAKE3 chunk id and stores block location metadata.

A v3 manifest also binds a per-file 16-byte `file_id` into the chunk AAD (the inner AEAD and the optional ChaCha20-Poly1305 cascade) to prevent chunk splicing and reordering. The `file_id` is stored in the AES-SIV-authenticated manifest and the on-disk version is covered by the HMAC-SHA512 header MAC, so neither the `file_id` nor the version can be stripped to force the legacy v2 path.

## 8. Hash Separation

v3 deliberately separates two hashes:

- `chunk_id`: keyed BLAKE3, truncated to 128 bits, over plaintext chunk bytes. It is used for content addressing and deduplication and is stored only inside the encrypted manifest.
- `cipher_hash`: full BLAKE3-256 over the encrypted block. It is used by scrub/Error Correction workflows to identify damaged stored bytes before decryption.

The chunk-id key is derived from the vault master key by HKDF. Chunk IDs are not raw public hashes of user content.

## 9. Backward Compatibility

Compatibility rules:

- A v3-capable reader MUST continue to read v1 and v2 vaults through their existing readers.
- A v4-capable reader MUST read v3 vaults without migration.
- A v3 reader MUST be able to extract data from a v4 vault when all unknown extensions are non-critical.
- A v3 reader MUST refuse a vault with an unknown critical extension rather than silently degrading a promised safety property.

## 10. AeroVault v2 Spec Correction

The v2 wire format stores the HMAC-SHA512 at bytes `448..512` and computes it over all 512 header bytes with that MAC field zeroed. Earlier prose in the v2 spec described the MAC as if it lived at `128..192`; that was documentation drift, not the implementation contract. See [AEROVAULT-V2-SPEC.md](AEROVAULT-V2-SPEC.md) for the base layout.

## 11. v4 = v3 + Error Correction (current version)

v4 = v3 + non-critical "error-correction.reed-solomon" extension (always critical=false). The extension carries a v2 Reed-Solomon payload (AVEC magic, version=2, K=10/P=2 fixed grid over the concatenated live-block stream, per-shard 16-byte truncated BLAKE3 for erasure localization, parity data).

- Overhead target: ~P/K = 20% (clamped shard size; proven on real incompressible data).
- Damage model: per-shard cksums (not just per-block cipher_hash) so rot inside a large CDC chunk only erases the affected shards; a bad parity shard is detected and routed around.
- Repair contract (all-or-nothing): reconstruct, re-verify *every* repaired block against its manifest cipher_hash; persist the re-sealed vault only if *all* verify, else leave the file byte-for-byte untouched.
- Forward-compat: a pure v3 open/extract path ignores the non-critical extension and still works (magic stays `AEROVAULT3` / format=3).
- Pipeline position: Error Correction is the *fourth* first-class wrapper, after crypt (see the AeroFTP [#276 wrapper-stack discussion](https://github.com/axpdev-lab/aeroftp/discussions/276)).

### 11.1 Recovery placement: embedded vs detached (the `.aerocorrect` sidecar)

Parity can live in three places (`RecoveryPlacement`): `embedded` (the in-container
extension above, recomputed on every seal), `detached` (a sibling recovery file,
the container stays byte-identical to a plain vault), or `both`. The reconstruction
engine is placement-agnostic (`reconstruct_from_error_correction` takes the parity
bytes), so a detached file simply carries the same AVEC payloads in a framed sidecar.

The detached file is the **unified `.aerocorrect` sidecar** shared with AeroFTP / AeroSync
(Ehud's #276 call: one detached parity format for any file, see
[AEROCORRECT-SPEC.md](AEROCORRECT-SPEC.md) for the full binary layout). It supersedes
the earlier vault-only `.aerovault.rec` / `AVREC1` format. The sidecar is content
addressed: it binds to the SHA-256 of the whole container, not to a vault salt.

A vault writes **exactly three segments** (windows) over its container file, in a
fixed order, so each region's parity is found by position:

```
segment 0 = header window   [0, HEADER_SIZE)        -> header parity
segment 1 = manifest window [manifest_offset, +len) -> manifest (locator) parity
segment 2 = data window     [data_offset, +len)     -> data-block parity
```

An empty `avec_bytes` for a segment means that region is not protected.

- **Why three regions travel outside the container**: the header and manifest cannot
  self-locate their own recovery once damaged (chicken-and-egg). Opening a vault rebuilds
  a corrupted header / manifest from the sidecar, proving correctness by the header MAC
  / AEAD decrypt; `repair` persists the healed region on the next seal.
- **Binding**: the unified format stores the container's SHA-256 as its content binding.
  The vault never enforces that binding on the repair path (a vault being repaired is
  corrupt by definition, so its live bytes cannot match the good hash). The real safety
  gate is unchanged: every reconstructed region is re-verified against the vault's
  authenticated values (header MAC / manifest `cipher_hash`) before being persisted, so
  a foreign or stale sidecar can only make a repair FAIL, never overwrite good data.
- **Self-healing (sidecar format v2)**: the `.aerocorrect` locator (segment directory,
  content hash, per-window geometry) is stored in triplicate with per-copy checksums, so
  a lightly-corrupted sidecar still recovers instead of being rejected wholesale; the bulk
  parity carries no wholesale checksum because each Reed-Solomon shard self-checks and a
  rotted shard is routed around as an erasure. v1 sidecars are still read.
- **Add-later win**: a sidecar can be written or refreshed for an existing vault by
  reading the encrypted container without rewriting it (Kopia can only enable ECC at repo
  creation).
- **Source resolution** (scrub/repair): explicit `--parity` -> `<vault>.aerocorrect`
  sidecar -> embedded extension; the chosen source is reported (`parity_source`).
- Default path: `secret.aerovault` -> `secret.aerovault.aerocorrect`.

### 11.2 Overhead level (QR-style, #276)

The overhead is user-selectable as a target storage-overhead percentage, mapped to a
Reed-Solomon (K data, P parity) group by `error_correction_grid(pct)` (overhead is
P/K). Named QR-style levels: Low ~7% (K=14, P=1), Medium ~15% (K=13, P=2), Quartile
~25% (K=8, P=2), High ~30% (K=7, P=2). The default 20% (K=10, P=2) reproduces the
original fixed grid, so vaults created before this knob keep their exact geometry.
The chosen percentage is recorded on the manifest (`error_correction_pct`, absent =
default) and drives both embedded re-seals and detached sidecars; the grid is
also stored in the AVEC payload header, so reconstruction reads K/P back regardless of
the level a vault was created with.

The `.aerocorrect` format is shared byte-for-byte with AeroFTP v4, pinned by a
cross-implementation fixture: a sidecar produced by either implementation verifies and
repairs with the other for the same file and overhead level. "v3 + Error Correction = v4".

## 12. Crate Surface

The standalone `aerovault` crate (0.5.0+) exposes the v3 container and the `.aerocorrect`
sidecar through both a library API and the `aerovault` CLI:

- Library: vault create / open / list / add / extract over the v3 format, with `RecoveryPlacement`
  selecting embedded, detached, or both.
- CLI: `aerovault correct {gen,verify,repair}` for the detached `.aerocorrect` sidecar over any file.

See [AEROCORRECT-SPEC.md](AEROCORRECT-SPEC.md) for the sidecar binary layout, the
[CHANGELOG](../CHANGELOG.md) (0.4.0 for v3, 0.5.0 for `.aerocorrect`) for the deltas, and
the [README](../README.md) for usage examples.
