# AeroVault Format Specification (AEROVAULT3 container, rev. 4 = rev. 3 + EC)

**Current revision**: rev. 4 (= rev. 3 container + Reed-Solomon Error Correction)
**Container format major**: 3 (magic `AEROVAULT3`, `format = 3`)
**Status**: Implemented in crate `aerovault` 0.6.0 (byte-compatible with the AeroFTP application; cross-impl fixture pinned)
**Date**: 2026-06-17
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
| Master-key wrapping | AES-256-KW | RFC 3394 | Wraps the per-vault master and MAC keys in the header |
| Key derivation | Argon2id | RFC 9106 | Memory-hard KDF (128 MiB, t=4, p=4), above the OWASP 2024 baseline |
| Header integrity | HMAC-SHA512 | RFC 4231 | MAC over the 1024-byte header, so metadata tampering is caught before any key is used |

AEROVAULT3 has no separate filename encryption and no cascade: in an encrypted container, paths live inside the encrypted manifest, and both layers use AES-256-GCM-SIV. A plaintext-lane container (header flag `0x01`, section 5) encrypts neither. Each content block is sealed with AAD `"AeroVault v3 block"` followed by its `block_index` (u64 little-endian) and its chunk id. The manifest is sealed with the constant AAD `"AeroVault v3 manifest"`. Chunks are content-addressed and shared across files by deduplication, so there is no per-file binding: the authenticated manifest is what maps each file to its chunks. (The per-file `file_id` binding belongs to the AEROVAULT2 lineage.)

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

Header flags:

| Bit | Name | Meaning |
|---:|---|---|
| `0x01` | `FLAG_PLAINTEXT_CONTENT` | Plaintext lane (`.aerozip`): no password, the manifest and content blocks are stored unencrypted, and the header MAC uses a fixed public key. Integrity and recovery only, no confidentiality. The manifest `crypt` wrapper is `none` and MUST agree with this flag. |

Because the plaintext-lane header MAC key is public, anyone can produce a valid plaintext container. A password-unlock entrypoint (`VaultV3::open` and the CLI encrypted extraction path) MUST reject a container with `FLAG_PLAINTEXT_CONTENT` set whose header verifies under the public key, before reading its payload, and open it only through an explicit plaintext path. The parity export and parity-strip tools also accept plaintext archives; these operations do not authenticate an encrypted unlock and their success is not evidence that a container is encrypted. If the flag is set but the header does not verify under the public key, the flag bit may have rotted on an encrypted vault: the reader treats it as encrypted, so the real MAC check and header recovery still apply. Otherwise, replacing an encrypted vault with a plaintext container would make the unlock succeed and later writes would be stored in the clear.

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

In an encrypted container the manifest is authenticated by its AES-256-GCM-SIV seal and the on-disk version is covered by the HMAC-SHA512 header MAC, so the version cannot be stripped to force another code path. A plaintext-lane manifest has no seal and its header MAC key is public: anyone can modify it and recompute the MAC, so there these checks detect accidental damage only, not tampering.

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

## 12. Writer Lock

Lock naming first removes the ignored-name characters below, then trims trailing dots/spaces, normalizes Unicode basenames to NFC using pinned tables, applies Unicode 9.0 full non-Turkic case folding, and normalizes to NFC again. If that normalized basename plus `.aerolock` fits 255 native units (Unix bytes or Windows UTF-16 units), the normalized basename receives the suffix. Otherwise the name is `.<BLAKE3 digest>.aerolock`, hashing the normalized basename's encoded bytes. The same normalization applies below and above the cutoff, including aliases whose original spelling exceeds it. Non-Unicode basenames use their raw encoded bytes, without normalization, for both the length decision and digest. Tables are pinned so MSRV and stable builds take the same lock. Ordinary lowercase ASCII names retain `<container>.aerolock`.

A container is written by replacing the whole file (temp file, then rename), and its `.aerocorrect` sidecar the same way. A writer MUST hold an exclusive OS lock (`flock`, `LockFileEx` on Windows) on the separate file selected by the lock-naming rule above, in the same directory from the moment it reads the state it will write (or, for state read earlier, from the moment it checks that the container is still the file it read) until its rename is done. This covers saves, sidecar exports (from the read of the container to the sidecar rename) and container creation. A writer MUST open the lock file without following a symbolic link or reparse point at that path, and MUST refuse a lock path that is not a regular file. The lock file is never read, written or renamed, and is not removed after use. Readers normally do not take it; recovery of a pending strip transaction takes the source and sidecar locks before reading the recovered state. Under the lock and before the rename, a writer checks that the container is byte for byte the file it read (the implementation compares its length and BLAKE3 hash; the header alone is not enough, since a change can leave it identical). This also refuses a writer that does not take the lock when its change lands before that check, but not one that lands between the check and the rename. A writer that may not write an existing lock file MAY lock it through a read-only handle. Every replacing write MUST fail if it cannot acquire a real lock, even if directory permissions currently prevent replacement, since those permissions can change. Only a read-only sidecar export MAY read a container on read-only media without a missing source lock; its generation check cannot exclude writes after that check. Its destination MUST still be locked.

A writer that replaces a container path MUST refuse a path that is itself a symbolic link: the link and its target would name two different lock files, and the rename would replace the link rather than the container behind it. A writer that only writes next to a linked path (an `.aerocorrect` beside the link) MUST take the lock of the file the link names. A tool that rewrites an arbitrary file, or writes its `.aerocorrect`, after reading it without the lock (error-correction generate and repair) MUST take the lock of that file before its write whether or not the file is a container, and MUST first check under the lock that the file still holds the bytes it read (the implementation compares their SHA-256), so a container created or saved at that path in the meantime is not overwritten. A writer that writes a sidecar, including a default or seeded sidecar, MUST also hold the lock of the destination path during its rename (including when the leaf is a symbolic link: lock that destination namespace without following the leaf, then replace the link), and MUST refuse a path that is the file it reads (or the link passed to read it).

The `.aerolock` suffix is reserved. A writer MUST NOT replace a file whose name ends with `.aerolock` (compared as a case-insensitive file system sees it: without case, after Unicode lowercasing, ignoring trailing dots and spaces and the characters HFS+ ignores in names), whatever it is writing (a container, a sidecar at a chosen path, a repaired file): replacing the lock file of a container while a writer holds it would let a second writer lock the new file and save at the same time. An extracted entry with such a name MAY be created where no file exists, never over one, and extraction MUST NOT create a directory with such a name taken from the container's entries. On Windows a writer SHOULD open the lock file without delete sharing, so that no program can replace or delete it while it is held, and SHOULD take the lock file name from the container's real (long, canonical) name when it exists, so that every name of one file locks one lock file. A reader that records the state of the container for a later write MUST take that record (length and hash) before decoding the payload, not after: taken after, it could describe a file rewritten in place during the decoding, which the later write would then overwrite. It SHOULD take it after checking the header, so a failed unlock does not read the whole file, and then MUST check that the hashed bytes start with the original header bytes read from disk, including their damage when sidecar recovery supplied a reconstructed authenticated header. It SHOULD reject declared ranges outside the initial file length before hashing the payload.

### Interrupted strip publication

Non-forced `strip-parity` prepares a stripped container and its refreshed detached recovery before replacing either original. It retains synced rollback copies of both originals on disk, then publishes a bounded journal in a private sibling directory named `.<BLAKE3 of lock basename>.aerostrip`. The journal records the original basename and the lengths/BLAKE3 hashes of both old and new files; it carries no password or unwrapped key. Source and default-sidecar guards remain held through publication. On Unix, preparation and active-journal directories are created with owner-only permissions (`0700`), and rollback copies and the journal with `0600`, subject to a more restrictive umask.

A participating reader or writer MUST recover a pending transaction before normal operations. A writer or exporter MUST recheck pending state after acquiring its source guard, including after waiting for another holder, and perform recovery using that guard rather than reacquiring it. A complete old pair or complete new pair needs only cleanup. A partial old/new pair is rolled back from copies whose generations are verified before replacement. An unknown or damaged generation MUST NOT be overwritten automatically: recovery fails with the retained-copy location for manual handling. The journal is bounded to 4096 bytes, uses fixed child filenames and accepts a differently spelled source only when filesystem identity proves it is the recorded file. Equal normalized names alone are insufficient on a case-sensitive volume. Backup reads do not follow symbolic links.

The recovery marker is removed by an atomic directory rename before garbage collection. Process interruption during cleanup therefore cannot expose a half-deleted active journal. An interrupted preparation can leave a private `.aerostrip-prepare-*` directory without changing either original; a cleanup interruption can leave `.aerostrip-gc-*`. These working directories and active journals are local recovery state and SHOULD be excluded from sync. An active `.aerostrip` directory MUST NOT be deleted while recovery can still complete automatically. Reopening a pending transaction requires writable media; read-only opens report the recovery failure. Older implementations do not recover this journal and should not operate on an interrupted pair until recovery completes. Durability depends on filesystem rename/fsync support; this protocol does not coordinate writers that bypass its locks.

Source and destination parent directories are resolved before lock selection. A reused source guard MUST refer to the lock actually held, not a fresh resolution through a mutable directory alias. The bounded lock basename is independent of the destination filesystem's accepted filename length.

## 13. Crate Surface

The standalone `aerovault` crate (0.5.0+) exposes the v3 container and the `.aerocorrect`
sidecar through both a library API and the `aerovault` CLI:

- Library: vault create / open / list / add / extract over the v3 format, with `RecoveryPlacement`
  selecting embedded, detached, or both.
- CLI: `aerovault vault extract --plaintext` explicitly selects unencrypted archive extraction without a password; password-based unlock never falls back to this lane.
- CLI: `aerovault correct {gen,verify,repair}` for the detached `.aerocorrect` sidecar over any file.

See [AEROCORRECT-SPEC.md](AEROCORRECT-SPEC.md) for the sidecar binary layout, the
[CHANGELOG](../CHANGELOG.md) (0.4.0 for v3, 0.5.0 for `.aerocorrect`) for the deltas, and
the [README](../README.md) for usage examples.

#### Pending-strip conflict procedure

If a nonparticipating tool has replaced the vault, damaged a rollback file, or removed the sidecar, automatic recovery refuses to guess which generation to keep. Reads also stop: treating an incomplete pair as recovered could silently discard metadata recovery. The error names the active journal directory and this procedure. Stop all writers and sync tools first. Preserve independent copies of the current vault, any sidecar, and the entire named journal directory, including `old-vault` and `old-sidecar`. Choose the pair to retain, using the preserved originals when the current pair is damaged. With all writers still stopped, restore BOTH selected files to the original vault path and its exact default sidecar path. For the recorded old pair, copy the preserved `old-vault` to the vault path and `old-sidecar` to the sidecar path; do not operate on a partial pair or mix files from different generations. Confirm both restored files match the selected copies before retiring the marker. Then, with writers still stopped, move the active journal directory to a different backup name outside the active `.<hash>.aerostrip` namespace; do not delete its contents. Reopen the selected vault and validate/extract its contents, then regenerate detached parity only from a healthy vault. Retain the backups until verification is complete. This explicit journal retirement is the supported manual escape from a conflict; automatic recovery never overwrites a newer generation or recreates a missing sidecar by guessing.

Legacy Unix sidecars whose names were formed through lossy UTF-8 conversion are read-only fallback candidates only while the native sidecar is absent. Header recovery retains the password/MAC checks and requires unchanged salt/wrapped-key material before accepting an ambiguously named candidate; otherwise the owner must explicitly select and copy the verified recovery file to its native sidecar path. Manifest recovery retains its AEAD verification, and data repair verifies every reconstructed chunk. The implementation never automatically overwrites or deletes a shared lossy filename. Before password rotation, the owner must migrate the verified file and retire the legacy name, so an automatically used old-password recovery copy is not silently retained. Other custom-path backups remain subject to manual re-export as documented.

### Interrupted password rotation

When the default detached sidecar exists, password rotation stages the new container and recovery file together and uses the same bounded pair journal as non-forced stripping. A restart recovers the old pair or recognizes a completed new pair before attempting any password. Rotation without a default sidecar retains the single-file atomic save path. Existing custom-path and externally copied recovery backups still require explicit re-export or retirement.

On Windows, pair preparation directories and their new children grant access only to the owner and SYSTEM before any vault bytes are staged. The journal records bounded owner/DACL text for each original. New files receive that security context before publication; the original inheritance setting is restored under the original parent. Failure to capture, serialize within the journal cap or apply the original security context refuses publication. Rollback restores the same context. A recovery journal without the original Windows descriptor requires manual recovery instead of guessing permissions.

AVEC reconstruction checks its declared shard size against the supported generator rule, `clamp(ceil(L/K), 4096, 1048576)`, before any shard allocation. The original fixed K=10/P=2 release and all percentage-selected grids use this rule. Serialized parity byte caps remain unchanged. This rejects padding amplification even when the serialized input fits its byte cap.

Healthy opens remain lock-free. If a header or manifest needs recovery, the reader acquires the source coordination guard, recovers any pending pair and reopens the physical source under that guard before consulting recovery data. This covers a reader that passed its initial journal check before rotation published its journal. Read-only media retain the documented unlocked-read limitation when a missing source guard cannot be created; pending pair recovery still requires a real guard.
