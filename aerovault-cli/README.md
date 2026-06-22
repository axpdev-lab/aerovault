<p align="center">
  <img src="https://raw.githubusercontent.com/axpdev-lab/aerovault/main/docs/img/banner.png" alt="AeroVault" width="100%" />
</p>

# aerovault-cli

[![Crates.io](https://img.shields.io/crates/v/aerovault-cli)](https://crates.io/crates/aerovault-cli)
[![Library](https://img.shields.io/crates/v/aerovault?label=aerovault%20lib)](https://crates.io/crates/aerovault)
[![License: GPL-3.0](https://img.shields.io/crates/l/aerovault-cli)](https://github.com/axpdev-lab/aerovault/blob/main/LICENSE)

Command-line interface for **AeroVault**: military-grade single-file encrypted vaults
(**AES-256-GCM-SIV**, **Argon2id**, optional **ChaCha20-Poly1305** cascade) with detached
**`.aerocorrect`** Reed-Solomon error correction for any file.

The encryption engine lives in the companion library crate
[`aerovault`](https://crates.io/crates/aerovault); this crate is the thin command-line
front end over it.

## Install

```bash
cargo install aerovault-cli
```

This installs a single binary named **`aerovault`** (not `aerovault-cli`). From a checkout
of the [repository](https://github.com/axpdev-lab/aerovault) you can instead run
`cargo install --path aerovault-cli`.

## Two container lineages

AeroVault ships two container formats that share the same crypto stack:

- **AEROVAULT2** (legacy, magic `AEROVAULT2`, 512-byte header, fixed 64 KiB chunks): the
  **top-level** commands (`create`, `add`, `list`, `extract`, ...) operate on it. Fully
  supported for read, write, and in-place re-encrypt.
- **AEROVAULT3** (modern, magic `AEROVAULT3`, 1024-byte header: gear content-defined
  chunking, per-chunk zstd, keyed-BLAKE3 deduplication, small-file packing, and a
  revision-4 Reed-Solomon error-correction extension): the **`vault`** subcommand group.
  This container is byte-for-byte identical to the AeroFTP application's vault.

Two conventions apply everywhere:

- **Passwords are read interactively** at a `Password:` prompt. They are never accepted as
  a command-line argument or an environment variable, and are zeroized from memory after
  use.
- The global **`--json`** flag prints machine-readable output for the `correct` and `vault`
  command groups (their reports, listings, and `info`).

## Quick start (AEROVAULT2)

```bash
# Create a new vault (prompts for a password)
aerovault create my-vault.aerovault

# Create with cascade encryption (AES-256-GCM-SIV + ChaCha20-Poly1305)
aerovault create my-vault.aerovault --cascade

# Create with a custom chunk size (KiB, default 64)
aerovault create my-vault.aerovault --chunk-size 128

# Add files, optionally into a directory inside the vault
aerovault add my-vault.aerovault file1.pdf file2.jpg
aerovault add my-vault.aerovault document.pdf --dir docs/reports

# List contents (-H / --human for readable sizes)
aerovault list my-vault.aerovault -H

# Extract one entry, or everything, into an output directory
aerovault extract my-vault.aerovault -e document.pdf -o /tmp/out/
aerovault extract my-vault.aerovault -o /tmp/out/

# Organize: mkdir / rename / move / copy / rm
aerovault mkdir  my-vault.aerovault docs/reports
aerovault rename my-vault.aerovault docs/report.txt report-final.txt
aerovault move   my-vault.aerovault docs/report-final.txt archive/report-final.txt
aerovault copy   my-vault.aerovault archive/report-final.txt backup/report-final.txt
aerovault rm     my-vault.aerovault document.pdf

# Inspect security info / change the password
aerovault info   my-vault.aerovault
aerovault passwd my-vault.aerovault

# Detect whether a file is an AEROVAULT2 container
aerovault check suspicious-file.bin
```

## AEROVAULT3 containers (the `vault` group)

The modern format and its Reed-Solomon recovery surfaces live under `vault`:

```bash
# Create an AEROVAULT3 container (zstd level default 9)
aerovault vault create my.aerovault

# Create with embedded plus detached Error Correction (revision 4)
aerovault vault create my.aerovault --error-correction both --ec-pct 20

# Add files, or a directory tree under a prefix
aerovault vault add     my.aerovault report.pdf photo.jpg
aerovault vault add-dir my.aerovault ./project --prefix work

# List, extract, info (all honor --json)
aerovault vault list my.aerovault -H
aerovault vault extract my.aerovault -o ./out
aerovault --json vault info my.aerovault

# Read-only damage report, then repair from parity if needed
aerovault vault scrub  my.aerovault
aerovault vault repair my.aerovault --dry-run
aerovault vault repair my.aerovault

# Manage the detached recovery sidecar
aerovault vault export-parity my.aerovault
aerovault vault strip-parity  my.aerovault
```

`vault` also provides the same `mkdir` / `rm` (with `--recursive`) / `rename` / `move` /
`copy` / `change-password` / `check` verbs as the legacy group, for AEROVAULT3 containers.

## Error correction (`.aerocorrect`)

`.aerocorrect` is a detached, par2-style Reed-Solomon recovery sidecar for **any** byte
stream. It binds to the **SHA-256 of the protected content** (not a path or account), so the
same format repairs `.aerovault` containers and ordinary files alike. Repair is atomic and
all-or-nothing.

```bash
# Generate a detached sidecar (writes report.bin.aerocorrect)
$ aerovault correct gen report.bin --ec medium
Wrote report.bin.aerocorrect (31543 bytes, 1 segment(s), 15 shards, 15.5% overhead) for report.bin

# Verify without modifying the file
$ aerovault correct verify report.bin
Verified: report.bin matches report.bin.aerocorrect

# Repair in place from the sidecar
$ aerovault correct repair report.bin
Repaired report.bin from report.bin.aerocorrect (1 shard(s) reconstructed)
```

For a hardened repair, pass `--expect-sha256 <hex>`: the 64-char SHA-256 of the
known-good content. A sidecar declaring a different content hash is then refused before any
write, so a planted sidecar cannot steer the repair toward attacker-chosen bytes.

### Overhead levels

`--error-correction` (alias `--ec`) takes a named level or an explicit `5-50` percentage.
The exact Reed-Solomon grid is stored in each payload, so readers reconstruct from the
payload metadata rather than from a CLI-level assumption.

| Level       | Target overhead |
|-------------|-----------------|
| `low`       | ~7%             |
| `medium`    | ~15% (default)  |
| `quartile`  | ~25%            |
| `high`      | ~30%            |

## Cryptographic stack

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| KDF | Argon2id (128 MiB, t=4, p=4) | RFC 9106 |
| Key wrapping | AES-256-KW | RFC 3394 |
| Content encryption | AES-256-GCM-SIV | RFC 8452 |
| Cascade mode | ChaCha20-Poly1305 | RFC 8439 |
| Filename encryption | AES-256-SIV | RFC 5297 |
| Header integrity | HMAC-SHA512 | RFC 2104 |
| Key separation | HKDF-SHA256 | RFC 5869 |
| Error correction | Reed-Solomon parity sidecar | `.aerocorrect` v2 (self-healing) |

## Links

- Library crate: [crates.io/crates/aerovault](https://crates.io/crates/aerovault) - [docs.rs/aerovault](https://docs.rs/aerovault)
- Repository and full documentation: [github.com/axpdev-lab/aerovault](https://github.com/axpdev-lab/aerovault)
- Format specs: [AEROVAULT-V3-SPEC](https://github.com/axpdev-lab/aerovault/blob/main/docs/AEROVAULT-V3-SPEC.md), [AEROVAULT-V2-SPEC](https://github.com/axpdev-lab/aerovault/blob/main/docs/AEROVAULT-V2-SPEC.md)
- [CHANGELOG](https://github.com/axpdev-lab/aerovault/blob/main/CHANGELOG.md)

## License

GPL-3.0-only. See [LICENSE](https://github.com/axpdev-lab/aerovault/blob/main/LICENSE).
