# AeroVault

<p align="center">
  <img src="docs/img/aerovault-icon-128.png" alt="AeroVault" width="96" />
</p>

[![Crates.io](https://img.shields.io/crates/v/aerovault)](https://crates.io/crates/aerovault)
[![docs.rs](https://docs.rs/aerovault/badge.svg)](https://docs.rs/aerovault)
[![License: GPL-3.0](https://img.shields.io/crates/l/aerovault)](LICENSE)

Military-grade encrypted vault format for single-file encrypted containers.

AeroVault combines **AES-256-GCM-SIV** (nonce misuse-resistant), **Argon2id** (128 MiB), **AES-256-KW** key wrapping, and optional **ChaCha20-Poly1305** cascade encryption into a portable `.aerovault` file format.

The current container format is **v3**, which binds a per-file 16-byte `file_id` into the chunk AAD to prevent chunk splicing and reordering. Existing **v2** containers stay fully supported (read, write, and in-place re-encrypt); the crypto stack below is shared by both.

Since 0.5.0 the crate also ships the unified `.aerocorrect` Reed-Solomon sidecar format: a detached, content-SHA-bound recovery file for any byte stream. It can protect `.aerovault` containers or ordinary files, and repair is atomic and all-or-nothing.

## Cryptographic Stack

| Layer | Algorithm | Standard |
|-------|-----------|----------|
| KDF | Argon2id (128 MiB, t=4, p=4) | RFC 9106 |
| Key Wrapping | AES-256-KW | RFC 3394 |
| Content Encryption | AES-256-GCM-SIV | RFC 8452 |
| Cascade Mode | ChaCha20-Poly1305 | RFC 8439 |
| Filename Encryption | AES-256-SIV | RFC 5297 |
| Header Integrity | HMAC-SHA512 | RFC 2104 |
| Key Separation | HKDF-SHA256 | RFC 5869 |
| Error Correction | Reed-Solomon parity sidecar | `.aerocorrect` v1 |

## Installation

### From source

```bash
cargo install --path aerovault-cli
```

### From crates.io

```bash
cargo add aerovault
```

## CLI Usage

```bash
# Create a new vault
aerovault create my-vault.aerovault

# Create with cascade encryption (AES-GCM-SIV + ChaCha20-Poly1305)
aerovault create my-vault.aerovault --cascade

# Add files
aerovault add my-vault.aerovault file1.pdf file2.jpg

# Add files to a directory
aerovault add my-vault.aerovault document.pdf --dir docs/reports

# List contents
aerovault list my-vault.aerovault -H

# Extract a specific file
aerovault extract my-vault.aerovault -e document.pdf -o /tmp/output/

# Extract all
aerovault extract my-vault.aerovault -o /tmp/output/

# Create directories
aerovault mkdir my-vault.aerovault docs/reports

# Delete an entry
aerovault rm my-vault.aerovault document.pdf

# Rename an entry in place
aerovault rename my-vault.aerovault docs/report.txt report-final.txt

# Move or rename across directories
aerovault move my-vault.aerovault docs/report-final.txt archive/reports/report-final.txt

# Copy file or directory to another path
aerovault copy my-vault.aerovault archive/reports/report-final.txt backup/report-final.txt

# Show security info
aerovault info my-vault.aerovault

# Change password
aerovault passwd my-vault.aerovault

# Check if file is an AeroVault
aerovault check suspicious-file.bin

# Generate a detached recovery sidecar for any file
aerovault correct gen my-vault.aerovault --ec medium

# Verify without modifying the file
aerovault correct verify my-vault.aerovault

# Repair in place from my-vault.aerovault.aerocorrect
aerovault correct repair my-vault.aerovault
```

## Library Usage

```rust
use aerovault::{Vault, CreateOptions, EncryptionMode};

// Create a new vault
let opts = CreateOptions::new("secure.aerovault", "strong-password")
    .with_mode(EncryptionMode::Cascade);
let vault = Vault::create(opts)?;

// Add files
vault.add_files(&["secret.pdf", "keys.txt"])?;

// Open and list
let vault = Vault::open("secure.aerovault", "strong-password")?;
for entry in vault.list()? {
    println!("{} ({} bytes)", entry.name, entry.size);
}

// Extract
vault.extract("secret.pdf", "/tmp/")?;

// Rename in place (same parent directory)
vault.rename_entry("keys.txt", "keys-2026.txt")?;

// Move (works for files and directories)
vault.move_entry("secret.pdf", "archive/secret.pdf")?;

// Copy (works for files and directories)
vault.copy_entry("archive/secret.pdf", "backup/secret.pdf")?;
```

### Error Correction API

```rust
use aerovault::{correct_generate, correct_repair, correct_verify};

fn protect_and_repair() -> Result<(), Box<dyn std::error::Error>> {
    let report = correct_generate("my-vault.aerovault", 15, None)?;
    println!("wrote {}", report.sidecar);

    let verified = correct_verify("my-vault.aerovault", None)?;
    if !verified.verified {
        let repaired = correct_repair("my-vault.aerovault", None)?;
        println!("status: {}", repaired.status);
    }
    Ok(())
}
```

## Format Specification

See [docs/AEROVAULT-V2-SPEC.md](docs/AEROVAULT-V2-SPEC.md) for the base binary layout. The current **v3** container keeps that layout and adds a per-file 16-byte `file_id` to the chunk AAD (inner AEAD and the optional ChaCha20-Poly1305 cascade). The `file_id` is stored in the AES-SIV-authenticated manifest and the on-disk version is covered by the HMAC-SHA512 header MAC, so neither can be stripped to force the legacy path. See [docs/AEROCORRECT-SPEC.md](docs/AEROCORRECT-SPEC.md) for the detached Error Correction sidecar. See the [CHANGELOG](CHANGELOG.md) (0.4.0, 0.5.0) for the v3 and `.aerocorrect` deltas.

## vs Cryptomator

| | AeroVault | Cryptomator v8 |
|---|---|---|
| KDF | Argon2id (128 MiB) | scrypt (64 MiB) |
| Content cipher | AES-256-GCM-SIV | AES-256-GCM |
| Nonce misuse resistance | Yes | No |
| Cascade mode | Optional | No |
| Storage | Single file | Directory tree |
| Implementation | Rust | Java |

## Security

- All key material is zeroized after use
- Constant-time MAC comparison prevents timing attacks
- File-id-bound chunk AAD (current format) prevents chunk splicing and reordering
- Extraction opens outputs with `O_NOFOLLOW` + `create_new` to refuse symlink redirection
- Per-chunk lengths are bounds-checked before allocation
- `.aerocorrect` repair verifies the final SHA-256 before replacing the original
- Atomic writes prevent corruption on crash
- 128 MiB Argon2id makes GPU brute-force impractical

## License

GPL-3.0 -- See [LICENSE](LICENSE) for details.

## Origin

AeroVault was originally developed as the encryption engine for [AeroFTP](https://github.com/axpdev-lab/aeroftp), a professional FTP/SFTP/cloud client. This standalone crate makes the format available for any Rust project.

## Acknowledgements

From the v3 format work onward, the AeroVault wrapper-stack pipeline model (the
packing / chunking / chunk-id / compression / crypt / cipher-hash taxonomy) is a
design contribution by **Ehud Kirsh (E. Kirsh)**, AeroFTP issue
[#162](https://github.com/axpdev-lab/aeroftp/issues/162), 2026. Ehud has also
provided sustained community testing of AeroVault across releases. The
wrapper-stack format itself is implemented in the AeroFTP application; this crate
provides the stable v2 / current-format library it builds on.
