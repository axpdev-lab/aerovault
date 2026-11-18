// SPDX-License-Identifier: MPL-2.0
use aerovault::v3::{CreateOptionsV3, VaultV3};
use std::process::{Command, Stdio};

#[test]
fn plaintext_extract_is_explicit_and_does_not_prompt_for_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.aerozip");
    VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
    let source = dir.path().join("input");
    std::fs::write(&source, b"plaintext archive contents").unwrap();
    let mut vault = VaultV3::open_plaintext(&path).unwrap();
    VaultV3::add_files(&mut vault, &[(source, "folder/item.txt".to_string())]).unwrap();
    assert!(VaultV3::open(&path, "any-password-123").is_err());
    for selected in [false, true] {
        let out = dir.path().join(if selected { "selected" } else { "all" });
        std::fs::create_dir(&out).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_aerovault"));
        command
            .args(["--json", "vault", "extract"])
            .arg(&path)
            .args(["--plaintext", "--output"])
            .arg(&out)
            .stdin(Stdio::null());
        if selected {
            command.args(["--entry", "folder/item.txt"]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("Password:"));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["status"], "extracted");
        assert_eq!(
            std::fs::read(out.join("folder/item.txt")).unwrap(),
            b"plaintext archive contents"
        );
    }
}

#[test]
fn plaintext_extract_refuses_encrypted_containers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypted.aerovault");
    VaultV3::create(&CreateOptionsV3::new(&path, "test-password-123")).unwrap();
    let out = dir.path().join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_aerovault"))
        .args(["vault", "extract"])
        .arg(&path)
        .args(["--plaintext", "--output"])
        .arg(&out)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!out.exists());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Password:"));
}

#[test]
fn plaintext_extract_rejects_hostile_manifest_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hostile.aerozip");
    VaultV3::create(&CreateOptionsV3::new_plaintext(&path)).unwrap();
    let source = dir.path().join("input");
    std::fs::write(&source, b"must not escape").unwrap();
    let mut vault = VaultV3::open_plaintext(&path).unwrap();
    VaultV3::add_files(&mut vault, &[(source, "folder/item.txt".to_string())]).unwrap();
    // Public-key integrity on the plaintext lane is not authenticity. Preserve
    // header/ranges while forging a traversal in the on-disk plaintext manifest.
    let mut bytes = std::fs::read(&path).unwrap();
    let name = b"folder/item.txt";
    let position = bytes.windows(name.len()).position(|w| w == name).unwrap();
    bytes[position..position + name.len()].copy_from_slice(b"../escape.txt  ");
    std::fs::write(&path, bytes).unwrap();
    for selected in [false, true] {
        let out = dir.path().join(if selected { "selected" } else { "all" });
        let mut command = Command::new(env!("CARGO_BIN_EXE_aerovault"));
        command
            .args(["vault", "extract"])
            .arg(&path)
            .args(["--plaintext", "--output"])
            .arg(&out)
            .stdin(Stdio::null());
        if selected {
            command.args(["--entry", "../escape.txt  "]);
        }
        let result = command.output().unwrap();
        assert!(!result.status.success());
        assert!(!out.exists());
        assert!(!dir.path().join("escape.txt  ").exists());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("Password:"));
    }
}
