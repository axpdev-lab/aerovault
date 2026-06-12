use aerovault::{correct_generate, correct_repair, correct_verify};

const PAYLOAD: &[u8] = include_bytes!("fixtures/cross_impl_payload.bin");
const AEROFTP_SIDECAR: &[u8] = include_bytes!("fixtures/cross_impl_payload.bin.aerocorrect");

fn path_s(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn aeroftp_sidecar_round_trips_and_crate_generation_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("cross_impl_payload.bin");
    let aeroftp_sidecar = dir.path().join("cross_impl_payload.bin.aerocorrect");
    let crate_sidecar = dir.path().join("crate-generated.aerocorrect");
    std::fs::write(&file, PAYLOAD).unwrap();
    std::fs::write(&aeroftp_sidecar, AEROFTP_SIDECAR).unwrap();

    let verify = correct_verify(&path_s(&file), Some(&path_s(&aeroftp_sidecar))).unwrap();
    assert!(verify.verified, "AeroFTP-generated sidecar must verify");

    let mut damaged = PAYLOAD.to_vec();
    damaged[123] ^= 0x5a;
    damaged[777] ^= 0xa5;
    std::fs::write(&file, &damaged).unwrap();

    let verify = correct_verify(&path_s(&file), Some(&path_s(&aeroftp_sidecar))).unwrap();
    assert!(!verify.verified, "corruption must be detected");
    let repair = correct_repair(&path_s(&file), Some(&path_s(&aeroftp_sidecar))).unwrap();
    assert!(repair.repaired, "corruption must be repaired");
    assert_eq!(std::fs::read(&file).unwrap(), PAYLOAD);

    correct_generate(&path_s(&file), 15, Some(&path_s(&crate_sidecar))).unwrap();
    assert_eq!(
        std::fs::read(&crate_sidecar).unwrap(),
        AEROFTP_SIDECAR,
        "crate-generated sidecar must be byte-identical to AeroFTP for the same file and level"
    );
}
