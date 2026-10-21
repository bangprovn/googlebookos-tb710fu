use std::process::Command;
#[test]
fn report_refuses_to_overwrite_any_input_or_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let caps = dir.path().join("caps.json");
    let sample = dir.path().join("sample.json");
    let output = dir.path().join("report.json");
    std::fs::write(
        &caps,
        include_str!("../../../tests/fixtures/host_egl_advertisements.example.json"),
    )
    .unwrap();
    std::fs::write(
        &sample,
        include_str!("../../../tests/fixtures/ahb_sampling.example.json"),
    )
    .unwrap();
    std::fs::write(&output, b"existing report must remain intact\n").unwrap();
    for target in [&caps, &sample, &output] {
        let before = std::fs::read(target).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_gb"))
            .args(["compat", "host-images"])
            .arg(&caps)
            .arg("--sampling")
            .arg(&sample)
            .arg("--out")
            .arg(target)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        assert_eq!(std::fs::read(target).unwrap(), before);
    }
}

#[test]
fn valid_host_witnesses_publish_an_incomplete_assessment() {
    let dir = tempfile::tempdir().unwrap();
    let caps = dir.path().join("caps.json");
    let sample = dir.path().join("sample.json");
    let out = dir.path().join("report.json");
    std::fs::write(
        &caps,
        include_str!("../../../tests/fixtures/host_egl_advertisements.example.json"),
    )
    .unwrap();
    std::fs::write(
        &sample,
        include_str!("../../../tests/fixtures/ahb_sampling.example.json"),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_gb"))
        .args(["compat", "host-images"])
        .arg(&caps)
        .arg("--sampling")
        .arg(&sample)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap();
    assert_eq!(report["state"], "implementation_required");
    assert_eq!(report["reported_direct_ahb_sampling_passes"], 1);
    assert_eq!(report["guest_integration_verified"], false);
    assert_eq!(report["originating_device_verified"], false);
    assert_eq!(report["full_port_verified"], false);
}
