//! Integration test for the audit-trace to profile generation flow.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

#[test]
fn generate_excludes_high_risk_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");

    // A routine read inside the target directory, a credential read, and an
    // outbound connection.
    let target_dir = dir.path().display();
    fs::write(
        &trace,
        format!(
            r#"[
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0}},
              {{"kind":"read","resource":{{"path":"/home/user/.ssh/id_rsa"}},"pid":10,"timestamp_ns":0}},
              {{"kind":"connect","resource":{{"net":{{"host":"1.2.3.4","port":443}}}},"pid":10,"timestamp_ns":0}}
            ]"#
        ),
    )
    .unwrap();

    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();

    assert!(output.status.success());
    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(
        profile.contains("data.pak"),
        "routine read should be granted"
    );
    assert!(
        !profile.contains("id_rsa"),
        "credential read must be excluded"
    );
    assert!(!profile.contains("egress"), "egress must be excluded");
}

#[test]
fn generate_includes_high_risk_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    fs::write(
        &trace,
        r#"[{"kind":"connect","resource":{"net":{"host":"1.2.3.4","port":443}},"pid":10,"timestamp_ns":0}]"#,
    )
    .unwrap();
    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--include-high-risk", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();

    assert!(output.status.success());
    let profile = String::from_utf8_lossy(&output.stdout);
    assert!(
        profile.contains("egress"),
        "egress should be included when requested"
    );
    assert!(profile.contains("443"));
}
