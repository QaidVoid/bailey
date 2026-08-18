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
            r#"{{"version":1,"dropped":0,"events":[
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"read","resource":{{"path":"/home/user/.ssh/id_rsa"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}},
              {{"kind":"connect","resource":{{"net":{{"host":"1.2.3.4","port":443}}}},"pid":10,"timestamp_ns":0,"resolution":"not_applicable"}}
            ]}}"#
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
        r#"{"version":1,"dropped":0,"events":[{"kind":"connect","resource":{"net":{"host":"1.2.3.4","port":443}},"pid":10,"timestamp_ns":0,"resolution":"not_applicable"}]}"#,
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

#[test]
fn a_truncated_trace_is_refused_unless_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    let target_dir = dir.path().display();
    fs::write(
        &trace,
        format!(
            r#"{{"version":1,"dropped":7,"events":[
              {{"kind":"read","resource":{{"path":"{target_dir}/data.pak"}},"pid":10,"timestamp_ns":0,"resolution":"absolute"}}
            ]}}"#
        ),
    )
    .unwrap();
    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let refused = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "a truncated trace must be refused"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("7"),
        "the loss count must be reported: {stderr}"
    );

    let accepted = Command::new(bailey())
        .args(["profile", "generate", "--accept-truncated", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();
    assert!(accepted.status.success());
    let profile = String::from_utf8_lossy(&accepted.stdout);
    assert!(
        profile.contains("incomplete trace"),
        "the profile must record that it came from a partial trace: {profile}"
    );
}

#[test]
fn an_unknown_trace_version_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let trace = dir.path().join("trace.json");
    fs::write(&trace, r#"{"version":99,"dropped":0,"events":[]}"#).unwrap();
    let target = dir.path().join("game");
    fs::write(&target, "").unwrap();

    let output = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&target)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("version 99"),
        "the unsupported version must be named: {stderr}"
    );
}
