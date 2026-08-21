//! Integration test for the audit-trace to profile generation flow.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// The privileged helper, when this host has one that can actually load its
/// programs. Without it there is no trace to generate anything from.
fn helper() -> Option<std::path::PathBuf> {
    // Whatever the probe resolved, rather than a path guessed alongside the test
    // binary: the one next to it is usually the debug build, which has no
    // capabilities and would make this fail instead of skip.
    match bailey::backend::probe::probe(true).helper {
        bailey::backend::probe::HelperStatus::Ready(path) => Some(path),
        _ => None,
    }
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

/// The whole loop the README advertises: watch a program, turn what it did into
/// a policy, and run it under that policy.
///
/// Both halves of this are covered elsewhere, live recording in `audit.rs` and
/// trace-to-profile above, but nothing walked the join between them, which is
/// where the two halves disagreeing would show up.
#[test]
fn a_recorded_run_produces_a_policy_that_run_accepts() {
    let Some(helper) = helper() else {
        eprintln!("skipping: no audit helper with capabilities on this host");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    // The program and its data share a directory, so reading the data is a
    // routine finding rather than a high-risk one held back for review.
    let program = dir.path().join("program");
    fs::copy("/bin/cat", &program).unwrap();
    let data = dir.path().join("data.txt");
    fs::write(&data, "recorded\n").unwrap();

    // Without a policy for it, the data is not granted and the read fails.
    let before = Command::new(bailey())
        .arg("run")
        .arg(&program)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&before.stdout).contains("recorded"),
        "the data is not granted yet, so this must not read it"
    );

    let trace = dir.path().join("trace.json");
    let audited = Command::new(bailey())
        .env("BAILEY_BPF_HELPER", &helper)
        .args(["audit", "--save-trace"])
        .arg(&trace)
        .arg(&program)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        audited.status.success(),
        "the audit run failed: {}",
        String::from_utf8_lossy(&audited.stderr)
    );

    let generated = Command::new(bailey())
        .args(["profile", "generate", "--trace"])
        .arg(&trace)
        .arg("--target")
        .arg(&program)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let config = dir.path().join("bailey.toml");
    fs::write(&config, &generated.stdout).unwrap();
    assert!(
        String::from_utf8_lossy(&generated.stdout).contains("data.txt"),
        "the trace saw the read, so the profile must grant it: {}",
        String::from_utf8_lossy(&generated.stdout)
    );

    let after = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg(&program)
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&after.stdout).contains("recorded"),
        "the generated policy must be enough to run under: {} {}",
        String::from_utf8_lossy(&after.stdout),
        String::from_utf8_lossy(&after.stderr)
    );
}
