//! Integration tests for config discovery and argument handling.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

#[test]
fn working_directory_config_applies_to_a_system_interpreter() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker-dir");
    fs::create_dir(&marker).unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", marker.display()),
    )
    .unwrap();

    // A discovered config is inert until accepted, so this test accepts it and
    // then asks what the walk found.
    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();

    // The target lives under a system path, so the upward walk from the target
    // finds nothing; only the working directory walk can find this config.
    let output = Command::new(bailey())
        .args(["show", "/usr/bin/true"])
        .current_dir(dir.path())
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("working dir"),
        "config layer should be attributed to the working directory walk: {stdout}"
    );
    assert!(
        stdout.contains(&marker.display().to_string()),
        "grant from the working directory config should be in the policy: {stdout}"
    );
}

#[test]
fn target_arguments_are_not_parsed_by_bailey() {
    let output = Command::new(bailey())
        .args(["run", "/bin/sh", "-c", "echo passed-through"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "run should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "passed-through",
        "`-c` must reach the target rather than being read as bailey's --config"
    );
}

#[test]
fn target_outside_system_paths_runs_without_config() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("program");
    fs::copy("/bin/true", &program).unwrap();

    let output = Command::new(bailey())
        .arg("run")
        .arg(&program)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "a target outside the system paths must be granted implicitly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_bare_name_resolves_on_path() {
    let output = Command::new(bailey())
        .args(["show", "sh"])
        .output()
        .unwrap();

    assert!(output.status.success(), "a name on PATH must resolve");
    let shown = String::from_utf8_lossy(&output.stdout);
    assert!(
        shown.contains("/sh"),
        "the resolved path must be the one on PATH: {shown}"
    );
}

#[test]
fn a_target_that_does_not_exist_is_an_error() {
    for name in ["definitely-not-a-real-command", "./also-not-real"] {
        let output = Command::new(bailey())
            .args(["show", name])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "a missing target must fail rather than describe a policy for nothing"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(name),
            "the error must name the target: {stderr}"
        );
    }
}
