//! Integration tests for config discovery and argument handling.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

#[test]
fn working_directory_config_applies_to_a_system_interpreter() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker-dir");
    fs::create_dir(&marker).unwrap();
    fs::write(
        dir.path().join("bailey.toml"),
        format!("[filesystem]\nread = [\"{}\"]\n", marker.display()),
    )
    .unwrap();

    // The target lives under a system path, so the upward walk from the target
    // finds nothing; only the working directory walk can find this config.
    let output = Command::new(bailey())
        .args(["show", "/usr/bin/true"])
        .current_dir(dir.path())
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
