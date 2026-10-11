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

/// The `show` output names a grant as its access bits, then the path.
fn policy_line(stdout: &str, bits: &str, path: &std::path::Path) -> bool {
    stdout.contains(&format!("{bits} {}", path.display()))
}

#[test]
fn command_line_grants_reach_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    fs::create_dir(&marker).unwrap();

    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-read",
            marker.to_str().unwrap(),
            "--allow-net",
            "443",
            "/usr/bin/true",
        ])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        policy_line(&stdout, "r--", &marker),
        "the quick grant must reach the policy: {stdout}"
    );
    assert!(
        stdout.contains("443"),
        "the quick egress port must reach the policy: {stdout}"
    );
}

#[test]
fn a_command_line_deny_retracts_a_config_grant() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("project");
    fs::create_dir(&marker).unwrap();
    let config = dir.path().join("given.toml");
    fs::write(
        &config,
        format!("[filesystem]\nwrite = [\"{}\"]\n", marker.display()),
    )
    .unwrap();

    // Without the flag, the config's grant stands.
    let base = Command::new(bailey())
        .args(["show", "--config"])
        .arg(&config)
        .arg("/usr/bin/true")
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&base.stdout);
    assert!(
        policy_line(&stdout, "-w-", &marker),
        "the config grant should be in the policy: {stdout}"
    );

    // With the flag, the same path is denied outright.
    let denied = Command::new(bailey())
        .args(["show", "--config"])
        .arg(&config)
        .args(["--deny", marker.to_str().unwrap(), "/usr/bin/true"])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        policy_line(&stdout, "---", &marker),
        "the command-line deny must retract the config grant: {stdout}"
    );
}

#[test]
fn a_relative_quick_grant_resolves_against_the_working_directory() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(bailey())
        .args(["show", "--allow-write", ".", "/usr/bin/true"])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        policy_line(&stdout, "-w-", dir.path()),
        "a relative grant means the directory the command was typed in: {stdout}"
    );
}

#[test]
fn a_conflicting_command_line_grant_is_refused() {
    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-write",
            "/tmp/conflict-check",
            "--deny",
            "/tmp/conflict-check",
            "/usr/bin/true",
        ])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("both granted and denied"),
        "the error should name the contradiction: {stderr}"
    );
}
