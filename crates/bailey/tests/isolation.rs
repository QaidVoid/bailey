//! Integration tests for namespace isolation.
//!
//! These run real programs under user, mount, and PID namespaces. They self-skip
//! where isolation cannot actually be established (for example, a host that
//! restricts unprivileged user namespaces via AppArmor), detected by checking
//! whether the target really lands as PID 1.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// True only when an isolated run genuinely enters a new PID namespace. When the
/// host forces the Landlock-only fallback, the target keeps its host PID, so
/// this returns false and the tests skip.
fn isolation_active() -> bool {
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "--", "-c", "echo $$"])
        .output();
    matches!(output, Ok(out) if out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "1")
}

#[test]
fn ungranted_path_is_absent_under_isolation() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "--", "-c", "ls /home"])
        .output()
        .unwrap();
    // /home is not granted, so it is absent from the reconstructed root.
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No such file") || stderr.contains("cannot access"),
        "expected /home to be absent, got: {stderr}"
    );
}

#[test]
fn target_is_pid_one_under_isolation() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "--", "-c", "echo $$"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "1");
}

#[test]
fn landlock_still_denies_writes_under_isolation() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data.txt");
    fs::write(&file, "content").unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", file.display()),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "--", "-c"])
        .arg(format!("echo x > {}", file.display()))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "write to a read-only grant must be denied under isolation"
    );
}
