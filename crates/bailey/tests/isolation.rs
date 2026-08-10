//! Integration tests for namespace isolation.
//!
//! These run real programs under user, mount, and PID namespaces. They self-skip
//! where Landlock or unprivileged user namespaces are unavailable.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn supported() -> bool {
    bailey::backend::probe::probe().landlock && bailey::backend::isolation::available()
}

#[test]
fn ungranted_path_is_absent_under_isolation() {
    if !supported() {
        eprintln!("skipping: Landlock or user namespaces unavailable");
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
    if !supported() {
        eprintln!("skipping: Landlock or user namespaces unavailable");
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
    if !supported() {
        eprintln!("skipping: Landlock or user namespaces unavailable");
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
