//! Integration tests for the enforcement backend.
//!
//! These execute real programs under Landlock and seccomp. They self-skip on a
//! kernel without Landlock so they stay green in environments that lack it.

use std::fs;
use std::path::Path;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn landlock_available() -> bool {
    bailey::backend::probe::probe(false).landlock_abi.is_some()
}

fn write_config(dir: &Path, extra_read: &str) -> std::path::PathBuf {
    let config = dir.join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{extra_read}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n"
        ),
    )
    .unwrap();
    config
}

#[test]
fn granted_path_is_readable_and_program_runs() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed.txt");
    fs::write(&allowed, "hello-allowed").unwrap();
    let config = write_config(dir.path(), allowed.to_str().unwrap());

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("cat {}", allowed.display()))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "program should run under enforcement"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello-allowed"
    );
}

#[test]
fn ungranted_path_is_denied() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed.txt");
    let secret = dir.path().join("secret.txt");
    fs::write(&allowed, "hello-allowed").unwrap();
    fs::write(&secret, "top-secret").unwrap();
    let config = write_config(dir.path(), allowed.to_str().unwrap());

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("cat {}", secret.display()))
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "reading an ungranted path must fail"
    );
}

#[test]
fn denied_syscall_is_blocked() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    if !Path::new("/usr/bin/unshare").exists() {
        eprintln!("skipping: /usr/bin/unshare not present");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed.txt");
    fs::write(&allowed, "x").unwrap();
    let config = write_config(dir.path(), allowed.to_str().unwrap());

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/usr/bin/unshare", "-U", "true"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "unshare must be blocked by seccomp"
    );
}
