//! Integration tests for a bailey run from inside a bailey sandbox.
//!
//! These nest for real rather than simulating the environment, because the thing
//! under test is what the inner run says about layers it could not build and did
//! not need to. The inner binary is copied into the granted directory, since a
//! sandbox's `PATH` is `/usr/local/bin:/usr/bin:/bin` and the test binary is not
//! on it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn isolation_active() -> bool {
    let output = Command::new(bailey())
        .args(["run", "/bin/sh", "-c", "echo $$"])
        .output();
    matches!(output, Ok(out) if out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "1")
}

/// A project directory with a trusted config and a copy of bailey inside it.
fn project(store: &Path) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("project");
    fs::create_dir(&dir).unwrap();
    fs::copy(bailey(), dir.join("bailey-bin")).unwrap();

    let config = dir.join("bailey.toml");
    fs::write(&config, "[filesystem]\nread = [\".\"]\n").unwrap();
    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store)
        .output()
        .unwrap();

    (root, dir)
}

/// Run `script` in an outer confined shell launched from `dir`.
fn outer(store: &Path, dir: &Path, script: &str) -> Output {
    let mut child = Command::new(bailey())
        .args(["shell", "--shell", "/bin/sh"])
        .current_dir(dir)
        .env("XDG_DATA_HOME", store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn an_inherited_layer_is_reported_as_enforced() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());

    let output = outer(
        store.path(),
        &dir,
        "./bailey-bin run --no-isolate /bin/true\n",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("(inherited)"),
        "a layer the outer sandbox established is enforced, not missing: {stderr}"
    );
    assert!(
        !stderr.contains("UDP"),
        "the inherited namespace has no route, so nothing about UDP is unrestricted: {stderr}"
    );
    assert!(
        !stderr.contains("unprivileged user namespaces unavailable"),
        "the cause is our own seccomp filter, not the host: {stderr}"
    );
}

#[test]
fn an_unreachable_trust_store_is_not_reported_as_untrusted() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());

    let output = outer(store.path(), &dir, "./bailey-bin run /bin/true\n");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("not reachable"),
        "the store cannot be read from inside, which is not the same as the file \
         being untrusted: {stderr}"
    );
    assert!(
        !stderr.contains("you have not trusted it"),
        "the file is trusted; bailey simply cannot see the record: {stderr}"
    );
    assert!(
        !stderr.contains("bailey trust /"),
        "and it must not suggest a command that would write into a discarded \
         home: {stderr}"
    );
}

#[test]
fn trusting_from_inside_a_sandbox_is_refused() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());

    let output = outer(
        store.path(),
        &dir,
        "./bailey-bin trust ./bailey.toml && echo RECORDED\n",
    );

    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("RECORDED"),
        "recording trust into a home that is discarded must fail rather than \
         appear to work"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not reachable"),
        "and it must say why: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
