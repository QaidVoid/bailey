//! Integration tests for the audit backend.
//!
//! These need the privileged helper: eBPF programs cannot be loaded without
//! `CAP_BPF` and `CAP_PERFMON`. They self-skip where the helper is absent or
//! lacks its capabilities, so the suite stays green on a machine that cannot
//! record.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// The helper, if one is configured and able to load its programs.
fn helper() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os("BAILEY_BPF_HELPER")?);
    path.is_file().then_some(path)
}

fn audit(helper: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bailey())
        .args(args)
        .env("BAILEY_BPF_HELPER", helper)
        .output()
        .unwrap()
}

/// Run an audit that saves a trace, and return the parsed trace.
fn trace_of(helper: &Path, dir: &Path, args: &[&str]) -> Value {
    let path = dir.join("trace.json");
    let mut full = vec!["audit", "--save-trace", path.to_str().unwrap()];
    full.extend_from_slice(args);
    let output = audit(helper, &full);
    assert!(
        path.exists(),
        "audit did not produce a trace: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

fn paths_in(trace: &Value) -> Vec<String> {
    trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["resource"]["path"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn startup_access_is_recorded() {
    let Some(helper) = helper() else {
        eprintln!("skipping: no audit helper configured");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let trace = trace_of(&helper, dir.path(), &["/bin/sh", "-c", "true"]);

    assert_eq!(
        trace["version"].as_u64(),
        Some(1),
        "trace must be versioned"
    );

    let paths = paths_in(&trace);
    assert!(
        paths.iter().any(|path| path.contains("libc.so")),
        "the dynamic linker's library search must be recorded, so nothing the \
         target does before the recorder is watching is missed: {paths:?}"
    );
    assert!(
        paths.iter().all(|path| path.starts_with('/')),
        "recorded paths must be absolute: {paths:?}"
    );
}

#[test]
fn the_target_is_confined_during_an_audit() {
    let Some(helper) = helper() else {
        eprintln!("skipping: no audit helper configured");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "top-secret").unwrap();

    let output = audit(
        &helper,
        &[
            "audit",
            "/bin/sh",
            "-c",
            &format!("cat {}", secret.display()),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("top-secret"),
        "an audited target must not reach an ungranted path: {stdout}"
    );
}

#[test]
fn an_ungranted_egress_attempt_is_refused_during_an_audit() {
    let Some(helper) = helper() else {
        eprintln!("skipping: no audit helper configured");
        return;
    };
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("skipping: needs python3");
        return;
    }

    let output = audit(
        &helper,
        &[
            "audit",
            "/usr/bin/python3",
            "-c",
            "import socket\n\
             try:\n\
             \x20   socket.socket().connect(('1.1.1.1', 443))\n\
             \x20   print('connected')\n\
             except OSError:\n\
             \x20   print('refused')\n",
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("refused"),
        "the default policy denies egress, and auditing must not lift that: {stdout}"
    );
}

#[test]
fn unconfined_is_an_explicit_opt_in() {
    let Some(helper) = helper() else {
        eprintln!("skipping: no audit helper configured");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "top-secret").unwrap();

    let output = audit(
        &helper,
        &[
            "audit",
            "--unconfined",
            "/bin/sh",
            "-c",
            &format!("cat {}", secret.display()),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("top-secret"),
        "--unconfined must actually lift confinement: {stderr}"
    );
    assert!(
        stderr.contains("without confinement"),
        "running unconfined must be reported: {stderr}"
    );
}

#[test]
fn execution_of_a_child_program_is_recorded() {
    let Some(helper) = helper() else {
        eprintln!("skipping: no audit helper configured");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    // `exec` replaces the shell, so the executed program is the target process
    // itself rather than a short-lived child.
    let trace = trace_of(&helper, dir.path(), &["/bin/sh", "-c", "exec /bin/true"]);

    let executed: Vec<_> = trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "execute")
        .filter_map(|event| event["resource"]["path"].as_str().map(str::to_owned))
        .collect();

    assert!(
        executed.iter().any(|path| path.contains("true")),
        "an executed program must appear as an execute event: {executed:?}"
    );
}

#[test]
fn a_short_lived_child_is_recorded_when_scoping_by_cgroup() {
    let Some(helper) = helper() else {
        eprintln!("skipping: no audit helper configured");
        return;
    };
    // Scoping by cgroup needs only a cgroup to create, not the controllers that
    // resource limits need. Without one, observation follows the process tree
    // and this case is a race rather than a guarantee.
    if bailey::backend::cgroup::usable_root(&[]).is_none() {
        eprintln!("skipping: no cgroup to scope observation to");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    // `cat` lives a couple of milliseconds. Under process-tree scoping its exec
    // falls inside the polling window and is missed; under cgroup scoping it is
    // in scope from its first instruction.
    let trace = trace_of(
        &helper,
        dir.path(),
        &["/bin/sh", "-c", "cat /etc/hostname > /dev/null"],
    );

    let events = trace["events"].as_array().unwrap();
    let read_hostname = events.iter().any(|event| {
        event["kind"] == "read"
            && event["resource"]["path"]
                .as_str()
                .is_some_and(|path| path.contains("hostname"))
    });
    let exec_cat = events.iter().any(|event| {
        event["kind"] == "execute"
            && event["resource"]["path"]
                .as_str()
                .is_some_and(|path| path.contains("cat"))
    });

    assert!(read_hostname, "the child's read must be recorded");
    assert!(
        exec_cat,
        "the child's exec must be recorded, which process-tree scoping misses"
    );
}
