//! Integration tests for the audit backend.
//!
//! These need the privileged helper: eBPF programs cannot be loaded without
//! `CAP_BPF` and `CAP_PERFMON`. They self-skip where the helper is absent or
//! lacks its capabilities, so the suite stays green on a machine that cannot
//! record.
mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// The helper, if one is configured and able to load its programs.
/// `doctor` and a run must agree about where the helper is. They looked
/// separately once, and disagreed: a helper installed on PATH was reported
/// missing by `doctor` while `bailey audit` used it happily.
#[test]
fn the_helper_is_found_on_path() {
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join("bailey-bpf-helper");
    fs::write(&installed, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Somewhere with no helper beside it, so only PATH can answer.
    let elsewhere = dir.path().join("bin");
    fs::create_dir(&elsewhere).unwrap();
    let bailey_copy = elsewhere.join("bailey");
    fs::copy(bailey(), &bailey_copy).unwrap();

    let output = Command::new(&bailey_copy)
        .arg("doctor")
        .env("PATH", dir.path())
        .env_remove("BAILEY_BPF_HELPER")
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&output.stdout);

    assert!(
        !report.contains("helper: not found"),
        "a helper on PATH is one a run would use, so `doctor` must see it: {report}"
    );
    assert!(
        report.contains(&installed.display().to_string()),
        "and must name the one it found: {report}"
    );
}

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
        common::skip("no audit helper configured");
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
        common::skip("no audit helper configured");
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
        common::skip("no audit helper configured");
        return;
    };
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("needs python3");
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

/// Audit runs in the host namespace by design, so a policy whose mode asks
/// for more than Landlock's TCP rules names the gap instead of quietly
/// skipping it.
#[test]
fn an_audit_of_a_network_mode_it_cannot_honour_names_the_gap() {
    let Some(helper) = helper() else {
        common::skip("no audit helper configured");
        return;
    };
    let dir = tempfile::tempdir().unwrap();

    let private = dir.path().join("private.toml");
    fs::write(&private, "[network]\nmode = \"private\"\n").unwrap();
    let output = audit(
        &helper,
        &[
            "audit",
            "-c",
            private.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit runs in the host namespace"),
        "a private-mode policy audited in the host namespace must say so: {stderr}"
    );
    assert!(
        stderr.contains(&private.display().to_string()),
        "the note must name where the private mode came from: {stderr}"
    );

    let brokered = dir.path().join("brokered.toml");
    fs::write(&brokered, "[network]\nbroker = \"10.0.0.1:9999\"\n").unwrap();
    let output = audit(
        &helper,
        &[
            "audit",
            "-c",
            brokered.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("the broker at 10.0.0.1:9999"),
        "a brokered policy audited in the host namespace must say so: {stderr}"
    );
    assert!(
        stderr.contains(&brokered.display().to_string()),
        "the note must name where the broker came from: {stderr}"
    );
}

#[test]
fn unconfined_is_an_explicit_opt_in() {
    let Some(helper) = helper() else {
        common::skip("no audit helper configured");
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
        common::skip("no audit helper configured");
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
        common::skip("no audit helper configured");
        return;
    };
    // Scoping by cgroup needs only a cgroup to create, not the controllers that
    // resource limits need. Without one, observation follows the process tree
    // and this case is a race rather than a guarantee.
    if bailey::backend::cgroup::usable_root(&[]).is_none() {
        common::skip("no cgroup to scope observation to");
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

/// Where the run's cgroup carries the measuring controllers, the trace records
/// what the run reached: a shell that backgrounds several sleeps holds more
/// tasks at once than its own process, and allocates something.
#[test]
fn peaks_are_recorded_when_the_cgroup_carries_them() {
    let Some(helper) = helper() else {
        common::skip("no audit helper configured");
        return;
    };
    if bailey::backend::cgroup::usable_root(&["memory", "pids"]).is_none() {
        common::skip("no cgroup carrying memory and pids to measure in");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let trace = trace_of(
        &helper,
        dir.path(),
        &["/bin/sh", "-c", "for i in 1 2 3 4; do sleep 1 & done; wait"],
    );

    let usage = &trace["usage"];
    assert!(
        usage.is_object(),
        "a measured run records its peaks: {trace}"
    );
    let tasks = usage["tasks_peak"].as_u64().expect("a tasks peak");
    assert!(
        tasks >= 4,
        "four backgrounded sleeps plus the shell must hold at least 5 tasks, got {tasks}"
    );
    let memory = usage["memory_peak_bytes"].as_u64().expect("a memory peak");
    assert!(memory > 0, "the run allocated something: {memory}");
    assert!(
        usage["unmeasured"]
            .as_array()
            .is_none_or(|reasons| reasons.is_empty()),
        "measured peaks leave nothing to explain: {usage}"
    );
}

/// A run with no cgroup at all records both peaks as unmeasured, and each
/// reason says what was lost rather than leaving the fields absent.
#[test]
fn an_unmeasured_peak_says_why() {
    let Some(helper) = helper() else {
        common::skip("no audit helper configured");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trace.json");
    let override_path = "/nonexistent";
    let output = Command::new(bailey())
        .args([
            "audit",
            "--save-trace",
            path.to_str().unwrap(),
            "/bin/sh",
            "-c",
            "true",
        ])
        .env("BAILEY_BPF_HELPER", helper)
        .env("BAILEY_CGROUP_ROOT", override_path)
        .output()
        .unwrap();
    assert!(
        path.exists(),
        "audit did not produce a trace: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    let usage = &trace["usage"];
    assert!(
        usage.is_object(),
        "the run explains its missing peaks: {trace}"
    );
    assert!(
        usage["memory_peak_bytes"].is_null(),
        "no cgroup, no memory peak: {usage}"
    );
    assert!(
        usage["tasks_peak"].is_null(),
        "no cgroup, no tasks peak: {usage}"
    );
    let reasons: Vec<String> = usage["unmeasured"]
        .as_array()
        .expect("unmeasured peaks are listed")
        .iter()
        .map(|reason| reason.as_str().expect("a string reason").to_owned())
        .collect();
    assert_eq!(reasons.len(), 2, "both peaks are named: {reasons:?}");
    assert!(
        reasons.iter().all(|reason| reason.contains("no cgroup")),
        "each reason names the missing cgroup: {reasons:?}"
    );
}
