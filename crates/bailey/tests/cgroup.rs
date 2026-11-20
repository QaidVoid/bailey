//! Integration tests for cgroup resource limits.
//!
//! Limits need a writable delegated cgroup v2. These self-skip where the
//! session does not provide one, which is common in containers and CI.
mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bailey::backend::cgroup;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// Whether this host gives the user a cgroup runs can be created in, asked the
/// same way the enforcement backend asks it.
fn cgroup_usable() -> bool {
    bailey::backend::cgroup::usable_root(&["memory", "pids"]).is_some()
}

/// Whether a run's scope request would get past the gates: systemd as init,
/// and a user manager that lingers so its answer can be had.
fn user_manager_available() -> bool {
    if !Path::new("/run/systemd/system").is_dir() {
        return false;
    }
    let user = std::env::var("USER").unwrap_or_default();
    Path::new("/var/lib/systemd/linger").join(&user).exists()
}

fn config_with_limits(dir: &Path) -> PathBuf {
    let config = dir.join("bailey.toml");
    fs::write(&config, "[resources]\npids_max = 64\nmemory = \"256MiB\"\n").unwrap();
    config
}

/// A grandchild of the target reports the cgroup it belongs to. The subshell
/// forces a fork, so this fails if membership were established after the spawn.
fn cgroup_of_a_forked_descendant(isolate: bool) -> String {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_limits(dir.path());

    let mut command = Command::new(bailey());
    command.arg("run");
    if isolate {
        command.arg("--isolate");
    }
    command
        .arg("-c")
        .arg(&config)
        .args(["/bin/sh", "-c", "(cat /proc/self/cgroup)"]);

    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn forked_descendant_is_in_the_run_cgroup() {
    if !cgroup_usable() {
        common::skip("no delegated cgroup to create runs in");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_limits(dir.path());

    let output = Command::new(bailey())
        .arg("run")
        .arg("-c")
        .arg(&config)
        .args(["/bin/sh", "-c", "(cat /proc/self/cgroup)"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reported = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        reported.contains("bailey."),
        "a process forked by the target must inherit the run's cgroup: {reported}"
    );
    // A session that already sits in a delegated subtree must not produce a
    // scope: the request is only for sessions the search fails in.
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        !summary.contains("systemd user scope"),
        "a session with delegation must not ask the user manager: {summary}"
    );
}

#[test]
fn limits_apply_under_isolation() {
    if !cgroup_usable() {
        common::skip("no delegated cgroup to create runs in");
        return;
    }
    let reported = cgroup_of_a_forked_descendant(true);
    assert!(
        reported.contains("bailey."),
        "the target must join the run's cgroup under isolation: {reported}"
    );
}

#[test]
fn cgroup_is_removed_after_the_run() {
    if !cgroup_usable() {
        common::skip("no delegated cgroup to create runs in");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_limits(dir.path());

    // The check is scoped to this run's own cgroup, named for the bailey
    // process's pid: the matrix runs suites in parallel, so another test's
    // live run cgroup may exist while this one looks, and a whole-subtree
    // scan would fail on it.
    let mut child = Command::new(bailey())
        .arg("run")
        .arg("-c")
        .arg(&config)
        .arg("/bin/true")
        .spawn()
        .unwrap();
    let run_cgroup = cgroup::usable_root(&["memory", "pids"])
        .unwrap()
        .join(format!("bailey.{}", child.id()));
    let status = child.wait().unwrap();
    assert!(status.success());

    assert!(
        !run_cgroup.exists(),
        "the run's own cgroup must be removed after the run: {}",
        run_cgroup.display()
    );
}

/// A session the search fails in gets a delegated scope from the user
/// manager: bailey moves into a leaf of it, the run's cgroup is created
/// beside the leaf, and the limits are enforced through it. This is the path
/// an SSH session, a text console or a CI job takes on a systemd host.
#[test]
fn a_session_without_delegation_gets_a_user_scope() {
    if cgroup_usable() {
        common::skip("the session already has a delegated cgroup");
        return;
    }
    if !user_manager_available() {
        common::skip("no systemd user manager to ask");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_limits(dir.path());

    let output = Command::new(bailey())
        .arg("run")
        .arg("-c")
        .arg(&config)
        .args(["/bin/sh", "-c", "cat /proc/self/cgroup"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reported = String::from_utf8_lossy(&output.stdout).into_owned();
    let line = reported
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("the target must sit in the unified hierarchy");
    let mut components: Vec<&str> = line.trim().split('/').filter(|c| !c.is_empty()).collect();
    let run_dir = components.pop().expect("a cgroup path");
    let scope = components.last().copied().unwrap_or_default();
    assert!(
        scope.starts_with("bailey-") && scope.ends_with(".scope"),
        "the run's cgroup must sit beneath a bailey scope: {reported}"
    );
    let memory_max = Path::new("/sys/fs/cgroup")
        .join(components.join("/"))
        .join(scope)
        .join(run_dir)
        .join("memory.max");
    assert_eq!(
        fs::read_to_string(&memory_max).unwrap().trim(),
        (256 * 1024 * 1024).to_string(),
        "the policy's memory limit must hold in the run's cgroup: {}",
        memory_max.display()
    );

    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        summary.contains("resource limits") && summary.contains("systemd user scope"),
        "the summary must name the limits and the scope that carries them: {summary}"
    );

    let json = Command::new(bailey())
        .arg("run")
        .arg("--json")
        .arg("-c")
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim())
            .expect("--json must emit valid JSON");
    let applied = parsed["applied"].as_array().expect("applied is an array");
    assert!(
        applied.iter().any(|layer| layer == "resource limits")
            && applied.iter().any(|layer| layer == "systemd user scope"),
        "--json must carry both layers in applied: {parsed}"
    );
}

/// The scope exists only while the run does: once bailey and the target have
/// exited, the manager collects the unit and nothing named for bailey is
/// left in `systemctl --user`.
#[test]
fn the_scope_is_gone_after_the_run() {
    if cgroup_usable() {
        common::skip("the session already has a delegated cgroup");
        return;
    }
    if !user_manager_available() {
        common::skip("no systemd user manager to ask");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_limits(dir.path());

    let output = Command::new(bailey())
        .arg("run")
        .arg("-c")
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The unit stops by itself once its last process exits; the manager
    // collects it in its own time, hence the poll.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let listed = Command::new("systemctl")
            .args(["--user", "list-units", "--all", "--no-legend", "bailey-*"])
            .output();
        match listed {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                common::skip("systemctl is unavailable");
                return;
            }
            Err(error) => panic!("listing the user's units failed: {error}"),
            Ok(units) if units.stdout.is_empty() => break,
            Ok(units) if std::time::Instant::now() >= deadline => panic!(
                "the scope must be collected after the run: {}",
                String::from_utf8_lossy(&units.stdout)
            ),
            Ok(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// An override names the cgroup itself, so no scope may be asked for: the
/// run keeps today's reason and no unit appears in the user manager.
#[test]
fn a_cgroup_root_override_suppresses_the_scope_request() {
    if !Path::new("/run/systemd/system").is_dir() {
        common::skip("needs a systemd host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config_with_limits(dir.path());

    let output = Command::new(bailey())
        .arg("run")
        .arg("-c")
        .arg(&config)
        .arg("/bin/true")
        .env("BAILEY_CGROUP_ROOT", "/nonexistent")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        summary.contains("not enforced, resource limits:")
            && summary.contains("no cgroup this user may create runs in"),
        "an override that fails keeps today's reason: {summary}"
    );
    assert!(
        !summary.contains("systemd user scope"),
        "an override must suppress the scope request: {summary}"
    );
}
