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
    let reported = cgroup_of_a_forked_descendant(false);
    assert!(
        reported.contains("bailey."),
        "a process forked by the target must inherit the run's cgroup: {reported}"
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
