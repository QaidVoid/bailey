//! Integration tests for what bailey reports about a host and about a run.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bailey()).args(args).output().unwrap()
}

#[test]
fn doctor_reports_every_mechanism_with_its_consequence() {
    let output = run(&["doctor"]);
    assert!(output.status.success());
    let report = String::from_utf8_lossy(&output.stdout);

    for mechanism in [
        "landlock",
        "user namespaces",
        "cgroup delegation",
        "kernel BTF",
        "helper",
    ] {
        assert!(
            report.contains(mechanism),
            "doctor must report {mechanism}: {report}"
        );
    }
}

#[test]
fn doctor_explains_what_a_missing_feature_costs() {
    let output = run(&["doctor"]);
    let report = String::from_utf8_lossy(&output.stdout);

    // Every "no" answer must be followed by what it means for a run, since the
    // consequence is the part a user can act on.
    for (line, next) in report.lines().zip(report.lines().skip(1)) {
        if line.trim_end().ends_with(": no") {
            assert!(
                next.starts_with("    "),
                "`{}` reports a gap without saying what it costs",
                line.trim()
            );
        }
    }
}

#[test]
fn a_run_reports_what_it_enforced() {
    let output = run(&["run", "/bin/true"]);
    assert!(output.status.success());
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        summary.contains("enforced:") && summary.contains("landlock"),
        "a run must say what it enforced: {summary}"
    );
}

#[test]
fn a_skipped_layer_is_named_with_its_reason() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[resources]\nmemory = \"1GiB\"\n").unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    let summary = String::from_utf8_lossy(&output.stderr);

    // Either the limits applied, or the summary says why they did not.
    let applied = summary.contains("enforced:") && summary.contains("resource limits");
    let explained = summary.contains("not enforced, resource limits:");
    assert!(
        applied || explained,
        "a policy that sets limits must report whether they took effect: {summary}"
    );
}

#[test]
fn the_summary_can_be_suppressed_and_machine_read() {
    let quiet = run(&["run", "--quiet", "/bin/true"]);
    assert!(
        !String::from_utf8_lossy(&quiet.stderr).contains("enforced:"),
        "--quiet must suppress the summary"
    );

    let json = run(&["run", "--json", "/bin/true"]);
    let line = String::from_utf8_lossy(&json.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(line.trim()).expect("--json must emit valid JSON");
    assert!(parsed["applied"].as_array().is_some_and(|a| !a.is_empty()));
    assert_eq!(parsed["exit_code"].as_i64(), Some(0));
}

#[test]
fn every_bundled_profile_can_be_shown_and_used() {
    let listed = run(&["profile", "list"]);
    let list = String::from_utf8_lossy(&listed.stdout);

    for name in [
        "untrusted",
        "native-game",
        "desktop-app",
        "ai-agent",
        "network-client",
    ] {
        assert!(list.contains(name), "profile list must include {name}");

        let shown = run(&["profile", "show", name]);
        assert!(shown.status.success(), "profile show {name} must succeed");
        assert!(
            !shown.stdout.is_empty(),
            "profile show {name} must print the profile"
        );

        let used = run(&["run", "--profile", name, "/bin/true"]);
        assert!(
            used.status.success(),
            "a target must run under the {name} profile: {}",
            String::from_utf8_lossy(&used.stderr)
        );
    }

    let unknown = run(&["profile", "show", "does-not-exist"]);
    assert!(!unknown.status.success());
}

#[test]
fn completions_and_a_man_page_are_generated() {
    let completions = run(&["completions", "bash"]);
    assert!(completions.status.success());
    let script = String::from_utf8_lossy(&completions.stdout);
    assert!(
        script.contains("doctor") && script.contains("audit"),
        "completions must cover the current commands"
    );

    let man = run(&["man"]);
    assert!(man.status.success());
    let page = String::from_utf8_lossy(&man.stdout);
    assert!(page.contains(".TH bailey"), "man output must be a man page");
}

#[test]
fn a_removed_hook_is_explained_rather_than_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[hooks]\non_violation = [\"true\"]\n").unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "an existing config must still run, not fail to parse"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("on_violation") && stderr.contains("ignored"),
        "the removed hook must be explained: {stderr}"
    );
}
