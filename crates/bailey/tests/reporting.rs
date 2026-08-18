//! Integration tests for what bailey reports about a host and about a run.

use std::fs;
use std::path::Path;
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

/// A run with its own config home, so user profiles land somewhere temporary.
fn with_profiles(config_home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bailey())
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .output()
        .unwrap()
}

fn write_profile(config_home: &Path, name: &str, body: &str) {
    let dir = config_home.join("bailey/profiles");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(format!("{name}.toml")), body).unwrap();
}

#[test]
fn a_user_profile_can_be_listed_shown_and_used() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(dir.path(), "mine", "[filesystem]\nread = [\"/opt/mine\"]\n");

    let listed = with_profiles(dir.path(), &["profile", "list"]);
    let list = String::from_utf8_lossy(&listed.stdout);
    assert!(list.contains("yours:") && list.contains("mine"), "{list}");

    let shown = with_profiles(dir.path(), &["profile", "show", "mine"]);
    assert!(String::from_utf8_lossy(&shown.stdout).contains("/opt/mine"));

    let used = with_profiles(dir.path(), &["show", "--profile", "mine", "/bin/true"]);
    assert!(
        String::from_utf8_lossy(&used.stdout).contains("/opt/mine"),
        "a user profile must contribute to the policy"
    );
}

#[test]
fn a_profile_claims_its_target_unless_one_is_given() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(
        dir.path(),
        "claims-true",
        "applies_to = [\"true\"]\n[filesystem]\nread = [\"/opt/claimed\"]\n",
    );

    let auto = with_profiles(dir.path(), &["show", "/bin/true"]);
    assert!(
        String::from_utf8_lossy(&auto.stdout).contains("/opt/claimed"),
        "a profile that claims the target must be selected"
    );
    assert!(
        String::from_utf8_lossy(&auto.stderr).contains("claims this target"),
        "a policy selected for the user must be reported"
    );

    let explicit = with_profiles(dir.path(), &["show", "--profile", "untrusted", "/bin/true"]);
    assert!(
        !String::from_utf8_lossy(&explicit.stdout).contains("/opt/claimed"),
        "an explicit --profile must win"
    );

    let other = with_profiles(dir.path(), &["show", "/bin/sh"]);
    assert!(
        !String::from_utf8_lossy(&other.stdout).contains("/opt/claimed"),
        "a profile must not apply to a target it does not claim"
    );
}

#[test]
fn two_profiles_claiming_one_target_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(dir.path(), "first", "applies_to = [\"true\"]\n");
    write_profile(dir.path(), "second", "applies_to = [\"true\"]\n");

    let output = with_profiles(dir.path(), &["show", "/bin/true"]);
    assert!(
        !output.status.success(),
        "ambiguous selection must not proceed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("first") && stderr.contains("second"),
        "the error must name both profiles: {stderr}"
    );
}

#[test]
fn a_bundled_name_cannot_be_shadowed() {
    let dir = tempfile::tempdir().unwrap();
    write_profile(
        dir.path(),
        "untrusted",
        "[filesystem]\nread = [\"/opt/shadow\"]\n",
    );

    let output = with_profiles(dir.path(), &["show", "--profile", "untrusted", "/bin/true"]);
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("/opt/shadow"),
        "a bundled profile must win over a file of the same name"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ignored"),
        "the shadowing attempt must be reported"
    );
}
