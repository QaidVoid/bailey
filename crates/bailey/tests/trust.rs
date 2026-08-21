//! Integration tests for the trust gate on discovered configuration.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// Run bailey with a trust store of its own, so a test never reads or writes
/// the store belonging to whoever is running the suite.
fn run(store: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(bailey())
        .args(args)
        .current_dir(cwd)
        .env("XDG_DATA_HOME", store)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A project directory whose config grants read on a marker path.
fn project(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let marker = dir.join("marker-dir");
    fs::create_dir(&marker).unwrap();
    let config = dir.join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", marker.display()),
    )
    .unwrap();
    (config, marker)
}

#[test]
fn a_discovered_config_applies_only_once_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (config, marker) = project(dir.path());

    let before = run(store.path(), dir.path(), &["show", "/usr/bin/true"]);
    let shown = stdout(&before);
    assert!(
        shown.contains("not applied"),
        "an untrusted config must be reported: {shown}"
    );
    assert!(
        !shown.contains(&marker.display().to_string()),
        "and must grant nothing: {shown}"
    );

    let accepted = run(
        store.path(),
        dir.path(),
        &["trust", &config.display().to_string()],
    );
    assert!(
        accepted.status.success(),
        "trusting must succeed: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    let after = run(store.path(), dir.path(), &["show", "/usr/bin/true"]);
    let shown = stdout(&after);
    assert!(
        shown.contains(&marker.display().to_string()),
        "a trusted config must contribute its grants: {shown}"
    );
    assert!(
        !shown.contains("not applied"),
        "and must not be reported as skipped: {shown}"
    );
}

#[test]
fn editing_a_trusted_config_revokes_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (config, marker) = project(dir.path());

    run(
        store.path(),
        dir.path(),
        &["trust", &config.display().to_string()],
    );
    fs::write(&config, "[filesystem]\nread = [\"/\"]\n").unwrap();

    let shown = stdout(&run(store.path(), dir.path(), &["show", "/usr/bin/true"]));
    assert!(
        shown.contains("changed since you trusted it"),
        "an edited config must say why it stopped applying: {shown}"
    );
    assert!(
        !shown.contains(&marker.display().to_string()),
        "and must contribute nothing: {shown}"
    );

    let listed = stdout(&run(store.path(), dir.path(), &["trust", "--list"]));
    assert!(
        listed.contains("changed") && listed.contains(&config.display().to_string()),
        "the listing must show that the recorded file no longer verifies: {listed}"
    );
}

#[test]
fn trust_can_be_withdrawn() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (config, marker) = project(dir.path());
    let path = config.display().to_string();

    run(store.path(), dir.path(), &["trust", &path]);
    let listed = stdout(&run(store.path(), dir.path(), &["trust", "--list"]));
    assert!(listed.contains("ok"), "{listed}");

    let withdrawn = run(store.path(), dir.path(), &["untrust", &path]);
    assert!(withdrawn.status.success(), "untrust must succeed");

    let shown = stdout(&run(store.path(), dir.path(), &["show", "/usr/bin/true"]));
    assert!(
        !shown.contains(&marker.display().to_string()),
        "a withdrawn config must stop contributing: {shown}"
    );

    let again = run(store.path(), dir.path(), &["untrust", &path]);
    assert!(
        !again.status.success(),
        "withdrawing what was never trusted must say so rather than pass silently"
    );
}

#[test]
fn an_explicitly_named_config_needs_no_trust() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let (config, marker) = project(dir.path());

    // Run from elsewhere, so the file can only arrive through `--config`.
    let elsewhere = tempfile::tempdir().unwrap();
    let shown = stdout(&run(
        store.path(),
        elsewhere.path(),
        &[
            "show",
            "--config",
            &config.display().to_string(),
            "/usr/bin/true",
        ],
    ));

    assert!(
        shown.contains(&marker.display().to_string()),
        "a config the user named on the command line applies as given: {shown}"
    );
}

#[test]
fn an_empty_store_lists_nothing() {
    let store = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let listed = stdout(&run(store.path(), dir.path(), &["trust", "--list"]));
    assert!(listed.contains("no config files"), "{listed}");
}

#[test]
fn a_run_reports_a_skipped_config_without_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    project(dir.path());

    let output = run(
        store.path(),
        dir.path(),
        &["run", "--no-isolate", "/bin/true"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "an untrusted config narrows the policy rather than failing the run: {stderr}"
    );
    assert!(
        stderr.contains("not applying") && stderr.contains("bailey trust"),
        "the run must name the file and the command that would accept it: {stderr}"
    );
}
