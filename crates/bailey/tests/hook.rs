//! Integration tests for the shell integration.
//!
//! The snippets are handed to the shells they are for, rather than only being
//! string-matched: a shell integration that does not parse is the failure mode
//! worth catching, and it cannot be caught from Rust.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn hook(store: &Path, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(bailey());
    command
        .arg("hook")
        .args(args)
        .current_dir(cwd)
        .env("XDG_DATA_HOME", store);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A directory holding a config, and a store to record trust in.
fn project() -> (tempfile::TempDir, tempfile::TempDir, std::path::PathBuf) {
    let store = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[filesystem]\nread = [\".\"]\n").unwrap();
    (store, dir, config)
}

#[test]
fn an_untrusted_config_is_announced_with_the_command_that_accepts_it() {
    let (store, dir, _config) = project();

    let shown = stdout(&hook(
        store.path(),
        dir.path(),
        &["status", "--porcelain"],
        &[],
    ));

    assert!(
        shown.starts_with("info\t"),
        "not an offer to act on: {shown}"
    );
    assert!(shown.contains("have not accepted"), "{shown}");
    assert!(
        shown.contains("bailey trust ./bailey.toml"),
        "and it names the command, as typed from here: {shown}"
    );
    assert!(
        !shown.contains("bailey shell"),
        "a shell would not apply this config, so it must not be suggested: {shown}"
    );
}

#[test]
fn a_trusted_config_is_offered() {
    let (store, dir, config) = project();
    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();

    let shown = stdout(&hook(
        store.path(),
        dir.path(),
        &["status", "--porcelain"],
        &[],
    ));

    assert!(shown.starts_with("ready\t"), "{shown}");
    assert!(shown.contains("bailey shell"), "{shown}");
}

#[test]
fn an_edited_config_says_it_changed() {
    let (store, dir, config) = project();
    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();
    fs::write(&config, "[filesystem]\nread = [\"/\"]\n").unwrap();

    let shown = stdout(&hook(
        store.path(),
        dir.path(),
        &["status", "--porcelain"],
        &[],
    ));

    assert!(shown.starts_with("info\t"), "{shown}");
    assert!(shown.contains("changed since you accepted it"), "{shown}");
}

#[test]
fn a_directory_with_no_config_says_nothing() {
    let store = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let shown = stdout(&hook(
        store.path(),
        dir.path(),
        &["status", "--porcelain"],
        &[],
    ));

    assert!(shown.trim().is_empty(), "expected silence, got: {shown}");
}

#[test]
fn inside_a_sandbox_only_leaving_the_policy_directory_is_reported() {
    let (store, dir, _config) = project();

    let inside = stdout(&hook(
        store.path(),
        dir.path(),
        &["status", "--porcelain"],
        &[
            ("BAILEY_SANDBOX", "1"),
            ("BAILEY_SANDBOX_DIR", &dir.path().display().to_string()),
        ],
    ));
    assert!(
        inside.trim().is_empty(),
        "a confined shell in its own directory has nothing to report: {inside}"
    );

    let elsewhere = stdout(&hook(
        store.path(),
        dir.path(),
        &["status", "--porcelain"],
        &[
            ("BAILEY_SANDBOX", "1"),
            ("BAILEY_SANDBOX_DIR", "/somewhere/else"),
        ],
    ));
    assert!(
        elsewhere.contains("does not cover the directory you are now in"),
        "the policy does not follow a cd, and the failures that causes look like \
         a broken tool: {elsewhere}"
    );
}

#[test]
fn the_snippets_parse_in_the_shells_they_are_for() {
    let store = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();

    for (shell, check) in [("fish", vec!["-n"]), ("bash", vec!["-n"])] {
        if Command::new(shell).arg("--version").output().is_err() {
            eprintln!("skipping: no {shell} on this host");
            continue;
        }
        for flags in [vec![], vec!["--ask"], vec!["--wrap"]] {
            let mut args = vec![shell];
            args.extend(flags.iter().copied());
            let snippet = stdout(&hook(store.path(), dir.path(), &args, &[]));
            assert!(!snippet.is_empty(), "{shell} {flags:?} emitted nothing");

            let path = dir.path().join(format!("hook-{shell}"));
            fs::write(&path, &snippet).unwrap();
            let parsed = Command::new(shell)
                .args(&check)
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                parsed.status.success(),
                "{shell} cannot parse its own hook with {flags:?}: {}",
                String::from_utf8_lossy(&parsed.stderr)
            );
        }
    }
}

#[test]
fn asking_is_opt_in() {
    let store = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let plain = stdout(&hook(store.path(), dir.path(), &["fish"], &[]));
    let asking = stdout(&hook(store.path(), dir.path(), &["fish", "--ask"], &[]));

    assert!(
        !plain.contains("__bailey_hook_ask 1"),
        "a cd is not a decision point: {plain}"
    );
    assert!(asking.contains("set -g __bailey_hook_ask 1"));
}

#[test]
fn wrappers_come_from_a_user_profiles_claims() {
    let store = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();
    let profiles = config_home.path().join("bailey/profiles");
    fs::create_dir_all(&profiles).unwrap();
    fs::write(
        profiles.join("agent.toml"),
        "applies_to = [\"my-agent\", \"/opt/thing/bin/thing\"]\n",
    )
    .unwrap();
    let env = [(
        "XDG_CONFIG_HOME",
        &*config_home.path().display().to_string(),
    )];

    let listed = stdout(&hook(
        store.path(),
        config_home.path(),
        &["list-wrapped"],
        &env,
    ));
    assert!(listed.contains("my-agent"), "{listed}");
    assert!(
        !listed.contains("thing"),
        "a claim written as a path names one executable; a function of that name \
         would catch every program called `thing`: {listed}"
    );

    let wrapped = stdout(&hook(
        store.path(),
        config_home.path(),
        &["fish", "--wrap"],
        &env,
    ));
    assert!(wrapped.contains("function my-agent"), "{wrapped}");
    assert!(wrapped.contains("command bailey run my-agent"), "{wrapped}");

    let plain = stdout(&hook(store.path(), config_home.path(), &["fish"], &env));
    assert!(
        !plain.contains("function my-agent"),
        "shadowing a command is opt-in: {plain}"
    );
}

#[test]
fn an_unsupported_shell_names_the_supported_ones() {
    let output = Command::new(bailey())
        .args(["hook", "zsh"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fish") && stderr.contains("bash"),
        "{stderr}"
    );
}
