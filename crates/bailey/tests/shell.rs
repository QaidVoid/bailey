//! Integration tests for the confined shell.
//!
//! Each test drives `/bin/sh` with a script on stdin rather than a terminal, so
//! the assertions are about what the shell and its children can reach, which is
//! the property the command exists for.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// Whether this kernel can deny anything at all. Without Landlock a shell still
/// runs, so a test that asserts a path is unreachable would fail rather than
/// report the host's limits.
fn landlock_available() -> bool {
    bailey::backend::probe::probe(false).landlock_abi.is_some()
}

/// Whether a run genuinely enters its own namespaces, which the read-only
/// remount of a narrower grant needs.
fn isolation_active() -> bool {
    let output = Command::new(bailey())
        .args(["run", "/bin/sh", "-c", "echo $$"])
        .output();
    matches!(output, Ok(out) if out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "1")
}

/// Run a script inside a confined shell launched from `cwd`.
///
/// The store is per-test so that neither the trust records nor the private
/// homes of whoever runs the suite are touched.
fn shell(store: &Path, cwd: &Path, script: &str, env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(bailey());
    command
        .args(["shell", "--shell", "/bin/sh"])
        .current_dir(cwd)
        .env("XDG_DATA_HOME", store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }

    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A project directory next to a directory holding something private.
fn workspace() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let private = root.path().join("private");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&private).unwrap();
    fs::write(project.join("notes.txt"), "project file\n").unwrap();
    fs::write(private.join("key.txt"), "top secret\n").unwrap();
    (root, project, private)
}

#[test]
fn a_command_in_the_shell_is_confined() {
    if !landlock_available() {
        eprintln!("skipping: no Landlock on this kernel");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, project, private) = workspace();

    let output = shell(
        store.path(),
        &project,
        &format!("echo ran\ncat {}/key.txt\n", private.display()),
        &[],
    );
    let shown = stdout(&output);

    assert!(
        shown.contains("ran"),
        "the shell must have started: {shown}"
    );
    assert!(
        !shown.contains("top secret"),
        "a sibling directory is not granted, so the shell must not read it: {shown}"
    );
}

#[test]
fn a_grandchild_process_is_confined() {
    if !landlock_available() {
        eprintln!("skipping: no Landlock on this kernel");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, project, private) = workspace();

    // The point of the command: the restriction is inherited, so a process the
    // shell starts is confined without being invoked through bailey.
    let output = shell(
        store.path(),
        &project,
        &format!("sh -c 'echo ran; cat {}/key.txt'\n", private.display()),
        &[],
    );
    let shown = stdout(&output);

    assert!(
        shown.contains("ran"),
        "the grandchild must have started: {shown}"
    );
    assert!(
        !shown.contains("top secret"),
        "a process started by the shell must inherit the confinement: {shown}"
    );
}

#[test]
fn the_launch_directory_is_readable_and_writable() {
    let store = tempfile::tempdir().unwrap();
    let (_root, project, _private) = workspace();

    let output = shell(
        store.path(),
        &project,
        "cat notes.txt\necho written > new.txt && echo write-ok\n",
        &[],
    );
    let shown = stdout(&output);

    assert!(
        shown.contains("project file"),
        "the launch directory is granted implicitly: {shown}"
    );
    assert!(
        shown.contains("write-ok"),
        "and granted for writing: {shown}"
    );
}

#[test]
fn a_config_layer_can_retract_the_implicit_grant() {
    if !landlock_available() {
        eprintln!("skipping: no Landlock on this kernel");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, project, _private) = workspace();
    let config = project.join("bailey.toml");
    fs::write(&config, "[filesystem]\ndeny = [\".\"]\n").unwrap();

    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();

    let output = shell(
        store.path(),
        &project,
        &format!("echo ran\ncat {}/notes.txt\n", project.display()),
        &[],
    );
    let shown = stdout(&output);

    assert!(
        shown.contains("ran"),
        "the shell must have started: {shown}"
    );
    assert!(
        !shown.contains("project file"),
        "the implicit grant sits beneath every config layer, so a denial retracts it: {shown}"
    );
}

/// The launch directory is granted read-write on the user's behalf. A grant the
/// user wrote for read beneath it must not inherit that write right, or writing
/// `read` in a config would quietly mean `write` on their own files.
#[test]
fn a_read_only_grant_beneath_the_launch_directory_is_honoured() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, project, _private) = workspace();
    let vendor = project.join("vendor");
    fs::create_dir(&vendor).unwrap();
    fs::write(vendor.join("lib.txt"), "original").unwrap();

    let config = project.join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", vendor.display()),
    )
    .unwrap();
    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();

    let output = shell(
        store.path(),
        &project,
        "cat vendor/lib.txt\necho tampered > vendor/lib.txt && echo WROTE\n",
        &[],
    );
    let shown = stdout(&output);

    assert!(
        shown.contains("original"),
        "the read grant must still be readable: {shown}"
    );
    assert!(
        !shown.contains("WROTE"),
        "read was granted, not write: {shown}"
    );
    assert_eq!(
        fs::read_to_string(vendor.join("lib.txt")).unwrap(),
        "original",
        "and nothing must reach the host file"
    );
}

#[test]
fn the_marker_variables_reach_a_command_inside() {
    let store = tempfile::tempdir().unwrap();
    let (_root, project, _private) = workspace();

    let output = shell(
        store.path(),
        &project,
        "echo \"marker=$BAILEY_SANDBOX dir=$BAILEY_SANDBOX_DIR net=$BAILEY_SANDBOX_NET\"\n",
        &[],
    );
    let shown = stdout(&output);

    assert!(shown.contains("marker=1"), "{shown}");
    // Which network the run got depends on the host: without user namespaces
    // there is no namespace to build. What matters is that the marker says which
    // one, since a nested run reads it rather than guessing.
    let network = if isolation_active() {
        "net=isolated"
    } else {
        "net=host"
    };
    assert!(
        shown.contains(network),
        "the network the sandbox built is published, so a nested run can report \
         what it inherited rather than guess: {shown}"
    );
    assert!(
        shown.contains(&format!("dir={}", project.display())),
        "the marker names the directory the policy was resolved for: {shown}"
    );
}

#[test]
fn each_directory_gets_its_own_private_home() {
    let store = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();

    // Same file name, different directories: the case a home keyed on the name
    // alone would collapse into one.
    for parent in ["one", "two"] {
        let dir = root.path().join(parent).join("app");
        fs::create_dir_all(&dir).unwrap();
        shell(store.path(), &dir, "true\n", &[]);
    }

    let homes: Vec<_> = fs::read_dir(store.path().join("bailey/shell"))
        .expect("a shell home directory")
        .flatten()
        .collect();
    assert_eq!(
        homes.len(),
        2,
        "two directories called `app` must not share one private home"
    );
}

#[test]
fn the_shells_exit_status_is_baileys() {
    let store = tempfile::tempdir().unwrap();
    let (_root, project, _private) = workspace();

    let output = shell(store.path(), &project, "exit 7\n", &[]);
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn launching_from_the_home_directory_is_reported() {
    let store = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    let output = shell(
        store.path(),
        home.path(),
        "true\n",
        &[("HOME", &home.path().display().to_string())],
    );

    assert!(
        stderr(&output).contains("your whole home directory"),
        "granting the home by standing in it must be said out loud: {}",
        stderr(&output)
    );
}

#[test]
fn a_shell_inside_a_shell_explains_itself() {
    let store = tempfile::tempdir().unwrap();
    let (_root, project, _private) = workspace();

    let output = shell(
        store.path(),
        &project,
        "true\n",
        &[
            ("BAILEY_SANDBOX", "1"),
            ("BAILEY_SANDBOX_DIR", "/elsewhere"),
        ],
    );

    assert!(
        stderr(&output).contains("/elsewhere"),
        "a nested shell names the sandbox it is already inside: {}",
        stderr(&output)
    );
}

#[test]
fn what_was_enforced_is_reported_before_the_shell_runs() {
    let store = tempfile::tempdir().unwrap();
    let (_root, project, _private) = workspace();

    // Both writes land on the same stream, so their order in it is the thing
    // being asserted: a summary printed after the shell has already spoken is
    // one the user reads too late.
    let output = shell(store.path(), &project, "echo shell-output >&2\n", &[]);
    let shown = stderr(&output);

    let summary = shown
        .find("bailey: enforced:")
        .unwrap_or_else(|| panic!("no summary: {shown}"));
    let from_shell = shown
        .find("shell-output")
        .unwrap_or_else(|| panic!("the shell did not run: {shown}"));
    assert!(
        summary < from_shell,
        "the summary belongs before the shell takes the terminal: {shown}"
    );
}
