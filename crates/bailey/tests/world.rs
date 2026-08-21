//! Integration tests for the world a target is placed in: its environment,
//! temporary storage, home, and working directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// True only when an isolated run genuinely enters a new PID namespace.
fn isolation_active() -> bool {
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "-c", "echo $$"])
        .output();
    matches!(output, Ok(out) if out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "1")
}

/// A run with its own data home, so the private home lands somewhere temporary.
fn run_in(data_home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bailey())
        .args(args)
        .env("XDG_DATA_HOME", data_home)
        .output()
        .unwrap()
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn caller_credentials_do_not_reach_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(bailey())
        .args(["run", "/usr/bin/env"])
        .env("XDG_DATA_HOME", dir.path())
        .env("AWS_SECRET_ACCESS_KEY", "hunter2")
        .env("SSH_AUTH_SOCK", "/run/user/1000/keyring/ssh")
        .env("GITHUB_TOKEN", "ghp_example")
        .output()
        .unwrap();

    let env = stdout_of(&output);
    for leaked in ["AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "GITHUB_TOKEN"] {
        assert!(
            !env.contains(leaked),
            "{leaked} must not reach the target:\n{env}"
        );
    }
    assert!(
        env.contains("PATH="),
        "the base set must be present:\n{env}"
    );
    assert!(
        env.contains("HOME="),
        "the base set must be present:\n{env}"
    );
}

#[test]
fn named_variables_pass_through_and_denied_ones_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[env]\npass = [\"BAILEY_IT_*\"]\nset = { BAILEY_IT_SET = \"from-config\" }\ndeny = [\"TERM\"]\n",
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg("/usr/bin/env")
        .env("XDG_DATA_HOME", dir.path())
        .env("BAILEY_IT_PASSED", "from-caller")
        .env("BAILEY_IT_SECRET_NOT", "should-still-pass")
        .env("TERM", "xterm")
        .output()
        .unwrap();

    let env = stdout_of(&output);
    assert!(
        env.contains("BAILEY_IT_PASSED=from-caller"),
        "prefix match should pass the variable:\n{env}"
    );
    assert!(
        env.contains("BAILEY_IT_SET=from-config"),
        "set should define the variable:\n{env}"
    );
    assert!(
        !env.lines().any(|line| line.starts_with("TERM=")),
        "deny should remove a base variable:\n{env}"
    );
}

#[test]
fn private_tmp_is_invisible_to_the_host_and_discarded() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();

    // No config, so nothing is granted under /tmp and the private one applies.
    let first = run_in(
        dir.path(),
        &[
            "run",
            "--isolate",
            "/bin/sh",
            "-c",
            "echo written > /tmp/bailey-it-marker && cat /tmp/bailey-it-marker",
        ],
    );
    assert_eq!(
        stdout_of(&first),
        "written",
        "the private /tmp must be writable: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        !Path::new("/tmp/bailey-it-marker").exists(),
        "a write to the private /tmp must not reach the host"
    );

    let second = run_in(
        dir.path(),
        &[
            "run",
            "--isolate",
            "/bin/sh",
            "-c",
            "cat /tmp/bailey-it-marker 2>&1 || echo gone",
        ],
    );
    assert_eq!(
        stdout_of(&second).lines().last().unwrap_or_default().trim(),
        "gone",
        "the private /tmp must not survive the run"
    );
}

#[test]
fn private_home_persists_and_the_real_home_stays_out_of_reach() {
    let dir = tempfile::tempdir().unwrap();

    let first = run_in(
        dir.path(),
        &["run", "/bin/sh", "-c", "echo saved > $HOME/save.txt"],
    );
    assert!(
        first.status.success(),
        "writing to the private home must work: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = run_in(dir.path(), &["run", "/bin/sh", "-c", "cat $HOME/save.txt"]);
    assert_eq!(
        stdout_of(&second),
        "saved",
        "the private home must persist between runs"
    );

    let listing = run_in(dir.path(), &["run", "/bin/sh", "-c", "ls -A $HOME"]);
    assert_eq!(
        stdout_of(&listing),
        "save.txt",
        "the target must see only its private home"
    );

    let real_home = std::env::var("HOME").unwrap();
    assert!(
        !Path::new(&real_home).join("save.txt").exists(),
        "the write must not have reached the real home"
    );
}

#[test]
fn working_directory_is_kept_under_isolation_when_granted() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("data.txt"), "relative-read").unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", work.display()),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", "cat data.txt"])
        .current_dir(&work)
        .env("XDG_DATA_HOME", dir.path())
        .output()
        .unwrap();

    assert_eq!(
        stdout_of(&output),
        "relative-read",
        "a relative path must resolve under isolation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn no_staging_directory_is_left_behind() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let output = run_in(dir.path(), &["run", "--isolate", "/bin/true"]);
    assert!(output.status.success());

    // A staging directory exists for the lifetime of the run that owns it, and
    // other tests run concurrently, so only directories whose owning process is
    // gone count as leaked.
    let leftovers: Vec<_> = fs::read_dir("/tmp")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let pid = name.strip_prefix(".bailey-root.")?;
            let owner_alive = Path::new(&format!("/proc/{pid}")).exists();
            if owner_alive {
                None
            } else {
                Some(entry.path())
            }
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "isolation must not leave staging directories on the host: {leftovers:?}"
    );
}

#[test]
fn a_target_under_the_home_keeps_its_private_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = std::env::var("HOME").unwrap();
    // Most programs live under the home. The target is granted implicitly, and
    // that grant must not be mistaken for the user asking for their real home.
    let program = Path::new(&home).join(".local/bin");
    if !program.join("claude").is_file() && !Path::new("/bin/true").is_file() {
        return;
    }

    let output = run_in(dir.path(), &["show", "/bin/true"]);
    let shown = stdout_of(&output);
    assert!(
        shown.contains("(private;"),
        "a run must get a private home unless the policy grants the real one: {shown}"
    );
}

#[test]
fn granting_the_real_home_still_opts_out() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[filesystem]\nread = [\"~\"]\n").unwrap();

    let output = Command::new(bailey())
        .args(["show", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .env("XDG_DATA_HOME", dir.path())
        .output()
        .unwrap();
    let shown = String::from_utf8_lossy(&output.stdout);
    assert!(
        !shown.contains("(private;"),
        "granting the home itself must hand over the real one: {shown}"
    );
}

/// The guard cleans up on every path a run returns by, but a signal does not
/// unwind: a Ctrl-C leaves the staging directory behind. The next run is what
/// clears it.
#[test]
fn a_staging_directory_from_a_dead_run_is_swept() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }

    // A process id that has certainly finished, standing in for a run that was
    // interrupted before its guard could run.
    let finished = Command::new("/bin/true").output().unwrap();
    assert!(finished.status.success());
    let owner = Command::new("/bin/sh")
        .args(["-c", "echo $$"])
        .output()
        .unwrap();
    let owner = String::from_utf8_lossy(&owner.stdout).trim().to_owned();
    if Path::new(&format!("/proc/{owner}")).exists() {
        eprintln!("skipping: pid {owner} was reused");
        return;
    }

    let stale = PathBuf::from(format!("/tmp/.bailey-root.{owner}"));
    fs::create_dir(&stale).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let output = run_in(dir.path(), &["run", "/bin/true"]);
    assert!(output.status.success());

    let swept = !stale.exists();
    let _ = fs::remove_dir(&stale);
    assert!(
        swept,
        "a run must remove staging directories whose owner is gone"
    );
}
