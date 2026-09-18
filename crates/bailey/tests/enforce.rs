//! Integration tests for the enforcement backend.
//!
//! These execute real programs under Landlock and seccomp. They self-skip on a
//! kernel without Landlock so they stay green in environments that lack it.

use std::fs;
use std::path::Path;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn landlock_available() -> bool {
    bailey::backend::probe::probe(false).landlock_abi.is_some()
}

fn write_config(dir: &Path, extra_read: &str) -> std::path::PathBuf {
    let config = dir.join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{extra_read}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n"
        ),
    )
    .unwrap();
    config
}

#[test]
fn granted_path_is_readable_and_program_runs() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed.txt");
    fs::write(&allowed, "hello-allowed").unwrap();
    let config = write_config(dir.path(), allowed.to_str().unwrap());

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("cat {}", allowed.display()))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "program should run under enforcement"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello-allowed"
    );
}

#[test]
fn ungranted_path_is_denied() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed.txt");
    let secret = dir.path().join("secret.txt");
    fs::write(&allowed, "hello-allowed").unwrap();
    fs::write(&secret, "top-secret").unwrap();
    let config = write_config(dir.path(), allowed.to_str().unwrap());

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("cat {}", secret.display()))
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "reading an ungranted path must fail"
    );
}

#[test]
fn denied_syscall_is_blocked() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    if !Path::new("/usr/bin/unshare").exists() {
        eprintln!("skipping: /usr/bin/unshare not present");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed.txt");
    fs::write(&allowed, "x").unwrap();
    let config = write_config(dir.path(), allowed.to_str().unwrap());

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/usr/bin/unshare", "-U", "true"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "unshare must be blocked by seccomp"
    );
}

#[test]
fn a_file_cannot_grow_past_the_limit() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{work}\"]\n\
             write = [\"{work}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             \n\
             [resources]\n\
             file_max = \"1M\"\n",
            work = work.display()
        ),
    )
    .unwrap();

    let target = work.join("big.bin");
    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!(
            "dd if=/dev/zero of={} bs=1024 count=8192 2>/dev/null",
            target.display()
        ))
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "a write past the limit must fail rather than succeed quietly"
    );
    let written = fs::metadata(&target).map(|meta| meta.len()).unwrap_or(0);
    assert!(
        written <= 1_000_000,
        "the file grew to {written} bytes despite a 1M limit"
    );
}

/// Where no cgroup was delegated, `pids_max` is met by `RLIMIT_NPROC` instead,
/// which is only a bound at all because the run has a user namespace of its own.
/// Skipped where a cgroup is available, since there the cgroup takes the limit
/// and no rlimit is set.
#[test]
fn a_process_limit_holds_without_a_cgroup() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    if bailey::backend::cgroup::usable_root(&["pids"]).is_some() {
        eprintln!("skipping: a delegated cgroup takes the limit here");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[resources]\npids_max = 7\n").unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/cat", "/proc/self/limits"])
        .output()
        .unwrap();

    let limits = String::from_utf8_lossy(&output.stdout);
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max processes"))
        .unwrap_or_default();
    let reported = String::from_utf8_lossy(&output.stderr);
    // The summary line rather than the whole of stderr: a host without user
    // namespaces warns that it is "running without namespace isolation", which
    // names the layer it is saying is absent.
    let summary = reported
        .lines()
        .find(|line| line.starts_with("bailey: enforced:"))
        .unwrap_or_default();

    // The rlimit bounds what it should only inside a user namespace of the
    // run's own, so which case this host is is what the summary says. Where
    // unprivileged user namespaces are restricted, Ubuntu's default among them,
    // the limit must stay off rather than count the caller's own processes.
    let namespaced =
        summary.contains("namespace isolation") || summary.contains("network namespace");
    if namespaced {
        assert!(
            line.split_whitespace()
                .filter(|field| *field == "7")
                .count()
                == 2,
            "the process limit must reach the target, soft and hard: {line:?}"
        );
        assert!(
            summary.contains("process limit"),
            "the process limit must be reported as enforced: {reported}"
        );
    } else {
        assert!(
            !summary.contains("process limit"),
            "without a user namespace the limit must not be claimed: {reported}"
        );
        assert!(
            reported.contains("not enforced, resource limits"),
            "without a user namespace the limit must be reported skipped: {reported}"
        );
    }
}

/// The limit is an rlimit, so unlike the cgroup limits it needs no delegated
/// cgroup. This asserts it is reported as applied rather than skipped, which is
/// what tells an operator the guarantee actually holds on this host.
#[test]
fn the_file_limit_is_reported_as_enforced() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[resources]\nfile_max = \"1M\"\n").unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();

    let reported = String::from_utf8_lossy(&output.stderr);
    assert!(
        reported.contains("file size limit"),
        "the file limit must be reported as enforced: {reported}"
    );
}
