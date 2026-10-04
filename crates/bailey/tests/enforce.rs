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

/// A `[[fuse]]` entry is mounted by bailey before the target starts and
/// appears at its `at` inside the sandbox. The mount command here fills the
/// mountpoint by hand, which stands in for a real FUSE filesystem: what the
/// test proves is the wiring, that the command runs, the grant is placed, and
/// the mount lands where the policy says.
#[test]
fn a_fuse_mount_is_performed_and_placed() {
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             [[fuse]]\n\
             mount = \"mkdir -p \\\"$BAILEY_MOUNTPOINT\\\" && echo from-mount > \\\"$BAILEY_MOUNTPOINT/inside\\\"\"\n\
             at = \"/mnt/data\"\n"
        ),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", "cat /mnt/data/inside"])
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "the mount should be placed and readable: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "from-mount",
        "the target reads the mount at its at"
    );

    // The fake mount leaves plain files where a real filesystem would have
    // been mounted, so the unmount fails and the guard says so rather than
    // deleting a tree it cannot prove is unmounted. A real FUSE unmount
    // empties the staging directory, and teardown is then silent; the lib
    // test `a_guard_tears_down_its_run_directory` covers that path.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did not unmount"),
        "a mount that will not go must be named: {stderr}"
    );

    // The stub's own leftover is the test's to remove: this tree provably
    // holds nothing but the files the stub wrote.
    for entry in fs::read_dir("/tmp").unwrap().flatten() {
        let is_ours = entry
            .path()
            .join("0/inside")
            .is_file()
            && entry.file_name().to_str().unwrap().starts_with(".bailey-fuse.");
        if is_ours {
            fs::remove_dir_all(entry.path()).unwrap();
        }
    }
}

/// A `[[fuse]]` entry without namespace isolation cannot be placed, so the
/// run refuses rather than silently dropping the mount the policy names.
#[test]
fn a_fuse_mount_without_isolation_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         [[fuse]]\n\
         mount = \"true\"\n\
         at = \"/mnt/data\"\n",
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--no-isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", "true"])
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fuse mounts"),
        "the refusal should name the unplaceable mounts: {stderr}"
    );
}
