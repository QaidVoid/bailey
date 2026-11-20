//! Integration tests for the enforcement backend.
//!
//! These execute real programs under Landlock and seccomp. They self-skip on a
//! kernel without Landlock so they stay green in environments that lack it.

use std::fs;
use std::path::Path;
use std::process::Command;

mod common;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn landlock_available() -> bool {
    bailey::backend::probe::probe(false).landlock_abi.is_some()
}

/// Whether this host can create the user namespace a `[[socket]]` relay or a
/// `[[fuse]]` mount needs. Both are placed inside the reconstructed root, so
/// without one the run refuses rather than dropping what the policy names, and
/// a test that asserts the mount or the relay arrived fails on a host that
/// cannot build one. The GitHub-hosted runners report no user namespaces.
fn isolation_available() -> bool {
    bailey::backend::isolation::available()
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

/// Without the isolation layer, bailey creates no user namespace and the
/// kernel limit has nothing to bound, so the seccomp filter is the only layer
/// between the target and a fresh namespace. Every process-creation syscall
/// that can carry namespace flags must refuse them: `clone3` answers ENOSYS,
/// which libcs treat as unimplemented and fall back from to `clone`, whose
/// flags the filter reads.
#[test]
fn no_isolate_refuses_namespace_flags_on_every_route() {
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("/usr/bin/python3 unavailable");
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
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             [network]\n\
             egress = \"allow\"\n",
            work = work.display()
        ),
    )
    .unwrap();
    let probe = common::write_namespace_probe(&work);

    let output = Command::new(bailey())
        .args(["run", "--no-isolate", "-c"])
        .arg(&config)
        .args(["/usr/bin/python3"])
        .arg(&probe)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    common::assert_every_namespace_route_refused("--no-isolate", &stdout);
    assert!(
        output.status.success(),
        "the run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn granted_path_is_readable_and_program_runs() {
    if !landlock_available() {
        common::skip("Landlock unavailable");
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
        common::skip("Landlock unavailable");
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
        common::skip("Landlock unavailable");
        return;
    }
    if !Path::new("/usr/bin/unshare").exists() {
        common::skip("/usr/bin/unshare not present");
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
        common::skip("Landlock unavailable");
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
        common::skip("Landlock unavailable");
        return;
    }
    if bailey::backend::cgroup::usable_root(&["pids"]).is_some() {
        common::skip("a delegated cgroup takes the limit here");
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
        common::skip("Landlock unavailable");
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

/// The open-file limit is an rlimit like the file size one, so it holds on a
/// host with no delegated cgroup at all: `/nonexistent` names one bailey can
/// never find, whatever this host delegates. The limit is lower-only, so a
/// caller whose own limits sit below the policy's number passes the caller's
/// lower ones on, and the test accepts both shapes.
#[test]
fn an_open_file_limit_holds_without_a_cgroup() {
    if !landlock_available() {
        common::skip("Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[resources]\nopen_files = 64\n").unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/cat", "/proc/self/limits"])
        .env("BAILEY_CGROUP_ROOT", "/nonexistent")
        .output()
        .unwrap();

    let limits = String::from_utf8_lossy(&output.stdout);
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .unwrap_or_default();
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert!(
        fields.len() >= 5,
        "the target must report its own limits: {line:?}; {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (soft, hard) = (fields[3].parse::<u64>(), fields[4].parse::<u64>());
    match (soft, hard) {
        (Ok(soft), Ok(hard)) => assert!(
            soft <= 64 && hard <= 64 && soft <= hard,
            "the target must be bounded by at most the policy's number: {line}"
        ),
        _ => assert!(
            line.contains("unlimited"),
            "an unparsable limit must be an unlimited one, never a raised \
             one: {line}"
        ),
    }
    let summary = String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|line| line.starts_with("bailey: enforced:"))
        .unwrap_or_default()
        .to_owned();
    assert!(
        summary.contains("open file limit"),
        "the open-file limit must be reported as enforced: {summary}"
    );
    assert!(
        !summary.contains("resource limits"),
        "with only the open-file limit set there is no cgroup limit to talk \
         about: {summary}"
    );
}

/// An open-file limit is a bound on new descriptors, so a target that opens
/// until the kernel refuses must be refused at or before the policy's number,
/// with the kernel's own error, and anything it starts must carry the same
/// bound. Both run shapes matter: the limit sits in the pre-exec child either
/// way.
#[test]
fn an_open_file_limit_refuses_the_next_open() {
    if !landlock_available() {
        common::skip("Landlock unavailable");
        return;
    }
    let python = ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).exists());
    let Some(python) = python else {
        common::skip("no python3 for the descriptor loop");
        return;
    };
    let program = "\
import os, subprocess
fds = []
try:
    while True:
        fds.append(os.open('/dev/null', os.O_RDONLY))
except OSError as error:
    assert error.errno == 24, f'expected EMFILE, got {error}'
print(f'opened={len(fds)}', flush=True)
assert len(fds) <= 32, f'opened {len(fds)} past the policy number'
# The child spawn itself needs a few descriptors for its pipes, so hand the
# bound back a little before proving the child inherited it.
for fd in fds[:8]:
    os.close(fd)
out = subprocess.run(['/bin/cat', '/proc/self/limits'], capture_output=True, text=True).stdout
for line in out.splitlines():
    if line.startswith('Max open files'):
        print('child:', line, flush=True)
        fields = line.split()
        soft, hard = int(fields[3]), int(fields[4])
        assert soft <= 32 and hard <= 32, f'child unbounded: {line}'
";
    for isolate in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("bailey.toml");
        let mut config_text = String::from("[resources]\nopen_files = 32\n");
        if isolate {
            config_text.push_str(
                "[filesystem]\n\
                 read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
                 execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
            );
        }
        fs::write(&config, config_text).unwrap();

        let mut command = Command::new(bailey());
        command.args(["run", "-c"]).arg(&config);
        if isolate {
            command.arg("--isolate");
        }
        let output = command
            .args(["/usr/bin/env", python, "-c", program])
            .env("BAILEY_CGROUP_ROOT", "/nonexistent")
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the run shape {isolate} must refuse the open, not fail: {} {}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        let opened = stdout
            .lines()
            .find_map(|line| line.strip_prefix("opened="))
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or_else(|| panic!("the target must report its count: {stdout}"));
        assert!(
            opened <= 32,
            "the open must fail at or before 32, not after {opened}"
        );
        assert!(
            opened > 0,
            "some descriptors must succeed before the refusal: {stdout}"
        );
        let child_line = stdout
            .lines()
            .find(|line| line.starts_with("child: Max open files"))
            .unwrap_or_else(|| panic!("the child must report its limits: {stdout}"));
        let fields: Vec<&str> = child_line.split_whitespace().collect();
        let soft: u64 = fields[4].parse().expect("child soft limit");
        let hard: u64 = fields[5].parse().expect("child hard limit");
        assert!(
            soft <= 32 && hard <= 32,
            "the child must carry the same bound: {child_line}"
        );
    }
}

/// The address-space fallback exists for the run where `memory` is set and no
/// cgroup could carry it. Where a cgroup does carry the memory limit the
/// fallback must stay off, and the memory limit must still be reported as
/// skipped: the fallback is not the memory limit and never stands in for it
/// in the reporting.
#[test]
fn an_address_space_fallback_applies_only_without_a_cgroup() {
    if !landlock_available() {
        common::skip("Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[resources]\nmemory = \"2GiB\"\naddress_space = \"128MiB\"\n",
    )
    .unwrap();
    let fallback_bytes = 128 * 1024 * 1024;

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/cat", "/proc/self/limits"])
        .env("BAILEY_CGROUP_ROOT", "/nonexistent")
        .output()
        .unwrap();

    let limits = String::from_utf8_lossy(&output.stdout);
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max address space"))
        .unwrap_or_default();
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert!(
        fields.len() >= 5,
        "the target must report its own limits: {line:?}; {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let soft: u64 = fields[3].parse().expect("address space soft limit");
    let hard: u64 = fields[4].parse().expect("address space hard limit");
    // Lower-only semantics: the target is bounded by at most the fallback's
    // number, so a caller who arrived already bounded below it is not lifted.
    assert!(
        soft <= fallback_bytes && hard <= fallback_bytes,
        "the target must be bounded by at most the fallback: {line}"
    );

    let summary = String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|line| line.starts_with("bailey: enforced:"))
        .unwrap_or_default()
        .to_owned();
    assert!(
        summary.contains("per-process address space"),
        "the fallback must be reported under its own name: {summary}"
    );
    let reported = String::from_utf8_lossy(&output.stderr);
    assert!(
        reported.contains("not enforced, resource limits"),
        "the memory limit stays reported as skipped: {reported}"
    );

    let json = Command::new(bailey())
        .args(["run", "--json", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .env("BAILEY_CGROUP_ROOT", "/nonexistent")
        .output()
        .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim())
            .expect("--json must emit valid JSON");
    let applied = parsed["applied"].as_array().expect("applied is an array");
    assert!(
        applied
            .iter()
            .any(|layer| layer == "per-process address space"),
        "the JSON must carry the fallback: {}",
        String::from_utf8_lossy(&json.stdout)
    );
    assert!(
        !applied.iter().any(|layer| layer == "resource limits"),
        "the fallback must never be reported as the memory limit: {parsed}"
    );
}

/// Where a cgroup carries the memory limit, the fallback must not apply: the
/// cgroup's `memory.max` is the sound answer, and an address-space bound
/// would only add breakage. Whatever address-space bound bailey itself
/// inherited is what the target must keep.
#[test]
fn the_address_space_fallback_stays_off_where_a_cgroup_carries_memory() {
    if !landlock_available() {
        common::skip("Landlock unavailable");
        return;
    }
    if bailey::backend::cgroup::usable_root(&["memory"]).is_none() {
        common::skip("no delegated cgroup carries memory here");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[resources]\nmemory = \"2GiB\"\naddress_space = \"128MiB\"\n",
    )
    .unwrap();

    let own = fs::read_to_string("/proc/self/limits").unwrap();
    let own_line = own
        .lines()
        .find(|line| line.starts_with("Max address space"))
        .expect("this test process reports its own limits")
        .to_owned();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/cat", "/proc/self/limits"])
        .output()
        .unwrap();

    let limits = String::from_utf8_lossy(&output.stdout);
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max address space"))
        .unwrap_or_default();
    assert_eq!(
        line.split_whitespace().collect::<Vec<_>>(),
        own_line.split_whitespace().collect::<Vec<_>>(),
        "the target must keep the address-space bound bailey inherited, not \
         the fallback's: target {line:?} own {own_line:?}"
    );
    let summary = String::from_utf8_lossy(&output.stderr)
        .lines()
        .find(|line| line.starts_with("bailey: enforced:"))
        .unwrap_or_default()
        .to_owned();
    assert!(
        !summary.contains("per-process address space"),
        "the fallback must not be claimed where a cgroup carries memory: \
         {summary}"
    );
    assert!(
        summary.contains("resource limits"),
        "the cgroup limits must be reported as applied: {summary}"
    );
}

/// A `[[fuse]]` entry is mounted by bailey before the target starts and
/// appears at its `at` inside the sandbox. The mount command here fills the
/// mountpoint by hand, which stands in for a real FUSE filesystem: what the
/// test proves is the wiring, that the command runs, the grant is placed, and
/// the mount lands where the policy says.
#[test]
fn a_fuse_mount_is_performed_and_placed() {
    if !isolation_available() {
        common::skip("namespace isolation unavailable on this host");
        return;
    }
    if !landlock_available() {
        common::skip("Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         [[fuse]]\n\
         mount = \"mkdir -p \\\"$BAILEY_MOUNTPOINT\\\" && echo from-mount > \\\"$BAILEY_MOUNTPOINT/inside\\\"\"\n\
         at = \"/mnt/data\"\n"
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
        let is_ours = entry.path().join("0/inside").is_file()
            && entry
                .file_name()
                .to_str()
                .unwrap()
                .starts_with(".bailey-fuse.");
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

/// A `[[socket]]` relay carries a host service into the sandbox one socket at
/// a time: the target talks to the socket at its `at`, and the bytes come out
/// at the real host socket, while the directory holding it is never granted.
#[test]
fn a_socket_relay_carries_a_service_into_the_sandbox() {
    if !isolation_available() {
        common::skip("namespace isolation unavailable on this host");
        return;
    }
    if !landlock_available() {
        common::skip("Landlock unavailable");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() && !Path::new("/bin/python3").exists() {
        common::skip("python3 unavailable to stand in for a service");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let service_sock = dir.path().join("real.sock");
    let at_sock = dir.path().join("presented.sock");

    // The service echoes one line per connection.
    let mut server = std::process::Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import socket, os\n\
             p = {service_sock:?}\n\
             s = socket.socket(socket.AF_UNIX)\n\
             s.bind(p)\n\
             s.listen(4)\n\
             for _ in range(3):\n\
             \x20   c, _ = s.accept()\n\
             \x20   c.sendall(b'pong')\n\
             \x20   c.close()\n",
            service_sock = service_sock.to_str().unwrap(),
        ))
        .spawn()
        .unwrap();
    // Wait for the socket to appear.
    for _ in 0..50 {
        if service_sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             [[socket]]\n\
             host = \"{}\"\n\
             at = \"{}\"\n",
            service_sock.display(),
            at_sock.display(),
        ),
    )
    .unwrap();

    let client = format!(
        "import socket\n\
         s = socket.socket(socket.AF_UNIX)\n\
         s.connect({at_sock:?})\n\
         print(s.recv(8).decode())\n",
        at_sock = at_sock.to_str().unwrap(),
    );
    let output = std::process::Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/usr/bin/python3", "-c", &client])
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    let _ = server.kill();
    let _ = server.wait();
    assert!(
        output.status.success(),
        "the relayed socket should answer: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "pong",
        "the target reached the host service through the relay"
    );
}

/// A named `dbus` relay points the session bus variable at the relayed
/// socket, without the runtime directory being granted.
#[test]
fn a_dbus_relay_sets_the_bus_address() {
    if !isolation_available() {
        common::skip("namespace isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         [[socket]]\n\
         service = \"dbus\"\n",
    )
    .unwrap();

    let output = std::process::Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", "echo $DBUS_SESSION_BUS_ADDRESS"])
        // A fake runtime dir keeps the assertion deterministic: the relay's
        // paths mirror whatever the session names, real or not.
        .env("XDG_RUNTIME_DIR", "/run/user/test")
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        "unix:path=/run/user/test/bus",
        "the bus address should name the relayed socket: {stdout}"
    );
}

/// A relay and a grant of the same hierarchy are refused together: the relay
/// exists to keep the directory ungranted, and both at once is a contradiction.
#[test]
fn a_socket_relay_overlapping_a_grant_is_refused() {
    if !isolation_available() {
        common::skip("namespace isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             [[socket]]\n\
             host = \"{}\"\n\
             at = \"{}\"\n",
            dir.path().display(),
            dir.path().join("real.sock").display(),
            dir.path().join("presented.sock").display(),
        ),
    )
    .unwrap();

    let output = std::process::Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", "true"])
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("overlaps the grant"),
        "the refusal should name the overlap: {stderr}"
    );
}

/// The URL broker answers through a real sandbox: the target writes one line
/// to the broker socket and reads the verdict. A refused scheme needs nothing
/// from the host desktop, so the protocol is proven end to end whatever the
/// machine's browser situation is.
#[test]
fn the_url_broker_refuses_non_web_schemes_through_a_run() {
    if !isolation_available() {
        common::skip("namespace isolation unavailable on this host");
        return;
    }
    if !landlock_available() {
        common::skip("Landlock unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         [[socket]]\n\
         service = \"url-open\"\n",
    )
    .unwrap();

    // One line in, one verdict out, in a dozen lines of Python: the protocol
    // is deliberately something any agent can speak.
    let client = format!(
        "import socket\n\
         s = socket.socket(socket.AF_UNIX)\n\
         s.connect({at:?})\n\
         s.sendall(b'file:///etc/passwd\\n')\n\
         print(s.recv(8).decode().strip())\n",
        at = "/run/user/test/url-open",
    );
    let output = std::process::Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/usr/bin/python3", "-c", &client])
        .env("XDG_RUNTIME_DIR", "/run/user/test")
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "ERR",
        "a file:// URL must be refused by the broker, not opened"
    );
}
