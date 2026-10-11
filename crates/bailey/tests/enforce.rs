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
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() && !Path::new("/bin/python3").exists() {
        eprintln!("skipping: python3 unavailable to stand in for a service");
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
    if !landlock_available() {
        eprintln!("skipping: Landlock unavailable");
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
