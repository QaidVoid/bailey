//! Integration tests for namespace isolation.
//!
//! These run real programs under user, mount, and PID namespaces. They self-skip
//! where isolation cannot actually be established (for example, a host that
//! restricts unprivileged user namespaces via AppArmor), detected by checking
//! whether the sandbox's init really is bailey's own supervisor.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

mod common;

use common::assert_every_namespace_route_refused;
use common::write_namespace_probe;

/// True only when an isolated run genuinely enters a new PID namespace. When
/// the host forces the Landlock-only fallback, the target keeps its host PID,
/// so this returns false and the tests skip. Inside a real sandbox PID 1 is
/// the supervisor that reaps the namespace's orphans.
fn isolation_active() -> bool {
    let output = Command::new(bailey())
        .args([
            "run",
            "--isolate",
            "/bin/sh",
            "-c",
            "[ \"$(cat /proc/1/comm)\" = bailey ] && echo yes || echo no",
        ])
        .output();
    matches!(output, Ok(out) if out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "yes")
}

/// A workspace with a granted directory holding both a denied subdirectory and
/// an ordinary sibling, plus a config that grants the parent and denies the one
/// subdirectory.
fn denial_workspace() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    fs::create_dir(work.join("secret")).unwrap();
    fs::write(work.join("secret/key"), "topsecret").unwrap();
    fs::write(work.join("visible.txt"), "readable").unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{work}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             deny = [\"{work}/secret\"]\n",
            work = work.display()
        ),
    )
    .unwrap();
    (dir, config)
}

#[test]
fn denied_subdirectory_is_concealed_under_isolation() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let (dir, config) = denial_workspace();
    let work = dir.path().join("work");

    let denied = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("cat {}/secret/key", work.display()))
        .output()
        .unwrap();
    assert!(
        !denied.status.success(),
        "a file under a denied directory must not be readable: {}",
        String::from_utf8_lossy(&denied.stdout)
    );
    assert!(
        !String::from_utf8_lossy(&denied.stdout).contains("topsecret"),
        "denied content leaked"
    );

    let sibling = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("cat {}/visible.txt", work.display()))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&sibling.stdout).trim(),
        "readable",
        "a sibling of the denied path must stay readable"
    );
}

#[test]
fn denied_directory_is_empty_and_read_only_under_isolation() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let (dir, config) = denial_workspace();
    let work = dir.path().join("work");

    let listing = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("ls -A {}/secret", work.display()))
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&listing.stdout).trim().is_empty(),
        "the denied directory must have no entries: {}",
        String::from_utf8_lossy(&listing.stdout)
    );

    let write = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("echo x > {}/secret/planted", work.display()))
        .output()
        .unwrap();
    assert!(
        !write.status.success(),
        "the denied directory must not be writable"
    );
    assert!(
        !work.join("secret/planted").exists(),
        "a write into the denied directory must not reach the host"
    );
}

#[test]
fn ungranted_path_is_absent_under_isolation() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    // `/var` is not granted, and unlike `/home` it is not a parent of anything
    // the sandbox provides, so it is absent from the reconstructed root.
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "-c", "ls /var"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No such file") || stderr.contains("cannot access"),
        "expected /var to be absent, got: {stderr}"
    );
}

/// The kernel hands every orphaned process to PID 1 and reaps nothing itself,
/// so the target must not hold the namespace's init role: a target that leaks
/// a grandchild would otherwise leave an immortal zombie pinning a host PID
/// until the run ended, and enough leaked zombies drain the kernel's PID
/// space until `fork` fails on the whole host. The supervisor takes the role
/// instead and reaps what reparents to it.
#[test]
fn orphans_a_target_leaves_are_reaped() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    // Two generations: the inner sh backgrounds a sleeper and exits, so the
    // sleeper reparents to PID 1, runs out its sleep, and stays a zombie
    // until PID 1 reaps it. The spawner is nested inside the counter subshell
    // so every shell that exits is reaped by its own shell parent, and the
    // target itself execs `sleep`, which never waits: the count must come out
    // zero because the supervisor reaped, not because the target did.
    let script = r#"( ( i=0; while [ $i -lt 20 ]; do sh -c 'sh -c "sleep 0.3" &'; i=$((i+1)); done ) & sleep 1; z=0; for p in /proc/[0-9]*/stat; do set -- $(cat "$p" 2>/dev/null); [ "$3" = Z ] && z=$((z+1)); done; echo zombies=$z ) & exec sleep 2.5"#;
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "-c", script])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "the run must still exit with the target's own status: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "zombies=0",
        "every orphan the target left must have been reaped while the run lived"
    );
}

#[test]
fn landlock_still_denies_writes_under_isolation() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data.txt");
    fs::write(&file, "content").unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", file.display()),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("echo x > {}", file.display()))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "write to a read-only grant must be denied under isolation"
    );
}

#[test]
fn a_read_only_island_survives_inside_a_writable_grant() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir_all(work.join("protected")).unwrap();
    fs::write(work.join("protected/binary"), "original").unwrap();
    fs::write(work.join("data.txt"), "data").unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{work}\"]\n             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n             write = [\"{work}\"]\n             read_only = [\"{work}/protected\"]\n",
            work = work.display()
        ),
    )
    .unwrap();

    let run = |script: String| {
        Command::new(bailey())
            .args(["run", "--isolate", "-c"])
            .arg(&config)
            .args(["/bin/sh", "-c"])
            .arg(script)
            .output()
            .unwrap()
    };

    // Readable, unlike a denial, which empties the path.
    let read = run(format!("cat {}/protected/binary", work.display()));
    assert_eq!(
        String::from_utf8_lossy(&read.stdout).trim(),
        "original",
        "a read-only island must stay readable"
    );

    // The parent is still writable.
    let write_parent = run(format!("echo new > {}/added.txt", work.display()));
    assert!(
        write_parent.status.success(),
        "the grant must stay writable"
    );

    // The island is not.
    let write_island = run(format!(
        "echo tampered > {}/protected/binary",
        work.display()
    ));
    assert!(
        !write_island.status.success(),
        "a read-only island must refuse writes"
    );
    assert_eq!(
        fs::read_to_string(work.join("protected/binary")).unwrap(),
        "original",
        "and nothing must reach the host"
    );
}

/// The read-only remount applies to grants bailey added, not to two grants the
/// user wrote. Granting write on a directory and read on something beneath it
/// still resolves to a writable path: that is the documented merge rule, and
/// changing it would be a different tool.
#[test]
fn two_grants_the_user_wrote_still_accumulate() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir_all(work.join("inner")).unwrap();
    fs::write(work.join("inner/file"), "original").unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\nwrite = [\"{work}\"]\nread = [\"{work}\", \"{work}/inner\"]\n",
            work = work.display()
        ),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("echo changed > {}/inner/file", work.display()))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "a user's own write grant on the parent still covers the child: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A read-only grant beneath the home is the shape of "let it read my dotfiles".
/// The private home is mounted at the real home's path and granted read-write,
/// so without a read-only remount the home's write right covers the narrower
/// grant, and the write reaches the host file through the bind.
#[test]
fn a_read_only_grant_inside_the_home_is_not_writable() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let dotfiles = home.path().join(".config/app");
    fs::create_dir_all(&dotfiles).unwrap();
    fs::write(dotfiles.join("settings"), "original").unwrap();

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", dotfiles.display()),
    )
    .unwrap();

    let run = |script: String| {
        Command::new(bailey())
            .args(["run", "-c"])
            .arg(&config)
            .args(["/bin/sh", "-c"])
            .arg(script)
            .env("HOME", home.path())
            .output()
            .unwrap()
    };

    let read = run(format!("cat {}/settings", dotfiles.display()));
    assert_eq!(
        String::from_utf8_lossy(&read.stdout).trim(),
        "original",
        "a granted dotfile directory must be readable"
    );

    let write = run(format!("echo tampered > {}/settings", dotfiles.display()));
    assert!(
        !write.status.success(),
        "read was granted, not write: {}",
        String::from_utf8_lossy(&write.stderr)
    );
    assert_eq!(
        fs::read_to_string(dotfiles.join("settings")).unwrap(),
        "original",
        "and the host file must be untouched"
    );
}

/// Binding a symlink follows it, which puts a regular file where the link was.
/// An interpreter that resolves its own modules relative to itself then looks in
/// the wrong directory, so a link whose destination the policy already provides
/// is recreated as a link.
#[test]
fn a_symlink_into_a_granted_tree_stays_a_symlink() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let bin = dir.path().join("bin");
    fs::create_dir_all(&store).unwrap();
    fs::create_dir_all(&bin).unwrap();
    // A script that reports where it thinks it lives, which is what an
    // interpreter resolving relative imports is really asking.
    fs::write(
        store.join("prog"),
        "#!/bin/sh\necho \"$(dirname \"$(readlink -f \"$0\")\")\"\n",
    )
    .unwrap();
    fs::set_permissions(store.join("prog"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("../store/prog", bin.join("prog")).unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\nread = [\"{store}\"]\nexecute = [\"{store}\"]\n",
            store = store.display()
        ),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg(bin.join("prog"))
        .output()
        .unwrap();
    let seen = String::from_utf8_lossy(&output.stdout);

    assert!(
        seen.contains("store"),
        "the link must still resolve into the store it points at, not be replaced \
         by a file beside the link: {seen}"
    );
}

/// A grant may be placed somewhere other than its own path.
///
/// Paths are otherwise preserved exactly, because a program that resolves
/// anything relative to its own location breaks when moved. Relocating is for a
/// path whose name is the thing to withhold: a directory named after the
/// operator tells a target who is running it and how the host is laid out.
#[test]
fn a_grant_can_be_placed_at_another_path() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("operator-named-directory");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("file.txt"), "content").unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", {{ path = \"{real}\", at = \"/workspace\" }}]\n\
             write = [{{ path = \"{real}\", at = \"/workspace\" }}]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
            real = real.display()
        ),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args([
            "/bin/sh",
            "-c",
            "cat /workspace/file.txt; echo new > /workspace/w.txt && echo written",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("content"),
        "the grant must be readable at its new path: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("written"),
        "the grant must be writable at its new path, so the rule followed it: {stdout}"
    );
    // The write reached the real directory, not somewhere inside the sandbox.
    assert_eq!(
        fs::read_to_string(real.join("w.txt")).unwrap().trim(),
        "new"
    );
}

#[test]
fn the_host_path_of_a_relocated_grant_is_gone() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("operator-named-directory");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("file.txt"), "content").unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", {{ path = \"{real}\", at = \"/workspace\" }}]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
            real = real.display()
        ),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args([
            "/bin/sh",
            "-c",
            &format!(
                "ls {} 2>/dev/null && echo VISIBLE || echo absent",
                real.display()
            ),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("absent"),
        "the host path must not exist in the reconstructed root: {stdout}"
    );
}

/// Denying `/etc/hostname` is not enough. `uname` is a syscall, so a program
/// that asks the kernel gets the machine's real name however the filesystem is
/// confined. Only a UTS namespace takes that away.
#[test]
fn the_target_is_not_told_the_machines_name() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let real = std::process::Command::new("uname")
        .arg("-n")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_default();

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", "uname -n"])
        .output()
        .unwrap();

    let seen = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(!seen.is_empty(), "the target must still have a hostname");
    if !real.is_empty() {
        assert_ne!(seen, real, "the target must not be told the machine's name");
    }
}

#[test]
fn the_target_keeps_the_callers_uid() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/usr/bin/id", "-u"])
        .env("XDG_DATA_HOME", dir.path())
        .output()
        .unwrap();

    let seen = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let real = unsafe { libc::getuid() }.to_string();
    assert_eq!(
        seen,
        real,
        "the isolation layer must map the caller's own uid, not 0: a target \
         that refuses to run as root would refuse here, and D-Bus EXTERNAL \
         authentication would fail against the daemon's SO_PEERCRED:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The private network namespace maps its caller to 0 so the netfilter rule
/// survives exec, and the namespaces built beneath it must map the host
/// identity back. Automatic mode takes that path by default for an
/// egress-allowing policy, so this is the shape an ordinary run has.
#[test]
fn a_private_network_run_keeps_the_callers_uid_and_gid() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    if bailey::cli::resolve_helper("pasta").is_err() {
        common::skip("needs trusted pasta");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, "[network]\negress = \"allow\"\n").unwrap();
    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", "id -u; id -g"])
        .env("XDG_DATA_HOME", dir.path())
        .output()
        .unwrap();

    let seen = String::from_utf8_lossy(&output.stdout);
    let real_uid = unsafe { libc::getuid() }.to_string();
    let real_gid = unsafe { libc::getgid() }.to_string();
    let mut lines = seen.lines().filter(|line| !line.is_empty());
    let uid = lines.next().unwrap_or_default().trim();
    let gid = lines.next().unwrap_or_default().trim();
    assert_eq!(
        uid,
        real_uid,
        "an automatic private-network run must keep the caller's uid, not the 0 \
         the proxy namespace maps its caller to: a target that refuses root \
         would refuse here\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        gid,
        real_gid,
        "the caller's gid must survive the proxy namespace as well\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_denied_file_is_concealed_rather_than_failing_the_run() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("token"), "topsecret").unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{work}\"]\n\
             write = [\"{work}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
             deny = [\"{work}/token\"]\n",
            work = work.display()
        ),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c"])
        .arg(format!("cat {}/token", work.join("").display()))
        .output()
        .unwrap();

    // Denying a file covers it with an empty one. Naming the cover by the
    // descriptor that found the original fails the whole run instead, since
    // the bind leaves that descriptor pointing at something else.
    assert!(
        output.status.success(),
        "denying a file must not fail the run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("topsecret"),
        "a denied file must read empty, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn granting_dev_pts_gives_the_run_terminals_of_its_own() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    // `script` allocates a pty and reports what it got. Binding the host's
    // /dev/pts instead of mounting an instance leaves /dev/ptmx answering
    // ENOENT, which is what a terminal reports as `forkpty(3) failed`.
    fs::write(
        &config,
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n\
         [[device]]\n\
         path = \"/dev/pts\"\n\
         access = \"rw\"\n\
         [[device]]\n\
         path = \"/dev/ptmx\"\n\
         access = \"rw\"\n",
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args([
            "/bin/sh",
            "-c",
            "python3 -c 'import pty,os; m,s=pty.openpty(); print(os.ttyname(s))'              && ls /dev/pts",
        ])
        .env("XDG_DATA_HOME", dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("/dev/pts/"),
        "granting /dev/pts must let the run allocate a pty: {}{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    // Its own instance, not the host's: a fresh one starts numbering at 0 and
    // holds nothing else.
    assert!(
        !stdout.lines().any(|line| line.trim() == "1"),
        "the run must not see the host's terminals: {stdout}"
    );
}

/// The policy for a mount test: the workspace granted for reading and writing
/// so the mountpoint is reachable, on top of the system paths the target's own
/// tools need.
fn mount_workspace(
    dir: &std::path::Path,
    work: &std::path::Path,
    self_fuse: bool,
) -> std::path::PathBuf {
    let config = dir.join("bailey.toml");
    fs::write(
        &config,
        format!(
            "{}[filesystem]\n\
             read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{work}\"]\n\
             write = [\"{work}\"]\n\
             execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
            if self_fuse { "self_fuse = true\n" } else { "" },
            work = work.display()
        ),
    )
    .unwrap();
    config
}

/// The proof is at the syscall boundary, exactly as with the subvolume ioctl:
/// the same `mount(2)` call is EPERM under the default filter and succeeds
/// when `self_fuse` keeps the capability. A tmpfs is used rather than a real
/// FUSE mount because it exercises the identical gate (the capability and the
/// seccomp family) with no /dev/fuse or helper daemon on the path.
///
/// The call is made through ctypes because mount(8) refuses in restricted
/// mode whenever it is not setuid and its caller is not root, and never
/// reaches the syscall whose permission we are testing.
#[test]
fn self_fuse_lets_the_target_mount_and_unmount() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("/usr/bin/python3 unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();

    let config = mount_workspace(dir.path(), &work, true);
    let script = format!(
        "python3 -c \"\n\
         import ctypes, os\n\
         libc = ctypes.CDLL(None, use_errno=True)\n\
         point = '{work}'.encode() + b'/m'\n\
         os.makedirs(point, exist_ok=True)\n\
         if libc.mount(b'tmpfs', point, b'tmpfs', 0, b'size=1m') != 0:\n\
         \x20   raise SystemExit('mount failed: ' + os.strerror(ctypes.get_errno()))\n\
         open(point + b'/inside', 'w').write('there')\n\
         print('mounted')\n\
         if libc.umount2(point, 0) != 0:\n\
         \x20   raise SystemExit('umount failed: ' + os.strerror(ctypes.get_errno()))\n\
         print('unmounted' if not os.path.exists(point + b'/inside') else 'still there')\n\"",
        work = work.display()
    );
    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", &script])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("mounted") && stdout.contains("unmounted"),
        "self_fuse must let the target mount and unmount: {}{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Every route to a fresh user namespace must be closed for the target, in
/// every layout bailey can build. The clone3 route is the one that matters:
/// the seccomp filter inspects `clone` flags but has nothing readable to
/// match on for clone3, so a target could create a user namespace under
/// bailey's own and regain every capability inside it. The kernel's guard
/// limit closes what the filter cannot see, so the two layers together leave
/// no route.
#[test]
fn target_cannot_create_a_user_namespace() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("/usr/bin/python3 unavailable");
        return;
    }
    let pasta = Command::new("sh")
        .args(["-c", "command -v pasta >/dev/null 2>&1"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    let grants = format!(
        "[filesystem]\n\
         read = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\", \"/etc\", \"{work}\"]\n\
         execute = [\"/usr\", \"/bin\", \"/lib\", \"/lib64\"]\n",
        work = work.display()
    );
    let layouts: [(&str, String, &[&str]); 5] = [
        ("isolated", grants.clone(), &["--isolate"]),
        ("network-only", grants.clone(), &["--no-isolate"]),
        (
            "proxied, isolated",
            format!("{grants}[network]\negress = \"allow\"\n"),
            &["--proxy-net"],
        ),
        // This layout has no reconstructed root to stage the private
        // network's `resolv.conf` into, so an allowed DNS refuses the run;
        // denying DNS is the shape a no-isolate proxied run takes, and the
        // namespace routes it exists to check stay the same.
        (
            "proxied, --no-isolate",
            format!("{grants}[network]\negress = \"allow\"\ndns = \"deny\"\n"),
            &["--proxy-net", "--no-isolate"],
        ),
        (
            "self_fuse",
            format!("self_fuse = true\n{grants}"),
            &["--isolate"],
        ),
    ];
    for (name, config_body, extra_args) in layouts {
        if extra_args.contains(&"--proxy-net") && !pasta {
            common::skip(&format!("pasta unavailable for the {name} layout"));
            continue;
        }
        let config = dir.path().join("bailey.toml");
        fs::write(&config, config_body).unwrap();
        let probe = write_namespace_probe(&work);

        let output = Command::new(bailey())
            .args(["run"])
            .args(extra_args)
            .arg("-c")
            .arg(&config)
            .args(["/usr/bin/python3"])
            .arg(&probe)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_every_namespace_route_refused(name, &stdout);
        assert!(
            output.status.success(),
            "{name}: the run must succeed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn mounting_stays_refused_without_self_fuse() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("/usr/bin/python3 unavailable");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();

    let config = mount_workspace(dir.path(), &work, false);
    let script = format!(
        "python3 -c \"\n\
         import ctypes, os\n\
         libc = ctypes.CDLL(None, use_errno=True)\n\
         point = '{work}'.encode() + b'/m'\n\
         os.makedirs(point, exist_ok=True)\n\
         if libc.mount(b'tmpfs', point, b'tmpfs', 0, b'size=1m') == 0:\n\
         \x20   raise SystemExit('unexpectedly mounted')\n\
         print('refused')\n\"",
        work = work.display()
    );
    let output = Command::new(bailey())
        .args(["run", "--isolate", "-c"])
        .arg(&config)
        .args(["/bin/sh", "-c", &script])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("refused"),
        "mounting must be refused without self_fuse: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A connect entry places exactly one socket in the reconstructed root: the
/// listed one is connectable, and the runtime directory around it carries
/// nothing else. This is the placement the desktop profiles depend on.
#[test]
fn a_connect_entry_binds_its_socket_and_nothing_else() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    if !bailey::backend::probe::landlock_abi().is_some_and(|abi| abi >= 9) {
        common::skip("socket connect control needs Landlock ABI 9");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() && !Path::new("/bin/python3").exists() {
        common::skip("python3 unavailable");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let listed = runtime.path().join("pulse/native");
    let unlisted = runtime.path().join("bus");
    for socket in [&listed, &unlisted] {
        if let Some(parent) = socket.parent() {
            fs::create_dir_all(parent).unwrap();
        }
    }
    let mut listeners = Vec::new();
    let listener_program = |socket: &Path| {
        format!(
            "import socket\n\
             s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
             s.bind('{path}')\n\
             s.listen(8)\n\
             print('ready', flush=True)\n\
             while True:\n\
             \x20   try:\n\
             \x20       conn, _ = s.accept()\n\
             \x20       conn.sendall(b'pong')\n\
             \x20   except OSError:\n\
             \x20       pass\n",
            path = socket.display()
        )
    };
    for socket in [&listed, &unlisted] {
        let mut child = Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(listener_program(socket))
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        listeners.push(child);
    }

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\nconnect = [\"{listed}\"]\n",
            listed = listed.display()
        ),
    )
    .unwrap();

    let probe = format!(
        "import os, socket\n\
         for name in ['pulse/native', 'bus']:\n\
         \x20   try:\n\
         \x20       c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20       c.connect(os.path.join({rt:?}, name))\n\
         \x20       c.recv(4)\n\
         \x20       print(name, 'ok')\n\
         \x20   except OSError:\n\
         \x20       print(name, 'no')\n\
         print('listed-exists:', os.path.exists({rt:?} + '/pulse/native'))\n\
         print('bus-exists:', os.path.exists({rt:?} + '/bus'))\n",
        rt = runtime.path()
    );
    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .current_dir(dir.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .arg("/usr/bin/python3")
        .arg("-c")
        .arg(&probe)
        .output()
        .unwrap();
    for mut child in listeners.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pulse/native ok"),
        "the listed socket must be connectable: {stdout}"
    );
    assert!(
        stdout.contains("bus no"),
        "the unlisted socket must be refused: {stdout}"
    );
    assert!(
        stdout.contains("listed-exists: True"),
        "the listed socket must be the only thing placed in the runtime directory: {stdout}"
    );
    assert!(
        stdout.contains("bus-exists: False"),
        "the unlisted socket must not be visible in the runtime directory: {stdout}"
    );
}
/// A refusal made while the sandbox is built reaches the user as written.
///
/// The child that builds the sandbox can only hand `Command` an errno, so a
/// refusal that is a message arrived as "Invalid argument" and said nothing
/// about what was wrong.
#[test]
fn a_refusal_while_building_the_sandbox_names_its_reason() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    fs::create_dir_all(&project).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    fs::write(&secret, "x").unwrap();
    std::os::unix::fs::symlink(&secret, project.join("escape")).unwrap();

    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[filesystem]\nread = [\"{project}\"]\nread_only = [\"{escape}\"]\n",
            project = project.display(),
            escape = project.join("escape").display()
        ),
    )
    .unwrap();

    let output = Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .arg("/bin/true")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "the run must be refused: {stderr}"
    );
    assert!(stderr.contains("leaves the sandbox"), "{stderr}");
    assert!(!stderr.contains("Invalid argument"), "{stderr}");
}
