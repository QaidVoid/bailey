//! Integration tests for namespace isolation.
//!
//! These run real programs under user, mount, and PID namespaces. They self-skip
//! where isolation cannot actually be established (for example, a host that
//! restricts unprivileged user namespaces via AppArmor), detected by checking
//! whether the target really lands as PID 1.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

/// True only when an isolated run genuinely enters a new PID namespace. When the
/// host forces the Landlock-only fallback, the target keeps its host PID, so
/// this returns false and the tests skip.
fn isolation_active() -> bool {
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "-c", "echo $$"])
        .output();
    matches!(output, Ok(out) if out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "1")
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
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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

#[test]
fn target_is_pid_one_under_isolation() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
        return;
    }
    let output = Command::new(bailey())
        .args(["run", "--isolate", "/bin/sh", "-c", "echo $$"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "1");
}

#[test]
fn landlock_still_denies_writes_under_isolation() {
    if !isolation_active() {
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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
        eprintln!("skipping: isolation unavailable on this host");
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
