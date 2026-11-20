//! Integration tests for config discovery and argument handling.

use std::fs;
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

#[test]
fn working_directory_config_applies_to_a_system_interpreter() {
    let dir = tempfile::tempdir().unwrap();
    let store = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker-dir");
    fs::create_dir(&marker).unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!("[filesystem]\nread = [\"{}\"]\n", marker.display()),
    )
    .unwrap();

    // A discovered config is inert until accepted, so this test accepts it and
    // then asks what the walk found.
    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();

    // The target lives under a system path, so the upward walk from the target
    // finds nothing; only the working directory walk can find this config.
    let output = Command::new(bailey())
        .args(["show", "/usr/bin/true"])
        .current_dir(dir.path())
        .env("XDG_DATA_HOME", store.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("working dir"),
        "config layer should be attributed to the working directory walk: {stdout}"
    );
    assert!(
        stdout.contains(&marker.display().to_string()),
        "grant from the working directory config should be in the policy: {stdout}"
    );
}

#[test]
fn target_arguments_are_not_parsed_by_bailey() {
    let output = Command::new(bailey())
        .args(["run", "/bin/sh", "-c", "echo passed-through"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "run should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "passed-through",
        "`-c` must reach the target rather than being read as bailey's --config"
    );
}

#[test]
fn target_outside_system_paths_runs_without_config() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("program");
    fs::copy("/bin/true", &program).unwrap();

    let output = Command::new(bailey())
        .arg("run")
        .arg(&program)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "a target outside the system paths must be granted implicitly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_bare_name_resolves_on_path() {
    let output = Command::new(bailey())
        .args(["show", "sh"])
        .output()
        .unwrap();

    assert!(output.status.success(), "a name on PATH must resolve");
    let shown = String::from_utf8_lossy(&output.stdout);
    assert!(
        shown.contains("/sh"),
        "the resolved path must be the one on PATH: {shown}"
    );
}

#[test]
fn a_target_that_does_not_exist_is_an_error() {
    for name in ["definitely-not-a-real-command", "./also-not-real"] {
        let output = Command::new(bailey())
            .args(["show", name])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "a missing target must fail rather than describe a policy for nothing"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(name),
            "the error must name the target: {stderr}"
        );
    }
}

/// The `show` output names a grant as its access bits, then the path.
fn policy_line(stdout: &str, bits: &str, path: &std::path::Path) -> bool {
    stdout.contains(&format!("{bits} {}", path.display()))
}

#[test]
fn command_line_grants_reach_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    fs::create_dir(&marker).unwrap();

    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-read",
            marker.to_str().unwrap(),
            "--allow-net",
            "443",
            "/usr/bin/true",
        ])
        .current_dir(dir.path())
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
    assert!(
        policy_line(&stdout, "r---", &marker),
        "the quick grant must reach the policy: {stdout}"
    );
    assert!(
        stdout.contains("443"),
        "the quick egress port must reach the policy: {stdout}"
    );
}

#[test]
fn a_command_line_deny_retracts_a_config_grant() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("project");
    fs::create_dir(&marker).unwrap();
    let config = dir.path().join("given.toml");
    fs::write(
        &config,
        format!("[filesystem]\nwrite = [\"{}\"]\n", marker.display()),
    )
    .unwrap();

    // Without the flag, the config's grant stands.
    let base = Command::new(bailey())
        .args(["show", "--config"])
        .arg(&config)
        .arg("/usr/bin/true")
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&base.stdout);
    assert!(
        policy_line(&stdout, "-w--", &marker),
        "the config grant should be in the policy: {stdout}"
    );

    // With the flag, the same path is denied outright.
    let denied = Command::new(bailey())
        .args(["show", "--config"])
        .arg(&config)
        .args(["--deny", marker.to_str().unwrap(), "/usr/bin/true"])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        policy_line(&stdout, "----", &marker),
        "the command-line deny must retract the config grant: {stdout}"
    );
}

#[test]
fn a_relative_quick_grant_resolves_against_the_working_directory() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(bailey())
        .args(["show", "--allow-write", ".", "/usr/bin/true"])
        .current_dir(dir.path())
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
    assert!(
        policy_line(&stdout, "-w--", dir.path()),
        "a relative grant means the directory the command was typed in: {stdout}"
    );
}

/// A socket path a `--allow-connect` flag names, shown with the connect bit.
#[test]
fn a_connect_flag_reaches_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wayland-1");

    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-connect",
            socket.to_str().unwrap(),
            "/usr/bin/true",
        ])
        .current_dir(dir.path())
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
    assert!(
        policy_line(&stdout, "---c", &socket),
        "the connect flag must reach the policy as its own grant: {stdout}"
    );
}

/// A flag naming a variable the run cannot see is refused, not dropped: a
/// one-off ask that silently grants nothing would be a lie on the command
/// line.
#[test]
fn a_connect_flag_with_an_unset_variable_is_refused() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-connect",
            "${BAILEY_NO_SUCH_VARIABLE}/wayland-1",
            "/usr/bin/true",
        ])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .env_remove("BAILEY_NO_SUCH_VARIABLE")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "an unset variable in a connect flag must refuse the flag"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BAILEY_NO_SUCH_VARIABLE"),
        "the refusal must name the variable: {stderr}"
    );
}

#[test]
fn a_connect_flag_with_an_empty_variable_is_refused() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-connect",
            "${BAILEY_EMPTY_DISPLAY}/wayland-1",
            "/usr/bin/true",
        ])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .env("BAILEY_EMPTY_DISPLAY", "")
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "an empty variable in a connect flag must refuse the flag"
    );
}

/// The runtime directory itself is never connectable, not even when the flag
/// names it exactly: connect there is granted socket by socket.
#[test]
fn a_connect_flag_on_the_runtime_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-connect",
            "${XDG_RUNTIME_DIR}",
            "/usr/bin/true",
        ])
        .current_dir(dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
        .env("XDG_DATA_HOME", dir.path().join("no-store"))
        .env("XDG_RUNTIME_DIR", dir.path().join("missing-runtime"))
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "the runtime directory must not be connectable through a flag"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("runtime directory"),
        "the refusal must say why: {stderr}"
    );
}

#[test]
fn a_conflicting_command_line_grant_is_refused() {
    let output = Command::new(bailey())
        .args([
            "show",
            "--allow-write",
            "/tmp/conflict-check",
            "--deny",
            "/tmp/conflict-check",
            "/usr/bin/true",
        ])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("both granted and denied"),
        "the error should name the contradiction: {stderr}"
    );
}

/// The desktop profiles list their display and audio sockets. The connect
/// entries follow `WAYLAND_DISPLAY` like the variables do: the compositor's
/// name when it is set, the two audio sockets alone when it is not, and the
/// absolute path when a compositor sets one.
#[test]
fn desktop_profiles_resolve_their_connect_entries() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();

    for name in ["desktop-app", "native-game"] {
        let show = |wayland: Option<&str>| {
            let mut command = Command::new(bailey());
            command
                .args(["show", "--profile", name, "/usr/bin/true"])
                .env("XDG_CONFIG_HOME", dir.path().join("no-config"))
                .env("XDG_DATA_HOME", dir.path().join("no-store"))
                .env("XDG_RUNTIME_DIR", runtime.path());
            match wayland {
                Some(value) => {
                    command.env("WAYLAND_DISPLAY", value);
                }
                None => {
                    command.env_remove("WAYLAND_DISPLAY");
                }
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{name} must resolve: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        let shown = show(Some("wayland-1"));
        for socket in ["wayland-1", "pulse/native", "pipewire-0"] {
            let path = runtime.path().join(socket);
            assert!(
                policy_line(&shown, "---c", &path),
                "{name} must list {socket} with the connect bit: {shown}"
            );
        }

        let shown = show(None);
        assert!(
            policy_line(&shown, "---c", &runtime.path().join("pulse/native"))
                && policy_line(&shown, "---c", &runtime.path().join("pipewire-0")),
            "{name} must keep the audio sockets without a compositor: {shown}"
        );
        assert!(
            !shown.contains(&runtime.path().join("wayland-1").display().to_string()),
            "{name} must not grant a display socket when no compositor is named: {shown}"
        );

        let shown = show(Some("/elsewhere/absolute-wayland-1"));
        assert!(
            policy_line(
                &shown,
                "---c",
                std::path::Path::new("/elsewhere/absolute-wayland-1")
            ),
            "{name} must follow an absolute WAYLAND_DISPLAY: {shown}"
        );
    }
}
