//! Integration tests for a bailey run from inside a bailey sandbox.
//!
//! These nest for real rather than simulating the environment, because the thing
//! under test is what the inner run says about layers it could not build and did
//! not need to. The inner binary is copied into the granted directory, since a
//! sandbox's `PATH` is `/usr/local/bin:/usr/bin:/bin` and the test binary is not
//! on it.
mod common;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn isolation_active() -> bool {
    let output = Command::new(bailey())
        .args([
            "run",
            "/bin/sh",
            "-c",
            "[ \"$(cat /proc/1/comm)\" = bailey ] && echo yes || echo no",
        ])
        .output();
    matches!(output, Ok(out) if out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == "yes")
}

/// A project directory with a trusted config and a copy of bailey inside it.
fn project(store: &Path) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("project");
    fs::create_dir(&dir).unwrap();
    fs::copy(bailey(), dir.join("bailey-bin")).unwrap();

    let config = dir.join("bailey.toml");
    fs::write(&config, "[filesystem]\nread = [\".\"]\n").unwrap();
    Command::new(bailey())
        .arg("trust")
        .arg(&config)
        .env("XDG_DATA_HOME", store)
        .output()
        .unwrap();

    (root, dir)
}

/// Run `script` in an outer confined shell launched from `dir`.
fn outer(store: &Path, dir: &Path, script: &str) -> Output {
    outer_with(store, dir, None, script)
}

/// The same, with a config the outer shell itself is held to.
fn outer_with(store: &Path, dir: &Path, config: Option<&Path>, script: &str) -> Output {
    let mut command = Command::new(bailey());
    command.args(["shell", "--shell", "/bin/sh"]);
    if let Some(config) = config {
        command.arg("-c").arg(config);
    }
    let mut child = command
        .current_dir(dir)
        .env("XDG_DATA_HOME", store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn an_inherited_layer_is_reported_as_enforced() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());

    let output = outer(
        store.path(),
        &dir,
        "./bailey-bin run --no-isolate /bin/true\n",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("(inherited)"),
        "a layer the outer sandbox established is enforced, not missing: {stderr}"
    );
    assert!(
        !stderr.contains("UDP"),
        "the inherited namespace has no route, so nothing about UDP is unrestricted: {stderr}"
    );
    assert!(
        !stderr.contains("unprivileged user namespaces unavailable"),
        "the cause is our own seccomp filter, not the host: {stderr}"
    );
}

#[test]
fn an_unreachable_trust_store_is_not_reported_as_untrusted() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());

    let output = outer(store.path(), &dir, "./bailey-bin run /bin/true\n");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("not reachable"),
        "the store cannot be read from inside, which is not the same as the file \
         being untrusted: {stderr}"
    );
    assert!(
        !stderr.contains("you have not trusted it"),
        "the file is trusted; bailey simply cannot see the record: {stderr}"
    );
    assert!(
        !stderr.contains("bailey trust /"),
        "and it must not suggest a command that would write into a discarded \
         home: {stderr}"
    );
}

#[test]
fn trusting_from_inside_a_sandbox_is_refused() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());

    let output = outer(
        store.path(),
        &dir,
        "./bailey-bin trust ./bailey.toml && echo RECORDED\n",
    );

    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("RECORDED"),
        "recording trust into a home that is discarded must fail rather than \
         appear to work"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not reachable"),
        "and it must say why: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// An inner run adds its own Landlock layer, and a socket the outer target
/// created counts as outside the inner domain: it is connectable only when
/// the inner policy lists it.
#[test]
fn an_inner_run_needs_its_own_connect_entry_for_an_outer_socket() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("/usr/bin/python3 unavailable");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());
    // The second config adds the connect entry the first leaves out.
    fs::write(
        dir.join("listed.toml"),
        "[filesystem]\nread = [\".\"]\nconnect = [\"./inner.sock\"]\n",
    )
    .unwrap();

    let probe = "'import socket\n\
         try:\n\
         \x20   c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   c.connect(\"./inner.sock\")\n\
         \x20   print(\"CONNECTED\")\n\
         except OSError:\n\
         \x20   print(\"REFUSED\")\n'";
    let script = format!(
        "/usr/bin/python3 -c 'import socket\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         s.bind(\"./inner.sock\")\n\
         s.listen(8)\n\
         import time\n\
         time.sleep(30)\n' &\n\
         sleep 0.5\n\
         ./bailey-bin run -c bailey.toml --no-isolate /usr/bin/python3 -c {probe}\n\
         ./bailey-bin run -c listed.toml --no-isolate /usr/bin/python3 -c {probe}\n"
    );
    let output = outer(store.path(), &dir, &script);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let refused = stdout.matches("REFUSED").count();
    let connected = stdout.matches("CONNECTED").count();
    assert_eq!(
        (refused, connected),
        (1, 1),
        "the inner run without the entry must be refused and the one with it \
         must connect: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A nested run cannot build the namespace that destination, UDP, deny and
/// DNS rules are enforced in, so a policy carrying one must be refused
/// rather than quietly reduced to the Landlock layer.
#[test]
fn a_nested_run_refuses_egress_rules_it_cannot_enforce() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());
    fs::write(
        dir.join("nested-net.toml"),
        "[filesystem]\nread = [\".\"]\n\n[network]\negress = \"allow\"\n\
         egress_deny = [{ host = \"203.0.113.0/24\", port = 443 }]\n",
    )
    .unwrap();

    let output = outer(
        store.path(),
        &dir,
        "./bailey-bin run -c nested-net.toml /bin/true\n",
    );

    assert!(
        !output.status.success(),
        "a nested run must refuse a policy whose egress rules need the \
         namespace it cannot build: stdout {} stderr {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nested"),
        "the refusal says the run is nested: {stderr}"
    );
}

/// An outer run allowing every host on 443 leaves the inner run the same
/// contract whatever it inherits: a policy naming a broker is refused,
/// because a nested run cannot establish one.
#[test]
fn a_nested_broker_is_refused_whatever_the_outer_allows() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());
    fs::write(
        dir.join("outer-443.toml"),
        "[filesystem]\nread = [\".\"]\n\n[network]\n\
         egress_allow = [{ host = \"*\", port = 443 }]\n",
    )
    .unwrap();
    fs::write(
        dir.join("inner-broker.toml"),
        "[filesystem]\nread = [\".\"]\n\n[network]\nbroker = \"127.0.0.1:8081\"\n",
    )
    .unwrap();

    let output = outer_with(
        store.path(),
        &dir,
        Some(&dir.join("outer-443.toml")),
        "./bailey-bin run -c inner-broker.toml /bin/true\n",
    );

    assert!(
        !output.status.success(),
        "a nested run must refuse a policy naming a broker: stdout {} stderr {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nested") && stderr.contains("broker"),
        "the refusal names the nesting and the broker: {stderr}"
    );
}

/// A port-only allowance is all a nested run can carry on its own, so it
/// runs and its summary names the Landlock ports it applies, rather than
/// leaving a run that restricts ten ports reading like one that restricts
/// none.
#[test]
fn an_inner_run_with_a_port_only_allowance_reports_its_ports() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());
    fs::write(
        dir.join("ports.toml"),
        "[filesystem]\nread = [\".\"]\n\n[network]\n\
         egress_allow = [{ host = \"*\", port = 443 }, { host = \"*\", port = 80 }]\n",
    )
    .unwrap();

    let output = outer(
        store.path(),
        &dir,
        "./bailey-bin run -c ports.toml /bin/true\n",
    );

    assert!(
        output.status.success(),
        "a port-only allowance runs nested: stdout {} stderr {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nested run"),
        "the summary says the network is the sandbox's inheritance: {stderr}"
    );
    assert!(
        stderr.contains("egress destinations (Landlock): tcp *:443; tcp *:80"),
        "the summary names the ports the run's own layer carries: {stderr}"
    );
}

/// A forward needs a namespace of the run's own to land in, so a nested
/// run carrying one is refused.
#[test]
fn a_nested_forward_is_refused() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());
    fs::write(
        dir.join("forward.toml"),
        "[filesystem]\nread = [\".\"]\n\nforward = [{ port = 8080, host_port = 9090 }]\n",
    )
    .unwrap();

    let output = outer(
        store.path(),
        &dir,
        "./bailey-bin run -c forward.toml /bin/true\n",
    );

    assert!(
        !output.status.success(),
        "a nested run must refuse a policy carrying a forward: stdout {} stderr {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nested") && stderr.contains("forward"),
        "the refusal names the nesting and the forward: {stderr}"
    );
}

/// Processes a confined shell starts are in the shell's own domain, so a
/// socket one of them created is connectable by the others with no entry at
/// all. That is what keeps a shell's own services working.
#[test]
fn a_shell_process_reaches_a_socket_its_own_child_created() {
    if !isolation_active() {
        common::skip("isolation unavailable on this host");
        return;
    }
    if !Path::new("/usr/bin/python3").exists() {
        common::skip("/usr/bin/python3 unavailable");
        return;
    }
    let store = tempfile::tempdir().unwrap();
    let (_root, dir) = project(store.path());

    let script = "\
         /usr/bin/python3 -c 'import socket, time\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         s.bind(\"./shell.sock\")\n\
         s.listen(8)\n\
         time.sleep(20)\n' &\n\
         sleep 0.5\n\
         /usr/bin/python3 -c 'import socket\n\
         c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         c.connect(\"./shell.sock\")\n\
         print(\"CONNECTED\")\n'\n";
    let output = outer(store.path(), &dir, script);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("CONNECTED"),
        "a socket the shell's own child created must be reachable from a sibling: \
         {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
