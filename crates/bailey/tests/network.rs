//! Integration tests for network confinement.
//!
//! The interesting cases need a program that can open sockets, so these use
//! `python3` and self-skip where it is absent. They also self-skip where user
//! namespaces are unavailable, since the network namespace depends on them.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bailey() -> &'static str {
    env!("CARGO_BIN_EXE_bailey")
}

fn python() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).exists())
}

fn netns_available() -> bool {
    bailey::backend::isolation::available()
}

/// Run a short python program under enforcement with the given config body.
fn run_python(config_body: &str, program: &str) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, config_body).unwrap();

    Command::new(bailey())
        .args(["run", "-c"])
        .arg(&config)
        .args([python().unwrap(), "-c", program])
        .output()
        .unwrap()
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn denied_egress_blocks_udp_as_well_as_tcp() {
    if python().is_none() || !netns_available() {
        eprintln!("skipping: needs python3 and user namespaces");
        return;
    }
    let output = run_python(
        "",
        "import socket\n\
         try:\n\
         \x20   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         \x20   s.sendto(b'x', ('8.8.8.8', 53))\n\
         \x20   print('udp-allowed')\n\
         except OSError:\n\
         \x20   print('udp-blocked')\n",
    );
    assert_eq!(
        stdout_of(&output),
        "udp-blocked",
        "denying egress must block UDP, not only TCP"
    );
}

#[test]
fn denied_egress_blocks_name_resolution() {
    if python().is_none() || !netns_available() {
        eprintln!("skipping: needs python3 and user namespaces");
        return;
    }
    let output = run_python(
        "",
        "import socket\n\
         try:\n\
         \x20   socket.gethostbyname('example.com')\n\
         \x20   print('resolved')\n\
         except OSError:\n\
         \x20   print('blocked')\n",
    );
    assert_eq!(stdout_of(&output), "blocked");
}

#[test]
fn loopback_works_inside_the_sandbox() {
    if python().is_none() || !netns_available() {
        eprintln!("skipping: needs python3 and user namespaces");
        return;
    }
    let output = run_python(
        "",
        "import socket\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         s.bind(('127.0.0.1', 0))\n\
         s.sendto(b'ping', s.getsockname())\n\
         s.settimeout(2)\n\
         print('loopback-ok' if s.recvfrom(8)[0] == b'ping' else 'unexpected')\n",
    );
    assert_eq!(
        stdout_of(&output),
        "loopback-ok",
        "the sandbox's own loopback must be usable"
    );
}

#[test]
fn only_loopback_is_visible() {
    if !netns_available() {
        eprintln!("skipping: user namespaces unavailable");
        return;
    }
    let output = Command::new(bailey())
        .args([
            "run",
            "/bin/sh",
            "-c",
            "awk 'NR>2 {sub(/:.*/, \"\", $1); print $1}' /proc/net/dev",
        ])
        .output()
        .unwrap();
    assert_eq!(
        stdout_of(&output),
        "lo",
        "a target with no network policy must see only loopback"
    );
}

#[test]
fn host_abstract_socket_is_refused() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    if python().is_none() {
        eprintln!("skipping: needs python3");
        return;
    }
    // Egress is allowed, so no network namespace is created and the abstract
    // socket namespace is shared with the host. Only Landlock scoping can refuse
    // this, which is the point of the test.
    let name = format!("bailey-test-{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let _listener = UnixListener::bind_addr(&addr).unwrap();

    let output = run_python(
        "[network]\negress = \"allow\"\n",
        &format!(
            "import socket\n\
             try:\n\
             \x20   c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
             \x20   c.connect('\\0{name}')\n\
             \x20   print('connected')\n\
             except OSError:\n\
             \x20   print('refused')\n"
        ),
    );
    assert_eq!(
        stdout_of(&output),
        "refused",
        "a host abstract socket must be out of reach"
    );
}

#[test]
fn signalling_a_host_process_is_refused() {
    if python().is_none() {
        eprintln!("skipping: needs python3");
        return;
    }
    // The test process belongs to the same user, so this would succeed without
    // Landlock's signal scoping.
    let pid = std::process::id();
    let output = run_python(
        "[network]\negress = \"allow\"\n",
        &format!(
            "import os\n\
             try:\n\
             \x20   os.kill({pid}, 0)\n\
             \x20   print('allowed')\n\
             except OSError:\n\
             \x20   print('refused')\n"
        ),
    );
    assert_eq!(
        stdout_of(&output),
        "refused",
        "signalling a process outside the sandbox must be refused"
    );
}

#[test]
fn allowed_egress_reports_that_only_tcp_is_covered() {
    let dir = tempfile::tempdir().unwrap();
    let config: PathBuf = dir.path().join("bailey.toml");
    fs::write(
        &config,
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\n",
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
        stderr.contains("TCP port only") && stderr.contains("not restricted"),
        "a partial allowance must say what it does not cover: {stderr}"
    );
}
