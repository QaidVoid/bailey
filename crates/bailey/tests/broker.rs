//! Integration tests for the built-in egress broker's own confinement.
//!
//! These spawn `bailey-broker` directly, with the pid, stdin configuration
//! and descriptors bailey's parent would give it. The probes that answer
//! whether confinement holds run inside the broker through the
//! `BAILEY_BROKER_SELFTEST` hook, because a non-dumpable process's `/proc`
//! entries are root's, which is confinement doing its work. The one test
//! that needs a full run under netns self-skips where python3 or user
//! namespaces are unavailable, like the network suite does.
mod common;

use std::io::Write;
use std::process::{Command, Stdio};

fn broker() -> std::path::PathBuf {
    let path = std::env::var("CARGO_BIN_EXE_bailey-broker")
        .map(Into::into)
        .unwrap_or_else(|_| {
            // The broker lands beside the bailey binary in the same target
            // directory, which is also how bailey finds it beside itself.
            std::path::Path::new(env!("CARGO_BIN_EXE_bailey")).with_file_name("bailey-broker")
        });
    assert!(
        path.exists(),
        "`{}` is missing; build the broker first (`cargo build -p bailey-broker`, \
         or run the whole workspace's tests)",
        path.display()
    );
    path
}

fn python() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

/// A configuration with no HTTP rules at all: the broker may resolve and
/// connect to nothing but its DNS port, and even that no probe tries.
fn empty_config() -> Vec<u8> {
    serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(
            r#"{"intercept":[],"allow":[],"deny":[],"credentials":[],"log":null,"source":null}"#,
        )
        .unwrap(),
        credentials: Vec::new(),
        log: false,
    })
    .unwrap()
}

/// Spawn the broker the way bailey's parent does: the pid as the only
/// argument, the configuration on stdin, the ready line back on stdout.
fn run_broker_with(command: Command, envs: &[(&str, &std::ffi::OsStr)]) -> std::process::Child {
    run_broker_with_config(command, envs, empty_config())
}

/// Spawn the broker with a configuration of the test's own.
fn run_broker_with_config(
    mut command: Command,
    envs: &[(&str, &std::ffi::OsStr)],
    config: Vec<u8>,
) -> std::process::Child {
    command
        .arg(std::process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&config).unwrap();
    drop(stdin);
    child
}

fn run_broker(envs: &[(&str, &std::ffi::OsStr)]) -> std::process::Child {
    run_broker_with(Command::new(broker()), envs)
}

/// Everything the broker printed: the ready line, then any probe lines.
fn output_of(mut child: std::process::Child) -> (std::process::Output, Vec<String>) {
    use std::io::Read;

    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&stdout);
    let lines = text
        .lines()
        .filter(|line| line.starts_with("probe "))
        .map(|line| line.trim_start_matches("probe ").to_string())
        .collect();
    (output, lines)
}

fn probe_value(lines: &[String], name: &str) -> String {
    lines
        .iter()
        .find(|line| line.starts_with(&format!("{name}=")))
        .map(|line| line.trim_start_matches(&format!("{name}=")).to_string())
        .unwrap_or_else(|| panic!("no `{name}` probe in {lines:?}"))
}

/// Bind a listening UNIX socket at `path`, by pathname.
fn bind_path_socket(path: &std::path::Path) -> std::io::Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    let bytes = path.as_os_str().as_encoded_bytes();
    let len = bytes.len().min(address.sun_path.len() - 1);
    address.sun_path[..len]
        .copy_from_slice(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), len) });
    let bound = unsafe {
        libc::bind(
            fd,
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if bound != 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    if unsafe { libc::listen(fd, 8) } != 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(fd)
}

/// Bind a listening UNIX socket at an abstract `name`.
fn bind_abstract_socket(name: &str) -> std::io::Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut address = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    let bytes = name.as_bytes();
    let len = bytes.len().min(address.sun_path.len() - 1);
    address.sun_path[1..=len]
        .copy_from_slice(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), len) });
    let address_len =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + len) as libc::socklen_t;
    let bound = unsafe {
        libc::bind(
            fd,
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            address_len,
        )
    };
    if bound != 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    if unsafe { libc::listen(fd, 8) } != 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(fd)
}

/// A broker started with a pid that is not its parent's exits at once, with
/// no ready line: it could have been orphaned before the death signal was
/// armed, or started by something other than bailey.
#[test]
fn a_broker_with_a_wrong_parent_pid_exits_at_once() {
    let mut child = Command::new(broker())
        // Init's pid can never be this test's parent.
        .arg("1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let started = std::time::Instant::now();
    let output = child.wait_with_output().unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the broker must exit at once, not linger"
    );
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "a refused broker writes no ready line"
    );
}

/// After confinement, an open of a file in the caller's home fails, and a
/// connect to a host test service on a pathname UNIX socket and on an
/// abstract UNIX socket both fail, even with services listening on them.
#[test]
fn a_confined_broker_cannot_reach_the_callers_files_or_unix_sockets() {
    let dir = tempfile::tempdir().unwrap();

    // The files and sockets a caller leaves lying around.
    let home_file = dir.path().join("home-marker");
    std::fs::write(&home_file, "secret").unwrap();
    let path_socket = dir.path().join("service.sock");
    let pathname_listener = bind_path_socket(&path_socket).unwrap();
    let abstract_name = "bailey-broker-test-abstract";
    let abstract_listener = bind_abstract_socket(abstract_name).unwrap();
    // A host TCP service whose port no rule grants.
    let tcp_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();

    let unix_path = path_socket.clone().into_os_string();
    let tcp_addr = std::ffi::OsString::from(format!("127.0.0.1:{tcp_port}"));
    let (output, probes) = output_of(run_broker(&[
        ("BAILEY_BROKER_SELFTEST", &std::ffi::OsString::from("1")),
        ("HOME", dir.path().as_os_str()),
        ("BAILEY_BROKER_SELFTEST_UNIX_PATH", &unix_path),
        (
            "BAILEY_BROKER_SELFTEST_UNIX_ABSTRACT",
            &std::ffi::OsString::from(abstract_name),
        ),
        ("BAILEY_BROKER_SELFTEST_TCP_ADDR", &tcp_addr),
    ]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "probes must run cleanly: {stderr}");

    // An open of a file in the caller's home fails.
    let home = probe_value(&probes, "home");
    assert!(home != "ok", "the broker read a caller's file: {probes:?}");
    // Pathname and abstract UNIX sockets both fail, even though services are
    // listening on them.
    let path = probe_value(&probes, "unix-path");
    assert!(
        path != "ok",
        "the broker reached a pathname socket: {probes:?}"
    );
    let abstract_value = probe_value(&probes, "unix-abstract");
    assert!(
        abstract_value != "ok",
        "the broker reached an abstract socket: {probes:?}"
    );
    // Sanity: the internet families are not what is broken.
    assert_eq!(probe_value(&probes, "inet-socket"), "ok", "{probes:?}");
    // The ungranted TCP port is refused by Landlock, not by the address,
    // where the kernel has network rules at all (Landlock ABI 4).
    if bailey::backend::probe::landlock_abi().is_some_and(|abi| abi >= 4) {
        let tcp = probe_value(&probes, "tcp-connect");
        assert!(
            tcp != "ok",
            "the broker connected to an ungranted port: {probes:?}"
        );
    }

    // Hold the listeners to the end of the test: the probes must answer
    // against services that are listening.
    let _ = pathname_listener;
    let _ = abstract_listener;
    let _ = tcp_listener;
}

/// A rule that names no port allows every port to its host, so the
/// broker's Landlock connect grant cannot stop at the default pair: the
/// probe reaches a service on a port no rule names.
#[test]
fn a_portless_rule_connects_beyond_the_default_ports() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(
            r#"{"intercept":[],"allow":[{"host":{"Exact":"example.com"},"port":null,"methods":[],"path":null}],"deny":[],"credentials":[],"log":null,"source":null}"#,
        )
        .unwrap(),
        credentials: Vec::new(),
        log: false,
    })
    .unwrap();
    let tcp_addr = std::ffi::OsString::from(format!("127.0.0.1:{port}"));
    let (output, probes) = output_of(run_broker_with_config(
        Command::new(broker()),
        &[
            ("BAILEY_BROKER_SELFTEST", &std::ffi::OsString::from("1")),
            ("BAILEY_BROKER_SELFTEST_TCP_ADDR", &tcp_addr),
        ],
        config,
    ));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "probes must run cleanly: {stderr}");
    assert_eq!(
        probe_value(&probes, "tcp-connect"),
        "ok",
        "a rule without a port allows every port to its host: {probes:?}"
    );
    let _ = listener;
}

/// The host's trust roots load before confinement, not lazily on the first
/// upstream session: after confinement, whether the loader's probe paths
/// fall inside the broker's grants decides the load, and a failure would
/// surface mid-serve instead of at startup. An intercepting broker whose
/// only named bundle is a readable file outside those grants still answers
/// with the roots it read at startup.
#[test]
fn trust_roots_load_regardless_of_confinement() {
    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("outside-grants.pem");
    std::fs::copy("/etc/ssl/certs/ca-certificates.crt", &pem)
        .or_else(|_| std::fs::copy("/etc/pki/tls/certs/ca-bundle.crt", &pem))
        .expect("a host trust bundle to copy");
    let pem_env = std::ffi::OsString::from(pem.as_os_str());
    // cargo exports `SSL_CERT_DIR` into the test's environment, and with it
    // set the loader falls back to the hashed-certificates directory the
    // broker's grants cover. The scenario is a root bundle that only
    // `SSL_CERT_FILE` names, so the directory is cleared.
    let mut command = Command::new(broker());
    command.env_remove("SSL_CERT_DIR");

    let config = serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(
            r#"{"intercept":[{"Exact":"example.com"}],"allow":[],"deny":[],"credentials":[],"log":null,"source":null}"#,
        )
        .unwrap(),
        credentials: Vec::new(),
        log: false,
    })
    .unwrap();
    let (output, probes) = output_of(run_broker_with_config(
        command,
        &[
            ("BAILEY_BROKER_SELFTEST", &std::ffi::OsString::from("1")),
            ("SSL_CERT_FILE", &pem_env),
        ],
        config,
    ));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "probes must run cleanly: {stderr}");
    assert_eq!(
        probe_value(&probes, "trust-roots"),
        "ok",
        "the trust roots load before confinement, from a file no grant covers"
    );
}

/// The roots are read before confinement, where the process still sees the
/// host's filesystem: in a private root whose only trust bundle is
/// `/etc/certs.pem`, an intercepting broker reads it at startup and serves
/// the whole run from what it read. The same path read after confinement
/// sits outside the broker's grants, which is exactly the late failure the
/// early read prevents.
#[test]
fn trust_roots_load_before_confinement_in_a_bare_root() {
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    // A private /etc needs a mount namespace, which a user namespace alone
    // cannot make: probe the exact command.
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("bundle.pem");
    std::fs::copy("/etc/ssl/certs/ca-certificates.crt", &pem)
        .or_else(|_| std::fs::copy("/etc/pki/tls/certs/ca-bundle.crt", &pem))
        .expect("a host trust bundle to copy");
    let setup = format!(
        "mount -t tmpfs none /etc \
         && cp '{pem}' /etc/certs.pem \
         && exec \"$0\" \"$@\"",
        pem = pem.display()
    );
    let mut command = Command::new(unshare);
    command
        .args(["-Urm", "sh", "-c", &setup])
        .arg(broker())
        .arg(std::process::id().to_string())
        .env_remove("SSL_CERT_DIR");

    let config = serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(
            r#"{"intercept":[{"Exact":"example.com"}],"allow":[],"deny":[],"credentials":[],"log":null,"source":null}"#,
        )
        .unwrap(),
        credentials: Vec::new(),
        log: false,
    })
    .unwrap();
    let (output, probes) = output_of(run_broker_with_config(
        command,
        &[
            ("BAILEY_BROKER_SELFTEST", &std::ffi::OsString::from("1")),
            ("SSL_CERT_FILE", &std::ffi::OsString::from("/etc/certs.pem")),
        ],
        config,
    ));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "probes must run cleanly: {stderr}");
    assert_eq!(
        probe_value(&probes, "trust-roots"),
        "ok",
        "the roots are read before confinement, where /etc/certs.pem is still visible"
    );
}

/// A non-CLOEXEC descriptor left open in bailey is closed in the broker: the
/// broker reports what it holds, and descriptor 9 is not on the list.
#[test]
fn a_foreign_descriptor_does_not_reach_the_broker() {
    use std::os::unix::io::AsRawFd;

    let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let leaked_fd = reader.as_raw_fd();

    let mut command = Command::new(broker());
    // Safety: runs in the forked child before exec, where only
    // async-signal-safe calls are made. `dup2` clears close-on-exec, which
    // is exactly the leak bailey can produce.
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            if libc::dup2(leaked_fd, 9) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let (_, probes) = output_of(run_broker_with(
        command,
        &[("BAILEY_BROKER_SELFTEST", &std::ffi::OsString::from("1"))],
    ));

    // Whatever the broker kept, descriptor 9 is not on the list.
    let list = probe_value(&probes, "descriptors");
    assert!(
        !list.split(',').any(|fd| fd == "9"),
        "descriptor 9 leaked: {list}"
    );
    // The descriptors the broker lives on are still there.
    for kept in ["0", "1", "2", "3"] {
        assert!(
            list.split(',').any(|fd| fd == kept),
            "descriptor {kept} is missing: {list}"
        );
    }
}

/// On a kernel below Landlock ABI 6, or with the test hook forcing that
/// belief, the ready line reports the missing layers and the UNIX connects
/// still fail, because the seccomp family filter is the boundary.
#[test]
fn below_landlock_abi_six_the_layers_are_reported_and_unix_still_fails() {
    let forced = std::ffi::OsString::from("4");

    // The layers, from the ready line.
    let mut child = run_broker(&[("BAILEY_BROKER_LANDLOCK_ABI", &forced)]);
    let mut stdout = child.stdout.take().unwrap();
    let ready = bailey::broker::BrokerReady::decode(&mut stdout).expect("a ready line");
    assert!(
        ready.layers.seccomp,
        "the family filter is the boundary: {ready:?}"
    );
    assert!(
        !ready.layers.landlock,
        "ABI 4 has no scopes, so the full ruleset is not applied: {ready:?}"
    );
    assert!(
        ready.layers.landlock_network,
        "ABI 4 has TCP connect rules: {ready:?}"
    );
    let _ = child.kill();
    let _ = child.wait();

    // The probes, under the same forced ABI.
    let dir = tempfile::tempdir().unwrap();
    let path_socket = dir.path().join("service.sock");
    let pathname_listener = bind_path_socket(&path_socket).unwrap();
    let abstract_name = "bailey-broker-test-abstract-4";
    let abstract_listener = bind_abstract_socket(abstract_name).unwrap();
    let unix_path = path_socket.into_os_string();
    let (_, probes) = output_of(run_broker(&[
        ("BAILEY_BROKER_SELFTEST", &std::ffi::OsString::from("1")),
        ("BAILEY_BROKER_LANDLOCK_ABI", &forced),
        ("HOME", dir.path().as_os_str()),
        ("BAILEY_BROKER_SELFTEST_UNIX_PATH", &unix_path),
        (
            "BAILEY_BROKER_SELFTEST_UNIX_ABSTRACT",
            &std::ffi::OsString::from(abstract_name),
        ),
    ]));
    assert!(probe_value(&probes, "unix-path") != "ok", "{probes:?}");
    assert!(probe_value(&probes, "unix-abstract") != "ok", "{probes:?}");
    let _ = pathname_listener;
    let _ = abstract_listener;
}

/// Killing bailey with SIGKILL takes the broker with it: the death signal
/// the broker armed as its first action.
#[test]
fn killing_bailey_takes_the_broker_with_it() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    if !bailey::backend::isolation::available() {
        common::skip("needs user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    std::fs::write(
        &config,
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\nbroker = \"builtin\"\n",
    )
    .unwrap();

    let mut run = Command::new(env!("CARGO_BIN_EXE_bailey"))
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .arg("run")
        .arg("-c")
        .arg(&config)
        .args([python, "-c", "import time; time.sleep(60)"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    // The real broker beside the bailey binary serves the run. Wait for it
    // to appear, then kill bailey and check the broker follows.
    let broker_pid = (|| {
        for _ in 0..50 {
            if let Some(pid) = find_process("bailey-broker", run.id()) {
                return Some(pid);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        None
    })()
    .expect("the broker must be running while bailey runs");

    unsafe { libc::kill(run.id() as libc::pid_t, libc::SIGKILL) };
    let gone = (|| {
        for _ in 0..50 {
            if !std::path::Path::new("/proc")
                .join(broker_pid.to_string())
                .exists()
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    })();
    assert!(gone, "the broker outlived bailey");
    let _ = run.kill();
    let _ = run.wait();
}

/// A broker killed mid-run is reported as an early exit, and the run
/// summary names the broker as built-in.
///
/// The run starts, the broker is killed while the target is still going,
/// and the target keeps running to a normal end: nothing about the broker's
/// death stops the run, but the parent says the broker went away.
#[test]
fn a_broker_killed_mid_run_is_reported_when_the_run_ends() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    if !bailey::backend::isolation::available() {
        common::skip("needs user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    std::fs::write(
        &config,
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\nbroker = \"builtin\"\n",
    )
    .unwrap();

    let mut run = Command::new(env!("CARGO_BIN_EXE_bailey"))
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .arg("run")
        .arg("-c")
        .arg(&config)
        .args([
            python,
            "-c",
            "import time; print('STARTED', flush=True); time.sleep(3)",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // The broker is up before the target exists; wait for the target's own
    // first output, then kill the broker out from under the run.
    let mut stdout = run.stdout.take().unwrap();
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(&mut stdout), &mut line)
        .expect("the target's first output");
    assert!(line.contains("STARTED"), "unexpected target output: {line}");

    let broker_pid = (|| {
        for _ in 0..50 {
            if let Some(pid) = find_process("bailey-broker", run.id()) {
                return Some(pid);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        None
    })()
    .expect("the broker must be running while the target runs");
    unsafe { libc::kill(broker_pid as libc::pid_t, libc::SIGKILL) };

    let run_pid = run.id();
    let output = run.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the run itself must succeed: {}\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("egress broker (built-in)"),
        "the summary must name the built-in broker: {stderr}"
    );
    assert!(
        stderr.contains("the egress broker exited early"),
        "the early exit must be reported: {stderr}"
    );
    common::remove_staging_for(run_pid);
}

/// The pid of a process whose name is `name` and whose parent is `parent`,
/// or `None`. A stale broker from an earlier failed test must not be
/// mistaken for this run's.
fn find_process(name: &str, parent: u32) -> Option<u32> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim() != name {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Field 4 of `stat` is the parent pid; the comm field is in
        // parentheses and can itself contain them, so split after the last.
        let Some(rest) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        let ppid = rest
            .split_whitespace()
            .nth(1)
            .and_then(|ppid| ppid.parse::<u32>().ok());
        if ppid == Some(parent) {
            return Some(pid);
        }
    }
    None
}
