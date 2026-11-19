//! Integration tests for network confinement.
//!
//! The interesting cases need a program that can open sockets, so these use
//! `python3` and self-skip where it is absent. They also self-skip where user
//! namespaces are unavailable, since the network namespace depends on them.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

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

fn isolated_command(dir: &Path) -> Command {
    let mut command = Command::new(bailey());
    command
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"));
    command
}

/// Run a short python program under enforcement with the given config body.
fn run_python(config_body: &str, program: &str) -> std::process::Output {
    run_python_with_args(config_body, program, &[])
}

fn run_python_with_args(config_body: &str, program: &str, args: &[&str]) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, config_body).unwrap();

    isolated_command(dir.path())
        .arg("run")
        .args(args)
        .arg("-c")
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
    let dir = tempfile::tempdir().unwrap();
    let output = isolated_command(dir.path())
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

    // Automatic mode puts this run in the private namespace, where the
    // allowance is the whole story. On the host's namespace, where the
    // fallback lands, the run must say what it does not cover.
    let output = isolated_command(dir.path())
        .args(["run", "--no-proxy-net", "-c"])
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

/// Host listeners on an ungranted loopback port, over both address families.
/// Returns the port and the two listeners left nonblocking, so the test can
/// count what was accepted after the run.
fn ungranted_listeners() -> (u16, TcpListener, TcpListener) {
    let v4 = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = v4.local_addr().unwrap().port();
    let v6 = TcpListener::bind(("::1", port)).unwrap();
    v4.set_nonblocking(true).unwrap();
    v6.set_nonblocking(true).unwrap();
    (port, v4, v6)
}

fn accepted_count(listener: &TcpListener) -> usize {
    let mut accepted = 0;
    while listener.accept().is_ok() {
        accepted += 1;
    }
    accepted
}

/// An MPTCP socket must not sidestep the TCP port rules on connect, over
/// either address family. Before the protocol guard this connected: an
/// MPTCP socket is not `sk_is_tcp()`, so Landlock skipped it.
#[test]
fn mptcp_cannot_reach_an_ungranted_port() {
    if python().is_none() {
        eprintln!("skipping: needs python3");
        return;
    }
    let (port, v4, v6) = ungranted_listeners();
    let output = run_python(
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\n",
        &format!(
            "import socket\n\
             for family, address in ((2, '127.0.0.1'), (10, '::1')):\n\
             \x20   try:\n\
             \x20       s = socket.socket(family, socket.SOCK_STREAM, 262)\n\
             \x20       s.settimeout(2)\n\
             \x20       s.connect((address, {port}))\n\
             \x20       print(family, 'CONNECTED')\n\
             \x20   except OSError as e:\n\
             \x20       print(family, 'errno', e.errno)\n",
            port = port,
        ),
    );
    assert_eq!(
        stdout_of(&output),
        "2 errno 92\n10 errno 92",
        "an MPTCP connect to an ungranted port must fail with the kernel's \
         disabled-feature errno on both families"
    );
    assert_eq!(accepted_count(&v4), 0, "the IPv4 listener was reached");
    assert_eq!(accepted_count(&v6), 0, "the IPv6 listener was reached");
}

/// An MPTCP socket must not sidestep the bind rules either: without
/// `bind_ports` the target binds nothing, MPTCP or not.
#[test]
fn mptcp_cannot_bind_an_ungranted_port() {
    if python().is_none() {
        eprintln!("skipping: needs python3");
        return;
    }
    // Hold the port first so the attempt below is known to target a free one,
    // and drop it once the port is recorded.
    let held = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = held.local_addr().unwrap().port();
    drop(held);
    let output = run_python(
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\n",
        &format!(
            "import socket\n\
             try:\n\
             \x20   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)\n\
             \x20   s.bind(('127.0.0.1', {port}))\n\
             \x20   s.listen(1)\n\
             \x20   print('BOUND')\n\
             except OSError as e:\n\
             \x20   print('errno', e.errno)\n",
            port = port,
        ),
    );
    assert_eq!(
        stdout_of(&output),
        "errno 92",
        "an MPTCP bind without bind_ports must fail with the kernel's \
         disabled-feature errno"
    );
    // The port stayed free: nothing took it, which is the property the bind
    // refusal exists to keep.
    let probe = TcpListener::bind(("127.0.0.1", port)).unwrap();
    drop(probe);
}

/// Every stream protocol the kernel offers must respect the port rules. The
/// inventory comes from the enumeration in the change's design: on a kernel
/// with MPTCP, only 0, 6, 132 and 262 create stream sockets, and before the
/// protocol guard 262 reached the ungranted port. Removing the MPTCP refusal
/// makes this fail; the SMC refusal cannot be observed on a host without SMC
/// support, where the kernel refuses the family on its own.
#[test]
fn every_stream_protocol_respects_port_rules() {
    if python().is_none() {
        eprintln!("skipping: needs python3");
        return;
    }
    let (port, v4, v6) = ungranted_listeners();
    let output = run_python(
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\n",
        &format!(
            "import socket\n\
             for protocol in (0, 6, 132, 262):\n\
             \x20   for family, address in ((2, '127.0.0.1'), (10, '::1')):\n\
             \x20       try:\n\
             \x20           s = socket.socket(family, socket.SOCK_STREAM, protocol)\n\
             \x20           s.settimeout(2)\n\
             \x20           s.connect((address, {port}))\n\
             \x20           print(protocol, family, 'CONNECTED')\n\
             \x20       except OSError as e:\n\
             \x20           print(protocol, family, 'errno', e.errno)\n\
             try:\n\
             \x20   socket.socket(43, socket.SOCK_STREAM, 0)\n\
             \x20   print('smc CREATED')\n\
             except OSError as e:\n\
             \x20   print('smc errno', e.errno)\n",
            port = port,
        ),
    );
    // TCP is refused by Landlock with EACCES, MPTCP by the protocol guard
    // with ENOPROTOOPT. SCTP cannot speak to a TCP listener, so its refusal
    // comes from the network; what matters is that it never connects.
    assert_eq!(
        stdout_of(&output),
        "0 2 errno 13\n0 10 errno 13\n\
         6 2 errno 13\n6 10 errno 13\n\
         132 2 errno 111\n132 10 errno 111\n\
         262 2 errno 92\n262 10 errno 92\n\
         smc errno 97",
        "no stream protocol may reach an ungranted port"
    );
    assert_eq!(accepted_count(&v4), 0, "the IPv4 listener was reached");
    assert_eq!(accepted_count(&v6), 0, "the IPv6 listener was reached");
}

/// Host TCP and UDP services whose sockets stay held until their workers stop.
struct EchoServer {
    port: u16,
    stop: Arc<AtomicBool>,
    udp_received: Arc<AtomicUsize>,
    workers: Vec<JoinHandle<()>>,
}

impl EchoServer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let tcp_stop = Arc::clone(&stop);
        let tcp = std::thread::spawn(move || {
            while !tcp_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut client, _)) => {
                        client
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        client
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut buf = [0; 64];
                        if let Ok(n) = client.read(&mut buf) {
                            let _ = client.write_all(&buf[..n]);
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("host TCP listener failed: {err}"),
                }
            }
        });
        let udp_stop = Arc::clone(&stop);
        let udp_received = Arc::new(AtomicUsize::new(0));
        let received = Arc::clone(&udp_received);
        let udp = std::thread::spawn(move || {
            let mut buf = [0; 64];
            while !udp_stop.load(Ordering::Relaxed) {
                match udp.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        received.fetch_add(1, Ordering::Relaxed);
                        let _ = udp.send_to(&buf[..n], peer);
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(err) => panic!("host UDP listener failed: {err}"),
                }
            }
        });
        Self {
            port,
            stop,
            udp_received,
            workers: vec![tcp, udp],
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            if worker.join().is_err() && !std::thread::panicking() {
                panic!("host echo worker panicked");
            }
        }
    }
}

fn proxy_net_available() -> bool {
    if python().is_none() || !netns_available() {
        eprintln!("skipping: needs python3 and user namespaces");
        return false;
    }
    for helper in ["pasta", "nft"] {
        if let Err(err) = bailey::cli::resolve_helper(helper) {
            eprintln!("skipping: needs trusted {helper}: {err}");
            return false;
        }
    }
    // Probe nft independently, so only missing kernel support can skip a test.
    // A failure in Bailey's own firewall installation must fail the test.
    let nft = bailey::cli::resolve_helper("nft").unwrap();
    let program = format!(
        r#"import ctypes, os, subprocess
uid, gid = os.getuid(), os.getgid()
libc = ctypes.CDLL(None, use_errno=True)
if libc.unshare(0x10000000 | 0x40000000):
    raise OSError(ctypes.get_errno(), 'unshare')
with open('/proc/self/setgroups', 'w') as f:
    f.write('deny')
with open('/proc/self/uid_map', 'w') as f:
    f.write(f'0 {{uid}} 1')
with open('/proc/self/gid_map', 'w') as f:
    f.write(f'0 {{gid}} 1')
subprocess.run([{nft:?}, '-f', '-'], input='table inet bailey_test {{\n chain output {{\n type filter hook output priority 0; policy accept;\n }}\n}}\n', text=True, check=True)
"#,
        nft = nft.to_str().unwrap()
    );
    let output = Command::new(python().unwrap())
        .args(["-c", &program])
        .output()
        .unwrap();
    if !output.status.success() {
        eprintln!(
            "skipping: nft is unavailable in a private user/network namespace: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return false;
    }
    true
}

/// A denied-egress forward still carries to the host without a private proxy.
#[test]
fn forwarded_ports_carry_to_the_host_and_others_stay_dead() {
    if python().is_none() || !netns_available() {
        eprintln!("skipping: needs python3 and user namespaces");
        return;
    }
    let echo = EchoServer::start();
    let hidden = EchoServer::start();
    let output = run_python(
        &format!("[[forward]]\nport = {}\n", echo.port),
        &format!(
            r#"import socket
s = socket.create_connection(('127.0.0.1', {}), timeout=3)
s.sendall(b'ping-forward')
print('echo-' + s.recv(64).decode())
s.close()
try:
    socket.create_connection(('127.0.0.1', {}), timeout=1)
    print('reached-hidden')
except OSError:
    print('hidden-refused')
"#,
            echo.port, hidden.port
        ),
    );
    assert!(
        output.status.success(),
        "forwarded target failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "echo-ping-forward\nhidden-refused");
}

fn check_proxy_net_forward(network: &str) {
    if !proxy_net_available() {
        return;
    }
    let echo = EchoServer::start();
    let hidden = EchoServer::start();
    // Holding a third host listener also guarantees an explicit, distinct remap.
    let inside = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let inside_port = inside.local_addr().unwrap().port();
    assert_ne!(inside_port, echo.port);
    let output = run_python_with_args(
        &format!(
            "[network]\n{network}\n[[forward]]\nport = {inside_port}\nhost_port = {}\n",
            echo.port
        ),
        &format!(
            r#"import concurrent.futures, socket
inside, host, hidden = {inside_port}, {host}, {hidden}
def echo(i):
    payload = ('ping-forward-' + str(i)).encode()
    with socket.create_connection(('127.0.0.1', inside), timeout=3) as s:
        s.sendall(payload)
        assert s.recv(64) == payload
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(echo, range(4)))
print('concurrent-echo-ok')
for address, port in (('127.0.0.1', host), ('127.0.0.1', hidden),
                      ('10.0.2.15', inside), ('127.0.0.2', inside), ('::1', inside)):
    try:
        with socket.create_connection((address, port), timeout=1):
            raise AssertionError('reached unforwarded endpoint ' + str((address, port)))
    except OSError:
        pass
print('other-host-ports-refused')
for port in (inside, host, hidden):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.3)
        try:
            s.sendto(b'udp-must-not-cross', ('127.0.0.1', port))
            s.recv(64)
            raise AssertionError('forward opened UDP port ' + str(port))
        except OSError:
            pass
print('udp-refused')
"#,
            host = echo.port,
            hidden = hidden.port,
        ),
        &["--proxy-net"],
    );
    assert!(
        output.status.success(),
        "private-network forward failed: status {} stdout: {} stderr: {}",
        output.status,
        stdout_of(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout_of(&output),
        "concurrent-echo-ok\nother-host-ports-refused\nudp-refused"
    );
    assert_eq!(echo.udp_received.load(Ordering::Relaxed), 0);
    assert_eq!(hidden.udp_received.load(Ordering::Relaxed), 0);
}

#[test]
fn proxy_net_forwards_remap_only_selected_tcp_host_ports() {
    check_proxy_net_forward("egress = \"allow\"");
}

#[test]
fn proxy_net_partial_egress_allows_only_selected_host_forward() {
    check_proxy_net_forward("egress_allow = [{ host = \"*\", port = 443 }]");
}

#[test]
fn proxy_net_without_forwards_blocks_host_loopback() {
    if !proxy_net_available() {
        return;
    }
    let host = EchoServer::start();
    let output = run_python_with_args(
        "[network]\negress = \"allow\"\n",
        &format!(
            r#"import socket
try:
    with socket.create_connection(('127.0.0.1', {}), timeout=1):
        raise AssertionError('default proxy network reached host loopback')
except OSError:
    print('host-refused')
"#,
            host.port
        ),
        &["--proxy-net"],
    );
    assert!(
        output.status.success(),
        "private-network control failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "host-refused");
}

/// A forward under allowed egress is carried by pasta in automatic mode, with
/// no flag to ask for it: the mode key and the default cover what `--proxy-net`
/// used to have to be spelled out for.
#[test]
fn forwards_carry_without_a_flag_in_auto_mode() {
    if !proxy_net_available() {
        return;
    }
    let echo = EchoServer::start();
    let hidden = EchoServer::start();
    let inside = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let inside_port = inside.local_addr().unwrap().port();
    let output = run_python(
        &format!(
            "[network]\negress = \"allow\"\n[[forward]]\nport = {inside_port}\nhost_port = {}\n",
            echo.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('127.0.0.1', {inside_port}), timeout=3) as s:
    s.sendall(b'auto-forward')
    assert s.recv(64) == b'auto-forward'
print('forward-ok')
for address, port in (('127.0.0.1', {host}), ('127.0.0.1', {hidden})):
    try:
        with socket.create_connection((address, port), timeout=1):
            raise AssertionError('reached unforwarded endpoint')
    except OSError:
        pass
print('other-host-ports-refused')
"#,
            host = echo.port,
            hidden = hidden.port,
        ),
    );
    assert!(
        output.status.success(),
        "an automatic-mode forward failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "forward-ok\nother-host-ports-refused");
}

/// Run a target under enforcement with extra environment, so a test can
/// simulate a host whose helper lookups fail.
fn run_with_env(
    config_body: &str,
    args: &[&str],
    envs: &[(&str, &Path)],
    target: &[&str],
) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(&config, config_body).unwrap();
    let mut command = isolated_command(dir.path());
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .arg("run")
        .args(args)
        .arg("-c")
        .arg(&config)
        .args(target)
        .output()
        .unwrap()
}

/// Automatic mode with allowed egress picks the private namespace when the
/// host provides it: no flag names it, and the target sees a private
/// address, not the host's.
#[test]
fn auto_mode_uses_the_private_namespace() {
    if !proxy_net_available() {
        return;
    }
    let Some(host_address) = non_loopback_host_address() else {
        eprintln!("skipping: no non-loopback host address");
        return;
    };
    let output = run_python(
        "[network]\negress = \"allow\"\n",
        r#"import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.connect(('10.254.254.254', 1))
    print('addr=' + s.getsockname()[0])
"#,
    );
    assert!(
        output.status.success(),
        "the automatic-mode run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = stdout_of(&output);
    let address = stdout
        .trim()
        .strip_prefix("addr=")
        .unwrap_or_else(|| panic!("the target must report its address: {stdout}"));
    assert_ne!(
        address,
        host_address.to_string(),
        "a private namespace must not show the host's address"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("network mode: private"),
        "the summary must name the private mode: {stderr}"
    );
}

/// A forward under allowed egress makes automatic mode need the private
/// namespace, and a host without a trusted pasta refuses the run, naming
/// both what it wanted and what was missing.
#[test]
fn auto_mode_refuses_when_a_forward_needs_it() {
    if !netns_available() {
        eprintln!("skipping: needs user namespaces");
        return;
    }
    let helpers = tempfile::tempdir().unwrap();
    let output = run_with_env(
        "[network]\negress = \"allow\"\n[[forward]]\nport = 54321\n",
        &[],
        &[("BAILEY_HELPER_DIRS", helpers.path())],
        &["/bin/true"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a forward without pasta must refuse the run: {stderr}"
    );
    assert!(
        stderr.contains("the port forwards need the private namespace"),
        "the refusal must name the forwards: {stderr}"
    );
    assert!(
        stderr.contains("pasta, which is not in a trusted location"),
        "the refusal must name the missing helper: {stderr}"
    );
}

/// Without forwards or publications nothing needs the private namespace, so
/// automatic mode continues on the host's namespace and says what it gave up.
#[test]
fn auto_mode_falls_back_when_nothing_needs_it() {
    if !netns_available() {
        eprintln!("skipping: needs user namespaces");
        return;
    }
    let helpers = tempfile::tempdir().unwrap();
    let output = run_with_env(
        "[network]\negress = \"allow\"\n",
        &[],
        &[("BAILEY_HELPER_DIRS", helpers.path())],
        &["/bin/true"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a run with nothing to place must continue: {stderr}"
    );
    assert!(
        stderr.contains("network mode: host"),
        "the summary must name the host mode: {stderr}"
    );
    assert!(
        stderr.contains("automatic mode fell back"),
        "the summary must say the fallback was automatic: {stderr}"
    );
}

/// An explicit private mode without pasta refuses rather than continuing on
/// the host's network: the request is the user's, and a downgrade would lie
/// about where the session's traffic leaves from.
#[test]
fn private_mode_refuses_without_pasta() {
    let helpers = tempfile::tempdir().unwrap();
    let output = run_with_env(
        "[network]\negress = \"allow\"\nmode = \"private\"\n",
        &[],
        &[("BAILEY_HELPER_DIRS", helpers.path())],
        &["/bin/true"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an explicit private mode without pasta must refuse the run: {stderr}"
    );
    assert!(
        stderr.contains("the policy's private mode"),
        "the refusal must name the private mode: {stderr}"
    );
    assert!(
        stderr.contains("the run is refused"),
        "the refusal must say the run was refused: {stderr}"
    );
}

/// The flag asks for the same private network the mode key does, so it
/// refuses the same way, and says the flag asked.
#[test]
fn proxy_net_flag_refuses_without_pasta() {
    let helpers = tempfile::tempdir().unwrap();
    let output = run_with_env(
        "[network]\negress = \"allow\"\n",
        &["--proxy-net"],
        &[("BAILEY_HELPER_DIRS", helpers.path())],
        &["/bin/true"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "--proxy-net without pasta must refuse the run: {stderr}"
    );
    assert!(
        stderr.contains("private mode (flag --proxy-net)"),
        "the refusal must name the flag that asked: {stderr}"
    );
}

/// A configured broker confines the run to that broker: the target reaches
/// it and nothing else, and the summary names the brokered mode and where
/// the broker came from.
#[test]
fn configured_broker_confines_the_run() {
    if !proxy_net_available() {
        return;
    }
    let broker = EchoServer::start();
    let other = EchoServer::start();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!("[network]\nbroker = \"10.0.0.1:{}\"\n", broker.port),
    )
    .unwrap();
    let output = isolated_command(dir.path())
        .arg("run")
        .arg("-c")
        .arg(&config)
        .args([
            python().unwrap(),
            "-c",
            &format!(
                r#"import socket
with socket.create_connection(('10.0.0.1', {broker}), timeout=3) as s:
    s.sendall(b'to-broker')
    assert s.recv(64) == b'to-broker'
print('broker-ok')
try:
    socket.create_connection(('10.0.0.1', {other}), timeout=2)
    print('reached-other')
except OSError:
    print('other-dropped')
"#,
                broker = broker.port,
                other = other.port,
            ),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the brokered run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "broker-ok\nother-dropped");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("network mode: brokered"),
        "the summary must name the brokered mode: {stderr}"
    );
    assert!(
        stderr.contains(&config.display().to_string()),
        "the summary must name where the broker came from: {stderr}"
    );
    assert!(
        stderr.contains(&format!("10.0.0.1:{}", broker.port)),
        "the summary must name the broker's address: {stderr}"
    );
}

struct PublishingChild {
    child: std::process::Child,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl PublishingChild {
    fn spawn(command: &mut Command, dir: &Path) -> Self {
        let stdout = dir.join("child.stdout");
        let stderr = dir.join("child.stderr");
        let child = command
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        Self {
            child,
            stdout,
            stderr,
        }
    }

    fn diagnostics(&self) -> String {
        format!(
            "stdout: {}\nstderr: {}",
            fs::read_to_string(&self.stdout).unwrap(),
            fs::read_to_string(&self.stderr).unwrap()
        )
    }

    fn wait_for_ready(&mut self) -> u16 {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let stdout = fs::read_to_string(&self.stdout).unwrap();
            if let Some(port) = stdout.lines().find_map(|line| line.strip_prefix("ready ")) {
                return port.parse().unwrap();
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "publication target exited before readiness: {}",
                self.diagnostics()
            );
            assert!(
                std::time::Instant::now() < deadline,
                "publication target never became ready: {}",
                self.diagnostics()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "publication target did not exit: {}",
                self.diagnostics()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for PublishingChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn publication_echo(port: u16, payload: &[u8]) -> std::io::Result<()> {
    let mut client = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(250),
    )?;
    client.set_read_timeout(Some(Duration::from_millis(500)))?;
    client.set_write_timeout(Some(Duration::from_millis(500)))?;
    client.write_all(payload)?;
    let mut echoed = vec![0; payload.len()];
    client.read_exact(&mut echoed)?;
    assert_eq!(echoed, payload);
    Ok(())
}

fn non_loopback_host_address() -> Option<std::net::Ipv4Addr> {
    let output = Command::new(python().unwrap())
        .args([
            "-c",
            r#"import fcntl, ipaddress, socket, struct
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    for _, name in sorted(socket.if_nameindex()):
        request = struct.pack('256s', name.encode()[:15])
        try:
            flags = struct.unpack_from('H', fcntl.ioctl(s, 0x8913, request), 16)[0]
            address = socket.inet_ntoa(fcntl.ioctl(s, 0x8915, request)[20:24])
        except OSError:
            continue
        ip = ipaddress.ip_address(address)
        if flags & 1 and not (ip.is_loopback or ip.is_unspecified or ip.is_link_local):
            print(address)
            break
"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "could not enumerate host interfaces: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let address = stdout_of(&output);
    if address.is_empty() {
        None
    } else {
        Some(address.parse().unwrap())
    }
}

#[test]
fn proxy_net_publishes_only_requested_loopback_tcp_and_keeps_forwarding() {
    if !proxy_net_available() {
        return;
    }
    let forward = EchoServer::start();
    let hidden = EchoServer::start();
    let inside = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let inside_port = inside.local_addr().unwrap().port();
    let publication = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = publication.local_addr().unwrap().port();
    let publication_udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    fs::write(
        &config,
        format!(
            "[network]\negress = \"allow\"\npublish_ports = [{port}]\n\
             [[forward]]\nport = {inside_port}\nhost_port = {}\n",
            forward.port
        ),
    )
    .unwrap();
    let program = format!(
        r#"import selectors, socket, time
with socket.create_connection(('127.0.0.1', {inside_port}), timeout=3) as client:
    client.sendall(b'remapped-forward')
    assert client.recv(64) == b'remapped-forward'
print('forward-ok', flush=True)
for port in ({host_port}, {hidden_port}):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=1):
            raise AssertionError('publication allowed unrelated host loopback: ' + str(port))
    except OSError:
        pass
print('host-loopback-blocked', flush=True)
with selectors.DefaultSelector() as selector:
    published = socket.socket()
    published.bind(('127.0.0.1', {port}))
    published.listen()
    unpublished = socket.socket()
    unpublished.bind(('127.0.0.1', 0))
    unpublished.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', {port}))
    selector.register(published, selectors.EVENT_READ, 'published')
    selector.register(unpublished, selectors.EVENT_READ, 'unpublished')
    selector.register(udp, selectors.EVENT_READ, 'udp')
    print('ready ' + str(unpublished.getsockname()[1]), flush=True)
    deadline, done, received = time.monotonic() + 20, False, 0
    while not done and time.monotonic() < deadline:
        for key, _ in selector.select(timeout=0.1):
            if key.data == 'udp':
                payload, peer = udp.recvfrom(64)
                received += 1
                udp.sendto(payload, peer)
            else:
                with key.fileobj.accept()[0] as client:
                    client.settimeout(1)
                    payload = client.recv(64)
                    assert key.data == 'published', 'unrequested ingress reached sandbox'
                    client.sendall(payload)
                    done = payload == b'stop'
    print('udp-received=' + str(received), flush=True)
    assert done, 'host never stopped publication server'
    assert received == 0, 'TCP publication also forwarded UDP'
"#,
        host_port = forward.port,
        hidden_port = hidden.port,
    );
    drop(publication_udp);
    drop(publication);
    let mut command = isolated_command(dir.path());
    command
        .args(["run", "--proxy-net", "-c"])
        .arg(&config)
        .args([python().unwrap(), "-c", &program]);
    let mut child = PublishingChild::spawn(&mut command, dir.path());
    let unpublished_port = child.wait_for_ready();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match publication_echo(port, b"host-to-sandbox") {
            Ok(()) => break,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "published loopback TCP port was unreachable: {error}; {}",
                    child.diagnostics()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    if let Some(address) = non_loopback_host_address() {
        assert!(
            std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from((address, port)),
                Duration::from_millis(500),
            )
            .is_err(),
            "published TCP port was reachable on non-loopback address {address}"
        );
    } else {
        eprintln!("skipping non-loopback assertion: no active non-loopback IPv4 address");
    }
    assert!(
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], unpublished_port)),
            Duration::from_millis(500),
        )
        .is_err(),
        "an unpublished sandbox TCP listener was reachable from the host"
    );
    let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    udp.send_to(b"udp-must-not-be-published", ("127.0.0.1", port))
        .unwrap();
    let mut buf = [0; 64];
    assert!(udp.recv_from(&mut buf).is_err(), "publication exposed UDP");
    publication_echo(port, b"stop").unwrap();
    assert!(
        child.wait_for_exit().success(),
        "publication target failed: {}",
        child.diagnostics()
    );
    let stdout = fs::read_to_string(&child.stdout).unwrap();
    assert!(stdout.contains("forward-ok\nhost-loopback-blocked\nready "));
    assert!(stdout.contains("udp-received=0"));
    assert_eq!(forward.udp_received.load(Ordering::Relaxed), 0);
    assert_eq!(hidden.udp_received.load(Ordering::Relaxed), 0);
}

#[test]
fn proxy_net_occupied_publication_fails_before_hooks_or_target() {
    if !proxy_net_available() {
        return;
    }
    let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let free = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let free_port = free.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("bailey.toml");
    let hook_marker = dir.path().join("hook-ran");
    let target_marker = dir.path().join("target-ran");
    fs::write(
        &config,
        format!(
            "[network]\negress = \"allow\"\npublish_ports = [{free_port}, {occupied_port}]\n\
             [filesystem]\nwrite = [{directory:?}]\n\
             [hooks]\npre_launch = [\"touch '{hook}'\"]\n",
            directory = dir.path().to_str().unwrap(),
            hook = hook_marker.display(),
        ),
    )
    .unwrap();
    drop(free);
    let mut command = isolated_command(dir.path());
    command
        .args(["run", "--proxy-net", "-c"])
        .arg(&config)
        .args([python().unwrap(), "-c"])
        .arg(format!(
            "from pathlib import Path; Path({:?}).touch()",
            target_marker.to_str().unwrap()
        ));
    let mut child = PublishingChild::spawn(&mut command, dir.path());
    assert!(
        !child.wait_for_exit().success(),
        "an occupied host publication must fail: {}",
        child.diagnostics()
    );
    assert!(
        !hook_marker.exists() && !target_marker.exists(),
        "publication preflight ran a hook or target before rejecting the occupied port: {}",
        child.diagnostics()
    );
    let stderr = fs::read_to_string(&child.stderr).unwrap();
    assert!(
        stderr.contains(&occupied_port.to_string()),
        "rejection must identify the occupied port: {}",
        child.diagnostics()
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match TcpListener::bind(("127.0.0.1", free_port)) {
            Ok(listener) => {
                drop(listener);
                break;
            }
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "failed publication left the free port occupied: {error}; {}",
                    child.diagnostics()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    assert!(
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], free_port)),
            Duration::from_millis(250),
        )
        .is_err(),
        "failed publication left the free port accepting connections"
    );
}
