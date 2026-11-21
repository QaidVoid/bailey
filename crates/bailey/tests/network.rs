//! Integration tests for network confinement.
//!
//! The interesting cases need a program that can open sockets, so these use
//! `python3` and self-skip where it is absent. They also self-skip where user
//! namespaces are unavailable, since the network namespace depends on them.
mod common;

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
        common::skip("needs python3 and user namespaces");
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
        common::skip("needs python3 and user namespaces");
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

/// A policy naming a host that does not resolve is refused before any
/// namespace is built, with the name in the message: a rule that could never
/// match must not read as a restriction the run made.
#[test]
fn an_unresolvable_hostname_refuses_the_run() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    let output = run_python(
        "[network]\negress_allow = [{ host = \"does-not-exist.invalid\", port = 443 }]",
        "print('started')\n",
    );
    assert!(!output.status.success(), "the run must be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does-not-exist.invalid"), "{stderr}");
    assert!(
        !stdout_of(&output).contains("started"),
        "the target must not have started"
    );
}

#[test]
fn loopback_works_inside_the_sandbox() {
    if python().is_none() || !netns_available() {
        common::skip("needs python3 and user namespaces");
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

/// A TCP server the target binds to its own loopback answers inside a
/// private-mode sandbox: the namespace's loopback is the target's own, and
/// nothing in the egress table drops it.
#[test]
fn sandbox_loopback_works_in_private_mode() {
    if python().is_none() || !proxy_net_available() {
        common::skip("needs python3 and pasta");
        return;
    }
    let output = run_python(
        "[network]\negress = \"allow\"\n",
        r#"import socket, threading
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 0))
server.listen(4)
port = server.getsockname()[1]
def serve():
    connection, _ = server.accept()
    connection.sendall(b'loopback-tcp')
    connection.close()
worker = threading.Thread(target=serve)
worker.start()
with socket.create_connection(('127.0.0.1', port), timeout=3) as c:
    assert c.recv(64) == b'loopback-tcp'
worker.join(3)
print('loopback-tcp-ok')
"#,
    );
    assert!(
        output.status.success(),
        "the private-mode run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout_of(&output),
        "loopback-tcp-ok",
        "a loopback-bound server must answer inside the sandbox"
    );
}

#[test]
fn only_loopback_is_visible() {
    if !netns_available() {
        common::skip("user namespaces unavailable");
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
        common::skip("needs python3");
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
        common::skip("needs python3");
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
        common::skip("needs python3");
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
        common::skip("needs python3");
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
        common::skip("needs python3");
        return;
    }
    // The errno table names Landlock's refusals, which exist from ABI 4
    // (Linux 6.7). Below it nothing enforces the port rule, and the table
    // would describe the namespace's routing rather than the policy.
    if !bailey::backend::probe::landlock_abi().is_some_and(|abi| abi >= 4) {
        common::skip("landlock does not enforce port rules before ABI 4");
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
        Self::serve(listener, udp)
    }

    /// The same echo service on the wildcard addresses: a private namespace
    /// reaches it at one of the host's own addresses, which loopback binds
    /// never answer. A dual-stack `::` bind serves v4 dials as well, which
    /// the v6 destination tests lean on; a host without v6 falls back to v4.
    fn start_wildcard() -> Self {
        if let Ok(listener) = TcpListener::bind(("::", 0)) {
            let port = listener.local_addr().unwrap().port();
            let udp = UdpSocket::bind(("::", port)).unwrap();
            return Self::serve(listener, udp);
        }
        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("0.0.0.0", port)).unwrap();
        Self::serve(listener, udp)
    }

    fn serve(listener: TcpListener, udp: UdpSocket) -> Self {
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let udp_received = Arc::new(AtomicUsize::new(0));
        let workers = vec![
            tcp_worker(listener, Arc::clone(&stop)),
            udp_worker(udp, Arc::clone(&stop), Arc::clone(&udp_received)),
        ];
        Self {
            port,
            stop,
            udp_received,
            workers,
        }
    }
}

fn tcp_worker(listener: TcpListener, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
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
    })
}

fn udp_worker(
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    received: Arc<AtomicUsize>,
) -> JoinHandle<()> {
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    std::thread::spawn(move || {
        let mut buf = [0; 64];
        while !stop.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    received.fetch_add(1, Ordering::Relaxed);
                    let _ = socket.send_to(&buf[..n], peer);
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(err) => panic!("host UDP listener failed: {err}"),
            }
        }
    })
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
        common::skip("needs python3 and user namespaces");
        return false;
    }
    for helper in ["pasta", "nft"] {
        if let Err(err) = bailey::cli::resolve_helper(helper) {
            common::skip(&format!("needs trusted {helper}: {err}"));
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
        common::skip("needs python3 and user namespaces");
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
        common::skip("no non-loopback host address");
        return;
    };
    // A QEMU guest on user networking sits at 10.0.2.15, the very address
    // bailey's private namespace is given (cli's PROXY_ADDRESS_V4), so there
    // sandbox and host report the same address and the assertion below says
    // nothing about the namespace.
    if host_address.to_string() == "10.0.2.15" {
        common::skip("the host's address is the sandbox's own (QEMU slirp)");
        return;
    }
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
        common::skip("needs user namespaces");
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
        common::skip("needs user namespaces");
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

/// A loopback port that is free on the host, for a listener the target
/// opens inside its own namespace.
fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The host's global-scope IPv6 address, found the way bailey itself looks:
/// `/proc/net/if_inet6`, scope `00`, any device but `lo`.
fn non_loopback_host_v6() -> Option<std::net::Ipv6Addr> {
    let contents = fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        let (hex, scope, device) = (fields[0], fields[3], fields[5]);
        if scope == "00"
            && device != "lo"
            && let Some(address) = parse_ipv6_hex(hex)
            && !address.is_loopback()
        {
            return Some(address);
        }
    }
    None
}

/// `/proc/net/if_inet6` writes addresses as 32 hex digits without colons.
fn parse_ipv6_hex(hex: &str) -> Option<std::net::Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let high = u64::from_str_radix(&hex[..16], 16).ok()?;
    let low = u64::from_str_radix(&hex[16..], 16).ok()?;
    Some(std::net::Ipv6Addr::new(
        (high >> 48) as u16,
        (high >> 32) as u16,
        (high >> 16) as u16,
        high as u16,
        (low >> 48) as u16,
        (low >> 32) as u16,
        (low >> 16) as u16,
        low as u16,
    ))
}

/// A name in an allow rule is pinned before the run: with DNS denied, the
/// generated /etc/hosts still answers the name, and the target reaches its
/// own loopback listener through the pinned address.
#[test]
fn pinned_name_resolves_without_dns() {
    if !proxy_net_available() {
        return;
    }
    let port = free_loopback_port();
    let output = run_python(
        &format!(
            "[network]\n\
             egress_allow = [{{ host = \"localhost\", port = {port} }}]\n\
             bind_ports = [{port}]\n\
             dns = \"deny\"\n"
        ),
        &format!(
            r#"import socket
found = sorted(set([info[4][0] for info in socket.getaddrinfo('localhost', {port}, socket.AF_INET)]))
assert found == ['127.0.0.1'], found
server = socket.socket()
server.bind(('127.0.0.1', {port}))
server.listen(1)
with socket.create_connection(('localhost', {port}), timeout=5) as client:
    client.sendall(b'pin')
    conn, _ = server.accept()
    conn.sendall(conn.recv(64))
    conn.close()
server.close()
print('pinned-ok')
"#
        ),
    );
    assert!(
        output.status.success(),
        "the pinned-name run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "pinned-ok");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("network mode: private ("),
        "a named destination must pick the private namespace: {stderr}"
    );
}

/// A named destination carries TCP and UDP to the allowed host only: the
/// same port on another host is dropped inside the namespace, never
/// reaching the wire.
#[test]
fn an_allowed_destination_is_reached_and_other_hosts_dropped() {
    if !proxy_net_available() {
        return;
    }
    let Some(host) = non_loopback_host_address() else {
        common::skip("no non-loopback host address");
        return;
    };
    if host.to_string() == "10.0.2.15" {
        common::skip("the host's address is the sandbox's own (QEMU slirp)");
        return;
    }
    let echo = EchoServer::start_wildcard();
    let output = run_python(
        &format!(
            "[network]\n\
             egress_allow = [\n\
             \x20 {{ host = \"{host}\", port = {port} }},\n\
             \x20 {{ host = \"{host}\", port = {port}, protocol = \"udp\" }},\n\
             ]\n",
            host = host,
            port = echo.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('{host}', {port}), timeout=3) as s:
    s.sendall(b'tcp-dest')
    assert s.recv(64) == b'tcp-dest'
print('allowed-tcp-ok')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(3)
    s.sendto(b'udp-dest', ('{host}', {port}))
    assert s.recvfrom(64)[0] == b'udp-dest'
print('allowed-udp-ok')
try:
    with socket.create_connection(('203.0.113.9', {port}), timeout=2):
        print('reached-other')
except OSError:
    print('other-dropped')
"#,
            host = host,
            port = echo.port
        ),
    );
    assert!(
        output.status.success(),
        "the destination run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout_of(&output),
        "allowed-tcp-ok\nallowed-udp-ok\nother-dropped"
    );
}

/// An allow-all policy carries egress, with a deny still winning: the
/// namespace's table admits everything the deny, DNS and loopback rules do
/// not name, so `egress = "allow"` is usable on its own and a denied
/// address still drops, TCP and UDP alike.
#[test]
fn allow_all_with_a_deny_carries_egress_and_holds_the_deny() {
    if !proxy_net_available() {
        return;
    }
    let Some(host) = non_loopback_host_address() else {
        common::skip("no non-loopback host address");
        return;
    };
    if host.to_string() == "10.0.2.15" {
        common::skip("the host's address is the sandbox's own (QEMU slirp)");
        return;
    }
    let echo = EchoServer::start_wildcard();
    let output = run_python(
        &format!(
            "[network]\n\
             egress = \"allow\"\n\
             egress_deny = [{{ host = \"203.0.113.0/24\", port = {port} }}]\n",
            port = echo.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('{host}', {port}), timeout=3) as s:
    s.sendall(b'allow-all')
    assert s.recv(64) == b'allow-all'
print('tcp-ok')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(3)
    s.sendto(b'allow-all', ('{host}', {port}))
    assert s.recvfrom(64)[0] == b'allow-all'
print('udp-ok')
try:
    with socket.create_connection(('203.0.113.9', {port}), timeout=2):
        print('tcp-denied-reached')
except OSError:
    print('tcp-denied-dropped')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(2)
    try:
        s.sendto(b'x', ('203.0.113.9', {port}))
    except OSError:
        print('udp-denied-dropped')
        raise SystemExit(0)
    try:
        s.recvfrom(64)
        print('udp-denied-replied')
    except OSError:
        print('udp-denied-dropped')
"#,
            host = host,
            port = echo.port
        ),
    );
    assert!(
        output.status.success(),
        "the allow-all run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout_of(&output),
        "tcp-ok\nudp-ok\ntcp-denied-dropped\nudp-denied-dropped"
    );
}

/// An allow naming a block carries every address inside it that routes: a
/// /24 and a /64 whose only reachable members are this host's own
/// addresses both answer, and an address outside both blocks drops. This
/// is the CIDR form of the destination contract.
#[test]
fn a_cidr_allow_carries_the_block_it_names() {
    if !proxy_net_available() {
        return;
    }
    let Some(v4) = non_loopback_host_address() else {
        common::skip("no non-loopback host address");
        return;
    };
    if v4.to_string() == "10.0.2.15" {
        common::skip("the host's address is the sandbox's own (QEMU slirp)");
        return;
    }
    let Some(v6) = non_loopback_host_v6() else {
        common::skip("no global IPv6 address for the v6 block");
        return;
    };
    let echo = EchoServer::start_wildcard();
    let output = run_python(
        &format!(
            "[network]\n\
             egress_allow = [\n\
             \x20 {{ host = \"{v4}/24\", port = {port} }},\n\
             \x20 {{ host = \"{v6}/64\", port = {port} }},\n\
             ]\n",
            v4 = v4,
            v6 = v6,
            port = echo.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('{v4}', {port}), timeout=3) as s:
    s.sendall(b'cidr-v4')
    assert s.recv(64) == b'cidr-v4'
print('cidr-v4-ok')
with socket.create_connection(('{v6}', {port}), timeout=3) as s:
    s.sendall(b'cidr-v6')
    assert s.recv(64) == b'cidr-v6'
print('cidr-v6-ok')
try:
    with socket.create_connection(('203.0.113.9', {port}), timeout=2):
        print('outside-reached')
except OSError:
    print('outside-dropped')
"#,
            v4 = v4,
            v6 = v6,
            port = echo.port
        ),
    );
    assert!(
        output.status.success(),
        "the CIDR run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout_of(&output),
        "cidr-v4-ok\ncidr-v6-ok\noutside-dropped"
    );
}

/// An address the rules do not name drops even when it is another real
/// address of this very host, at the same port the allowance carries: the
/// drop cannot be confused with an unreachable address, because the same
/// port on the allowed address answers, TCP and UDP alike.
#[test]
fn another_real_host_on_the_same_port_drops() {
    if !proxy_net_available() {
        return;
    }
    let Some(v4) = non_loopback_host_address() else {
        common::skip("no non-loopback host address");
        return;
    };
    if v4.to_string() == "10.0.2.15" {
        common::skip("the host's address is the sandbox's own (QEMU slirp)");
        return;
    }
    let Some(v6) = non_loopback_host_v6() else {
        common::skip("no global IPv6 address to play the other host");
        return;
    };
    let echo = EchoServer::start_wildcard();
    let output = run_python(
        &format!(
            "[network]\n\
             egress_allow = [\n\
             \x20 {{ host = \"{v4}\", port = {port} }},\n\
             \x20 {{ host = \"{v4}\", port = {port}, protocol = \"udp\" }},\n\
             ]\n",
            v4 = v4,
            port = echo.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('{v4}', {port}), timeout=3) as s:
    s.sendall(b'allowed-v4')
    assert s.recv(64) == b'allowed-v4'
print('allowed-tcp-ok')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(3)
    s.sendto(b'allowed-udp', ('{v4}', {port}))
    assert s.recvfrom(64)[0] == b'allowed-udp'
print('allowed-udp-ok')
try:
    with socket.create_connection(('{v6}', {port}), timeout=2):
        print('other-tcp-reached')
except OSError:
    print('other-tcp-dropped')
with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
    s.settimeout(2)
    try:
        s.sendto(b'other-udp', ('{v6}', {port}))
    except OSError:
        print('other-udp-dropped')
        raise SystemExit(0)
    try:
        s.recvfrom(64)
        print('other-udp-replied')
    except OSError:
        print('other-udp-dropped')
"#,
            v4 = v4,
            v6 = v6,
            port = echo.port
        ),
    );
    assert!(
        output.status.success(),
        "the single-destination run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout_of(&output),
        "allowed-tcp-ok\n\
         allowed-udp-ok\n\
         other-tcp-dropped\n\
         other-udp-dropped"
    );
}

/// With a wildcard rule the resolver may ask: pasta's forwarder answers UDP
/// DNS, so names resolve without any other network being open.
#[test]
fn dns_only_reaches_the_forwarder() {
    if !proxy_net_available() {
        return;
    }
    let output = run_python(
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\n",
        r#"import socket
socket.gethostbyname('example.com')
print('dns-ok')
"#,
    );
    assert!(
        output.status.success(),
        "the resolver must be reached through pasta: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "dns-ok");
}

/// The forwarder answers DNS over TCP as well, which a truncated or large
/// answer drives the resolver to: the netfilter allowance must carry it.
#[test]
fn dns_over_tcp_reaches_the_forwarder() {
    if !proxy_net_available() {
        return;
    }
    let output = run_python(
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\n",
        r#"import socket, struct
question = (b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x07example\x03com\x00\x00\x01\x00\x01')
with socket.create_connection(('10.0.2.3', 53), timeout=5) as s:
    s.sendall(struct.pack('!H', len(question)) + question)
    header = s.recv(2)
    assert len(header) == 2, header
    remaining = struct.unpack('!H', header)[0]
    answer = b''
    while len(answer) < remaining:
        answer += s.recv(remaining - len(answer))
assert answer[3] & 0xF == 0, 'rcode ' + str(answer[3] & 0xF)
print('dns-tcp-ok')
"#,
    );
    assert!(
        output.status.success(),
        "DNS over TCP must reach the forwarder: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "dns-tcp-ok");
}

/// Without a wildcard rule the resolver is configured but unreachable: UDP
/// and TCP DNS questions are dropped, so name lookup fails instead of
/// leaking a query to the host's network.
#[test]
fn dns_dropped_without_a_wildcard_rule() {
    if !proxy_net_available() {
        return;
    }
    let Some(host) = non_loopback_host_address() else {
        common::skip("no non-loopback host address");
        return;
    };
    if host.to_string() == "10.0.2.15" {
        common::skip("the host's address is the sandbox's own (QEMU slirp)");
        return;
    }
    let echo = EchoServer::start_wildcard();
    let output = run_python(
        &format!(
            "[network]\negress_allow = [{{ host = \"{host}\", port = {port} }}]\n",
            host = host,
            port = echo.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('{host}', {port}), timeout=3) as s:
    print('tcp-ok')
try:
    socket.gethostbyname('example.com')
    print('dns-leaked')
except OSError:
    print('dns-dropped')
try:
    socket.create_connection(('10.0.2.3', 53), timeout=5)
    print('tcp-dns-leaked')
except OSError:
    print('tcp-dns-dropped')
"#,
            host = host,
            port = echo.port
        ),
    );
    assert!(
        output.status.success(),
        "the named-destination run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "tcp-ok\ndns-dropped\ntcp-dns-dropped");
}

/// A deny inside an allowed range wins over the range, per family: the
/// allowed block still carries a sibling address and port beside the denied
/// one, and the denied address and port drops, TCP and UDP alike. The allow
/// and the deny name the same family here, so the range itself is what is
/// under test.
#[test]
fn deny_inside_an_allowed_range() {
    if !proxy_net_available() {
        return;
    }
    let Some(v4) = non_loopback_host_address() else {
        common::skip("no non-loopback host address");
        return;
    };
    if v4.to_string() == "10.0.2.15" {
        common::skip("the host's address is the sandbox's own (QEMU slirp)");
        return;
    }
    let Some(v6) = non_loopback_host_v6() else {
        common::skip("no global IPv6 address to allow beside the denied one");
        return;
    };
    let carried = EchoServer::start_wildcard();
    let denied = EchoServer::start_wildcard();
    let output = run_python(
        &format!(
            "[network]\n\
             egress_allow = [\n\
             \x20 {{ host = \"{v4}/24\", port = {carried} }},\n\
             \x20 {{ host = \"{v4}/24\", port = {denied} }},\n\
             \x20 {{ host = \"{v6}/64\", port = {carried} }},\n\
             \x20 {{ host = \"{v6}/64\", port = {denied} }},\n\
             ]\n\
             egress_deny = [\n\
             \x20 {{ host = \"{v4}\", port = {denied} }},\n\
             \x20 {{ host = \"{v6}\", port = {denied} }},\n\
             ]\n",
            v4 = v4,
            v6 = v6,
            carried = carried.port,
            denied = denied.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('{v4}', {carried}), timeout=3) as s:
    s.sendall(b'carried-v4')
    assert s.recv(64) == b'carried-v4'
print('carried-v4-ok')
with socket.create_connection(('{v6}', {carried}), timeout=3) as s:
    s.sendall(b'carried-v6')
    assert s.recv(64) == b'carried-v6'
print('carried-v6-ok')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(3)
    s.sendto(b'carried-udp', ('{v4}', {carried}))
    assert s.recvfrom(64)[0] == b'carried-udp'
print('carried-udp-ok')
try:
    with socket.create_connection(('{v4}', {denied}), timeout=2):
        print('deny-bypassed')
except OSError:
    print('denied-v4-dropped')
try:
    with socket.create_connection(('{v6}', {denied}), timeout=2):
        print('deny-bypassed')
except OSError:
    print('denied-v6-dropped')
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(2)
    try:
        s.sendto(b'denied-udp', ('{v4}', {denied}))
    except OSError:
        print('denied-udp-dropped')
        raise SystemExit(0)
    try:
        s.recvfrom(64)
        print('deny-bypassed')
    except OSError:
        print('denied-udp-dropped')
"#,
            v4 = v4,
            v6 = v6,
            carried = carried.port,
            denied = denied.port
        ),
    );
    assert!(
        output.status.success(),
        "the deny run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        stdout_of(&output),
        "carried-v4-ok\n\
         carried-v6-ok\n\
         carried-udp-ok\n\
         denied-v4-dropped\n\
         denied-v6-dropped\n\
         denied-udp-dropped"
    );
}

/// A private namespace that cannot install the egress rules must refuse the
/// run before the target starts: the rules are the boundary, and starting
/// without them would run wider than the policy.
#[test]
fn a_failing_nft_refuses_the_run_before_the_target_starts() {
    if python().is_none() || !netns_available() {
        common::skip("needs python3 and user namespaces");
        return;
    }
    let Ok(pasta) = bailey::cli::resolve_helper("pasta") else {
        common::skip("needs trusted pasta");
        return;
    };
    let helpers = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(&pasta, helpers.path().join("pasta")).unwrap();
    let nft = helpers.path().join("nft");
    fs::write(&nft, "#!/bin/sh\nexit 1\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&nft, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let output = run_with_env(
        "[network]\negress_allow = [{ host = \"*\", port = 443 }]\n",
        &[],
        &[("BAILEY_HELPER_DIRS", helpers.path())],
        &[python().unwrap(), "-c", "print('started')"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a failing nft must refuse the run: {stderr}"
    );
    assert!(
        stderr.contains("the egress rules could not be installed"),
        "the refusal must name the failed installation: {stderr}"
    );
    assert_ne!(stdout_of(&output), "started", "the target must never start");
}

/// A broker supersedes destination rules: the run still starts, held to the
/// broker alone, and the summary names the supersession so the policy's
/// narrower rules are not mistaken for the enforcement in place.
#[test]
fn a_brokered_run_names_destination_rules_superseded() {
    if !proxy_net_available() {
        return;
    }
    let broker = EchoServer::start();
    let outside = EchoServer::start();
    let output = run_python(
        &format!(
            "[network]\nbroker = \"10.0.0.1:{broker}\"\n\
             egress_allow = [{{ host = \"localhost\", port = 443 }}]\n",
            broker = broker.port
        ),
        &format!(
            r#"import socket
with socket.create_connection(('10.0.0.1', {broker}), timeout=3) as s:
    s.sendall(b'to-broker')
    assert s.recv(64) == b'to-broker'
print('broker-ok')
try:
    socket.create_connection(('10.0.0.1', {outside}), timeout=2)
    print('reached-outside')
except OSError:
    print('outside-dropped')
"#,
            broker = broker.port,
            outside = outside.port
        ),
    );
    assert!(
        output.status.success(),
        "the brokered run must start despite destination rules: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), "broker-ok\noutside-dropped");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("network mode: brokered"),
        "the summary must name the brokered mode: {stderr}"
    );
    assert!(
        stderr.contains("superseded by the broker"),
        "the summary must say the destination rules are superseded: {stderr}"
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
        let pid = self.child.id();
        let _ = self.child.kill();
        let _ = self.child.wait();
        common::remove_staging_for(pid);
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

/// A connect the sandbox never asked for can still succeed against an
/// unrelated host listener that happened to draw the same ephemeral port
/// number. Only an accept inside the sandbox proves a real forward, and the
/// child reports that itself by failing on unrequested ingress; probe the
/// port and let the child's fate classify the connection.
fn probe_reaches_sandbox(child: &mut PublishingChild, address: std::net::SocketAddr) -> bool {
    let mut probe = match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500))
    {
        Ok(probe) => probe,
        Err(_) => return false,
    };
    let _ = probe.write_all(b"unrequested-probe");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if child.child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
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
            !probe_reaches_sandbox(&mut child, std::net::SocketAddr::from((address, port))),
            "published TCP port was reachable on non-loopback address {address}: {}",
            child.diagnostics()
        );
    } else {
        common::skip("non-loopback assertion: no active non-loopback IPv4 address");
    }
    assert!(
        !probe_reaches_sandbox(
            &mut child,
            std::net::SocketAddr::from(([127, 0, 0, 1], unpublished_port)),
        ),
        "an unpublished sandbox TCP listener was reachable from the host \
         (port {unpublished_port} answered): {}",
        child.diagnostics()
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

/// The host process that listens on the pathname socket a connect test aims
/// at. It must live outside the run: a socket the target's own domain created
/// is reachable by construction, so the listener proves the grant is what
/// opened the door.
fn spawn_listener(socket: &Path) -> std::process::Child {
    use std::io::{BufRead, BufReader};
    let program = format!(
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
    );
    let mut child = Command::new(python().unwrap())
        .arg("-c")
        .arg(&program)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("the listener must announce itself");
    assert_eq!(line.trim(), "ready", "the listener must be ready");
    child
}

/// The socket connect right arrived in Landlock ABI 9; below it the kernel
/// enforces no pathname socket restriction and the policy cannot hold.
fn connect_enforced() -> bool {
    bailey::backend::probe::landlock_abi().is_some_and(|abi| abi >= 9)
}

#[test]
fn an_unlisted_socket_in_a_writable_grant_is_refused() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    if !connect_enforced() {
        common::skip("socket connect control needs Landlock ABI 9");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("srv.sock");
    let mut listener = spawn_listener(&socket);
    let program = format!(
        "import socket\n\
         try:\n\
         \x20   c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   c.connect('{path}')\n\
         \x20   print(c.recv(4))\n\
         except OSError:\n\
         \x20   print('refused')\n",
        path = socket.display()
    );
    let output = run_python(
        &format!("[filesystem]\nwrite = [\"{}\"]\n", dir.path().display()),
        &program,
    );
    listener.kill().unwrap();
    listener.wait().unwrap();
    assert_eq!(
        stdout_of(&output),
        "refused",
        "write on the directory must not read as the right to connect to the socket in it"
    );
}

#[test]
fn a_listed_socket_connects() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    if !connect_enforced() {
        common::skip("socket connect control needs Landlock ABI 9");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("srv.sock");
    let mut listener = spawn_listener(&socket);
    let program = format!(
        "import socket\n\
         try:\n\
         \x20   c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   c.connect('{path}')\n\
         \x20   print(c.recv(4))\n\
         except OSError:\n\
         \x20   print('refused')\n",
        path = socket.display()
    );
    let output = run_python(
        &format!(
            "[filesystem]\nwrite = [\"{dir}\"]\nconnect = [\"{sock}\"]\n",
            dir = dir.path().display(),
            sock = socket.display()
        ),
        &program,
    );
    listener.kill().unwrap();
    listener.wait().unwrap();
    assert_eq!(
        stdout_of(&output),
        "b'pong'",
        "a listed socket must be connectable through the grant"
    );
}

#[test]
fn an_unlisted_socket_is_refused_without_isolation_too() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    if !connect_enforced() {
        common::skip("socket connect control needs Landlock ABI 9");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("srv.sock");
    let mut listener = spawn_listener(&socket);
    let program = format!(
        "import socket\n\
         try:\n\
         \x20   c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   c.connect('{path}')\n\
         \x20   print('connected')\n\
         except OSError:\n\
         \x20   print('refused')\n",
        path = socket.display()
    );
    let output = run_python_with_args(
        &format!("[filesystem]\nwrite = [\"{}\"]\n", dir.path().display()),
        &program,
        &["--no-isolate"],
    );
    listener.kill().unwrap();
    listener.wait().unwrap();
    assert_eq!(
        stdout_of(&output),
        "refused",
        "the connect list must hold with Landlock alone, no namespaces needed"
    );
}

#[test]
fn a_datagram_to_an_unlisted_socket_is_refused() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    if !connect_enforced() {
        common::skip("socket connect control needs Landlock ABI 9");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("srv.sock");
    let mut listener = spawn_listener(&socket);
    let program = format!(
        "import socket\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
         try:\n\
         \x20   s.sendto(b'x', '{path}')\n\
         \x20   print('sent')\n\
         except OSError:\n\
         \x20   print('refused')\n",
        path = socket.display()
    );
    let output = run_python(
        &format!("[filesystem]\nwrite = [\"{}\"]\n", dir.path().display()),
        &program,
    );
    listener.kill().unwrap();
    listener.wait().unwrap();
    assert_eq!(
        stdout_of(&output),
        "refused",
        "an explicit-recipient datagram is a connect, and must obey the connect list"
    );
}

#[test]
fn a_socket_reached_through_proc_self_root_is_still_refused() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    if !connect_enforced() {
        common::skip("socket connect control needs Landlock ABI 9");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("srv.sock");
    let mut listener = spawn_listener(&socket);
    // A read grant on `/proc/self/root` covers the whole visible hierarchy,
    // because that is what the path resolves to. If the connect right were
    // folded into read, this would connect.
    let program = format!(
        "import socket\n\
         try:\n\
         \x20   c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         \x20   c.connect('{path}')\n\
         \x20   print('connected')\n\
         except OSError:\n\
         \x20   print('refused')\n",
        path = socket.display()
    );
    let output = run_python_with_args(
        "[filesystem]\nread = [\"/proc/self/root\"]\n",
        &program,
        &["--no-isolate"],
    );
    listener.kill().unwrap();
    listener.wait().unwrap();
    assert_eq!(
        stdout_of(&output),
        "refused",
        "read on the hierarchy must not grant connecting to the socket in it"
    );
}

/// A server the target starts itself stays reachable from its own children:
/// the kernel exempts sockets created inside the Landlock domain, which is
/// what keeps a compositor able to reach the helpers it started.
#[test]
fn a_server_the_target_starts_is_reachable_from_its_child() {
    if python().is_none() || !netns_available() {
        common::skip("needs python3 and user namespaces");
        return;
    }
    if !connect_enforced() {
        common::skip("socket connect control needs Landlock ABI 9");
        return;
    }
    let program = "import os, socket, subprocess, sys\n\
         if os.path.exists('/tmp/srv-test.sock'):\n\
         \x20   os.unlink('/tmp/srv-test.sock')\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         s.bind('/tmp/srv-test.sock')\n\
         s.listen(1)\n\
         code = \"import socket\\nc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\\nc.connect('/tmp/srv-test.sock')\\nc.sendall(b'ok')\\n\"\n\
         r = subprocess.run([sys.executable, '-c', code], capture_output=True)\n\
         if r.returncode != 0:\n\
         \x20   print(r.stderr.decode().strip())\n\
         else:\n\
         \x20   conn, _ = s.accept()\n\
         \x20   print(conn.recv(2).decode())\n";
    let output = run_python("[filesystem]\nwrite = [\"/tmp\"]\n", program);
    assert_eq!(
        stdout_of(&output),
        "ok",
        "a socket the target's own domain created must stay connectable inside it"
    );
}

/// `socketpair` has no pathname, so the connect list has nothing to say
/// about it.
#[test]
fn a_socketpair_works() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    let output = run_python(
        "",
        "import socket\n\
         a, b = socket.socketpair()\n\
         b.sendall(b'hi')\n\
         print(a.recv(2))\n",
    );
    assert_eq!(stdout_of(&output), "b'hi'", "socketpair must be untouched");
}

/// The listeners a matrix run holds, so every profile sees the same sockets.
/// Killed whenever the guard drops, panic or not.
struct Listeners(Vec<std::process::Child>);

impl Drop for Listeners {
    fn drop(&mut self) {
        for mut child in self.0.drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The bundled profiles against a fake session: which of the runtime
/// directory's sockets each profile may connect to is the contract, recorded
/// here so a profile edit that widens it fails loudly. `bus`, `pipewire-0-manager`
/// and `ssh-agent.socket` are the sockets the profiles deliberately leave out.
#[test]
fn the_bundled_profiles_connect_exactly_to_their_listed_sockets() {
    if python().is_none() {
        common::skip("needs python3");
        return;
    }
    if !connect_enforced() {
        common::skip("the contract needs Landlock ABI 9 to observe");
        return;
    }
    let sockets = [
        "wayland-1",
        "pulse/native",
        "pipewire-0",
        "pipewire-0-manager",
        "bus",
        "ssh-agent.socket",
    ];
    let runtime = tempfile::tempdir().unwrap();
    let mut listeners = Listeners(Vec::new());
    for socket in sockets {
        let path = runtime.path().join(socket);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        listeners.0.push(spawn_listener(&path));
    }

    // What each profile may connect to, as the profile's connect list says.
    // Everything else in the fake runtime directory must be refused, in a
    // private namespace and with Landlock alone.
    let matrix: [(&str, &[&str]); 5] = [
        ("untrusted", &[]),
        ("network-client", &[]),
        ("ai-agent", &[]),
        ("desktop-app", &["wayland-1", "pulse/native", "pipewire-0"]),
        ("native-game", &["wayland-1", "pulse/native", "pipewire-0"]),
    ];

    for (profile, allowed) in matrix {
        for isolate in [true, false] {
            let probe = sockets
                .iter()
                .map(|socket| format!("probe('{socket}')\n"))
                .collect::<String>();
            let program = format!(
                "import socket\n\
                 def probe(name):\n\
                 \x20   try:\n\
                 \x20       c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
                 \x20       c.connect('{rt}/' + name)\n\
                 \x20       if c.recv(4) == b'pong':\n\
                 \x20           print(name, 'ok')\n\
                 \x20       else:\n\
                 \x20           print(name, 'no')\n\
                 \x20   except OSError:\n\
                 \x20       print(name, 'no')\n\
                 {probe}",
                rt = runtime.path().display()
            );
            let mut command = isolated_command(runtime.path());
            command.env("XDG_RUNTIME_DIR", runtime.path());
            command.arg("run").arg("--profile").arg(profile);
            if !isolate {
                command.arg("--no-isolate");
            }
            let output = command
                .args([python().unwrap(), "-c", &program])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{profile} (isolate: {isolate}) must run its probe: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let seen = stdout_of(&output);
            for socket in sockets {
                let expected = if allowed.contains(&socket) {
                    "ok"
                } else {
                    "no"
                };
                assert!(
                    seen.contains(&format!("{socket} {expected}")),
                    "{profile} (isolate: {isolate}) must connect to `{socket}` only when its \
                     connect list names it: {seen}"
                );
            }
        }
    }
}

/// A broker stub that speaks the wire protocol and counts what it accepts.
///
/// The real broker's CONNECT server is 3.5; what 3.2 needs is a process on
/// the other end of the handed-off listener, so this stub answers the ready
/// line the protocol defines and appends one line per accepted connection to
/// a file the test reads afterwards.
const STUB_BROKER: &str = r#"#!/usr/bin/python3
import json, os, socket, sys
config = sys.stdin.buffer.read()
sys.stdout.write(json.dumps({
    "version": 1, "ca_pem": None,
    "layers": {"seccomp": False, "landlock": False, "landlock_network": False},
}) + "\n")
sys.stdout.flush()
listener = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        conn, peer = listener.accept()
    except OSError:
        break
    with open(os.environ["BAILEY_STUB_REPORT"], "ab") as report:
        report.write(f"accepted {peer[0]}:{peer[1]}\n".encode())
    conn.close()
"#;

/// A builtin run aims every proxy variable at the handed-off listener, which
/// only the broker serves, while the namespace has no route to anything
/// else: not to the internet, and not to the host's loopback.
#[test]
fn builtin_broker_reaches_the_broker_and_nothing_else() {
    if python().is_none() || !netns_available() {
        common::skip("needs python3 and user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let helpers = dir.path().join("helpers");
    fs::create_dir(&helpers).unwrap();
    let stub = helpers.join("bailey-broker");
    fs::write(&stub, STUB_BROKER).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

    let report = dir.path().join("accepted.log");
    let host_service = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let host_port = host_service.local_addr().unwrap().port();
    // The host service must be serving while the target dials it.
    std::thread::spawn(move || {
        for stream in host_service.incoming() {
            drop(stream);
        }
    });

    let program = format!(
        r#"
import os, socket, sys
from urllib.parse import urlparse

proxy = urlparse(os.environ["HTTPS_PROXY"])
assert proxy.hostname == "127.0.0.1", proxy
port = proxy.port

# The broker's listener answers, whatever is sent to it.
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
s.close()
print("broker-reached")

# No route in the namespace, so the internet fails at once.
try:
    socket.create_connection(("1.1.1.1", 80), timeout=5)
    print("internet-REACHED")
except OSError as err:
    print("internet-refused", err.errno)

# The host's loopback is another namespace's loopback.
try:
    socket.create_connection(("127.0.0.1", {host_port}), timeout=5)
    print("host-loopback-REACHED")
except OSError as err:
    print("host-loopback-refused", err.errno)
"#,
        host_port = host_port
    );

    let config = "[network]\negress_allow = [{ host = \"*\", port = 443 }]\nbroker = \"builtin\"\n";
    let config_path = dir.path().join("bailey.toml");
    fs::write(&config_path, config).unwrap();

    let output = isolated_command(dir.path())
        .env("BAILEY_HELPER_DIRS", &helpers)
        .env("BAILEY_STUB_REPORT", &report)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .args([python().unwrap(), "-c", &program])
        .output()
        .unwrap();
    let stdout = stdout_of(&output);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "the run must succeed: {stderr}");
    assert!(stdout.contains("broker-reached"), "{stdout}");
    assert!(
        stdout.contains("internet-refused") && !stdout.contains("internet-REACHED"),
        "{stdout}"
    );
    assert!(
        stdout.contains("host-loopback-refused") && !stdout.contains("host-loopback-REACHED"),
        "{stdout}"
    );
    // Exactly one connection reached the stub: the one the target made.
    let accepted = fs::read_to_string(&report).unwrap_or_default();
    assert_eq!(accepted.lines().count(), 1, "{accepted}");
}

/// A stub broker whose answer is written by the test: a good ready line, a
/// bad version, garbage, or nothing at all.
fn stub_broker_with_answer(answer: &str) -> String {
    format!(
        r#"#!/usr/bin/env python3
import os, sys
listener = os.environ.get("BAILEY_STUB_REPORT")
if listener:
    with open(listener, "ab") as report:
        report.write(b"started\n")
config = sys.stdin.buffer.read()
answer = {answer:?}
if answer:
    sys.stdout.buffer.write(answer)
    sys.stdout.buffer.flush()
"#,
        answer = answer
    )
}

/// A helper's refusal must fail the run before the target starts: the
/// namespace is never given a route, so nothing the target would have done
/// can happen. Each way a helper can be wrong is refused here.
#[test]
fn a_failing_builtin_helper_refuses_the_run_before_the_target_starts() {
    if python().is_none() || !netns_available() {
        common::skip("needs python3 and user namespaces");
        return;
    }
    let good_ready = r#"{"version":1,"ca_pem":null,"layers":{"seccomp":false,"landlock":false,"landlock_network":false}}"#;
    let wrong_version = good_ready.replace("\"version\":1", "\"version\":999");
    let cases: [(&str, Option<&str>, bool); 4] = [
        // (name, the helper's stdout answer, whether a helper exists at all)
        ("a missing helper", None, false),
        (
            "a wrong protocol version",
            Some(wrong_version.as_str()),
            true,
        ),
        ("a helper that exits before answering", None, true),
        (
            "an answer that is not a ready line",
            Some("garbage\n"),
            true,
        ),
    ];
    for (name, answer, helper_exists) in cases {
        let dir = tempfile::tempdir().unwrap();
        let helpers = dir.path().join("helpers");
        fs::create_dir(&helpers).unwrap();
        if helper_exists {
            let stub = helpers.join("bailey-broker");
            let script = match answer {
                Some(answer) => stub_broker_with_answer(&format!("{answer}\n")),
                None => stub_broker_with_answer(""),
            };
            fs::write(&stub, script).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let started = dir.path().join("target-started");
        let program = format!(
            r#"
with open({started:?}, "w") as marker:
    marker.write("started")
"#,
            started = started
        );
        let config =
            "[network]\negress_allow = [{ host = \"*\", port = 443 }]\nbroker = \"builtin\"\n";
        let config_path = dir.path().join("bailey.toml");
        fs::write(&config_path, config).unwrap();

        let output = isolated_command(dir.path())
            .env("BAILEY_HELPER_DIRS", &helpers)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .args([python().unwrap(), "-c", &program])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(
            !output.status.success(),
            "{name} must refuse the run: {stderr}"
        );
        assert!(!started.exists(), "{name}: the target must never start");
    }
}
