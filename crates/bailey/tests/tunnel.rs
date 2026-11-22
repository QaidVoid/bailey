//! Integration tests for the broker's CONNECT tunnel.
//!
//! These spawn `bailey-broker` with a listener of the test's own as
//! descriptor 3, and speak the proxy protocol to it directly, which is what
//! a target's client does through the handed-off listener. An upstream stub
//! counts what it accepts, so a tunnel that was refused but dialled anyway
//! shows up as a count; the one allowed tunnel echoes through it. Two tests
//! go further with the broker's name service: one runs the broker beside a
//! counting resolver stub inside its own namespaces, and one serves real
//! curl through a broker whose hosts file maps the allowed name to a local
//! TLS server. Both self-skip where user namespaces are unavailable.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn broker() -> std::path::PathBuf {
    let path = std::env::var("CARGO_BIN_EXE_bailey-broker")
        .map(Into::into)
        .unwrap_or_else(|_| {
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

/// An HTTP rule in the JSON the broker's configuration carries.
fn name_rule(host: &str) -> String {
    format!(r#"{{"host": {{"Exact": "{host}"}}, "port": null, "methods": [], "path": null}}"#)
}

/// The same, bounded to a path prefix.
fn name_rule_on_path(host: &str, prefix: &str) -> String {
    format!(
        r#"{{"host": {{"Exact": "{host}"}}, "port": null, "methods": [], "path": {{"Prefix": "{prefix}"}}}}"#
    )
}

/// The same, bounded to one method.
fn name_rule_on_method(host: &str, method: &str) -> String {
    format!(
        r#"{{"host": {{"Exact": "{host}"}}, "port": null, "methods": ["{method}"], "path": null}}"#
    )
}

/// The same, for a name on an explicit port: the only shape that both
/// matches a CONNECT for the name and makes the broker grant the port.
fn name_rule_on_port(host: &str, port: u16) -> String {
    format!(r#"{{"host": {{"Exact": "{host}"}}, "port": {port}, "methods": [], "path": null}}"#)
}

/// An address literal on an explicit port.
fn address_rule(ip: &str, port: u16) -> String {
    format!(r#"{{"host": {{"Address": "{ip}"}}, "port": {port}, "methods": [], "path": null}}"#)
}

/// A configuration carrying the given allowances and denials.
fn config_with(allow: &[String], deny: &[String]) -> Vec<u8> {
    let rules = |list: &[String]| list.join(",");
    serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(&format!(
            r#"{{"intercept":[],"allow":[{}],"deny":[{}],"credentials":[],"log":null,"source":"the test config"}}"#,
            rules(allow),
            rules(deny)
        ))
        .unwrap(),
        credentials: Vec::new(),
        log: false,
    })
    .unwrap()
}

/// The same, with denials, resolved credentials, and the log descriptor
/// expected on descriptor 4: the shapes the log tests need.
fn config_with_log(
    allow: &[String],
    deny: &[String],
    credentials: &[bailey::broker::BrokerCredential],
    log: bool,
) -> Vec<u8> {
    let rules = |list: &[String]| list.join(",");
    serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(&format!(
            r#"{{"intercept":[],"allow":[{}],"deny":[{}],"credentials":[],"log":null,"source":"the test config"}}"#,
            rules(allow),
            rules(deny)
        ))
        .unwrap(),
        credentials: credentials.to_vec(),
        log,
    })
    .unwrap()
}

/// An upstream service that counts what it accepts. In the echo mode it
/// waits for the test's marker inside whatever the tunnel carries, and
/// answers with exactly the marker, whatever came before it.
struct Upstream {
    port: u16,
    accepts: Arc<AtomicUsize>,
}

impl Upstream {
    fn counting() -> Self {
        Self::start(None)
    }

    fn echoing(marker: &'static [u8]) -> Self {
        Self::start(Some(marker))
    }

    fn start(marker: Option<&'static [u8]>) -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                let Ok(mut stream) = stream else { continue };
                let Some(marker) = marker else { continue };
                let mut seen = Vec::new();
                loop {
                    let mut buffer = [0u8; 512];
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            seen.extend_from_slice(&buffer[..read]);
                            if seen.windows(marker.len()).any(|part| part == marker) {
                                break;
                            }
                        }
                    }
                }
                let _ = stream.write_all(marker);
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        Self { port, accepts }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn count(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

/// Spawn the broker serving `listener` as descriptor 3. The child is
/// stopped and reaped when the guard drops, so no broker outlives a test.
fn spawn_broker(config: &[u8], listener: &TcpListener) -> Broker {
    let mut command = Command::new(broker());
    command
        .arg(std::process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    hand_listener(&mut command, listener);
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(config).unwrap();
    drop(stdin);
    let mut stdout = child.stdout.take().unwrap();
    bailey::broker::BrokerReady::decode(&mut stdout).expect("a ready line");
    Broker(child)
}

/// Spawn the broker serving `listener` as descriptor 3, with an audit log
/// handed over as descriptor 4 when `log_path` is given. Returns the
/// broker's stdout after its ready line, where its counts line will land.
fn spawn_broker_with_log(
    config: &[u8],
    listener: &TcpListener,
    log_path: &std::path::Path,
) -> (Broker, std::process::ChildStdout) {
    use std::os::unix::io::AsRawFd;

    let log_file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)
        .unwrap();
    let log_fd = log_file.as_raw_fd();
    let mut command = Command::new(broker());
    command
        .arg(std::process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    hand_listener(&mut command, listener);
    // Safety: runs in the forked child before exec, where only
    // async-signal-safe calls are made. The caller keeps its own file
    // open, so it outlives the dup.
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            let copy = libc::fcntl(log_fd, libc::F_DUPFD_CLOEXEC, 5);
            if copy < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(copy, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(config).unwrap();
    drop(stdin);
    let mut stdout = child.stdout.take().unwrap();
    bailey::broker::BrokerReady::decode(&mut stdout).expect("a ready line");
    (Broker(child), stdout)
}

/// A broker the test stops and reaps when it drops.
struct Broker(std::process::Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A ClientHello carrying exactly one `host_name` of `sni`.
fn client_hello(sni: &str) -> Vec<u8> {
    let mut name_list = vec![0u8];
    name_list.extend(&(sni.len() as u16).to_be_bytes());
    name_list.extend_from_slice(sni.as_bytes());
    let mut extension_body = (name_list.len() as u16).to_be_bytes().to_vec();
    extension_body.extend_from_slice(&name_list);
    let mut extensions = 0u16.to_be_bytes().to_vec();
    extensions.extend_from_slice(&(extension_body.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&extension_body);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut message = vec![0x01u8];
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);

    let mut record = vec![0x16u8, 0x03, 0x01];
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(&message);
    record
}

/// Connect to the broker's listener as a client would.
fn client_of(listener: &TcpListener) -> TcpStream {
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

/// Send a request head, then read the answer's status line and body: the
/// broker closes every refused connection after its answer.
fn refused(mut client: TcpStream, request: &str) -> (String, String) {
    client.write_all(request.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match client.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let status = text.lines().next().unwrap_or("").to_string();
    let mut rest = Vec::new();
    let _ = client.read_to_end(&mut rest);
    (status, String::from_utf8_lossy(&rest).into_owned())
}

/// The answer head a CONNECT is answered with, without riding the tunnel.
fn connect_status(listener: &TcpListener, authority: &str) -> String {
    let mut client = client_of(listener);
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match client.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Grant a CONNECT with a 200, then send the first flight, then read the
/// tunnel to its end. Returns what the broker sent after the answer head,
/// which is empty when the tunnel ended silently.
fn tunnel_to_end(listener: &TcpListener, authority: &str, first_flight: &[u8]) -> Vec<u8> {
    let mut client = client_of(listener);
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match client.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let status = String::from_utf8_lossy(&head).into_owned();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "the tunnel was not granted: {status}"
    );
    client.write_all(first_flight).unwrap();
    let mut end = Vec::new();
    let _ = client.read_to_end(&mut end);
    end
}

/// Wait for the stub's accept count to settle, and return it.
fn settled_count(upstream: &Upstream) -> usize {
    std::thread::sleep(Duration::from_millis(300));
    upstream.count()
}

/// A CONNECT a rule denies is answered 403 with a reason naming the rule
/// and the layer, and costs the broker no upstream dial.
#[test]
fn a_denied_connect_is_answered_with_a_reason_and_costs_nothing() {
    let upstream = Upstream::counting();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(
        &[name_rule("allowed.example")],
        &[name_rule("denied.example")],
    );
    let _child = spawn_broker(&config, &listener);

    let (status, reason) = refused(
        client_of(&listener),
        "CONNECT denied.example:443 HTTP/1.1\r\n\r\n",
    );
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    assert!(
        reason.contains("denied.example"),
        "the reason names the host: {reason}"
    );
    assert!(
        reason.contains("denied by deny rule 1 in the test config"),
        "the reason names the rule and the layer: {reason}"
    );
    assert_eq!(settled_count(&upstream), 0, "no upstream dial");
}

/// A CONNECT to a host whose only allowance bounds a path still opens the
/// tunnel: the rule bounds the requests riding inside it, not the CONNECT
/// itself, which carries no method and no path.
#[test]
fn a_connect_to_a_path_bounded_rule_is_granted() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule_on_path("allowed.example", "/v1")], &[]);
    let _child = spawn_broker(&config, &listener);

    let status = connect_status(&listener, "allowed.example:443");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
}

/// The same for a rule bounded to methods: a CONNECT names none of them,
/// and the tunnel is granted on the name and the port.
#[test]
fn a_connect_to_a_method_bounded_rule_is_granted() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule_on_method("allowed.example", "GET")], &[]);
    let _child = spawn_broker(&config, &listener);

    let status = connect_status(&listener, "allowed.example:443");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
}

/// A CONNECT for a host no rule allows is refused, saying why.
#[test]
fn a_connect_no_rule_allows_is_refused() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule("allowed.example")], &[]);
    let _child = spawn_broker(&config, &listener);

    let (status, reason) = refused(
        client_of(&listener),
        "CONNECT other.example:443 HTTP/1.1\r\n\r\n",
    );
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    assert!(
        reason.contains("no rule allows it"),
        "the reason says why: {reason}"
    );
}

/// A cleartext request whose `Host` does not agree with the authority its
/// target names is refused with a reason, and nothing is dialled.
#[test]
fn a_cleartext_request_with_a_foreign_host_is_refused() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule("allowed.example")], &[]);
    let _child = spawn_broker(&config, &listener);

    let (status, reason) = refused(
        client_of(&listener),
        "GET http://allowed.example/x HTTP/1.1\r\nHost: other.example\r\n\r\n",
    );
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    assert!(reason.contains("does not agree"), "{reason}");
}

/// Every malformed CONNECT is a refusal with its reason, not a silent
/// close: the port, the version, the authority, the host and an oversized
/// head each get their `403`.
#[test]
fn a_malformed_connect_is_refused_with_its_reason() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule("allowed.example")], &[]);
    let _child = spawn_broker(&config, &listener);

    for (request, fragment) in [
        (
            "CONNECT allowed.example:443 HTTP/2.0\r\n\r\n",
            "not HTTP/1.0 or HTTP/1.1",
        ),
        (
            "CONNECT allowed.example:70000 HTTP/1.1\r\n\r\n",
            "the CONNECT port is not a port",
        ),
        ("CONNECT\r\n\r\n", "the CONNECT authority is missing"),
        (
            "CONNECT allowed.example.:443 HTTP/1.1\r\n\r\n",
            "the CONNECT host is not a name",
        ),
    ] {
        let (status, reason) = refused(client_of(&listener), request);
        assert!(status.starts_with("HTTP/1.1 403"), "{status}");
        assert!(
            reason.contains(fragment),
            "expected {fragment:?} in the reason: {reason}"
        );
    }

    // A head over the bound is refused with its reason too.
    let padded = format!(
        "CONNECT allowed.example:443 HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
        "x".repeat(8 * 1024)
    );
    let (status, reason) = refused(client_of(&listener), &padded);
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    assert!(
        reason.contains("the request head exceeds 8 KiB"),
        "{reason}"
    );
}

/// A name that resolves only to loopback ends the tunnel: the 200 was
/// already sent, but nothing is dialled.
#[test]
fn a_name_resolving_to_loopback_ends_the_tunnel() {
    let upstream = Upstream::counting();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule("localhost")], &[]);
    let _child = spawn_broker(&config, &listener);

    let end = tunnel_to_end(&listener, "localhost:443", &client_hello("localhost"));
    assert!(
        end.is_empty(),
        "the tunnel closes silently: {}",
        String::from_utf8_lossy(&end)
    );
    assert_eq!(settled_count(&upstream), 0, "no upstream dial");
}

/// A ClientHello naming another host than the CONNECT target ends the
/// tunnel before a resolution or a dial.
#[test]
fn a_fronted_sni_ends_the_tunnel_before_anything_else() {
    let upstream = Upstream::counting();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule("allowed.example")], &[]);
    let _child = spawn_broker(&config, &listener);

    let end = tunnel_to_end(
        &listener,
        "allowed.example:443",
        &client_hello("evil.example"),
    );
    assert!(end.is_empty(), "the tunnel closes silently");
    assert_eq!(settled_count(&upstream), 0, "no resolution, no dial");
}

/// A first flight that is not TLS at all ends the tunnel the same way.
#[test]
fn a_non_tls_first_flight_ends_the_tunnel() {
    let upstream = Upstream::counting();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[name_rule("allowed.example")], &[]);
    let _child = spawn_broker(&config, &listener);

    let end = tunnel_to_end(
        &listener,
        "allowed.example:443",
        b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
    );
    assert!(end.is_empty(), "the tunnel closes silently");
    assert_eq!(settled_count(&upstream), 0, "no upstream dial");
}

/// An allowed tunnel dials the checked address and relays both ways.
///
/// The host is an address literal on the upstream's own port, so the test
/// needs no name service and the broker grants the port. The ClientHello's
/// server name is the literal itself, the upstream echoes the marker the
/// test sends after it, and the echo comes back through the tunnel.
#[test]
fn an_allowed_tunnel_relays_bytes_to_the_upstream() {
    let Some(host_ip) = host_address() else {
        common::skip("needs a non-loopback address of this host");
        return;
    };
    let upstream = Upstream::echoing(b"through-the-tunnel");
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[address_rule(&host_ip.to_string(), upstream.port())], &[]);
    let _child = spawn_broker(&config, &listener);

    let mut client = client_of(&listener);
    let authority = format!("{host_ip}:{}", upstream.port());
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match client.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let status = String::from_utf8_lossy(&head).into_owned();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "the tunnel was not granted: {status}"
    );

    client
        .write_all(&client_hello(&host_ip.to_string()))
        .unwrap();
    client.write_all(b"through-the-tunnel").unwrap();
    let marker = b"through-the-tunnel";
    let mut echoed = Vec::new();
    while !echoed.windows(marker.len()).any(|part| part == marker) {
        let mut buffer = [0u8; 256];
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => echoed.extend_from_slice(&buffer[..read]),
        }
    }
    assert!(
        echoed.windows(marker.len()).any(|part| part == marker),
        "the upstream's echo came back through the tunnel: {:?}",
        String::from_utf8_lossy(&echoed)
    );
    assert_eq!(upstream.count(), 1, "exactly one dial");
}

/// A slow upstream answer still reaches the client. The upstream's
/// response window is a generous idle bound of its own, not the dial
/// timeout, so an exchange whose target thinks for a while is not cut
/// off ten seconds in. The stub answers eleven seconds late, past the
/// dial timeout, and the body must still come back.
#[test]
fn a_slow_upstream_answer_is_not_cut_off_by_the_dial_timeout() {
    let Some(host_ip) = host_address() else {
        common::skip("needs a non-loopback address of this host");
        return;
    };
    let body = "late-but-fine";
    let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let marker: &'static [u8] = Box::leak(body.as_bytes().to_vec().into_boxed_slice());
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut seen = Vec::new();
        let mut buffer = [0u8; 1024];
        while !seen.windows(4).any(|part| part == b"\r\n\r\n") {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(read) => seen.extend_from_slice(&buffer[..read]),
            }
        }
        std::thread::sleep(Duration::from_secs(11));
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                marker.len()
            )
            .as_bytes(),
        );
        let _ = stream.write_all(marker);
    });
    let broker_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with(&[address_rule(&host_ip.to_string(), port)], &[]);
    let _child = spawn_broker(&config, &broker_listener);

    let mut client = client_of(&broker_listener);
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let request =
        format!("GET http://{host_ip}:{port}/x HTTP/1.1\r\nHost: {host_ip}:{port}\r\n\r\n");
    client.write_all(request.as_bytes()).unwrap();
    let mut answer = Vec::new();
    while !answer.windows(marker.len()).any(|part| part == marker) {
        let mut buffer = [0u8; 512];
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => answer.extend_from_slice(&buffer[..read]),
        }
    }
    let text = String::from_utf8_lossy(&answer).into_owned();
    assert!(
        text.contains("200 OK"),
        "the late answer arrived through the broker: {text}"
    );
    assert!(
        text.contains("late-but-fine"),
        "the late answer's body came through: {text}"
    );
}

/// An address of this host that is not loopback, for the relay test: the
/// address a connected UDP socket would send from, without sending.
fn host_address() -> Option<std::net::IpAddr> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Where python3 lives, for the sandboxed orchestration scripts.
fn python() -> Option<&'static str> {
    ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists())
}

/// The CONNECT request that names a denied host costs the broker no DNS
/// query at all, and the request that names an allowed host costs exactly
/// the lookups, however many the resolver makes of them. A fronted SNI and
/// a non-TLS first flight cost none either: the tunnel ends before the
/// name service is consulted.
///
/// The broker, a stub answering every query with NXDOMAIN, and the client
/// all run inside one fresh user, network and mount namespace: the stub
/// binds port 53 there, a tmpfs /etc carries the resolver configuration,
/// and the client drives the broker through its own loopback. The script
/// reports the counts as one JSON line on stdout.
#[test]
fn denials_cost_no_queries_and_allowances_cost_the_lookup() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    if !bailey::backend::isolation::available() {
        common::skip("needs user namespaces");
        return;
    }
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let config = config_with(&[name_rule("allowed.test")], &[name_rule("denied.test")]);

    let script = r#"
import fcntl, json, os, socket, struct, subprocess, sys, threading, time

broker_path, config_path, allowed, denied = sys.argv[1:5]
counts = {'queries': 0}

# The caller runs this script inside `unshare -Urnm`: one user, network and
# mount namespace, with the user mapped. A tmpfs /etc carries the resolver
# configuration the broker reads.
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
MS_REC = 0x8000
MS_PRIVATE = 0x40000
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 127.0.0.1\n')

# The listener the broker serves; descriptor 3 in the broker. A caller can
# leave descriptor 3 open, so the listener is placed there rather than
# assumed to land on it.
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen(16)
port = listener.getsockname()[1]
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)

# Loopback in a fresh network namespace starts down.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))

def dns_stub():
    stub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stub.bind(('127.0.0.1', 53))
    while True:
        data, peer = stub.recvfrom(1500)
        counts['queries'] += 1
        index = 12
        while index < len(data) and data[index] != 0:
            index += 1 + data[index]
        index += 5
        question = data[12:index]
        answer = data[:2] + b'\x81\x83' + data[4:6] + b'\x00\x00' * 3 + question
        stub.sendto(answer, peer)

threading.Thread(target=dns_stub, daemon=True).start()

def client_hello(sni):
    name = sni.encode()
    name_list = b'\x00' + len(name).to_bytes(2, 'big') + name
    extension = len(name_list).to_bytes(2, 'big') + name_list
    extensions = b'\x00\x00' + len(extension).to_bytes(2, 'big') + extension
    body = (b'\x03\x03' + b'\x00' * 32 + b'\x00' + b'\x00\x02' + b'\x13\x01'
            + b'\x01\x00' + len(extensions).to_bytes(2, 'big') + extensions)
    message = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + len(message).to_bytes(2, 'big') + message

def probe(authority, flight):
    client = socket.create_connection(('127.0.0.1', port), timeout=5)
    client.settimeout(5)
    client.sendall(f'CONNECT {authority} HTTP/1.1\r\n\r\n'.encode())
    answer = b''
    while b'\r\n\r\n' not in answer:
        chunk = client.recv(4096)
        if not chunk:
            break
        answer += chunk
    status = answer.split(b'\r\n', 1)[0].decode(errors='replace')
    if flight is not None:
        client.sendall(flight)
    tail = b''
    while len(tail) < 4096:
        try:
            chunk = client.recv(4096)
        except socket.timeout:
            break
        # A refused tunnel is closed the moment its answer is written, so
        # whatever the client sends after the answer can come back as a
        # reset instead of the FIN; either is the tunnel's end.
        except ConnectionResetError:
            break
        if not chunk:
            break
        tail += chunk
    client.close()
    return status, tail

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3,),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({'error': f'no ready line: {ready!r}'}))
    sys.exit(3)

denied_status, denied_tail = probe(f'{denied}:443', client_hello(denied))
time.sleep(0.5)
queries_denied = counts['queries']

allowed_status, allowed_tail = probe(f'{allowed}:443', client_hello(allowed))
time.sleep(0.5)
queries_allowed = counts['queries'] - queries_denied

fronted_status, fronted_tail = probe(f'{allowed}:443', client_hello('evil.test'))
time.sleep(0.5)
queries_fronted = counts['queries'] - queries_allowed - queries_denied

garbage_status, garbage_tail = probe(f'{allowed}:443', b'NOT A TLS RECORD\r\n\r\n')
time.sleep(0.5)
queries_garbage = counts['queries'] - queries_fronted - queries_allowed - queries_denied

broker.kill()
broker.wait()
print(json.dumps({
    'denied_status': denied_status, 'allowed_status': allowed_status,
    'queries_denied': queries_denied, 'queries_allowed': queries_allowed,
    'queries_fronted': queries_fronted, 'queries_garbage': queries_garbage,
    'tails': [allowed_tail.decode(errors='replace'),
              fronted_tail.decode(errors='replace'),
              garbage_tail.decode(errors='replace')],
}), flush=True)
"#;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();
    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, script).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg("allowed.test")
        .arg("denied.test")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }
    assert!(
        report["denied_status"]
            .as_str()
            .unwrap()
            .starts_with("HTTP/1.1 403"),
        "{}",
        stdout
    );
    assert_eq!(report["queries_denied"], 0, "{}", stdout);
    assert!(
        report["allowed_status"]
            .as_str()
            .unwrap()
            .starts_with("HTTP/1.1 200"),
        "{}",
        stdout
    );
    let queries_allowed = report["queries_allowed"].as_u64().unwrap();
    assert!(
        queries_allowed >= 1,
        "the allowed tunnel never consulted the resolver: {stdout}"
    );
    assert_eq!(report["queries_fronted"], 0, "{}", stdout);
    assert_eq!(report["queries_garbage"], 0, "{}", stdout);
    assert!(
        report["tails"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tail| tail.as_str().unwrap().is_empty()),
        "the tunnels ended silently: {stdout}"
    );
}

/// The throwaway certificate the curl acceptance serves. Self-signed,
/// matched to the allowed name, and never verified: curl runs with `-k`.
const TUNNEL_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyIxU/eGO55N6q8AV
fL4uvGEEvKZSE3uFNghUWyZwV4uhRANCAARjUN6NAAp5j/cnzRbnzPCt4RdwLApt
Ncg4rQYGEwDDbwqFWQQfXxPt7MZ9YEbq3voBTDul27TCQjBd5Y04qPtN
-----END PRIVATE KEY-----
";

const TUNNEL_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBnjCCAUSgAwIBAgIUEXGQqwToFLZZINLtz2YQWOpkMOowCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMYWxsb3dlZC50ZXN0MCAXDTI2MTEyMTA1NTYxOFoYDzIxMjYx
MDI4MDU1NjE4WjAXMRUwEwYDVQQDDAxhbGxvd2VkLnRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAARjUN6NAAp5j/cnzRbnzPCt4RdwLAptNcg4rQYGEwDDbwqF
WQQfXxPt7MZ9YEbq3voBTDul27TCQjBd5Y04qPtNo2wwajAdBgNVHQ4EFgQUDwA8
99QsHc3iHke/WNk2M2Az6u0wHwYDVR0jBBgwFoAUDwA899QsHc3iHke/WNk2M2Az
6u0wDwYDVR0TAQH/BAUwAwEB/zAXBgNVHREEEDAOggxhbGxvd2VkLnRlc3QwCgYI
KoZIzj0EAwIDSAAwRQIgTIeIytP4euoRWOudZD+w57qJAyQlR6l151biwsQB0CsC
IQDYcWy77FKnM7IGDBl7O7LSzTwyag7bjhCZfMX8RbPFFw==
-----END CERTIFICATE-----
";

/// Hand `listener` to a command as descriptor 3, surviving exec.
///
/// When the listener already is descriptor 3, dup2 would be the identity
/// call, which clears nothing: its close-on-exec flag is dropped with
/// fcntl instead.
fn hand_listener(command: &mut Command, listener: &TcpListener) {
    use std::os::unix::io::AsRawFd;

    let listener_fd = listener.as_raw_fd();
    // Safety: runs in the forked child before exec, where only
    // async-signal-safe calls are made. The caller keeps its own listener
    // open, so the socket outlives the dup.
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            if listener_fd != 3 && libc::dup2(listener_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(listener_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// curl reaches an allowed host through the broker over TLS.
///
/// The broker runs with a tmpfs `/etc` whose hosts file maps the allowed
/// name to this host's own address, where a real TLS server serves one
/// page. curl is pointed at the broker with the flag bailey's proxy
/// variables stand for, resolves nothing of its own, and gets the page
/// through the tunnel: CONNECT granted on the name, ClientHello server
/// name matching it, one resolution of it through the hosts file, one
/// dial to the mapped address, and the bytes both ways.
#[test]
fn curl_reaches_an_allowed_host_through_the_tunnel() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let curl = ["/usr/bin/curl", "/bin/curl"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(curl) = curl else {
        common::skip("needs curl");
        return;
    };
    // The broker's name resolution is redirected with a mount namespace,
    // which a user namespace alone cannot make: probe the exact command.
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
    let Some(lan_ip) = host_address() else {
        common::skip("needs a non-loopback address of this host");
        return;
    };

    // The upstream: one TLS page, self-signed, on this host's own address.
    // The server picks its port and names it after READY.
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.pem");
    let cert_path = dir.path().join("cert.pem");
    std::fs::write(&key_path, TUNNEL_KEY).unwrap();
    std::fs::write(&cert_path, TUNNEL_CERT).unwrap();
    let mut server = Command::new(python)
        .arg("-c")
        .arg(format!(
            r#"import http.server, ssl
class Served(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'bailey-tunnel-ok')
    def log_message(self, *rest):
        pass
    def finish(self):
        try:
            self.wfile.flush()
            self.connection.unwrap()
        except Exception:
            pass
        super().finish()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(r'{cert}', r'{key}')
server = http.server.HTTPServer(('0.0.0.0', 0), Served)
server.socket = context.wrap_socket(server.socket, server_side=True)
print('READY', server.server_address[1], flush=True)
server.serve_forever()
"#,
            cert = cert_path.display(),
            key = key_path.display(),
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut ready_line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(server.stdout.take().unwrap()),
        &mut ready_line,
    )
    .expect("the TLS server names itself");
    let tls_port: u16 = ready_line
        .split_whitespace()
        .nth(1)
        .and_then(|port| port.parse().ok())
        .expect("the TLS server names its port");

    // The broker: on this host's network, with its own view of /etc.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let config = config_with(&[name_rule_on_port("allowed.test", tls_port)], &[]);
    let hosts = format!("{lan_ip} allowed.test\n127.0.0.1 localhost\n",);
    let setup = format!(
        "mount -t tmpfs none /etc \
         && printf '{hosts}' > /etc/hosts \
         && printf 'hosts: files dns\\n' > /etc/nsswitch.conf \
         && printf 'nameserver 127.0.0.1\\n' > /etc/resolv.conf \
         && exec \"$0\" \"$@\""
    );
    let mut command = Command::new(unshare);
    command
        .args(["-Urm", "sh", "-c", &setup])
        .arg(broker())
        .arg(std::process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    hand_listener(&mut command, &listener);
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&config).unwrap();
    drop(stdin);
    let mut stdout = child.stdout.take().unwrap();
    bailey::broker::BrokerReady::decode(&mut stdout).expect("a ready line");

    // curl speaks for the target: CONNECT to the broker, TLS to the end.
    let fetched = Command::new(curl)
        .args([
            "-sS",
            "-k",
            "--max-time",
            "10",
            "--proxy",
            &format!("http://127.0.0.1:{proxy_port}"),
            "--noproxy",
            "",
            &format!("https://allowed.test:{tls_port}/"),
        ])
        .output()
        .unwrap();
    let body = String::from_utf8_lossy(&fetched.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&fetched.stderr).into_owned();
    assert!(
        fetched.status.success(),
        "curl failed: {}\n{stderr}",
        fetched.status
    );
    assert_eq!(body, "bailey-tunnel-ok", "{stderr}");

    let _ = child.kill();
    let _ = child.wait();
    let _ = server.kill();
    let _ = server.wait();
}

/// The stub authority the termination test serves its upstream with: a
/// self-signed CA and a leaf for the intercepted name, signed by it. The
/// test installs the CA as the namespace's whole trust store, so the
/// broker's upstream TLS session verifies the stub the way it would verify
/// a real host against the real host roots.
const TERMINATION_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBnzCCAUWgAwIBAgIUX/JhJQphkuxiRq2aaqKdvKL2+gowCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwaYmFpbGV5LXRlcm1pbmF0aW9uLXRlc3QtY2EwHhcNMjYxMTIx
MDkxMDU0WhcNMzYxMTE4MDkxMDU0WjAlMSMwIQYDVQQDDBpiYWlsZXktdGVybWlu
YXRpb24tdGVzdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJQgh+SdBzCk
7NPm/IxXg2OEVkHPyaASEeuUdrBH+HxpppMEn5+OGhJCW8F1qdjloRBSA1W1acwK
CC4MtmbcZ1mjUzBRMB0GA1UdDgQWBBTSjDAsI7XnfAIczw40VJ6U7sktqjAfBgNV
HSMEGDAWgBTSjDAsI7XnfAIczw40VJ6U7sktqjAPBgNVHRMBAf8EBTADAQH/MAoG
CCqGSM49BAMCA0gAMEUCIQDMUXAisuftW37SGPNdyFU5OXgn5t1V2mehKDUo4o5G
hQIgIb5Lcb7UnBwXr+F4AmM5QxlRrqbs4YPRCw2P9SC9Wis=
-----END CERTIFICATE-----
";

const TERMINATION_LEAF: &str = "-----BEGIN CERTIFICATE-----
MIIBtTCCAVygAwIBAgIUHKj5UA5wyMbD5Z7k7D/AlkcwTpwwCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwaYmFpbGV5LXRlcm1pbmF0aW9uLXRlc3QtY2EwHhcNMjYxMTIx
MDkxMDU0WhcNMzYxMTE4MDkxMDU0WjAbMRkwFwYDVQQDDBBpbnRlcmNlcHRlZC50
ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBFuJ4eZ9Cn/n0C7I3ztZXZlN
PhY+HBwdmyl8ugy50ms+iXHQgqC1uztDKz+hQEllh/hLeqIY9bAbr+i94s6ZqaN0
MHIwGwYDVR0RBBQwEoIQaW50ZXJjZXB0ZWQudGVzdDATBgNVHSUEDDAKBggrBgEF
BQcDATAdBgNVHQ4EFgQUHma8gTN+xurnUEEKbdhsQ/PCGEMwHwYDVR0jBBgwFoAU
0owwLCO153wCHM8ONFSelO7JLaowCgYIKoZIzj0EAwIDRwAwRAIgHdVB0mftWlvQ
iVddII/IAnUkPLlriHv70VIF16wP+/8CIBTibK33PAJi3FJUrZb1vR7P3/Sujk6E
YCgdO1cHY5Xg
-----END CERTIFICATE-----
";

const TERMINATION_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEJtOpGIIzi8N/hprsdi87VdoCPRZh0n3pMHlL1eysdyoAoGCCqGSM49
AwEHoUQDQgAEBFuJ4eZ9Cn/n0C7I3ztZXZlNPhY+HBwdmyl8ugy50ms+iXHQgqC1
uztDKz+hQEllh/hLeqIY9bAbr+i94s6ZqQ==
-----END EC PRIVATE KEY-----
";

/// The broker's configuration with `intercept` entries attached: the
/// hosts whose TLS the broker terminates instead of splicing.
fn config_with_intercept(intercept: &[&str], allow: &[String]) -> Vec<u8> {
    let listed = |hosts: &[&str]| {
        hosts
            .iter()
            .map(|host| format!(r#"{{"Exact": "{host}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
    };
    let rules = |list: &[String]| list.join(",");
    serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(&format!(
            r#"{{"intercept":[{}],"allow":[{}],"deny":[],"credentials":[],"log":null,"source":"the test config"}}"#,
            listed(intercept),
            rules(allow)
        ))
        .unwrap(),
        credentials: Vec::new(),
        log: false,
    })
    .unwrap()
}

/// A fronted SNI on an intercepted host ends the tunnel like it does on a
/// spliced one: the 200 was already sent, but the broker terminates
/// nothing and dials nothing.
#[test]
fn a_fronted_sni_on_an_intercepted_host_ends_the_tunnel() {
    let upstream = Upstream::counting();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with_intercept(&["allowed.example"], &[name_rule("allowed.example")]);
    let _child = spawn_broker(&config, &listener);

    let end = tunnel_to_end(
        &listener,
        "allowed.example:443",
        &client_hello("evil.example"),
    );
    assert!(end.is_empty(), "the tunnel closes silently");
    assert_eq!(settled_count(&upstream), 0, "no termination, no dial");
}

/// An intercepted tunnel is terminated, not spliced: the broker answers
/// the target's TLS with `http/1.1` as the only protocol, decides the
/// first request, and opens the upstream TLS session itself, verifying
/// the upstream for the CONNECT name against the host's roots, offering
/// `http/1.1` alone there too, and only then dialling.
///
/// The broker, its TLS upstream, and the client all meet inside one fresh
/// user, network and mount namespace: a tmpfs `/etc` maps the intercepted
/// name to this host's loopback and carries the stub CA as the whole
/// trust store, and the upstream serves one page whose body names the
/// ALPN it negotiated with the broker. The script reports one JSON line.
#[test]
fn an_intercepted_tunnel_is_terminated_and_carries_http() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let leaf_path = dir.path().join("leaf.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, TERMINATION_CA).unwrap();
    std::fs::write(&leaf_path, TERMINATION_LEAF).unwrap();
    std::fs::write(&key_path, TERMINATION_KEY).unwrap();
    let config = config_with_intercept(&["intercepted.test"], &[name_rule("intercepted.test")]);
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();
    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, script()).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg(&ca_path)
        .arg(&leaf_path)
        .arg(&key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }

    // The matching-SNI tunnel carried HTTP end to end: the broker selected
    // `http/1.1` for the target, the upstream answered through it, and the
    // upstream negotiated `http/1.1` with the broker too. One dial.
    assert_eq!(report["good_alpn"], "http/1.1", "{}", stdout);
    assert!(
        report["good_status"].as_str().unwrap().contains("200"),
        "the upstream answered through the termination: {}",
        stdout
    );
    let body = report["good_body"].as_str().unwrap();
    assert!(
        body.contains("bailey-termination-ok"),
        "the upstream's page came through the termination: {stdout}"
    );
    assert!(
        body.contains("http/1.1"),
        "the upstream negotiated http/1.1, not anything the broker offered beyond it: {stdout}"
    );
    assert_eq!(report["accepts"], 1, "exactly one upstream dial: {stdout}");

    // A matching CONNECT with a fronted SNI ends the tunnel silently, and
    // costs no dial: it was refused before the TLS termination began.
    assert!(
        report["evil_tail"].as_str().unwrap().is_empty(),
        "the fronted tunnel ended silently: {stdout}"
    );
    assert_eq!(
        report["good_accepts"], report["accepts"],
        "the fronted probe dialled nothing: {stdout}"
    );
}

/// The sandbox script for the termination test, as a file the namespace
/// runs. Everything inside one process: the mounts, the TLS upstream, the
/// broker, and the two client probes.
fn script() -> String {
    r#"
import fcntl, json, os, socket, ssl, struct, subprocess, sys, threading, time
import ctypes
import http.server

broker_path, config_path, ca_path, leaf_path, key_path = sys.argv[1:6]
counts = {'accepts': 0}

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n10.0.0.7 intercepted.test\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files dns\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 127.0.0.1\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_path) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

# Loopback comes up, and the upstream sits on a private address the broker
# is allowed to dial: it refuses loopback dials by design.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
sock.close()

# The listener the broker serves comes first and takes descriptor 3; the
# TLS upstream is created after it, so the two never share a descriptor.
listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]

class Served(http.server.BaseHTTPRequestHandler):
    def setup(self):
        counts['accepts'] += 1
        super().setup()
    def do_GET(self):
        alpn = self.connection.selected_alpn_protocol() or 'none'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'bailey-termination-ok ' + alpn.encode())
    def log_message(self, *rest):
        pass

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(leaf_path, key_path)
context.set_alpn_protocols(['h2', 'http/1.1'])
server = http.server.HTTPServer(('10.0.0.7', 443), Served)
server.socket = context.wrap_socket(server.socket, server_side=True)
threading.Thread(target=server.serve_forever, daemon=True).start()

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3,),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({'error': f'no ready line: {ready!r}'}))
    sys.exit(3)

def connect_head(authority):
    client = socket.create_connection(('10.0.0.7', port), timeout=10)
    client.settimeout(10)
    client.sendall(f'CONNECT {authority} HTTP/1.1\r\n\r\n'.encode())
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = client.recv(4096)
        if not chunk:
            break
        head += chunk
    return client, head.split(b'\r\n', 1)[0].decode(errors='replace')

def client_hello(sni):
    name = sni.encode()
    name_list = b'\x00' + len(name).to_bytes(2, 'big') + name
    extension = len(name_list).to_bytes(2, 'big') + name_list
    extensions = b'\x00\x00' + len(extension).to_bytes(2, 'big') + extension
    body = (b'\x03\x03' + b'\x00' * 32 + b'\x00' + b'\x00\x02' + b'\x13\x01'
            + b'\x01\x00' + len(extensions).to_bytes(2, 'big') + extensions)
    message = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + len(message).to_bytes(2, 'big') + message

# The probe that means it: TLS with the CONNECT name, http/1.1 offered
# among the client's protocols, then one plain HTTP/1.1 request.
tls_client, status = connect_head('intercepted.test:443')
client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
client.check_hostname = False
client.verify_mode = ssl.CERT_NONE
client.set_alpn_protocols(['h2', 'http/1.1'])
tls = client.wrap_socket(tls_client, server_hostname='intercepted.test')
good_alpn = tls.selected_alpn_protocol() or 'none'
tls.sendall(b'GET / HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
response = b''
while True:
    try:
        chunk = tls.recv(4096)
    except socket.timeout:
        break
    if not chunk:
        break
    response += chunk
tls.close()
good_status = response.split(b'\r\n', 1)[0].decode(errors='replace')
good_body = response.split(b'\r\n\r\n', 1)[-1].decode(errors='replace')
good_accepts = counts['accepts']

# The fronted probe: a raw ClientHello naming another host.
evil_client, evil_status = connect_head('intercepted.test:443')
evil_client.sendall(client_hello('evil.test'))
evil_tail = b''
while len(evil_tail) < 4096:
    try:
        chunk = evil_client.recv(4096)
    except socket.timeout:
        break
    # The refusal closed the tunnel; the mis-fronted hello the client sent
    # after the answer can draw a reset rather than the FIN.
    except ConnectionResetError:
        break
    if not chunk:
        break
    evil_tail += chunk
evil_client.close()

broker.kill()
broker.wait()
print(json.dumps({
    'good_status': good_status, 'good_alpn': good_alpn, 'good_body': good_body,
    'evil_status': evil_status, 'evil_tail': evil_tail.decode(errors='replace'),
    'good_accepts': good_accepts, 'accepts': counts['accepts'],
}), flush=True)
server.shutdown()
"#
    .to_string()
}

/// The stub upstream of the response test: one canned exchange per path,
/// with a close mode that decides how the connection ends. `unwrap` ends
/// with a TLS close notice, `abrupt` closes the TCP connection under the
/// TLS session, and `keep` just closes as an ordinary server does.
fn response_stub_routes() -> String {
    r#"
ROUTES = {
    '/ok':            (b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nok-body', 'keep'),
    '/head-cl500':    (b'HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n', 'keep'),
    '/204-stray':     (b'HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n', 'keep'),
    '/304-stray':     (b'HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n', 'keep'),
    '/interim':       (b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi', 'keep'),
    '/close-clean':   (b'HTTP/1.1 200 OK\r\n\r\nclose-body', 'unwrap'),
    '/close-truncated': (b'HTTP/1.1 200 OK\r\n\r\nclose-trun', 'abrupt'),
    '/both-frames':   (b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n', 'abrupt'),
    '/trunc-chunked': (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki', 'abrupt'),
    '/trunc-length':  (b'HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\nabc', 'abrupt'),
}

def serve_tls(conn):
    try:
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return
            head += chunk
        path = head.split(b'\r\n', 1)[0].split(b' ')[1].decode()
        payload, mode = ROUTES.get(path, (b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n', 'keep'))
        conn.sendall(payload)
        if mode == 'unwrap':
            conn.settimeout(1)
            try:
                conn.unwrap()
            except Exception:
                pass
            conn.close()
        elif mode == 'abrupt':
            # A TCP end under the TLS session: no close notice, so the
            # peer must not read the exchange as complete.
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        else:
            conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
"#
    .to_string()
}

/// An intercepted tunnel serves request after request, each answered by
/// the response state machine: HEAD with a stray length
/// frames nothing and the same connection carries a second request, bodyless
/// statuses ignore stray length headers, an interim response is relayed
/// before the final one, a close-delimited body ends with the connection,
/// and every ambiguity or truncation reaches the client as an incomplete
/// response: no final chunk, no close notice.
#[test]
fn the_response_state_machine_relays_and_aborts() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let leaf_path = dir.path().join("leaf.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, TERMINATION_CA).unwrap();
    std::fs::write(&leaf_path, TERMINATION_LEAF).unwrap();
    std::fs::write(&key_path, TERMINATION_KEY).unwrap();
    let config = config_with_intercept(&["intercepted.test"], &[name_rule("intercepted.test")]);
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();

    let script = format!(
        r#"
import fcntl, json, os, socket, ssl, struct, subprocess, sys, threading
import ctypes
import http.server
broker_path, config_path, ca_path, leaf_path, key_path = sys.argv[1:6]

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({{'error': f'remount private refused: {{ctypes.get_errno()}}'}}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({{'error': f'/etc mount refused: {{ctypes.get_errno()}}'}}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n10.0.0.7 intercepted.test\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files dns\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 127.0.0.1\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_path) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

# Loopback comes up, and the upstream sits on a private address the broker
# is allowed to dial: it refuses loopback.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
sock.close()

{routes}

# The listener the broker serves comes first and takes descriptor 3.
listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(leaf_path, key_path)
context.set_alpn_protocols(['h2', 'http/1.1'])
upstream_listener = socket.socket()
upstream_listener.bind(('10.0.0.7', 443))
upstream_listener.listen(16)
def upstream_acceptor():
    while True:
        try:
            raw, _ = upstream_listener.accept()
        except OSError:
            return
        try:
            conn = context.wrap_socket(raw, server_side=True)
        except Exception:
            continue
        threading.Thread(target=serve_tls, args=(conn,), daemon=True).start()
threading.Thread(target=upstream_acceptor, daemon=True).start()

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3,),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({{'error': f'no ready line: {{ready!r}}'}}))
    sys.exit(3)

def open_tunnel():
    client = socket.create_connection(('10.0.0.7', port), timeout=10)
    client.settimeout(10)
    client.sendall(b'CONNECT intercepted.test:443 HTTP/1.1\r\n\r\n')
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = client.recv(4096)
        if not chunk:
            break
        head += chunk
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    tls = ctx.wrap_socket(client, server_hostname='intercepted.test')
    return tls

def read_exchange(tls, quiet=1.0):
    tls.settimeout(quiet)
    data = b''
    end = 'timeout'
    while True:
        try:
            chunk = tls.recv(8192)
        except socket.timeout:
            end = 'timeout'
            break
        except ssl.SSLEOFError:
            end = 'abrupt'
            break
        except (ssl.SSLError, ConnectionError, OSError):
            end = 'abrupt'
            break
        if not chunk:
            # A bare TCP end under the session reads the same as a
            # close notice; unwrap tells them apart.
            try:
                tls.unwrap()
                end = 'clean'
            except Exception:
                end = 'abrupt'
            break
        data += chunk
    return data, end

def request_on(tls, line):
    tls.sendall(f'{{line}} HTTP/1.1\r\nHost: intercepted.test\r\nConnection: keep-alive\r\n\r\n'.encode())

report = {{}}

# HEAD answered with Content-Length: 500 frames nothing, and the same
# connection carries a second request afterwards.
tls = open_tunnel()
request_on(tls, 'HEAD /head-cl500')
head_data, head_end = read_exchange(tls)
second_data, second_end = (b'', 'none')
if head_end == 'timeout':
    request_on(tls, 'GET /ok')
    second_data, second_end = read_exchange(tls)
report['head'] = {{'data': head_data.decode(errors='replace'), 'end': head_end}}
report['second'] = {{'data': second_data.decode(errors='replace'), 'end': second_end}}
try:
    tls.close()
except Exception:
    pass

# The one-exchange probes: status seen, body seen, and how the exchange
# ended on the client.
probes = {{
    '204': 'GET /204-stray',
    '304': 'GET /304-stray',
    'interim': 'GET /interim',
    'close_clean': 'GET /close-clean',
    'close_truncated': 'GET /close-truncated',
    'both_frames': 'GET /both-frames',
    'trunc_chunked': 'GET /trunc-chunked',
    'trunc_length': 'GET /trunc-length',
}}
for name, line in probes.items():
    tls = open_tunnel()
    request_on(tls, line)
    data, end = read_exchange(tls)
    report[name] = {{'data': data.decode(errors='replace'), 'end': end}}
    try:
        tls.close()
    except Exception:
        pass

broker.kill()
broker.wait()
print(json.dumps(report), flush=True)
"#,
        routes = response_stub_routes()
    );

    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, script).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg(&ca_path)
        .arg(&leaf_path)
        .arg(&key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }
    let get = |name: &str| -> (String, String) {
        let entry = &report[name];
        (
            entry["data"].as_str().unwrap().to_owned(),
            entry["end"].as_str().unwrap().to_owned(),
        )
    };

    // HEAD: the length header framed nothing, and the same connection
    // served a second request.
    let (head_data, head_end) = get("head");
    assert!(
        head_data.starts_with("HTTP/1.1 200"),
        "the HEAD response was relayed: {head_data:?}"
    );
    assert!(!head_data.contains("ok-body"), "HEAD carried no body");
    assert_eq!(
        head_end, "timeout",
        "the connection stayed open: {head_data:?}"
    );
    let (second_data, second_end) = get("second");
    assert!(
        second_data.contains("ok-body"),
        "the second request on the same connection was served: {second_data:?}"
    );
    assert_eq!(second_end, "timeout", "{second_data:?}");

    // Bodyless statuses ignore stray length headers and keep the
    // connection open.
    for name in ["204", "304"] {
        let (data, end) = get(name);
        assert!(data.starts_with("HTTP/1.1"), "{name}: {data:?}");
        assert!(
            !data.contains("0\r\n\r\n"),
            "{name}: no chunked body followed: {data:?}"
        );
        assert_eq!(
            end, "timeout",
            "{name}: the connection stayed open: {data:?}"
        );
    }

    // The interim response was relayed verbatim before the final one.
    let (data, end) = get("interim");
    assert!(data.contains("HTTP/1.1 100 Continue"), "{data:?}");
    assert!(data.contains("hi"), "the final body followed: {data:?}");
    assert_eq!(end, "timeout", "{data:?}");

    // A close-delimited body completes only when the upstream ended
    // cleanly; the broker closed the client connection either way.
    let (data, end) = get("close_clean");
    assert!(data.contains("close-body"), "{data:?}");
    assert_eq!(
        end, "clean",
        "a clean upstream end completes the body: {data:?}"
    );
    let (data, end) = get("close_truncated");
    assert!(data.contains("close-trun"), "{data:?}");
    assert_eq!(
        end, "abrupt",
        "an upstream end without a close notice is an incomplete response: {data:?}"
    );

    // Ambiguous framing closes both sides with nothing on the wire.
    let (data, end) = get("both_frames");
    assert!(
        data.is_empty(),
        "an ambiguous response was not relayed: {data:?}"
    );
    assert_eq!(end, "abrupt", "{data:?}");

    // A body cut short under each framing reaches the client incomplete:
    // whatever arrived, the end was abrupt, never clean.
    for name in ["trunc_chunked", "trunc_length"] {
        let (data, end) = get(name);
        assert!(data.contains("HTTP/1.1 200"), "{name}: {data:?}");
        assert_eq!(
            end, "abrupt",
            "{name}: the client saw an incomplete response: {data:?}"
        );
        if name == "trunc_chunked" {
            assert!(
                !data.ends_with("0\r\n\r\n"),
                "{name}: no final chunk was written: {data:?}"
            );
        }
    }
}

/// The rules apply per request inside an intercepted tunnel, and every
/// refusal closes the connection: an allowed request is served and keeps
/// the tunnel open, a denied one on the same connection is refused with no
/// rule to allow it, a `Host` that does not agree with the tunnel, a
/// WebSocket upgrade, and a nested `CONNECT` are each refused, and the
/// upstream saw only the allowed request.
#[test]
fn refusals_close_the_tunnel_and_spare_the_upstream() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let leaf_path = dir.path().join("leaf.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, TERMINATION_CA).unwrap();
    std::fs::write(&leaf_path, TERMINATION_LEAF).unwrap();
    std::fs::write(&key_path, TERMINATION_KEY).unwrap();
    let config = config_with_intercept(
        &["intercepted.test"],
        &[
            name_rule_on_method("intercepted.test", "CONNECT"),
            name_rule_on_path("intercepted.test", "/ok"),
        ],
    );
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();

    let script = r#"
import fcntl, json, os, socket, ssl, struct, subprocess, sys, threading
import ctypes
broker_path, config_path, ca_path, leaf_path, key_path = sys.argv[1:6]

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n10.0.0.7 intercepted.test\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files dns\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 127.0.0.1\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_path) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
sock.close()

# The upstream records every request line it is handed and every session
# it serves, so the refusals can be shown to cost it nothing.
seen = []
handshakes = []
def serve_tls(conn):
    handshakes.append(1)
    try:
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return
            head += chunk
        seen.append(head.split(b'\r\n', 1)[0].decode())
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nallowed-body')
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass

listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(leaf_path, key_path)
context.set_alpn_protocols(['h2', 'http/1.1'])
upstream_listener = socket.socket()
upstream_listener.bind(('10.0.0.7', 443))
upstream_listener.listen(16)
def upstream_acceptor():
    while True:
        try:
            raw, _ = upstream_listener.accept()
        except OSError:
            return
        try:
            conn = context.wrap_socket(raw, server_side=True)
        except Exception:
            continue
        threading.Thread(target=serve_tls, args=(conn,), daemon=True).start()
threading.Thread(target=upstream_acceptor, daemon=True).start()

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3,),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({'error': f'no ready line: {ready!r}'}))
    sys.exit(3)

def open_tunnel():
    client = socket.create_connection(('10.0.0.7', port), timeout=10)
    client.settimeout(10)
    client.sendall(b'CONNECT intercepted.test:443 HTTP/1.1\r\n\r\n')
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = client.recv(4096)
        if not chunk:
            break
        head += chunk
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    tls = ctx.wrap_socket(client, server_hostname='intercepted.test')
    return tls

def read_exchange(tls, quiet=1.0):
    tls.settimeout(quiet)
    data = b''
    end = 'timeout'
    while True:
        try:
            chunk = tls.recv(8192)
        except socket.timeout:
            end = 'timeout'
            break
        except (ssl.SSLError, ConnectionError, OSError):
            end = 'abrupt'
            break
        if not chunk:
            try:
                tls.unwrap()
                end = 'clean'
            except Exception:
                end = 'abrupt'
            break
        data += chunk
    return data, end

report = {}

# One kept-alive tunnel: the allowed request is served and the connection
# stays open, the denied request on the same connection is refused and the
# connection ends with a close notice.
tls = open_tunnel()
tls.sendall(b'GET /ok HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
allowed, allowed_end = read_exchange(tls)
tls.sendall(b'GET /nope HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
denied, denied_end = read_exchange(tls)
report['allowed'] = {'data': allowed.decode(errors='replace'), 'end': allowed_end}
report['denied'] = {'data': denied.decode(errors='replace'), 'end': denied_end}
try:
    tls.close()
except Exception:
    pass

# The refusal probes, one tunnel each.
probes = {
    'host_mismatch': b'GET /ok HTTP/1.1\r\nHost: other.example\r\n\r\n',
    'upgrade': b'GET /ok HTTP/1.1\r\nHost: intercepted.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
    'nested_connect': b'CONNECT inner.example:443 HTTP/1.1\r\nHost: inner.example:443\r\n\r\n',
}
for name, raw in probes.items():
    tls = open_tunnel()
    tls.sendall(raw)
    data, end = read_exchange(tls)
    report[name] = {'data': data.decode(errors='replace'), 'end': end}
    try:
        tls.close()
    except Exception:
        pass

report['handshakes'] = len(handshakes)
report['seen'] = seen

broker.kill()
broker.wait()
print(json.dumps(report), flush=True)
"#;

    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, script).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg(&ca_path)
        .arg(&leaf_path)
        .arg(&key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }
    let get = |name: &str| -> (String, String) {
        let entry = &report[name];
        (
            entry["data"].as_str().unwrap().to_owned(),
            entry["end"].as_str().unwrap().to_owned(),
        )
    };

    // The allowed request was served, and the tunnel stayed open.
    let (allowed, allowed_end) = get("allowed");
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "the allowed request was served: {allowed:?}"
    );
    assert!(allowed.contains("allowed-body"), "{allowed:?}");
    assert_eq!(
        allowed_end, "timeout",
        "the tunnel stayed open after the allowed request: {allowed:?}"
    );

    // The denied request on the same connection was refused, and the
    // refusal ended the connection with a close notice.
    let (denied, denied_end) = get("denied");
    assert!(
        denied.contains("403 Forbidden"),
        "the denied request was refused: {denied:?}"
    );
    assert!(denied.contains("no rule allows"), "{denied:?}");
    assert_eq!(
        denied_end, "clean",
        "the refusal ends the connection with a close notice: {denied:?}"
    );

    // A Host that does not agree with the tunnel is refused.
    let (data, end) = get("host_mismatch");
    assert!(data.contains("403 Forbidden"), "{data:?}");
    assert!(data.contains("does not agree"), "{data:?}");
    assert_eq!(end, "clean", "{data:?}");

    // A WebSocket upgrade is refused.
    let (data, end) = get("upgrade");
    assert!(data.contains("403 Forbidden"), "{data:?}");
    assert!(data.contains("asks to upgrade"), "{data:?}");
    assert_eq!(end, "clean", "{data:?}");

    // A nested CONNECT is refused.
    let (data, end) = get("nested_connect");
    assert!(data.contains("403 Forbidden"), "{data:?}");
    assert!(data.contains("CONNECT is not served"), "{data:?}");
    assert_eq!(end, "clean", "{data:?}");

    // The upstream served the one allowed request and nothing else.
    assert_eq!(
        report["handshakes"].as_u64(),
        Some(1),
        "the refused requests opened no upstream session"
    );
    assert_eq!(
        report["seen"].as_array().map(|lines| lines
            .iter()
            .map(|line| line.as_str().map(str::to_owned))
            .collect::<Vec<_>>()),
        Some(vec![Some("GET /ok HTTP/1.1".to_owned())]),
        "the upstream saw only the allowed request"
    );
}

/// A cleartext absolute-form request is served on the authority its target
/// names: an allowed request reaches the upstream in origin form with a
/// `Host` the broker wrote, and the same connection carries another one. A
/// `Host` that does not agree with the target's authority is refused with
/// no DNS query, and an absolute-form target inside a tunnel is refused.
#[test]
fn cleartext_absolute_form_serves_the_checked_authority() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let leaf_path = dir.path().join("leaf.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, TERMINATION_CA).unwrap();
    std::fs::write(&leaf_path, TERMINATION_LEAF).unwrap();
    std::fs::write(&key_path, TERMINATION_KEY).unwrap();
    let config = config_with_intercept(&["allowed.example"], &[name_rule("allowed.example")]);
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();

    let script = r#"
import fcntl, json, os, socket, ssl, struct, subprocess, sys, threading
import ctypes
broker_path, config_path, ca_path, leaf_path, key_path = sys.argv[1:6]

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n10.0.0.7 allowed.example\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files dns\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 10.0.0.7\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_path) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
sock.close()

# The listener the broker serves comes first and takes descriptor 3; the
# stubs come after the settle, so the dup2 never closes one of theirs.
listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]

# The cleartext stub upstream records each request line and Host header
# it is handed, one connection per request.
seen = []
def serve_http(conn):
    try:
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return
            head += chunk
        lines = head.split(b'\r\n')
        seen.append({'line': lines[0].decode(), 'host': next(
            (l.decode() for l in lines if l.lower().startswith(b'host:')), '')})
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\ncleartext-ok')
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
http_listener = socket.socket()
http_listener.bind(('10.0.0.7', 80))
http_listener.listen(16)
def http_acceptor():
    while True:
        try:
            conn, _ = http_listener.accept()
        except OSError:
            return
        threading.Thread(target=serve_http, args=(conn,), daemon=True).start()
threading.Thread(target=http_acceptor, daemon=True).start()

# The resolver sink counts every DNS datagram; the hosts file answers the
# names, so a count above zero means a refused request made a query.
dns_queries = []
sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sink.bind(('10.0.0.7', 53))
sink.settimeout(0.2)
def sink_loop():
    while True:
        try:
            sink.recvfrom(4096)
            dns_queries.append(1)
        except socket.timeout:
            continue
        except OSError:
            return
threading.Thread(target=sink_loop, daemon=True).start()

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3,),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({'error': f'no ready line: {ready!r}'}))
    sys.exit(3)

def read_plain(sock, quiet=1.0):
    sock.settimeout(quiet)
    data = b''
    end = 'timeout'
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        # A refusal closes the connection as it answers, so whatever the
        # client sends afterwards can come back as a reset; that is the
        # close, not a failure to read the answer.
        except ConnectionResetError:
            end = 'closed'
            break
        if not chunk:
            end = 'closed'
            break
        data += chunk
    return data, end

report = {}

# The allowed absolute-form requests are served, and the connection
# carries the second one.
client = socket.create_connection(('10.0.0.7', port), timeout=10)
client.settimeout(10)
client.sendall(b'GET http://allowed.example/x HTTP/1.1\r\nHost: allowed.example\r\n\r\n')
first, first_end = read_plain(client)
client.sendall(b'GET http://allowed.example/y?q=2 HTTP/1.1\r\nHost: allowed.example\r\n\r\n')
second, second_end = read_plain(client)
report['first'] = {'data': first.decode(errors='replace'), 'end': first_end}
report['second'] = {'data': second.decode(errors='replace'), 'end': second_end}
try:
    client.close()
except Exception:
    pass

# A Host that does not agree with the target's authority is refused, with
# no DNS query.
client = socket.create_connection(('10.0.0.7', port), timeout=10)
client.settimeout(10)
client.sendall(b'GET http://allowed.example/x HTTP/1.1\r\nHost: forbidden.example\r\n\r\n')
mismatch, mismatch_end = read_plain(client)
report['mismatch'] = {'data': mismatch.decode(errors='replace'), 'end': mismatch_end}
try:
    client.close()
except Exception:
    pass

# An absolute-form target inside a tunnel is refused.
tls_client = socket.create_connection(('10.0.0.7', port), timeout=10)
tls_client.settimeout(10)
tls_client.sendall(b'CONNECT allowed.example:443 HTTP/1.1\r\n\r\n')
head = b''
while b'\r\n\r\n' not in head:
    chunk = tls_client.recv(4096)
    if not chunk:
        break
    head += chunk
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2', 'http/1.1'])
tls = ctx.wrap_socket(tls_client, server_hostname='allowed.example')
tls.sendall(b'GET http://allowed.example/x HTTP/1.1\r\nHost: allowed.example\r\n\r\n')
tls.settimeout(1.0)
tunnel_data = b''
tunnel_end = 'timeout'
while True:
    try:
        chunk = tls.recv(8192)
    except socket.timeout:
        break
    except (ssl.SSLError, ConnectionError, OSError):
        tunnel_end = 'abrupt'
        break
    if not chunk:
        try:
            tls.unwrap()
            tunnel_end = 'clean'
        except Exception:
            tunnel_end = 'abrupt'
        break
    tunnel_data += chunk
report['in_tunnel'] = {'data': tunnel_data.decode(errors='replace'), 'end': tunnel_end}
try:
    tls.close()
except Exception:
    pass

import time
time.sleep(0.3)
report['seen'] = seen
report['dns_queries'] = len(dns_queries)

broker.kill()
broker.wait()
print(json.dumps(report), flush=True)
"#;

    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, script).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg(&ca_path)
        .arg(&leaf_path)
        .arg(&key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }
    let get = |name: &str| -> (String, String) {
        let entry = &report[name];
        (
            entry["data"].as_str().unwrap().to_owned(),
            entry["end"].as_str().unwrap().to_owned(),
        )
    };

    // The allowed requests were served, and the connection carried the
    // second one.
    let (first, first_end) = get("first");
    assert!(
        first.starts_with("HTTP/1.1 200") && first.contains("cleartext-ok"),
        "the first request was served: {first:?}"
    );
    assert_eq!(
        first_end, "timeout",
        "the connection stayed open: {first:?}"
    );
    let (second, second_end) = get("second");
    assert!(
        second.starts_with("HTTP/1.1 200") && second.contains("cleartext-ok"),
        "the second request was served: {second:?}"
    );
    assert_eq!(second_end, "timeout", "{second:?}");

    // The mismatched Host was refused.
    let (mismatch, mismatch_end) = get("mismatch");
    assert!(
        mismatch.contains("403 Forbidden") && mismatch.contains("does not agree"),
        "the mismatched Host was refused: {mismatch:?}"
    );
    assert_eq!(
        mismatch_end, "closed",
        "the refusal ended the connection: {mismatch:?}"
    );

    // The absolute-form target inside a tunnel was refused.
    let (in_tunnel, in_tunnel_end) = get("in_tunnel");
    assert!(
        in_tunnel.contains("403 Forbidden") && in_tunnel.contains("origin form"),
        "the absolute-form target inside a tunnel was refused: {in_tunnel:?}"
    );
    assert_eq!(
        in_tunnel_end, "clean",
        "the refusal ended the tunnel with a close notice: {in_tunnel:?}"
    );

    // The upstream saw the origin-form targets and the regenerated Host,
    // one connection per request.
    let seen: Vec<(String, String)> = report["seen"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    (
                        entry["line"].as_str().unwrap_or("").to_owned(),
                        entry["host"].as_str().unwrap_or("").to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        seen,
        vec![
            (
                "GET /x HTTP/1.1".to_owned(),
                "Host: allowed.example".to_owned()
            ),
            (
                "GET /y?q=2 HTTP/1.1".to_owned(),
                "Host: allowed.example".to_owned()
            ),
        ],
        "the upstream saw origin-form targets and the broker's Host"
    );

    // No refused request made a DNS query.
    assert_eq!(
        report["dns_queries"].as_u64(),
        Some(0),
        "no DNS query was issued for the refused request"
    );
}

/// A refused first request inside an intercepted tunnel costs the broker
/// neither an upstream connection nor a DNS query, while an allowed first
/// request costs both. The resolver is a stub answering the name with the
/// private address, so every lookup is counted, and the hosts file names
/// nothing: any resolution must ask the stub.
#[test]
fn a_refused_first_request_costs_no_lookup_and_no_dial() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let leaf_path = dir.path().join("leaf.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, TERMINATION_CA).unwrap();
    std::fs::write(&leaf_path, TERMINATION_LEAF).unwrap();
    std::fs::write(&key_path, TERMINATION_KEY).unwrap();
    let config = config_with_intercept(
        &["intercepted.test"],
        &[
            name_rule_on_method("intercepted.test", "CONNECT"),
            name_rule_on_path("intercepted.test", "/ok"),
        ],
    );
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();

    let script = r#"
import fcntl, json, os, socket, ssl, struct, subprocess, sys, threading, time
import ctypes
broker_path, config_path, ca_path, leaf_path, key_path = sys.argv[1:6]

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files dns\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 10.0.0.7\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_path) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
sock.close()

# The listener the broker serves comes first and takes descriptor 3.
listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]

counts = {'queries': 0}

# The resolver stub answers every question, A with the private address and
# AAAA with no data, and counts. It comes after the descriptor 3 settle, so
# the dup2 that gives the broker its listener never closes its socket.
def dns_stub():
    stub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stub.bind(('10.0.0.7', 53))
    while True:
        try:
            data, peer = stub.recvfrom(1500)
        except OSError:
            return
        counts['queries'] += 1
        index = 12
        while index < len(data) and data[index] != 0:
            index += 1 + data[index]
        qtype = data[index + 1:index + 3]
        index += 5
        question = data[12:index]
        if qtype == b'\x00\x1c':
            answer = (data[:2] + b'\x81\x80' + data[4:6]
                      + b'\x00\x00\x00\x00\x00\x00' + question)
        else:
            answer = (data[:2] + b'\x81\x80' + data[4:6]
                      + b'\x00\x01\x00\x00\x00\x00' + question
                      + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04'
                      + bytes([10, 0, 0, 7]))
        try:
            stub.sendto(answer, peer)
        except OSError:
            pass
threading.Thread(target=dns_stub, daemon=True).start()

# The upstream TLS stub counts the sessions it serves.
seen = []
handshakes = []
def serve_tls(conn):
    handshakes.append(1)
    try:
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return
            head += chunk
        seen.append(head.split(b'\r\n', 1)[0].decode())
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nallowed-body')
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass

listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(leaf_path, key_path)
context.set_alpn_protocols(['h2', 'http/1.1'])
upstream_listener = socket.socket()
upstream_listener.bind(('10.0.0.7', 443))
upstream_listener.listen(16)
def upstream_acceptor():
    while True:
        try:
            raw, _ = upstream_listener.accept()
        except OSError:
            return
        try:
            conn = context.wrap_socket(raw, server_side=True)
        except Exception:
            continue
        threading.Thread(target=serve_tls, args=(conn,), daemon=True).start()
threading.Thread(target=upstream_acceptor, daemon=True).start()

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3,),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({'error': f'no ready line: {ready!r}'}))
    sys.exit(3)

def open_tunnel():
    client = socket.create_connection(('10.0.0.7', port), timeout=10)
    client.settimeout(10)
    client.sendall(b'CONNECT intercepted.test:443 HTTP/1.1\r\n\r\n')
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = client.recv(4096)
        if not chunk:
            break
        head += chunk
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    tls = ctx.wrap_socket(client, server_hostname='intercepted.test')
    return tls

def read_exchange(tls, quiet=1.0):
    tls.settimeout(quiet)
    data = b''
    end = 'timeout'
    while True:
        try:
            chunk = tls.recv(8192)
        except socket.timeout:
            end = 'timeout'
            break
        except (ssl.SSLError, ConnectionError, OSError):
            end = 'abrupt'
            break
        if not chunk:
            try:
                tls.unwrap()
                end = 'clean'
            except Exception:
                end = 'abrupt'
            break
        data += chunk
    return data, end

report = {}

# The allowed first request is served: it costs the lookup and the dial.
tls = open_tunnel()
tls.sendall(b'GET /ok HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
allowed, allowed_end = read_exchange(tls)
report['allowed'] = {'data': allowed.decode(errors='replace'), 'end': allowed_end}
try:
    tls.close()
except Exception:
    pass
time.sleep(0.5)
after_allowed = {'queries': counts['queries'], 'sessions': len(handshakes)}

# The refused first request on a fresh tunnel costs neither.
tls = open_tunnel()
tls.sendall(b'GET /nope HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
refused, refused_end = read_exchange(tls)
report['refused'] = {'data': refused.decode(errors='replace'), 'end': refused_end}
try:
    tls.close()
except Exception:
    pass
time.sleep(0.5)
after_refused = {'queries': counts['queries'], 'sessions': len(handshakes)}

report['allowed_cost'] = after_allowed
report['refused_cost'] = {
    'queries': after_refused['queries'] - after_allowed['queries'],
    'sessions': after_refused['sessions'] - after_allowed['sessions'],
}
report['seen'] = seen

broker.kill()
broker.wait()
print(json.dumps(report), flush=True)
"#;
    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, script).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg(&ca_path)
        .arg(&leaf_path)
        .arg(&key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }

    // The allowed first request was served, and cost the lookup and the
    // dial.
    let allowed = &report["allowed"];
    assert!(
        allowed["data"].as_str().unwrap().contains("allowed-body"),
        "the allowed request was served: {report}"
    );
    let allowed_queries = report["allowed_cost"]["queries"].as_u64().unwrap();
    assert!(
        allowed_queries >= 1,
        "the allowed request never consulted the resolver: {report}"
    );
    assert_eq!(
        report["allowed_cost"]["sessions"], 1,
        "the allowed request dialled once: {report}"
    );

    // The refused first request was refused, and cost neither.
    let refused = &report["refused"];
    assert!(
        refused["data"].as_str().unwrap().contains("403 Forbidden")
            && refused["data"].as_str().unwrap().contains("no rule allows"),
        "the first request was refused: {report}"
    );
    assert_eq!(
        refused["end"], "clean",
        "the refusal ended the tunnel with a close notice: {report}"
    );
    assert_eq!(
        report["refused_cost"]["queries"], 0,
        "the refused request made no DNS query: {report}"
    );
    assert_eq!(
        report["refused_cost"]["sessions"], 0,
        "the refused request opened no upstream connection: {report}"
    );
    assert_eq!(
        report["seen"][0].as_str(),
        Some("GET /ok HTTP/1.1"),
        "the upstream saw only the allowed request: {report}"
    );
}

/// The path forwarded is the path matched: canonical paths with queries and
/// `%20` reach the upstream byte for byte, inside an intercepted tunnel and
/// through a cleartext absolute-form request, and a path the rule does not
/// match forwards nothing.
#[test]
fn the_forwarded_path_is_the_matched_path() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let leaf_path = dir.path().join("leaf.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, TERMINATION_CA).unwrap();
    std::fs::write(&leaf_path, TERMINATION_LEAF).unwrap();
    std::fs::write(&key_path, TERMINATION_KEY).unwrap();
    let config = config_with_intercept(
        &["intercepted.test"],
        &[
            name_rule_on_method("intercepted.test", "CONNECT"),
            name_rule_on_path("intercepted.test", "/ok"),
        ],
    );
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();

    let script = r#"
import fcntl, json, os, socket, ssl, struct, subprocess, sys, threading, time
import ctypes
broker_path, config_path, ca_path, leaf_path, key_path = sys.argv[1:6]

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n10.0.0.7 intercepted.test\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files dns\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 10.0.0.7\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_path) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
sock.close()

# The listener the broker serves comes first and takes descriptor 3; the
# stubs come after the settle, so the dup2 never closes one of theirs.
listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]

# The cleartext stub on port 80 records the request line and Host header.
seen_http = []
def serve_http(conn):
    try:
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return
            head += chunk
        lines = head.split(b'\r\n')
        seen_http.append({'line': lines[0].decode(), 'host': next(
            (l.decode() for l in lines if l.lower().startswith(b'host:')), '')})
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone')
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
http_listener = socket.socket()
http_listener.bind(('10.0.0.7', 80))
http_listener.listen(16)
def http_acceptor():
    while True:
        try:
            conn, _ = http_listener.accept()
        except OSError:
            return
        threading.Thread(target=serve_http, args=(conn,), daemon=True).start()
threading.Thread(target=http_acceptor, daemon=True).start()

# The TLS stub on port 443 records the request line of each session.
seen_tls = []
def serve_tls(conn):
    try:
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = conn.recv(4096)
            if not chunk:
                return
            head += chunk
        seen_tls.append(head.split(b'\r\n', 1)[0].decode())
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone')
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(leaf_path, key_path)
context.set_alpn_protocols(['h2', 'http/1.1'])
upstream_listener = socket.socket()
upstream_listener.bind(('10.0.0.7', 443))
upstream_listener.listen(16)
def upstream_acceptor():
    while True:
        try:
            raw, _ = upstream_listener.accept()
        except OSError:
            return
        try:
            conn = context.wrap_socket(raw, server_side=True)
        except Exception:
            continue
        threading.Thread(target=serve_tls, args=(conn,), daemon=True).start()
threading.Thread(target=upstream_acceptor, daemon=True).start()

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3,),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({'error': f'no ready line: {ready!r}'}))
    sys.exit(3)

def open_tunnel():
    client = socket.create_connection(('10.0.0.7', port), timeout=10)
    client.settimeout(10)
    client.sendall(b'CONNECT intercepted.test:443 HTTP/1.1\r\n\r\n')
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = client.recv(4096)
        if not chunk:
            break
        head += chunk
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    tls = ctx.wrap_socket(client, server_hostname='intercepted.test')
    return tls

def read_exchange(tls, quiet=1.0):
    tls.settimeout(quiet)
    data = b''
    end = 'timeout'
    while True:
        try:
            chunk = tls.recv(8192)
        except socket.timeout:
            end = 'timeout'
            break
        except (ssl.SSLError, ConnectionError, OSError):
            end = 'abrupt'
            break
        if not chunk:
            try:
                tls.unwrap()
                end = 'clean'
            except Exception:
                end = 'abrupt'
            break
        data += chunk
    return data, end

report = {}

# The canonical paths through the tunnel, one request per upstream session.
tunnel_paths = ['/ok', '/ok/a/b', '/ok?q=1&x=%20', '/ok%20y', '/ok/z%20w?q=a%20b']
for path in tunnel_paths:
    tls = open_tunnel()
    tls.sendall(f'GET {path} HTTP/1.1\r\nHost: intercepted.test\r\n\r\n'.encode())
    data, end = read_exchange(tls)
    report[path] = {'ok': b'HTTP/1.1 200' in data and b'done' in data, 'end': end}
    try:
        tls.close()
    except Exception:
        pass

# The one the rule does not match forwards nothing.
tls = open_tunnel()
tls.sendall(b'GET /nope HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
refused, refused_end = read_exchange(tls)
report['/nope'] = {'data': refused.decode(errors='replace'), 'end': refused_end}
try:
    tls.close()
except Exception:
    pass

# The absolute-form cleartext request with the same shape.
client = socket.create_connection(('10.0.0.7', port), timeout=10)
client.settimeout(10)
client.sendall(b'GET http://intercepted.test/ok%20y?q=%20 HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
client.settimeout(1.0)
plain = b''
while True:
    try:
        chunk = client.recv(8192)
    except socket.timeout:
        break
    if not chunk:
        break
    plain += chunk
report['cleartext'] = {'ok': b'HTTP/1.1 200' in plain and b'done' in plain}
try:
    client.close()
except Exception:
    pass

time.sleep(0.3)
report['seen_tls'] = seen_tls
report['seen_http'] = seen_http

broker.kill()
broker.wait()
print(json.dumps(report), flush=True)
"#;
    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, script).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg(&ca_path)
        .arg(&leaf_path)
        .arg(&key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }

    // Every canonical path was served.
    for path in [
        "/ok",
        "/ok/a/b",
        "/ok?q=1&x=%20",
        "/ok%20y",
        "/ok/z%20w?q=a%20b",
    ] {
        let entry = &report[path];
        assert!(
            entry["ok"].as_bool() == Some(true) && entry["end"] == "timeout",
            "{path} was served and the tunnel stayed open: {report}"
        );
    }

    // The unmatched path was refused, and the tunnel closed with it.
    let refused = &report["/nope"];
    assert!(
        refused["data"].as_str().unwrap().contains("403 Forbidden")
            && refused["data"].as_str().unwrap().contains("no rule allows"),
        "the unmatched path was refused: {report}"
    );
    assert_eq!(refused["end"], "clean", "{report}");

    // The cleartext absolute-form request was served.
    assert_eq!(
        report["cleartext"]["ok"], true,
        "the cleartext request was served: {report}"
    );

    // The TLS upstream saw the paths byte for byte, in order.
    let seen_tls: Vec<&str> = report["seen_tls"]
        .as_array()
        .map(|lines| lines.iter().map(|line| line.as_str().unwrap()).collect())
        .unwrap_or_default();
    assert_eq!(
        seen_tls,
        vec![
            "GET /ok HTTP/1.1",
            "GET /ok/a/b HTTP/1.1",
            "GET /ok?q=1&x=%20 HTTP/1.1",
            "GET /ok%20y HTTP/1.1",
            "GET /ok/z%20w?q=a%20b HTTP/1.1",
        ],
        "the tunnel upstream saw the matched paths byte for byte: {report}"
    );

    // The cleartext upstream saw the origin-form path byte for byte, with
    // the Host the broker writes.
    let seen_http = &report["seen_http"];
    let forwarded = (
        seen_http[0]["line"].as_str().unwrap_or(""),
        seen_http[0]["host"].as_str().unwrap_or(""),
    );
    assert_eq!(
        forwarded,
        ("GET /ok%20y?q=%20 HTTP/1.1", "Host: intercepted.test"),
        "the cleartext upstream saw the matched path byte for byte: {report}"
    );
}

/// Every decision writes one line to the log the caller handed over: what
/// was decided, which rule decided it, and never a header, a query, or a
/// credential value. The broker reports the counts on its stdout when it
/// is asked to stop.
#[test]
fn the_log_records_one_line_per_decision_and_the_counts() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("http-log.jsonl");
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let config = config_with_log(
        &[name_rule("tun.test")],
        &[name_rule_on_path("tun.test", "/private")],
        &[bailey::broker::BrokerCredential {
            host: serde_json::from_str(r#"{"Exact": "tun.test"}"#).unwrap(),
            auth: bailey::policy::AuthShape::Bearer,
            value: "sekrit-value".into(),
        }],
        true,
    );
    let (mut child, mut stdout) = spawn_broker_with_log(&config, &listener, &log_path);

    // An allowed CONNECT: logged at the decision, before the name is even
    // resolved, and this name resolves nowhere dialable.
    let _ = tunnel_to_end(&listener, "tun.test:443", &client_hello("tun.test"));

    // A refused CONNECT: no rule allows the host.
    let (_, body) = refused(
        client_of(&listener),
        "CONNECT refused.test:443 HTTP/1.1\r\n\r\n",
    );
    assert!(body.contains("no rule allows it"), "{body}");

    // A cleartext request denied by the deny rule, with the query the
    // request carried nowhere in the answer or the log.
    let (_, body) = refused(
        client_of(&listener),
        "GET http://tun.test/private/thing?q=sekrit-value HTTP/1.1\r\nHost: tun.test\r\n\r\n",
    );
    assert!(body.contains("deny rule 1"), "{body}");

    // A cleartext request to a credentialed host: refused before anything
    // is attached, and the credential's value rides nothing.
    let (_, body) = refused(
        client_of(&listener),
        "GET http://tun.test/ok HTTP/1.1\r\nHost: tun.test\r\n\r\n",
    );
    assert!(body.contains("served over TLS only"), "{body}");

    // The broker reports the counts on its stdout when it is asked to
    // stop: the last line it writes.
    unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) };
    let mut counts_text = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut counts_text).unwrap();
    let status = child.0.wait().unwrap();
    assert!(
        status.success(),
        "a stopped broker exits cleanly: {status:?}"
    );
    let counts: serde_json::Value = serde_json::from_str(counts_text.trim())
        .unwrap_or_else(|error| panic!("the counts line is not json: {error}; {counts_text:?}"));
    assert_eq!(counts["allowed"], 1, "{counts_text}");
    assert_eq!(counts["refused"], 3, "{counts_text}");

    // The log: one line per decision, in the order they were decided.
    let text = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("log line is not json: {error}; {line:?}"))
        })
        .collect();
    assert_eq!(lines.len(), 4, "{text}");
    let time = lines[0]["time"].as_str().unwrap();
    assert!(
        time.len() > 20 && time.contains('T'),
        "the line carries a timestamp: {time}"
    );
    assert_eq!(
        lines[0],
        serde_json::json!({
            "time": time,
            "method": "CONNECT",
            "host": "tun.test",
            "port": 443,
            "path": "",
            "verdict": "allowed",
            "reason": "",
            "rule": "allow rule 1 in the test config",
            "intercepted": false,
        }),
        "the allowed tunnel's line: {text}"
    );
    assert_eq!(lines[1]["verdict"], "refused", "{text}");
    assert_eq!(lines[1]["host"], "refused.test", "{text}");
    assert_eq!(
        lines[1]["reason"], "CONNECT refused.test denied: no rule allows it",
        "{text}"
    );
    assert_eq!(lines[1]["rule"], "", "no rule decided it: {text}");
    assert_eq!(lines[2]["method"], "GET", "{text}");
    assert_eq!(lines[2]["path"], "/private/thing", "{text}");
    assert_eq!(lines[2]["rule"], "deny rule 1 in the test config", "{text}");
    assert!(
        lines[2]["reason"].as_str().unwrap().contains("denied by"),
        "{text}"
    );
    assert_eq!(lines[3]["verdict"], "refused", "{text}");
    assert!(
        lines[3]["reason"]
            .as_str()
            .unwrap()
            .contains("served over TLS only"),
        "{text}"
    );

    // Nothing but decisions: no query, no credential shape, no value.
    assert!(!text.contains("sekrit-value"), "{text}");
    assert!(!text.contains("q="), "{text}");
    assert!(!text.contains("Bearer"), "{text}");
    for line in &lines {
        assert!(
            line.get("status").is_none(),
            "no upstream answered, so no status: {line}"
        );
    }
}
/// The terminated path's decisions carry the upstream status and the
/// deciding rule, and never the request's query, its extra headers, or
/// the credential the broker attached upstream.
///
/// Same shape as the termination test: the broker, its TLS upstream, and
/// the client meet inside one fresh namespace, and the script reports the
/// log's lines and the counts the broker wrote on its way out.
#[test]
fn the_terminated_log_carries_the_decisions_and_no_secrets() {
    let Some(python) = python() else {
        common::skip("needs python3");
        return;
    };
    let unshare = ["/usr/bin/unshare", "/bin/unshare"]
        .into_iter()
        .find(|path| std::path::Path::new(path).exists());
    let Some(unshare) = unshare else {
        common::skip("needs the unshare binary");
        return;
    };
    let probe = Command::new(unshare)
        .args(["-Urm", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("unshare runs");
    if !probe.success() {
        common::skip("needs mountable user namespaces");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    let leaf_path = dir.path().join("leaf.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&ca_path, TERMINATION_CA).unwrap();
    std::fs::write(&leaf_path, TERMINATION_LEAF).unwrap();
    std::fs::write(&key_path, TERMINATION_KEY).unwrap();
    let config = serde_json::to_vec(&bailey::broker::BrokerConfig {
        version: bailey::broker::BROKER_PROTOCOL_VERSION,
        http: serde_json::from_str(&format!(
            r#"{{"intercept":[{{"Exact": "intercepted.test"}}],"allow":[{}],"deny":[{}],"credentials":[],"log":null,"source":"the test config"}}"#,
            name_rule("intercepted.test"),
            name_rule_on_path("intercepted.test", "/private")
        ))
        .unwrap(),
        credentials: vec![bailey::broker::BrokerCredential {
            host: serde_json::from_str(r#"{"Exact": "intercepted.test"}"#).unwrap(),
            auth: bailey::policy::AuthShape::Bearer,
            value: "sekrit-value".into(),
        }],
        log: true,
    })
    .unwrap();
    let config_path = dir.path().join("broker-config.json");
    std::fs::write(&config_path, &config).unwrap();
    let log_path = dir.path().join("http-log.jsonl");
    let script_path = dir.path().join("sandbox.py");
    std::fs::write(&script_path, log_script()).unwrap();

    let output = Command::new(unshare)
        .arg("-Urnm")
        .arg(python)
        .arg(&script_path)
        .arg(broker())
        .arg(&config_path)
        .arg(&ca_path)
        .arg(&leaf_path)
        .arg(&key_path)
        .arg(&log_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("the sandbox script did not report: {error}; stdout: {stdout}")
    });
    if let Some(error) = report.get("error") {
        panic!("the sandbox script failed: {error}");
    }
    assert_eq!(
        report["good_status"].as_str().unwrap(),
        "HTTP/1.0 200 OK",
        "the allowed request was answered upstream: {}",
        stdout
    );

    // The counts the broker wrote on its way out: four allowed (three
    // tunnels, one request), two refused (the denied request, and the
    // tunnel whose ClientHello fronted another host).
    let counts: serde_json::Value = serde_json::from_str(report["counts"].as_str().unwrap())
        .unwrap_or_else(|error| panic!("the counts are not json: {error}; {}", stdout));
    assert_eq!(counts["allowed"], 4, "{counts}");
    assert_eq!(counts["refused"], 2, "{counts}");

    // The log: one line per decision, nothing but decisions in them.
    let lines: Vec<String> = report["log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line.as_str().unwrap().to_string())
        .collect();
    assert_eq!(lines.len(), 6, "{}", lines.join("\n"));
    let parsed: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("log line is not json: {error}; {line:?}"))
        })
        .collect();
    assert_eq!(parsed[0]["method"], "CONNECT", "{}", lines.join("\n"));
    assert_eq!(parsed[0]["verdict"], "allowed");
    assert_eq!(parsed[0]["intercepted"], true);
    assert_eq!(
        parsed[0]["rule"],
        "allow rule 1 in the test config",
        "{}",
        lines.join("\n")
    );
    assert!(parsed[0].get("status").is_none(), "a tunnel has no status");
    assert_eq!(parsed[1]["method"], "GET");
    assert_eq!(parsed[1]["path"], "/secret", "the query is not the path");
    assert_eq!(parsed[1]["status"], 200, "{}", lines.join("\n"));
    assert_eq!(parsed[1]["intercepted"], true);
    assert_eq!(parsed[2]["method"], "CONNECT");
    assert_eq!(parsed[2]["verdict"], "allowed");
    assert!(parsed[2].get("status").is_none(), "a tunnel has no status");
    assert_eq!(parsed[3]["path"], "/private");
    assert_eq!(parsed[3]["verdict"], "refused");
    assert_eq!(
        parsed[3]["rule"],
        "deny rule 1 in the test config",
        "{}",
        lines.join("\n")
    );
    assert_eq!(parsed[4]["method"], "CONNECT");
    assert_eq!(
        parsed[4]["verdict"], "allowed",
        "the evil tunnel was granted on the name"
    );
    assert_eq!(parsed[5]["verdict"], "refused");
    assert_eq!(
        parsed[5]["reason"],
        "the ClientHello named another host",
        "{}",
        lines.join("\n")
    );
    let joined = lines.join("\n");
    assert!(!joined.contains("sekrit-value"), "{}", joined);
    assert!(!joined.contains("token"), "{}", joined);
    assert!(!joined.contains("X-Other"), "{}", joined);
    assert!(!joined.contains("Bearer"), "{}", joined);
}

/// The sandbox script for the log test: the mounts, the TLS upstream, the
/// broker with its log on descriptor 4, and the four probes.
fn log_script() -> String {
    r#"
import fcntl, json, os, signal, socket, ssl, struct, subprocess, sys, threading, time
import ctypes
import http.server

broker_path, config_path, ca_path, leaf_path, key_path, log_path = sys.argv[1:7]
counts = {'accepts': 0}

MS_REC = 0x8000
MS_PRIVATE = 0x40000
libc = ctypes.CDLL(None, use_errno=True)
if libc.mount(None, b'/', None, MS_PRIVATE | MS_REC, None) != 0:
    print(json.dumps({'error': f'remount private refused: {ctypes.get_errno()}'}))
    sys.exit(3)
if libc.mount(b'tmpfs', b'/etc', b'tmpfs', 0, None) != 0:
    print(json.dumps({'error': f'/etc mount refused: {ctypes.get_errno()}'}))
    sys.exit(3)
with open('/etc/hosts', 'w') as hosts:
    hosts.write('127.0.0.1 localhost\n10.0.0.7 intercepted.test\n')
with open('/etc/nsswitch.conf', 'w') as switch:
    switch.write('hosts: files dns\n')
with open('/etc/resolv.conf', 'w') as resolv:
    resolv.write('nameserver 127.0.0.1\n')
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open(ca_path) as source, open('/etc/ssl/certs/ca-certificates.crt', 'w') as store:
    store.write(source.read())

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fcntl.ioctl(sock, 0x8914, struct.pack('16sH22x', b'lo', 0x41))
fcntl.ioctl(sock, 0x8916, struct.pack('16sH2s4s16x', b'lo', 2, b'\x00\x00', socket.inet_aton('10.0.0.7')))
sock.close()

# The listener takes descriptor 3, the log takes descriptor 4.
listener = socket.socket()
listener.bind(('10.0.0.7', 0))
listener.listen(16)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3)
    listener.close()
    listener = socket.socket(fileno=3)
port = listener.getsockname()[1]
log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
if log_fd != 4:
    os.dup2(log_fd, 4)
    os.close(log_fd)

class Served(http.server.BaseHTTPRequestHandler):
    def setup(self):
        counts['accepts'] += 1
        super().setup()
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'bailey-termination-ok')
    def log_message(self, *rest):
        pass

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(leaf_path, key_path)
context.set_alpn_protocols(['http/1.1'])
server = http.server.HTTPServer(('10.0.0.7', 443), Served)
server.socket = context.wrap_socket(server.socket, server_side=True)
threading.Thread(target=server.serve_forever, daemon=True).start()

config = open(config_path, 'rb').read()
broker = subprocess.Popen(
    [broker_path, str(os.getpid())], pass_fds=(3, 4),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
broker.stdin.write(config)
broker.stdin.close()
ready = broker.stdout.readline()
if b'"layers"' not in ready:
    print(json.dumps({'error': f'no ready line: {ready!r}'}))
    sys.exit(3)

def connect_head(authority):
    client = socket.create_connection(('10.0.0.7', port), timeout=10)
    client.settimeout(10)
    client.sendall(f'CONNECT {authority} HTTP/1.1\r\n\r\n'.encode())
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = client.recv(4096)
        if not chunk:
            break
        head += chunk
    return client, head.split(b'\r\n', 1)[0].decode(errors='replace')

def client_hello(sni):
    name = sni.encode()
    name_list = b'\x00' + len(name).to_bytes(2, 'big') + name
    extension = len(name_list).to_bytes(2, 'big') + name_list
    extensions = b'\x00\x00' + len(extension).to_bytes(2, 'big') + extension
    body = (b'\x03\x03' + b'\x00' * 32 + b'\x00' + b'\x00\x02' + b'\x13\x01'
            + b'\x01\x00' + len(extensions).to_bytes(2, 'big') + extensions)
    message = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + len(message).to_bytes(2, 'big') + message

# One allowed request whose query and extra header carry the secret, and
# one denied by the deny rule.
tls_client, _ = connect_head('intercepted.test:443')
client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
client.check_hostname = False
client.verify_mode = ssl.CERT_NONE
client.set_alpn_protocols(['http/1.1'])
tls = client.wrap_socket(tls_client, server_hostname='intercepted.test')
tls.sendall(b'GET /secret?token=sekrit-value HTTP/1.1\r\nHost: intercepted.test\r\nX-Other: sekrit-value\r\n\r\n')
response = b''
while True:
    try:
        chunk = tls.recv(4096)
    except socket.timeout:
        break
    if not chunk:
        break
    response += chunk
tls.close()
good_status = response.split(b'\r\n', 1)[0].decode(errors='replace')

# The denied request rides its own tunnel: the stub upstream speaks HTTP/1.0,
# so the broker ends the first tunnel after one exchange.
tls_client, _ = connect_head('intercepted.test:443')
tls = client.wrap_socket(tls_client, server_hostname='intercepted.test')
tls.sendall(b'GET /private HTTP/1.1\r\nHost: intercepted.test\r\n\r\n')
denied = b''
while True:
    try:
        chunk = tls.recv(4096)
    except socket.timeout:
        break
    if not chunk:
        break
    denied += chunk
tls.close()

# The fronted probe: a raw ClientHello naming another host.
evil_client, _ = connect_head('intercepted.test:443')
evil_client.sendall(client_hello('evil.test'))
evil_client.close()

# The last probe's decisions are written by the time the signal lands.
time.sleep(0.3)
os.kill(broker.pid, signal.SIGTERM)
broker.wait()
counts_text = broker.stdout.read().decode().strip()
log_lines = open(log_path).read().splitlines()
print(json.dumps({
    'good_status': good_status,
    'counts': counts_text,
    'log': log_lines,
}), flush=True)
server.shutdown()
"#
    .to_string()
}
