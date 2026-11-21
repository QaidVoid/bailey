//! The CONNECT tunnel: the host-level ACL, the ClientHello check, the
//! checked dial, and TLS termination for intercepted hosts.
//!
//! Tunnelling stays host-level: a CONNECT is decided on its
//! authority alone, before anything is resolved. A host the intercept list
//! covers is terminated: the broker holds the run's CA,
//! answers the target's TLS with a leaf for the CONNECT name and `http/1.1`
//! alone, and opens the upstream TLS session itself with the host's roots,
//! also `http/1.1` alone, once the first request passes the ACL. Any other
//! host is spliced: the TLS session after the 200 is the client's own, end
//! to end, with the ClientHello relayed byte for byte after its server
//! name has been checked against the CONNECT target.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use bailey::broker::BrokerConfig;
use bailey::policy::{request_host, Decision, HttpRequest};
use crate::request;
use crate::response;
use rustls::StreamOwned;
use rustls::pki_types::ServerName;
use rustls::server::ServerConnection;
use rustls::client::ClientConnection;

/// The request head is read before anything is decided, so it is bounded.
const MAX_HEAD: usize = 8 * 1024;

/// The first TLS record, the ClientHello, is bounded the same way. A real
/// one with a full modern cipher list sits well under 4 KiB.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// How long a client may take between bytes while the broker is deciding.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// How long dialling the checked address may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the upstream may sit between bytes once the exchange is under
/// way. Targets that answer late are ordinary here: a model call can think
/// for minutes and a long poll can stay quiet, so the response window is
/// deliberately generous while the dial and the handshake stay tight.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);

/// The authority a CONNECT named, with the default port applied.
struct ConnectRequest {
    host: String,
    port: u16,
}

/// Serve one client connection to the end of its tunnel.
///
/// Every branch that refuses closes the connection after its answer; the
/// counts and the log line are the caller's business.
pub fn handle_connection(
    stream: TcpStream,
    config: &BrokerConfig,
    authority: &Option<crate::tls::CertificateAuthority>,
) {
    if let Err(error) = serve(stream, config, authority) {
        // A client that vanishes mid-handshake is ordinary; report only
        // what a run could act on.
        if error.kind() != io::ErrorKind::UnexpectedEof
            && error.kind() != io::ErrorKind::ConnectionReset
            && error.kind() != io::ErrorKind::TimedOut
            && error.kind() != io::ErrorKind::WouldBlock
        {
            eprintln!("bailey-broker: connection: {error}");
        }
    }
}

fn serve(
    mut client: TcpStream,
    config: &BrokerConfig,
    authority: &Option<crate::tls::CertificateAuthority>,
) -> io::Result<()> {
    client.set_read_timeout(Some(HEAD_TIMEOUT))?;
    client.set_nodelay(true).ok();

    let head = match read_head(&mut client) {
        Ok(head) => head,
        // A client that sends no head at all gets no answer, whether it
        // hung up or only went quiet.
        Err(error)
            if error.kind() == io::ErrorKind::UnexpectedEof
                || error.kind() == io::ErrorKind::TimedOut
                || error.kind() == io::ErrorKind::WouldBlock =>
        {
            return Err(error);
        }
        // An oversized head is a refusal like any other.
        Err(error) => {
            write_answer(
                &mut client,
                "403 Forbidden",
                &format!("bailey: {error}\r\n"),
            )?;
            return Ok(());
        }
    };
    let request = match parse_connect(&head) {
        Ok(Some(request)) => request,
        // Any other request line: a cleartext proxy request in absolute
        // form, served with the same codec and rules.
        Ok(None) => return serve_cleartext(client, head, config),
        Err(error) => {
            write_answer(
                &mut client,
                "403 Forbidden",
                &format!("bailey: {error}\r\n"),
            )?;
            return Ok(());
        }
    };
    let source = config
        .http
        .source
        .clone()
        .unwrap_or_else(|| "the policy".to_string());
    let host = request.host.as_str();
    match config.http.decide_connect(host, request.port) {
        Decision::Denied(rule) => {
            write_answer(
                &mut client,
                "403 Forbidden",
                &format!(
                    "bailey: CONNECT {} denied by deny rule {} in {}\r\n",
                    host,
                    rule_index(config, rule),
                    source
                ),
            )?;
            return Ok(());
        }
        Decision::Refused => {
            write_answer(
                &mut client,
                "403 Forbidden",
                &format!("bailey: CONNECT {} denied: no rule allows it\r\n", host),
            )?;
            return Ok(());
        }
        Decision::Allowed(_) => {}
    }

    // The tunnel is granted on the name. The ClientHello must agree with it
    // before anything is resolved: a target that fronted another host
    // through this one gets a closed connection, and costs the broker
    // neither a DNS query nor an upstream dial.
    write_answer(&mut client, "200 Connection established", "")?;
    let hello = read_client_hello(&mut client)?;
    let granted_ok = hello_server_name(&hello).is_some_and(|name| name.eq_ignore_ascii_case(host));
    if !granted_ok {
        return Ok(());
    }

    // An intercepted host is terminated, not spliced: the broker holds the
    // run's CA, answers the target's TLS itself, and opens the upstream TLS
    // session once the first request passes the ACL. The
    // upstream is not even resolved until then.
    if let Some(ca) = authority.as_ref().filter(|ca| ca.is_intercepted(host)) {
        return terminate(client, hello, config, ca, host, request.port);
    }

    // One resolution, after the ACL and the SNI agree. The addresses it
    // returns are filtered, and the first survivor is dialled; the name is
    // never resolved again.
    let addresses = (host, request.port).to_socket_addrs()?;
    let checked = addresses.map(|address| address.ip()).find(|ip| is_dialable(*ip));
    let Some(ip) = checked else {
        // A name that resolves only to addresses the broker refuses ends
        // the tunnel.
        return Ok(());
    };
    let address = std::net::SocketAddr::new(ip, request.port);
    let mut upstream = TcpStream::connect_timeout(&address, DIAL_TIMEOUT)?;
    upstream.set_nodelay(true).ok();
    upstream.set_read_timeout(None).ok();
    client.set_read_timeout(None).ok();

    // The ClientHello was buffered, not interpreted beyond its server name:
    // it goes upstream byte for byte, and the tunnel is the client's and
    // the upstream's from here.
    upstream.write_all(&hello)?;
    upstream.flush()?;

    relay(client, upstream);
    Ok(())
}

/// Terminate an intercepted tunnel: answer the target's TLS with a leaf for
/// the CONNECT name, decide the first request, and open the upstream TLS
/// session with the host's roots.
///
/// Both legs speak `http/1.1` alone, by ALPN. A target whose ClientHello
/// named another host never reaches this function: the SNI check above ends
/// the connection first. Anything that goes wrong inside the target's
/// handshake closes the connection like a splice-path refusal does.
fn terminate(
    client: TcpStream,
    hello: Vec<u8>,
    config: &BrokerConfig,
    ca: &crate::tls::CertificateAuthority,
    host: &str,
    port: u16,
) -> io::Result<()> {
    let server_config = ca
        .server_config(host)
        .map_err(|error| io::Error::other(format!("the leaf for `{host}`: {error}")))?;
    let mut conn = ServerConnection::new(server_config)
        .map_err(|error| io::Error::other(format!("the target's TLS: {error}")))?;
    // The ClientHello left the socket before the SNI check; the session
    // takes it as its first record.
    if conn.read_tls(&mut &hello[..]).is_err() {
        return Ok(());
    }
    if conn.process_new_packets().is_err() {
        return Ok(());
    }
    let mut client_tls = StreamOwned::new(conn, client);

    // Requests are served one at a time on this TLS session. Each gets its
    // own upstream session, resolved and dialled only after the request
    // passed; the response is read with its own state
    // machine, and the connection carries another request only when that
    // response was framed and neither side asked to close.
    loop {
        let mut head = match request::read_request(&mut client_tls, request::Form::Origin) {
            Ok(head) => head,
            // The target is done, or has simply gone quiet on a keep-alive
            // connection; neither is a request to refuse, so the
            // connection ends without an answer.
            Err(request::RequestError::Eof) => break,
            Err(request::RequestError::TimedOut) => break,
            Err(error) => {
                write_answer(&mut client_tls, "403 Forbidden", &format!("{error}\r\n"))?;
                break;
            }
        };
        if let Err(error) = head.check_host(host, port, 443) {
            write_answer(&mut client_tls, "403 Forbidden", &format!("{error}\r\n"))?;
            break;
        }
        let acl_request = HttpRequest {
            host,
            port,
            method: &head.method,
            path: head.acl_path(),
        };
        match config.http.decide(&acl_request) {
            Decision::Denied(rule) => {
                write_answer(
                    &mut client_tls,
                    "403 Forbidden",
                    &format!(
                        "bailey: {} {} denied by deny rule {}\r\n",
                        head.method,
                        head.acl_path(),
                        rule_index(config, rule)
                    ),
                )?;
                break;
            }
            Decision::Refused => {
                write_answer(
                    &mut client_tls,
                    "403 Forbidden",
                    &format!(
                        "bailey: {} {} denied: no rule allows it\r\n",
                        head.method,
                        head.acl_path()
                    ),
                )?;
                break;
            }
            Decision::Allowed(_) => {}
        }
        // A non-canonical path is refused: there is one form to reason
        // about, and what reaches the upstream is what the rule matched.
        if !bailey::policy::is_canonical_path(head.acl_path()) {
            write_answer(
                &mut client_tls,
                "403 Forbidden",
                &format!("bailey: the path {} is not canonical\r\n", head.acl_path()),
            )?;
            break;
        }

        // The credential rides only a passed request on an intercepted
        // host, upstream over TLS, and replaces every header of the same
        // name the target sent.
        if let Some(credential) = config.credential_for(host) {
            let (name, value) = attached_header(credential);
            head.attach_header(name, &value);
        }

        // Upstream TLS with the host's roots, `http/1.1` offered alone,
        // the certificate verified for the CONNECT name. The
        // dial happens per request, after the request passed.
        let addresses = (host, port).to_socket_addrs()?;
        let Some(ip) =
            addresses.map(|address| address.ip()).find(|ip| is_dialable(*ip))
        else {
            // A name that resolves only to addresses the broker refuses
            // ends the tunnel.
            break;
        };
        let upstream = TcpStream::connect_timeout(
            &std::net::SocketAddr::new(ip, port),
            DIAL_TIMEOUT,
        )?;
        upstream.set_nodelay(true).ok();
        let client_config = crate::tls::upstream_config()
            .map_err(|error| io::Error::other(format!("the host's trust roots: {error}")))?;
        let name = if let Ok(ip) = host.parse::<IpAddr>() {
            ServerName::IpAddress(ip.into())
        } else {
            ServerName::try_from(host.to_string())
                .map_err(|_| io::Error::other("the CONNECT host is not a TLS name"))?
        };
        let conn = ClientConnection::new(client_config, name)
            .map_err(|error| io::Error::other(format!("the upstream TLS: {error}")))?;
        let mut upstream_tls = StreamOwned::new(conn, upstream);
        upstream_tls.sock.set_write_timeout(Some(DIAL_TIMEOUT))?;
        upstream_tls.sock.set_read_timeout(Some(DIAL_TIMEOUT))?;
        // The handshake runs under the dial timeout, driven to completion
        // here rather than riding the first request byte, and the exchange
        // then gets the response window for its reads.
        while upstream_tls.conn.is_handshaking() {
            upstream_tls.conn.complete_io(&mut upstream_tls.sock)?;
        }
        upstream_tls.sock.set_read_timeout(Some(RESPONSE_TIMEOUT))?;

        // The serialised head, then the body under its own framing: a
        // chunked body is re-encoded without its extensions, a length body
        // copied for exactly its length. A body that ends early aborts the
        // connection: neither side sees a complete exchange.
        let forwarded = head.serialise(host, port, 443);
        upstream_tls.write_all(&forwarded)?;
        if request::relay_body(&mut client_tls, &mut upstream_tls, head.body).is_err() {
            abort(&mut client_tls, &mut upstream_tls);
            return Ok(());
        }

        // The response, one interim at a time until the final one, relayed
        // under its own state machine.
        let keep_alive;        loop {
            match response::read_step(&mut upstream_tls, &head.method) {
                Ok(response::Step::Interim(raw)) => {
                    if client_tls.write_all(&raw).is_err() {
                        abort(&mut client_tls, &mut upstream_tls);
                        return Ok(());
                    }
                }
                Ok(response::Step::Final(answer)) => {
                    if client_tls.write_all(&answer.serialise()).is_err() {
                        abort(&mut client_tls, &mut upstream_tls);
                        return Ok(());
                    }
                    if response::relay_body(&mut upstream_tls, &mut client_tls, answer.body)
                        .is_err()
                    {
                        // A truncation is passed on as an aborted
                        // connection: no final chunk, no close notice. A
                        // TCP end without a close notice is one: rustls
                        // reports it instead of a clean end.
                        abort(&mut client_tls, &mut upstream_tls);
                        return Ok(());
                    }
                    keep_alive = answer.keep_alive(head.client_close);
                    break;
                }
                // An ambiguous or unreadable response closes both sides.
                Err(_) => {
                    abort(&mut client_tls, &mut upstream_tls);
                    return Ok(());
                }
            }
        }
        // The upstream session ends with the response; a fresh one serves
        // the next request.
        drop(upstream_tls);
        if !keep_alive {
            break;
        }
    }
    // A clean end for the target: a close notice, then the connection.
    client_tls.conn.send_close_notify();
    let _ = io::Write::flush(&mut client_tls);
    Ok(())
}

/// Serve one cleartext proxy connection: absolute-form requests under the
/// same codec and rules as a tunnel, one checked authority
/// taken from the request-target, `Host` agreement, and forwarding in
/// origin form with a `Host` the broker writes.
///
/// Requests are served one at a time on this connection. Each gets its own
/// upstream connection, resolved and dialled only after the request
/// passed; the response is read with its own state machine, and the
/// connection carries another request only when that response was framed
/// and neither side asked to close.
fn serve_cleartext(
    mut client: TcpStream,
    first_head: String,
    config: &BrokerConfig,
) -> io::Result<()> {
    let mut first_head = Some(first_head);
    loop {
        let head = match first_head.take() {
            Some(head) => request::parse_checked(&head, request::Form::Absolute),
            None => request::read_request(&mut client, request::Form::Absolute),
        };
        let head = match head {
            Ok(head) => head,
            // The client is done, or idling past the head timeout on a
            // keep-alive connection; neither is a request to refuse.
            Err(request::RequestError::Eof) => break,
            Err(request::RequestError::TimedOut) => break,
            Err(error) => {
                write_answer(&mut client, "403 Forbidden", &format!("{error}\r\n"))?;
                break;
            }
        };
        let Some((raw_host, port)) = head.authority.clone() else {
            break;
        };
        let host = match request_host(&raw_host) {
            Some(host) => host,
            None => {
                write_answer(
                    &mut client,
                    "403 Forbidden",
                    "bailey: the request's authority is not a servable name\r\n",
                )?;
                break;
            }
        };
        if let Err(error) = head.check_host(&host, port, 80) {
            write_answer(&mut client, "403 Forbidden", &format!("{error}\r\n"))?;
            break;
        }
        let acl_request = HttpRequest {
            host: &host,
            port,
            method: &head.method,
            path: head.acl_path(),
        };
        match config.http.decide(&acl_request) {
            Decision::Denied(rule) => {
                write_answer(
                    &mut client,
                    "403 Forbidden",
                    &format!(
                        "bailey: {} {} denied by deny rule {}\r\n",
                        head.method,
                        head.acl_path(),
                        rule_index(config, rule)
                    ),
                )?;
                break;
            }
            Decision::Refused => {
                write_answer(
                    &mut client,
                    "403 Forbidden",
                    &format!(
                        "bailey: {} {} denied: no rule allows it\r\n",
                        head.method,
                        head.acl_path()
                    ),
                )?;
                break;
            }
            Decision::Allowed(_) => {}
        }
        // A non-canonical path is refused: there is one form to reason
        // about, and what reaches the upstream is what the rule matched.
        if !bailey::policy::is_canonical_path(head.acl_path()) {
            write_answer(
                &mut client,
                "403 Forbidden",
                &format!("bailey: the path {} is not canonical\r\n", head.acl_path()),
            )?;
            break;
        }

        // A cleartext request to a host with a credential is refused: the
        // value never rides an unencrypted leg.
        if config.credential_for(&host).is_some() {
            write_answer(
                &mut client,
                "403 Forbidden",
                &format!(
                    "bailey: {} {} refused: a credential is bound to {host}, \
                     which is served over TLS only\r\n",
                    head.method,
                    head.acl_path()
                ),
            )?;
            break;
        }

        // The upstream connection, resolved and dialled only after the
        // request passed.
        let addresses = (host.as_str(), port).to_socket_addrs()?;
        let Some(ip) =
            addresses.map(|address| address.ip()).find(|ip| is_dialable(*ip))
        else {
            // A name that resolves only to addresses the broker refuses
            // ends the connection.
            break;
        };
        let mut upstream = TcpStream::connect_timeout(
            &std::net::SocketAddr::new(ip, port),
            DIAL_TIMEOUT,
        )?;
        upstream.set_nodelay(true).ok();
        upstream.set_write_timeout(Some(DIAL_TIMEOUT))?;
        upstream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;

        // The origin-form head with the broker's `Host`, then the body
        // under its own framing. A body that ends early aborts the
        // connection: neither side sees a complete exchange.
        let forwarded = head.serialise(&host, port, 80);
        upstream.write_all(&forwarded)?;
        if request::relay_body(&mut client, &mut upstream, head.body).is_err() {
            abort_plain(&mut client, &mut upstream);
            return Ok(());
        }

        // The response, one interim at a time until the final one, relayed
        // under its own state machine.
        let keep_alive;
        loop {
            match response::read_step(&mut upstream, &head.method) {
                Ok(response::Step::Interim(raw)) => {
                    if client.write_all(&raw).is_err() {
                        abort_plain(&mut client, &mut upstream);
                        return Ok(());
                    }
                }
                Ok(response::Step::Final(answer)) => {
                    if client.write_all(&answer.serialise()).is_err() {
                        abort_plain(&mut client, &mut upstream);
                        return Ok(());
                    }
                    if response::relay_body(&mut upstream, &mut client, answer.body).is_err() {
                        // A truncation is passed on as an aborted
                        // connection: no final chunk, no clean end.
                        abort_plain(&mut client, &mut upstream);
                        return Ok(());
                    }
                    keep_alive = answer.keep_alive(head.client_close);
                    break;
                }
                // An ambiguous or unreadable response closes both sides.
                Err(_) => {
                    abort_plain(&mut client, &mut upstream);
                    return Ok(());
                }
            }
        }
        // The upstream connection ends with the response; a fresh one
        // serves the next request.
        drop(upstream);
        if !keep_alive {
            break;
        }
    }
    Ok(())
}

/// End an exchange that must look incomplete to the client: the sockets
/// close with nothing framed after what already travelled.
fn abort_plain(client: &mut TcpStream, upstream: &mut TcpStream) {
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = upstream.shutdown(std::net::Shutdown::Both);
}

/// End an exchange that must look incomplete to both sides: the sockets
/// close with no TLS close notice on either leg.
fn abort(
    client: &mut StreamOwned<ServerConnection, TcpStream>,
    upstream: &mut StreamOwned<ClientConnection, TcpStream>,
) {
    let _ = client.sock.shutdown(std::net::Shutdown::Both);
    let _ = upstream.sock.shutdown(std::net::Shutdown::Both);
}

/// The header name and value one resolved credential attaches as.
fn attached_header(credential: &bailey::broker::BrokerCredential) -> (&str, String) {
    match &credential.auth {
        bailey::policy::AuthShape::Bearer => ("Authorization", format!("Bearer {}", credential.value)),
        bailey::policy::AuthShape::Header(name) => (name, credential.value.clone()),
    }
}

/// The deny rule's number in the policy, for the refusal line.
fn rule_index(config: &BrokerConfig, rule: &bailey::policy::HttpRule) -> usize {    config
        .http
        .deny
        .iter()
        .position(|listed| std::ptr::eq(listed, rule))
        .map(|at| at + 1)
        .unwrap_or(0)
}

/// Read the request head: to the first empty line, bounded.
fn read_head(client: &mut impl Read) -> io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = client.read(&mut byte)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the client closed before sending a request",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the request head exceeds 8 KiB",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Parse a CONNECT request into the authority the ACL matches, or `None`
/// for any request that is not a CONNECT.
///
/// The authority is `host:port`, with the CONNECT default applied when the
/// port is absent. The host must be a name or address a rule can be written
/// against: lowercase ASCII, no trailing dot, no userinfo.
fn parse_connect(head: &str) -> io::Result<Option<ConnectRequest>> {
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method != "CONNECT" {
        return Ok(None);
    }
    if authority.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the CONNECT authority is missing",
        ));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the request is not HTTP/1.0 or HTTP/1.1",
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let Ok(port) = port.parse::<u16>() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the CONNECT port is not a port",
                ));
            };
            (host.to_string(), port)
        }
        None => {
            if authority.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the CONNECT authority is missing",
                ));
            }
            // No port: the CONNECT default.
            (authority.to_string(), 443)
        }
    };
    let host = request_host(&host).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "the CONNECT host is not a name")
    })?;
    Ok(Some(ConnectRequest { host, port }))
}

/// Write an HTTP answer with a plain-text body, then nothing else.
fn write_answer(client: &mut impl Write, status: &str, body: &str) -> io::Result<()> {
    let answer = if body.is_empty() {
        format!("HTTP/1.1 {status}\r\n\r\n")
    } else {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    client.write_all(answer.as_bytes())?;
    client.flush()
}

/// Read the client's first TLS record, the ClientHello, whole.
///
/// The tunnel was granted on the CONNECT authority and the client is
/// expected to start TLS at once; anything that is not one complete record
/// inside the bound ends the read with an error, and the connection with it.
fn read_client_hello(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    read_exact_bounded(client, &mut header)?;
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if length > MAX_CLIENT_HELLO - header.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the ClientHello exceeds the record bound",
        ));
    }
    let mut record = Vec::with_capacity(header.len() + length);
    record.extend_from_slice(&header);
    let mut body = vec![0u8; length];
    read_exact_bounded(client, &mut body)?;
    record.extend_from_slice(&body);
    Ok(record)
}

fn read_exact_bounded(client: &mut TcpStream, buffer: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = client.read(&mut buffer[filled..])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the client closed mid-flight",
            ));
        }
        filled += read;
    }
    Ok(())
}

/// The server name the ClientHello carries, if it is a well-formed TLS
/// ClientHello with a name of the `host_name` type.
///
/// The parse is bounds-checked throughout and answers `None` for anything
/// it does not recognise: whatever a real TLS stack would reject, this
/// closes before anything is resolved or dialled.
fn hello_server_name(hello: &[u8]) -> Option<String> {
    // Record header: content type, legacy version, length.
    if hello.len() < 5 || hello[0] != 0x16 {
        return None;
    }
    let length = u16::from_be_bytes([hello[3], hello[4]]) as usize;
    let end = 5usize.checked_add(length)?;
    if hello.len() < end {
        return None;
    }
    let message = &hello[5..end];
    // Handshake header: type 1 is ClientHello.
    if message.len() < 4 || message[0] != 0x01 {
        return None;
    }
    let body_length =
        (message[1] as usize) << 16 | (message[2] as usize) << 8 | message[3] as usize;
    let body_end = 4usize.checked_add(body_length)?;
    if message.len() < body_end {
        return None;
    }
    let mut body = &message[4..body_end];
    // Version (2), random (32), then the session id, cipher suites and
    // compression methods, each length-prefixed.
    body = body.get(34..)?;
    let session_length = *body.first()? as usize;
    body = body.get(1 + session_length..)?;
    let suites_length = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?) as usize;
    body = body.get(2 + suites_length..)?;
    let compression_length = *body.first()? as usize;
    body = body.get(1 + compression_length..)?;
    // Extensions, when the ClientHello carries any.
    if body.is_empty() {
        return None;
    }
    let extensions_length = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?) as usize;
    body = body.get(2..)?;
    if body.len() < extensions_length {
        return None;
    }
    let mut extensions = &body[..extensions_length];
    while !extensions.is_empty() {
        if extensions.len() < 4 {
            return None;
        }
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        let length = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        let value = extensions.get(4..4 + length)?;
        if kind == 0x0000 {
            // server_name: a list of (type, name) entries.
            let list_length = u16::from_be_bytes(value.get(0..2)?.try_into().ok()?) as usize;
            let mut entries = value.get(2..2 + list_length)?;
            while !entries.is_empty() {
                if entries.len() < 3 {
                    return None;
                }
                let name_type = entries[0];
                let name_length = u16::from_be_bytes([entries[1], entries[2]]) as usize;
                let name = entries.get(3..3 + name_length)?;
                if name_type == 0x00 {
                    return Some(String::from_utf8_lossy(name).into_owned());
                }
                entries = &entries[3 + name_length..];
            }
            return None;
        }
        extensions = &extensions[4 + length..];
    }
    None
}

/// Whether the broker may dial this address.
///
/// Loopback, unspecified, link-local, multicast and broadcast are refused,
/// in both families and through the IPv4-mapped form. Private ranges are
/// not: a rule naming an internal host is the user's statement.
fn is_dialable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] != 127
                && octets[0] != 0
                && !octets.starts_with(&[169, 254])
                && octets[0] != 224
                && octets != [255, 255, 255, 255]
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // IPv4-mapped addresses answer for the address they carry.
            if segments[0..5].iter().all(|segment| *segment == 0)
                && (segments[5] == 0xffff || segments[5] == 0)
            {
                let mapped = IpAddr::V4(std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    (segments[6] & 0xff) as u8,
                    (segments[7] >> 8) as u8,
                    (segments[7] & 0xff) as u8,
                ));
                return is_dialable(mapped);
            }
            !ip.is_loopback()
                && !ip.is_unspecified()
                && (segments[0] & 0xffc0) != 0xfe80
                && (segments[0] & 0xff00) != 0xff00
        }
    }
}

/// Move bytes both ways until one side ends; both close.
fn relay(client: TcpStream, upstream: TcpStream) {
    let Ok(other_client) = client.try_clone() else {
        return;
    };
    let Ok(mut other_upstream) = upstream.try_clone() else {
        return;
    };
    let client_to_upstream = std::thread::spawn(move || {
        copy_until_eof(other_client, &mut other_upstream);
        let _ = other_upstream.shutdown(std::net::Shutdown::Both);
    });
    let (mut read_upstream, mut write_client) = (upstream, client);
    copy_until_eof(&mut read_upstream, &mut write_client);
    let _ = write_client.shutdown(std::net::Shutdown::Both);
    let _ = client_to_upstream.join();
}

fn copy_until_eof<R: Read, W: Write>(mut reader: R, writer: &mut W) {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if writer.write_all(&buffer[..read]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.flush();
}
