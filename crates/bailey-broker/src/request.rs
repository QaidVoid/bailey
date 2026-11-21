//! The request codec: parse, check, serialise.
//!
//! The broker parses with httparse for tokenisation and applies its own
//! checks on top, then serialises the request it forwards itself, so the
//! upstream receives exactly what was checked: the line, the kept headers
//! with the hop-by-hop ones removed, a `Host` the broker generates from the
//! checked authority, and framing it re-encodes. A request that fails any
//! check names why, and nothing of it is forwarded.

use std::fmt;
use std::io::{self, Read, Write};

/// The request head is read before anything is decided, so it is bounded.
pub const MAX_HEAD: usize = 8 * 1024;

/// The most headers one request may carry.
const MAX_HEADERS: usize = 64;

/// The request-target shape a caller expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Inside a tunnel: the origin form, a path starting with `/`.
    Origin,
    /// On a cleartext proxy connection: the absolute form. The target names
    /// one authority, and the origin form is forwarded in its place.
    Absolute,
}

/// The body framing the request declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// Neither framing header: no body follows the head.
    None,
    /// Exactly one `Content-Length`.
    Length(u64),
    /// `Transfer-Encoding` of exactly `chunked`, re-encoded without
    /// extensions on the way upstream.
    Chunked,
}

/// Why a request was refused. The text is the reason the client sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The request ended before a head arrived: an ordinary end of a
    /// connection, not a refusal.
    Eof,
    /// The client went quiet before a head arrived: an idle keep-alive
    /// connection, not a refusal.
    TimedOut,
    /// The head was cut off, oversized or carried a control character.
    Head(&'static str),
    /// The request line is not an HTTP/1.0 or 1.1 request of the expected
    /// form.
    Line(&'static str),
    /// A header fails the shape checks.
    Header(&'static str),
    /// The body framing is ambiguous or not one the broker re-encodes.
    Framing(&'static str),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            RequestError::Eof => "the request ends before its head",
            RequestError::TimedOut => "the client went quiet before a head arrived",
            RequestError::Head(reason)
            | RequestError::Line(reason)
            | RequestError::Header(reason)
            | RequestError::Framing(reason) => reason,
        };
        write!(f, "bailey: {reason}")
    }
}

/// A parsed, checked request head: the line, the kept headers with the
/// hop-by-hop ones removed, and the declared framing.
#[derive(Debug)]
pub struct RequestHead {
    /// The method, as received.
    pub method: String,
    /// The request-target as forwarded, always in origin form: byte for
    /// byte as received inside a tunnel, and rewritten from the absolute
    /// form the target carried on a cleartext proxy connection.
    pub target: String,
    /// The authority the absolute-form target named, host and port with
    /// the default applied. `None` for origin-form requests, whose
    /// authority is the caller's tunnel.
    pub authority: Option<(String, u16)>,
    /// The request's own version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub version: u8,
    /// Every `Host` the request carried, for the agreement check.
    pub hosts: Vec<Vec<u8>>,
    /// The headers that survive, in their received order, without the
    /// hop-by-hop ones, `Host`, and the framing headers the broker writes
    /// itself.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The declared framing.
    pub body: Body,
    /// The target asked to close the connection after the response: it
    /// named `close`, or spoke HTTP/1.0 without asking to keep the
    /// connection alive.
    pub client_close: bool,
}

impl RequestHead {
    /// The path the rules match: the target up to its query.
    pub fn acl_path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    /// Attach a credential under a header name, replacing every header of
    /// the same name the target sent, whatever its case. The
    /// attached header joins the kept ones in their received order.
    pub fn attach_header(&mut self, name: &str, value: &str) {
        self.headers
            .retain(|(header, _)| !header.eq_ignore_ascii_case(name));
        self.headers
            .push((name.to_owned(), value.as_bytes().to_vec()));
    }

    /// The forwarded request head: the checked line, a `Host` generated
    /// from the checked authority, the kept headers, and the framing the
    /// broker writes itself.
    pub fn serialise(&self, host: &str, port: u16, default_port: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(
            format!(
                "{} {} HTTP/1.{}\r\n",
                self.method, self.target, self.version
            )
            .as_bytes(),
        );
        // The default port may be omitted; anything else names itself.
        if port == default_port {
            out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
        } else {
            out.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
        }
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        match self.body {
            Body::None => {}
            Body::Length(length) => {
                out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
            }
            Body::Chunked => {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// `Host` agreement: exactly one `Host`, equal to the checked authority
    /// in host and port, the default port possibly omitted, and no
    /// userinfo in the authority the request names.
    pub fn check_host(
        &self,
        expected_host: &str,
        expected_port: u16,
        default_port: u16,
    ) -> Result<(), RequestError> {
        if self.hosts.len() != 1 {
            return Err(RequestError::Header(
                "the request carries more than one Host, or none",
            ));
        }
        let value = String::from_utf8_lossy(&self.hosts[0]).into_owned();
        if value.contains('@') {
            return Err(RequestError::Header("the Host authority carries userinfo"));
        }
        let (name, port) = match value.rsplit_once(':') {
            Some((name, port)) => {
                let Ok(port) = port.parse::<u16>() else {
                    return Err(RequestError::Header("the Host port is not a port"));
                };
                (name, Some(port))
            }
            None => (value.as_str(), None),
        };
        if !name.eq_ignore_ascii_case(expected_host) {
            return Err(RequestError::Header(
                "the Host does not agree with the request's authority",
            ));
        }
        if port.unwrap_or(default_port) != expected_port {
            return Err(RequestError::Header(
                "the Host port does not agree with the request's authority",
            ));
        }
        Ok(())
    }
}

/// Read and check one request head from `reader`.
///
/// Everything the codec asks of the line and the headers is checked here:
/// the version, the target form, no fragment, header names and values, no
/// folded lines, no whitespace before a colon, and the framing headers.
/// The `Host` agreement is the head's own, called by the caller with the
/// authority it checked.
pub fn read_request(reader: &mut impl Read, form: Form) -> Result<RequestHead, RequestError> {
    let head = read_head(reader)?;
    parse_checked(&head, form)
}

/// Check and parse a head the caller already read whole.
pub fn parse_checked(head: &str, form: Form) -> Result<RequestHead, RequestError> {
    if head.contains('\0') {
        return Err(RequestError::Head("the request carries NUL"));
    }
    check_lines(head)?;
    parse_request(head, form)
}

/// Read the request head: to the first empty line, bounded.
fn read_head(reader: &mut impl Read) -> Result<String, RequestError> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = match reader.read(&mut byte) {
            Ok(read) => read,
            // A signal that landed on the read is not the client's doing;
            // the byte is still owed.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                return Err(RequestError::TimedOut);
            }
            Err(_) => return Err(RequestError::Head("the request head could not be read")),
        };
        if read == 0 {
            return Err(RequestError::Eof);
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(RequestError::Head("the request head exceeds 8 KiB"));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// The shape checks that run on the raw head before any tokenisation: no
/// folded header line, no whitespace before the colon.
fn check_lines(head: &str) -> Result<(), RequestError> {
    for line in head.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(RequestError::Header("a header line is folded"));
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        if line[..colon].ends_with(' ') || line[..colon].ends_with('\t') {
            return Err(RequestError::Header(
                "a header name is followed by whitespace before the colon",
            ));
        }
    }
    Ok(())
}

/// Tokenise the head with httparse and apply the codec's checks.
fn parse_request(head: &str, form: Form) -> Result<RequestHead, RequestError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = request
        .parse(head.as_bytes())
        .map_err(|error| map_httparse_error(&error))?;
    if parsed.is_partial() {
        return Err(RequestError::Head("the request head is incomplete"));
    }
    let version = match request.version {
        Some(0) => 0,
        Some(1) => 1,
        _ => {
            return Err(RequestError::Line(
                "the request is not HTTP/1.0 or HTTP/1.1",
            ));
        }
    };
    let method = request
        .method
        .ok_or(RequestError::Line("the request line carries no method"))?;
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(RequestError::Line("CONNECT is not served inside a tunnel"));
    }
    let target = request
        .path
        .ok_or(RequestError::Line("the request line carries no target"))?;
    if target.contains('#') {
        return Err(RequestError::Line("the request-target carries a fragment"));
    }
    // The authority an absolute-form target names, and the origin-form
    // target forwarded in its place.
    let mut authority: Option<(String, u16)> = None;
    let target = match form {
        Form::Origin => {
            if !target.starts_with('/') {
                return Err(RequestError::Line(
                    "the request-target is not in origin form",
                ));
            }
            target.to_owned()
        }
        Form::Absolute => {
            let (host, port, path) = split_absolute(target)?;
            authority = Some((host.to_owned(), port));
            path
        }
    };

    let listed = header_list(request.headers);
    // The framing headers are decided here, so the caller sees one answer.
    // A length with a coding is the ambiguity the codec refuses; every
    // other excess count was refused by `framing_of` already.
    let (lengths, codings) = framing_of(&listed)?;
    let body = match (lengths.len(), codings.len()) {
        (0, 0) => Body::None,
        (1, 0) => Body::Length(lengths[0]),
        (0, 1) => Body::Chunked,
        _ => {
            return Err(RequestError::Framing(
                "the request declares both Content-Length and Transfer-Encoding",
            ));
        }
    };

    // A request asking to upgrade is refused before anything is stripped.
    if listed
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
    {
        return Err(RequestError::Header("the request asks to upgrade"));
    }

    // Hop-by-hop: `Connection` and the headers it names, and the fixed
    // list, never travel. The framing headers and `Host` are the broker's
    // own on the way out.
    let mut dropped: Vec<String> = Vec::new();
    for (name, value) in &listed {
        if name.eq_ignore_ascii_case("connection") {
            dropped.extend(
                String::from_utf8_lossy(value)
                    .split(',')
                    .map(|named| named.trim().to_ascii_lowercase())
                    .filter(|named| !named.is_empty()),
            );
        }
    }
    let hop_by_hop = bailey::policy::HOP_BY_HOP_HEADERS;
    let mut hosts = Vec::new();
    let mut kept = Vec::new();
    for (name, value) in listed {
        let lower = name.to_ascii_lowercase();
        if lower == "host" {
            hosts.push(value.clone());
        }
        if hop_by_hop.contains(&lower.as_str()) || dropped.contains(&lower) {
            continue;
        }
        kept.push((name, value));
    }

    // The target's own wish for the connection: `close` wins, `keep-alive`
    // overrides the HTTP/1.0 default.
    let mut client_close = version == 0;
    for value in hosts_connection_values(head) {
        for token in value.split(',') {
            match token.trim().to_ascii_lowercase().as_str() {
                "close" => client_close = true,
                "keep-alive" => client_close = false,
                _ => {}
            }
        }
    }

    Ok(RequestHead {
        method: method.to_owned(),
        target,
        authority,
        version,
        hosts,
        headers: kept,
        body,
        client_close,
    })
}

/// Split an absolute-form target into the authority it names, host and
/// port with the default applied, and the origin-form target forwarded in
/// its place. A target that names no path names the root; a query with no
/// path joins the root.
fn split_absolute(target: &str) -> Result<(&str, u16, String), RequestError> {
    let Some(rest) = target.strip_prefix("http://") else {
        return Err(RequestError::Line("the request-target does not name http"));
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(RequestError::Line(
            "the request-target carries no authority",
        ));
    }
    if authority.contains('@') {
        return Err(RequestError::Line("the request-target carries userinfo"));
    }
    let (host, port) = if authority.starts_with('[') {
        // A bracketed literal keeps its brackets: they belong to the name
        // the `Host` is regenerated with and the address is dialled by.
        let Some(end) = authority.find(']') else {
            return Err(RequestError::Line("the request-target host is not a host"));
        };
        if end == 1 {
            return Err(RequestError::Line("the request-target host is not a host"));
        }
        (&authority[..=end], authority[end + 1..].strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(RequestError::Line(
            "the request-target carries no authority",
        ));
    }
    let port = match port {
        None => 80,
        Some("") => return Err(RequestError::Line("the request-target port is not a port")),
        Some(port) => port
            .parse::<u16>()
            .map_err(|_| RequestError::Line("the request-target port is not a port"))?,
    };
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    Ok((host, port, path))
}

/// The values of every `Connection` header in the raw head, for the
/// target's keep-alive wish, which the strip below removes.
fn hosts_connection_values(head: &str) -> Vec<String> {
    head.lines()
        .filter_map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("connection")
                .then(|| value.trim().to_owned())
        })
        .collect()
}

fn map_httparse_error(error: &httparse::Error) -> RequestError {
    match error {
        httparse::Error::TooManyHeaders => {
            RequestError::Header("the request carries too many headers")
        }
        httparse::Error::Version => RequestError::Line("the request is not HTTP/1.0 or HTTP/1.1"),
        httparse::Error::Token | httparse::Error::HeaderName | httparse::Error::HeaderValue => {
            RequestError::Header("a header name or value is not well formed")
        }
        httparse::Error::NewLine => RequestError::Head("a line of the request head ends badly"),
        httparse::Error::Status => RequestError::Line("the request line is not a request line"),
    }
}

/// The headers as name, value pairs, values as raw bytes.
fn header_list(headers: &[httparse::Header<'_>]) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .map(|header| (header.name.to_owned(), header.value.to_vec()))
        .collect()
}

/// The `Content-Length` values and `Transfer-Encoding` codings, refused if
/// either repeats or is not a plain number or coding list.
fn framing_of(headers: &[(String, Vec<u8>)]) -> Result<(Vec<u64>, Vec<String>), RequestError> {
    let mut lengths = Vec::new();
    let mut codings = Vec::new();
    for (name, value) in headers {
        let value = String::from_utf8_lossy(value);
        if name.eq_ignore_ascii_case("content-length") {
            for part in value.split(',') {
                let Ok(length) = part.trim().parse::<u64>() else {
                    return Err(RequestError::Framing(
                        "the Content-Length is not a plain number",
                    ));
                };
                lengths.push(length);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            for part in value.split(',') {
                codings.push(part.trim().to_owned());
            }
        }
    }
    if lengths.len() > 1 {
        return Err(RequestError::Framing(
            "the request carries more than one Content-Length",
        ));
    }
    // Exactly `chunked`, one coding, however many headers named it.
    if codings.len() > 1
        || codings
            .first()
            .is_some_and(|coding| !coding.eq_ignore_ascii_case("chunked"))
    {
        return Err(RequestError::Framing(
            "the transfer coding is not exactly chunked",
        ));
    }
    Ok((lengths, codings))
}

/// Relay a request body from `reader` to `writer`, following the framing
/// the head declared.
///
/// A length body is copied for exactly its length; a chunked body is
/// decoded and re-encoded without its chunk extensions, and a non-empty
/// trailer refuses the relay. Anything short of the declared end is an
/// error, which the caller turns into an aborted connection.
pub fn relay_body(reader: &mut impl Read, writer: &mut impl Write, body: Body) -> io::Result<()> {
    match body {
        Body::None => Ok(()),
        Body::Length(length) => {
            let mut remaining = length;
            let mut buffer = [0u8; 16 * 1024];
            while remaining > 0 {
                let want = buffer.len().min(remaining as usize);
                let read = reader.read(&mut buffer[..want])?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "bailey: the request body ended before its Content-Length",
                    ));
                }
                writer.write_all(&buffer[..read])?;
                remaining -= read as u64;
            }
            Ok(())
        }
        Body::Chunked => relay_chunked(reader, writer),
    }
}

/// Decode a chunked body and re-encode it without chunk extensions.
fn relay_chunked(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<()> {
    loop {
        let line = read_line(reader)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_text, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "bailey: a chunk size is not a size",
            )
        })?;
        if size == 0 {
            // The trailer section: every line before the empty one is a
            // trailer, and a trailer is a refusal. With none, the broker
            // writes the terminating chunk itself.
            if !read_line(reader)?.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bailey: a chunked body carries a trailer",
                ));
            }
            writer.write_all(b"0\r\n\r\n")?;
            return Ok(());
        }
        writer.write_all(format!("{size:x}\r\n").as_bytes())?;
        let mut remaining = size;
        let mut buffer = [0u8; 16 * 1024];
        while remaining > 0 {
            let want = buffer.len().min(remaining as usize);
            let read = reader.read(&mut buffer[..want])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "bailey: a chunked body ended mid-chunk",
                ));
            }
            writer.write_all(&buffer[..read])?;
            remaining -= read as u64;
        }
        // The CRLF after the chunk data.
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bailey: a chunk is not followed by CRLF",
            ));
        }
        writer.write_all(b"\r\n")?;
    }
}

/// One CRLF-terminated line, bounded, without its line ending.
fn read_line(reader: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = reader.read(&mut byte)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "bailey: the body ends mid-line",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bailey: a body line exceeds the bound",
            ));
        }
    }
    let mut text = String::from_utf8_lossy(&line).into_owned();
    if text.ends_with('\r') {
        text.pop();
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a head from its bytes, in origin form.
    fn parse(head: &str) -> Result<RequestHead, RequestError> {
        let mut reader = head.as_bytes();
        read_request(&mut reader, Form::Origin)
    }

    fn parse_ok(head: &str) -> RequestHead {
        parse(head).unwrap_or_else(|error| panic!("{head:?} refused: {error}"))
    }

    fn refused(head: &str) -> RequestError {
        parse(head)
            .map(|_| panic!("{head:?} was accepted"))
            .unwrap_err()
    }

    /// The corpus of request smuggles the codec refuses, one refusal per
    /// case. Each refusal names its layer, except the two legacy-line
    /// cases, where any refusal is the point.
    #[test]
    fn the_smuggling_corpus_is_refused() {
        let base = "Host: example.com\r\n";
        let cases: [(String, Option<&str>); 13] = [
            // Content-Length together with Transfer-Encoding.
            (
                format!(
                    "POST /x HTTP/1.1\r\n{base}Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                ),
                Some("both Content-Length and Transfer-Encoding"),
            ),
            // A repeated Content-Length, even with the same value.
            (
                format!("POST /x HTTP/1.1\r\n{base}Content-Length: 5\r\nContent-Length: 5\r\n\r\n"),
                Some("more than one Content-Length"),
            ),
            // A transfer coding list is not exactly chunked.
            (
                format!("POST /x HTTP/1.1\r\n{base}Transfer-Encoding: gzip, chunked\r\n\r\n"),
                Some("not exactly chunked"),
            ),
            // A folded header line.
            (
                format!("GET /x HTTP/1.1\r\n{base}X-A: 1\r\n\tmore\r\n\r\n"),
                Some("folded"),
            ),
            // Whitespace before the colon.
            (
                "GET /x HTTP/1.1\r\nHost : example.com\r\n\r\n".to_string(),
                Some("whitespace before the colon"),
            ),
            // A bare CR inside the head.
            (
                format!("GET /x HTTP/1.1\rX-Bad: 1\r\n{base}\r\n"),
                Some("ends badly"),
            ),
            // A NUL in a header value.
            (
                format!("GET /x HTTP/1.1\r\nX-Bad: a\0b\r\n{base}\r\n"),
                Some("NUL"),
            ),
            // HTTP/0.9.
            ("GET /\r\n\r\n".to_string(), None),
            // HTTP/2.0.
            (format!("GET / HTTP/2.0\r\n{base}\r\n"), None),
            // A fragment in the target.
            (
                format!("GET /x#frag HTTP/1.1\r\n{base}\r\n"),
                Some("fragment"),
            ),
            // An absolute-form target inside a tunnel.
            (
                format!("GET http://example.com/x HTTP/1.1\r\n{base}\r\n"),
                Some("origin form"),
            ),
            // CONNECT inside a tunnel.
            (
                format!("CONNECT example.com:443 HTTP/1.1\r\n{base}\r\n"),
                Some("CONNECT"),
            ),
            // An upgrade attempt.
            (
                format!(
                    "GET /x HTTP/1.1\r\n{base}Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                ),
                Some("upgrade"),
            ),
        ];
        for (head, fragment) in cases {
            let error = refused(&head);
            let Some(fragment) = fragment else { continue };
            let text = error.to_string();
            assert!(
                text.contains(fragment),
                "`{fragment}` missing from the refusal for {head:?}: {text}"
            );
        }
    }

    /// A chunked body with a non-empty trailer is refused while the body
    /// is relayed, so the trailer case drives `relay_body`.
    #[test]
    fn a_chunked_trailer_is_refused() {
        let mut reader = "4\r\nwiki\r\n0\r\nX-Trailer: 1\r\n\r\n".as_bytes();
        let mut sink = Vec::new();
        let error = relay_body(&mut reader, &mut sink, Body::Chunked).unwrap_err();
        assert!(error.to_string().contains("trailer"), "{error}");
    }

    /// A chunked body cut short before the final chunk is an error, not a
    /// complete relay.
    #[test]
    fn a_chunked_body_cut_short_is_an_error() {
        let mut reader = "4\r\nwiki".as_bytes();
        let mut sink = Vec::new();
        assert!(relay_body(&mut reader, &mut sink, Body::Chunked).is_err());
    }

    /// A length body cut short is an error.
    #[test]
    fn a_length_body_cut_short_is_an_error() {
        let mut reader = "wel".as_bytes();
        let mut sink = Vec::new();
        assert!(relay_body(&mut reader, &mut sink, Body::Length(5)).is_err());
    }

    /// An accepted request keeps its line, its headers in order, its
    /// framing, and loses exactly the hop-by-hop headers, the ones
    /// `Connection` names included.
    #[test]
    fn an_accepted_request_serialises_exactly() {
        let head = parse_ok(
            "POST /a%20b?q=1 HTTP/1.1\r\n\
             Host: example.com\r\n\
             Connection: keep-alive, X-Secret\r\n\
             Keep-Alive: timeout=5\r\n\
             X-Secret: named by Connection\r\n\
             Proxy-Connection: close\r\n\
             TE: trailers\r\n\
             Accept: text/plain\r\n\
             Content-Length: 5\r\n\r\n",
        );
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/a%20b?q=1");
        assert_eq!(head.acl_path(), "/a%20b");
        assert_eq!(head.body, Body::Length(5));
        let names: Vec<&str> = head.headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["Accept"], "hop-by-hop stripped, order kept");
        let forwarded = String::from_utf8(head.serialise("example.com", 443, 443)).unwrap();
        assert_eq!(
            forwarded,
            "POST /a%20b?q=1 HTTP/1.1\r\n\
             Host: example.com\r\n\
             Accept: text/plain\r\n\
             Content-Length: 5\r\n\
             \r\n"
        );
        assert_eq!(head.authority, None, "origin form names no authority");
    }

    /// An absolute-form request names one authority, and forwards as the
    /// origin-form target with a `Host` the broker writes.
    #[test]
    fn an_absolute_form_request_carries_one_authority() {
        let mut reader =
            "GET http://example.com/x?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();
        let head = read_request(&mut reader, Form::Absolute).unwrap();
        assert_eq!(head.target, "/x?q=1");
        assert_eq!(head.acl_path(), "/x");
        assert_eq!(head.authority, Some(("example.com".to_owned(), 80)));
        let forwarded = String::from_utf8(head.serialise("example.com", 80, 80)).unwrap();
        assert_eq!(
            forwarded,
            "GET /x?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );

        // A non-default port names itself, and a target with no path names
        // the root.
        let mut reader =
            "GET http://example.com:8080 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".as_bytes();
        let head = read_request(&mut reader, Form::Absolute).unwrap();
        assert_eq!(head.target, "/");
        assert_eq!(head.authority, Some(("example.com".to_owned(), 8080)));
        let forwarded = String::from_utf8(head.serialise("example.com", 8080, 80)).unwrap();
        assert_eq!(
            forwarded,
            "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        );

        // An IPv6 literal keeps its brackets, in the authority and in the
        // `Host` agreement.
        let mut reader = "GET http://[::1]:8080/x HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n".as_bytes();
        let head = read_request(&mut reader, Form::Absolute).unwrap();
        assert_eq!(head.authority, Some(("[::1]".to_owned(), 8080)));
        head.check_host("[::1]", 8080, 80).unwrap();
    }

    /// Absolute-form targets that fail the authority checks are refused,
    /// each naming why.
    #[test]
    fn absolute_form_targets_are_checked() {
        for (head, fragment) in [
            (
                "GET https://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "does not name http",
            ),
            (
                "GET http:///x HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "no authority",
            ),
            (
                "GET http://user@example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "userinfo",
            ),
            (
                "GET http://example.com:port/x HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "not a port",
            ),
            (
                "GET http://[::1/x HTTP/1.1\r\nHost: [::1]\r\n\r\n",
                "not a host",
            ),
        ] {
            let mut reader = head.as_bytes();
            let error = read_request(&mut reader, Form::Absolute).unwrap_err();
            assert!(
                error.to_string().contains(fragment),
                "`{fragment}` missing from the refusal for {head:?}: {error}"
            );
        }
    }

    /// A chunked body is re-encoded without its chunk extensions.
    #[test]
    fn a_chunked_body_is_re_encoded_without_extensions() {
        let head =
            parse_ok("PUT /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(head.body, Body::Chunked);
        let forwarded = String::from_utf8(head.serialise("example.com", 443, 443)).unwrap();
        assert!(
            forwarded.contains("Transfer-Encoding: chunked\r\n"),
            "{forwarded}"
        );
        let mut reader = "4;ext=1\r\nwiki\r\n0\r\n\r\n".as_bytes();
        let mut sink = Vec::new();
        relay_body(&mut reader, &mut sink, head.body).unwrap();
        assert_eq!(sink, b"4\r\nwiki\r\n0\r\n\r\n");
    }

    /// `Host` agreement: one `Host`, the tunnel's host, its port or the
    /// default one, no userinfo.
    #[test]
    fn host_agreement_is_checked() {
        let head = |host: &str| parse_ok(&format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"));
        head("example.com").host_ok("example.com", 443);
        head("EXAMPLE.com").host_ok("example.com", 443);
        head("example.com:443").host_ok("example.com", 443);
        head("example.com:8443").host_ok("example.com", 8443);
        for (host, expected, port) in [
            ("other.example", "example.com", 443),
            ("example.com:8443", "example.com", 443),
            ("example.com", "example.com", 8443),
            ("user@example.com", "example.com", 443),
            ("example.com:70000", "example.com", 443),
        ] {
            let error = head(host).host_refused(expected, port);
            assert!(error.to_string().contains("Host"), "{error}");
        }
        // Two Host headers are refused by the agreement check, not the
        // parse.
        let two_hosts = parse("GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n")
            .map(|head| head.check_host("example.com", 443, 443).is_err())
            .unwrap_or(true);
        assert!(two_hosts, "two Host headers were accepted");
        // No Host header at all is refused the same way.
        let no_host = parse("GET / HTTP/1.1\r\nAccept: x\r\n\r\n")
            .map(|head| head.check_host("example.com", 443, 443).is_err())
            .unwrap_or(true);
        assert!(no_host, "a request without Host was accepted");
    }

    /// A request with no body serialises with no framing header.
    #[test]
    fn a_bodyless_request_carries_no_framing_header() {
        let head = parse_ok("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(head.body, Body::None);
        let forwarded = String::from_utf8(head.serialise("example.com", 443, 443)).unwrap();
        assert!(!forwarded.contains("Content-Length"));
        assert!(!forwarded.contains("Transfer-Encoding"));
    }

    /// The forwarded `Host` carries the port when it is not the default.
    #[test]
    fn a_non_default_port_is_named_in_the_forwarded_host() {
        let head = parse_ok("GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n");
        let forwarded = String::from_utf8(head.serialise("example.com", 8443, 443)).unwrap();
        assert!(forwarded.starts_with("GET / HTTP/1.1\r\nHost: example.com:8443\r\n"));
    }

    /// An oversized head is refused, whatever its shape.
    #[test]
    fn an_oversized_head_is_refused() {
        let padded = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nX-Pad: {}\r\n\r\n",
            "x".repeat(8 * 1024)
        );
        assert_eq!(
            refused(&padded),
            RequestError::Head("the request head exceeds 8 KiB")
        );
    }

    /// Paths are matched with the same canonical check the rules use.
    #[test]
    fn paths_are_checked_with_the_policy_check() {
        for path in ["/admin", "/a%20b?q=1", "/deep/path"] {
            assert!(bailey::policy::is_canonical_path(path), "{path}");
        }
        for path in ["/%61dmin", "/a/../b", "//x", "/a\\b"] {
            assert!(!bailey::policy::is_canonical_path(path), "{path}");
        }
    }

    /// An attachment replaces every header of the same name the target
    /// sent, whatever its case, and leaves the neighbours alone.
    #[test]
    fn an_attachment_replaces_the_same_named_headers() {
        let mut head = parse_ok(
            "GET /ok HTTP/1.1\r\n\
             Host: x.test\r\n\
             authorization: attacker\r\n\
             AUTHORIZATION: again\r\n\
             X-Trail: kept\r\n\r\n",
        );
        head.attach_header("Authorization", "Bearer secret");
        let forwarded = String::from_utf8(head.serialise("x.test", 443, 443)).unwrap();
        assert!(
            forwarded.contains("Authorization: Bearer secret\r\n"),
            "{forwarded}"
        );
        assert!(!forwarded.contains("attacker"), "{forwarded}");
        assert!(!forwarded.contains("again"), "{forwarded}");
        assert!(forwarded.contains("X-Trail: kept\r\n"), "{forwarded}");
        assert_eq!(
            forwarded.matches("uthorization").count(),
            1,
            "exactly one authorization header remains: {forwarded}"
        );
    }

    impl RequestHead {
        fn host_ok(&self, host: &str, port: u16) {
            self.check_host(host, port, 443)
                .unwrap_or_else(|error| panic!("`Host: {host}` refused: {error}"));
        }

        fn host_refused(&self, host: &str, port: u16) -> RequestError {
            match self.check_host(host, port, 443) {
                Ok(()) => panic!("`Host` agreed with {host}:{port}"),
                Err(error) => error,
            }
        }
    }
    /// A reader that goes quiet is how a keep-alive connection idles: the
    /// read times out, and no request ever arrived. The error must say so,
    /// because a timeout is not a request to refuse, and the connection
    /// should end without an answer.
    struct GoesQuiet;

    impl Read for GoesQuiet {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }
    }

    #[test]
    fn a_reader_that_goes_quiet_reports_a_timeout() {
        let error = read_request(&mut GoesQuiet, Form::Origin).unwrap_err();
        assert_eq!(error, RequestError::TimedOut);
    }
}
