//! The response state machine.
//!
//! Responses are framed differently from requests: a response to `HEAD`,
//! any interim status, `204` and `304` has no body whatever its headers
//! say, and a response with neither framing header runs until the upstream
//! closes. The broker reads one response per request it forwarded, relays
//! the head and body it can re-encode, and treats every ambiguity and
//! every truncation as an aborted connection, so a client never mistakes
//! an incomplete response for a complete one.

use std::fmt;
use std::io::{Read, Write};

/// A response head is bounded like a request head, a little more generous
/// because servers carry long cookies.
pub const MAX_HEAD: usize = 16 * 1024;

/// The body framing a response declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// No body follows, whatever the headers say.
    None,
    /// `Transfer-Encoding` of exactly `chunked`, re-encoded without
    /// extensions.
    Chunked,
    /// One valid `Content-Length`.
    Length(u64),
    /// Neither framing header: the body runs until the upstream closes,
    /// and the client connection closes with it.
    UntilClose,
}

/// Why a response could not be relayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseError {
    /// The head was cut off, oversized or not a response at all.
    Head(&'static str),
    /// The framing is ambiguous: both sides close rather than relay.
    Framing(&'static str),
    /// The upstream ended before the framing said it could.
    Truncated(&'static str),
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            ResponseError::Head(reason)
            | ResponseError::Framing(reason)
            | ResponseError::Truncated(reason) => reason,
        };
        write!(f, "bailey: {reason}")
    }
}

/// A parsed response head: the final status, the kept headers with the
/// hop-by-hop ones removed, and the framing the broker decided.
#[derive(Debug, PartialEq, Eq)]
pub struct ResponseHead {
    /// The status code of the final response.
    pub status: u16,
    /// The reason phrase as received, possibly empty.
    pub reason: String,
    /// The response's own version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub version: u8,
    /// The headers that survive, in their received order, without the
    /// hop-by-hop ones and without the framing headers the broker writes
    /// itself.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The framing the broker decided from the headers and the request's
    /// method.
    pub body: BodyKind,
    /// The upstream asked to close the connection after the response.
    pub server_close: bool,
}

impl ResponseHead {
    /// Whether the client connection may carry another request after this
    /// response: any framed or bodyless response, with neither side asking
    /// to close. A close-delimited body ends the connection with the
    /// response, so it never carries another.
    pub fn keep_alive(&self, request_close: bool) -> bool {
        !matches!(self.body, BodyKind::UntilClose)
            && !request_close
            && !self.server_close
    }

    /// The forwarded response head: the line as received, the kept
    /// headers, and the framing the broker writes itself. A
    /// close-delimited body carries no framing header: the connection
    /// close that follows is the frame.
    pub fn serialise(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(
            format!("HTTP/1.{} {} {}\r\n", self.version, self.status, self.reason).as_bytes(),
        );
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        match self.body {
            BodyKind::None | BodyKind::UntilClose => {}
            BodyKind::Length(length) => {
                out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
            }
            BodyKind::Chunked => {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

/// Read one step of the response: an interim response to relay, or the
/// final response head.
///
/// `method` is the forwarded request's method, because a response to
/// `HEAD` has no body whatever its headers say. Interim responses are
/// returned as the raw bytes as they arrived, relayed verbatim.
pub fn read_step(reader: &mut impl Read, method: &str) -> Result<Step, ResponseError> {
    let raw = read_head(reader)?;
    let mut headers = [httparse::EMPTY_HEADER; 100];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(raw.as_bytes())
        .map_err(|_| ResponseError::Head("the response head is not a response"))?;
    if parsed.is_partial() {
        return Err(ResponseError::Head("the response head is incomplete"));
    }
    let status = response
        .code
        .ok_or(ResponseError::Head("the response carries no status"))?;
    if (100..200).contains(&status) {
        if status == 101 {
            // Upgrades are refused on the way in; an upstream answering
            // with one anyway cannot be relayed.
            return Err(ResponseError::Head(
                "the upstream answered a protocol upgrade",
            ));
        }
        return Ok(Step::Interim(raw.into_bytes()));
    }
    let version = match response.version {
        Some(0) => 0,
        Some(1) => 1,
        _ => return Err(ResponseError::Head("the response is not HTTP/1.0 or HTTP/1.1")),
    };

    let listed = header_list(response.headers);
    let body = if status == 204 || status == 304 || method.eq_ignore_ascii_case("HEAD") {
        // No body whatever the headers say, and stray length headers in
        // the head are not an ambiguity the broker has to resolve: they
        // frame nothing.
        BodyKind::None
    } else {
        framing_of(&listed)?
    };
    let server_close = asked_close(version, &listed);
    // Hop-by-hop: `Connection` and the headers it names, and the fixed
    // list, never travel. The framing headers are the broker's own, and
    // `Trailer` goes too, because a re-encoded body carries none.
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
    let hop_by_hop = [
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "upgrade",
        "trailer",
        "transfer-encoding",
        "content-length",
    ];
    let kept = listed
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !hop_by_hop.contains(&lower.as_str()) && !dropped.contains(&lower)
        })
        .collect();
    Ok(Step::Final(ResponseHead {
        status,
        reason: response.reason.unwrap_or("").to_owned(),
        version,
        headers: kept,
        body,
        server_close,
    }))
}

/// One step of the response.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// An interim response, relayed verbatim; the final one follows.
    Interim(Vec<u8>),
    /// The final response head.
    Final(ResponseHead),
}

/// Whether the upstream asked to close: `Connection: close`, or an
/// HTTP/1.0 response that did not ask to keep the connection alive.
fn asked_close(version: u8, headers: &[(String, Vec<u8>)]) -> bool {
    let mut close = version == 0;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            for token in String::from_utf8_lossy(value).split(',') {
                match token.trim().to_ascii_lowercase().as_str() {
                    "close" => close = true,
                    "keep-alive" => close = false,
                    _ => {}
                }
            }
        }
    }
    close
}

/// The response framing from its headers, refused where it is ambiguous.
fn framing_of(headers: &[(String, Vec<u8>)]) -> Result<BodyKind, ResponseError> {
    let mut lengths: Vec<u64> = Vec::new();
    let mut codings: Vec<String> = Vec::new();
    for (name, value) in headers {
        let value = String::from_utf8_lossy(value);
        if name.eq_ignore_ascii_case("content-length") {
            for part in value.split(',') {
                let Ok(length) = part.trim().parse::<u64>() else {
                    return Err(ResponseError::Framing(
                        "the response's Content-Length is not a plain number",
                    ));
                };
                lengths.push(length);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            codings.extend(
                value
                    .split(',')
                    .map(|part| part.trim().to_owned())
                    .filter(|part| !part.is_empty()),
            );
        }
    }
    let framed_chunked = codings.len() == 1 && codings[0].eq_ignore_ascii_case("chunked");
    match (lengths.len(), framed_chunked, !codings.is_empty()) {
        (0, false, false) => Ok(BodyKind::UntilClose),
        (0, true, _) => Ok(BodyKind::Chunked),
        (1, false, false) => Ok(BodyKind::Length(lengths[0])),
        _ => Err(ResponseError::Framing(
            "the response's framing is ambiguous or not one the broker re-encodes",
        )),
    }
}

fn header_list(headers: &[httparse::Header<'_>]) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .map(|header| (header.name.to_owned(), header.value.to_vec()))
        .collect()
}

/// Read the response head: to the first empty line, bounded.
fn read_head(reader: &mut impl Read) -> Result<String, ResponseError> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .map_err(|_| ResponseError::Truncated("the response head could not be read"))?;
        if read == 0 {
            return Err(ResponseError::Truncated("the response ends before its head"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(ResponseError::Head("the response head exceeds 16 KiB"));
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Relay a response body from the upstream to the client, following the
/// framing the head decided.
///
/// A chunked body is decoded and re-encoded without extensions, with the
/// terminating chunk the broker writes itself. A length body is copied for
/// exactly its length. A close-delimited body is copied until the upstream
/// ends; a clean end is the body's own frame, so the caller closes the
/// client connection after it. Every truncation is an error, and the
/// caller aborts both sides rather than letting the client believe the
/// response was complete.
pub fn relay_body(
    reader: &mut impl Read,
    writer: &mut impl Write,
    body: BodyKind,
) -> Result<(), ResponseError> {
    match body {
        BodyKind::None => Ok(()),
        BodyKind::Length(length) => {
            let mut remaining = length;
            let mut buffer = [0u8; 16 * 1024];
            while remaining > 0 {
                let want = buffer.len().min(remaining as usize);
                let read = reader
                    .read(&mut buffer[..want])
                    .map_err(|_| ResponseError::Truncated("the upstream failed mid-body"))?;
                if read == 0 {
                    return Err(ResponseError::Truncated(
                        "the upstream ended before the response body it declared",
                    ));
                }
                writer
                    .write_all(&buffer[..read])
                    .map_err(|_| ResponseError::Truncated("the client went away mid-body"))?;
                remaining -= read as u64;
            }
            Ok(())
        }
        BodyKind::Chunked => relay_chunked(reader, writer),
        BodyKind::UntilClose => relay_until_close(reader, writer),
    }
}

/// Decode a chunked body and re-encode it without extensions.
fn relay_chunked(reader: &mut impl Read, writer: &mut impl Write) -> Result<(), ResponseError> {
    loop {
        let line = read_line(reader)?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_text, 16).map_err(|_| {
            ResponseError::Framing("a chunk size in the response is not a size")
        })?;
        if size == 0 {
            // The trailer section belongs to the upstream's own framing
            // and is dropped: the re-encoded body ends with the
            // terminating chunk alone.
            while !read_line(reader)?.is_empty() {}
            writer
                .write_all(b"0\r\n\r\n")
                .map_err(|_| ResponseError::Truncated("the client went away mid-body"))?;
            return Ok(());
        }
        writer
            .write_all(format!("{size:x}\r\n").as_bytes())
            .map_err(|_| ResponseError::Truncated("the client went away mid-body"))?;
        let mut remaining = size;
        let mut buffer = [0u8; 16 * 1024];
        while remaining > 0 {
            let want = buffer.len().min(remaining as usize);
            let read = reader.read(&mut buffer[..want]).map_err(|_| {
                ResponseError::Truncated("the upstream failed mid-chunk")
            })?;
            if read == 0 {
                return Err(ResponseError::Truncated(
                    "the upstream ended before the last chunk",
                ));
            }
            writer
                .write_all(&buffer[..read])
                .map_err(|_| ResponseError::Truncated("the client went away mid-body"))?;
            remaining -= read as u64;
        }
        // The CRLF after the chunk data.
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|_| ResponseError::Truncated("the upstream ended mid-chunk"))?;
        if &crlf != b"\r\n" {
            return Err(ResponseError::Framing("a chunk is not followed by CRLF"));
        }
        writer
            .write_all(b"\r\n")
            .map_err(|_| ResponseError::Truncated("the client went away mid-body"))?;
    }
}

/// Copy until the upstream ends. A clean end completes the body; an error
/// is a truncation, the client's own signal being the connection that
/// never completed.
fn relay_until_close(
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<(), ResponseError> {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(_) => {
                return Err(ResponseError::Truncated(
                    "the upstream ended the response without completing it",
                ))
            }
        };
        writer
            .write_all(&buffer[..read])
            .map_err(|_| ResponseError::Truncated("the client went away mid-body"))?;
    }
}

/// One CRLF-terminated line, bounded, without its line ending.
fn read_line(reader: &mut impl Read) -> Result<String, ResponseError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .map_err(|_| ResponseError::Truncated("the body ends mid-line"))?;
        if read == 0 {
            return Err(ResponseError::Truncated("the body ends mid-line"));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 1024 {
            return Err(ResponseError::Head("a body line exceeds the bound"));
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
    use std::io;

    /// Parse one final response head out of `raw`, for a `GET`.
    fn final_of(raw: &str) -> ResponseHead {
        final_for("GET", raw)
    }

    /// Parse one final response head out of `raw`, for `method`.
    fn final_for(method: &str, raw: &str) -> ResponseHead {
        match read_step(&mut raw.as_bytes(), method).expect("the response parses") {
            Step::Final(head) => head,
            Step::Interim(_) => panic!("an interim response came back as the final one"),
        }
    }

    /// Parse the steps of a raw response exchange in order.
    fn steps_of(raw: &str) -> Vec<Step> {
        let mut reader = raw.as_bytes();
        let mut steps = Vec::new();
        while let Ok(step) = read_step(&mut reader, "GET") {
            steps.push(step);
        }
        steps
    }

    /// A response to HEAD with a length header frames nothing, and the
    /// connection may carry another request.
    #[test]
    fn a_response_to_head_has_no_body() {
        let head = final_for(
            "HEAD",
            "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n",
        );
        assert_eq!(head.body, BodyKind::None);
        assert!(head.keep_alive(false), "HEAD keeps the connection alive");
        let mut reader = &b""[..];
        assert_eq!(relay_body(&mut reader, &mut Vec::new(), head.body), Ok(()));
    }

    /// 204 and 304 with stray length headers frame nothing.
    #[test]
    fn stray_lengths_on_bodyless_statuses_frame_nothing() {
        for status in ["204 No Content", "304 Not Modified"] {
            let head = final_of(&format!(
                "HTTP/1.1 {status}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
            ));
            assert_eq!(head.body, BodyKind::None, "{status}");
        }
    }

    /// A 100 before the final response is relayed verbatim, and the final
    /// response follows it.
    #[test]
    fn an_interim_response_is_relayed_and_the_final_one_follows() {
        let raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let steps = steps_of(raw);
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0],
            Step::Interim(b"HTTP/1.1 100 Continue\r\n\r\n".to_vec())
        );
        let Step::Final(head) = &steps[1] else {
            panic!("the second step was not final")
        };
        assert_eq!(head.status, 200);
        assert_eq!(head.body, BodyKind::Length(2));
    }

    /// A response with both framing headers closes both sides instead of
    /// relaying an ambiguity, and so does a repeated or invalid
    /// Content-Length.
    #[test]
    fn ambiguous_framing_is_refused() {
        for raw in [
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: five\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        ] {
            let error = match read_step(&mut raw.as_bytes(), "GET") {
                Err(error) => error,
                Ok(_) => panic!("{raw:?} was accepted"),
            };
            assert!(
                matches!(error, ResponseError::Framing(_)),
                "{raw:?}: {error}"
            );
        }
    }

    /// A chunked body is re-encoded without extensions and ends with the
    /// terminating chunk the broker writes.
    #[test]
    fn a_chunked_body_is_re_encoded() {
        let head = final_of("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(head.body, BodyKind::Chunked);
        let mut reader = "4;ext=1\r\nwiki\r\n3\r\nmed\r\n0\r\nX-T: 1\r\n\r\n".as_bytes();
        let mut sink = Vec::new();
        relay_body(&mut reader, &mut sink, head.body).unwrap();
        assert_eq!(sink, b"4\r\nwiki\r\n3\r\nmed\r\n0\r\n\r\n");
        assert!(head.keep_alive(false), "chunked keeps the connection alive");
    }

    /// A length body is copied exactly; an upstream that ends early is a
    /// truncation, never a completion.
    #[test]
    fn a_length_body_is_copied_and_truncation_is_an_error() {
        let head = final_of("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        let mut reader = "hello".as_bytes();
        let mut sink = Vec::new();
        relay_body(&mut reader, &mut sink, head.body).unwrap();
        assert_eq!(sink, b"hello");

        let mut reader = "hel".as_bytes();
        let error = relay_body(&mut reader, &mut Vec::new(), head.body).unwrap_err();
        assert!(matches!(error, ResponseError::Truncated(_)), "{error}");
    }

    /// A chunked body cut short before the last chunk is a truncation.
    #[test]
    fn a_chunked_body_cut_short_is_a_truncation() {
        let head = final_of("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        let mut reader = "4\r\nwiki".as_bytes();
        let error = relay_body(&mut reader, &mut Vec::new(), head.body).unwrap_err();
        assert!(matches!(error, ResponseError::Truncated(_)), "{error}");
    }

    /// A close-delimited body completes on a clean end of the upstream,
    /// and its truncation is an error. The connection cannot carry another
    /// request after it.
    #[test]
    fn a_close_delimited_body_ends_with_the_connection() {
        let head = final_of("HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(head.body, BodyKind::UntilClose);
        assert!(!head.keep_alive(false), "a close-delimited body ends the connection");

        let mut reader = "body".as_bytes();
        let mut sink = Vec::new();
        relay_body(&mut reader, &mut sink, head.body).unwrap();
        assert_eq!(sink, b"body");

        // A truncated reader, one that errors instead of ending cleanly.
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing close_notify",
                ))
            }
        }
        let error = relay_body(&mut Broken, &mut Vec::new(), head.body).unwrap_err();
        assert!(matches!(error, ResponseError::Truncated(_)), "{error}");
    }

    /// The server's own wish to close is honoured, and the client's is
    /// consulted through `keep_alive`.
    #[test]
    fn keep_alive_needs_both_sides_and_a_frame() {
        let head = final_of("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        assert!(head.keep_alive(false));
        assert!(!head.keep_alive(true), "the client asked to close");

        let head = final_of("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n");
        assert!(head.server_close);
        assert!(!head.keep_alive(false), "the server asked to close");

        let head = final_of("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\n");
        assert!(head.server_close, "HTTP/1.0 closes unless it keeps alive");
        let head = final_of("HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n");
        assert!(!head.server_close);
    }

    /// The forwarded head regenerates the framing headers and drops the
    /// hop-by-hop ones, and a close-delimited body carries none.
    #[test]
    fn the_forwarded_head_is_the_broker_s_own() {
        let head = final_of(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nX-Keep: 1\r\nKeep-Alive: timeout=5\r\nContent-Length: 5\r\nServer: stub\r\n\r\n",
        );
        let forwarded = String::from_utf8(head.serialise()).unwrap();
        assert_eq!(
            forwarded,
            "HTTP/1.1 200 OK\r\nX-Keep: 1\r\nServer: stub\r\nContent-Length: 5\r\n\r\n"
        );
        let head = final_of("HTTP/1.1 200 OK\r\n\r\n");
        let forwarded = String::from_utf8(head.serialise()).unwrap();
        assert_eq!(forwarded, "HTTP/1.1 200 OK\r\n\r\n");
    }
}
