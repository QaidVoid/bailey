//! A minimal D-Bus client for the systemd user manager's private socket.
//!
//! One call, `StartTransientUnit`, on the bus-less endpoint `systemctl --user`
//! itself uses. No `Hello`, no signals, no other message type: on a direct
//! connection the manager answers a call the same way it would over the
//! session bus, so the bus daemon and everything it implies can be skipped.
//! Writing this by hand keeps a D-Bus crate out of the build, one that would
//! bring an async runtime or a C library into the trusted base for the sake of
//! a single message.
//!
//! The wire format is the D-Bus specification's little-endian layout. A
//! message is a fixed part (endianness, type, flags, protocol version, body
//! length, serial, header fields), padded to eight bytes, then the arguments.
//! Strings are a length, the bytes and a NUL; every value starts on its
//! natural boundary, counted from the start of the message.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Header-field tags this client writes or reads.
const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_SIGNATURE: u8 = 8;

const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const METHOD_ERROR: u8 = 3;

/// An error the manager answered a call with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagerError {
    /// The D-Bus error name, for example
    /// `org.freedesktop.systemd1.TransactionIsDegraded`.
    pub(crate) name: String,
    /// The human-readable text the manager attached.
    pub(crate) message: String,
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.name, self.message)
    }
}

/// Builds message bytes, aligning values the way the specification says.
#[derive(Default)]
struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn align(&mut self, to: usize) {
        while !self.buf.len().is_multiple_of(to) {
            self.buf.push(0);
        }
    }

    fn byte(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.align(4);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.align(4);
        self.buf
            .extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
    }

    fn signature(&mut self, value: &str) {
        self.buf.push(value.len() as u8);
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
    }

    /// One header field: a struct of the tag and a variant holding the value.
    /// A struct is always padded to eight bytes.
    fn field(&mut self, tag: u8, signature: &str, write: impl FnOnce(&mut Self)) {
        self.align(8);
        self.byte(tag);
        self.signature(signature);
        write(self);
    }
}

/// The bytes of a `StartTransientUnit` call creating scope `unit` on the
/// manager at `/org/freedesktop/systemd1`.
///
/// The properties say why the scope exists: `PIDs` holds a single zero, which
/// the manager resolves to the caller through the connection's peer
/// credentials, so the number bailey would otherwise send never exists;
/// `Delegate` hands the scope's cgroup subtree to the process inside it;
/// `CollectMode` has the manager drop the unit once it ends, failed or not,
/// the way `systemd-run --collect` does.
pub(crate) fn start_transient_unit_call(unit: &str) -> Vec<u8> {
    let mut body = Encoder::default();
    body.string(unit);
    body.string("fail");
    // The entries are marshalled on their own offsets and spliced in after
    // the array's length, because that length counts the entries and not
    // the padding that aligns the first entry to the struct boundary.
    let mut entries = Encoder::default();
    entries.string("PIDs");
    entries.signature("au");
    entries.u32(4);
    entries.u32(0);
    entries.align(8);
    entries.string("Delegate");
    entries.signature("b");
    entries.u32(1);
    entries.align(8);
    entries.string("CollectMode");
    entries.signature("s");
    entries.string("inactive-or-failed");
    body.u32(entries.buf.len() as u32);
    body.align(8);
    body.buf.extend_from_slice(&entries.buf);
    // An empty array still ends aligned to its element boundary.
    body.u32(0);
    body.align(8);

    let mut fields = Encoder::default();
    fields.field(FIELD_PATH, "o", |e| e.string("/org/freedesktop/systemd1"));
    fields.field(FIELD_INTERFACE, "s", |e| {
        e.string("org.freedesktop.systemd1.Manager")
    });
    fields.field(FIELD_MEMBER, "s", |e| e.string("StartTransientUnit"));
    fields.field(FIELD_SIGNATURE, "g", |e| e.signature("ssa(sv)a(sa(sv))"));

    let mut message = Encoder::default();
    message.byte(b'l');
    message.byte(METHOD_CALL);
    message.byte(0);
    message.byte(1);
    message.u32(body.buf.len() as u32);
    message.u32(1);
    message.u32(fields.buf.len() as u32);
    message.buf.extend_from_slice(&fields.buf);
    message.align(8);
    message.buf.extend_from_slice(&body.buf);
    message.buf
}

/// What a reply from the manager said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    /// The job was accepted.
    Return,
    /// The job was refused, with the manager's name and reason.
    Error(ManagerError),
}

/// The greatest container nesting a type may have, the limit most D-Bus
/// implementations agree on.
const MAX_TYPE_DEPTH: usize = 64;

/// The length in bytes of the first complete type in a signature.
fn complete_type_len(sig: &str) -> Result<usize, String> {
    complete_type_depth(sig, 0)
}

/// The same, counting nesting so an array chain cannot outgrow the stack.
fn complete_type_depth(sig: &str, depth: usize) -> Result<usize, String> {
    if depth > MAX_TYPE_DEPTH {
        return Err("a signature nests more than 64 levels deep".to_owned());
    }
    let bytes = sig.as_bytes();
    match bytes.first() {
        Some(b'a') => Ok(1 + complete_type_depth(&sig[1..], depth + 1)?),
        Some(b'(') | Some(b'{') => {
            let (open, close) = if bytes[0] == b'(' {
                (b'(', b')')
            } else {
                (b'{', b'}')
            };
            let mut depth = 0usize;
            for (index, &byte) in bytes.iter().enumerate() {
                if byte == open {
                    depth += 1;
                }
                if byte == close {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(index + 1);
                    }
                }
            }
            Err("a signature ends inside a container".to_owned())
        }
        Some(byte) if byte.is_ascii() => Ok(1),
        Some(_) => Err("a signature byte is not a type code".to_owned()),
        None => Err("a signature ends where a type should begin".to_owned()),
    }
}

/// Reads message bytes, keeping the position alignment asks for.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn at(bytes: &'a [u8], pos: usize) -> Self {
        Reader { bytes, pos }
    }

    fn align(&mut self, to: usize) -> Result<(), String> {
        while !self.pos.is_multiple_of(to) {
            self.byte()?;
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, String> {
        let value = self
            .bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| "the message ends early".to_owned())?;
        self.pos += 1;
        Ok(value)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        if self.pos + count > self.bytes.len() {
            return Err("the message ends early".to_owned());
        }
        let slice = &self.bytes[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, String> {
        self.align(4)?;
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn string(&mut self) -> Result<String, String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len + 1)?;
        if bytes[len] != 0 {
            return Err("a string is not NUL-terminated".to_owned());
        }
        String::from_utf8(bytes[..len].to_vec())
            .map(|text| text.to_owned())
            .map_err(|_| "a string is not UTF-8".to_owned())
    }

    fn signature(&mut self) -> Result<String, String> {
        let len = self.byte()? as usize;
        let bytes = self.take(len + 1)?;
        if bytes[len] != 0 {
            return Err("a signature is not NUL-terminated".to_owned());
        }
        String::from_utf8(bytes[..len].to_vec()).map_err(|_| "a signature is not UTF-8".to_owned())
    }

    /// Consume one value named by the first complete type in `sig`, returning
    /// the signature that follows it.
    fn skip_value<'s>(&mut self, sig: &'s str) -> Result<&'s str, String> {
        self.skip_value_depth(sig, 0)
    }

    /// The same, counting nesting so a variant chain cannot outgrow the stack.
    fn skip_value_depth<'s>(&mut self, sig: &'s str, depth: usize) -> Result<&'s str, String> {
        if depth > MAX_TYPE_DEPTH {
            return Err("a value nests more than 64 levels deep".to_owned());
        }
        let len = complete_type_len(sig)?;
        let (code, rest) = sig.split_at(len);
        match code.as_bytes()[0] {
            b'y' => {
                self.byte()?;
            }
            b'b' | b'i' | b'u' => {
                self.u32()?;
            }
            b'n' | b'q' => {
                self.align(2)?;
                self.take(2)?;
            }
            b'x' | b't' | b'd' => {
                self.align(8)?;
                self.take(8)?;
            }
            b's' | b'o' => {
                self.string()?;
            }
            b'g' => {
                self.signature()?;
            }
            b'v' => {
                let inner = self.signature()?;
                self.skip_value_depth(&inner, depth + 1)?;
            }
            // An array's length prefix covers its whole body, padding inside
            // it included, so the element type never has to be walked.
            b'a' => {
                let len = self.u32()? as usize;
                self.take(len)?;
            }
            b'(' | b'{' => {
                self.align(8)?;
                let mut members = &code[1..code.len() - 1];
                while !members.is_empty() {
                    members = self.skip_value_depth(members, depth + 1)?;
                }
            }
            _ => return Err(format!("a type this client cannot read: {code}")),
        }
        Ok(rest)
    }
}

/// Parse one complete message the manager sent.
pub(crate) fn parse_reply(bytes: &[u8]) -> Result<Reply, String> {
    let mut fixed = Reader::new(bytes);
    if fixed.byte()? != b'l' {
        return Err("the reply is not little-endian".to_owned());
    }
    let message_type = fixed.byte()?;
    let _flags = fixed.byte()?;
    let _version = fixed.byte()?;
    let body_len = fixed.u32()? as usize;
    let _serial = fixed.u32()?;
    let fields_len = fixed.u32()? as usize;

    match message_type {
        METHOD_RETURN | METHOD_ERROR => {}
        other => return Err(format!("the manager sent a message of type {other}")),
    }
    let body_start = (16 + fields_len).div_ceil(8) * 8;
    if body_start + body_len > bytes.len() {
        return Err("the message ends early".to_owned());
    }

    let mut fields = Reader::at(bytes, 16);
    let fields_end = 16 + fields_len;
    let mut error_name = None;
    while fields.pos < fields_end {
        // Every field element starts on an eighth byte, wherever the field
        // before it left off: the padding is the manager's, not data.
        fields.align(8)?;
        let tag = fields.byte()?;
        let sig = fields.signature()?;
        let mut rest = sig.as_str();
        let captured = loop {
            if rest.is_empty() {
                break None;
            }
            let len = complete_type_len(rest)?;
            let (first, tail) = rest.split_at(len);
            if first == "s" || first == "o" {
                let text = fields.string()?;
                break Some(text);
            }
            fields.skip_value(first)?;
            rest = tail;
        };
        if tag == FIELD_ERROR_NAME {
            error_name = captured.or(error_name);
        }
    }
    if fields.pos > fields_end {
        return Err("the header fields overrun their array".to_owned());
    }

    if message_type == METHOD_RETURN {
        return Ok(Reply::Return);
    }
    let name = error_name.ok_or_else(|| "an error reply without an error name".to_owned())?;
    let mut body = Reader::at(bytes, body_start);
    let message = body.string().unwrap_or_default();
    Ok(Reply::Error(ManagerError { name, message }))
}

/// Read one message from the manager and parse it.
pub(crate) fn read_reply(stream: &mut UnixStream) -> Result<Reply, String> {
    let mut head = [0u8; 16];
    stream
        .read_exact(&mut head)
        .map_err(|error| format!("reading the manager's reply: {error}"))?;
    let body_len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
    let fields_len = u32::from_le_bytes(head[12..16].try_into().unwrap()) as usize;
    let body_start = (16 + fields_len).div_ceil(8) * 8;
    let total = body_start
        .checked_add(body_len)
        .filter(|total| *total >= 16 && *total <= 1024 * 1024)
        .ok_or_else(|| "the manager's reply has an impossible length".to_owned())?;
    let mut message = head.to_vec();
    message.resize(total, 0);
    stream
        .read_exact(&mut message[16..])
        .map_err(|error| format!("reading the manager's reply: {error}"))?;
    parse_reply(&message)
}

/// Negotiate the SASL `EXTERNAL` handshake the private socket expects.
///
/// The uid is sent as the hex of its decimal text, which is what the
/// specification asks for; the manager compares it with the peer credentials
/// the kernel recorded at `connect()`, and either answer other than `OK`
/// refuses the connection.
pub(crate) fn authenticate(stream: &mut UnixStream, uid: u32) -> Result<(), String> {
    let hex_uid: String = uid
        .to_string()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    write_line(stream, "\0")?;
    write_line(stream, &format!("AUTH EXTERNAL {hex_uid}\r\n"))?;
    let reply = read_line(stream)?;
    if !reply.starts_with("OK") {
        return Err(format!(
            "the manager answered the handshake with: {}",
            reply.trim_end_matches('\r')
        ));
    }
    write_line(stream, "BEGIN\r\n")
}

fn write_line(stream: &mut UnixStream, line: &str) -> Result<(), String> {
    stream
        .write_all(line.as_bytes())
        .map_err(|error| format!("writing to the user manager: {error}"))
}

fn read_line(stream: &mut UnixStream) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if line.len() > 1024 {
            return Err("the manager's handshake reply is too long".to_owned());
        }
        stream
            .read_exact(&mut byte)
            .map_err(|error| format!("reading the handshake: {error}"))?;
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Send `StartTransientUnit` for `unit` and wait for the manager's answer.
pub(crate) fn start_transient_unit(stream: &mut UnixStream, unit: &str) -> Result<(), String> {
    let call = start_transient_unit_call(unit);
    stream
        .write_all(&call)
        .map_err(|error| format!("writing to the user manager: {error}"))?;
    match read_reply(stream)? {
        Reply::Return => Ok(()),
        Reply::Error(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    /// An error reply the way the manager sends one: serial 10, reply serial
    /// 9, the name in a header field, the message as the body's first string.
    fn access_denied_reply() -> Vec<u8> {
        hex_bytes(
            "6c 03 01 01 21 00 00 00 0a 00 00 00 38 00 00 00
             05 01 75 00 09 00 00 00
             04 01 73 00 27 00 00 00
             6f 72 67 2e 66 72 65 65 64 65 73 6b 74 6f 70 2e 44 42 75 73 2e 45 72 72 6f 72 2e 41 63 63 65 73 73 44 65 6e 69 65 64 00
             1c 00 00 00
             41 63 63 65 73 73 20 74 6f 20 74 68 65 20 73 65 72 76 69 63 65 20 64 65 6e 69 65 64 00",
        )
    }

    /// A reply whose header fields are aligned the way the manager aligns
    /// them: every field element starts on an eighth byte, padding and all,
    /// whatever the field before it left. The name is read from where it
    /// sits instead of the parser losing the reply to the padding.
    #[test]
    fn a_reply_with_aligned_header_fields_is_parsed() {
        let reply = hex_bytes(
            "6c 03 01 01 0c 00 00 00 01 00 00 00 20 00 00 00
             04 01 73 00 08 00 00 00
             62 61 64 2d 6e 61 6d 65 00
             00 00 00 00 00 00 00
             05 01 75 00 09 00 00 00
             07 00 00 00
             62 65 63 61 75 73 65 00",
        );
        let Reply::Error(error) = parse_reply(&reply).unwrap() else {
            panic!("an error reply");
        };
        assert_eq!(error.name, "bad-name");
        assert_eq!(error.message, "because");
    }

    /// The full call for `t.scope`, byte for byte against a layout built
    /// from the specification: every alignment is counted from the message
    /// start, an array is a length followed by padding to its element
    /// boundary, and the length excludes that padding.
    ///
    /// - offset 0: `l`, type 1 (call), flags 0, version 1
    /// - offset 4: body length 128, offset 8: serial 1, offset 12: fields 142
    /// - offsets 16, 56, 104 and 136: the path, interface, member and
    ///   signature fields, each a tag, a variant signature and its value,
    ///   aligned to eight
    /// - offset 158: pad to 160, where the body starts
    /// - body: unit at 160, mode at 172, the properties array's length at
    ///   184 with its entries from 192, and the empty aux array's length at
    ///   284, which closes the message on the struct boundary
    #[test]
    fn the_encoded_call_matches_the_specification_byte_for_byte() {
        let expected = "6c 01 00 01 80 00 00 00 01 00 00 00
            8e 00 00 00 01 01 6f 00 19 00 00 00
            2f 6f 72 67 2f 66 72 65 65 64 65 73
            6b 74 6f 70 2f 73 79 73 74 65 6d 64
            31 00 00 00 00 00 00 00 02 01 73 00
            20 00 00 00 6f 72 67 2e 66 72 65 65
            64 65 73 6b 74 6f 70 2e 73 79 73 74
            65 6d 64 31 2e 4d 61 6e 61 67 65 72
            00 00 00 00 00 00 00 00 03 01 73 00
            12 00 00 00 53 74 61 72 74 54 72 61
            6e 73 69 65 6e 74 55 6e 69 74 00 00
            00 00 00 00 08 01 67 00 10 73 73 61
            28 73 76 29 61 28 73 61 28 73 76 29
            29 00 00 00 07 00 00 00 74 2e 73 63
            6f 70 65 00 04 00 00 00 66 61 69 6c
            00 00 00 00 5b 00 00 00 00 00 00 00
            04 00 00 00 50 49 44 73 00 02 61 75
            00 00 00 00 04 00 00 00 00 00 00 00
            08 00 00 00 44 65 6c 65 67 61 74 65
            00 01 62 00 01 00 00 00 00 00 00 00
            0b 00 00 00 43 6f 6c 6c 65 63 74 4d
            6f 64 65 00 01 73 00 00 12 00 00 00
            69 6e 61 63 74 69 76 65 2d 6f 72 2d
            66 61 69 6c 65 64 00 00 00 00 00 00";
        assert_eq!(start_transient_unit_call("t.scope"), hex_bytes(expected));
    }

    /// Locate the PIDs property in an encoded call and read its array.
    fn encoded_pids(call: &[u8]) -> Option<(usize, u32)> {
        let needle = b"PIDs\0";
        let start = call
            .windows(needle.len())
            .position(|window| window == needle)?;
        let mut cursor = start + needle.len();
        // The variant's signature, then the array, aligned to four.
        if call.get(cursor)? != &2 || &call[cursor + 1..cursor + 3] != b"au" {
            return None;
        }
        cursor = (cursor + 4).div_ceil(4) * 4;
        let len = u32::from_le_bytes(call[cursor..cursor + 4].try_into().ok()?);
        let element = u32::from_le_bytes(call[cursor + 4..cursor + 8].try_into().ok()?);
        Some((len as usize, element))
    }

    #[test]
    fn the_pids_array_holds_exactly_one_zero() {
        let call = start_transient_unit_call("bailey-1-x.scope");
        let (len, element) = encoded_pids(&call).expect("the call must carry a PIDs array");
        assert_eq!(len, 4, "one u32 element");
        assert_eq!(element, 0, "zero names the sender, by peer credentials");
    }

    /// A `METHOD_RETURN` with no body: serial 9, one field naming the reply
    /// serial, header of 24 bytes and nothing else.
    #[test]
    fn a_method_return_parses() {
        let bytes = hex_bytes(
            "6c 02 01 01 00 00 00 00 09 00 00 00 08 00 00 00
             05 01 75 00 01 00 00 00",
        );
        assert_eq!(parse_reply(&bytes), Ok(Reply::Return));
    }

    /// An error reply carries the error name in a header field and the
    /// message as the body's first string. Fields: reply serial (u) then the
    /// error name (s), header of 72 bytes, body of 33.
    #[test]
    fn an_error_reply_carries_name_and_message() {
        assert_eq!(
            parse_reply(&access_denied_reply()),
            Ok(Reply::Error(ManagerError {
                name: "org.freedesktop.DBus.Error.AccessDenied".to_owned(),
                message: "Access to the service denied".to_owned(),
            }))
        );
    }

    #[test]
    fn a_truncated_reply_is_reported() {
        let full = access_denied_reply();
        assert!(parse_reply(&full[..full.len() - 1]).is_err());
        assert!(parse_reply(&full[..24]).is_err());
    }

    /// A signature byte that is not a type code, here the two bytes of a
    /// two-byte character, is refused rather than sliced mid-character. The
    /// error-name field's signature and the byte after it are overwritten so
    /// the field reads as the valid UTF-8 string that the two bytes make.
    #[test]
    fn a_signature_byte_that_is_not_a_type_code_is_refused() {
        let mut reply = access_denied_reply();
        let at = reply
            .windows(4)
            .position(|window| window == [4, 1, b's', 0])
            .unwrap();
        reply[at..at + 5].copy_from_slice(&[4, 2, 0xc3, 0xa9, 0]);
        assert!(parse_reply(&reply).is_err());
    }

    /// Nesting one past the depth cap is refused, at the cap it parses.
    #[test]
    fn a_type_nesting_past_the_cap_is_refused() {
        let at_cap = format!("{}u", "a".repeat(MAX_TYPE_DEPTH));
        assert!(complete_type_len(&at_cap).is_ok());
        let past_cap = format!("{}u", "a".repeat(MAX_TYPE_DEPTH + 1));
        assert!(complete_type_len(&past_cap).is_err());

        let mut bytes = Vec::new();
        for _ in 0..MAX_TYPE_DEPTH - 1 {
            bytes.extend_from_slice(&[1, b'v', 0]);
        }
        bytes.extend_from_slice(&[1, b'y', 0, 0]);
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.skip_value("v"), Ok(""));

        // One v-group more: the closing type's own entry lands past the cap.
        let mut bytes = bytes[..bytes.len() - 4].to_vec();
        bytes.extend_from_slice(&[1, b'v', 0, 1, b'y', 0, 0]);
        let mut reader = Reader::new(&bytes);
        assert_eq!(
            reader.skip_value("v"),
            Err("a value nests more than 64 levels deep".to_owned())
        );
    }

    /// The conversation as a manager would see it: the handshake, one call
    /// naming `StartTransientUnit`, and an error answer that surfaces as the
    /// call's reason. A socket pair stands in for the private socket.
    #[test]
    fn a_manager_that_refuses_answers_the_call_with_its_reason() {
        use std::io::{Read, Write};

        let (mut mine, mut theirs) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let mut first = [0u8; 1];
            theirs.read_exact(&mut first).unwrap();
            assert_eq!(first[0], 0, "the client opens with a single NUL");
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                theirs.read_exact(&mut byte).unwrap();
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            let auth = String::from_utf8_lossy(&line).into_owned();
            assert!(
                auth.starts_with("AUTH EXTERNAL "),
                "the handshake must authenticate by peer credentials: {auth}"
            );
            theirs
                .write_all(b"OK 0123456789abcdef0123456789abcdef\r\n")
                .unwrap();
            let mut line = Vec::new();
            loop {
                theirs.read_exact(&mut byte).unwrap();
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            assert_eq!(line, b"BEGIN\r".to_vec());

            let mut head = [0u8; 16];
            theirs.read_exact(&mut head).unwrap();
            assert_eq!(head[0], b'l', "the call is little-endian");
            assert_eq!(head[1], METHOD_CALL);
            let body_len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
            let fields_len = u32::from_le_bytes(head[12..16].try_into().unwrap()) as usize;
            let body_start = (16 + fields_len).div_ceil(8) * 8;
            let mut rest = vec![0u8; body_start + body_len - 16];
            theirs.read_exact(&mut rest).unwrap();
            let call = [head.to_vec(), rest].concat();
            let needle = b"StartTransientUnit";
            assert!(
                call.windows(needle.len()).any(|window| window == needle),
                "the call must name the one method this client speaks"
            );
            theirs.write_all(&access_denied_reply()).unwrap();
        });

        let uid = unsafe { libc::geteuid() };
        authenticate(&mut mine, uid).unwrap();
        let reason = start_transient_unit(&mut mine, "bailey-1-x.scope").unwrap_err();
        server.join().unwrap();
        assert!(
            reason.contains("org.freedesktop.DBus.Error.AccessDenied"),
            "the refusal must name the manager's error: {reason}"
        );
        assert!(
            reason.contains("Access to the service denied"),
            "the refusal must carry the manager's message: {reason}"
        );
    }
}
