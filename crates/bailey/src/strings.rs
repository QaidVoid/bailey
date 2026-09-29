//! Quoting text into the formats bailey writes.
//!
//! A path or an error message may hold a quote, a backslash, or a control
//! character, and pasting one between quotes produces something that is not
//! the format it was meant for, or worse, a valid-looking document with a
//! field nobody wrote.

/// Quote a value as a TOML basic string, written in the JSON escape syntax.
///
/// Both formats read the same short escapes (`\"`, `\\`, `\b`, `\t`, `\n`,
/// `\f`, `\r`) and accept `\uXXXX` for any other control character, so one
/// quoting serves the machine-readable report and the generated TOML
/// fragments alike. TOML refuses a raw U+007F where JSON allows one, so that
/// is escaped too, and every character of the value survives the round trip
/// in both.
pub fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::quoted;

    /// The whole point of the helper: a value that would end the string, or
    /// carry a newline into the document, comes back as one string that
    /// parses to what went in.
    #[test]
    fn a_value_with_quotes_and_control_characters_round_trips_through_toml() {
        for value in [
            "plain",
            "with \"quote\"",
            "back\\slash",
            "line\nbreak\rreturn",
            "tab\there",
            "\u{1}quiet\u{7f}",
            "/dev/shm/x\";\n[hooks]\npre_launch = [\"id\"]\n#",
        ] {
            let rendered = format!("value = {}", quoted(value));
            let parsed: Result<toml::Table, _> = toml::from_str(&rendered);
            let read_back = parsed
                .unwrap_or_else(|err| panic!("{rendered:?} does not parse as TOML: {err}"))
                .get("value")
                .and_then(toml::Value::as_str)
                .expect("a string")
                .to_owned();
            assert_eq!(read_back, value, "{rendered:?}");
        }
    }
}
