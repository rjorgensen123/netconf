// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the device writes on the wire, read strictly. A number is read exactly as
//! its RFC writes one, and text that goes into an error or a log line is made
//! printable first. One rule each, used wherever the device's bytes are read, so
//! that two places cannot read the same thing two ways.

use std::fmt::Write as _;

/// Read a decimal number as RFC 6242 writes a chunk-size and RFC 6241 a session-id:
/// ASCII digits only, no sign, no whitespace, no leading zero — `0` alone is the
/// number zero — and no more than 4294967295. Anything else is `None`.
///
/// `str::parse` reads `+7`, after a `trim` it reads ` 7 `, and it reads `007` as 7.
/// RFC 6242 §4.2 forbids a leading zero in the chunk-size outright and caps it at
/// 4294967295; RFC 6241 types the session-id as an `unsignedInt`. A device that
/// writes a number another way is not writing what the standard says, and a reader
/// that quietly agrees with it cannot be told what it accepted.
pub(crate) fn strict_u32(text: &str) -> Option<u32> {
    strict_u64(text)?.try_into().ok()
}

/// [`strict_u32`] without the RFC cap: the number as this crate writes a `message-id`,
/// which is a `u64`. Decimal digits, no sign, no whitespace, no leading zero.
pub(crate) fn strict_u64(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if bytes[0] == b'0' && bytes.len() > 1 {
        return None;
    }
    text.parse::<u64>().ok()
}

/// Text from the device, made safe for an error message or a log line. Every control
/// character, and the Unicode line and paragraph separators U+2028 and U+2029, is
/// written out as an escape — `\n`, `\r`, `\t`, or `\u{XXXX}` — so the text stays on
/// its own line and shows what it holds. Everything else is kept as the device wrote
/// it, non-ASCII text included.
pub(crate) fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Bytes from the device as text, with nothing lost: every run of valid UTF-8 as it
/// is, and every byte that is not part of valid UTF-8 written as `\xNN`. For what
/// the device sent that goes into an error as data — a reply that is not UTF-8, the
/// bytes in the de-framer — where `from_utf8_lossy` would put the same U+FFFD in
/// place of every byte it cannot read.
pub(crate) fn bytes_as_text(mut bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    loop {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(e) => {
                let (valid, rest) = bytes.split_at(e.valid_up_to());
                // `valid_up_to` is where the valid prefix ends, so this cannot fail.
                out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                // An incomplete sequence at the end has no `error_len`: every byte
                // left is part of it.
                let bad = e.error_len().unwrap_or(rest.len());
                for b in &rest[..bad] {
                    // Writing to a String cannot fail.
                    let _ = write!(out, "\\x{b:02X}");
                }
                bytes = &rest[bad..];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_is_read_only_as_the_standard_writes_it() {
        assert_eq!(strict_u32("0"), Some(0));
        assert_eq!(strict_u32("7"), Some(7));
        assert_eq!(strict_u32("4294967295"), Some(u32::MAX));
        for not_a_number in ["", "007", "+7", " 7 ", "7 ", "-1", "4294967296", "1e3", "٧"] {
            assert_eq!(strict_u32(not_a_number), None, "{not_a_number:?}");
        }
        assert_eq!(strict_u64("4294967296"), Some(4_294_967_296));
        assert_eq!(strict_u64("18446744073709551615"), Some(u64::MAX));
        assert_eq!(strict_u64("18446744073709551616"), None);
        assert_eq!(strict_u64("007"), None);
    }

    #[test]
    fn bytes_that_are_not_utf8_are_written_out_and_nothing_is_lost() {
        assert_eq!(bytes_as_text(b"plain"), "plain");
        assert_eq!(bytes_as_text("æ".as_bytes()), "æ");
        assert_eq!(bytes_as_text(b"a\xff\xfeb"), "a\\xFF\\xFEb");
        // A sequence cut off at the end, and one broken in the middle.
        assert_eq!(bytes_as_text(&"æ".as_bytes()[..1]), "\\xC3");
        assert_eq!(bytes_as_text(b"\xc3x"), "\\xC3x");
    }

    #[test]
    fn control_characters_in_device_text_are_made_visible() {
        assert_eq!(printable("plain text, æøå"), "plain text, æøå");
        assert_eq!(
            printable("line one\r\nline two\tend\0\u{85}\u{2028}x"),
            "line one\\r\\nline two\\tend\\u{0000}\\u{0085}\\u{2028}x"
        );
    }
}
