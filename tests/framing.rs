// SPDX-License-Identifier: MIT OR Apache-2.0
//! Framing unit tests: end-of-message and chunked, including messages split at
//! arbitrary TCP boundaries and terminator sequences split across reads.

use netconf::framing::{encode, Decoder, Framing};

/// Feed the buffer one byte at a time and collect every complete message.
fn decode_byte_by_byte(mode: Framing, wire: &[u8]) -> Vec<Vec<u8>> {
    let mut d = Decoder::new(mode);
    let mut out = Vec::new();
    for b in wire {
        d.push(&[*b]);
        while let Some(m) = d.next_message().unwrap() {
            out.push(m);
        }
    }
    out
}

#[test]
fn eom_roundtrip() {
    let msg = b"<hello xmlns=\"urn:x\"/>";
    let wire = encode(Framing::Eom, msg);
    assert!(wire.ends_with(b"]]>]]>"));
    let mut d = Decoder::new(Framing::Eom);
    d.push(&wire);
    assert_eq!(d.next_message().unwrap().as_deref(), Some(&msg[..]));
    assert_eq!(d.next_message().unwrap(), None);
}

#[test]
fn eom_split_across_every_boundary() {
    let msg = b"<rpc-reply>data]that]contains]square]brackets</rpc-reply>";
    let wire = encode(Framing::Eom, msg);
    let got = decode_byte_by_byte(Framing::Eom, &wire);
    assert_eq!(got, vec![msg.to_vec()]);
}

#[test]
fn eom_two_messages_in_one_push() {
    let a = b"<a/>";
    let b = b"<b/>";
    let mut wire = encode(Framing::Eom, a);
    wire.extend_from_slice(&encode(Framing::Eom, b));
    let mut d = Decoder::new(Framing::Eom);
    d.push(&wire);
    assert_eq!(d.next_message().unwrap().as_deref(), Some(&a[..]));
    assert_eq!(d.next_message().unwrap().as_deref(), Some(&b[..]));
    assert_eq!(d.next_message().unwrap(), None);
}

/// Resuming the search must not miss a terminator. The search picks up where the
/// last one stopped, backed up by the terminator's length; a near-miss inside the
/// data and a second message behind the first are what a wrong back-up would miss.
#[test]
fn eom_resumed_search_misses_nothing() {
    let a = b"<a>]]>]]</a>";
    let b = b"<b>]]]>]]]></b>";
    let mut wire = encode(Framing::Eom, a);
    wire.extend_from_slice(&encode(Framing::Eom, b));
    let want = vec![a.to_vec(), b.to_vec()];
    assert_eq!(decode_byte_by_byte(Framing::Eom, &wire), want);
    for piece in [2, 3, 5, 7] {
        let mut d = Decoder::new(Framing::Eom);
        let mut got = Vec::new();
        for chunk in wire.chunks(piece) {
            d.push(chunk);
            while let Some(m) = d.next_message().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(got, want, "pieces of {piece}");
    }
}

#[test]
fn chunked_roundtrip() {
    let msg = b"<rpc-reply><data><foo/></data></rpc-reply>";
    let wire = encode(Framing::Chunked, msg);
    // wire = "\n#<len>\n<data>\n##\n"
    assert!(wire.starts_with(b"\n#"));
    assert!(wire.ends_with(b"\n##\n"));
    let mut d = Decoder::new(Framing::Chunked);
    d.push(&wire);
    assert_eq!(d.next_message().unwrap().as_deref(), Some(&msg[..]));
    assert_eq!(d.next_message().unwrap(), None);
}

#[test]
fn chunked_split_across_every_boundary() {
    let msg = b"<rpc-reply>abcdefghij</rpc-reply>";
    let wire = encode(Framing::Chunked, msg);
    let got = decode_byte_by_byte(Framing::Chunked, &wire);
    assert_eq!(got, vec![msg.to_vec()]);
}

/// A message in several chunks, arriving a byte at a time. The boundaries are
/// found first and the data copied once the end-of-chunks marker is in.
#[test]
fn chunked_multi_chunk_message_split_across_every_boundary() {
    let wire = b"\n#4\n<rpc\n#6\n-reply\n#2\n/>\n##\n";
    let got = decode_byte_by_byte(Framing::Chunked, wire);
    assert_eq!(got, vec![b"<rpc-reply/>".to_vec()]);
}

#[test]
fn chunked_multi_chunk_message() {
    // Two chunks followed by end-of-chunks must assemble into one message.
    let mut wire = Vec::new();
    wire.extend_from_slice(b"\n#3\nabc");
    wire.extend_from_slice(b"\n#3\ndef");
    wire.extend_from_slice(b"\n##\n");
    let mut d = Decoder::new(Framing::Chunked);
    d.push(&wire);
    assert_eq!(d.next_message().unwrap().as_deref(), Some(&b"abcdef"[..]));
}

#[test]
fn chunked_rejects_garbage() {
    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"garbage-without-a-chunk-header");
    assert!(d.next_message().is_err());
}

// --- Adversarial input: never panic ---------------------------------------- #

#[test]
fn chunked_hostile_chunk_size_gives_protocol_not_panic() {
    // usize::MAX as a chunk size: digit-valid, but must be refused BEFORE any
    // arithmetic runs on it, or `i + size` wraps and the slice panics.
    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"\n#18446744073709551615\n");
    assert!(d.next_message().is_err());
}

#[test]
fn chunked_over_max_gives_protocol() {
    // A chunk size above the cap is a protocol error, not unbounded buffering.
    let mut d = Decoder::with_max_message_size(Framing::Chunked, 8);
    d.push(b"\n#100\n");
    assert!(d.next_message().is_err());
}

#[test]
fn eom_without_terminator_over_max_gives_protocol() {
    // No terminator, and the buffer passes the cap: a protocol error rather than
    // unbounded growth.
    let mut d = Decoder::with_max_message_size(Framing::Eom, 16);
    d.push(&[b'a'; 64]);
    assert!(d.next_message().is_err());
}

// --- RFC 6242 §4.2 conformance ---------------------------------------------- #

/// **Whitespace between messages is discarded, not fatal.**
///
/// The parser required the very first byte to begin `\n#`, so a stray CR or a
/// blank line between messages — which a device is free to send — became a
/// protocol error and killed the session.
#[test]
fn whitespace_before_a_chunk_header_is_discarded() {
    let msg = b"<rpc-reply/>";
    for lead in ["", "\r\n", "  ", "\n\n", "\t\r\n "] {
        let mut wire = lead.as_bytes().to_vec();
        wire.extend_from_slice(&encode(Framing::Chunked, msg));
        let mut d = Decoder::new(Framing::Chunked);
        d.push(&wire);
        assert_eq!(
            d.next_message().unwrap().as_deref(),
            Some(&msg[..]),
            "leading {lead:?} should have been discarded"
        );
    }
}

/// But arbitrary bytes are still a protocol error. Discarding anything at all
/// would turn a malformed stream into a session that waits forever instead of
/// saying what is wrong.
#[test]
fn non_whitespace_before_a_chunk_header_is_still_an_error() {
    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"garbage\n#4\nabcd\n##\n");
    assert!(d.next_message().is_err(), "garbage must not be swallowed");
}

/// **A chunk size of 0 is forbidden by RFC 6242.** An empty message is the
/// end-of-chunks marker on its own, never a zero-length chunk.
#[test]
fn an_empty_chunked_message_is_not_a_zero_length_chunk() {
    let wire = encode(Framing::Chunked, b"");
    assert_eq!(wire, b"\n##\n", "an empty message must not send #0");
    assert!(
        !String::from_utf8_lossy(&wire).contains("#0"),
        "chunk size 0 is forbidden"
    );
}

// --- The walk resumes between reads ----------------------------------------- #

/// **A message in many chunks, arriving over many reads, assembles whatever the
/// read boundaries are** — and the walk picks up where it stopped. The walk used to
/// start over from the first header on every read, which read every header once
/// per read; here a header is read again only when a read cut it off. The second
/// message behind the first shows the walk starts afresh after a message.
#[test]
fn a_message_in_many_chunks_over_many_reads_assembles_and_the_next_one_follows() {
    let mut wire = Vec::new();
    let mut want_a = Vec::new();
    for n in 0..2000u32 {
        let b = b'a' + (n % 26) as u8;
        wire.extend_from_slice(b"\n#1\n");
        wire.push(b);
        want_a.push(b);
    }
    wire.extend_from_slice(b"\n##\n");
    let b = b"<rpc-reply><ok/></rpc-reply>";
    wire.extend_from_slice(&encode(Framing::Chunked, b));
    let want = vec![want_a, b.to_vec()];
    for piece in [1usize, 3, 7, 64, 4096] {
        let mut d = Decoder::new(Framing::Chunked);
        let mut got = Vec::new();
        for chunk in wire.chunks(piece) {
            d.push(chunk);
            while let Some(m) = d.next_message().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(got, want, "pieces of {piece}");
    }
}

/// A newline that ends a read may be the first byte of the next header. The walk
/// keeps it instead of discarding it as whitespace between messages, so a header
/// split after its `\n` is still read as a header.
#[test]
fn a_header_split_after_its_newline_is_still_a_header() {
    let wire = b"\r\n\n#4\nabcd\n##\n\n#2\nef\n##\n";
    let want = vec![b"abcd".to_vec(), b"ef".to_vec()];
    assert_eq!(decode_byte_by_byte(Framing::Chunked, wire), want);
    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"\r\n\n");
    assert_eq!(d.next_message().unwrap(), None);
    d.push(b"#4\nabcd\n##\n");
    assert_eq!(d.next_message().unwrap().as_deref(), Some(&b"abcd"[..]));
}

/// **The chunk-size is read as RFC 6242 writes it:** decimal digits, no leading zero,
/// at most 4294967295. `007` used to be read as 7.
#[test]
fn a_chunk_size_with_a_leading_zero_is_refused() {
    for wire in [&b"\n#007\nabcdefg\n##\n"[..], b"\n#01\na\n##\n"] {
        let mut d = Decoder::new(Framing::Chunked);
        d.push(wire);
        let e = d
            .next_message()
            .expect_err("a leading zero is not RFC 6242");
        assert!(e.to_string().contains("leading zero"), "{e}");
    }
    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"\n#4294967296\n");
    assert!(d.next_message().is_err(), "above the RFC 6242 maximum");
}

// --- What stood there goes with the error (0.5.13) -------------------------- #

/// **A framing violation names the bytes that stood where the frame was broken,
/// and carries the buffer as the device sent it.** The text used to give only what
/// was expected, or the cap, and the bytes that were there instead were left
/// behind.
#[test]
fn a_framing_violation_carries_the_bytes_that_stood_there() {
    let received = |d: &mut Decoder| match d.next_message() {
        Err(netconf::NetconfError::Protocol { detail, received }) => (detail, received),
        other => panic!("expected a Protocol error, got {other:?}"),
    };

    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"\n#3\nabcXY\xff");
    let (detail, bytes) = received(&mut d);
    assert!(
        detail.contains("expected \\n# at chunk start, found `XY` at byte 7"),
        "{detail}"
    );
    assert_eq!(bytes.as_deref(), Some("\n#3\nabcXY\\xFF"));

    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"\n#3x");
    let (detail, bytes) = received(&mut d);
    assert!(
        detail.contains("LF after chunk-size, found `x`"),
        "{detail}"
    );
    assert_eq!(bytes.as_deref(), Some("\n#3x"));

    let mut d = Decoder::new(Framing::Chunked);
    d.push(b"\n##x");
    let (detail, _) = received(&mut d);
    assert!(detail.contains("LF after ##, found `x`"), "{detail}");

    let mut d = Decoder::with_max_message_size(Framing::Eom, 4);
    d.push(b"<never-ends");
    let (detail, bytes) = received(&mut d);
    assert!(detail.contains("without EOM"), "{detail}");
    assert_eq!(bytes.as_deref(), Some("<never-ends"));
}
