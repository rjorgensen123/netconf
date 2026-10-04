// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 6242 framing: **end-of-message (`]]>]]>`) as the baseline**, and **chunked
//! (1.1)** when hello announces it. The framing is chosen from the announced
//! capabilities, never from an assumption about the version.
//!
//! [`Decoder`] is incremental: it tolerates messages and the terminator sequence
//! being split across **arbitrary** TCP boundaries. It never panics on invalid
//! input — a violation produces [`NetconfError::Protocol`].

use crate::error::NetconfError;
use crate::wire::{bytes_as_text, printable, strict_u32};

/// The sequence that terminates a message in base:1.0 framing.
pub const EOM: &[u8] = b"]]>]]>";

/// The upper bound on one buffered message, and on a single chunk size. It guards
/// against a device that never terminates a message, or that sends an absurd chunk
/// length, and so makes the de-framer buffer without limit. 64 MiB is generous even
/// for large configurations. Exceeding it produces `Protocol`, never an
/// out-of-memory condition or a panic.
pub const DEFAULT_MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// The framing chosen for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// End-of-message: `<message>]]>]]>`. The baseline, base:1.0.
    Eom,
    /// Chunked (base:1.1): `\n#<len>\n<data>` … `\n##\n`.
    Chunked,
}

/// Frame one message for sending.
pub fn encode(mode: Framing, msg: &[u8]) -> Vec<u8> {
    match mode {
        Framing::Eom => {
            let mut v = Vec::with_capacity(msg.len() + EOM.len());
            v.extend_from_slice(msg);
            v.extend_from_slice(EOM);
            v
        }
        Framing::Chunked => {
            // RFC 6242 forbids a chunk size of 0, so an empty message is the
            // end-of-chunks marker alone rather than a zero-length chunk. Nothing
            // here sends an empty RPC, but `encode` is public and must not be able
            // to produce a frame the standard rejects.
            if msg.is_empty() {
                return b"\n##\n".to_vec();
            }
            // One chunk per message is enough, and Junos accepts it.
            let size = msg.len().to_string();
            let mut v = Vec::with_capacity(msg.len() + size.len() + 8);
            v.extend_from_slice(b"\n#");
            v.extend_from_slice(size.as_bytes());
            v.push(b'\n');
            v.extend_from_slice(msg);
            v.extend_from_slice(b"\n##\n");
            v
        }
    }
}

/// An incremental de-framer. Fed raw bytes from the transport through
/// [`push`](Self::push), and yields complete messages through
/// [`next_message`](Self::next_message).
#[derive(Debug)]
pub struct Decoder {
    mode: Framing,
    buf: Vec<u8>,
    max: usize,
    /// How far the end-of-message search has already looked without a match. The
    /// next search resumes there instead of starting over, so a message arriving in
    /// many pieces costs linear time rather than quadratic.
    scanned: usize,
    /// How far the chunked walk has come through the message in progress. It too
    /// resumes where it stopped: the walk used to start over from the first chunk
    /// header on every read, so a message arriving in many chunks over many reads
    /// cost time in proportion to chunks × reads, while the data was copied once.
    chunks: ChunkWalk,
}

/// The chunked walk's position in the message in progress — see [`Decoder`].
#[derive(Debug, Default)]
struct ChunkWalk {
    /// Where the next chunk header begins; or, when the header at the end of the
    /// buffer is not complete, where it began, so the walk reads it again whole.
    pos: usize,
    /// The data range of every chunk found so far, in order.
    ranges: Vec<(usize, usize)>,
    /// The chunks' total length.
    total: usize,
}

impl Decoder {
    /// A new de-framer in the given mode, with the default maximum message size.
    pub fn new(mode: Framing) -> Self {
        Decoder {
            mode,
            buf: Vec::new(),
            max: DEFAULT_MAX_MESSAGE,
            scanned: 0,
            chunks: ChunkWalk::default(),
        }
    }

    /// A new de-framer with an explicit upper bound on one message.
    pub fn with_max_message_size(mode: Framing, max: usize) -> Self {
        Decoder {
            mode,
            buf: Vec::new(),
            max,
            scanned: 0,
            chunks: ChunkWalk::default(),
        }
    }

    /// Switch framing mode. Only to be called on a message boundary, with an empty
    /// remainder buffer — for instance right after hello, which is always
    /// end-of-message, has been read and the session moves to chunked.
    pub fn set_mode(&mut self, mode: Framing) {
        self.mode = mode;
        self.scanned = 0;
        self.chunks = ChunkWalk::default();
    }

    /// Whether anything other than whitespace is still buffered. A framing switch is
    /// only sound when nothing is: bytes buffered under one framing cannot be read
    /// under the other. Whitespace does not count — a device may send it between
    /// messages, and the chunked reader skips it (RFC 6242 §4.2).
    pub(crate) fn holds_data(&self) -> bool {
        self.buf.iter().any(|b| !b.is_ascii_whitespace())
    }

    /// What is buffered and not yet a message: the incomplete message, when the
    /// device stops part-way through one. A session puts it in the error it reports
    /// (0.5.13).
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buf
    }

    /// Add received bytes. They may be any part of one or more messages.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Take the next complete message, if the buffer holds one.
    ///
    /// `Ok(None)` means «more bytes are needed». `Err` means a framing violation.
    /// Never a panic.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>, NetconfError> {
        match self.mode {
            Framing::Eom => self.next_eom(),
            Framing::Chunked => self.next_chunked(),
        }
    }

    /// Drop the first `n` bytes, which have been turned into a message.
    ///
    /// `drain` shifts whatever follows, and in a request/response protocol that is
    /// normally nothing at all — so the common case is a whole-buffer clear, which
    /// needs no shifting. Taking that path explicitly keeps the frequent case free
    /// and leaves `drain` for the genuinely pipelined one.
    fn consume(&mut self, n: usize) {
        // Whatever remains is the start of a new message, searched from its start.
        self.scanned = 0;
        self.chunks = ChunkWalk::default();
        if n >= self.buf.len() {
            self.buf.clear();
        } else {
            self.buf.drain(..n);
        }
    }

    fn next_eom(&mut self) -> Result<Option<Vec<u8>>, NetconfError> {
        // Resume where the last search stopped, backed up by one byte less than the
        // terminator: a terminator split across two reads starts no earlier than
        // that. Searching the whole buffer on every read made a large reply that
        // arrives in many pieces cost quadratic time.
        let from = self.scanned.saturating_sub(EOM.len() - 1);
        if let Some(pos) = find_subslice(&self.buf[from..], EOM).map(|p| from + p) {
            let msg = self.buf[..pos].to_vec();
            self.consume(pos + EOM.len());
            Ok(Some(msg))
        } else if self.buf.len() > self.max {
            // No terminator found and the buffer has passed the cap: the device is
            // sending a message that never ends. Fail-closed rather than grow without
            // limit.
            Err(NetconfError::protocol_with(
                format!("message exceeds max ({} B) without EOM", self.max),
                bytes_as_text(&self.buf),
            ))
        } else {
            self.scanned = self.buf.len();
            Ok(None)
        }
    }

    fn next_chunked(&mut self) -> Result<Option<Vec<u8>>, NetconfError> {
        match walk_chunks(&self.buf, self.max, &mut self.chunks)? {
            Some(consumed) => {
                // The data is copied once, now that the whole message is here.
                let mut msg = Vec::with_capacity(self.chunks.total);
                for &(start, end) in &self.chunks.ranges {
                    msg.extend_from_slice(&self.buf[start..end]);
                }
                self.consume(consumed);
                Ok(Some(msg))
            }
            None if self.buf.len() > self.max => Err(NetconfError::protocol_with(
                format!("chunked message exceeds the maximum ({} B)", self.max),
                bytes_as_text(&self.buf),
            )),
            None => Ok(None),
        }
    }
}

/// Walk the chunk headers of the message at the front of `buf`, from where the walk
/// stopped last time. `Ok(Some(bytes_consumed))` when the end-of-chunks marker is in
/// and `walk` holds every chunk's range; `Ok(None)` if more data is needed; `Err` on
/// a violation.
///
/// The walk only reads headers — it jumps over each chunk's data — and it never
/// reads a header twice unless the header was cut off by the end of the buffer. So
/// the cost of de-framing a message is proportional to its headers and its data, not
/// to the number of reads it arrived in.
fn walk_chunks(
    buf: &[u8],
    max: usize,
    walk: &mut ChunkWalk,
) -> Result<Option<usize>, NetconfError> {
    let mut i = walk.pos;

    // RFC 6242 §4.2: characters between the end-of-chunks delimiter and the next
    // chunk header are discarded by the receiver. We used to require the very first
    // byte to begin `\n#`, so a stray CR or a blank line — which a device is free to
    // send — became a protocol error and killed the session.
    //
    // Only WHITESPACE is discarded, not anything at all. That is what the rule is
    // for in practice, and it keeps the useful property that real garbage still
    // fails fast: swallowing arbitrary bytes would turn a malformed stream into a
    // session that waits forever instead of saying what is wrong.
    //
    // A newline that is the last byte in the buffer is kept: it may be the first
    // byte of the header, with the `#` still to come.
    if walk.ranges.is_empty() {
        while i < buf.len() && buf[i].is_ascii_whitespace() {
            if buf[i] == b'\n' && !matches!(buf.get(i + 1), Some(b) if *b != b'#') {
                break;
            }
            i += 1;
        }
    }

    loop {
        // Every step begins with "\n#". A header cut off by the end of the buffer
        // is read again whole on the next read.
        let header = i;
        if i + 2 > buf.len() {
            walk.pos = header;
            return Ok(None);
        }
        if buf[i] != b'\n' || buf[i + 1] != b'#' {
            return Err(unexpected(buf, i, 2, "\\n# at chunk start"));
        }
        i += 2;

        if i >= buf.len() {
            walk.pos = header;
            return Ok(None);
        }
        if buf[i] == b'#' {
            // End-of-chunks is "\n##\n"; we have seen "\n##" and need the final LF.
            i += 1;
            if i >= buf.len() {
                walk.pos = header;
                return Ok(None);
            }
            if buf[i] != b'\n' {
                return Err(unexpected(buf, i, 1, "LF after ##"));
            }
            return Ok(Some(i + 1));
        }

        // The chunk-size is 1*DIGIT terminated by LF.
        let start = i;
        while i < buf.len() && buf[i].is_ascii_digit() {
            i += 1;
        }
        if i >= buf.len() {
            walk.pos = header;
            return Ok(None); // the digits may be incomplete
        }
        if buf[i] != b'\n' {
            return Err(unexpected(buf, i, 1, "LF after chunk-size"));
        }
        // From here on the buffer as it stood goes with every violation (0.5.13).
        if i == start {
            return Err(NetconfError::protocol_with(
                "chunked: empty chunk-size",
                bytes_as_text(buf),
            ));
        }
        // The digits are ASCII, so this cannot fail.
        let digits = std::str::from_utf8(&buf[start..i]).unwrap_or("");
        // RFC 6242 §4.2 writes the chunk-size as decimal digits with no leading zero
        // and no more than 4294967295. `parse` used to read `007` as 7; a device
        // writing that is not writing the standard, and is refused — as the same
        // reader refuses it everywhere a number from the device is read.
        let size = strict_u32(digits).ok_or_else(|| {
            NetconfError::protocol_with(
                format!(
                    "chunked: chunk-size `{digits}` is not one RFC 6242 allows — decimal \
                     digits, no leading zero, at most 4294967295"
                ),
                bytes_as_text(buf),
            )
        })? as usize;
        if size == 0 {
            return Err(NetconfError::protocol_with(
                "chunked: chunk-size 0",
                bytes_as_text(buf),
            ));
        }
        // Refuse an absurd chunk length — digit-valid though it may be — BEFORE using
        // it in arithmetic: otherwise `i + size` can wrap and the slice panics, or
        // the message grows without limit.
        if size > max || walk.total.saturating_add(size) > max {
            return Err(NetconfError::protocol_with(
                format!("chunked: chunk size {size} exceeds the maximum ({max} B)"),
                bytes_as_text(buf),
            ));
        }
        i += 1; // consume the LF

        match i.checked_add(size) {
            Some(end) if end <= buf.len() => {
                walk.ranges.push((i, end));
                walk.total += size;
                i = end;
                walk.pos = i;
            }
            // Overflow — impossible after the maximum check, but kept defensively —
            // or the data is not all here yet. The header is read again next time.
            _ => {
                walk.pos = header;
                return Ok(None);
            }
        }
        // Continue the loop: the next chunk header, or end-of-chunks.
    }
}

/// A chunked framing violation at `at`: `expected` should have stood there, and the
/// `len` bytes that did are named in the text (0.5.13). The whole buffer goes with
/// the error, as the device sent it — the chunks before the violation and what came
/// after it.
fn unexpected(buf: &[u8], at: usize, len: usize, expected: &str) -> NetconfError {
    let found = &buf[at..buf.len().min(at + len)];
    NetconfError::protocol_with(
        format!(
            "chunked: expected {expected}, found `{}` at byte {at}",
            printable(&bytes_as_text(found))
        ),
        bytes_as_text(buf),
    )
}

/// Find the first occurrence of `needle` in `hay`.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
