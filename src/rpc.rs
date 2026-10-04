// SPDX-License-Identifier: MIT OR Apache-2.0
//! Building and parsing NETCONF messages (RFC 6241). The parser is **lenient**: it
//! matches on the local element name, ignoring prefix and namespace, so that both
//! the classic non-RFC replies from Junos and its `rfc-compliant` mode are
//! understood. It never panics on malformed input — a fault gives
//! [`NetconfError::Protocol`] for parsing, or [`NetconfError::Device`] for an
//! `<rpc-error>`.

use quick_xml::events::{BytesRef, Event};
use quick_xml::Reader;

use crate::error::{DeviceError, NetconfError};
use crate::wire::{printable, strict_u32, strict_u64};

/// Resolve an entity reference (`&amp;`, `&#10;`, ...) to the text it stands for.
///
/// quick-xml 0.40 and later delivers references as their OWN events
/// (`Event::GeneralRef`) rather than expanding them inline the way the older
/// `unescape()` did. We resolve character references and the five predefined XML
/// entities, and refuse everything else — fail-closed. An unknown entity from a
/// device is a protocol deviation, not something to guess at.
///
/// The error carries no document; a caller reading one the device sent puts it in
/// with [`NetconfError::about`] (0.5.13). What it quotes of the document — the
/// entity's name, the parser's text — goes through `filter` before it is made
/// printable (0.5.13).
pub(crate) fn resolve_entity(r: &BytesRef<'_>, filter: Filter<'_>) -> Result<String, NetconfError> {
    if let Some(c) = r.resolve_char_ref().map_err(|e| {
        NetconfError::protocol(format!(
            "XML character reference: {}",
            quoted(filter, &e.to_string())
        ))
    })? {
        return Ok(c.to_string());
    }
    let name = r.decode().map_err(|e| {
        NetconfError::protocol(format!("XML entity: {}", quoted(filter, &e.to_string())))
    })?;
    Ok(match name.as_ref() {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "apos" => "'",
        "quot" => "\"",
        other => {
            return Err(NetconfError::protocol(format!(
                "unknown XML entity &{};",
                quoted(filter, other)
            )))
        }
    }
    .to_string())
}

/// The filter the device's text passes before it goes into an error's text: the
/// session's policy, or [`redact_secrets`](crate::redact::redact_secrets) where no
/// policy is bound (0.5.13).
pub(crate) type Filter<'a> = &'a dyn Fn(&str) -> String;

/// The filter where no policy is bound: the device's secrets redacted.
pub(crate) fn no_policy(text: &str) -> String {
    crate::redact::redact_secrets(text)
}

/// Text the error quotes from the document — a parser's message, a name — through
/// `filter` as the document wrote it, then made printable (0.5.13; it was made
/// printable and never filtered).
pub(crate) fn quoted(filter: Filter<'_>, text: &str) -> String {
    printable(&filter(text))
}

/// NETCONF base:1.0 capability-URI.
pub const BASE_1_0: &str = "urn:ietf:params:xml:ns:netconf:base:1.0";
/// NETCONF base:1.1 capability-URI (chunked framing).
pub const BASE_1_1: &str = "urn:ietf:params:xml:ns:netconf:base:1.1";

/// Build the client's `<hello>`. Announces 1.1 alongside 1.0 when `offer_1_1`.
pub fn client_hello(offer_1_1: bool) -> String {
    let extra = if offer_1_1 {
        format!("<capability>{BASE_1_1}</capability>")
    } else {
        String::new()
    };
    format!(
        "<hello xmlns=\"{BASE_1_0}\"><capabilities>\
         <capability>{BASE_1_0}</capability>{extra}\
         </capabilities></hello>"
    )
}

/// Wrap an RPC body in an `<rpc>` envelope with the given `message-id`.
pub fn wrap_rpc(message_id: u64, inner: &str) -> String {
    format!("<rpc xmlns=\"{BASE_1_0}\" message-id=\"{message_id}\">{inner}</rpc>")
}

/// Take the capability URIs out of a `<hello>` document. What a `Protocol` error
/// quotes of the document is redacted with
/// [`redact_secrets`](crate::redact::redact_secrets): no policy is bound here
/// (0.5.13).
pub fn parse_hello_capabilities(xml: &str) -> Result<Vec<String>, NetconfError> {
    let mut reader = Reader::from_str(xml);
    let filter: Filter<'_> = &no_policy;
    let mut caps = Vec::new();
    let mut in_cap = false;
    let mut cur = String::new();
    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(NetconfError::protocol_with(
                    format!("hello XML parse error: {}", quoted(filter, &e.to_string())),
                    xml,
                ))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if local_eq(e.local_name().as_ref(), b"capability") {
                    in_cap = true;
                    cur.clear();
                }
            }
            Ok(Event::Text(t)) if in_cap => {
                let s = t.xml10_content().map_err(|e| {
                    NetconfError::protocol_with(
                        format!("hello text: {}", quoted(filter, &e.to_string())),
                        xml,
                    )
                })?;
                cur.push_str(&s);
            }
            Ok(Event::GeneralRef(r)) if in_cap => {
                cur.push_str(&resolve_entity(&r, filter).map_err(|e| e.about(xml))?);
            }
            // A capability in CDATA is a capability (0.5.13); it used to be skipped.
            Ok(Event::CData(t)) if in_cap => {
                cur.push_str(&String::from_utf8_lossy(&t));
            }
            // An entity anywhere else in the hello must still be one we know.
            Ok(Event::GeneralRef(r)) => {
                resolve_entity(&r, filter).map_err(|e| e.about(xml))?;
            }
            Ok(Event::End(e)) if in_cap && local_eq(e.local_name().as_ref(), b"capability") => {
                // Made printable, as the device's text is wherever the crate hands
                // it on (0.5.13); a capability holds nothing secret.
                let v = printable(cur.trim());
                if !v.is_empty() {
                    caps.push(v);
                }
                in_cap = false;
            }
            _ => {}
        }
    }
    if caps.is_empty() {
        // What the device sent instead goes with it (0.5.13).
        return Err(NetconfError::protocol_with(
            "hello without capabilities",
            xml,
        ));
    }
    Ok(caps)
}

/// Check an `<rpc-reply>` for `<rpc-error>`. When any of them is an error, the first
/// error is returned as [`NetconfError::Device`], carrying every other `<rpc-error>`
/// of the reply — errors and warnings — in [`DeviceError::also`], and what the reply
/// held besides in [`DeviceError::rest`]. Warnings alone are not a fault: `Ok` with
/// the warnings, in the device's order (0.5.13; `Ok(())` before, and the warnings
/// were dropped), and the caller keeps the raw XML. Malformed XML gives
/// [`NetconfError::Protocol`].
///
/// The device's text in an error — every field of a `DeviceError`, `other` and
/// `rest`, and what a `Protocol` error quotes of the document — comes redacted with
/// [`redact_secrets`](crate::redact::redact_secrets): no policy is bound here, and
/// without one that lets the device's secrets through, they are redacted (0.5.13).
pub fn parse_rpc_reply(xml: &str) -> Result<Vec<DeviceError>, NetconfError> {
    split_reply_errors(read_rpc_reply(xml, &no_policy)?.finish(|text| no_policy(&text)))
}

/// Whether an `<rpc-error>` is fatal: `error`, `fatal`, or no severity at all. A
/// `warning` is not — Junos returns commit warnings that must not stop the RPC.
fn is_fatal(e: &DeviceError) -> bool {
    e.severity.as_deref() != Some("warning")
}

/// What [`read_rpc_reply`] read: every `<rpc-error>`, and the rest of the reply.
///
/// The text in each error's `other` is as the device wrote it until
/// [`finish`](Self::finish) has filtered it and made it printable.
pub(crate) struct ReplyRead {
    /// Every `<rpc-error>`, errors and warnings alike, in the device's order.
    pub(crate) errors: Vec<DeviceError>,
    /// The reply with every `<rpc-error>` cut out, when what is left is more than
    /// `<ok/>` and one of them is fatal — see [`DeviceError::rest`].
    pub(crate) rest: Option<String>,
}

impl ReplyRead {
    /// The device's text in every error — every field and `other` — through
    /// `filter`, then made printable; and the rest of the reply through `filter`,
    /// kept as the device wrote it.
    ///
    /// In that order: the filter reads the device's text as it wrote it — its
    /// lines and its words. Made printable first, a line break is the two
    /// characters `\n`, and a secret's name at the start of the next line is no
    /// longer a word of its own. A session passes its policy's redaction, so the
    /// policy decides, both ways (0.5.13; `path`, `message` and `info` used to be
    /// redacted whatever the policy said, and `error-type`, `-tag`, `-severity` and
    /// `-app-tag` were made printable and never filtered).
    pub(crate) fn finish(mut self, filter: impl Fn(String) -> String) -> Self {
        let shown = |text: &mut String| *text = printable(&filter(std::mem::take(text)));
        for e in &mut self.errors {
            for field in [
                &mut e.error_type,
                &mut e.tag,
                &mut e.severity,
                &mut e.path,
                &mut e.message,
                &mut e.app_tag,
                &mut e.info,
            ] {
                if let Some(text) = field.as_mut() {
                    shown(text);
                }
            }
            for (_, text) in &mut e.other {
                shown(text);
            }
        }
        self.rest = self.rest.map(&filter);
        self
    }
}

/// The result a reply's `<rpc-error>`s make. When any is fatal: `Err(Device)` with the
/// first fatal one, every other — errors and warnings, in the device's order — in
/// its `also`, and the rest of the reply in its `rest`. Otherwise `Ok` with the
/// warnings, which are not errors and are still reported.
pub(crate) fn split_reply_errors(read: ReplyRead) -> Result<Vec<DeviceError>, NetconfError> {
    let ReplyRead { mut errors, rest } = read;
    match errors.iter().position(is_fatal) {
        Some(i) => {
            let mut first = errors.remove(i);
            first.also = errors;
            first.rest = rest;
            Err(NetconfError::Device(Box::new(first)))
        }
        None => Ok(errors),
    }
}

/// The field of an `<rpc-error>` being read: which field, the local name of the
/// element that opened it, and — for `error-info` — the element names inside it.
struct OpenField {
    field: Field,
    /// The element that opened the field; only its own end tag closes it.
    name: Vec<u8>,
    /// For `Info`: the elements open inside it, outermost first, so its text keeps
    /// their names (0.5.13). `bad-element` opening the field directly is the first.
    path: Vec<String>,
    /// For `Info`: the parts read so far — `name: text`, or bare text.
    parts: Vec<String>,
}

impl OpenField {
    /// Take the text read since the last element boundary as one part of `Info`,
    /// named by the elements it stands in.
    fn flush_info(&mut self, text: &mut String) {
        let t = text.trim();
        if !t.is_empty() {
            self.parts.push(if self.path.is_empty() {
                t.to_string()
            } else {
                format!("{}: {t}", self.path.join("/"))
            });
        }
        text.clear();
    }
}

/// Read an `<rpc-reply>`: every `<rpc-error>` in it, errors and warnings alike, in the
/// order the device sent them, and what the reply holds besides. `Err` only when the
/// reply itself cannot be read — malformed XML, or a document that is not an
/// `<rpc-reply>`.
///
/// Only the first error used to be kept, and every other `<rpc-error>` of the reply
/// — further errors, and all warnings — was dropped. Until 0.5.13 so was the rest
/// of the reply, a child of `<rpc-error>` that is not one of its fields, text
/// outside its fields, and the element names inside `<error-info>`.
pub(crate) fn read_rpc_reply(xml: &str, filter: Filter<'_>) -> Result<ReplyRead, NetconfError> {
    let mut reader = Reader::from_str(xml);
    let mut in_error = false;
    // The field being read, together with the local name of the element that
    // opened it. The name matters: without it, a nested tag inside the field — and
    // Junos does emit markup inside `<error-message>` — closed the field early, and
    // its opening cleared the text accumulated so far. The message came out `None`.
    let mut cur_field: Option<OpenField> = None;
    let mut de = DeviceError::default();
    let mut errors: Vec<DeviceError> = Vec::new();
    let mut cur = String::new();
    // Text inside an `<rpc-error>` and outside every element in it.
    let mut loose = String::new();
    let mut depth: i32 = 0;
    // The root element has to BE an `<rpc-reply>`.
    //
    // This function only ever scanned for `<rpc-error>`, so anything without one
    // came back `Ok(())` — a `<hello>`, a notification, an unrelated document. The
    // caller then read it as a successful answer to its request.
    let mut root_seen: Option<Vec<u8>> = None;
    // The rest of the reply (0.5.13): where each `<rpc-error>` stands, to cut it
    // out, and whether what is left says more than `<ok/>` — text, or an element
    // with nothing in it other than `ok` and the root. `outside` holds, for every
    // element open outside an `<rpc-error>`, whether it has had a child.
    let mut cut: Vec<(usize, usize)> = Vec::new();
    let mut error_start = 0usize;
    let mut outside: Vec<bool> = Vec::new();
    let mut more = false;
    loop {
        let before = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
        let event = reader.read_event();
        let after = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
        match event {
            Err(e) => {
                return Err(NetconfError::protocol_with(
                    format!(
                        "rpc-reply XML parse error: {}",
                        quoted(filter, &e.to_string())
                    ),
                    xml,
                ))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                depth += 1;
                let ln = e.local_name();
                let name = ln.as_ref();
                if root_seen.is_none() {
                    root_seen = Some(name.to_vec());
                }
                if !in_error {
                    if let Some(parent) = outside.last_mut() {
                        *parent = true;
                    }
                }
                if !in_error && local_eq(name, b"rpc-error") {
                    in_error = true;
                    de = DeviceError::default();
                    error_start = before;
                } else if in_error {
                    // Anything that is NOT a field element is markup nested inside
                    // one we may already be reading. It is not a field of its own,
                    // and it must neither end nor erase the one in progress — the
                    // text around it is the message.
                    //
                    // The same holds for an element that IS a field name, once a
                    // field is already open. `bad-element` is the info under
                    // `error-info`, but Junos also marks the offending token inside
                    // the message itself — `<error-message>bad <bad-element>unit
                    // </bad-element> here</error-message>` — and treating that as a
                    // new field threw away «bad » and never closed the message. An
                    // open field keeps collecting until its own closing tag.
                    //
                    // Inside `error-info` the nested names are kept (0.5.13).
                    match cur_field.as_mut() {
                        Some(open) if matches!(open.field, Field::Info) => {
                            open.flush_info(&mut cur);
                            open.path.push(String::from_utf8_lossy(name).into_owned());
                        }
                        Some(_) => {}
                        None => {
                            take_loose(&mut de, &mut loose);
                            // A child that is not one of the known fields is kept by
                            // its name (0.5.13); it used to be dropped.
                            let field = field_of(name).unwrap_or(Field::Other);
                            let path = match field {
                                Field::Info if name != b"error-info" => {
                                    vec![String::from_utf8_lossy(name).into_owned()]
                                }
                                _ => Vec::new(),
                            };
                            cur_field = Some(OpenField {
                                field,
                                name: name.to_vec(),
                                path,
                                parts: Vec::new(),
                            });
                            cur.clear();
                        }
                    }
                } else {
                    outside.push(false);
                }
            }
            Ok(Event::Empty(e)) => {
                let ln = e.local_name();
                let name = ln.as_ref();
                // An empty reply arrives as `<rpc-reply/>`, which quick-xml reports
                // as Empty and never as Start. Recording the root only on Start made
                // the root check conclude that the document held no elements at all,
                // so a device answering a request with nothing to say was read as a
                // protocol violation.
                if root_seen.is_none() {
                    root_seen = Some(name.to_vec());
                }
                if in_error {
                    match cur_field.as_mut() {
                        Some(open) if matches!(open.field, Field::Info) => {
                            open.flush_info(&mut cur);
                            let mut path = open.path.clone();
                            path.push(String::from_utf8_lossy(name).into_owned());
                            open.parts.push(format!("{}:", path.join("/")));
                        }
                        Some(_) => {}
                        None => {
                            take_loose(&mut de, &mut loose);
                            // An empty child is there, and empty (0.5.13): a known
                            // field is `Some("")`, not absent, and any other is kept
                            // by its name. An empty `bad-element` reads `bad-element:`,
                            // as one inside `error-info` does.
                            let field = field_of(name).unwrap_or(Field::Other);
                            let value = match field {
                                Field::Info if name != b"error-info" => {
                                    format!("{}:", String::from_utf8_lossy(name))
                                }
                                _ => String::new(),
                            };
                            let open = OpenField {
                                field,
                                name: name.to_vec(),
                                path: Vec::new(),
                                parts: Vec::new(),
                            };
                            set_field(&mut de, &open, value);
                        }
                    }
                } else {
                    if let Some(parent) = outside.last_mut() {
                        *parent = true;
                    }
                    // A self-closing `<rpc-error/>` is still an error, not a silent
                    // success: it has no severity, so it is fatal.
                    if local_eq(name, b"rpc-error") {
                        errors.push(DeviceError::default());
                        cut.push((before, after));
                    } else if !local_eq(name, b"ok") && !local_eq(name, b"rpc-reply") {
                        more = true;
                    }
                }
            }
            Ok(Event::Text(t)) if in_error => {
                let s = t.xml10_content().map_err(|e| {
                    NetconfError::protocol_with(
                        format!("rpc-error text: {}", quoted(filter, &e.to_string())),
                        xml,
                    )
                })?;
                if cur_field.is_some() {
                    cur.push_str(&s);
                } else {
                    loose.push_str(&s);
                }
            }
            Ok(Event::GeneralRef(r)) if in_error => {
                let s = resolve_entity(&r, filter).map_err(|e| e.about(xml))?;
                if cur_field.is_some() {
                    cur.push_str(&s);
                } else {
                    loose.push_str(&s);
                }
            }
            Ok(Event::CData(t)) if in_error => {
                // CDATA is raw and unescaped, so take the content directly.
                let s = String::from_utf8_lossy(&t.into_inner()).into_owned();
                if cur_field.is_some() {
                    cur.push_str(&s);
                } else {
                    loose.push_str(&s);
                }
            }
            // An entity anywhere in a reply must be one we know — the five predefined
            // ones or a character reference. It used to be checked only inside an
            // `<rpc-error>`'s fields, while `&nbsp;` in `<data>` passed through.
            Ok(Event::GeneralRef(r)) => {
                resolve_entity(&r, filter).map_err(|e| e.about(xml))?;
                more = true;
            }
            Ok(Event::Text(t)) => {
                if t.iter().any(|b| !b.is_ascii_whitespace()) {
                    more = true;
                }
            }
            Ok(Event::CData(t)) => {
                if !t.is_empty() {
                    more = true;
                }
            }
            // A comment or a processing instruction is something the device wrote
            // (0.5.13): inside an `<rpc-error>` it is kept in `other` as `#comment`
            // or `#pi`, and outside one it makes the rest of the reply worth
            // carrying. Both used to be dropped.
            Ok(Event::Comment(t)) => {
                let text = String::from_utf8_lossy(&t).trim().to_string();
                if in_error {
                    de.other.push(("#comment".to_string(), text));
                } else {
                    more = true;
                }
            }
            Ok(Event::PI(t)) => {
                let text = String::from_utf8_lossy(&t).trim().to_string();
                if in_error {
                    de.other.push(("#pi".to_string(), text));
                } else {
                    more = true;
                }
            }
            Ok(Event::End(e)) => {
                depth -= 1;
                let ln = e.local_name();
                let name = ln.as_ref();
                if in_error && cur_field.is_none() && local_eq(name, b"rpc-error") {
                    in_error = false;
                    take_loose(&mut de, &mut loose);
                    // Every `<rpc-error>` is kept, warnings included. Which of them
                    // fail the call is `split_reply_errors`' decision.
                    errors.push(std::mem::take(&mut de));
                    cut.push((error_start, after));
                } else if in_error {
                    // Only the element that opened the field closes it. Any other
                    // end tag belongs to markup nested inside, and the field goes on.
                    let closes = cur_field.as_ref().is_some_and(|open| open.name == name);
                    if closes {
                        if let Some(mut open) = cur_field.take() {
                            let value = if matches!(open.field, Field::Info) {
                                open.flush_info(&mut cur);
                                open.parts.join(" · ")
                            } else {
                                cur.trim().to_string()
                            };
                            set_field(&mut de, &open, value);
                        }
                    } else if let Some(open) = cur_field.as_mut() {
                        if matches!(open.field, Field::Info)
                            && open.path.last().is_some_and(|n| n.as_bytes() == name)
                        {
                            open.flush_info(&mut cur);
                            open.path.pop();
                        }
                    }
                } else {
                    let had_child = outside.pop().unwrap_or(true);
                    if !had_child && !local_eq(name, b"ok") && !local_eq(name, b"rpc-reply") {
                        more = true;
                    }
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(NetconfError::protocol_with(
            "rpc-reply: incomplete XML (unclosed elements at EOF)",
            xml,
        ));
    }
    // A fatal `<rpc-error>` is reported as such whatever wrapped it — the error is
    // the more specific answer, and a device that sends one has told us what is
    // wrong. The rest of the reply goes with it; a reply that succeeds is handed
    // over whole, so its rest is not cut out.
    if errors.iter().any(is_fatal) {
        let rest = more.then(|| without(xml, &cut));
        return Ok(ReplyRead { errors, rest });
    }
    match root_seen {
        Some(root) if local_eq(&root, b"rpc-reply") => Ok(ReplyRead { errors, rest: None }),
        // The root's name goes into the text, and the document with it (0.5.13).
        Some(root) => Err(NetconfError::protocol_with(
            format!(
                "reply is not an <rpc-reply> but a <{}> — refusing to read it as one",
                quoted(filter, &String::from_utf8_lossy(&root))
            ),
            xml,
        )),
        None => Err(NetconfError::protocol_with(
            "reply contains no elements at all",
            xml,
        )),
    }
}

/// Text inside an `<rpc-error>` and outside every element in it, kept as an entry
/// of its own in `other` under the name `#text` (0.5.13).
fn take_loose(de: &mut DeviceError, loose: &mut String) {
    let t = loose.trim();
    if !t.is_empty() {
        // As the device wrote it: `ReplyRead::finish` filters it, then makes it
        // printable.
        de.other.push(("#text".to_string(), t.to_string()));
    }
    loose.clear();
}

/// `xml` with every range in `cut` taken out. The ranges are in order and do not
/// overlap.
fn without(xml: &str, cut: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut from = 0;
    for &(start, end) in cut {
        out.push_str(xml.get(from..start).unwrap_or_default());
        from = end;
    }
    out.push_str(xml.get(from..).unwrap_or_default());
    out
}

/// The server's `<session-id>` from its `<hello>`.
///
/// RFC 6241 §8.1 makes it mandatory in the server's hello, and it is the only way
/// a client can name its own session — to `<kill-session>` it later, or simply to
/// put it in a log line beside the device's own. It used to be parsed past and
/// dropped, so a consumer had no way to obtain it at all.
///
/// `None` if the element is absent or not a number; that is the device deviating,
/// and it is not worth refusing the session over. A number is what RFC 6241's
/// `unsignedInt` writes (0.5.11): decimal digits, no sign, no leading zero, at most
/// 4294967295. `007`, `+7` and `" 7 "` used to be read as 7; they are `None` now,
/// as the same reader says everywhere a number from the device is read. The
/// whitespace XML allows around an element's content is still trimmed.
pub fn hello_session_id(xml: &str) -> Option<u64> {
    let mut reader = Reader::from_str(xml);
    let mut in_id = false;
    let mut cur = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) if local_eq(e.local_name().as_ref(), b"session-id") => {
                in_id = true;
                cur.clear();
            }
            Ok(Event::Text(t)) if in_id => {
                cur.push_str(&String::from_utf8_lossy(&t.into_inner()));
            }
            Ok(Event::End(e)) if local_eq(e.local_name().as_ref(), b"session-id") => {
                return strict_u32(cur.trim()).map(u64::from);
            }
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
    }
}

/// Extract the `message-id` attribute from the first `<rpc-reply>` element.
/// `None` if the attribute is absent: Junos leaves it out now and then, and we
/// tolerate that quirk rather than failing. Used to correlate replies.
///
/// A `message-id` that is present but not a number is also `None` here — and a
/// number is what this crate writes into a request (0.5.11): decimal digits, no
/// sign, no whitespace, no leading zero, anything a `u64` holds. `007` is not 7. The session does not read
/// the attribute as a number at all: it compares the text with the one it sent,
/// byte for byte, and tolerates only one that is absent.
pub fn reply_message_id(xml: &str) -> Option<u64> {
    strict_u64(&reply_message_id_raw(xml)?)
}

/// The `message-id` attribute of the first `<rpc-reply>`, as the device wrote it.
///
/// `None` means the attribute is absent — the Junos quirk we tolerate. `Some` is
/// the raw text whether or not it is a number, so a caller can tell a
/// `message-id` that is missing from one that is there and malformed. Collapsing
/// the two let a malformed id pass as a missing one, and a missing one is let
/// through.
pub(crate) fn reply_message_id_raw(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e))
                if local_eq(e.local_name().as_ref(), b"rpc-reply") =>
            {
                for attr in e.attributes().flatten() {
                    if attr.key.local_name().as_ref() == b"message-id" {
                        return Some(String::from_utf8_lossy(&attr.value).into_owned());
                    }
                }
                return None;
            }
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
    }
}

/// Extract the diff text itself from a `show | compare` reply — the content of
/// `<configuration-output>`. This is **deterministic**, unlike the raw
/// `<rpc-reply>`, which carries a per-call `message-id`, so it is what the drift
/// comparison in compare-then-commit rests on.
///
/// An empty element — `<configuration-output/>`, or one holding only whitespace —
/// is `""`: the device answered, and the diff is empty. A reply with **no**
/// `<configuration-output>` is [`NetconfError::Protocol`] (0.5.7): the device has
/// not said what the diff is, and an absent answer is not an empty one. It used to
/// read as `""` too, so a reply holding only `<ok/>`, or only warnings, passed the
/// drift check as «no change» and the candidate was committed.
///
/// What a `Protocol` error quotes of the document is redacted with
/// [`redact_secrets`](crate::redact::redact_secrets): no policy is bound here
/// (0.5.13).
pub fn extract_compare_diff(xml: &str) -> Result<String, NetconfError> {
    compare_diff(xml, &no_policy)
}

/// [`extract_compare_diff`], with what a `Protocol` error quotes of the document
/// through `filter` (0.5.13).
pub(crate) fn compare_diff(xml: &str, filter: Filter<'_>) -> Result<String, NetconfError> {
    let mut reader = Reader::from_str(xml);
    let mut present = false;
    let mut in_output = false;
    let mut out = String::new();
    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(NetconfError::protocol_with(
                    format!(
                        "compare XML parse error: {}",
                        quoted(filter, &e.to_string())
                    ),
                    xml,
                ))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) if local_eq(e.local_name().as_ref(), b"configuration-output") => {
                present = true;
                in_output = true;
            }
            Ok(Event::Empty(e)) if local_eq(e.local_name().as_ref(), b"configuration-output") => {
                present = true;
            }
            Ok(Event::End(e)) if local_eq(e.local_name().as_ref(), b"configuration-output") => {
                in_output = false;
            }
            Ok(Event::Text(t)) if in_output => {
                let s = t.xml10_content().map_err(|e| {
                    NetconfError::protocol_with(
                        format!("compare text: {}", quoted(filter, &e.to_string())),
                        xml,
                    )
                })?;
                out.push_str(&s);
            }
            Ok(Event::GeneralRef(r)) if in_output => {
                out.push_str(&resolve_entity(&r, filter).map_err(|e| e.about(xml))?);
            }
            Ok(Event::GeneralRef(r)) => {
                resolve_entity(&r, filter).map_err(|e| e.about(xml))?;
            }
            Ok(Event::CData(t)) if in_output => {
                // Some devices put the diff in CDATA. Without this the diff would come
                // back empty, and the drift check would read «no change» and commit
                // something nobody saw.
                out.push_str(&String::from_utf8_lossy(&t.into_inner()));
            }
            _ => {}
        }
    }
    // Absent is not empty (finding B2, Roger 2026-09-26: netconf reports what it
    // gets from the device, without judgement of its own). An empty element is the
    // device saying the diff is empty. No element is the device not saying — and
    // reading that as «no change» is a judgement this crate does not make.
    if !present {
        // What the device sent instead goes with it (0.5.13).
        return Err(NetconfError::protocol_with(
            "compare reply has no <configuration-output> — the device did not say what \
             the diff is, and an absent diff is not an empty one",
            xml,
        ));
    }
    Ok(out.trim().to_string())
}

#[derive(Clone, Copy)]
enum Field {
    Type,
    Tag,
    Severity,
    Path,
    Message,
    AppTag,
    Info,
    /// A child of `<rpc-error>` that is none of the above, kept by its name in
    /// `other` (0.5.13).
    Other,
}

fn field_of(name: &[u8]) -> Option<Field> {
    match name {
        b"error-type" => Some(Field::Type),
        b"error-tag" => Some(Field::Tag),
        b"error-severity" => Some(Field::Severity),
        b"error-path" => Some(Field::Path),
        b"error-message" => Some(Field::Message),
        b"error-app-tag" => Some(Field::AppTag),
        // `error-info` wraps free-form children. We take its text with the names of
        // the elements it stands in (0.5.13): the specific cause Junos puts in
        // `<bad-element>` is the point, and the name says what the text is.
        // Modelling the shape further would be guessing at a structure the standard
        // leaves open.
        b"error-info" | b"bad-element" | b"bad-attribute" => Some(Field::Info),
        _ => None,
    }
}

fn set_field(de: &mut DeviceError, open: &OpenField, v: String) {
    let f = open.field;
    // A child that is not a known field is kept by its name, made printable like
    // the fields; what the device wrote in it is kept as written here, and
    // `ReplyRead::finish` redacts it under the session's policy, as a reply is,
    // before it makes it printable (0.5.13).
    if let Field::Other = f {
        de.other
            .push((printable(&String::from_utf8_lossy(&open.name)), v));
        return;
    }
    // Sanitising the output: Junos often echoes the offending configuration line in
    // `<error-message>` and `<error-path>`, and a `DeviceError` ends up in the
    // consumer's error text and log. Secrets must not travel that way, and neither
    // may a control character (0.5.11): every field is made printable, so the
    // device's text stays on its own line and shows what it holds. Every field is
    // kept as the device wrote it here; `ReplyRead::finish` filters it under the
    // session's policy and then makes it printable (0.5.13). `error-type`, `-tag` and
    // `-severity` are meant to be fixed values, but nothing makes the device keep to
    // that, so they pass the filter like the rest.
    let slot = match f {
        Field::Type => &mut de.error_type,
        Field::Tag => &mut de.tag,
        Field::Severity => &mut de.severity,
        Field::Path => &mut de.path,
        Field::Message => &mut de.message,
        Field::AppTag => &mut de.app_tag,
        Field::Info => &mut de.info,
        Field::Other => return,
    };
    // A field the device sent again: the first stays where it is, and this one is
    // kept by its name in `other`, as the device wrote it — `ReplyRead::finish`
    // filters it and makes it printable (0.5.13). It used to overwrite the first.
    if slot.is_some() {
        de.other
            .push((printable(&String::from_utf8_lossy(&open.name)), v));
        return;
    }
    *slot = Some(v);
}

fn local_eq(name: &[u8], want: &[u8]) -> bool {
    name == want
}
