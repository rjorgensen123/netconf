// SPDX-License-Identifier: MIT OR Apache-2.0
//! Parsing of rpc-error and replies against fixtures: classic Junos style with
//! namespace prefixes, RFC-compliant style, and malformed input.

use netconf::rpc::parse_rpc_reply;
use netconf::NetconfError;

#[test]
fn ok_reply_is_ok() {
    let xml = "<rpc-reply message-id=\"1\"><ok/></rpc-reply>";
    assert!(parse_rpc_reply(xml).is_ok());
}

#[test]
fn data_reply_is_ok() {
    let xml = "<rpc-reply message-id=\"2\"><data><configuration><foo/></configuration></data></rpc-reply>";
    assert!(parse_rpc_reply(xml).is_ok());
}

#[test]
fn classic_junos_rpc_error_full_fields() {
    // A classic Junos reply, with a namespace prefix on the elements.
    let xml = "<nc:rpc-reply xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\
        <nc:rpc-error>\
        <nc:error-type>protocol</nc:error-type>\
        <nc:error-tag>operation-failed</nc:error-tag>\
        <nc:error-severity>error</nc:error-severity>\
        <nc:error-path>[edit interfaces]</nc:error-path>\
        <nc:error-message>syntax error</nc:error-message>\
        </nc:rpc-error></nc:rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(d.error_type.as_deref(), Some("protocol"));
            assert_eq!(d.tag.as_deref(), Some("operation-failed"));
            assert_eq!(d.severity.as_deref(), Some("error"));
            assert_eq!(d.path.as_deref(), Some("[edit interfaces]"));
            assert_eq!(d.message.as_deref(), Some("syntax error"));
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

#[test]
fn rfc_compliant_rpc_error_partial_fields() {
    // An RFC-compliant reply: tag and message only.
    let xml = "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\
        <rpc-error>\
        <error-tag>access-denied</error-tag>\
        <error-message>insufficient privileges</error-message>\
        </rpc-error></rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(d.tag.as_deref(), Some("access-denied"));
            assert_eq!(d.error_type, None);
            assert!(d.message.as_deref().unwrap().contains("privileges"));
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

#[test]
fn first_of_multiple_errors_is_reported() {
    let xml = "<rpc-reply>\
        <rpc-error><error-tag>first</error-tag></rpc-error>\
        <rpc-error><error-tag>second</error-tag></rpc-error>\
        </rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => assert_eq!(d.tag.as_deref(), Some("first")),
        other => panic!("expected a Device error, got {other:?}"),
    }
}

#[test]
fn malformed_xml_is_protocol_error() {
    let xml = "<rpc-reply><rpc-error><error-tag>unfinished";
    assert!(matches!(
        parse_rpc_reply(xml),
        Err(NetconfError::Protocol { .. })
    ));
}

#[test]
fn self_closed_rpc_error_is_not_silent_success() {
    // A self-closing <rpc-error/> (Event::Empty) must still be a Device error,
    // not Ok(()).
    let xml =
        r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><rpc-error/></rpc-reply>"#;
    assert!(matches!(parse_rpc_reply(xml), Err(NetconfError::Device(_))));
}

#[test]
fn rpc_error_message_in_cdata_is_caught() {
    // An error message wrapped in CDATA must reach DeviceError, not be dropped.
    let xml = concat!(
        r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><rpc-error>"#,
        r#"<error-severity>error</error-severity>"#,
        r#"<error-message><![CDATA[syntax error in set]]></error-message>"#,
        r#"</rpc-error></rpc-reply>"#,
    );
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert!(
                d.message.as_deref().unwrap_or("").contains("syntax error"),
                "the CDATA message is missing: {:?}",
                d.message
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

#[test]
fn warning_severity_is_not_fatal() {
    // Junos often returns commit warnings; they must NOT fail the RPC.
    let xml = "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><rpc-error>\
        <error-severity>warning</error-severity>\
        <error-message>statement not found, ignored</error-message>\
        </rpc-error></rpc-reply>";
    assert!(parse_rpc_reply(xml).is_ok());
}

#[test]
fn error_severity_is_still_fatal() {
    let xml = "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><rpc-error>\
        <error-severity>error</error-severity><error-message>it failed</error-message>\
        </rpc-error></rpc-reply>";
    assert!(matches!(parse_rpc_reply(xml), Err(NetconfError::Device(_))));
}

#[test]
fn reply_message_id_is_extracted_and_tolerates_absence() {
    use netconf::rpc::reply_message_id;
    assert_eq!(
        reply_message_id("<rpc-reply message-id=\"42\"><ok/></rpc-reply>"),
        Some(42)
    );
    assert_eq!(reply_message_id("<rpc-reply><ok/></rpc-reply>"), None); // the Junos quirk, tolerated
                                                                        // A number is what this crate writes: `042` is not 42.
    assert_eq!(
        reply_message_id("<rpc-reply message-id=\"042\"><ok/></rpc-reply>"),
        None
    );
}

/// **A control character in the device's error text is made visible, not passed
/// on.** The fields of a `DeviceError` end up in the consumer's error text and log;
/// a character the device wrote to act on a terminal or split a log line is written
/// out as an escape instead.
#[test]
fn a_control_character_in_a_device_error_is_made_printable() {
    let xml = "<rpc-reply><rpc-error><error-tag>x\u{7}</error-tag>\
               <error-message>line one\u{85}line two\u{2028}end</error-message>\
               </rpc-error></rpc-reply>";
    match netconf::rpc::parse_rpc_reply(xml) {
        Err(netconf::NetconfError::Device(d)) => {
            assert_eq!(d.tag.as_deref(), Some("x\\u{0007}"));
            assert_eq!(
                d.message.as_deref(),
                Some("line one\\u{0085}line two\\u{2028}end")
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// **A reply that is not an `<rpc-reply>` must not read as a successful one.**
///
/// The parser only ever scanned for `<rpc-error>`, so any document without one
/// came back `Ok(())`. A `<hello>`, a notification or an unrelated fragment was
/// therefore indistinguishable from a device saying «done».
#[test]
fn a_document_that_is_not_an_rpc_reply_is_refused() {
    for xml in [
        "<hello><capabilities><capability>urn:x</capability></capabilities></hello>",
        "<notification><eventTime>now</eventTime></notification>",
        "<data><something/></data>",
    ] {
        match netconf::rpc::parse_rpc_reply(xml) {
            Err(netconf::NetconfError::Protocol { detail, received }) => {
                assert!(detail.contains("rpc-reply"), "{xml}: {detail}");
                // The root that stood there is named, and the document goes with the
                // error (0.5.13).
                let root = &xml[1..xml.find('>').unwrap()];
                assert!(detail.contains(&format!("but a <{root}>")), "{detail}");
                assert_eq!(received.as_deref(), Some(xml));
            }
            other => panic!("{xml}: expected a Protocol error, got {other:?}"),
        }
    }
}

/// An empty document is not a reply either.
#[test]
fn an_empty_document_is_refused() {
    assert!(netconf::rpc::parse_rpc_reply("").is_err());
    assert!(netconf::rpc::parse_rpc_reply("   \n ").is_err());
}

/// And a real one still passes, prefixed or not.
#[test]
fn a_real_rpc_reply_still_passes() {
    netconf::rpc::parse_rpc_reply("<rpc-reply><ok/></rpc-reply>").expect("plain");
    netconf::rpc::parse_rpc_reply("<nc:rpc-reply><nc:ok/></nc:rpc-reply>").expect("prefixed");
}

/// **`<error-info>` is where Junos puts the specific cause.**
///
/// `<bad-element>` names the statement the device actually objected to, and it
/// used to be parsed past. Without it the caller gets «operation-failed» and no
/// indication of which statement caused it.
#[test]
fn the_specific_cause_in_error_info_reaches_the_caller() {
    let xml = "<rpc-reply><rpc-error>\
               <error-tag>operation-failed</error-tag>\
               <error-app-tag>commit-check</error-app-tag>\
               <error-message>configuration check-out failed</error-message>\
               <error-info><bad-element>vlan-id</bad-element></error-info>\
               </rpc-error></rpc-reply>";
    match netconf::rpc::parse_rpc_reply(xml) {
        Err(netconf::NetconfError::Device(d)) => {
            assert_eq!(d.tag.as_deref(), Some("operation-failed"));
            assert_eq!(d.app_tag.as_deref(), Some("commit-check"));
            assert_eq!(
                d.info.as_deref(),
                Some("bad-element: vlan-id"),
                "the element the device objected to must reach the caller, by its name"
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// And the content of `<error-info>` goes through redaction, like the message and
/// the path: it is device text that ends up in a consumer's log.
#[test]
fn error_info_is_redacted_like_the_rest() {
    let xml = "<rpc-reply><rpc-error><error-tag>x</error-tag>\
               <error-info><bad-element>encrypted-password \"$9$leaked\"</bad-element></error-info>\
               </rpc-error></rpc-reply>";
    match netconf::rpc::parse_rpc_reply(xml) {
        Err(netconf::NetconfError::Device(d)) => {
            let info = d.info.unwrap_or_default();
            assert!(
                !info.contains("$9$leaked"),
                "a secret leaked through: {info}"
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// **Markup inside `<error-message>` must not destroy the message.**
///
/// The field being read was identified only by which field it was, not by which
/// element opened it. So a nested tag — and Junos does emit markup inside an error
/// message — set the field to «none» and cleared the text accumulated so far,
/// while its closing tag ended the field early. The message came out as `None`:
/// the device explained itself and the caller got nothing.
#[test]
fn markup_inside_an_error_message_does_not_lose_it() {
    let xml = "<rpc-reply><rpc-error>\
               <error-message>before <b>inner</b> after</error-message>\
               </rpc-error></rpc-reply>";
    match netconf::rpc::parse_rpc_reply(xml) {
        Err(netconf::NetconfError::Device(d)) => {
            let m = d.message.unwrap_or_default();
            assert!(
                m.contains("before"),
                "the text before the markup is gone: {m}"
            );
            assert!(
                m.contains("after"),
                "the text after the markup is gone: {m}"
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// A field before or after a nested structure survives it either way.
#[test]
fn a_nested_structure_does_not_disturb_its_siblings() {
    let before = "<rpc-reply><rpc-error>\
                  <error-message>the reason</error-message>\
                  <error-info><bad-element>vlan-id</bad-element></error-info>\
                  </rpc-error></rpc-reply>";
    let after = "<rpc-reply><rpc-error>\
                 <error-info><bad-element>vlan-id</bad-element></error-info>\
                 <error-message>the reason</error-message>\
                 </rpc-error></rpc-reply>";
    for (name, xml) in [("before", before), ("after", after)] {
        match netconf::rpc::parse_rpc_reply(xml) {
            Err(netconf::NetconfError::Device(d)) => {
                assert_eq!(d.message.as_deref(), Some("the reason"), "{name}");
                assert_eq!(d.info.as_deref(), Some("bad-element: vlan-id"), "{name}");
            }
            other => panic!("{name}: expected a Device error, got {other:?}"),
        }
    }
}

/// **An empty reply is a reply.** A device with nothing to say answers
/// `<rpc-reply/>`, which quick-xml reports as an Empty event and never as a Start.
/// The root-element check recorded the root only on Start, so the whole document
/// looked as if it held no elements, and an ordinary answer came back as a protocol
/// violation. The check itself must survive the fix: a document rooted at something
/// else is still refused, whether it is self-closing or not.
#[test]
fn a_self_closing_rpc_reply_is_accepted() {
    let xml = "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\"/>";
    assert!(
        netconf::rpc::parse_rpc_reply(xml).is_ok(),
        "an empty reply is a valid reply"
    );
}

#[test]
fn the_root_check_still_refuses_another_document() {
    for xml in [
        "<hello/>",
        "<hello><capabilities/></hello>",
        "<notification/>",
    ] {
        let e =
            netconf::rpc::parse_rpc_reply(xml).expect_err("only an <rpc-reply> may be read as one");
        assert!(e.to_string().contains("not an <rpc-reply>"), "{xml}: {e}");
    }
    let e = netconf::rpc::parse_rpc_reply("").expect_err("nothing is not a reply");
    assert!(e.to_string().contains("no elements"), "{e}");
}

/// **A field name nested inside another field is text, not a new field.** Junos
/// can mark the offending token inside the message itself:
/// `<error-message>bad <bad-element>unit</bad-element> here</error-message>`.
/// `bad-element` is also the name the parser listens for under `error-info`, so on
/// seeing it the parser opened a NEW field, threw away «bad » and never closed the
/// message — which came back as `(no message)`. A field that is already open now
/// keeps collecting until its own closing tag.
#[test]
fn a_known_field_nested_in_another_does_not_empty_it() {
    let xml = "<rpc-reply><rpc-error>\
               <error-tag>operation-failed</error-tag>\
               <error-message>bad <bad-element>unit</bad-element> here</error-message>\
               </rpc-error></rpc-reply>";
    match netconf::rpc::parse_rpc_reply(xml) {
        Err(netconf::NetconfError::Device(d)) => {
            assert_eq!(d.message.as_deref(), Some("bad unit here"));
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
    // The ordinary shape is unchanged: `bad-element` under `error-info` is the info.
    let info = "<rpc-reply><rpc-error><error-message>m</error-message>\
                <error-info><bad-element>vlan-id</bad-element></error-info>\
                </rpc-error></rpc-reply>";
    match netconf::rpc::parse_rpc_reply(info) {
        Err(netconf::NetconfError::Device(d)) => {
            assert_eq!(d.message.as_deref(), Some("m"));
            assert_eq!(d.info.as_deref(), Some("bad-element: vlan-id"));
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// **Every `<rpc-error>` in a reply is reported, not only the first.** The first
/// error is the `Device` error; every other — further errors and warnings, in the
/// device's order — is in its `also`. They used to be dropped.
#[test]
fn every_rpc_error_in_a_reply_is_reported() {
    let xml = "<rpc-reply>\
        <rpc-error><error-severity>warning</error-severity>\
        <error-message>w1</error-message></rpc-error>\
        <rpc-error><error-tag>data-exists</error-tag>\
        <error-message>e1</error-message></rpc-error>\
        <rpc-error><error-tag>invalid-value</error-tag>\
        <error-message>e2</error-message></rpc-error>\
        </rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(d.message.as_deref(), Some("e1"), "the first error leads");
            let also: Vec<_> = d.also.iter().map(|e| e.message.as_deref()).collect();
            assert_eq!(
                also,
                [Some("w1"), Some("e2")],
                "the rest, in the device's order"
            );
            let text = d.to_string();
            assert!(
                text.contains("also warning: ") && text.contains("also error: "),
                "{text}"
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// **An unknown entity anywhere in a reply is refused**, not only inside an
/// `<rpc-error>`'s fields. `&nbsp;` in `<data>` used to pass through, while the
/// contract said an entity other than the five predefined ones is `Protocol`.
#[test]
fn an_unknown_entity_anywhere_in_a_reply_is_refused() {
    let e = netconf::rpc::parse_rpc_reply("<rpc-reply><data>&nbsp;</data></rpc-reply>")
        .expect_err("an unknown entity in data");
    assert!(e.to_string().contains("unknown XML entity &nbsp;"), "{e}");
    netconf::rpc::parse_rpc_reply("<rpc-reply><data>a &amp; b &#10;</data></rpc-reply>")
        .expect("the predefined entities and character references pass");
}

/// **The names quick-xml quotes in a parse error are made printable** before they go
/// into the `Protocol` text, like every other text the device wrote.
#[test]
fn a_parse_error_quoting_the_devices_text_is_made_printable() {
    let e = netconf::rpc::parse_rpc_reply("<rpc-reply><a\u{7}b></c></rpc-reply>")
        .expect_err("a mismatched end tag");
    let text = e.to_string();
    assert!(!text.contains('\u{7}'), "{text:?}");
    assert!(text.contains("\\u{0007}"), "{text}");
}

/// `reply_message_id` reads the whole range this crate writes: a `message-id` above
/// 4294967295 is a number, since the session counts in `u64`.
#[test]
fn reply_message_id_reads_a_u64() {
    assert_eq!(
        netconf::rpc::reply_message_id("<rpc-reply message-id=\"4294967296\"><ok/></rpc-reply>"),
        Some(4_294_967_296)
    );
}

/// **Every part of an `<rpc-error>` reaches the caller** (0.5.13). A child that is
/// not one of the known fields — Junos's `<source-daemon>` — is kept by its name,
/// text outside every element as `#text`, and `<error-info>` keeps the names of the
/// elements in it: `session-id: 7` says what `7` is. All three used to be dropped.
#[test]
fn every_part_of_an_rpc_error_reaches_the_caller() {
    let xml = "<rpc-reply><rpc-error>\
               <error-severity>error</error-severity>\
               <source-daemon>dcd</source-daemon>\
               a word from the device\
               <error-tag>lock-denied</error-tag>\
               <error-info><session-id>7</session-id><detail><bad-element>unit</bad-element>\
               </detail></error-info>\
               <no-text/>\
               </rpc-error></rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(
                d.other,
                vec![
                    ("source-daemon".to_string(), "dcd".to_string()),
                    ("#text".to_string(), "a word from the device".to_string()),
                    ("no-text".to_string(), String::new()),
                ]
            );
            assert_eq!(
                d.info.as_deref(),
                Some("session-id: 7 · detail/bad-element: unit")
            );
            let text = d.to_string();
            assert!(text.contains("[source-daemon: dcd]"), "{text}");
            assert!(text.contains("[#text: a word from the device]"), "{text}");
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// **What the reply held besides its errors goes with the error** (0.5.13), when it
/// is more than `<ok/>`: the reply with every `<rpc-error>` cut out. A reply that
/// says nothing but `<ok/>` around its errors has nothing more to carry.
#[test]
fn the_rest_of_a_reply_goes_with_its_error() {
    let xml = "<rpc-reply><commit-results>\
               <rpc-error><error-message>commit failed</error-message></rpc-error>\
               <routing-engine><name>re0</name></routing-engine>\
               <rpc-error><error-severity>warning</error-severity></rpc-error>\
               </commit-results></rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(
                d.rest.as_deref(),
                Some(
                    "<rpc-reply><commit-results>\
                     <routing-engine><name>re0</name></routing-engine>\
                     </commit-results></rpc-reply>"
                )
            );
            assert!(d.also.iter().all(|a| a.rest.is_none()));
            let text = d.to_string();
            assert!(
                text.ends_with("; the reply besides its errors: <rpc-reply><commit-results><routing-engine><name>re0</name></routing-engine></commit-results></rpc-reply>"),
                "{text}"
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }

    for only_ok in [
        "<rpc-reply><rpc-error><error-tag>x</error-tag></rpc-error></rpc-reply>",
        "<rpc-reply><load-configuration-results><rpc-error/><ok/>\
         </load-configuration-results></rpc-reply>",
    ] {
        match parse_rpc_reply(only_ok) {
            Err(NetconfError::Device(d)) => assert_eq!(d.rest, None, "{only_ok}"),
            other => panic!("expected a Device error, got {other:?}"),
        }
    }
}

/// **`parse_rpc_reply` gives the warnings back** (0.5.13). It parsed them and
/// returned `()`, so a caller using it directly lost them.
#[test]
fn parse_rpc_reply_gives_the_warnings_back() {
    let xml = "<rpc-reply><rpc-error><error-severity>warning</error-severity>\
               <error-message>statement has no effect</error-message></rpc-error>\
               <ok/></rpc-reply>";
    let warnings = parse_rpc_reply(xml).expect("warnings alone are a success");
    assert_eq!(warnings.len(), 1);
    assert_eq!(
        warnings[0].message.as_deref(),
        Some("statement has no effect")
    );
    assert!(parse_rpc_reply("<rpc-reply><ok/></rpc-reply>")
        .expect("ok")
        .is_empty());
}

/// **Every protocol error on what the device sent carries it** (0.5.13): an unknown
/// entity, a parse error in a hello, a compare reply or an `<rpc-error>`'s text,
/// and a chunk header the de-framer refuses. The document, or the buffer as it
/// stood, was in hand and was left behind.
#[test]
fn every_protocol_error_on_what_the_device_sent_carries_it() {
    fn received(r: Result<impl std::fmt::Debug, NetconfError>) -> (String, Option<String>) {
        match r {
            Err(NetconfError::Protocol { detail, received }) => (detail, received),
            other => panic!("expected a Protocol error, got {other:?}"),
        }
    }

    let reply = "<rpc-reply><data>&nbsp;</data></rpc-reply>";
    let (detail, r) = received(parse_rpc_reply(reply));
    assert!(detail.contains("&nbsp;"), "{detail}");
    assert_eq!(r.as_deref(), Some(reply));

    let hello = "<hello><capabilities><capability>urn:x</capability></capabilities></nope>";
    let (_, r) = received(netconf::rpc::parse_hello_capabilities(hello));
    assert_eq!(r.as_deref(), Some(hello));

    let compare = "<rpc-reply><configuration-output>&bogus;</configuration-output></rpc-reply>";
    let (_, r) = received(netconf::rpc::extract_compare_diff(compare));
    assert_eq!(r.as_deref(), Some(compare));

    let mut d = netconf::Decoder::new(netconf::Framing::Chunked);
    d.push(b"\n#0\nabc");
    let (detail, r) = received(d.next_message());
    assert!(detail.contains("chunk-size 0"), "{detail}");
    assert_eq!(r.as_deref(), Some("\n#0\nabc"));
}

/// **Nothing in an `<rpc-error>` is overwritten, and an empty field is there**
/// (0.5.13). A field the device sends twice keeps the first in its place and the
/// second, by its name, in `other`; each later one used to overwrite the one
/// before. An empty `<error-message/>` is present and empty, not absent.
#[test]
fn a_repeated_field_is_kept_and_an_empty_one_is_present() {
    let xml = "<rpc-reply><rpc-error>\
               <error-message>first</error-message>\
               <error-tag>operation-failed</error-tag>\
               <error-message>second</error-message>\
               <error-path/>\
               <error-message/>\
               </rpc-error></rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(d.message.as_deref(), Some("first"));
            assert_eq!(d.path.as_deref(), Some(""), "present and empty");
            assert_eq!(
                d.other,
                vec![
                    ("error-message".to_string(), "second".to_string()),
                    ("error-message".to_string(), String::new()),
                ]
            );
            assert!(d.to_string().contains("[error-message: second]"), "{d}");
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// **A comment the device writes is not dropped** (0.5.13): inside an
/// `<rpc-error>` it is in `other` as `#comment`, and outside one it makes the rest
/// of the reply worth carrying.
#[test]
fn a_comment_from_the_device_is_kept() {
    let xml = "<rpc-reply><rpc-error><error-tag>x</error-tag>\
               <!-- checked by mgd --></rpc-error>\
               <!-- user ops, class j-operator --></rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(
                d.other,
                vec![("#comment".to_string(), "checked by mgd".to_string())]
            );
            let rest = d.rest.unwrap_or_default();
            assert!(
                rest.contains("<!-- user ops, class j-operator -->"),
                "{rest}"
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// **A processing instruction inside an `<rpc-error>` is kept** (0.5.13), in
/// `other` as `#pi`, target and content.
#[test]
fn a_processing_instruction_in_an_rpc_error_is_kept() {
    let xml = "<rpc-reply><rpc-error><error-tag>x</error-tag>\
               <?junos-trace mgd 42?></rpc-error></rpc-reply>";
    match parse_rpc_reply(xml) {
        Err(NetconfError::Device(d)) => {
            assert_eq!(
                d.other,
                vec![("#pi".to_string(), "junos-trace mgd 42".to_string())]
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}
