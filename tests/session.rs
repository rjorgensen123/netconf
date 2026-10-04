// SPDX-License-Identifier: MIT OR Apache-2.0
//! Session tests over the mock transport: hello exchange, framing selection
//! and RPC — all without a network.

use netconf::framing::{encode, Framing};
use netconf::mock::MockTransport;
use netconf::rpc;
use netconf::NetconfSession;

fn hello(offer_1_1: bool) -> Vec<u8> {
    let extra = if offer_1_1 {
        format!("<capability>{}</capability>", rpc::BASE_1_1)
    } else {
        String::new()
    };
    let xml = format!(
        "<hello xmlns=\"{0}\"><capabilities>\
         <capability>{0}</capability>{extra}\
         </capabilities></hello>",
        rpc::BASE_1_0
    );
    encode(Framing::Eom, xml.as_bytes())
}

#[tokio::test]
async fn eom_only_peer_stays_eom() {
    let t = MockTransport::new(vec![hello(false)]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    // The peer did not announce 1.1, so the session must use EOM.
    assert_eq!(s.framing(), Framing::Eom);
    assert!(s.capabilities().iter().any(|c| c == rpc::BASE_1_0));
}

#[tokio::test]
async fn both_1_1_negotiates_chunked() {
    let t = MockTransport::new(vec![hello(true)]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    assert_eq!(s.framing(), Framing::Chunked);
    assert!(s.capabilities().iter().any(|c| c == rpc::BASE_1_1));
}

#[tokio::test]
async fn client_not_offering_1_1_stays_eom() {
    // The peer offers 1.1 but the client does not, so EOM it is.
    let t = MockTransport::new(vec![hello(true)]);
    let s = NetconfSession::establish(t, false).await.unwrap();
    assert_eq!(s.framing(), Framing::Eom);
}

#[tokio::test]
async fn rpc_roundtrip_over_chunked() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\"><data><foo>bar</foo></data></rpc-reply>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![
        hello(true),
        encode(Framing::Chunked, reply.as_bytes()),
    ]);
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    assert_eq!(s.framing(), Framing::Chunked);
    let out = s.rpc("<get-configuration/>").await.unwrap();
    assert!(out.contains("<foo>bar</foo>"));
}

#[tokio::test]
async fn rpc_error_maps_to_device_error() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\"><rpc-error>\
         <error-type>application</error-type>\
         <error-tag>operation-failed</error-tag>\
         <error-severity>error</error-severity>\
         <error-message>configuration check-out failed</error-message>\
         </rpc-error></rpc-reply>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    let err = s.rpc("<commit/>").await.unwrap_err();
    match err {
        netconf::NetconfError::Device(d) => {
            assert_eq!(d.tag.as_deref(), Some("operation-failed"));
            assert!(d.message.as_deref().unwrap().contains("check-out failed"));
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

#[tokio::test]
async fn recv_closed_before_hello_is_transport_error() {
    // Empty queue means recv yields empty Bytes: a transport error, not a
    // panic and not a hang.
    let t = MockTransport::new(vec![]);
    match NetconfSession::establish(t, true).await {
        Err(netconf::NetconfError::Transport(_)) => {}
        Err(other) => panic!("expected a Transport error, got {other:?}"),
        Ok(_) => panic!("expected an error, but establishing succeeded"),
    }
}

/// Bytes after the hello are not carried into chunked framing and misread there.
///
/// The hello is always end-of-message framed, and the session switches to chunked
/// only once both sides have announced 1.1. Anything the device sent after its
/// hello, in the same read, was framed for the mode being left; it used to be kept
/// in the buffer and parsed as chunked.
#[tokio::test]
async fn data_after_the_hello_stops_a_switch_to_chunked() {
    let mut chunk = hello(true);
    chunk.extend_from_slice(b"<unexpected/>]]>]]>");
    let t = MockTransport::new(vec![chunk]);
    // The data goes with the error (0.5.13).
    match NetconfSession::establish(t, true).await {
        Err(netconf::NetconfError::Protocol { detail, received }) => {
            assert!(detail.contains("after the hello"), "{detail}");
            assert_eq!(received.as_deref(), Some("<unexpected/>]]>]]>"));
        }
        Err(other) => panic!("expected a Protocol error, got {other:?}"),
        Ok(_) => panic!("establishing should have been refused"),
    }
}

/// Whitespace after the hello is not data. A device may send a line ending there,
/// and the chunked reader already skips it; refusing it would refuse real devices.
#[tokio::test]
async fn whitespace_after_the_hello_is_tolerated() {
    let mut chunk = hello(true);
    chunk.extend_from_slice(b"\r\n");
    let s = NetconfSession::establish(MockTransport::new(vec![chunk]), true)
        .await
        .expect("whitespace after the hello must be tolerated");
    assert_eq!(s.framing(), Framing::Chunked);
}

/// **A reply must answer the request that was sent.**
///
/// `message-id` was written into every request and then never looked at, so
/// whatever arrived on the channel was taken as the answer — a late reply to an
/// earlier RPC, or something the device volunteered. In a compare-then-commit
/// sequence that means approving one diff and committing against another.
#[tokio::test]
async fn a_reply_for_a_different_request_is_refused() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"99\"><data/></rpc-reply>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    // The reply goes with the error, not only its id (0.5.13).
    match s.rpc("<get-configuration/>").await {
        Err(netconf::NetconfError::Protocol { detail, received }) => {
            assert!(
                detail.contains("99"),
                "the message must name what arrived: {detail}"
            );
            assert!(detail.contains("does not match"), "{detail}");
            assert_eq!(received.as_deref(), Some(reply.as_str()));
        }
        other => panic!("expected a Protocol error, got {other:?}"),
    }
}

/// The matching case goes through, and so does a reply with no `message-id` at
/// all — Junos omits it on some replies, and refusing those would break ordinary
/// use for no gain.
#[tokio::test]
async fn a_matching_or_absent_message_id_is_accepted() {
    for tail in ["message-id=\"1\"", ""] {
        let reply = format!(
            "<rpc-reply xmlns=\"{}\" {tail}><data><ok/></data></rpc-reply>",
            rpc::BASE_1_0
        );
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        s.rpc("<get-configuration/>")
            .await
            .unwrap_or_else(|e| panic!("«{tail}» should be accepted: {e:?}"));
    }
}

/// A `message-id` that is present but not the request's is refused, not read as
/// absent — whatever it holds.
///
/// Only an absent `message-id` is the tolerated Junos quirk. A malformed one used
/// to collapse into «absent» and pass, without the check that ties the reply to
/// this request. Then it was read as a number, which took `01`, `+1` and `" 1 "`
/// for the request's 1. The text is now compared byte for byte with the one that
/// was sent: the device echoes the attribute as sent (RFC 6241 §4.1), and nothing
/// written another way is the request's.
#[tokio::test]
async fn a_message_id_that_is_not_the_requests_byte_for_byte_is_refused() {
    for id in ["", "abc", "-1", "1x", "01", "+1", " 1 ", "1\t"] {
        let reply = format!(
            "<rpc-reply xmlns=\"{}\" message-id=\"{id}\"><data><ok/></data></rpc-reply>",
            rpc::BASE_1_0
        );
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        match s.rpc("<get-configuration/>").await {
            Err(netconf::NetconfError::Protocol { detail, .. }) => {
                assert!(detail.contains("does not match"), "«{id}»: {detail}");
                assert!(
                    !detail.contains('\t'),
                    "the device's text is made printable in the error: {detail:?}"
                );
            }
            other => panic!("«{id}»: expected a Protocol error, got {other:?}"),
        }
    }
}

/// **A session id is read as RFC 6241 writes an `unsignedInt`.** `007`, `+7` and a
/// signed or non-decimal form used to be read as a number; now the device has sent
/// no usable id, which is tolerated as before.
#[tokio::test]
async fn a_session_id_written_another_way_is_not_a_number() {
    for id in ["007", "+7", "-7", "7a", "4294967296"] {
        let xml = format!(
            "<hello xmlns=\"{0}\"><session-id>{id}</session-id>\
             <capabilities><capability>{0}</capability></capabilities></hello>",
            rpc::BASE_1_0
        );
        let t = MockTransport::new(vec![encode(Framing::Eom, xml.as_bytes())]);
        let s = NetconfSession::establish(t, true).await.unwrap();
        assert_eq!(s.session_id(), None, "«{id}»");
    }
}

/// **The device's session id is available to the caller.**
///
/// RFC 6241 §8.1 makes `<session-id>` mandatory in the server's hello, and it is
/// how a client names its own session — to kill it later, or to put it in a log
/// line beside the device's own. It used to be parsed past and dropped.
#[tokio::test]
async fn the_session_id_from_hello_is_kept() {
    let xml = format!(
        "<hello xmlns=\"{0}\"><session-id>4321</session-id>\
         <capabilities><capability>{0}</capability></capabilities></hello>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![encode(Framing::Eom, xml.as_bytes())]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    assert_eq!(s.session_id(), Some(4321));
}

/// A device that sends no session id is not refused over it.
#[tokio::test]
async fn a_hello_without_a_session_id_is_still_accepted() {
    let t = MockTransport::new(vec![hello(false)]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    assert_eq!(s.session_id(), None);
}

/// **`close()` waits for the reply before tearing the transport down.**
///
/// It used to send `<close-session/>` and close immediately, which is an abrupt
/// disconnect from the device's point of view and loses whatever it had to say.
#[tokio::test]
async fn close_reads_the_reply_before_disconnecting() {
    let reply = format!("<rpc-reply xmlns=\"{}\"><ok/></rpc-reply>", rpc::BASE_1_0);
    let (t, log) =
        MockTransport::recording(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    s.close().await.unwrap();
    let sent = String::from_utf8_lossy(&log.lock().unwrap()).into_owned();
    assert!(sent.contains("<close-session/>"), "{sent}");
}

/// And a device that closes without replying is not an error: it has ended the
/// session either way.
#[tokio::test]
async fn close_succeeds_even_if_the_device_says_nothing() {
    let t = MockTransport::new(vec![hello(false)]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    s.close()
        .await
        .expect("a silent device still ends the session");
}

/// **Warnings come back.** A reply whose only `<rpc-error>`s are warnings is a
/// success, and the warnings are kept for `take_warnings` — in order, and handed
/// over once. They used to be dropped.
#[tokio::test]
async fn warnings_on_a_successful_reply_are_kept_for_the_caller() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\"><rpc-error>\
         <error-severity>warning</error-severity><error-message>no effect</error-message>\
         </rpc-error><ok/></rpc-reply>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    s.rpc("<commit-configuration/>")
        .await
        .expect("warnings alone are a success");
    let warnings = s.take_warnings();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].message.as_deref(), Some("no effect"));
    assert!(s.take_warnings().is_empty(), "handed over once");
}

/// An unknown entity in the hello is refused wherever it stands, not only inside a
/// `<capability>`.
#[tokio::test]
async fn a_hello_with_an_unknown_entity_outside_a_capability_is_refused() {
    let xml = format!(
        "<hello xmlns=\"{0}\"><session-id>1</session-id>&nbsp;\
         <capabilities><capability>{0}</capability></capabilities></hello>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![encode(Framing::Eom, xml.as_bytes())]);
    match NetconfSession::establish(t, true).await {
        Err(netconf::NetconfError::Protocol { detail, .. }) => {
            assert!(detail.contains("&nbsp;"), "{detail}")
        }
        Err(other) => panic!("expected a Protocol error, got {other:?}"),
        Ok(_) => panic!("expected a Protocol error, got a session"),
    }
}

/// A transport that hands out its pieces and then fails with `end`, standing in for
/// a device that stops part-way through a message.
struct StopsWith {
    inbound: std::collections::VecDeque<Vec<u8>>,
    end: fn() -> netconf::NetconfError,
}

#[async_trait::async_trait]
impl netconf::NetconfTransport for StopsWith {
    async fn connect(_: &netconf::ConnectOptions) -> Result<Self, netconf::NetconfError> {
        unreachable!("built directly and handed to establish")
    }
    async fn send(&mut self, _: &[u8]) -> Result<(), netconf::NetconfError> {
        Ok(())
    }
    async fn recv(&mut self) -> Result<bytes::Bytes, netconf::NetconfError> {
        match self.inbound.pop_front() {
            Some(piece) => Ok(piece.into()),
            None => Err((self.end)()),
        }
    }
    async fn close(self) -> Result<netconf::error::SshMessages, netconf::NetconfError> {
        Ok(Default::default())
    }
}

/// **A message cut off by a timeout, or by the device closing, goes with the
/// error** (0.5.13), redacted as a reply is. The error used to be the bare
/// `Timeout("rpc-recv")`, or `peer closed before a complete message`, with what had
/// arrived left behind in the de-framer.
#[tokio::test]
async fn an_incomplete_message_goes_with_a_timeout_and_a_close() {
    use netconf::{NetconfError, TransportError};
    let partial = "<rpc-reply message-id=\"1\"><configuration><system><root-authentication>\
                   <encrypted-password>$6$leak</encrypted-password>";
    let pieces = || vec![hello(false), partial.as_bytes().to_vec()];

    let t = StopsWith {
        inbound: pieces().into(),
        end: || NetconfError::Timeout {
            op: "rpc-recv",
            partial: String::new(),
        },
    };
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    match s.rpc("<get-configuration/>").await {
        Err(NetconfError::Timeout { op, partial: held }) => {
            assert_eq!(op, "rpc-recv");
            assert!(held.contains("<system><root-authentication>"), "{held}");
            assert!(!held.contains("$6$leak"), "a secret leaked: {held}");
        }
        other => panic!("expected a Timeout, got {other:?}"),
    }

    // The mock's empty read is the device closing.
    let t = MockTransport::new(pieces());
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    match s.rpc("<get-configuration/>").await {
        Err(NetconfError::Transport(TransportError::Closed {
            detail,
            partial: held,
            ..
        })) => {
            assert!(
                detail.contains("peer closed before a complete message"),
                "{detail}"
            );
            assert!(held.contains("<system><root-authentication>"), "{held}");
            assert!(!held.contains("$6$leak"), "a secret leaked: {held}");
        }
        other => panic!("expected Closed, got {other:?}"),
    }
}

/// **A hello the session cannot use goes with the error** (0.5.13): one with no
/// capabilities, and one that is not UTF-8, every byte written out.
#[tokio::test]
async fn a_hello_that_cannot_be_used_goes_with_the_error() {
    let no_caps = "<hello><session-id>4</session-id></hello>";
    let t = MockTransport::new(vec![encode(Framing::Eom, no_caps.as_bytes())]);
    match NetconfSession::establish(t, true).await {
        Err(netconf::NetconfError::Protocol { detail, received }) => {
            assert!(detail.contains("without capabilities"), "{detail}");
            assert_eq!(received.as_deref(), Some(no_caps));
        }
        Err(other) => panic!("expected a Protocol error, got {other:?}"),
        Ok(_) => panic!("expected a Protocol error, got a session"),
    }

    let t = MockTransport::new(vec![encode(Framing::Eom, b"<hello>\xff</hello>")]);
    match NetconfSession::establish(t, true).await {
        Err(netconf::NetconfError::Protocol { detail, received }) => {
            assert!(detail.contains("not valid UTF-8"), "{detail}");
            assert_eq!(received.as_deref(), Some("<hello>\\xFF</hello>"));
        }
        Err(other) => panic!("expected a Protocol error, got {other:?}"),
        Ok(_) => panic!("expected a Protocol error, got a session"),
    }
}

/// **A reply the session cannot read goes with the error** (0.5.13) — here one
/// that is not UTF-8 — and through the session's filter: redacted unless the policy
/// lets secrets through, as the reply itself would have been.
#[tokio::test]
async fn a_reply_that_cannot_be_read_goes_with_the_error_through_the_filter() {
    let reply = b"<rpc-reply message-id=\"1\"><encrypted-password>$6$leak</encrypted-password>\xff\
                  </rpc-reply>";
    for (policy, shows_secret) in [
        (None, false),
        (
            Some(netconf::ConfigPolicy::with_default_floor().allow_secrets()),
            true,
        ),
    ] {
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply)]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        if let Some(p) = policy {
            s.set_policy(p);
        }
        match s.rpc("<get-configuration/>").await {
            Err(netconf::NetconfError::Protocol { detail, received }) => {
                assert!(detail.contains("not valid UTF-8"), "{detail}");
                let r = received.unwrap_or_default();
                assert!(r.contains("\\xFF"), "{r}");
                assert_eq!(r.contains("$6$leak"), shows_secret, "{r}");
            }
            other => panic!("expected a Protocol error, got {other:?}"),
        }
    }
}

/// **What 0.5.13 added to an `<rpc-error>` goes through the session's filter**, as
/// a reply does: the rest of the reply and the children that are not known fields
/// come with the device's secrets redacted unless the policy lets them through.
#[tokio::test]
async fn the_rest_of_an_rpc_error_reply_goes_through_the_filter() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\"><load-configuration-results>\
         <rpc-error><error-message>bad</error-message>\
         <statement>authentication-key \"$9$leak1\"</statement></rpc-error>\
         <echo>set protocols ospf authentication-key \"$9$leak2\"</echo>\
         </load-configuration-results></rpc-reply>",
        rpc::BASE_1_0
    );
    for (policy, shows) in [
        (None, false),
        (
            Some(netconf::ConfigPolicy::with_default_floor().allow_secrets()),
            true,
        ),
    ] {
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        if let Some(p) = policy {
            s.set_policy(p);
        }
        match s.rpc("<load-configuration/>").await {
            Err(netconf::NetconfError::Device(d)) => {
                let rest = d.rest.clone().unwrap_or_default();
                assert!(rest.contains("<echo>"), "{rest}");
                assert_eq!(rest.contains("$9$leak2"), shows, "{rest}");
                let statement = &d.other[0];
                assert_eq!(statement.0, "statement");
                assert_eq!(statement.1.contains("$9$leak1"), shows, "{statement:?}");
            }
            other => panic!("expected a Device error, got {other:?}"),
        }
    }
}

/// **A device that refuses `<close-session/>` is reported** (0.5.13), after the
/// transport is closed. The reply used to be read and dropped. A device that
/// answers `<ok/>`, or simply closes, has ended the session, and `close()` is `Ok`.
#[tokio::test]
async fn a_refused_close_session_is_reported() {
    let refusal = format!(
        "<rpc-reply xmlns=\"{}\"><rpc-error><error-tag>operation-failed</error-tag>\
         <error-message>session is busy</error-message></rpc-error></rpc-reply>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, refusal.as_bytes())]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    match s.close().await {
        Err(netconf::NetconfError::CloseFailed { error, .. }) => match *error {
            netconf::NetconfError::Device(d) => {
                assert_eq!(d.message.as_deref(), Some("session is busy"));
            }
            other => panic!("expected a Device error inside, got {other:?}"),
        },
        other => panic!("expected CloseFailed, got {other:?}"),
    }

    let ok = format!("<rpc-reply xmlns=\"{}\"><ok/></rpc-reply>", rpc::BASE_1_0);
    let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, ok.as_bytes())]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    s.close().await.expect("an ok closes the session");

    let t = MockTransport::new(vec![hello(false)]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    s.close()
        .await
        .expect("a device that just closes has ended the session");
}

/// **The text of an `<rpc-error>`'s other children is filtered as the device wrote
/// it, and made printable after.** Made printable first, a line break became the
/// two characters `\n`, and a secret's name at the start of the next line was no
/// longer a word of its own to the filter: the secret went out in `other` while the
/// same text in `message` was redacted. Over several lines, in a child that is not
/// a known field and in text outside every element, under a policy that redacts.
#[tokio::test]
async fn multi_line_text_in_other_is_filtered_before_it_is_made_printable() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\">\
         <rpc-error><error-message>bad</error-message>\
         <statement>[edit system]\nsecret \"s3cr3t-A\";\n\
         pre-shared-key ascii-text \"psk-B\";</statement></rpc-error>\
         <rpc-error><error-severity>warning</error-severity>\
         loose line\nsecret \"s3cr3t-C\";</rpc-error></rpc-reply>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    s.set_policy(netconf::ConfigPolicy::with_default_floor());
    match s.rpc("<get-configuration/>").await {
        Err(netconf::NetconfError::Device(d)) => {
            let (name, statement) = &d.other[0];
            assert_eq!(name, "statement");
            assert!(statement.starts_with("[edit system]\\n"), "{statement}");
            for secret in ["s3cr3t-A", "psk-B"] {
                assert!(!statement.contains(secret), "{secret} leaked: {statement}");
            }
            let (name, loose) = &d.also[0].other[0];
            assert_eq!(name, "#text");
            assert!(loose.starts_with("loose line\\n"), "{loose}");
            assert!(!loose.contains("s3cr3t-C"), "s3cr3t-C leaked: {loose}");
            let text = d.to_string();
            assert!(
                !text.contains("s3cr3t") && !text.contains("psk-B"),
                "{text}"
            );
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

/// A transport that hands out its pieces, and fails every send after the first
/// `sends` with a closed connection.
struct SendsThenFails {
    inbound: std::collections::VecDeque<Vec<u8>>,
    sends: usize,
}

#[async_trait::async_trait]
impl netconf::NetconfTransport for SendsThenFails {
    async fn connect(_: &netconf::ConnectOptions) -> Result<Self, netconf::NetconfError> {
        unreachable!("built directly and handed to establish")
    }
    async fn send(&mut self, _: &[u8]) -> Result<(), netconf::NetconfError> {
        if self.sends == 0 {
            return Err(netconf::NetconfError::Transport(
                netconf::TransportError::Io("broken pipe".into()),
            ));
        }
        self.sends -= 1;
        Ok(())
    }
    async fn recv(&mut self) -> Result<bytes::Bytes, netconf::NetconfError> {
        Ok(self.inbound.pop_front().unwrap_or_default().into())
    }
    async fn close(self) -> Result<netconf::error::SshMessages, netconf::NetconfError> {
        Ok(Default::default())
    }
}

/// **`close()` reports what goes wrong, and hands over the warnings** (0.5.13).
/// The send, the wait for the reply and the reply itself were ignored, and the
/// warnings the session held were dropped with it. Now the warnings — those not yet
/// taken and those in the reply to `<close-session/>` — come back; a send that
/// fails, a reply that is not one, and a reply left incomplete are errors; and a
/// device that ends the session without a word has still ended it.
#[tokio::test]
async fn close_reports_what_goes_wrong_and_hands_over_the_warnings() {
    let reply = |body: &str| {
        encode(
            Framing::Eom,
            format!("<rpc-reply xmlns=\"{}\">{body}</rpc-reply>", rpc::BASE_1_0).as_bytes(),
        )
    };
    let warning = |m: &str| {
        format!(
            "<rpc-error><error-severity>warning</error-severity>\
             <error-message>{m}</error-message></rpc-error>"
        )
    };

    let t = MockTransport::new(vec![
        hello(false),
        reply(&format!("{}<data/>", warning("from the request"))),
        reply(&format!("{}<ok/>", warning("from the close"))),
    ]);
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    s.rpc("<get-configuration/>").await.unwrap();
    let end = s.close().await.expect("the session is closed");
    let said: Vec<_> = end.warnings.iter().map(|w| w.message.as_deref()).collect();
    assert_eq!(said, [Some("from the request"), Some("from the close")]);

    let t = SendsThenFails {
        inbound: vec![hello(false)].into(),
        sends: 1,
    };
    let s = NetconfSession::establish(t, true).await.unwrap();
    match s.close().await {
        Err(netconf::NetconfError::CloseFailed { error, .. }) => match *error {
            netconf::NetconfError::Transport(netconf::TransportError::Io(m)) => {
                assert_eq!(m, "broken pipe")
            }
            other => panic!("expected the send's error inside, got {other:?}"),
        },
        other => panic!("expected CloseFailed, got {other:?}"),
    }

    let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, b"<hello/>")]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    match s.close().await {
        Err(netconf::NetconfError::CloseFailed { error, .. }) => match *error {
            netconf::NetconfError::Protocol { detail, received } => {
                assert!(detail.contains("not an <rpc-reply>"), "{detail}");
                assert_eq!(received.as_deref(), Some("<hello/>"));
            }
            other => panic!("expected a Protocol error inside, got {other:?}"),
        },
        other => panic!("expected CloseFailed, got {other:?}"),
    }

    let t = MockTransport::new(vec![hello(false), b"<rpc-reply><o".to_vec()]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    match s.close().await {
        Err(netconf::NetconfError::CloseFailed { error, .. }) => match *error {
            netconf::NetconfError::Transport(netconf::TransportError::Closed {
                partial, ..
            }) => assert_eq!(partial, "<rpc-reply><o"),
            other => panic!("expected Closed with the incomplete reply, got {other:?}"),
        },
        other => panic!("expected CloseFailed, got {other:?}"),
    }

    let t = MockTransport::new(vec![hello(false)]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    assert!(s
        .close()
        .await
        .expect("ended without a word")
        .warnings
        .is_empty());
}

/// **When `close()` fails, the warnings the session held still reach the caller**
/// (0.5.13), in `CloseFailed`. They used to be dropped with the session.
#[tokio::test]
async fn a_failed_close_hands_over_the_warnings_all_the_same() {
    let warned = format!(
        "<rpc-reply xmlns=\"{}\"><rpc-error><error-severity>warning</error-severity>\
         <error-message>held</error-message></rpc-error><data/></rpc-reply>",
        rpc::BASE_1_0
    );
    let t = SendsThenFails {
        inbound: vec![hello(false), encode(Framing::Eom, warned.as_bytes())].into(),
        sends: 2,
    };
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    s.rpc("<get-configuration/>").await.unwrap();
    match s.close().await {
        Err(netconf::NetconfError::CloseFailed { error, end }) => {
            assert!(error.to_string().contains("broken pipe"), "{error}");
            assert_eq!(end.warnings.len(), 1);
            assert_eq!(end.warnings[0].message.as_deref(), Some("held"));
        }
        other => panic!("expected CloseFailed, got {other:?}"),
    }
}

/// **The device's hello is there to read, whole** (0.5.13). The session took the
/// capabilities and the session id out of it and dropped the rest: Junos writes
/// the login's user and class in comments there, and a capability in CDATA, or a
/// session id that is not a number, was lost.
#[tokio::test]
async fn the_devices_hello_is_there_to_read_whole() {
    let hello = format!(
        "<!-- No zombies were killed during the creation of this user interface -->\
         <!-- user ops, class j-super-user -->\
         <hello xmlns=\"{0}\"><capabilities><capability>{0}</capability>\
         <capability><![CDATA[http://xml.juniper.net/netconf/junos/1.0]]></capability>\
         </capabilities><session-id>0042</session-id></hello>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![encode(Framing::Eom, hello.as_bytes())]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    assert_eq!(s.hello(), hello);
    assert!(s
        .capabilities()
        .iter()
        .any(|c| c == "http://xml.juniper.net/netconf/junos/1.0"));
    assert_eq!(s.session_id(), None, "not a number as RFC 6241 writes one");
}

/// **A device that ends the session without replying, and says something over SSH
/// as it ends, has not ended it cleanly** (0.5.13): an exit status, an exit signal
/// or a disconnect message is the answer then, and `close()` reports it. With
/// nothing said and nothing incomplete it has ended the session, and `close()` is
/// `Ok`.
#[tokio::test]
async fn a_close_with_something_said_over_ssh_is_not_clean() {
    let t = StopsWith {
        inbound: vec![hello(false)].into(),
        end: || {
            netconf::NetconfError::Transport(netconf::TransportError::Closed {
                detail: "the device closed the netconf subsystem".into(),
                partial: String::new(),
                ssh: Box::new(netconf::error::SshMessages {
                    exit_status: Some(1),
                    ..Default::default()
                }),
            })
        },
    };
    let s = NetconfSession::establish(t, true).await.unwrap();
    match s.close().await {
        Err(netconf::NetconfError::CloseFailed { error, .. }) => match *error {
            netconf::NetconfError::Transport(netconf::TransportError::Closed { ssh, .. }) => {
                assert_eq!(ssh.exit_status, Some(1))
            }
            other => panic!("expected Closed with the exit status inside, got {other:?}"),
        },
        other => panic!("expected CloseFailed, got {other:?}"),
    }
}

/// **The hello goes out through the policy's filter** (0.5.13), as a reply does:
/// redacted without `allow_secrets`, as the device sent it with.
#[tokio::test]
async fn the_hello_goes_out_through_the_filter() {
    let hello = format!(
        "<!-- user ops, authentication-key \"$9$leak\" -->\
         <hello xmlns=\"{0}\"><capabilities><capability>{0}</capability>\
         </capabilities></hello>",
        rpc::BASE_1_0
    );
    for (policy, shows) in [
        (netconf::ConfigPolicy::with_default_floor(), false),
        (
            netconf::ConfigPolicy::with_default_floor().allow_secrets(),
            true,
        ),
    ] {
        let t = MockTransport::new(vec![encode(Framing::Eom, hello.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        s.set_policy(policy);
        let seen = s.hello();
        assert_eq!(seen.contains("$9$leak"), shows, "{seen}");
        if shows {
            assert_eq!(seen, hello);
        } else {
            assert!(seen.contains(netconf::REDACTED), "{seen}");
        }
    }
}

/// **The device's own error text follows the policy** (0.5.13): `path`, `message`
/// and `info` were redacted whatever the policy said, so `allow_secrets` did not
/// let them through. Now the filter decides, as for everything else — redacted as
/// the device wrote them, then made printable.
#[tokio::test]
async fn an_rpc_error_follows_the_policy_both_ways() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\"><rpc-error>\
         <error-path>[edit system]\nsecret \"s3cr3t-P\"</error-path>\
         <error-message>bad value\nencrypted-password \"s3cr3t-M\"</error-message>\
         <error-info><bad-element>secret s3cr3t-I</bad-element></error-info>\
         </rpc-error></rpc-reply>",
        rpc::BASE_1_0
    );
    for (policy, shows) in [
        (netconf::ConfigPolicy::with_default_floor(), false),
        (
            netconf::ConfigPolicy::with_default_floor().allow_secrets(),
            true,
        ),
    ] {
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        s.set_policy(policy);
        match s.rpc("<get-configuration/>").await {
            Err(netconf::NetconfError::Device(d)) => {
                let path = d.path.unwrap_or_default();
                let message = d.message.unwrap_or_default();
                let info = d.info.unwrap_or_default();
                assert_eq!(path.contains("s3cr3t-P"), shows, "{path}");
                assert_eq!(message.contains("s3cr3t-M"), shows, "{message}");
                assert_eq!(info.contains("s3cr3t-I"), shows, "{info}");
                assert!(
                    message.starts_with("bad value\\n"),
                    "made printable: {message}"
                );
            }
            other => panic!("expected a Device error, got {other:?}"),
        }
    }
}

/// A capability is the device's text in the session's answer, and is made printable
/// like the rest of it (0.5.13).
#[tokio::test]
async fn a_capability_is_made_printable() {
    let xml = format!(
        "<hello xmlns=\"{0}\"><capabilities><capability>{0}</capability>\
         <capability>urn:x&#7;y</capability></capabilities></hello>",
        rpc::BASE_1_0
    );
    let t = MockTransport::new(vec![encode(Framing::Eom, xml.as_bytes())]);
    let s = NetconfSession::establish(t, true).await.unwrap();
    assert!(
        s.capabilities().iter().any(|c| c == "urn:x\\u{0007}y"),
        "{:?}",
        s.capabilities()
    );
}

/// A reply under each of the two policies that matter here: one that redacts, and
/// one that lets secrets through.
fn under_both_policies() -> [(netconf::ConfigPolicy, bool); 2] {
    [
        (netconf::ConfigPolicy::with_default_floor(), false),
        (
            netconf::ConfigPolicy::with_default_floor().allow_secrets(),
            true,
        ),
    ]
}

/// **`error-type`, `error-tag`, `error-severity` and `error-app-tag` follow the
/// policy** (0.5.13), filtered as the device wrote them and then made printable, as
/// the other fields of an `<rpc-error>` are. They were made printable and never
/// filtered.
#[tokio::test]
async fn every_field_of_an_rpc_error_follows_the_policy() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\"><rpc-error>\
         <error-type>application\nsecret s3cr3t-T</error-type>\
         <error-tag>operation-failed\nsecret s3cr3t-G</error-tag>\
         <error-severity>error\nsecret s3cr3t-S</error-severity>\
         <error-app-tag>app\nsecret s3cr3t-A</error-app-tag>\
         </rpc-error></rpc-reply>",
        rpc::BASE_1_0
    );
    for (policy, shows) in under_both_policies() {
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        s.set_policy(policy);
        match s.rpc("<get-configuration/>").await {
            Err(netconf::NetconfError::Device(d)) => {
                for (field, secret) in [
                    (&d.error_type, "s3cr3t-T"),
                    (&d.tag, "s3cr3t-G"),
                    (&d.severity, "s3cr3t-S"),
                    (&d.app_tag, "s3cr3t-A"),
                ] {
                    let text = field.clone().unwrap_or_default();
                    assert_eq!(text.contains(secret), shows, "{text}");
                    assert!(text.contains("\\n"), "made printable: {text}");
                }
            }
            other => panic!("expected a Device error, got {other:?}"),
        }
    }
}

/// **The `message-id` a reply carries is filtered in the error's text** (0.5.13), as
/// the reply in `received` is. It was made printable and never filtered.
#[tokio::test]
async fn a_wrong_message_id_is_filtered_in_the_errors_text() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"$9$abcDEF\"><ok/></rpc-reply>",
        rpc::BASE_1_0
    );
    for (policy, shows) in under_both_policies() {
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        s.set_policy(policy);
        match s.rpc("<get-configuration/>").await {
            Err(netconf::NetconfError::Protocol { detail, .. }) => {
                assert!(detail.contains("does not match"), "{detail}");
                assert_eq!(detail.contains("abcDEF"), shows, "{detail}");
            }
            other => panic!("expected a Protocol error, got {other:?}"),
        }
    }
}

/// **What the XML parser quotes from the document is filtered in the error's text**
/// (0.5.13), as the reply in `received` is: an entity's name, an end tag. It was made
/// printable and never filtered. `rpc::parse_rpc_reply`, with no policy, redacts it.
#[tokio::test]
async fn what_the_parser_quotes_is_filtered_in_the_errors_text() {
    let reply = format!(
        "<rpc-reply xmlns=\"{}\" message-id=\"1\"><data>&$9$abcDEF;</data></rpc-reply>",
        rpc::BASE_1_0
    );
    for (policy, shows) in under_both_policies() {
        let t = MockTransport::new(vec![hello(false), encode(Framing::Eom, reply.as_bytes())]);
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        s.set_policy(policy);
        match s.rpc("<get-configuration/>").await {
            Err(netconf::NetconfError::Protocol { detail, .. }) => {
                assert!(detail.contains("unknown XML entity"), "{detail}");
                assert_eq!(detail.contains("abcDEF"), shows, "{detail}");
            }
            other => panic!("expected a Protocol error, got {other:?}"),
        }
    }
    match rpc::parse_rpc_reply("<rpc-reply><a></b $9$abcDEF></rpc-reply>") {
        Err(netconf::NetconfError::Protocol { detail, .. }) => {
            assert!(detail.contains("parse error"), "{detail}");
            assert!(!detail.contains("abcDEF"), "{detail}");
        }
        other => panic!("expected a Protocol error, got {other:?}"),
    }
}

/// A transport whose connect is refused, and whose refusal names a secret.
struct RefusedWithASecret;

#[async_trait::async_trait]
impl netconf::NetconfTransport for RefusedWithASecret {
    async fn connect(_: &netconf::ConnectOptions) -> Result<Self, netconf::NetconfError> {
        Err(netconf::NetconfError::Transport(
            netconf::TransportError::Io("refused: authentication-key hunter2".into()),
        ))
    }
    async fn send(&mut self, _: &[u8]) -> Result<(), netconf::NetconfError> {
        unreachable!("never connected")
    }
    async fn recv(&mut self) -> Result<bytes::Bytes, netconf::NetconfError> {
        unreachable!("never connected")
    }
    async fn close(self) -> Result<netconf::error::SshMessages, netconf::NetconfError> {
        unreachable!("never connected")
    }
}

/// **The text of an `Io` error goes through the filter** (0.5.13), as what the
/// device sent does in every other error: a transport other than russh's hands its
/// text on as it got it. A connect has no policy yet, so it is redacted; after it,
/// the policy decides.
#[tokio::test]
async fn the_text_of_an_io_error_goes_through_the_filter() {
    use netconf::{NetconfError, TransportError};
    let opts = netconf::ConnectOptions {
        host: "192.0.2.1".into(),
        port: 830,
        username: "x".into(),
        auth: netconf::Auth::Password(
            krypto::SecretString::from_string("test-password".into()).unwrap(),
        ),
        ssh_policy: netconf::SshPolicy::Modern,
        timeouts: netconf::Timeouts::default(),
        platform_hint: None,
        host_key: None,
    };
    match NetconfSession::<RefusedWithASecret>::connect(&opts).await {
        Err(NetconfError::Transport(TransportError::Io(text))) => {
            assert!(!text.contains("hunter2"), "a secret leaked: {text}");
            assert!(text.contains("refused: authentication-key"), "{text}");
        }
        Err(other) => panic!("expected an Io error, got {other:?}"),
        Ok(_) => panic!("expected an Io error, got a session"),
    }

    for (policy, shows) in under_both_policies() {
        let t = StopsWith {
            inbound: vec![hello(false)].into(),
            end: || {
                NetconfError::Transport(TransportError::Io(
                    "reset: authentication-key hunter2".into(),
                ))
            },
        };
        let mut s = NetconfSession::establish(t, true).await.unwrap();
        s.set_policy(policy);
        match s.rpc("<get-configuration/>").await {
            Err(NetconfError::Transport(TransportError::Io(text))) => {
                assert_eq!(text.contains("hunter2"), shows, "{text}")
            }
            other => panic!("expected an Io error, got {other:?}"),
        }
    }
}
