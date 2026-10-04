// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the errors SAY, not just which variant they are.
//!
//! The rest of the suite proves the right variant is produced and that the right
//! data is carried in its fields. None of it renders the error. That is a real
//! gap in a crate whose job is to refuse and explain: the text is what an
//! operator acts on, and a `Display` that drops a field is invisible to every
//! test that only inspects the struct.
//!
//! Concretely: `Negotiation` carries what the peer offered, and `HostKey`
//! carries the fingerprint the device actually presented. Both were added
//! because the error without them left the operator with nothing to do next.
//! Remove either from the rendered text and the crate is back where it started,
//! while every other test stays green.

use netconf::error::{
    ConfirmedCheck, DeviceChanged, DeviceError, NetconfError, SshMessages, TransportError,
};

fn text(e: NetconfError) -> String {
    e.to_string()
}

fn protocol(detail: &str) -> NetconfError {
    NetconfError::Protocol {
        detail: detail.into(),
        received: None,
    }
}

fn timeout(op: &'static str) -> NetconfError {
    NetconfError::Timeout {
        op,
        partial: String::new(),
    }
}

fn changed(check: ConfirmedCheck, rollback: Option<u32>, diff: Option<&str>) -> NetconfError {
    NetconfError::ChangedSinceConfirmed(Box::new(DeviceChanged {
        check,
        confirmed: "sequence-number=0 · user=ops".into(),
        now: "sequence-number=0 · user=someone".into(),
        rollback,
        diff: diff.map(String::from),
        diff_error: None,
    }))
}

/// The branch is the contract a consumer switches on; the prefix is how a human
/// reads the same distinction in a log.
#[test]
fn every_branch_names_itself() {
    assert!(text(protocol("bad hello")).starts_with("protocol:"));
    assert!(text(NetconfError::Policy("denied".into())).starts_with("policy:"));
    assert!(text(timeout("commit")).starts_with("timeout:"));
    assert!(text(NetconfError::Transport(TransportError::Io(
        "broken pipe".into()
    )))
    .starts_with("transport:"));
    assert!(text(NetconfError::Device(Box::default())).starts_with("device:"));
    assert!(text(changed(ConfirmedCheck::Candidate, Some(0), Some("x")))
        .starts_with("changed since the confirmed commit:"));
}

/// The payload has to survive the wrapping. A prefix with the detail dropped
/// tells the operator which kind of thing went wrong and nothing else.
#[test]
fn the_detail_survives_the_prefix() {
    assert!(text(protocol("unknown XML entity &foo;")).contains("unknown XML entity &foo;"));
    assert!(text(NetconfError::Policy(
        "floor: delete of a top-level tree".into()
    ))
    .contains("floor: delete of a top-level tree"));
    assert!(text(timeout("compare")).contains("compare"));
}

/// **The whole reason `offered` exists.** Without it the operator is told «we
/// could not agree» and has no way to know whether the device is too old, too
/// new, or configured oddly.
#[test]
fn a_negotiation_failure_lists_what_the_peer_offered() {
    let e = NetconfError::Transport(TransportError::Negotiation {
        offered: vec![
            "diffie-hellman-group1-sha1".into(),
            "diffie-hellman-group14-sha1".into(),
        ],
        detail: "no common key exchange".into(),
    });
    let s = text(e);
    assert!(s.contains("no common key exchange"), "{s}");
    assert!(
        s.contains("diffie-hellman-group1-sha1"),
        "the first offer is missing: {s}"
    );
    assert!(
        s.contains("diffie-hellman-group14-sha1"),
        "the second offer is missing: {s}"
    );
}

/// **The whole reason `observed` exists.** The fingerprint in the text is the one
/// the device presented in the handshake that broke — the operator compares it
/// against what they expected without connecting again.
#[test]
fn a_host_key_failure_shows_the_fingerprint_that_was_presented() {
    let e = NetconfError::Transport(TransportError::HostKey {
        observed: Some("SHA256:abcdef0123456789".into()),
        detail: "not the pinned key".into(),
    });
    let s = text(e);
    assert!(s.contains("not the pinned key"), "{s}");
    assert!(
        s.contains("SHA256:abcdef0123456789"),
        "the fingerprint is missing: {s}"
    );
}

/// And when key exchange never got that far, the text must not imply a
/// fingerprint was seen. Saying nothing is correct; inventing a placeholder that
/// an operator might compare against is not.
#[test]
fn without_an_observation_no_fingerprint_is_implied() {
    let e = NetconfError::Transport(TransportError::HostKey {
        observed: None,
        detail: "connection closed during key exchange".into(),
    });
    let s = text(e);
    assert!(s.contains("connection closed during key exchange"), "{s}");
    assert!(
        !s.contains("SHA256"),
        "no fingerprint was seen, so none may appear: {s}"
    );
    assert!(!s.contains("presented"), "nothing was presented: {s}");
}

/// A device error is the device's own words. All the fields are optional, because
/// the classic Junos reply omits some of them.
#[test]
fn a_device_error_carries_the_devices_own_words() {
    let d = DeviceError {
        tag: Some("operation-failed".into()),
        message: Some("configuration check-out failed".into()),
        path: Some("[edit interfaces ge-0/0/1]".into()),
        ..DeviceError::default()
    };
    let s = d.to_string();
    assert!(s.contains("operation-failed"), "{s}");
    assert!(s.contains("configuration check-out failed"), "{s}");
    assert!(
        s.contains("[edit interfaces ge-0/0/1]"),
        "the path is missing: {s}"
    );
}

/// **Every field the device filled in is in the text** (0.5.13). `info` is where
/// Junos names the statement it objected to, and the text used to leave it out,
/// with `app-tag` and `type`; an error logged as text lost them.
#[test]
fn info_app_tag_and_type_are_in_the_text() {
    let d = DeviceError {
        tag: Some("operation-failed".into()),
        message: Some("check-out failed".into()),
        info: Some("bad-element=vlan-id".into()),
        app_tag: Some("commit-check".into()),
        error_type: Some("application".into()),
        ..DeviceError::default()
    };
    let s = d.to_string();
    assert!(
        s.contains("[info: bad-element=vlan-id]")
            && s.contains("[app-tag: commit-check]")
            && s.contains("[type: application]"),
        "{s}"
    );
}

/// With nothing filled in, the text still has to be readable and must not claim
/// more than it knows.
#[test]
fn an_empty_device_error_says_so_rather_than_lying() {
    let s = DeviceError::default().to_string();
    assert!(
        s.contains("unknown"),
        "an absent tag must read as unknown: {s}"
    );
    assert!(
        s.contains("no message"),
        "an absent message must say so: {s}"
    );
    assert!(
        !s.contains("path"),
        "no path was given, so none may be shown: {s}"
    );
}

/// Drift says what drifted, and shows the fresh diff it drifted to (0.5.13): the
/// operator decides what to do about the change, and the text stands on its own.
#[test]
fn drift_explains_itself_and_shows_the_fresh_diff() {
    let s = text(NetconfError::Drift {
        fresh: "[edit system]\n+  host-name x;".into(),
    });
    assert!(s.starts_with("drift:"), "{s}");
    assert!(s.contains("compare"), "it must name what was compared: {s}");
    assert!(
        s.contains("approved"),
        "it must say what it deviated from: {s}"
    );
    assert!(
        s.contains("the fresh diff: [edit system]\\n+  host-name x;"),
        "the diff, on the error's own line: {s}"
    );
}

/// **What the device sent travels in the text too** (0.5.13), made printable, so an
/// error logged as text says what came. An incomplete message says it is one.
#[test]
fn the_devices_content_is_in_the_text() {
    let s = text(NetconfError::Protocol {
        detail: "reply is not an <rpc-reply> but a <hello>".into(),
        received: Some("<hello>\n</hello>".into()),
    });
    assert!(s.ends_with("; the device sent: <hello>\\n</hello>"), "{s}");

    let s = text(NetconfError::Timeout {
        op: "rpc-recv",
        partial: "<rpc-reply><data>".into(),
    });
    assert!(
        s.ends_with("; the incomplete message so far: <rpc-reply><data>"),
        "{s}"
    );

    let s = text(NetconfError::Transport(TransportError::Closed {
        detail: "peer closed before a complete message".into(),
        partial: "<rpc-re".into(),
        ssh: Box::new(SshMessages::default()),
    }));
    assert!(
        s.contains("peer closed") && s.ends_with("so far: <rpc-re"),
        "{s}"
    );
}

/// The confirming commit that was withheld says why, and shows the diff — or says
/// there was none to fetch.
#[test]
fn changed_since_confirmed_shows_the_diff_or_says_there_is_none() {
    let s = text(changed(
        ConfirmedCheck::LastCommit,
        Some(1),
        Some("[edit]\n+  x;"),
    ));
    assert!(
        s.contains("it was «sequence-number=0 · user=ops»")
            && s.contains("it is «sequence-number=0 · user=someone»")
            && s.contains("withheld"),
        "{s}"
    );
    assert!(
        s.ends_with("the diff against rollback 1: [edit]\\n+  x;"),
        "{s}"
    );

    let s = text(changed(ConfirmedCheck::LastCommit, None, None));
    assert!(
        s.contains("no longer in the device's commit history"),
        "{s}"
    );

    let s = text(changed(ConfirmedCheck::Candidate, Some(0), Some("a\nb")));
    assert!(
        s.contains("2 line(s)") && s.ends_with("rollback 0: a\\nb"),
        "{s}"
    );
}

/// The change-flow reports say what happened, and carry what came back.
#[test]
fn change_flow_reports_say_what_happened_and_carry_what_came_back() {
    let inner = || timeout("rpc-recv");

    let t = text(NetconfError::CommittedThenFailed {
        reply: "<rpc-reply><commit-results/></rpc-reply>".into(),
        error: Box::new(inner()),
    });
    assert!(t.starts_with("committed:") && t.contains("rpc-recv"), "{t}");
    assert!(
        t.ends_with(
            "; the device's answer to the commit: <rpc-reply><commit-results/></rpc-reply>"
        ),
        "{t}"
    );

    let t = text(NetconfError::CommitUnanswered(Box::new(inner())));
    assert!(
        t.starts_with("commit unanswered:") && t.contains("rpc-recv"),
        "{t}"
    );

    let t = text(NetconfError::CleanupFailed {
        error: Box::new(NetconfError::Drift {
            fresh: String::new(),
        }),
        cleanup: vec![("discard-changes", inner()), ("unlock", inner())],
    });
    assert!(t.starts_with("drift:"), "{t}");
    assert!(
        t.contains("discard-changes: timeout: rpc-recv; unlock: timeout: rpc-recv"),
        "{t}"
    );
}

/// A tag the crate translates says what it means next to the device's own words,
/// with RFC 6241 as the reference. A tag it does not translate reads as before.
#[test]
fn a_known_tag_is_translated_with_the_rfc_as_reference() {
    let d = DeviceError {
        tag: Some("lock-denied".into()),
        message: Some("configuration database locked by user ops".into()),
        ..DeviceError::default()
    };
    let s = d.to_string();
    assert!(s.contains("locked by another session"), "{s}");
    assert!(s.contains("RFC 6241"), "{s}");
    assert!(
        s.contains("configuration database locked by user ops"),
        "the device's words stay: {s}"
    );
    assert_eq!(
        d.explanation(),
        Some("the configuration is locked by another session")
    );

    let untranslated = DeviceError {
        tag: Some("operation-failed".into()),
        ..DeviceError::default()
    };
    assert_eq!(untranslated.explanation(), None);
    assert!(!untranslated.to_string().contains("RFC"), "{untranslated}");
}

fn auth_rejected(remaining: &[&str], partial_success: bool) -> String {
    text(NetconfError::Transport(TransportError::AuthRejected {
        username: "ops".into(),
        remaining_methods: remaining.iter().map(|m| m.to_string()).collect(),
        partial_success,
    }))
}

/// The device says what it wants. That is the piece of information which decides
/// whether the operator changes the password or changes the method.
#[test]
fn the_devices_own_methods_appear_in_the_error() {
    let m = auth_rejected(&["publickey", "keyboard-interactive"], false);
    assert!(
        m.contains("publickey") && m.contains("keyboard-interactive"),
        "{m}"
    );
    assert!(m.contains("rejected"), "{m}");
}

/// `partial_success` means the password WAS accepted. Saying «rejected» there is
/// not merely unhelpful — it is wrong, and it sends the operator off to reset a
/// password that worked.
#[test]
fn partial_success_does_not_say_rejected() {
    let m = auth_rejected(&["keyboard-interactive"], true);
    assert!(
        m.contains("ACCEPTED"),
        "the password was accepted, and that must be said: {m}"
    );
    assert!(!m.contains("rejected"), "«rejected» is wrong here: {m}");
    assert!(m.contains("keyboard-interactive"), "{m}");
}

/// If the device names nothing, we say so — rather than letting an empty list look
/// as though we never asked.
#[test]
fn a_silent_device_is_said_to_be_silent() {
    let m = auth_rejected(&[], false);
    assert!(m.contains("named no other method"), "{m}");
}
