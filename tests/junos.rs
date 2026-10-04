// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Junos helpers over the mock transport: that the right RPC is built, that
//! payloads are XML-escaped, and that ok and rpc-error replies are handled.

use netconf::error::ConfirmedCheck;
use netconf::framing::{encode, Framing};
use netconf::mock::{MockTransport, SentLog};
use netconf::rpc::{wrap_rpc, BASE_1_0};
use netconf::{Access, ConfigPolicy, Format, LoadAction, NetconfError, NetconfSession, Scope};

fn eom(xml: &str) -> Vec<u8> {
    encode(Framing::Eom, xml.as_bytes())
}

fn hello() -> Vec<u8> {
    eom(&format!(
        "<hello xmlns=\"{0}\"><capabilities><capability>{0}</capability></capabilities></hello>",
        BASE_1_0
    ))
}

fn text_reply(body: &str) -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><output>{body}</output></rpc-reply>"
    ))
}
fn ok_reply() -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\" message-id=\"1\"><ok/></rpc-reply>"
    ))
}

/// A session with the ordinary policy bound, and one change grant so the commit
/// helpers have something to commit under. Every typed helper passes the policy
/// first (0.5.11); the tests that are about a session WITHOUT one use
/// `session_without_policy`.
async fn session(replies: Vec<Vec<u8>>) -> (NetconfSession<MockTransport>, SentLog) {
    let (mut s, log) = session_without_policy(replies).await;
    s.set_policy(ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rw));
    (s, log)
}

async fn session_without_policy(replies: Vec<Vec<u8>>) -> (NetconfSession<MockTransport>, SentLog) {
    let mut chunks = vec![hello()];
    chunks.extend(replies);
    let (t, log) = MockTransport::recording(chunks);
    let s = NetconfSession::establish(t, true).await.unwrap();
    (s, log)
}

fn sent_str(log: &SentLog) -> String {
    String::from_utf8_lossy(&log.lock().unwrap()).into_owned()
}

#[tokio::test]
async fn lock_sends_lock_candidate() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.lock().await.unwrap();
    let sent = sent_str(&log);
    assert!(sent.contains("<lock>"));
    assert!(sent.contains("<candidate/>"));
}

#[tokio::test]
async fn load_set_format_escapes_payload() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    // Since 0.4.0 a write requires a bound policy.
    s.set_policy(ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rw));
    s.load_configuration(
        "set interfaces ge-0/0/1 unit 1 description \"R&D\"",
        LoadAction::Merge,
        Format::Set,
    )
    .await
    .unwrap();
    let sent = sent_str(&log);
    // The Junos XML protocol requires both attributes for configuration mode
    // commands; `format` defaults to `xml` on the device.
    assert!(sent.contains("<load-configuration action=\"set\" format=\"text\"><configuration-set>"));
    assert!(sent.contains("R&amp;D")); // the & left escaped
}

#[tokio::test]
async fn commit_with_comment_includes_log() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.commit(Some("change ticket 4711")).await.unwrap();
    let sent = sent_str(&log);
    assert!(sent.contains("<commit-configuration>"));
    assert!(sent.contains("<log>change ticket 4711</log>"));
}

/// `commit check` validates the candidate without committing it. The RPC form is
/// what makes that true — send the wrong element and the device happily commits,
/// or validates nothing, and the caller is told neither.
#[tokio::test]
async fn commit_check_validates_without_committing() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.commit_check().await.unwrap();
    let sent = sent_str(&log);
    assert!(sent.contains("<commit-configuration>"));
    assert!(
        sent.contains("<check/>"),
        "commit check must carry <check/>: {sent}"
    );
    // The distinction that matters: a check must not look like a commit.
    assert!(!sent.contains("<confirmed/>"));
    assert!(!sent.contains("<log>"));
}

#[tokio::test]
async fn commit_confirmed_uses_minutes() {
    let (mut s, log) = session(vec![ok_reply(), info_a()]).await;
    s.commit_confirmed(5, None).await.unwrap();
    let sent = sent_str(&log);
    assert!(sent.contains("<confirmed/>"));
    assert!(sent.contains("<confirm-timeout>5</confirm-timeout>"));
}

/// An `<ok/>` reply with no `message-id`, which the session accepts for any
/// request, so one session can send several commits.
fn ok_reply_any() -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><ok/></rpc-reply>"
    ))
}

/// A `<get-commit-information>` reply whose first entry is the given commit.
fn commit_info_reply(seq: &str, user: &str, time: &str, log: &str) -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information>\
         <commit-history><sequence-number>{seq}</sequence-number><user>{user}</user>\
         <client>netconf</client><date-time junos:seconds=\"1\">{time}</date-time>\
         <log>{log}</log></commit-history>\
         <commit-history><sequence-number>1</sequence-number><user>other</user>\
         <client>cli</client><date-time>2026-10-01 08:00:00 UTC</date-time></commit-history>\
         </commit-information></rpc-reply>"
    ))
}

fn info_a() -> Vec<u8> {
    commit_info_reply(
        "0",
        "rjorgensen",
        "2026-10-03 10:00:00 UTC",
        "commit confirmed, rollback in 5mins",
    )
}

/// Off by default: every commit is sent exactly as before the option existed.
#[tokio::test]
async fn commits_carry_no_synchronize_by_default() {
    // Each confirmed commit reads the device's commit information after it.
    let (mut s, log) = session(vec![
        ok_reply_any(),
        ok_reply_any(),
        ok_reply_any(),
        info_a(),
        ok_reply_any(),
        info_a(),
    ])
    .await;
    s.commit(None).await.unwrap();
    s.commit(Some("t")).await.unwrap();
    s.commit_confirmed(5, None).await.unwrap();
    s.commit_confirmed(5, Some("t")).await.unwrap();
    let sent = sent_str(&log);
    for (id, body) in [
        (1, "<commit-configuration/>"),
        (2, "<commit-configuration><log>t</log></commit-configuration>"),
        (
            3,
            "<commit-configuration><confirmed/><confirm-timeout>5</confirm-timeout></commit-configuration>",
        ),
        (
            5,
            "<commit-configuration><confirmed/><confirm-timeout>5</confirm-timeout><log>t</log></commit-configuration>",
        ),
    ] {
        assert!(sent.contains(&wrap_rpc(id, body)), "{body} not in {sent}");
    }
    assert!(!sent.contains("synchronize"), "{sent}");
}

/// On: `<synchronize/>` comes first in the plain commit and in the confirmed one.
#[tokio::test]
async fn commits_carry_synchronize_when_set() {
    let (mut s, log) = session(vec![
        ok_reply_any(),
        ok_reply_any(),
        ok_reply_any(),
        info_a(),
        ok_reply_any(),
        info_a(),
    ])
    .await;
    s.set_synchronize_commits(true);
    s.commit(None).await.unwrap();
    s.commit(Some("t")).await.unwrap();
    s.commit_confirmed(5, None).await.unwrap();
    s.commit_confirmed(5, Some("t")).await.unwrap();
    let sent = sent_str(&log);
    for (id, body) in [
        (1, "<commit-configuration><synchronize/></commit-configuration>"),
        (
            2,
            "<commit-configuration><synchronize/><log>t</log></commit-configuration>",
        ),
        (
            3,
            "<commit-configuration><synchronize/><confirmed/><confirm-timeout>5</confirm-timeout></commit-configuration>",
        ),
        (
            5,
            "<commit-configuration><synchronize/><confirmed/><confirm-timeout>5</confirm-timeout><log>t</log></commit-configuration>",
        ),
    ] {
        assert!(sent.contains(&wrap_rpc(id, body)), "{body} not in {sent}");
    }
}

#[tokio::test]
async fn compare_returns_diff_body() {
    let reply = format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-information>\
         <configuration-output>[edit interfaces]\n+   unit 123</configuration-output>\
         </configuration-information></rpc-reply>"
    );
    let (mut s, _log) = session(vec![eom(&reply)]).await;
    let out = s.compare().await.unwrap();
    // Plain diff text out, not the envelope.
    assert!(out.contains("[edit interfaces]"));
    assert!(out.contains("unit 123"));
    assert!(!out.contains("rpc-reply"));
    assert!(!out.contains("configuration-output"));
}

/// **Absent is not empty.** A compare reply without `<configuration-output>` is the
/// device not saying what the diff is, and that is reported as `Protocol` — not read
/// as «no change». It used to come back `""`, the same as an empty element: a reply
/// holding only `<ok/>`, or only warnings, then passed the drift check and the
/// candidate was committed.
#[test]
fn a_compare_reply_without_configuration_output_is_an_error() {
    use netconf::rpc::extract_compare_diff;
    for reply in [
        "<rpc-reply/>",
        "<rpc-reply><ok/></rpc-reply>",
        "<rpc-reply><rpc-error><error-severity>warning</error-severity>\
         <error-message>statement has no effect</error-message></rpc-error></rpc-reply>",
        "<rpc-reply><configuration-information/></rpc-reply>",
        "<rpc-reply><configuration-information><configuration-text>[edit]\n+ x\
         </configuration-text></configuration-information></rpc-reply>",
    ] {
        match extract_compare_diff(reply) {
            Err(NetconfError::Protocol { detail, received }) => {
                assert!(
                    detail.contains("<configuration-output>"),
                    "{reply}: {detail}"
                );
                // What the device sent instead goes with the error (0.5.13).
                assert_eq!(received.as_deref(), Some(reply));
            }
            other => panic!("{reply}: expected a Protocol error, got {other:?}"),
        }
    }
}

/// An element that is there and empty is the device saying the diff is empty: `""`.
/// A diff is its text.
#[test]
fn an_empty_configuration_output_is_an_empty_diff() {
    use netconf::rpc::extract_compare_diff;
    for reply in [
        "<rpc-reply><configuration-information><configuration-output/>\
         </configuration-information></rpc-reply>",
        "<rpc-reply><configuration-information><configuration-output>\
         </configuration-output></configuration-information></rpc-reply>",
        "<rpc-reply><configuration-information><configuration-output>\n  \n\
         </configuration-output></configuration-information></rpc-reply>",
    ] {
        assert_eq!(extract_compare_diff(reply).unwrap(), "", "{reply}");
    }
    let diff = extract_compare_diff(
        "<rpc-reply><configuration-information><configuration-output>\
         [edit interfaces]\n+   unit 123\n</configuration-output></configuration-information></rpc-reply>",
    )
    .unwrap();
    assert_eq!(diff, "[edit interfaces]\n+   unit 123");
}

#[tokio::test]
async fn command_wraps_operational() {
    let reply = format!("<rpc-reply xmlns=\"{BASE_1_0}\"><output>up</output></rpc-reply>");
    let (mut s, log) = session(vec![eom(&reply)]).await;
    let out = s.command("show l2circuit connections").await.unwrap();
    let sent = sent_str(&log);
    assert!(sent.contains("<command format=\"text\">show l2circuit connections</command>"));
    assert!(out.contains("up"));
}

#[tokio::test]
async fn commit_rpc_error_is_device_error() {
    let reply = format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error>\
         <error-tag>operation-failed</error-tag>\
         <error-message>commit failed</error-message></rpc-error></rpc-reply>"
    );
    let (mut s, _log) = session(vec![eom(&reply)]).await;
    match s.commit(None).await {
        Err(NetconfError::Device(d)) => {
            assert_eq!(d.tag.as_deref(), Some("operation-failed"));
        }
        other => panic!("expected a Device error, got {other:?}"),
    }
}

// ---- The policy is bound to the session and enforced in load ----

#[tokio::test]
async fn load_without_a_policy_is_refused_fail_closed() {
    // No replies queued beyond hello: the refusal happens BEFORE anything is sent.
    let (mut s, log) = session_without_policy(vec![]).await;
    match s
        .load_configuration(
            "set interfaces ge-0/0/1 unit 1 vlan-id 1",
            LoadAction::Merge,
            Format::Set,
        )
        .await
    {
        Err(NetconfError::Policy(reason)) => assert!(reason.contains("no policy bound")),
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("load-configuration"));
}

#[tokio::test]
async fn load_outside_the_scope_is_refused_in_the_library() {
    let (mut s, log) = session(vec![]).await;
    s.set_policy(ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rw));
    match s
        .load_configuration("set system host-name evil", LoadAction::Merge, Format::Set)
        .await
    {
        Err(NetconfError::Policy(_)) => {}
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("load-configuration"));
}

#[tokio::test]
async fn load_xml_is_refused_without_a_deliberate_all_free_rwd() {
    let (mut s, log) = session(vec![]).await;
    // Even all_free(Rw) is not enough: XML cannot be parsed and checked.
    s.set_policy(ConfigPolicy::all_free(Access::Rw));
    match s
        .load_configuration("<configuration/>", LoadAction::Merge, Format::Xml)
        .await
    {
        Err(NetconfError::Policy(reason)) => assert!(reason.contains("all_free(Rwd)")),
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("load-configuration"));
}

#[tokio::test]
async fn load_xml_passes_with_a_deliberate_all_free_rwd() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.set_policy(ConfigPolicy::all_free(Access::Rwd));
    s.load_configuration("<configuration/>", LoadAction::Merge, Format::Xml)
        .await
        .unwrap();
    assert!(sent_str(&log).contains("load-configuration"));
}

#[tokio::test]
async fn load_of_an_unparsable_set_payload_is_refused() {
    let (mut s, log) = session(vec![]).await;
    s.set_policy(ConfigPolicy::all_free(Access::Rwd));
    match s
        .load_configuration("frobnicate everything", LoadAction::Merge, Format::Set)
        .await
    {
        Err(NetconfError::Policy(_)) => {}
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("load-configuration"));
}

// ---- Read gating on sensitive subtrees, and the command filter ----

/// **Without a bound policy nothing is permitted** (0.5.11). `show` and reads used to
/// run under the default rules; now every typed helper refuses, with the same words
/// as `load_configuration`, and nothing is sent. The consumer defines the policy it
/// uses; until it does, netconf does nothing on its behalf.
#[tokio::test]
async fn nothing_is_permitted_without_a_policy() {
    let (mut s, log) = session_without_policy(vec![]).await;
    let refused = |r: Result<String, NetconfError>, what: &str| match r {
        Err(NetconfError::Policy(reason)) => {
            assert!(reason.contains("no policy bound"), "{what}: {reason}")
        }
        other => panic!("{what}: expected a Policy refusal, got {other:?}"),
    };
    refused(s.command("show version").await, "command");
    refused(
        s.get_configuration(Some("<configuration><interfaces/></configuration>"))
            .await,
        "get_configuration",
    );
    refused(s.compare().await, "compare");
    refused(s.lock().await, "lock");
    refused(s.commit(None).await, "commit");
    refused(s.rollback(0).await, "rollback");
    assert!(
        !sent_str(&log).contains("<rpc "),
        "nothing may be sent: {}",
        sent_str(&log)
    );
}

/// **`all_deny` permits nothing, bound explicitly** — the same as no policy, said
/// out loud.
#[tokio::test]
async fn all_deny_refuses_every_helper() {
    let (mut s, log) = session_without_policy(vec![]).await;
    s.set_policy(ConfigPolicy::all_deny().allow_command("show version"));
    for (what, r) in [
        ("command", s.command("show version").await),
        ("get_configuration", s.get_configuration(None).await),
        ("compare", s.compare().await),
    ] {
        match r {
            Err(NetconfError::Policy(reason)) => {
                assert!(reason.contains("all-deny"), "{what}: {reason}")
            }
            other => panic!("{what}: expected a Policy refusal, got {other:?}"),
        }
    }
    assert!(matches!(s.lock().await, Err(NetconfError::Policy(_))));
    assert!(matches!(s.commit(None).await, Err(NetconfError::Policy(_))));
    assert!(!sent_str(&log).contains("<rpc "), "{}", sent_str(&log));
}

/// **A policy that can change nothing commits nothing** (0.5.11): `read_only`,
/// `all_free(Ro)` and rules without a change grant refuse `commit`,
/// `commit_confirmed` and `load_configuration` before anything is sent, while
/// `show` and reads go through. Rollback to a previous configuration loads it
/// whole, which the filter cannot read, so it requires `all_free(Rwd)` like a
/// `Text` load; rollback 0 only discards.
#[tokio::test]
async fn a_policy_that_changes_nothing_commits_nothing() {
    for policy in [
        ConfigPolicy::read_only(),
        ConfigPolicy::all_free(Access::Ro),
        ConfigPolicy::with_default_floor(),
    ] {
        // The second reply answers the second request, so it carries no message-id.
        let (mut s, log) = session_without_policy(vec![text_reply("x"), ok_reply_any()]).await;
        let what = policy.describe();
        s.set_policy(policy);
        s.command("show version")
            .await
            .unwrap_or_else(|e| panic!("{what}: show must pass: {e:?}"));
        for (step, r) in [
            ("commit", s.commit(None).await.map(|_| ())),
            (
                "commit_confirmed",
                s.commit_confirmed(5, None).await.map(|_| ()),
            ),
            ("rollback 1", s.rollback(1).await.map(|_| ())),
            (
                "load",
                s.load_configuration(
                    "set interfaces ge-0/0/1 unit 1 vlan-id 1",
                    LoadAction::Merge,
                    Format::Set,
                )
                .await
                .map(|_| ()),
            ),
        ] {
            match r {
                Err(NetconfError::Policy(reason)) => assert!(
                    reason.contains("no change") || reason.contains("rollback"),
                    "{what}, {step}: {reason}"
                ),
                other => panic!("{what}, {step}: expected a Policy refusal, got {other:?}"),
            }
        }
        s.rollback(0)
            .await
            .unwrap_or_else(|e| panic!("{what}: rollback 0 discards: {e:?}"));
        let sent = sent_str(&log);
        assert!(!sent.contains("<commit-configuration"), "{what}: {sent}");
        assert!(!sent.contains("rollback=\"1\""), "{what}: {sent}");
    }
    // With a change grant the commit goes through, and rollback 1 still needs all_free(Rwd).
    let (mut s, _l) = session(vec![ok_reply()]).await;
    s.commit(None).await.unwrap();
    assert!(matches!(s.rollback(1).await, Err(NetconfError::Policy(_))));
    let (mut s, log) = session_without_policy(vec![ok_reply()]).await;
    s.set_policy(ConfigPolicy::all_free(Access::Rwd));
    s.rollback(1).await.unwrap();
    assert!(sent_str(&log).contains("rollback=\"1\""));
}

#[tokio::test]
async fn request_commands_are_refused_without_a_grant() {
    let (mut s, log) = session(vec![]).await;
    // Under the ordinary policy, with or without change grants: request is outside
    // the rule set.
    match s.command("request system reboot").await {
        Err(NetconfError::Policy(reason)) => assert!(reason.contains("allow_command")),
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    s.set_policy(ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rwd));
    assert!(matches!(
        s.command("clear bgp neighbor").await,
        Err(NetconfError::Policy(_))
    ));
    assert!(!sent_str(&log).contains("request"));
}

#[tokio::test]
async fn request_commands_need_an_explicit_grant_or_all_free_rwd() {
    let (mut s, _l) = session(vec![text_reply("ok"), text_reply("ok")]).await;
    s.set_policy(ConfigPolicy::with_default_floor().allow_command("request system reboot"));
    s.command("request system reboot").await.unwrap();
    // The all/all rule lets it through as well.
    s.set_policy(ConfigPolicy::all_free(Access::Rwd));
    s.command("restart routing").await.unwrap();
}

/// An empty grant grants nothing. A grant with no tokens is a prefix of every
/// command, so `allow_command("")` — what a missing configuration value becomes —
/// used to let `request`, `clear` and the rest through.
#[tokio::test]
async fn an_empty_command_grant_grants_nothing() {
    for blank in ["", "   ", "\t"] {
        let (mut s, log) = session(vec![]).await;
        s.set_policy(ConfigPolicy::with_default_floor().allow_command(blank));
        assert!(
            matches!(
                s.command("request system reboot").await,
                Err(NetconfError::Policy(_))
            ),
            "{blank:?} must not grant anything"
        );
        assert!(!sent_str(&log).contains("request"), "{blank:?}");
        assert!(
            s.policy().unwrap().command_allows().is_empty(),
            "{blank:?} must not be recorded as a grant"
        );
    }
}

/// A command that holds a line break is refused before anything is sent, under the
/// ordinary policy with and without change grants: the line after the break is
/// nothing the gate has read.
#[tokio::test]
async fn a_command_with_a_line_break_is_not_sent() {
    let (mut s, log) = session(vec![]).await;
    for cmd in [
        "show interfaces\rrequest system reboot",
        "show interfaces\nrequest system reboot",
    ] {
        match s.command(cmd).await {
            Err(NetconfError::Policy(reason)) => assert!(reason.contains("control character")),
            other => panic!("{cmd:?}: expected a Policy refusal, got {other:?}"),
        }
    }
    s.set_policy(ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rwd));
    assert!(matches!(
        s.command("show interfaces\rrequest system reboot").await,
        Err(NetconfError::Policy(_))
    ));
    assert!(!sent_str(&log).contains("<command"), "{}", sent_str(&log));
}

/// A set payload with a lone carriage return is refused before anything is sent,
/// under a scoped policy: the device would read a line the filter has not.
#[tokio::test]
async fn a_set_payload_with_a_lone_carriage_return_is_not_sent() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.set_policy(
        ConfigPolicy::with_default_floor()
            .grant(Scope::LogicalUnits, Access::Rwd)
            .grant(Scope::Protocols, Access::Rwd),
    );
    for payload in [
        "#\rdelete protocols",
        "set interfaces ge-0/0/1 unit 1 description x\rdelete system",
    ] {
        match s
            .load_configuration(payload, LoadAction::Merge, Format::Set)
            .await
        {
            Err(NetconfError::Policy(reason)) => {
                assert!(reason.contains("control character"), "{reason}")
            }
            other => panic!("{payload:?}: expected a Policy refusal, got {other:?}"),
        }
    }
    assert!(
        !sent_str(&log).contains("<load-configuration"),
        "{}",
        sent_str(&log)
    );
}

#[tokio::test]
async fn sensitive_show_configuration_is_gated_by_a_read_grant() {
    let (mut s, _l) = session(vec![text_reply("...")]).await;
    // Refused by default, including the Junos abbreviation («conf sys»).
    assert!(matches!(
        s.command("show configuration system").await,
        Err(NetconfError::Policy(_))
    ));
    assert!(matches!(
        s.command("show conf sys").await,
        Err(NetconfError::Policy(_))
    ));
    // With the grant: allowed.
    s.set_policy(ConfigPolicy::with_default_floor().allow_read("system"));
    s.command("show configuration system").await.unwrap();
}

#[tokio::test]
async fn non_sensitive_show_configuration_is_open_by_default() {
    let (mut s, _l) = session(vec![text_reply("...")]).await;
    s.command("show configuration interfaces ge-0/0/1")
        .await
        .unwrap();
}

#[tokio::test]
async fn getting_the_whole_config_needs_every_sensitive_grant() {
    let (mut s, _l) = session(vec![]).await;
    match s.get_configuration(None).await {
        Err(NetconfError::Policy(reason)) => assert!(reason.contains("FULL configuration")),
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    // all_free is deliberate full control, so the read goes through.
    let (mut s2, _l2) = session(vec![text_reply("<configuration/>")]).await;
    s2.set_policy(ConfigPolicy::all_free(Access::Ro));
    s2.get_configuration(None).await.unwrap();
}

#[tokio::test]
async fn get_with_a_filter_gates_only_on_sensitive_subtrees() {
    let (mut s, _l) = session(vec![text_reply("...")]).await;
    // Not sensitive, so open by default.
    s.get_configuration(Some("<configuration><interfaces/></configuration>"))
        .await
        .unwrap();
    // Sensitive: refused without the grant ...
    assert!(matches!(
        s.get_configuration(Some("<configuration><system/></configuration>"))
            .await,
        Err(NetconfError::Policy(_))
    ));
    // ... and allowed with it.
    let (mut s2, _l2) = session(vec![text_reply("...")]).await;
    s2.set_policy(ConfigPolicy::with_default_floor().allow_read("system"));
    s2.get_configuration(Some("<configuration><system/></configuration>"))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Read gating and XML namespaces
// ---------------------------------------------------------------------------

/// A filter element is matched exactly, not as an abbreviation. XML never
/// abbreviates, so the prefix tolerance the CLI needs («sys» for «system») only
/// produced false refusals here: a BGP `<group>` was taken for `groups`.
#[tokio::test]
async fn a_filter_element_is_matched_exactly_not_as_an_abbreviation() {
    let (mut s, _l) = session(vec![text_reply("x")]).await;
    s.set_policy(ConfigPolicy::with_default_floor());
    let filter = "<configuration><protocols><bgp><group/></bgp></protocols></configuration>";
    s.get_configuration(Some(filter))
        .await
        .expect("a BGP group read must not be taken for `groups`");

    // A sensitive tree spelled out is still refused.
    let (mut s, _l) = session(vec![]).await;
    s.set_policy(ConfigPolicy::with_default_floor());
    assert!(matches!(
        s.get_configuration(Some("<configuration><groups/></configuration>"))
            .await,
        Err(NetconfError::Policy(_))
    ));
}

/// **One parser reads the filter, for the gate and for the device.** It must be
/// well-formed XML whose elements all close inside it, with no `]]>]]>`. Markup that
/// closed `<get-configuration>`, or the end-of-message sequence, used to reach the
/// device as more than a filter, past a gate that read it differently. Nothing is
/// sent when the filter is refused.
#[tokio::test]
async fn a_filter_that_is_not_one_closed_xml_tree_is_refused() {
    for filter in [
        "<configuration/></get-configuration>",
        "<configuration><interfaces/>",
        "<configuration><interfaces></configuration>",
        "<configuration/>]]>]]>",
        "<?xml version=\"1.0\"?><configuration/>",
    ] {
        let (mut s, log) = session(vec![]).await;
        s.set_policy(ConfigPolicy::with_default_floor());
        match s.get_configuration(Some(filter)).await {
            Err(NetconfError::Policy(reason)) => {
                assert!(reason.contains("filter"), "{filter}: {reason}");
            }
            other => panic!("{filter}: expected a Policy refusal, got {other:?}"),
        }
        assert!(
            !sent_str(&log).contains("get-configuration"),
            "{filter}: something was sent"
        );
    }
}

/// **No processing instruction, doctype or entity declaration in a filter.** Only
/// elements and text belong in one. A `<?…?>` or a `<!DOCTYPE …>` — with or without
/// an internal subset declaring entities — is refused by the gate's own rule; an
/// `<!ENTITY …>` outside a doctype is not XML at all and is refused as not
/// well-formed. Nothing is sent in any case.
#[tokio::test]
async fn a_filter_with_a_processing_instruction_or_doctype_is_refused() {
    for (filter, why) in [
        ("<?pi data?><configuration/>", "only elements and text"),
        (
            "<configuration><?junos x?><interfaces/></configuration>",
            "only elements and text",
        ),
        (
            "<!DOCTYPE configuration><configuration/>",
            "only elements and text",
        ),
        (
            "<!DOCTYPE x [<!ENTITY a \"b\">]><configuration/>",
            "only elements and text",
        ),
        ("<!ENTITY a \"b\"><configuration/>", "not well-formed"),
        (
            "<configuration><!ENTITY a \"b\"></configuration>",
            "not well-formed",
        ),
    ] {
        let (mut s, log) = session(vec![]).await;
        s.set_policy(ConfigPolicy::with_default_floor());
        match s.get_configuration(Some(filter)).await {
            Err(NetconfError::Policy(reason)) => {
                assert!(reason.contains(why), "{filter}: {reason}");
            }
            other => panic!("{filter}: expected a Policy refusal, got {other:?}"),
        }
        assert!(
            !sent_str(&log).contains("get-configuration"),
            "{filter}: something was sent"
        );
    }
}

/// An end tag that closes nothing the filter opened is refused. quick-xml refuses it
/// itself, before the gate sees an end event, so the gate keeps no check of its own.
#[tokio::test]
async fn an_end_tag_that_closes_nothing_is_refused() {
    for filter in [
        "</configuration>",
        "<configuration/></get-configuration>",
        "<configuration></configuration></configuration>",
    ] {
        let (mut s, log) = session(vec![]).await;
        s.set_policy(ConfigPolicy::with_default_floor());
        match s.get_configuration(Some(filter)).await {
            Err(NetconfError::Policy(reason)) => {
                assert!(reason.contains("not well-formed"), "{filter}: {reason}");
            }
            other => panic!("{filter}: expected a Policy refusal, got {other:?}"),
        }
        assert!(!sent_str(&log).contains("get-configuration"), "{filter}");
    }
}

/// **A namespace prefix must not walk past the read gate.**
///
/// The gate compares the elements a filter names against the sensitive trees. It
/// used to read the token before the colon, so `<junos:system/>` presented itself
/// as `junos` — a name on nobody's list — and the read went through. Any prefix
/// at all was enough.
#[tokio::test]
async fn a_namespace_prefix_does_not_bypass_the_read_gate() {
    for filter in [
        "<configuration><system/></configuration>",
        "<configuration><junos:system/></configuration>",
        "<configuration><nc:system/></configuration>",
        "<configuration><anything:system/></configuration>",
    ] {
        let (mut s, _l) = session(vec![text_reply("x")]).await;
        s.set_policy(ConfigPolicy::with_default_floor()); // no read grants
        let err = s
            .get_configuration(Some(filter))
            .await
            .expect_err("a sensitive tree must be refused however it is spelled");
        match err {
            NetconfError::Policy(reason) => {
                assert!(reason.contains("system"), "{filter}: {reason}");
            }
            other => panic!("{filter}: expected a Policy refusal, got {other:?}"),
        }
    }
}

/// And the prefix must not break the ordinary case either: a non-sensitive tree
/// stays readable whether or not it carries one.
#[tokio::test]
async fn a_namespace_prefix_does_not_gate_a_harmless_tree() {
    for filter in [
        "<configuration><interfaces/></configuration>",
        "<configuration><junos:interfaces/></configuration>",
    ] {
        let (mut s, _l) = session(vec![text_reply("x")]).await;
        s.set_policy(ConfigPolicy::with_default_floor());
        s.get_configuration(Some(filter))
            .await
            .unwrap_or_else(|e| panic!("{filter} should be readable: {e:?}"));
    }
}

/// **`Format::Xml` must send XML, not a string that looks like XML.**
///
/// The payload used to go through the same escaping as the text formats, so
/// `<system/>` left as `&lt;system/&gt;`. Junos needs real child elements inside
/// `<configuration>`; given escaped text it answers with a syntax error. The
/// format was unusable against a device.
#[tokio::test]
async fn xml_payloads_are_not_escaped_into_text() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.set_policy(ConfigPolicy::all_free(Access::Rwd)); // Xml needs the deliberate policy
    s.load_configuration(
        "<system><host-name>edge1</host-name></system>",
        LoadAction::Merge,
        Format::Xml,
    )
    .await
    .unwrap();
    let sent = sent_str(&log);
    assert!(
        sent.contains(
            "<configuration><system><host-name>edge1</host-name></system></configuration>"
        ),
        "the XML must arrive as elements: {sent}"
    );
    assert!(
        !sent.contains("&lt;system"),
        "the payload was escaped into text: {sent}"
    );
}

/// The text formats still escape, because there the payload IS text.
#[tokio::test]
async fn text_payloads_are_still_escaped() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.set_policy(ConfigPolicy::all_free(Access::Rwd));
    s.load_configuration(
        "system { host-name \"a & b\"; }",
        LoadAction::Merge,
        Format::Text,
    )
    .await
    .unwrap();
    assert!(
        sent_str(&log).contains("a &amp; b"),
        "text must be escaped: {}",
        sent_str(&log)
    );
}

/// **The filter is read strictly, and what was read is what is sent.** The parser is
/// lenient in places the gate is not: `<system\x0c/>` named a target `system\x0c`,
/// on nobody's list, while the original text went to the device, which may read it
/// as `system`. What goes to the device is now serialized from what the gate read,
/// and the reading refuses what the parser would have let through: a name that is
/// not an ASCII XML name, an unquoted or repeated attribute, `<` in a value, an
/// unknown entity, a comment, CDATA, a control character. Nothing is sent then.
#[tokio::test]
async fn a_filter_is_read_strictly_and_what_was_read_is_what_is_sent() {
    for (filter, why) in [
        ("<configuration><system\x0c/></configuration>", "not a name"),
        (
            "<configuration><interfaces a=b/></configuration>",
            "attribute",
        ),
        (
            "<configuration><interfaces a=\"1\" a=\"2\"/></configuration>",
            "attribute",
        ),
        (
            "<configuration><interfaces a=\"<\"/></configuration>",
            "`<`",
        ),
        (
            "<configuration><interfaces/>&undefined;</configuration>",
            "entity",
        ),
        (
            "<configuration><!-- c --><interfaces/></configuration>",
            "no comment",
        ),
        ("<configuration><![CDATA[x]]></configuration>", "no CDATA"),
        (
            "<configuration><interfaces>a\u{7}b</interfaces></configuration>",
            "control character",
        ),
        (
            "<configuration><interfaces>a&#12;b</interfaces></configuration>",
            "control character",
        ),
        (
            "<configuration><interfaces>a&#xD;b</interfaces></configuration>",
            "control character",
        ),
        (
            "<configuration><interfaces a=\"x&#12;y\"/></configuration>",
            "control character",
        ),
        (
            "<configuration><interfaces 1a=\"x\"/></configuration>",
            "not a name",
        ),
    ] {
        let (mut s, log) = session(vec![]).await;
        match s.get_configuration(Some(filter)).await {
            Err(NetconfError::Policy(reason)) => {
                assert!(reason.contains(why), "{filter:?}: {reason}");
            }
            other => panic!("{filter:?}: expected a Policy refusal, got {other:?}"),
        }
        assert!(
            !sent_str(&log).contains("get-configuration"),
            "{filter:?}: something was sent"
        );
    }

    // What is read is what is sent: formatting whitespace is gone, entities are
    // resolved and written back, prefixes and attributes are kept.
    let (mut s, log) = session(vec![text_reply("x")]).await;
    s.get_configuration(Some(
        "<configuration>\n  <junos:interfaces xmlns:junos=\"x\" a=\"1&amp;2\">\n    \
         <interface><name>ge-0/0/0 &lt; 1</name></interface>\n  </junos:interfaces>\n</configuration>",
    ))
    .await
    .unwrap();
    assert!(
        sent_str(&log).contains(
            "<get-configuration><configuration><junos:interfaces xmlns:junos=\"x\" a=\"1&amp;2\">\
             <interface><name>ge-0/0/0 &lt; 1</name></interface></junos:interfaces></configuration>\
             </get-configuration>"
        ),
        "{}",
        sent_str(&log)
    );
}

/// **What the device returns is redacted before it leaves the crate** (0.5.11) —
/// `show` output, configuration and the raw `rpc` reply alike — unless the policy
/// lets the device's secrets through: `allow_secrets`, or `all_free`, which redacts
/// nothing. The marker says what was there and how to read it.
#[tokio::test]
async fn what_the_device_returns_is_redacted_unless_the_policy_allows_secrets() {
    let show = "login {\n    user x {\n        authentication {\n            \
                encrypted-password \"$9$secretHASH\"; ## SECRET-DATA\n        }\n    }\n}";
    let xml = "<configuration><system><login><user><name>x</name><authentication>\
               <encrypted-password>$9$secretHASH</encrypted-password></authentication>\
               </user></login></system></configuration>";

    // The ordinary policy, with the sensitive tree granted for reading.
    let (mut s, _l) = session(vec![text_reply(show), text_reply(xml)]).await;
    s.set_policy(ConfigPolicy::with_default_floor().allow_read("system"));
    let out = s.command("show configuration system login").await.unwrap();
    assert!(!out.contains("secretHASH"), "{out}");
    assert!(
        out.contains(netconf::REDACTED) && out.contains("encrypted-password"),
        "{out}"
    );
    let cfg = s
        .get_configuration(Some("<configuration><system/></configuration>"))
        .await
        .unwrap();
    assert!(!cfg.contains("secretHASH"), "{cfg}");
    assert!(
        cfg.contains("<encrypted-password>") && cfg.contains(netconf::REDACTED),
        "{cfg}"
    );

    // allow_secrets, and all_free, let them through.
    for policy in [
        ConfigPolicy::with_default_floor()
            .allow_read("system")
            .allow_secrets(),
        ConfigPolicy::all_free(Access::Ro),
    ] {
        let (mut s, _l) = session(vec![text_reply(show)]).await;
        assert!(policy.secrets_allowed());
        s.set_policy(policy);
        let out = s.command("show configuration system login").await.unwrap();
        assert!(out.contains("secretHASH"), "{out}");
    }

    // The raw rpc layer goes around the gates, not around the redaction — with no
    // policy bound there is nothing that lets a secret out.
    let (mut s, _l) = session_without_policy(vec![text_reply(xml)]).await;
    let raw = s.rpc("<get-configuration/>").await.unwrap();
    assert!(!raw.contains("secretHASH"), "{raw}");
    assert!(raw.contains(netconf::REDACTED), "{raw}");
}

/// **The confirming commit is withheld when the device changed** (0.5.12). After a
/// confirmed commit the session records the device's last commit; the commit that
/// is to confirm it first reads the commit information again and the candidate's
/// diff. Another commit on the device, or changes loaded in the candidate, withhold
/// it: the device then rolls the confirmed commit back by itself. Unchanged, and a
/// clean candidate, it confirms — and a plain commit with nothing pending makes no
/// check at all.
#[tokio::test]
async fn the_confirming_commit_is_withheld_when_the_device_changed() {
    let info_b = || commit_info_reply("0", "someone", "2026-10-03 10:02:00 UTC", "hotfix");
    let empty_diff = || {
        eom(&format!(
            "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-information>\
             <configuration-output/></configuration-information></rpc-reply>"
        ))
    };
    let some_diff = || {
        eom(&format!(
            "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-information>\
             <configuration-output>[edit system]\n+  host-name x;</configuration-output>\
             </configuration-information></rpc-reply>"
        ))
    };

    // Another commit on the device, with ours one place down in the history. What
    // changed goes with the error as data (0.5.13): both entries, and the diff
    // against our commit — fetched as `show | compare rollback 1`, our place —
    // redacted under the policy.
    let foreign_then_ours = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information>\
         <commit-history><sequence-number>0</sequence-number><user>someone</user>\
         <client>cli</client><date-time>2026-10-03 10:02:00 UTC</date-time>\
         <log>hotfix</log></commit-history>\
         <commit-history><sequence-number>1</sequence-number><user>rjorgensen</user>\
         <client>netconf</client><date-time junos:seconds=\"1\">2026-10-03 10:00:00 UTC\
         </date-time><log>commit confirmed, rollback in 5mins</log></commit-history>\
         </commit-information></rpc-reply>"
    ));
    let foreign_diff = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-information><configuration-output>\
         [edit system]\n+  host-name hotfix;\n+  root-authentication encrypted-password \
         \"$6$leak\";</configuration-output></configuration-information></rpc-reply>"
    ));
    let (mut s, log) = session(vec![
        ok_reply_any(),
        info_a(),
        foreign_then_ours,
        foreign_diff,
    ])
    .await;
    s.commit_confirmed(5, Some("job")).await.unwrap();
    match s.commit(Some("job")).await {
        Err(NetconfError::ChangedSinceConfirmed(c)) => {
            assert_eq!(c.check, ConfirmedCheck::LastCommit);
            assert!(c.confirmed.contains("user=rjorgensen"), "{c:?}");
            assert!(
                c.now.contains("user=someone") && c.now.contains("log=hotfix"),
                "{c:?}"
            );
            assert_eq!(c.rollback, Some(1));
            let diff = c.diff.as_deref().expect("the diff against our commit");
            assert!(diff.contains("host-name hotfix;"), "{diff}");
            assert!(!diff.contains("$6$leak"), "a secret leaked: {diff}");
            let text = c.to_string();
            assert!(
                text.contains("withheld") && text.contains("rollback 1"),
                "{text}"
            );
        }
        other => panic!("expected ChangedSinceConfirmed, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(
        sent.contains("<get-configuration compare=\"rollback\" rollback=\"1\" format=\"text\"/>"),
        "{sent}"
    );
    assert_eq!(sent.matches("<commit-configuration").count(), 1, "{sent}");

    // Another commit, and ours is no longer in the history: the error says so, and
    // nothing is fetched or made up.
    let (mut s, log) = session(vec![ok_reply_any(), info_a(), info_b()]).await;
    s.commit_confirmed(5, Some("job")).await.unwrap();
    match s.commit(Some("job")).await {
        Err(NetconfError::ChangedSinceConfirmed(c)) => {
            assert_eq!(c.check, ConfirmedCheck::LastCommit);
            assert!(c.now.contains("user=someone"), "{c:?}");
            assert_eq!((c.rollback, c.diff.as_deref()), (None, None));
            let text = c.to_string();
            assert!(
                text.contains("no longer in the device's commit history"),
                "{text}"
            );
        }
        other => panic!("expected ChangedSinceConfirmed, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(!sent.contains("compare="), "{sent}");
    assert_eq!(sent.matches("<commit-configuration").count(), 1, "{sent}");

    // Changes loaded in the candidate: the diff the check read goes with the error.
    let (mut s, log) = session(vec![ok_reply_any(), info_a(), info_a(), some_diff()]).await;
    s.commit_confirmed(5, Some("job")).await.unwrap();
    match s.commit(Some("job")).await {
        Err(NetconfError::ChangedSinceConfirmed(c)) => {
            assert_eq!(c.check, ConfirmedCheck::Candidate);
            assert_eq!(c.confirmed, c.now);
            assert_eq!(c.rollback, Some(0));
            assert_eq!(c.diff.as_deref(), Some("[edit system]\n+  host-name x;"));
            let text = c.to_string();
            assert!(
                text.contains("candidate") && text.contains("withheld"),
                "{text}"
            );
        }
        other => panic!("expected ChangedSinceConfirmed, got {other:?}"),
    }
    assert_eq!(sent_str(&log).matches("<commit-configuration").count(), 1);

    // Unchanged: the commit confirms, and the record is cleared.
    let (mut s, log) = session(vec![
        ok_reply_any(),
        info_a(),
        info_a(),
        empty_diff(),
        ok_reply_any(),
        ok_reply_any(),
    ])
    .await;
    s.commit_confirmed(5, Some("job")).await.unwrap();
    s.commit(Some("job")).await.expect("unchanged: confirmed");
    s.commit(None)
        .await
        .expect("nothing pending: no check, one request");
    let sent = sent_str(&log);
    assert_eq!(
        sent.matches("<get-commit-information/>").count(),
        2,
        "{sent}"
    );
    assert_eq!(sent.matches("<commit-configuration").count(), 3, "{sent}");
}

/// A confirmed commit whose record cannot be read is `CommittedThenFailed`: the
/// change is live, and the device rolls it back by itself unless it is confirmed.
#[tokio::test]
async fn a_confirmed_commit_whose_record_cannot_be_read_is_committed_then_failed() {
    let no_entry = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information/></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![commit_results("<commit-success/>"), no_entry]).await;
    match s.commit_confirmed(5, None).await {
        Err(NetconfError::CommittedThenFailed { reply, error }) => {
            assert!(error.to_string().contains("commit-history"), "{error}");
            // The device's answer to the commit goes with it (0.5.13).
            assert!(reply.contains("<commit-success/>"), "{reply}");
        }
        other => panic!("expected CommittedThenFailed, got {other:?}"),
    }
}

/// A `<commit-results>` reply as Junos sends one, for the routing engine `re0`,
/// with `outcome` as its result element.
fn commit_results(outcome: &str) -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-results>\
         <routing-engine junos:style=\"normal\"><name>re0</name>{outcome}\
         <message>prior commit used authentication-key \"$9$leak\"</message>\
         </routing-engine></commit-results></rpc-reply>"
    ))
}

/// **The device's answer to a commit reaches the caller** (0.5.13). `commit_check`
/// is the case it matters most for: the reply is what the check found. `commit` and
/// `commit_confirmed` are answered the same way, naming each routing engine. All
/// three returned `()`, and the reply was dropped. It comes as a reply does: the
/// device's secrets redacted under the policy.
#[tokio::test]
async fn the_answer_to_a_commit_reaches_the_caller() {
    let (mut s, _log) = session(vec![
        commit_results("<commit-check-success/>"),
        commit_results("<commit-success/>"),
        commit_results("<commit-success/>"),
        info_a(),
    ])
    .await;

    let checked = s.commit_check().await.unwrap();
    assert!(
        checked.contains("<name>re0</name><commit-check-success/>"),
        "{checked}"
    );
    assert!(!checked.contains("$9$leak"), "a secret leaked: {checked}");

    let committed = s.commit(Some("job")).await.unwrap();
    assert!(committed.contains("<commit-success/>"), "{committed}");

    let confirmed = s.commit_confirmed(5, None).await.unwrap();
    assert!(confirmed.contains("<commit-success/>"), "{confirmed}");
}

/// **The confirmed commit's record can be read** (0.5.13): what the session keeps
/// after `commit_confirmed` — the device's last commit right after it — and checks
/// the confirming commit against. It was kept inside the session.
#[tokio::test]
async fn the_record_of_a_confirmed_commit_can_be_read() {
    let empty_diff = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-information>\
         <configuration-output/></configuration-information></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![
        ok_reply_any(),
        info_a(),
        info_a(),
        empty_diff,
        ok_reply_any(),
    ])
    .await;
    assert_eq!(s.confirmed_commit(), None, "nothing is waiting");
    s.commit_confirmed(5, Some("job")).await.unwrap();
    assert_eq!(
        s.confirmed_commit().as_deref(),
        Some(
            "sequence-number=0 · user=rjorgensen · client=netconf · \
             date-time=2026-10-03 10:00:00 UTC · seconds=1 · \
             log=commit confirmed, rollback in 5mins"
        )
    );
    s.commit(Some("job")).await.unwrap();
    assert_eq!(s.confirmed_commit(), None, "confirmed: nothing is waiting");
}

/// **A commit entry is filtered as the device wrote it, and made printable after.**
/// Made printable first, a control character after a `$9$` value became `\u{0001}`,
/// the filter stopped at its `}`, and the rest of the value went out in
/// `confirmed_commit()` and in `ChangedSinceConfirmed`, while the same text in an
/// `error-message` was redacted whole. Under `allow_secrets` the value is there,
/// printable.
#[tokio::test]
async fn a_commit_entry_is_filtered_before_it_is_made_printable() {
    let ours = || {
        commit_info_reply(
            "0",
            "rjorgensen",
            "2026-10-03 10:00:00 UTC",
            "job $9$abcDEF\u{1}TAILSECRET",
        )
    };
    let theirs = || {
        commit_info_reply(
            "0",
            "someone",
            "2026-10-03 10:02:00 UTC",
            "hotfix $9$ghiJKL\u{1}OTHERTAIL",
        )
    };

    let (mut s, _log) = session(vec![ok_reply_any(), ours(), theirs()]).await;
    s.commit_confirmed(5, Some("job")).await.unwrap();
    let record = s.confirmed_commit().expect("a confirmed commit is waiting");
    assert!(record.contains("log=job $9$"), "{record}");
    for leaked in ["abcDEF", "TAILSECRET"] {
        assert!(!record.contains(leaked), "{leaked} leaked: {record}");
    }
    match s.commit(Some("job")).await {
        Err(NetconfError::ChangedSinceConfirmed(c)) => {
            let text = c.to_string();
            for (what, value) in [
                ("confirmed", &c.confirmed),
                ("now", &c.now),
                ("text", &text),
            ] {
                for leaked in ["abcDEF", "TAILSECRET", "ghiJKL", "OTHERTAIL"] {
                    assert!(
                        !value.contains(leaked),
                        "{leaked} leaked in {what}: {value}"
                    );
                }
            }
        }
        other => panic!("expected ChangedSinceConfirmed, got {other:?}"),
    }

    let (mut s, _log) = session(vec![ok_reply_any(), ours()]).await;
    s.set_policy(
        ConfigPolicy::with_default_floor()
            .grant(Scope::LogicalUnits, Access::Rw)
            .allow_secrets(),
    );
    s.commit_confirmed(5, Some("job")).await.unwrap();
    let record = s.confirmed_commit().expect("a confirmed commit is waiting");
    assert!(
        record.contains("log=job $9$abcDEF\\u{0001}TAILSECRET"),
        "{record}"
    );
}

/// **When the diff cannot be fetched, the answer is still that the device
/// changed** (0.5.13): `ChangedSinceConfirmed` with both entries and the place of
/// the confirmed commit, no diff, and the error the request for it came back with.
/// That error used to be returned in its place, and the caller did not learn that
/// the device had changed.
#[tokio::test]
async fn a_diff_that_cannot_be_fetched_goes_with_the_change_it_was_for() {
    let foreign_then_ours = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information>\
         <commit-history><sequence-number>0</sequence-number><user>someone</user>\
         <client>cli</client><date-time>2026-10-03 10:02:00 UTC</date-time>\
         <log>hotfix</log></commit-history>\
         <commit-history><sequence-number>1</sequence-number><user>rjorgensen</user>\
         <client>netconf</client><date-time junos:seconds=\"1\">2026-10-03 10:00:00 UTC\
         </date-time><log>commit confirmed, rollback in 5mins</log></commit-history>\
         </commit-information></rpc-reply>"
    ));
    let refused = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error><error-tag>operation-failed</error-tag>\
         <error-message>rollback 1 is not available</error-message></rpc-error></rpc-reply>"
    ));
    let (mut s, log) = session(vec![ok_reply_any(), info_a(), foreign_then_ours, refused]).await;
    s.commit_confirmed(5, Some("job")).await.unwrap();
    match s.commit(Some("job")).await {
        Err(NetconfError::ChangedSinceConfirmed(c)) => {
            assert_eq!(c.check, ConfirmedCheck::LastCommit);
            assert!(c.confirmed.contains("user=rjorgensen"), "{c:?}");
            assert!(c.now.contains("user=someone"), "{c:?}");
            assert_eq!(c.rollback, Some(1));
            assert_eq!(c.diff, None);
            match c.diff_error.as_deref() {
                Some(NetconfError::Device(d)) => {
                    assert_eq!(d.message.as_deref(), Some("rollback 1 is not available"))
                }
                other => panic!("expected the fetch's Device error, got {other:?}"),
            }
            let text = c.to_string();
            assert!(
                text.contains("could not be fetched")
                    && text.contains("rollback 1 is not available"),
                "{text}"
            );
        }
        other => panic!("expected ChangedSinceConfirmed, got {other:?}"),
    }
    assert_eq!(sent_str(&log).matches("<commit-configuration").count(), 1);
}

/// **Nothing in a commit entry is skipped** (0.5.13): a value in CDATA, a field
/// that is there and empty, and text outside every field are in the record. And
/// an empty first `<commit-history/>` is an entry — one with nothing in it, which
/// is no record — where it used to be skipped, so the next entry was taken for
/// the device's last commit.
#[tokio::test]
async fn nothing_in_a_commit_entry_is_skipped() {
    let entry = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information><commit-history>\
         <sequence-number>0</sequence-number><user>ops</user><client/>\
         <log><![CDATA[job 42]]></log>loose words</commit-history>\
         </commit-information></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![ok_reply_any(), entry]).await;
    s.commit_confirmed(5, None).await.unwrap();
    assert_eq!(
        s.confirmed_commit().as_deref(),
        Some("sequence-number=0 · user=ops · client= · log=job 42 · #text=loose words")
    );

    let empty_first = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information><commit-history/>\
         <commit-history><sequence-number>1</sequence-number><user>old</user>\
         </commit-history></commit-information></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![ok_reply_any(), empty_first]).await;
    match s.commit_confirmed(5, None).await {
        Err(NetconfError::CommittedThenFailed { error, .. }) => {
            assert!(
                error.to_string().contains("no <commit-history> entry"),
                "{error}"
            )
        }
        other => panic!("expected CommittedThenFailed, got {other:?}"),
    }
}

/// A reply that says more than `<ok/>`, with a secret in it, for the helpers that
/// Junos answers with `<ok/>`: what comes back is the reply, redacted.
fn answer_with_a_secret() -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><ok/><output>prior session set \
         system root-authentication encrypted-password \"$6$leak\"</output></rpc-reply>"
    ))
}

/// The reply a helper returned: the device's answer, with the secret redacted.
fn is_the_answer_redacted(reply: &str) {
    assert!(reply.contains("<ok/><output>prior session set"), "{reply}");
    assert!(!reply.contains("$6$leak"), "a secret leaked: {reply}");
    assert!(reply.contains(netconf::REDACTED), "{reply}");
}

/// **`lock` returns the device's answer** (0.5.13), redacted as a reply is. It
/// returned `()`, and dropped whatever the device answered.
#[tokio::test]
async fn lock_returns_the_devices_answer() {
    let (mut s, _log) = session(vec![answer_with_a_secret()]).await;
    is_the_answer_redacted(&s.lock().await.unwrap());
}

/// **`unlock` returns the device's answer** (0.5.13), redacted as a reply is.
#[tokio::test]
async fn unlock_returns_the_devices_answer() {
    let (mut s, _log) = session(vec![answer_with_a_secret()]).await;
    is_the_answer_redacted(&s.unlock().await.unwrap());
}

/// **`load_configuration` returns the device's answer** (0.5.13), redacted as a
/// reply is.
#[tokio::test]
async fn load_configuration_returns_the_devices_answer() {
    let (mut s, _log) = session(vec![answer_with_a_secret()]).await;
    let reply = s
        .load_configuration(
            "set interfaces ge-0/0/1 unit 1 description x",
            LoadAction::Merge,
            Format::Set,
        )
        .await
        .unwrap();
    is_the_answer_redacted(&reply);
}

/// **`rollback` returns the device's answer** (0.5.13), redacted as a reply is.
#[tokio::test]
async fn rollback_returns_the_devices_answer() {
    let (mut s, _log) = session(vec![answer_with_a_secret()]).await;
    is_the_answer_redacted(&s.rollback(0).await.unwrap());
}

/// **`discard_changes` returns the device's answer** (0.5.13), redacted as a reply
/// is.
#[tokio::test]
async fn discard_changes_returns_the_devices_answer() {
    let (mut s, _log) = session(vec![answer_with_a_secret()]).await;
    is_the_answer_redacted(&s.discard_changes().await.unwrap());
}

/// **The seconds the device gives a commit are in the record** (0.5.13): Junos puts
/// the commit's time as a number in `junos:seconds` on `<date-time>`, and it was
/// dropped with every other attribute. It is the field `seconds`, after
/// `date-time`, read strictly as a number; anything else goes as it stood.
#[tokio::test]
async fn the_seconds_of_a_commit_are_in_the_record() {
    let entry = |seconds: &str| {
        eom(&format!(
            "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information><commit-history>\
             <sequence-number>0</sequence-number><user>ops</user>\
             <date-time junos:seconds=\"{seconds}\">2026-10-03 10:00:00 UTC</date-time>\
             </commit-history></commit-information></rpc-reply>"
        ))
    };
    for (seconds, field) in [("1759485600", "1759485600"), ("007", "007"), ("", "")] {
        let (mut s, _log) = session(vec![ok_reply_any(), entry(seconds)]).await;
        s.commit_confirmed(5, None).await.unwrap();
        assert_eq!(
            s.confirmed_commit().as_deref(),
            Some(
                format!(
                    "sequence-number=0 · user=ops · date-time=2026-10-03 10:00:00 UTC · \
                     seconds={field}"
                )
                .as_str()
            )
        );
    }
}

/// **A rename or copy never overwrites** (0.5.13): its target is looked for in the
/// candidate configuration first, and when it is there nothing is loaded.
#[tokio::test]
async fn a_copy_onto_a_target_that_is_there_is_refused() {
    let candidate = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-set>\
         set interfaces ge-0/0/0 unit 20 description x\n</configuration-set></rpc-reply>"
    ));
    let (mut s, log) = session(vec![candidate]).await;
    let e = s
        .load_configuration(
            "copy interfaces ge-0/0/0 unit 10 to unit 20",
            LoadAction::Merge,
            Format::Set,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&e, NetconfError::Policy(m) if m.contains("there already")),
        "{e}"
    );
    assert!(!sent_str(&log).contains("<load-configuration"));
}

/// **`<logical-systems>` with only its name reads a configuration whole** (0.5.13).
#[tokio::test]
async fn a_whole_logical_system_needs_every_read_grant() {
    let (mut s, _l) = session(vec![]).await;
    let filter =
        "<configuration><logical-systems><name>ls1</name></logical-systems></configuration>";
    assert!(matches!(
        s.get_configuration(Some(filter)).await,
        Err(NetconfError::Policy(_))
    ));
}
