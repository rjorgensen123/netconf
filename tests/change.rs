// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic compare-then-commit over the mock transport: the happy path, the
//! abort on drift, and the fail-fast policy block before the device is touched.

use netconf::framing::{Framing, encode};
use netconf::mock::{MockTransport, SentLog};
use netconf::rpc::BASE_1_0;
use netconf::{ConfigPolicy, Format, LoadAction, Match, NetconfError, NetconfSession, Op};

fn eom(xml: &str) -> Vec<u8> {
    encode(Framing::Eom, xml.as_bytes())
}
fn hello() -> Vec<u8> {
    eom(&format!(
        "<hello xmlns=\"{0}\"><capabilities><capability>{0}</capability></capabilities></hello>",
        BASE_1_0
    ))
}
fn ok_reply() -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><ok/></rpc-reply>"
    ))
}
/// A compare reply with no `message-id`. Junos omits it on some replies, and the
/// session tolerates that; only a mismatching id is refused.
fn diff_reply(body: &str) -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-information>\
         <configuration-output>{body}</configuration-output></configuration-information></rpc-reply>"
    ))
}
fn diff_reply_mid(body: &str, mid: u32) -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\" message-id=\"{mid}\"><configuration-information>\
         <configuration-output>{body}</configuration-output></configuration-information></rpc-reply>"
    ))
}

async fn session(replies: Vec<Vec<u8>>) -> (NetconfSession<MockTransport>, SentLog) {
    let mut chunks = vec![hello()];
    chunks.extend(replies);
    let (t, log) = MockTransport::recording(chunks);
    let mut s = NetconfSession::establish(t, true).await.unwrap();
    // The policy is bound to the session once, here.
    s.set_policy(deploy_policy());
    (s, log)
}
/// The error inside `WithReplies`, which carries the device's answers to the
/// requests that went through around a failure — here the cleanup's (0.5.13).
fn after_cleanup<T: std::fmt::Debug>(r: Result<T, NetconfError>) -> Result<T, NetconfError> {
    match r {
        Err(NetconfError::WithReplies { replies, error }) => {
            assert!(!replies.is_empty());
            Err(*error)
        }
        other => panic!("expected WithReplies, got {other:?}"),
    }
}

fn sent_str(log: &SentLog) -> String {
    String::from_utf8_lossy(&log.lock().unwrap()).into_owned()
}

fn deploy_policy() -> ConfigPolicy {
    ConfigPolicy::with_default_floor()
        .allow(
            "interfaces * unit *",
            Match::Subtree,
            &[Op::Set, Op::Delete],
        )
        .allow(
            "protocols l2circuit",
            Match::Subtree,
            &[Op::Set, Op::Delete],
        )
}

const PAYLOAD: &str = "\
set interfaces ge-0/0/1 unit 123 family ccc
set protocols l2circuit neighbor 10.0.0.2 interface ge-0/0/1.123 virtual-circuit-id 13080123";

#[tokio::test]
async fn happy_path_prepare_then_confirm() {
    // lock, load, compare(diff), [approve], compare(same diff), commit, unlock
    let d = diff_reply("[edit protocols l2circuit]\n+   neighbor 10.0.0.2");
    let (mut s, log) = session(vec![
        ok_reply(),
        ok_reply(),
        d.clone(),
        d.clone(),
        ok_reply(),
        ok_reply(),
    ])
    .await;

    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    assert!(prepared.diff.contains("neighbor 10.0.0.2"));

    s.confirm_commit(&prepared, "change ticket 4711")
        .await
        .unwrap();

    let sent = sent_str(&log);
    assert!(sent.contains("<lock>"));
    assert!(sent.contains("action=\"set\""));
    assert!(sent.contains("<log>change ticket 4711</log>"));
    assert!(sent.contains("<unlock>"));
}

#[tokio::test]
async fn no_false_drift_when_only_message_id_differs() {
    // The same diff CONTENT, but a different message-id and envelope between the
    // two compare calls.
    // Must NOT read as drift: this proves we compare the extracted diff rather
    // than the raw <rpc-reply>.
    let body = "[edit protocols l2circuit]\n+   neighbor 10.0.0.2";
    let (mut s, log) = session(vec![
        ok_reply(),
        ok_reply(),
        diff_reply_mid(body, 3),
        diff_reply_mid(body, 4), // a different message-id, the same diff
        ok_reply(),
        ok_reply(),
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    s.confirm_commit(&prepared, "job").await.unwrap();
    assert!(sent_str(&log).contains("<commit-configuration>")); // committed: no false drift
}

#[tokio::test]
async fn drift_between_review_and_commit_aborts() {
    let d1 = diff_reply("+ variant A");
    let d2 = diff_reply("+ variant B (someone changed the candidate)");
    let (mut s, log) = session(vec![
        ok_reply(),
        ok_reply(),
        d1,
        d2, // the fresh compare deviates
        ok_reply(),
        ok_reply(), // discard + unlock (cleanup)
    ])
    .await;

    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    // The fresh diff goes with the error (0.5.13): the operator sees what the
    // candidate drifted to.
    match after_cleanup(s.confirm_commit(&prepared, "job").await) {
        Err(NetconfError::Drift { fresh }) => {
            assert_eq!(fresh, "+ variant B (someone changed the candidate)");
        }
        other => panic!("expected Drift, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(sent.contains("<discard-changes/>")); // cleaned up
    assert!(!sent.contains("<commit-configuration>")); // NOT committed
}

#[tokio::test]
async fn policy_block_is_fail_fast_before_locking() {
    // No replies queued beyond hello: the policy must stop this before lock/load.
    let (mut s, log) = session(vec![]).await;
    let bad = "delete system"; // the floor: deleting a top-level tree
    match s.prepare_change(bad, Format::Set, LoadAction::Merge).await {
        Err(NetconfError::Policy(reason)) => assert!(reason.contains("floor")),
        other => panic!("expected a Policy error, got {other:?}"),
    }
    // The device was never touched.
    assert!(!sent_str(&log).contains("<lock>"));
}

// ---------------------------------------------------------------------------
// The fail-fast layer, on its own
//
// `prepare_change` checks the policy BEFORE it locks the device, and
// `load_configuration` checks the same policy again as defence in depth. The
// second layer is covered thoroughly elsewhere. These two cover the first,
// because a regression there is invisible: the device would be locked before
// anything refused, the refusal would still arrive from the depth layer, and
// every other test would stay green.
// ---------------------------------------------------------------------------

/// A session with NO policy bound — the helper above always binds one.
async fn session_without_policy(replies: Vec<Vec<u8>>) -> (NetconfSession<MockTransport>, SentLog) {
    let mut chunks = vec![hello()];
    chunks.extend(replies);
    let (t, log) = MockTransport::recording(chunks);
    let s = NetconfSession::establish(t, true).await.unwrap();
    (s, log)
}

/// No policy at all is the crate's most basic fail-closed promise: a session
/// that was never told what is permitted permits nothing.
#[tokio::test]
async fn prepare_change_without_a_policy_refuses_before_locking() {
    // No replies beyond hello: reaching the device at all would hang or error.
    let (mut s, log) = session_without_policy(vec![]).await;
    let payload = "set interfaces ge-0/0/1 unit 1 description \"x\"";
    match s
        .prepare_change(payload, Format::Set, LoadAction::Merge)
        .await
    {
        Err(NetconfError::Policy(reason)) => {
            assert!(
                reason.contains("no policy"),
                "the refusal must say what is missing: {reason}"
            );
            assert!(
                reason.contains("set_policy"),
                "and it must say how to fix it: {reason}"
            );
        }
        other => panic!("expected a Policy error, got {other:?}"),
    }
    assert!(
        !sent_str(&log).contains("<lock>"),
        "the device must not be locked when the policy already refused"
    );
}

/// Raw XML cannot be parsed into changes, so it cannot be checked. Letting it
/// through would mean sending an unchecked payload to the device, which is the
/// one thing this crate exists to prevent — so it takes a deliberate
/// `all_free(Rwd)` and nothing less.
#[tokio::test]
async fn prepare_change_refuses_raw_xml_unless_all_free_rwd_is_deliberate() {
    let (mut s, log) = session(vec![]).await; // an ordinary scoped policy
    match s
        .prepare_change("<configuration/>", Format::Xml, LoadAction::Merge)
        .await
    {
        Err(NetconfError::Policy(reason)) => {
            assert!(
                reason.contains("Format::Set"),
                "the refusal must name the only format that can be checked: {reason}"
            );
            assert!(
                reason.contains("all_free"),
                "and the deliberate way through: {reason}"
            );
        }
        other => panic!("expected a Policy error, got {other:?}"),
    }
    assert!(
        !sent_str(&log).contains("<lock>"),
        "the device must not be locked when the policy already refused"
    );
}

/// **A failure must not leave the device locked.**
///
/// `confirm_commit` used to apply `?` to the network calls directly, so a failure
/// in compare, commit or unlock returned straight out with the configuration still
/// locked and an unreviewed candidate loaded.
///
/// When the device answers — here it refuses the compare — the session is in step,
/// and discards and unlocks on the way out.
#[tokio::test]
async fn a_refusal_during_confirm_still_discards_and_unlocks() {
    let body = "+  set interfaces ge-0/0/1 unit 1";
    let refused = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error>\
         <error-tag>operation-failed</error-tag>\
         <error-message>compare refused</error-message></rpc-error></rpc-reply>"
    ));
    let (mut s, log) = session(vec![
        ok_reply(),       // lock
        ok_reply(),       // load
        diff_reply(body), // compare (prepare)
        refused,          // compare (confirm): the device says no
        ok_reply(),       // discard (cleanup)
        ok_reply(),       // unlock (cleanup)
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    match after_cleanup(s.confirm_commit(&prepared, "job").await) {
        Err(NetconfError::Device(d)) => assert_eq!(d.message.as_deref(), Some("compare refused")),
        other => panic!("expected the compare's Device error, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(sent.contains("<discard-changes/>"), "{sent}");
    assert_eq!(sent.matches("<unlock>").count(), 1, "{sent}");
    assert!(s.unanswered().is_none());
}

/// **A request that got no answer ends what the session sends** (0.7.0). The mock
/// runs out of replies part-way through, which is what a connection breaking looks
/// like from here. The compare's answer may still come, and a discard sent now
/// would read it as its own — so nothing more is sent, the session says which
/// request is unanswered, and closing it is what lets go of the lock.
#[tokio::test]
async fn a_request_without_an_answer_ends_what_the_session_sends() {
    let body = "+  set interfaces ge-0/0/1 unit 1";
    let (mut s, log) = session(vec![
        ok_reply(),       // lock
        ok_reply(),       // load
        diff_reply(body), // compare (prepare)
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();

    let err = s
        .confirm_commit(&prepared, "job")
        .await
        .expect_err("the session has no replies left, so this must fail");
    assert!(
        matches!(err, NetconfError::Transport(_)),
        "the failure comes back as it is: {err:?}"
    );
    let sent = sent_str(&log);
    assert!(!sent.contains("<discard-changes/>"), "{sent}");
    assert!(!sent.contains("<unlock>"), "{sent}");

    let unanswered = s.unanswered().expect("the compare is unanswered");
    assert!(
        unanswered.contains("request 4 (<get-configuration>)"),
        "{unanswered}"
    );
    // Every request after it is refused, before anything is sent.
    match s.unlock().await {
        Err(NetconfError::Protocol { detail, .. }) => {
            assert!(detail.contains("out of step"), "{detail}");
            assert!(detail.contains("request 4"), "{detail}");
        }
        other => panic!("expected the out-of-step refusal, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("<unlock>"));
}

/// The commit succeeded and the unlock after it failed. Both are reported: the error
/// says the commit went in, and carries what came back to the unlock. Nothing is
/// discarded after a commit that went in.
#[tokio::test]
async fn a_failed_unlock_after_a_commit_reports_the_commit() {
    let body = "+  set interfaces ge-0/0/1 unit 1";
    let unlock_error = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error>\
         <error-tag>operation-failed</error-tag>\
         <error-message>unlock refused</error-message></rpc-error></rpc-reply>"
    ));
    let (mut s, log) = session(vec![
        ok_reply(),       // lock
        ok_reply(),       // load
        diff_reply(body), // compare (prepare)
        diff_reply(body), // compare (confirm)
        ok_reply(),       // commit
        unlock_error,     // unlock
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    match s.confirm_commit(&prepared, "job").await {
        Err(NetconfError::CommittedThenFailed { reply, error }) => {
            // The device's answer to the commit goes with it (0.5.13).
            assert!(reply.contains("<ok/>"), "{reply}");
            match *error {
                NetconfError::Device(d) => {
                    assert_eq!(d.message.as_deref(), Some("unlock refused"))
                }
                other => panic!("expected the unlock's Device error inside, got {other:?}"),
            }
        }
        other => panic!("expected CommittedThenFailed, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("<discard-changes/>"));
}

/// A reply to the commit that cannot be tied to it is no answer: what comes back is
/// `CommitUnanswered`, carrying the reason. The commit's own answer may still come,
/// so the session sends nothing more (0.7.0) — no cleanup goes out on top of it.
#[tokio::test]
async fn a_commit_answered_by_something_else_is_reported_as_unanswered() {
    let body = "+  set interfaces ge-0/0/1 unit 1";
    let foreign = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\" message-id=\"99\"><ok/></rpc-reply>"
    ));
    let (mut s, log) = session(vec![
        ok_reply(),       // lock
        ok_reply(),       // load
        diff_reply(body), // compare (prepare)
        diff_reply(body), // compare (confirm)
        foreign,          // commit: an answer to something else
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    match s.confirm_commit(&prepared, "job").await {
        Err(NetconfError::CommitUnanswered(inner)) => {
            assert!(matches!(*inner, NetconfError::Protocol { .. }), "{inner:?}");
        }
        other => panic!("expected CommitUnanswered, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("<discard-changes/>"));
    let unanswered = s.unanswered().expect("the commit is unanswered");
    assert!(
        unanswered.contains("(<commit-configuration>)"),
        "{unanswered}"
    );
}

/// When the connection breaks at the commit, the commit is unanswered, and that is
/// what is reported. No cleanup is attempted on a connection that is gone (0.7.0;
/// the two cleanup steps used to be sent, and reported as failed).
#[tokio::test]
async fn an_unanswered_commit_is_reported_and_nothing_follows_it() {
    let body = "+  set interfaces ge-0/0/1 unit 1";
    let (mut s, log) = session(vec![
        ok_reply(),       // lock
        ok_reply(),       // load
        diff_reply(body), // compare (prepare)
        diff_reply(body), // compare (confirm)
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    match s.confirm_commit(&prepared, "job").await {
        Err(NetconfError::CommitUnanswered(_)) => {}
        other => panic!("expected CommitUnanswered, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("<discard-changes/>"));
    assert!(s.unanswered().is_some());
}

/// A compare reply with no `<configuration-output>` does not say what the diff is.
/// `prepare_change` reports it as `Protocol` — the operator is not handed an empty
/// diff to approve — and discards and unlocks on the way out.
#[tokio::test]
async fn prepare_change_reports_a_compare_reply_without_a_diff() {
    let (mut s, log) = session(vec![
        ok_reply(), // lock
        ok_reply(), // load
        ok_reply(), // compare: <ok/> and nothing else
        ok_reply(), // discard (cleanup)
        ok_reply(), // unlock (cleanup)
    ])
    .await;
    // What the device sent instead of a diff goes with the error (0.5.13).
    match after_cleanup(
        s.prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
            .await,
    ) {
        Err(NetconfError::Protocol { detail, received }) => {
            assert!(detail.contains("<configuration-output>"), "{detail}");
            assert!(
                received.as_deref().is_some_and(|r| r.contains("<ok/>")),
                "{received:?}"
            );
        }
        other => panic!("expected a Protocol error, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(sent.contains("<discard-changes/>"), "{sent}");
    assert!(sent.contains("<unlock>"), "{sent}");
}

/// **The B2 scenario.** The operator approved an empty diff — the device sent an
/// empty `<configuration-output/>` — and the fresh compare comes back with warnings
/// and no diff at all. That used to read as `""`, equal to the approved `""`, and the
/// candidate was committed. It is now a `Protocol` error: nothing is committed, the
/// candidate is discarded and the configuration unlocked, and the warnings are
/// still handed over.
#[tokio::test]
async fn confirm_commit_does_not_commit_on_a_compare_reply_without_a_diff() {
    let empty = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-information>\
         <configuration-output/></configuration-information></rpc-reply>"
    ));
    let warnings_only = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error>\
         <error-severity>warning</error-severity>\
         <error-message>uncommitted changes from another session</error-message>\
         </rpc-error></rpc-reply>"
    ));
    let (mut s, log) = session(vec![
        ok_reply(),    // lock
        ok_reply(),    // load
        empty,         // compare (prepare): an empty diff
        warnings_only, // compare (confirm): warnings, no diff
        ok_reply(),    // discard (cleanup)
        ok_reply(),    // unlock (cleanup)
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    assert_eq!(prepared.diff, "", "an empty element is an empty diff");
    match after_cleanup(s.confirm_commit(&prepared, "job").await) {
        Err(NetconfError::Protocol { detail, .. }) => {
            assert!(detail.contains("<configuration-output>"), "{detail}")
        }
        other => panic!("expected a Protocol error, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(!sent.contains("<commit-configuration"), "committed: {sent}");
    assert!(sent.contains("<discard-changes/>"), "{sent}");
    assert!(sent.contains("<unlock>"), "{sent}");
    let warnings = s.take_warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

/// An abort whose discard fails reports it. The discard used to be dropped, and the
/// abort reported success with the change still loaded.
#[tokio::test]
async fn an_abort_reports_a_failed_discard() {
    let discard_error = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error>\
         <error-tag>operation-failed</error-tag>\
         <error-message>discard refused</error-message></rpc-error></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![ok_reply(), discard_error, ok_reply()]).await;
    s.lock().await.unwrap();
    // The unlock went through, and its answer goes with the discard's error (0.5.13).
    match s.abort_change().await {
        Err(NetconfError::WithReplies { replies, error }) => {
            let steps: Vec<_> = replies.iter().map(|(step, _)| *step).collect();
            assert_eq!(steps, ["unlock"]);
            match *error {
                NetconfError::Device(d) => {
                    assert_eq!(d.message.as_deref(), Some("discard refused"))
                }
                other => panic!("expected the discard's Device error, got {other:?}"),
            }
        }
        other => panic!("expected WithReplies, got {other:?}"),
    }
}

/// A reply that refuses the request, in the device's words `message`.
fn refusal(message: &str) -> Vec<u8> {
    eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error>\
         <error-tag>operation-failed</error-tag>\
         <error-message>{message}</error-message></rpc-error></rpc-reply>"
    ))
}

/// An abort whose discard and unlock both go through returns the device's answer to
/// each, by its RPC name, in the order they were sent.
#[tokio::test]
async fn an_abort_returns_the_answers_to_the_discard_and_the_unlock() {
    let (mut s, log) = session(vec![ok_reply(), ok_reply(), ok_reply()]).await;
    s.lock().await.unwrap();
    let replies = s.abort_change().await.unwrap();
    let steps: Vec<_> = replies.iter().map(|(step, _)| *step).collect();
    assert_eq!(steps, ["discard-changes", "unlock"]);
    let sent = sent_str(&log);
    assert!(sent.contains("<discard-changes/>"), "{sent}");
    assert!(sent.contains("<unlock>"), "{sent}");
}

/// An abort whose unlock fails reports the unlock's error, with the answer to the
/// discard that went through before it.
#[tokio::test]
async fn an_abort_reports_a_failed_unlock_with_the_answer_to_the_discard() {
    let (mut s, _log) = session(vec![ok_reply(), ok_reply(), refusal("unlock refused")]).await;
    s.lock().await.unwrap();
    match s.abort_change().await {
        Err(NetconfError::WithReplies { replies, error }) => {
            let steps: Vec<_> = replies.iter().map(|(step, _)| *step).collect();
            assert_eq!(steps, ["discard-changes"]);
            match *error {
                NetconfError::Device(d) => {
                    assert_eq!(d.message.as_deref(), Some("unlock refused"))
                }
                other => panic!("expected the unlock's Device error, got {other:?}"),
            }
        }
        other => panic!("expected WithReplies, got {other:?}"),
    }
}

/// An abort whose discard and unlock both fail reports both: the discard's error,
/// and the unlock as the one cleanup step that failed after it, with its own error.
#[tokio::test]
async fn an_abort_reports_a_failed_discard_and_a_failed_unlock() {
    let (mut s, _log) = session(vec![
        ok_reply(),
        refusal("discard refused"),
        refusal("unlock refused"),
    ])
    .await;
    s.lock().await.unwrap();
    match s.abort_change().await {
        Err(NetconfError::CleanupFailed { error, cleanup }) => {
            match *error {
                NetconfError::Device(d) => {
                    assert_eq!(d.message.as_deref(), Some("discard refused"))
                }
                other => panic!("expected the discard's Device error, got {other:?}"),
            }
            let steps: Vec<_> = cleanup.iter().map(|(step, _)| *step).collect();
            assert_eq!(steps, ["unlock"]);
            match &cleanup[0].1 {
                NetconfError::Device(d) => {
                    assert_eq!(d.message.as_deref(), Some("unlock refused"))
                }
                other => panic!("expected the unlock's Device error, got {other:?}"),
            }
        }
        other => panic!("expected CleanupFailed, got {other:?}"),
    }
}

/// An abort whose discard gets no answer sends no unlock: the session is out of
/// step, and refuses the unlock before anything is sent. The unlock is reported as
/// the cleanup step that failed, with that refusal. The mock runs out of replies
/// after the lock, which is what a connection breaking looks like from here.
#[tokio::test]
async fn an_abort_whose_discard_gets_no_answer_sends_no_unlock() {
    let (mut s, log) = session(vec![ok_reply()]).await;
    s.lock().await.unwrap();
    match s.abort_change().await {
        Err(NetconfError::CleanupFailed { error, cleanup }) => {
            assert!(
                matches!(
                    *error,
                    NetconfError::Transport(netconf::TransportError::Closed { .. })
                ),
                "the discard's failure comes back as it is: {error:?}"
            );
            let steps: Vec<_> = cleanup.iter().map(|(step, _)| *step).collect();
            assert_eq!(steps, ["unlock"]);
            match &cleanup[0].1 {
                NetconfError::Protocol { detail, .. } => {
                    assert!(detail.contains("out of step"), "{detail}");
                    assert!(detail.contains("request 2 (<discard-changes>)"), "{detail}");
                }
                other => panic!("expected the out-of-step refusal, got {other:?}"),
            }
        }
        other => panic!("expected CleanupFailed, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(!sent.contains("<unlock"), "{sent}");
}

/// **The candidate is discarded only under the session's own lock** (0.7.0). It is
/// shared by everyone on the device: without the lock, what is in it may be someone
/// else's, so an abort and a confirm are refused and nothing is sent.
#[tokio::test]
async fn without_the_lock_nothing_is_discarded_or_committed() {
    let (mut s, log) = session(vec![]).await;
    match s.abort_change().await {
        Err(NetconfError::Policy(m)) => assert!(m.contains("does not hold the lock"), "{m}"),
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    let approved = netconf::PreparedChange::from_diff("+ approved".into());
    match s.confirm_commit(&approved, "job").await {
        Err(NetconfError::Policy(m)) => assert!(m.contains("does not hold the lock"), "{m}"),
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    assert!(!sent_str(&log).contains("<rpc"), "{}", sent_str(&log));
}

/// **A commit comment that cannot be sent discards nothing** (0.7.0). `confirm_commit`
/// checks it before anything is sent: the refusal is `Policy`, no compare, commit,
/// discard or unlock goes out, the lock and the loaded change are kept, and the
/// call goes through when it is made again with a comment that can be sent.
#[tokio::test]
async fn a_bad_commit_comment_discards_nothing_and_the_confirm_can_be_made_again() {
    let d = diff_reply("[edit protocols l2circuit]\n+   neighbor 10.0.0.2");
    let (mut s, log) = session(vec![
        ok_reply(),
        ok_reply(),
        d.clone(),
        d,
        ok_reply(),
        ok_reply(),
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    let after_prepare = sent_str(&log);
    match s
        .confirm_commit(&prepared, "ticket 4711\nsecond line")
        .await
    {
        Err(NetconfError::Policy(m)) => assert!(
            m.starts_with("a control character, U+000A, in the commit comment"),
            "{m}"
        ),
        other => panic!("expected a Policy refusal, got {other:?}"),
    }
    assert_eq!(
        sent_str(&log),
        after_prepare,
        "nothing may be sent after the prepare"
    );
    let replies = s.confirm_commit(&prepared, "ticket 4711").await.unwrap();
    let steps: Vec<_> = replies.iter().map(|(step, _)| *step).collect();
    assert_eq!(steps, ["commit-configuration", "unlock"]);
    let sent = sent_str(&log);
    assert!(sent.contains("<log>ticket 4711</log>"), "{sent}");
    assert!(!sent.contains("<discard-changes"), "{sent}");
}

/// **The diff is what the policy lets through** (0.5.11). Under the ordinary policy
/// the device's secrets are redacted before the diff reaches the consumer, and the
/// marker says what was there; a fresh diff under the same policy reads the same
/// way, so `confirm_commit` still finds no drift. Under `allow_secrets` the diff
/// carries them, `has_secrets()` says so, and `redacted_diff()` is the safe one.
#[tokio::test]
async fn the_diff_is_redacted_unless_the_policy_allows_secrets() {
    let diff = "[edit interfaces ge-0/0/1 unit 123]\n\
+  encapsulation vlan-ccc;\n\
[edit system login user x authentication]\n\
+  encrypted-password \"$9$secretHASH\"; ## SECRET-DATA";
    let replies = || {
        vec![
            ok_reply(),       // lock
            ok_reply(),       // load
            diff_reply(diff), // compare (prepare)
            diff_reply(diff), // compare (confirm)
            ok_reply(),       // commit
            ok_reply(),       // unlock
        ]
    };

    let (mut s, _log) = session(replies()).await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    assert!(!prepared.diff.contains("secretHASH"), "{}", prepared.diff);
    assert!(
        prepared.diff.contains(netconf::REDACTED),
        "{}",
        prepared.diff
    );
    assert!(prepared.diff.contains("encapsulation vlan-ccc"));
    assert!(!prepared.has_secrets());
    assert_eq!(prepared.redacted_diff(), prepared.diff);
    s.confirm_commit(&prepared, "job")
        .await
        .expect("a fresh diff under the same policy reads the same way: no drift");

    let (mut s, _log) = session(replies()).await;
    s.set_policy(deploy_policy().allow_secrets());
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    assert!(
        prepared.diff.contains("secretHASH"),
        "allow_secrets lets it through"
    );
    assert!(prepared.has_secrets());
    assert!(!prepared.redacted_diff().contains("secretHASH"));
    s.confirm_commit(&prepared, "job").await.unwrap();
}

/// **A change inside a redacted value is drift.** The operator sees the redacted
/// diff, but the drift guard compares the diff as the device wrote it: a password
/// changed on the box between approval and commit reads as the same marker on both
/// sides of the redacted diff, and used to pass (0.5.11). The state a change was
/// approved in has to be the state it is committed in.
#[tokio::test]
async fn a_change_inside_a_redacted_value_is_drift() {
    let approved = "[edit system login user x authentication]\n\
+  encrypted-password \"$9$oldHASH\"; ## SECRET-DATA";
    let fresh = "[edit system login user x authentication]\n\
+  encrypted-password \"$9$newHASH\"; ## SECRET-DATA";
    let (mut s, log) = session(vec![
        ok_reply(),           // lock
        ok_reply(),           // load
        diff_reply(approved), // compare (prepare)
        diff_reply(fresh),    // compare (confirm): only the secret differs
        ok_reply(),           // discard
        ok_reply(),           // unlock
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    assert!(
        !prepared.diff.contains("oldHASH"),
        "the operator sees it redacted"
    );
    assert!(
        !format!("{prepared:?}").contains("oldHASH"),
        "Debug shows no secret"
    );
    // The fresh diff goes with the error as the policy lets it through: redacted.
    match after_cleanup(s.confirm_commit(&prepared, "job").await) {
        Err(NetconfError::Drift { fresh }) => {
            assert!(!fresh.contains("newHASH"), "a secret leaked: {fresh}");
            assert!(fresh.contains(netconf::REDACTED), "{fresh}");
        }
        other => panic!("expected Drift, got {other:?}"),
    }
    let sent = sent_str(&log);
    assert!(!sent.contains("<commit-configuration"), "{sent}");
    assert!(
        sent.contains("<discard-changes/>") && sent.contains("<unlock>"),
        "{sent}"
    );
}

/// A change built from a stored diff has no raw text to compare with, so it is
/// compared with the fresh diff redacted the same way: the same redacted text is no
/// drift, a different one is. It is confirmed on a session that holds the lock
/// (0.7.0).
#[tokio::test]
async fn a_change_built_from_a_stored_diff_compares_the_redacted_diff() {
    let body = "[edit system login user x authentication]\n\
+  encrypted-password \"$9$HASH\"; ## SECRET-DATA";
    let (mut s, _log) = session(vec![ok_reply(), diff_reply(body), ok_reply(), ok_reply()]).await;
    s.lock().await.unwrap();
    let stored = netconf::redact_secrets(body);
    s.confirm_commit(&netconf::PreparedChange::from_diff(stored), "job")
        .await
        .expect("the stored redacted diff equals the fresh one redacted");

    let (mut s, _log) = session(vec![
        ok_reply(),
        diff_reply("+ something else"),
        ok_reply(),
        ok_reply(),
    ])
    .await;
    s.lock().await.unwrap();
    match after_cleanup(
        s.confirm_commit(
            &netconf::PreparedChange::from_diff("+ approved".into()),
            "job",
        )
        .await,
    ) {
        Err(NetconfError::Drift { fresh }) => assert_eq!(fresh, "+ something else"),
        other => panic!("expected Drift, got {other:?}"),
    }
}

/// **`confirm_commit` gives back the device's answer to the commit** (0.5.13), as
/// `commit` does: Junos answers with `<commit-results>`, naming each routing engine
/// that committed. It returned `()`, and the reply was dropped.
#[tokio::test]
async fn confirm_commit_gives_back_the_answer_to_the_commit() {
    let d = diff_reply("[edit protocols l2circuit]\n+   neighbor 10.0.0.2");
    let results = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\" message-id=\"5\"><commit-results>\
         <routing-engine><name>re0</name><commit-success/></routing-engine>\
         </commit-results></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![
        ok_reply(),
        ok_reply(),
        d.clone(),
        d,
        results,
        ok_reply(),
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    let replies = s.confirm_commit(&prepared, "job").await.unwrap();
    assert_eq!(replies[0].0, "commit-configuration");
    assert!(
        replies[0].1.contains("<name>re0</name><commit-success/>"),
        "{replies:?}"
    );
    assert_eq!(replies[1].0, "unlock");
}

/// **`prepare_change` gives back the answers to its lock and load, and a failure
/// after them keeps them** (0.5.13): on success they are in
/// `PreparedChange::replies`; when the compare fails, they go with the error in
/// `WithReplies`, with the answers to the cleanup after it.
#[tokio::test]
async fn prepare_change_keeps_the_answers_to_its_lock_and_load() {
    let locked = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><ok/><!-- locked by ops --></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![
        locked.clone(),
        ok_reply(),
        diff_reply("[edit]\n+  x;"),
    ])
    .await;
    let prepared = s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
        .unwrap();
    let steps: Vec<_> = prepared.replies.iter().map(|(step, _)| *step).collect();
    assert_eq!(steps, ["lock", "load-configuration"]);
    assert!(prepared.replies[0].1.contains("locked by ops"));

    let refused = eom(&format!(
        "<rpc-reply xmlns=\"{BASE_1_0}\"><rpc-error><error-tag>operation-failed</error-tag>\
         <error-message>compare refused</error-message></rpc-error></rpc-reply>"
    ));
    let (mut s, _log) = session(vec![locked, ok_reply(), refused, ok_reply(), ok_reply()]).await;
    match s
        .prepare_change(PAYLOAD, Format::Set, LoadAction::Merge)
        .await
    {
        Err(NetconfError::WithReplies { replies, error }) => {
            let steps: Vec<_> = replies.iter().map(|(step, _)| *step).collect();
            assert_eq!(
                steps,
                ["lock", "load-configuration", "discard-changes", "unlock"]
            );
            assert!(replies[0].1.contains("locked by ops"));
            assert!(matches!(*error, NetconfError::Device(_)), "{error:?}");
        }
        other => panic!("expected WithReplies, got {other:?}"),
    }
}
