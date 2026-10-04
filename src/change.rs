// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic **compare-then-commit**, as a library API that is easy to use correctly.
//!
//! Two phases, with an operator's approval in between:
//! 1. [`prepare_change`](NetconfSession::prepare_change) — check the policy
//!    (fail-fast), lock, load the payload, fetch the `show | compare` diff. Returns
//!    the diff for approval, with the device's answers to the lock and the load.
//! 2. [`confirm_commit`](NetconfSession::confirm_commit) — verify that a **fresh**
//!    diff still equals the approved one, then commit with a log message and
//!    unlock. On drift: discard, unlock and [`NetconfError::Drift`], carrying the
//!    fresh diff, inside [`NetconfError::WithReplies`] with the device's answers to
//!    the discard and the unlock.
//!
//! The point is that a change which slipped in between review and commit is
//! caught: we commit exactly what the operator saw, or nothing. The comparison is
//! made on the diff as the device wrote it (0.5.12), so a change inside a value the
//! policy redacts is caught too; what the operator sees is the redacted diff.

use crate::error::NetconfError;
use crate::junos::{Format, LoadAction};
use crate::policy::parse_set_lines;
use crate::session::{Action, NetconfSession};
use crate::transport::NetconfTransport;

/// A prepared change awaiting approval: the candidate is loaded and the
/// configuration is locked.
///
/// Built by [`prepare_change`](NetconfSession::prepare_change), or by
/// [`from_diff`](Self::from_diff) from a diff carried across a restart. `Debug`
/// shows [`diff`](Self::diff) only.
#[derive(Clone)]
pub struct PreparedChange {
    /// The `show | compare` diff the operator is to approve, **as the session's
    /// policy let it through** (0.5.11): the device's secrets redacted, each replaced
    /// by [`REDACTED`](crate::redact::REDACTED), unless the policy has
    /// [`allow_secrets`](crate::policy::ConfigPolicy::allow_secrets) or is `all_free`.
    ///
    /// It is the string the drift protection rests on, both for
    /// [`confirm_commit`](NetconfSession::confirm_commit)'s own comparison and for a
    /// consumer hashing it; a fresh diff under the same policy reads the same way.
    /// Until 0.5.11 it was returned raw, and the redaction was the consumer's to
    /// apply before showing or storing it.
    pub diff: String,
    /// The device's answers to the requests `prepare_change` sent before the diff,
    /// by their RPC names — `"lock"`, `"load-configuration"` — with each
    /// `<rpc-reply>`, in the order they were sent, redacted as a reply is (0.5.13).
    /// They used to be dropped. Empty for a change built with `from_diff`.
    pub replies: Vec<(&'static str, String)>,
    /// The diff as the device wrote it (0.5.12), for the drift guard alone: a change
    /// inside a value the policy redacts reads as the same marker in `diff`, and
    /// only the raw text shows it. `None` for a change built with `from_diff`, which
    /// then compares `diff` with a fresh diff redacted the same way. Never shown,
    /// never logged; `Debug` leaves it out.
    raw: Option<String>,
}

impl std::fmt::Debug for PreparedChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedChange")
            .field("diff", &self.diff)
            .finish_non_exhaustive()
    }
}

impl PreparedChange {
    /// A prepared change from a diff the consumer kept — one it stored at approval
    /// and carries across a restart (0.5.12). The drift guard then compares that
    /// diff with a fresh one redacted under the session's policy, so it sees what the
    /// stored diff can show; a change inside a redacted value is seen only by a
    /// change `prepare_change` built, which keeps the device's text for the purpose.
    pub fn from_diff(diff: String) -> Self {
        PreparedChange {
            diff,
            replies: Vec::new(),
            raw: None,
        }
    }

    /// The diff with the device's secrets redacted. Under a policy that lets secrets
    /// through, **this is the one to show the operator, to log and to store in an
    /// audit trail**; under every other policy it equals [`diff`](Self::diff), since
    /// the redaction is idempotent.
    ///
    /// Never use it for the drift comparison or for hashing when the policy lets
    /// secrets through: redaction then changes the string, and a hash over it would
    /// not match a fresh `show | compare`.
    pub fn redacted_diff(&self) -> String {
        crate::redact::redact_secrets(&self.diff)
    }

    /// Whether the diff carries secrets from the device — only under a policy that
    /// lets them through; see [`redacted_diff`](Self::redacted_diff).
    pub fn has_secrets(&self) -> bool {
        crate::redact::contains_secrets(&self.diff)
    }

    /// A short fingerprint of the diff, for logging and audit. Not a security
    /// primitive.
    ///
    /// FNV-1a, 64-bit: **stable** across processes and Rust versions, unlike
    /// `DefaultHasher`, so a fingerprint logged by one component is comparable with
    /// one logged by another.
    ///
    /// It is **not** what the drift check uses.
    /// [`confirm_commit`](crate::NetconfSession::confirm_commit) compares the diff
    /// strings themselves, byte for byte. A consumer that wants to carry an approval
    /// across a restart should hash the raw [`diff`](Self::diff) with something it
    /// trusts; this fingerprint is for correlating log lines, nothing more.
    pub fn fingerprint(&self) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for b in self.diff.as_bytes() {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }
}

impl<T: NetconfTransport> NetconfSession<T> {
    /// Phase 1 — see the module documentation. The candidate stays loaded and the
    /// configuration stays locked until
    /// [`confirm_commit`](Self::confirm_commit) or [`abort_change`](Self::abort_change).
    ///
    /// The policy is the **session's** ([`set_policy`](Self::set_policy)); it is not
    /// taken as a parameter. One policy, one enforcement point: the check here is
    /// fail-fast, before the lock, and
    /// [`load_configuration`](Self::load_configuration) enforces the same policy
    /// again as defence in depth.
    pub async fn prepare_change(
        &mut self,
        payload: &str,
        format: Format,
        action: LoadAction,
    ) -> Result<PreparedChange, NetconfError> {
        // The policy is enforced fail-fast, before the device is locked at all.
        // Only the set format can be parsed and checked; Text and Xml require a
        // deliberate all_free(Rwd), the same rule as in load_configuration.
        {
            let policy = self.permit(Action::Change)?;
            match format {
                // Fail-closed: a payload we cannot parse safely — an unknown verb,
                // an empty path, an unbalanced quote — is refused as a policy
                // violation. It is never sent unchecked.
                Format::Set => {
                    let lines = parse_set_lines(payload).map_err(|e| {
                        NetconfError::Policy(format!("could not parse payload: {e}"))
                    })?;
                    if let Err(v) = policy.check_lines(&lines) {
                        return Err(NetconfError::Policy(v.reason));
                    }
                }
                _ => {
                    if !policy.is_all_free_rwd() {
                        return Err(NetconfError::Policy(format!(
                            "policy enforcement is only implemented for Format::Set \
                             (got {format:?}); raw Text/Xml loads require the deliberate \
                             ConfigPolicy::all_free(Rwd)"
                        )));
                    }
                }
            }
        }

        // Each request's answer is kept, and goes with what comes back — the change,
        // or the failure and its cleanup (0.5.13).
        let mut replies = vec![("lock", self.lock().await?)];
        match self.load_configuration(payload, action, format).await {
            Ok(reply) => replies.push(("load-configuration", reply)),
            Err(e) => return Err(self.failed_after(replies, e).await),
        }
        match self.compare_raw().await {
            Ok(raw) => {
                let change = PreparedChange {
                    diff: self.redacted(raw.clone()),
                    replies,
                    raw: Some(raw),
                };
                // We NEVER log the diff itself — only a warning that it carries
                // device secrets, which it does only under a policy that lets them
                // through, so the consumer knows it has to go through
                // `redacted_diff()` before being displayed or stored.
                if change.has_secrets() {
                    tracing::warn!(
                        event = "secrets_in_diff",
                        fingerprint = format!("{:016x}", change.fingerprint()),
                        "the compare diff carries device secrets — the policy lets them through; \
                         use redacted_diff() for display/audit"
                    );
                }
                Ok(change)
            }
            Err(e) => Err(self.failed_after(replies, e).await),
        }
    }

    /// Phase 2 — see the module documentation.
    ///
    /// Returns the device's answers to the commit and the unlock after it, by their
    /// RPC names — `"commit-configuration"`, `"unlock"` — with each `<rpc-reply>`,
    /// redacted as a reply is (0.5.13): Junos answers the commit with
    /// `<commit-results>`, naming each routing engine that committed. Both used to
    /// be dropped.
    ///
    /// Everything that comes back is reported. If the commit succeeded and the
    /// unlock after it failed, that is
    /// [`CommittedThenFailed`](NetconfError::CommittedThenFailed), carrying the
    /// answer to the commit. If the commit got
    /// no readable answer, it is [`CommitUnanswered`](NetconfError::CommitUnanswered).
    /// That, and a failure before the commit, goes out as it came back, with the
    /// answers to the cleanup after it in [`WithReplies`](NetconfError::WithReplies)
    /// when a request of the cleanup went through — and if the cleanup fails as
    /// well, as [`CleanupFailed`](NetconfError::CleanupFailed), carrying both.
    pub async fn confirm_commit(
        &mut self,
        approved: &PreparedChange,
        comment: &str,
    ) -> Result<Vec<(&'static str, String)>, NetconfError> {
        // Every failure path cleans up, not just the drift one.
        //
        // This used to use `?` directly on the network calls, so a timeout or a
        // broken connection in `compare`, `commit` or `unlock` returned straight
        // out — leaving the device LOCKED with an unreviewed candidate loaded.
        // Nothing here could unlock it afterwards, and nothing on the device times
        // it out: the configuration stays locked until a person goes and clears it.
        match self.confirm_commit_inner(approved, comment).await {
            Ok(replies) => Ok(replies),
            // The commit went in. There is nothing to discard, and the unlock that
            // failed is the error being reported.
            Err(e @ NetconfError::CommittedThenFailed { .. }) => Err(e),
            Err(e) => Err(self.failed_after(Vec::new(), e).await),
        }
    }

    async fn confirm_commit_inner(
        &mut self,
        approved: &PreparedChange,
        comment: &str,
    ) -> Result<Vec<(&'static str, String)>, NetconfError> {
        // Raw against raw when the approved change has the device's text: the state
        // the change was approved in has to be the state it is committed in, and a
        // change inside a redacted value is a change. A change built from a stored
        // diff is compared with the fresh diff redacted the same way.
        let fresh = self.compare_raw().await?;
        let same = match &approved.raw {
            Some(raw) => fresh == *raw,
            None => self.redacted(fresh.clone()) == approved.diff,
        };
        if !same {
            // The fresh diff goes with the error, as the policy lets it through
            // (0.5.13): the operator decides what to do about the change, and needs
            // to see it. The cleanup after it discards the candidate as before.
            return Err(NetconfError::Drift {
                fresh: self.redacted(fresh),
            });
        }
        // `commit` reports what came back to the commit itself: the device's refusal,
        // or `CommitUnanswered`.
        let reply = self.commit(Some(comment)).await?;
        // The commit succeeded. A failure from here on is reported as coming after it,
        // with the device's answer to the commit (0.5.13).
        match self.unlock().await {
            Ok(unlocked) => Ok(vec![("commit-configuration", reply), ("unlock", unlocked)]),
            Err(error) => Err(NetconfError::CommittedThenFailed {
                reply,
                error: Box::new(error),
            }),
        }
    }

    /// Abort a prepared change: discard, then unlock. Both are attempted, and every
    /// failure is reported — a discard that failed used to be dropped, and the abort
    /// then reported success with the change still loaded.
    ///
    /// Returns the device's answers, by their RPC names — `"discard-changes"`,
    /// `"unlock"` — with each `<rpc-reply>`, redacted as a reply is (0.5.13). When
    /// one of them fails, the other's answer goes with its error, in
    /// [`WithReplies`](NetconfError::WithReplies).
    pub async fn abort_change(&mut self) -> Result<Vec<(&'static str, String)>, NetconfError> {
        let discarded = self.discard_changes().await;
        let unlocked = self.unlock().await;
        match (discarded, unlocked) {
            (Ok(d), Ok(u)) => Ok(vec![("discard-changes", d), ("unlock", u)]),
            (Err(e), Ok(u)) => Err(with_replies(vec![("unlock", u)], e)),
            (Ok(d), Err(e)) => Err(with_replies(vec![("discard-changes", d)], e)),
            (Err(d), Err(u)) => Err(with_cleanup(d, vec![("unlock", u)])),
        }
    }

    /// `error`, after the requests that went through with `replies`: discard and
    /// unlock, then the error with every cleanup step that failed, and with every
    /// answer the device gave — those in `replies` and the cleanup's (0.5.13).
    async fn failed_after(
        &mut self,
        mut replies: Vec<(&'static str, String)>,
        error: NetconfError,
    ) -> NetconfError {
        let (answered, failed) = self.cleanup().await;
        replies.extend(answered);
        with_replies(replies, with_cleanup(error, failed))
    }

    /// Discard and unlock after an earlier failure. Both are attempted. Every step
    /// that goes through is returned with the device's answer, and every step that
    /// fails with its error, to be reported with the failure it followed.
    async fn cleanup(&mut self) -> Cleanup {
        let mut answered = Vec::new();
        let mut failed = Vec::new();
        match self.discard_changes().await {
            Ok(reply) => answered.push(("discard-changes", reply)),
            Err(e) => failed.push(("discard-changes", e)),
        }
        match self.unlock().await {
            Ok(reply) => answered.push(("unlock", reply)),
            Err(e) => failed.push(("unlock", e)),
        }
        (answered, failed)
    }
}

/// What a cleanup came back with: the steps that went through, with the device's
/// answers, and the steps that failed, with their errors.
type Cleanup = (
    Vec<(&'static str, String)>,
    Vec<(&'static str, NetconfError)>,
);

/// `error`, together with every cleanup step that failed after it. When the cleanup
/// went through, `error` is returned exactly as it came back.
fn with_cleanup(error: NetconfError, cleanup: Vec<(&'static str, NetconfError)>) -> NetconfError {
    if cleanup.is_empty() {
        error
    } else {
        NetconfError::CleanupFailed {
            error: Box::new(error),
            cleanup,
        }
    }
}

/// `error`, with the device's answers to the requests that went through around it
/// (0.5.13). When none did, `error` is returned exactly as it came back.
fn with_replies(replies: Vec<(&'static str, String)>, error: NetconfError) -> NetconfError {
    if replies.is_empty() {
        error
    } else {
        NetconfError::WithReplies {
            replies,
            error: Box::new(error),
        }
    }
}
