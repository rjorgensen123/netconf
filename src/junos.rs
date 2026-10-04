// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed Junos helpers on top of the generic RPC layer. Each builds a Junos RPC and
//! sends it through [`NetconfSession::rpc`]. A consumer uses these rather than
//! assembling XML by hand.
//!

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer, XmlVersion};

use crate::error::{ConfirmedCheck, DeviceChanged, NetconfError};
use crate::session::{Action, NetconfSession};
use crate::transport::{NetconfTransport, ReplyBudget};
use crate::wire::printable;

/// How a configuration is loaded into the candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadAction {
    /// Merge into what is already there — the ordinary case.
    Merge,
    /// Replace the affected stanzas — `replace:` tags in the payload.
    Replace,
    /// Overwrite the whole configuration. **Dangerous.**
    ///
    /// The filter does not look at the action itself. A `Format::Set` payload always
    /// loads as `set`, so the action has no effect there; `Text` and `Xml`, where it
    /// does, are accepted only under the deliberate `all_free(Rwd)`.
    Override,
}

/// The payload format for `load-configuration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Curly-brace stanza text (`configuration-text`).
    Text,
    /// `set` commands (`configuration-set`) — the only format the filter can check.
    Set,
    /// XML (`configuration`).
    Xml,
}

impl LoadAction {
    fn as_attr(self) -> &'static str {
        match self {
            LoadAction::Merge => "merge",
            LoadAction::Replace => "replace",
            LoadAction::Override => "override",
        }
    }
}

impl<T: NetconfTransport> NetconfSession<T> {
    /// Lock the candidate database.
    ///
    /// **Every typed helper passes the session's policy first** (0.5.11): with no
    /// policy bound, or `all_deny`, it refuses before anything goes on the wire.
    ///
    /// **Every typed helper returns the device's `<rpc-reply>`** (0.5.13), with its
    /// secrets redacted unless the policy lets them through — see
    /// [`rpc`](crate::NetconfSession::rpc). Junos answers this one with `<ok/>`; the
    /// helpers that returned `()` dropped whatever the device answered.
    pub async fn lock(&mut self) -> Result<String, NetconfError> {
        self.permit(Action::Read)?;
        self.rpc("<lock><target><candidate/></target></lock>").await
    }

    /// Unlock the candidate database. Returns the device's `<rpc-reply>` (0.5.13) —
    /// see [`lock`](Self::lock).
    pub async fn unlock(&mut self) -> Result<String, NetconfError> {
        self.permit(Action::Read)?;
        self.rpc("<unlock><target><candidate/></target></unlock>")
            .await
    }

    /// Load configuration into the candidate. `payload` is XML-escaped internally.
    ///
    /// **Enforces the session's policy.** This is the one write entry point that
    /// carries a payload, and the check happens HERE, inside the library, fail-closed:
    ///
    /// - **No policy bound** ([`set_policy`](crate::NetconfSession::set_policy)), or
    ///   one that permits no change — `all_deny`, `read_only`, `all_free(Ro)`, rules
    ///   without a change grant — means refused. Someone who deliberately wants
    ///   everything binds `ConfigPolicy::all_free(Rwd)`.
    /// - **`Format::Set`** means the payload is parsed — unparsable is refused — and
    ///   checked against the policy before anything goes on the wire. It is sent
    ///   without its `#` comments, as the policy read it (0.5.13). A `rename` or
    ///   `copy` line's target must not be in the candidate configuration already,
    ///   nor be written by a line before it (0.5.13): the candidate is read first,
    ///   and if it is there the payload is refused as `Policy` and nothing is sent.
    /// - **`Text` and `Xml`** cannot be parsed and checked, so they are refused
    ///   UNLESS the policy is `all_free(Rwd)`: full control as an explicit choice,
    ///   never as a gap.
    ///
    /// The raw [`rpc`](crate::NetconfSession::rpc) is the low-level layer and goes
    /// around this; the guarantee is about the typed helpers.
    ///
    /// Returns the device's `<rpc-reply>` (0.5.13) — see [`lock`](Self::lock). Junos
    /// answers with `<load-configuration-results>`.
    pub async fn load_configuration(
        &mut self,
        payload: &str,
        action: LoadAction,
        format: Format,
    ) -> Result<String, NetconfError> {
        let lines = {
            let policy = self.permit(Action::Change)?;
            match format {
                Format::Set => {
                    // Fail-closed: a payload we cannot parse safely — unknown verb,
                    // empty path, unbalanced quote — is refused, never sent unchecked.
                    let lines = crate::policy::parse_set_lines(payload).map_err(|e| {
                        NetconfError::Policy(format!("could not parse payload: {e}"))
                    })?;
                    if let Err(v) = policy.check_lines(&lines) {
                        return Err(NetconfError::Policy(v.reason));
                    }
                    lines
                }
                Format::Text | Format::Xml => {
                    if !policy.is_all_free_rwd() {
                        return Err(NetconfError::Policy(format!(
                            "policy enforcement is only implemented for Format::Set \
                             (got {format:?}); raw Text/Xml loads require the deliberate \
                             ConfigPolicy::all_free(Rwd)"
                        )));
                    }
                    Vec::new()
                }
            }
        };
        self.no_target_there(&lines).await?;
        let inner = match format {
            // Set and Text are TEXT inside their elements, so they are escaped: a
            // `&` or a `<` in a description would otherwise break the envelope.
            //
            // Xml is not text. `<configuration>` must contain real child elements,
            // and escaping them turns the whole configuration into a single string
            // of `&lt;`, which the device rejects as a syntax error. The payload is
            // therefore passed through verbatim — the caller supplies XML and owns
            // its well-formedness, exactly as the format name says.
            //
            // That is also why this format needs a deliberate `all_free(Rwd)`: it
            // cannot be parsed into changes, so the filter cannot check it.
            // The set payload goes without its `#` comments, as the policy read it
            // (0.5.13).
            Format::Set => format!(
                "<load-configuration action=\"set\" format=\"text\"><configuration-set>{}</configuration-set></load-configuration>",
                xml_escape(&crate::policy::without_comments(payload))
            ),
            Format::Text => format!(
                "<load-configuration action=\"{}\" format=\"text\"><configuration-text>{}</configuration-text></load-configuration>",
                action.as_attr(),
                xml_escape(payload)
            ),
            Format::Xml => format!(
                "<load-configuration action=\"{}\"><configuration>{payload}</configuration></load-configuration>",
                action.as_attr()
            ),
        };
        self.rpc(&inner).await
    }

    /// `commit check` — validate the candidate without committing it. It commits
    /// nothing, so it waits under `per_rpc`, never `per_commit`.
    ///
    /// Returns the device's `<rpc-reply>`, with its secrets redacted unless the
    /// policy lets them through — see [`rpc`](crate::NetconfSession::rpc) (0.5.13).
    /// Junos answers with `<commit-results>`, one `<routing-engine>` for each it
    /// checked on, and the reply is what the check found; it used to be dropped.
    pub async fn commit_check(&mut self) -> Result<String, NetconfError> {
        self.permit(Action::Read)?;
        self.rpc("<commit-configuration><check/></commit-configuration>")
            .await
    }

    /// Commit, with an optional log message — the Junos `commit comment`.
    ///
    /// A refusal from the device comes back as the device's own `Device` error. A
    /// commit that got no readable answer comes back as
    /// [`CommitUnanswered`](NetconfError::CommitUnanswered), carrying what happened.
    ///
    /// With [`set_synchronize_commits`](crate::NetconfSession::set_synchronize_commits)
    /// on, `<synchronize/>` comes first inside `<commit-configuration>`.
    ///
    /// Waits under [`Timeouts::per_commit`](crate::Timeouts::per_commit) when that is
    /// set, and under `per_rpc` when it is not.
    ///
    /// A commit changes the device, so a policy that permits no change refuses it
    /// before anything is sent (0.5.11): no policy bound, `all_deny`, `read_only`,
    /// `all_free(Ro)`, or rules without a change grant.
    ///
    /// **When a confirmed commit made on this session is waiting to be confirmed**,
    /// this is the commit that confirms it, and it first checks that the device is
    /// as it was right after the confirmed commit (0.5.12): its last commit is still
    /// that one, and its candidate is clean. If either has changed, the commit is
    /// withheld as [`ChangedSinceConfirmed`](NetconfError::ChangedSinceConfirmed), and
    /// the device rolls the confirmed commit back by itself when its timeout runs
    /// out. The state a change was approved in has to be the state it is confirmed
    /// in; a confirming commit would otherwise also commit whatever someone else
    /// loaded in between.
    ///
    /// Returns the device's `<rpc-reply>` to the commit, redacted as
    /// [`commit_check`](Self::commit_check)'s is (0.5.13): Junos answers with
    /// `<commit-results>`, naming each routing engine that committed.
    pub async fn commit(&mut self, comment: Option<&str>) -> Result<String, NetconfError> {
        self.permit(Action::Change)?;
        if let Some(pending) = self.confirmed.clone() {
            self.check_unchanged_since(&pending).await?;
        }
        let sync = self.synchronize();
        let inner = match comment {
            Some(c) => format!(
                "<commit-configuration>{sync}<log>{}</log></commit-configuration>",
                xml_escape(c)
            ),
            // Off, this is the empty element it has always been.
            None if sync.is_empty() => "<commit-configuration/>".to_string(),
            None => format!("<commit-configuration>{sync}</commit-configuration>"),
        };
        let reply = self.send_commit(&inner).await?;
        self.confirmed = None;
        Ok(reply)
    }

    /// The check a confirming `commit` makes — see [`commit`](Self::commit).
    ///
    /// When it withholds the commit, what changed goes with the error as data
    /// (0.5.13): both commit entries and the diff, as the policy lets them through.
    /// For changes in the candidate the diff is the one the check read. For another
    /// commit it is fetched — `show | compare rollback N`, where N is the place the
    /// confirmed commit has in the commit history just read — and when the confirmed
    /// commit is no longer in that history, the error says so and carries no diff.
    async fn check_unchanged_since(
        &mut self,
        pending: &ConfirmedCommit,
    ) -> Result<(), NetconfError> {
        let history = self.commit_history().await?;
        // `commit_history` refuses a history without a first entry.
        let last = history[0].line();
        if last != pending.entry.line() {
            // The confirmed commit is found by everything but its sequence number,
            // which every later commit moves on by one.
            let place = history
                .iter()
                .position(|e| e.same_commit(&pending.entry))
                .and_then(|n| u32::try_from(n).ok());
            // The device changed whether or not the diff can be fetched: a failure
            // to fetch it goes with the answer, not in place of it (0.5.13). The
            // error is filtered already, as everything `compare_raw_against`
            // returns is.
            let (diff, diff_error) = match place {
                Some(n) => match self.compare_raw_against(n).await {
                    Ok(diff) => (Some(self.redacted(diff)), None),
                    Err(e) => (None, Some(Box::new(e))),
                },
                None => (None, None),
            };
            return Err(NetconfError::ChangedSinceConfirmed(Box::new(
                DeviceChanged {
                    check: ConfirmedCheck::LastCommit,
                    confirmed: self.shown(pending.entry.line()),
                    now: self.shown(last),
                    rollback: place,
                    diff,
                    diff_error,
                },
            )));
        }
        let diff = self.compare_raw().await?;
        if !diff.is_empty() {
            return Err(NetconfError::ChangedSinceConfirmed(Box::new(
                DeviceChanged {
                    check: ConfirmedCheck::Candidate,
                    confirmed: self.shown(pending.entry.line()),
                    now: self.shown(last),
                    rollback: Some(0),
                    diff: Some(self.redacted(diff)),
                    diff_error: None,
                },
            )));
        }
        Ok(())
    }

    /// A commit entry as it leaves the session: filtered under the policy as the
    /// device wrote it, then made printable. In that order — made printable first,
    /// a control character after a `$9$` value became `\u{0001}`, the filter
    /// stopped at its `}`, and the rest of the value went out.
    fn shown(&self, line: String) -> String {
        printable(&self.redacted(line))
    }

    /// The device's commit history, as `<get-commit-information>` describes it: one
    /// entry per `<commit-history>`, the newest first. Read raw: it is the crate's
    /// own record of the device's state, and leaves the crate only through the
    /// policy.
    async fn commit_history(&mut self) -> Result<Vec<CommitEntry>, NetconfError> {
        let xml = self
            .rpc_raw("<get-commit-information/>", ReplyBudget::PerRpc)
            .await?;
        let filter = |text: &str| self.redacted(text.to_string());
        commit_history(&xml, &filter).map_err(|e| self.filtered(e))
    }

    /// `commit confirmed <minutes>` — automatic rollback if not confirmed in time.
    /// Confirmed by a following [`commit`](Self::commit).
    ///
    /// With [`set_synchronize_commits`](crate::NetconfSession::set_synchronize_commits)
    /// on, `<synchronize/>` comes first inside `<commit-configuration>`.
    ///
    /// Waits under [`Timeouts::per_commit`](crate::Timeouts::per_commit) when that is
    /// set, and under `per_rpc` when it is not.
    ///
    /// Once the device has answered, the session records the device's last commit —
    /// this one — so that the confirming [`commit`](Self::commit) can check that
    /// nothing changed in between (0.5.12). The record can be read with
    /// [`confirmed_commit`](Self::confirmed_commit) (0.5.13). If it cannot be read
    /// from the device, the error is
    /// [`CommittedThenFailed`](NetconfError::CommittedThenFailed): the confirmed
    /// commit is live, and the device rolls it back by itself unless it is
    /// confirmed.
    ///
    /// Returns the device's `<rpc-reply>` to the commit, redacted as
    /// [`commit_check`](Self::commit_check)'s is (0.5.13).
    pub async fn commit_confirmed(
        &mut self,
        minutes: u32,
        comment: Option<&str>,
    ) -> Result<String, NetconfError> {
        self.permit(Action::Change)?;
        let sync = self.synchronize();
        let log = match comment {
            Some(c) => format!("<log>{}</log>", xml_escape(c)),
            None => String::new(),
        };
        let inner = format!(
            "<commit-configuration>{sync}<confirmed/><confirm-timeout>{minutes}</confirm-timeout>{log}</commit-configuration>"
        );
        let reply = self.send_commit(&inner).await?;
        // The commit is live. A failure to read the record is reported as coming
        // after it, with the device's answer to the commit (0.5.13).
        let mut history = match self.commit_history().await {
            Ok(history) => history,
            Err(error) => {
                return Err(NetconfError::CommittedThenFailed {
                    reply,
                    error: Box::new(error),
                })
            }
        };
        // `commit_history` refuses a history without a first entry.
        let entry = history.swap_remove(0);
        self.confirmed = Some(ConfirmedCommit { entry });
        Ok(reply)
    }

    /// The confirmed commit made on this session that is waiting for the commit
    /// that confirms it (0.5.13): the device's last commit right after it, as the
    /// session recorded it — the first `<commit-history>` entry's fields,
    /// `name=value`, joined with ` · ` — with the device's secrets redacted unless
    /// the policy lets them through, and then made printable.
    ///
    /// It is what the confirming [`commit`](Self::commit) checks the device
    /// against, and it was kept inside the session. `None` when no confirmed commit
    /// made on this session is waiting: none was made, or the commit that confirms
    /// it went through.
    pub fn confirmed_commit(&self) -> Option<String> {
        self.confirmed.as_ref().map(|c| self.shown(c.entry.line()))
    }

    /// The `<synchronize/>` child of a commit when the session asks for it, and
    /// nothing when it does not.
    fn synchronize(&self) -> &'static str {
        if self.synchronize_commits {
            "<synchronize/>"
        } else {
            ""
        }
    }

    /// Send a commit and report what came back. The device's answer is passed on as
    /// it is: an `<rpc-error>` is its `Device` error. When no answer that can be read
    /// comes back, that is what is reported — `CommitUnanswered`, carrying the
    /// timeout, the broken connection or the unreadable reply — rather than an error
    /// that looks like any other failed request.
    ///
    /// The commit runs under `Timeouts::per_commit` when the consumer has set one:
    /// a device can take far longer to commit than to answer anything else.
    async fn send_commit(&mut self, inner: &str) -> Result<String, NetconfError> {
        match self.rpc_with_budget(inner, ReplyBudget::PerCommit).await {
            Ok(reply) => Ok(reply),
            Err(e @ NetconfError::Device(_)) => Err(e),
            Err(e) => Err(NetconfError::CommitUnanswered(Box::new(e))),
        }
    }

    /// Roll the candidate back to rollback `n`; 0 is the last committed configuration.
    ///
    /// Rollback 0 discards the candidate's changes and changes nothing on the device.
    /// Rollback to a **previous** configuration loads it into the candidate whole, and
    /// the filter cannot read what it changes — so, like a `Text` or `Xml` load, it
    /// requires the deliberate `all_free(Rwd)` (0.5.11).
    ///
    /// Returns the device's `<rpc-reply>` (0.5.13) — see [`lock`](Self::lock).
    pub async fn rollback(&mut self, n: u32) -> Result<String, NetconfError> {
        if n == 0 {
            self.permit(Action::Read)?;
        } else if !self.permit(Action::Change)?.is_all_free_rwd() {
            return Err(NetconfError::Policy(format!(
                "rollback {n} loads a previous configuration whole, which the policy cannot \
                 check; like a Text or Xml load it requires the deliberate \
                 ConfigPolicy::all_free(Rwd)"
            )));
        }
        let inner = format!("<load-configuration rollback=\"{n}\"/>");
        self.rpc(&inner).await
    }

    /// Discard every uncommitted change in the candidate. Returns the device's
    /// `<rpc-reply>` (0.5.13) — see [`lock`](Self::lock).
    pub async fn discard_changes(&mut self) -> Result<String, NetconfError> {
        self.permit(Action::Read)?;
        self.rpc("<discard-changes/>").await
    }

    /// Fetch configuration, optionally filtered. Returns the `<rpc-reply>`, with the
    /// device's secrets redacted unless the policy lets them through — see
    /// [`rpc`](crate::NetconfSession::rpc).
    ///
    /// **Read gating:** under the ordinary policy reading is open, except for the
    /// sensitive subtrees ([`SENSITIVE_READ_ROOTS`](crate::policy::SENSITIVE_READ_ROOTS)),
    /// which require an explicit `allow_read` grant in the session's policy. `None`
    /// means the whole configuration, which includes them and therefore requires a
    /// grant on every one. With no policy bound nothing is read (0.5.11).
    pub async fn get_configuration(
        &mut self,
        filter: Option<&str>,
    ) -> Result<String, NetconfError> {
        let inner = {
            let policy = self.permit(Action::Read)?;
            let (targets, filter) = match filter {
                None => (Vec::new(), None), // the whole configuration
                Some(f) => {
                    let read = read_filter(f)?;
                    (read.targets, Some(read.xml))
                }
            };
            policy
                .check_config_read_elements(&targets)
                .map_err(NetconfError::Policy)?;
            match filter {
                Some(f) => format!("<get-configuration>{f}</get-configuration>"),
                None => "<get-configuration/>".to_string(),
            }
        };
        self.rpc(&inner).await
    }

    /// Refuse the payload when a `rename` or `copy` line would write a path that is
    /// there already (0.5.13): in the candidate configuration, read in set format, or
    /// written by a line before it. Reads nothing when no line renames or copies.
    async fn no_target_there(
        &mut self,
        lines: &[crate::policy::SetLine],
    ) -> Result<(), NetconfError> {
        if lines.iter().all(|l| l.target().is_none()) {
            return Ok(());
        }
        let reply = self
            .rpc_raw(
                "<get-configuration database=\"candidate\" format=\"set\"/>",
                ReplyBudget::PerRpc,
            )
            .await
            .map_err(|e| self.filtered(e))?;
        let candidate = configuration_set(&reply).map_err(|e| self.filtered(e))?;
        for (i, line) in lines.iter().enumerate() {
            let Some(target) = line.target() else {
                continue;
            };
            let written_before = lines[..i]
                .iter()
                .flat_map(|l| &l.changes)
                .any(|c| c.op == crate::policy::Op::Set && c.path.starts_with(target));
            if written_before || crate::policy::set_text_has(&candidate, target) {
                return Err(NetconfError::Policy(format!(
                    "the target «{}» of a rename or copy is there already{} — a rename or a \
                     copy creates, it does not overwrite (denied, fail-closed)",
                    crate::redact::redact_secrets(&target.join(" ")),
                    if written_before {
                        ", written by a line before it"
                    } else {
                        " in the candidate configuration"
                    }
                )));
            }
        }
        Ok(())
    }

    /// `show | compare` — the diff between the candidate and the last committed
    /// configuration. Returns the **plain diff text**, the content of
    /// `<configuration-output>`, not the envelope, with the device's secrets redacted
    /// unless the policy lets them through — see [`rpc`](crate::NetconfSession::rpc).
    /// It is deterministic under one policy, which is what makes it usable for the
    /// drift comparison in compare-then-commit. An empty
    /// element gives an empty string: no change. A reply without the element is
    /// [`NetconfError::Protocol`] (0.5.7) — see
    /// [`extract_compare_diff`](crate::rpc::extract_compare_diff).
    pub async fn compare(&mut self) -> Result<String, NetconfError> {
        let raw = self.compare_raw().await?;
        Ok(self.redacted(raw))
    }

    /// [`compare`](Self::compare) as the device wrote it, for the crate's own
    /// comparisons: the drift guard compares the diff the operator approved with a
    /// fresh one here, raw against raw, so a change inside a value the policy
    /// redacts is still drift (0.5.12). Nothing returned from here leaves the crate
    /// unredacted.
    pub(crate) async fn compare_raw(&mut self) -> Result<String, NetconfError> {
        self.compare_raw_against(0).await
    }

    /// The candidate against rollback `n`, as the device wrote it — `show | compare
    /// rollback n`. [`compare_raw`](Self::compare_raw) is `n = 0`. An error carries
    /// what the device sent, redacted under the policy.
    async fn compare_raw_against(&mut self, n: u32) -> Result<String, NetconfError> {
        self.permit(Action::Read)?;
        let reply = self
            .rpc_raw(
                &format!(
                    "<get-configuration compare=\"rollback\" rollback=\"{n}\" format=\"text\"/>"
                ),
                ReplyBudget::PerRpc,
            )
            .await?;
        let filter = |text: &str| self.redacted(text.to_string());
        crate::rpc::compare_diff(&reply, &filter).map_err(|e| self.filtered(e))
    }

    /// Run an operational command, for example `show l2circuit connections`. Text or
    /// XML out, with the device's secrets redacted unless the policy lets them through
    /// — see [`rpc`](crate::NetconfSession::rpc).
    ///
    /// **The command filter:** under the ordinary policy only `show ...` is permitted,
    /// unabbreviated, and `show configuration <tree>` is gated by the read grants.
    /// `request`, `clear`, `restart` and the rest require an explicit `allow_command`
    /// grant or `all_free(Rwd)`; `read_only` refuses them whatever is granted. With
    /// no policy bound no command runs (0.5.11). An ordinary `show` runs under the
    /// device user's OWN authorisation on the box — its login class — which this
    /// crate does not try to reproduce.
    pub async fn command(&mut self, cmd: &str) -> Result<String, NetconfError> {
        self.permit(Action::Read)?
            .check_command(cmd)
            .map_err(NetconfError::Policy)?;
        let inner = format!("<command format=\"text\">{}</command>", xml_escape(cmd));
        self.rpc(&inner).await
    }
}

/// A confirmed commit made on the session, waiting for the commit that confirms it
/// (0.5.12): the device's last commit right after it, as
/// `<get-commit-information>` described it.
#[derive(Debug, Clone)]
pub(crate) struct ConfirmedCommit {
    /// The first `<commit-history>` entry — see [`commit_history`].
    pub(crate) entry: CommitEntry,
}

/// One `<commit-history>` entry: each child element's local name and its text,
/// whitespace collapsed, as the device wrote it, in the device's order — and
/// `seconds`, after `date-time`, from the `junos:seconds` on it (0.5.13). It leaves
/// the session filtered, then made printable — see `shown`. Junos writes
/// `sequence-number`, `user`, `client`, `date-time` and `log`; whatever children
/// there are are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitEntry {
    fields: Vec<(String, String)>,
}

impl CommitEntry {
    /// The entry as one line: `name=value`, joined with ` · `.
    pub(crate) fn line(&self) -> String {
        let parts: Vec<String> = self
            .fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        parts.join(" · ")
    }

    /// Whether `other` is the same commit: every field the same but the sequence
    /// number, which is the commit's place in the history and moves on by one with
    /// every later commit.
    fn same_commit(&self, other: &CommitEntry) -> bool {
        let identity = |e: &CommitEntry| -> Vec<(String, String)> {
            e.fields
                .iter()
                .filter(|(name, _)| name != "sequence-number")
                .cloned()
                .collect()
        };
        identity(self) == identity(other)
    }
}

/// The `junos:seconds` attribute of a `<date-time>`, any prefix: the commit's time
/// as a number of seconds, the one form of it a program can read without parsing a
/// date (0.5.13; it was dropped). It is read strictly, as `wire::strict_u64` reads a
/// number; what is not one goes as it stood, never made into one.
fn date_time_seconds(e: &BytesStart<'_>) -> Option<String> {
    let attr = e
        .attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == b"seconds")?;
    let text = String::from_utf8_lossy(&attr.value).into_owned();
    Some(match crate::wire::strict_u64(&text) {
        Some(n) => n.to_string(),
        None => text,
    })
}

/// The `<commit-history>` entries of a `<get-commit-information>` reply, in the
/// device's order — the newest first. A reply whose first entry is missing or
/// empty is `Protocol`, carrying the reply: a device that has committed has at
/// least one.
///
/// What a `Protocol` error quotes of the document goes through `filter`, then is
/// made printable (0.5.13).
fn commit_history(
    xml: &str,
    filter: crate::rpc::Filter<'_>,
) -> Result<Vec<CommitEntry>, NetconfError> {
    let mut reader = Reader::from_str(xml);
    let mut in_entry = false;
    let mut field: Option<String> = None;
    let mut value = String::new();
    // Text in an entry outside every field (0.5.13).
    let mut loose = String::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut entries: Vec<CommitEntry> = Vec::new();
    // `junos:seconds` on the `<date-time>` being read, to follow it as its own
    // field (0.5.13).
    let mut seconds: Option<String> = None;
    let collapse = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    // Text outside every field is kept as `#text`, so it is not lost (0.5.13).
    let take_loose = |loose: &mut String, fields: &mut Vec<(String, String)>| {
        let t = collapse(loose);
        if !t.is_empty() {
            fields.push(("#text".to_string(), t));
        }
        loose.clear();
    };
    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(NetconfError::protocol_with(
                    format!(
                        "commit information: {}",
                        crate::rpc::quoted(filter, &e.to_string())
                    ),
                    xml,
                ))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if !in_entry && name == "commit-history" {
                    in_entry = true;
                } else if in_entry && field.is_none() {
                    take_loose(&mut loose, &mut fields);
                    if name == "date-time" {
                        seconds = date_time_seconds(&e);
                    }
                    field = Some(name);
                    value.clear();
                }
            }
            // An empty child is a field that is there and empty, and an empty entry
            // is an entry (0.5.13): both used to be skipped, and an empty first entry
            // left the next one to be taken for the last commit.
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if !in_entry && name == "commit-history" {
                    entries.push(CommitEntry { fields: Vec::new() });
                } else if in_entry && field.is_none() {
                    take_loose(&mut loose, &mut fields);
                    let seconds = (name == "date-time")
                        .then(|| date_time_seconds(&e))
                        .flatten();
                    fields.push((name, String::new()));
                    if let Some(seconds) = seconds {
                        fields.push(("seconds".to_string(), seconds));
                    }
                }
            }
            Ok(Event::Text(t)) if in_entry => {
                let s = t.xml10_content().map_err(|e| {
                    NetconfError::protocol_with(
                        format!(
                            "commit information: {}",
                            crate::rpc::quoted(filter, &e.to_string())
                        ),
                        xml,
                    )
                })?;
                if field.is_some() {
                    value.push_str(&s);
                } else {
                    loose.push_str(&s);
                }
            }
            // A value in CDATA is a value (0.5.13); it used to be skipped.
            Ok(Event::CData(t)) if in_entry => {
                let s = String::from_utf8_lossy(&t);
                if field.is_some() {
                    value.push_str(&s);
                } else {
                    loose.push_str(&s);
                }
            }
            Ok(Event::GeneralRef(r)) => {
                let s = crate::rpc::resolve_entity(&r, filter).map_err(|e| e.about(xml))?;
                if in_entry && field.is_some() {
                    value.push_str(&s);
                } else if in_entry {
                    loose.push_str(&s);
                }
            }
            Ok(Event::End(e)) if in_entry => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if field.as_deref() == Some(name.as_str()) {
                    fields.push((name, collapse(&value)));
                    if let Some(seconds) = seconds.take() {
                        fields.push(("seconds".to_string(), seconds));
                    }
                    field = None;
                } else if field.is_none() && name == "commit-history" {
                    take_loose(&mut loose, &mut fields);
                    entries.push(CommitEntry {
                        fields: std::mem::take(&mut fields),
                    });
                    in_entry = false;
                }
            }
            Ok(_) => {}
        }
    }
    // The reply goes with the error (0.5.13).
    if entries.first().map_or(true, |e| e.fields.is_empty()) {
        return Err(NetconfError::protocol_with(
            "commit information: the reply has no <commit-history> entry — the device has not \
             said what its last commit is",
            xml,
        ));
    }
    Ok(entries)
}

/// A `get_configuration` filter as the gate read it: the element names it checks, and
/// the filter serialized from exactly what was read, which is what goes to the
/// device.
struct ReadFilter {
    /// Every element name in the filter, nested ones included, by its local name —
    /// any namespace prefix removed — in lowercase; `configuration` itself is not
    /// among them. Empty means the whole configuration, which the gate treats most
    /// strictly — and so does a `<logical-systems>` or `<tenants>` with nothing in
    /// it but a `<name>`, a configuration whole (0.5.13).
    targets: Vec<String>,
    /// The filter as it will be sent.
    xml: String,
}

/// Read a `get_configuration` filter, strictly, and write it out again.
///
/// One parser does both the gate's reading and the device's. The gate used to read
/// the filter with a scanner of its own while the string went to the device
/// untouched, so the two could disagree about what the filter was — and markup that
/// closed `<get-configuration>`, or the end-of-message sequence, reached the device
/// as more than a filter. Then the filter had to be well-formed XML, but the text
/// still went to the device as written, and the parser is lenient in places the gate
/// is not: `<system\x0c/>` named a target `system\x0c`, which is on nobody's list,
/// while the device may well read it as `system`. Whether it does is beside the
/// point. What goes to the device is now **serialized from what was read** (0.5.11),
/// so the two cannot differ, and the reading is strict: elements, attributes and text
/// only — no declaration, doctype, processing instruction, comment or CDATA; every
/// element closed inside the filter; every element and attribute name an ASCII XML
/// name (`[A-Za-z_][A-Za-z0-9_.-]*`, with an optional prefix); every attribute
/// quoted, given once, and without `<`; only the five predefined entities and
/// character references; no control character in text. Whitespace between elements
/// is not kept.
fn read_filter(filter: &str) -> Result<ReadFilter, NetconfError> {
    let refuse = |why: String| NetconfError::Policy(format!("get_configuration filter: {why}"));
    if filter.contains("]]>]]>") {
        return Err(refuse(
            "it contains `]]>]]>`, which ends a message in end-of-message framing".into(),
        ));
    }
    let mut reader = Reader::from_str(filter);
    // An end tag with no element open is an error from quick-xml itself, so every
    // `End` that reaches the loop closes an element the filter opened. That is
    // quick-xml's default; it is set here because the loop relies on it.
    reader.config_mut().allow_unmatched_ends = false;
    let mut writer = Writer::new(Vec::new());
    let mut write = |event: Event<'_>| {
        writer
            .write_event(event)
            .map_err(|e| refuse(format!("could not write the filter back out: {e}")))
    };
    let mut depth = 0usize;
    let mut targets = Vec::new();
    // The elements open, and whether one has a child other than its `<name>`: a
    // `<logical-systems>` or `<tenants>` without one reads a whole configuration
    // (0.5.13).
    let mut open: Vec<(String, bool)> = Vec::new();
    let mut whole = false;
    let child = |open: &mut Vec<(String, bool)>, name: &str| {
        if let Some(parent) = open.last_mut() {
            if name != "name" {
                parent.1 = true;
            }
        }
    };
    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(refuse(format!(
                    "not well-formed XML: {}",
                    printable(&e.to_string())
                )))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                depth += 1;
                let name = element_name(e.name().into_inner(), &refuse)?;
                push_target(&mut targets, e.local_name().as_ref());
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                child(&mut open, &local);
                open.push((local, false));
                write(Event::Start(with_attributes(
                    BytesStart::new(name),
                    &e,
                    &refuse,
                )?))?;
            }
            Ok(Event::Empty(e)) => {
                let name = element_name(e.name().into_inner(), &refuse)?;
                push_target(&mut targets, e.local_name().as_ref());
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_ascii_lowercase();
                child(&mut open, &local);
                whole |= crate::policy::NESTED_CONFIGURATIONS.contains(&local.as_str());
                write(Event::Empty(with_attributes(
                    BytesStart::new(name),
                    &e,
                    &refuse,
                )?))?;
            }
            Ok(Event::End(e)) => {
                depth -= 1;
                if let Some((local, has_child)) = open.pop() {
                    whole |= !has_child
                        && crate::policy::NESTED_CONFIGURATIONS.contains(&local.as_str());
                }
                let name = element_name(e.name().into_inner(), &refuse)?;
                write(Event::End(BytesEnd::new(name)))?;
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .xml10_content()
                    .map_err(|e| refuse(format!("text: {}", printable(&e.to_string()))))?;
                if text.trim().is_empty() {
                    continue; // whitespace between elements is formatting, not filter
                }
                no_control(&text, &refuse)?;
                write(Event::Text(BytesText::new(&text)))?;
            }
            Ok(Event::GeneralRef(r)) => {
                // A character reference is text once resolved, and is held to the
                // same rule: `&#12;` is a form feed, not a way past the check.
                // The consumer's own filter, quoted back to it as written.
                let text = crate::rpc::resolve_entity(&r, &|t: &str| t.to_string())
                    .map_err(|e| refuse(format!("{e} (denied, fail-closed)")))?;
                no_control(&text, &refuse)?;
                write(Event::Text(BytesText::new(&text)))?;
            }
            Ok(Event::Decl(_) | Event::PI(_) | Event::DocType(_)) => {
                return Err(refuse("only elements and text belong in a filter".into()));
            }
            Ok(Event::Comment(_) | Event::CData(_)) => {
                return Err(refuse(
                    "only elements and text belong in a filter — no comment, no CDATA".into(),
                ));
            }
        }
    }
    if depth != 0 {
        return Err(refuse("an element is not closed".into()));
    }
    let xml = String::from_utf8(writer.into_inner())
        .map_err(|_| refuse("the filter written back out is not UTF-8".into()))?;
    Ok(ReadFilter {
        targets: if whole { Vec::new() } else { targets },
        xml,
    })
}

/// An element or attribute name the filter may use: an ASCII XML name, with an
/// optional prefix — `[A-Za-z_][A-Za-z0-9_.-]*`, once or twice around a colon. The
/// parser accepts far more; `system\x0c` is a name to it.
fn element_name<'a>(
    raw: &'a [u8],
    refuse: &dyn Fn(String) -> NetconfError,
) -> Result<&'a str, NetconfError> {
    let name = std::str::from_utf8(raw).unwrap_or("");
    let part_ok = |p: &str| {
        let mut chars = p.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    };
    let mut parts = name.split(':');
    let ok = match (parts.next(), parts.next(), parts.next()) {
        (Some(local), None, _) => part_ok(local),
        (Some(prefix), Some(local), None) => part_ok(prefix) && part_ok(local),
        _ => false,
    };
    if !ok {
        return Err(refuse(format!(
            "`{}` is not a name a filter may use — letters, digits, `_`, `-` and `.`, with an \
             optional prefix (denied, fail-closed)",
            printable(name)
        )));
    }
    Ok(name)
}

/// Copy an element's attributes onto the one being written, strictly: each given
/// once, quoted, with a name the filter may use, and a value without `<` whose
/// entities are known.
fn with_attributes<'a>(
    mut out: BytesStart<'a>,
    e: &BytesStart<'_>,
    refuse: &dyn Fn(String) -> NetconfError,
) -> Result<BytesStart<'a>, NetconfError> {
    for attr in e.attributes() {
        let attr = attr.map_err(|e| {
            refuse(format!(
                "attribute: {} (denied, fail-closed)",
                printable(&e.to_string())
            ))
        })?;
        let key = element_name(attr.key.as_ref(), refuse)?.to_string();
        if attr.value.contains(&b'<') {
            return Err(refuse(format!(
                "not well-formed XML: `<` in the value of the attribute `{key}`"
            )));
        }
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|e| {
                refuse(format!(
                    "attribute `{key}`: {} (denied, fail-closed)",
                    printable(&e.to_string())
                ))
            })?;
        if let Some(c) = value.chars().find(|c| c.is_control()) {
            return Err(refuse(format!(
                "a control character, U+{:04X}, in the value of the attribute `{key}` \
                 (denied, fail-closed)",
                u32::from(c)
            )));
        }
        out.push_attribute((key.as_str(), value.as_ref()));
    }
    Ok(out)
}

/// Refuse a control character in a filter's text, written directly or as a
/// character reference.
fn no_control(text: &str, refuse: &dyn Fn(String) -> NetconfError) -> Result<(), NetconfError> {
    match text.chars().find(|c| c.is_control()) {
        Some(c) => Err(refuse(format!(
            "a control character, U+{:04X}, in the text (denied, fail-closed)",
            u32::from(c)
        ))),
        None => Ok(()),
    }
}

/// The text of the `<configuration-set>` in a `get-configuration` reply in set
/// format (0.5.13).
fn configuration_set(xml: &str) -> Result<String, NetconfError> {
    let mut reader = Reader::from_str(xml);
    let (mut inside, mut out) = (false, String::new());
    let broken =
        |e: String| NetconfError::protocol_with(format!("candidate: {}", printable(&e)), xml);
    loop {
        match reader.read_event().map_err(|e| broken(e.to_string()))? {
            Event::Eof => return Ok(out),
            Event::Start(e) if e.local_name().as_ref() == b"configuration-set" => inside = true,
            Event::End(e) if e.local_name().as_ref() == b"configuration-set" => inside = false,
            Event::Text(t) if inside => {
                out.push_str(&t.xml10_content().map_err(|e| broken(e.to_string()))?)
            }
            Event::GeneralRef(r) if inside => out.push_str(
                &crate::rpc::resolve_entity(&r, &|t: &str| t.to_string())
                    .map_err(|e| broken(e.to_string()))?,
            ),
            _ => {}
        }
    }
}

/// Record one element name as a read target: lowercase, and not `configuration`.
fn push_target(names: &mut Vec<String>, local: &[u8]) {
    let name = String::from_utf8_lossy(local).to_ascii_lowercase();
    if name != "configuration" {
        names.push(name);
    }
}

/// Minimal XML escaping for text embedded in RPCs (`&`, `<`, `>`).
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod commit_budget_tests {
    //! Commit RPCs wait under `Timeouts::per_commit`, everything else under
    //! `per_rpc` (0.5.7).
    //!
    //! `MockTransport` has no clock, and the hook that tells a transport which
    //! budget applies is sealed, so the transport here lives inside the crate. Each
    //! reply arrives a given time after it is waited for, and a wait longer than the
    //! per-read limit the session selected is `Timeout { op: "rpc-recv" }`, as in
    //! `RusshTransport`. No time passes.

    use std::collections::VecDeque;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;

    use crate::error::NetconfError;
    use crate::framing::{encode, Framing};
    use crate::policy::ConfigPolicy;
    use crate::rpc::BASE_1_0;
    use crate::session::NetconfSession;
    use crate::transport::{ConnectOptions, NetconfTransport, ReplyBudget, Timeouts};
    use crate::{Access, Format, LoadAction};

    struct Delayed {
        timeouts: Timeouts,
        budget: ReplyBudget,
        /// Each reply, with how long after the read begins it arrives.
        inbound: VecDeque<(Duration, Vec<u8>)>,
    }

    #[async_trait]
    impl NetconfTransport for Delayed {
        async fn connect(_opts: &ConnectOptions) -> Result<Self, NetconfError> {
            unreachable!("built directly and handed to establish")
        }
        async fn send(&mut self, _bytes: &[u8]) -> Result<(), NetconfError> {
            Ok(())
        }
        async fn recv(&mut self) -> Result<Bytes, NetconfError> {
            let Some((after, reply)) = self.inbound.pop_front() else {
                return Ok(Bytes::new());
            };
            if after > self.timeouts.per_read(self.budget) {
                return Err(NetconfError::timeout("rpc-recv"));
            }
            Ok(Bytes::from(reply))
        }
        async fn close(self) -> Result<crate::error::SshMessages, NetconfError> {
            Ok(crate::error::SshMessages::default())
        }
        fn reply_budget(&mut self, budget: ReplyBudget) {
            self.budget = budget;
        }
    }

    const PER_RPC: Duration = Duration::from_secs(5);
    const PER_COMMIT: Duration = Duration::from_secs(120);
    /// Past `per_rpc`, well inside `per_commit`.
    const SLOW: Duration = Duration::from_secs(30);
    const QUICK: Duration = Duration::from_secs(1);

    fn eom(xml: &str) -> Vec<u8> {
        encode(Framing::Eom, xml.as_bytes())
    }

    fn ok() -> Vec<u8> {
        eom(&format!(
            "<rpc-reply xmlns=\"{BASE_1_0}\"><ok/></rpc-reply>"
        ))
    }

    fn commit_info() -> Vec<u8> {
        eom(&format!(
            "<rpc-reply xmlns=\"{BASE_1_0}\"><commit-information><commit-history>\
             <sequence-number>0</sequence-number><user>u</user><date-time>t</date-time>\
             </commit-history></commit-information></rpc-reply>"
        ))
    }

    fn diff() -> Vec<u8> {
        eom(&format!(
            "<rpc-reply xmlns=\"{BASE_1_0}\"><configuration-output>\
             +  set interfaces ge-0/0/1 unit 1</configuration-output></rpc-reply>"
        ))
    }

    async fn session(
        per_commit: Option<Duration>,
        replies: Vec<(Duration, Vec<u8>)>,
    ) -> NetconfSession<Delayed> {
        let hello = eom(&format!(
            "<hello xmlns=\"{0}\"><capabilities><capability>{0}</capability>\
             </capabilities></hello>",
            BASE_1_0
        ));
        let mut inbound = VecDeque::from(vec![(Duration::ZERO, hello)]);
        inbound.extend(replies);
        let t = Delayed {
            timeouts: Timeouts {
                per_rpc: PER_RPC,
                per_commit,
                ..Timeouts::default()
            },
            budget: ReplyBudget::PerRpc,
            inbound,
        };
        let mut s = NetconfSession::establish(t, false).await.unwrap();
        // Every helper passes the policy first; these tests are about the clock.
        s.set_policy(
            ConfigPolicy::with_default_floor().grant(crate::Scope::LogicalUnits, Access::Rw),
        );
        s
    }

    fn is_rpc_recv_timeout(e: &NetconfError) -> bool {
        matches!(e, NetconfError::Timeout { op: "rpc-recv", .. })
    }

    /// A commit answered after `per_rpc` and before `per_commit` goes through, for
    /// both commit helpers — and the request after it is back on `per_rpc`.
    #[tokio::test]
    async fn a_slow_commit_succeeds_under_per_commit() {
        let mut s = session(
            Some(PER_COMMIT),
            vec![
                (SLOW, ok()),
                (SLOW, ok()),
                (QUICK, commit_info()),
                (SLOW, ok()),
            ],
        )
        .await;
        s.commit(Some("job"))
            .await
            .expect("commit under per_commit");
        s.commit_confirmed(5, None)
            .await
            .expect("commit_confirmed under per_commit; its commit-information read is on per_rpc");
        let e = s
            .get_configuration(Some("<interfaces/>"))
            .await
            .expect_err("the next request is back on per_rpc");
        assert!(is_rpc_recv_timeout(&e), "{e:?}");
    }

    /// `per_commit` is not a longer `per_rpc`: a commit that outlasts it too is
    /// unanswered, as before.
    #[tokio::test]
    async fn a_commit_past_per_commit_is_unanswered() {
        let mut s = session(Some(PER_COMMIT), vec![(PER_COMMIT * 2, ok())]).await;
        match s.commit(None).await {
            Err(NetconfError::CommitUnanswered(inner)) if is_rpc_recv_timeout(&inner) => {}
            other => panic!("expected CommitUnanswered(Timeout {{ op: rpc-recv }}), got {other:?}"),
        }
    }

    /// Only the commits get the longer budget: a reply after `per_rpc` to
    /// `get_configuration`, `compare` or `commit_check` still times out.
    #[tokio::test]
    async fn everything_but_a_commit_stays_on_per_rpc() {
        let mut s = session(Some(PER_COMMIT), vec![(SLOW, ok())]).await;
        let e = s
            .get_configuration(Some("<interfaces/>"))
            .await
            .expect_err("get_configuration");
        assert!(is_rpc_recv_timeout(&e), "{e:?}");

        let mut s = session(Some(PER_COMMIT), vec![(SLOW, diff())]).await;
        let e = s.compare().await.expect_err("compare");
        assert!(is_rpc_recv_timeout(&e), "{e:?}");

        let mut s = session(Some(PER_COMMIT), vec![(SLOW, ok())]).await;
        let e = s.commit_check().await.expect_err("commit_check");
        assert!(is_rpc_recv_timeout(&e), "{e:?}");
    }

    /// Inside `confirm_commit` the compare runs under `per_rpc` and the commit under
    /// `per_commit`.
    #[tokio::test]
    async fn confirm_commit_commits_under_per_commit() {
        let mut s = session(
            Some(PER_COMMIT),
            vec![
                (QUICK, ok()),   // lock
                (QUICK, ok()),   // load
                (QUICK, diff()), // compare (prepare)
                (QUICK, diff()), // compare (confirm)
                (SLOW, ok()),    // commit
                (QUICK, ok()),   // unlock
            ],
        )
        .await;
        s.set_policy(
            ConfigPolicy::with_default_floor().grant(crate::Scope::LogicalUnits, Access::Rw),
        );
        let prepared = s
            .prepare_change(
                "set interfaces ge-0/0/1 unit 1 description x",
                Format::Set,
                LoadAction::Merge,
            )
            .await
            .unwrap();
        s.confirm_commit(&prepared, "job")
            .await
            .expect("the commit inside confirm_commit runs under per_commit");
    }

    /// `per_commit: None` is today's behaviour: a commit waits under `per_rpc`.
    #[tokio::test]
    async fn without_per_commit_a_commit_waits_under_per_rpc() {
        let mut s = session(None, vec![(QUICK, ok()), (SLOW, ok())]).await;
        s.commit(None).await.expect("inside per_rpc");
        match s.commit(None).await {
            Err(NetconfError::CommitUnanswered(inner)) if is_rpc_recv_timeout(&inner) => {}
            other => panic!("expected CommitUnanswered(Timeout {{ op: rpc-recv }}), got {other:?}"),
        }
    }
}
