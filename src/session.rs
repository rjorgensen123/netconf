// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`NetconfSession`] — the hello exchange, framing selection and generic RPC over
//! any [`NetconfTransport`]. All the protocol logic lives here, which is what makes
//! it testable through [`mock::MockTransport`](crate::mock) without a device.

use bytes::Bytes;

use crate::error::{DeviceError, NetconfError, SshMessages, TransportError};
use crate::framing::{encode, Decoder, Framing};
use crate::rpc;
use crate::transport::{ConnectOptions, NetconfTransport, ReplyBudget};
use crate::wire::{bytes_as_text, printable};

/// A NETCONF session: one per connection, no pooling.
pub struct NetconfSession<T: NetconfTransport> {
    transport: T,
    decoder: Decoder,
    encode_mode: Framing,
    capabilities: Vec<String>,
    /// The server's `<hello>`, as the device wrote it (0.5.13). It leaves the session
    /// through the policy's filter — see [`hello`](Self::hello).
    hello: String,
    /// The server's session id from its `<hello>`, when it sent one.
    session_id: Option<u64>,
    msg_id: u64,
    /// Warnings the device sent with replies that succeeded, since the last
    /// [`take_warnings`](Self::take_warnings).
    warnings: Vec<DeviceError>,
    /// The configuration policy bound to this session. `None` means none is bound,
    /// and **nothing is permitted** — every typed helper refuses, as under
    /// [`ConfigPolicy::all_deny`](crate::policy::ConfigPolicy::all_deny) (0.5.11;
    /// reads and `show` used to run under the default rules). The check happens
    /// INSIDE the library: the consumer chooses the policy, this crate enforces it,
    /// and none of the typed helpers offers a path around it.
    pub(crate) policy: Option<crate::policy::ConfigPolicy>,
    /// Whether `commit` and `commit_confirmed` carry `<synchronize/>`. Off unless
    /// the consumer turns it on with
    /// [`set_synchronize_commits`](Self::set_synchronize_commits).
    pub(crate) synchronize_commits: bool,
    /// The confirmed commit waiting for its confirming `commit`, if one was made on
    /// this session: what the device's last commit was right after it (0.5.12). The
    /// confirming `commit` checks that the device still shows it, and that the
    /// candidate is clean, before it confirms.
    pub(crate) confirmed: Option<crate::junos::ConfirmedCommit>,
}

impl<T: NetconfTransport> NetconfSession<T> {
    /// Bind the configuration policy to this session.
    ///
    /// With no policy bound the session permits nothing: every typed helper
    /// refuses, as under
    /// [`ConfigPolicy::all_deny`](crate::policy::ConfigPolicy::all_deny). Someone
    /// who deliberately wants everything binds
    /// [`ConfigPolicy::all_free`](crate::policy::ConfigPolicy::all_free)
    /// explicitly. One binding, one enforcement point, one place to maintain:
    /// the consumer decides WHAT is permitted, and this crate filters out the
    /// rest. The raw [`rpc`](Self::rpc) is the low-level layer and goes around it.
    pub fn set_policy(&mut self, policy: crate::policy::ConfigPolicy) {
        self.policy = Some(policy);
    }

    /// The policy, if it permits `action` at all — the gate every typed helper
    /// passes before anything goes on the wire (0.5.11). No policy bound, or
    /// `all_deny`, refuses everything; a policy that can change nothing —
    /// `read_only`, `all_free(Ro)`, rules without a change grant — refuses a
    /// [`Change`](Action::Change). What passes is then checked by the helper's own
    /// rule: the read gate, the command gate, the set parser.
    pub(crate) fn permit(
        &self,
        action: Action,
    ) -> Result<&crate::policy::ConfigPolicy, NetconfError> {
        let Some(policy) = self.policy.as_ref() else {
            return Err(no_policy_bound());
        };
        if policy.is_all_deny() {
            return Err(NetconfError::Policy(
                "all-deny: nothing is permitted — the policy bound to this session denies \
                 every read, command and change"
                    .into(),
            ));
        }
        if action == Action::Change && !policy.permits_any_change() {
            return Err(NetconfError::Policy(
                "the policy bound to this session permits no change — no load, no \
                 commit, no rollback; it has no change grant, or is read_only or \
                 all_free(Ro)"
                    .into(),
            ));
        }
        Ok(policy)
    }

    /// Send every commit with `<synchronize/>`: the Junos `commit synchronize`,
    /// which commits on both Routing Engines of a device that has two (0.5.7).
    ///
    /// Off by default, and the consumer's choice. A dual-RE device configured with
    /// `system commit synchronize` synchronizes every commit by itself, which is
    /// the recommended setup, and needs nothing from the session. When this is on,
    /// [`commit`](Self::commit) and [`commit_confirmed`](Self::commit_confirmed)
    /// carry it — and so does [`confirm_commit`](Self::confirm_commit), which
    /// commits through `commit`. [`commit_check`](Self::commit_check) commits
    /// nothing and is sent as before.
    pub fn set_synchronize_commits(&mut self, on: bool) {
        self.synchronize_commits = on;
    }

    /// The session id the device gave us in its `<hello>`.
    ///
    /// RFC 6241 §8.1 makes it mandatory in the server's hello. It is how a client
    /// names its own session — to `<kill-session>` it later, or to put it in a log
    /// line beside the device's own. It used to be parsed past and dropped, so a
    /// consumer could not obtain it at all. `None` if the device did not send one.
    pub fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    /// The device's `<hello>`, whole, as it sent it — with its secrets redacted
    /// unless the policy lets them through, as a reply is (0.5.13).
    ///
    /// The session reads the capabilities and the session id out of it, and the
    /// rest was dropped: Junos writes the login's user and class in comments there,
    /// and a session id that is not a number read as no session id at all.
    pub fn hello(&self) -> String {
        self.redacted(self.hello.clone())
    }

    /// Every warning the device has sent since the last call, in the order it sent
    /// them; the list is emptied (0.5.7).
    ///
    /// A warning is an `<rpc-error>` with `error-severity` `warning`: the operation
    /// was carried out, and the device has something to say about it — a commit
    /// warning, a statement with no effect. A call that returns `Ok` may have brought
    /// some, and this is where they are. A reply a call returns holds its own
    /// warnings as well. The others are only here: those of `compare`, which returns
    /// the diff and not the reply, and those of the requests a call makes inside it
    /// — the commit history read by `commit` and `commit_confirmed`, the compare read
    /// by `commit`, `prepare_change` and `confirm_commit`. Warnings that come in the
    /// same reply as an error are reported with that error, in its `also`, not here.
    /// They used to be dropped.
    pub fn take_warnings(&mut self) -> Vec<DeviceError> {
        std::mem::take(&mut self.warnings)
    }

    /// The policy bound to this session, if any.
    pub fn policy(&self) -> Option<&crate::policy::ConfigPolicy> {
        self.policy.as_ref()
    }
    /// The underlying transport, for reading.
    ///
    /// It exists so a consumer can ask the transport about things the NETCONF layer
    /// knows nothing about — above all which host key SSH actually saw
    /// (`RusshTransport::observed_host_key`). Without it the enrollment information
    /// would have to be either discarded or duplicated up through the layers.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Connect and run the hello exchange. Announces base:1.1 (chunked) as
    /// supported, and falls back to end-of-message if the peer does not.
    pub async fn connect(opts: &ConnectOptions) -> Result<Self, NetconfError> {
        // No policy is bound yet, so what the device sent is redacted (0.5.13).
        let transport = T::connect(opts).await.map_err(redact_content)?;
        Self::establish(transport, true).await
    }

    /// Run the hello exchange on a transport that is already connected.
    ///
    /// This is the entry point tests use, feeding a
    /// [`MockTransport`](crate::mock) directly. `offer_1_1` controls whether the
    /// client announces chunked framing.
    pub async fn establish(transport: T, offer_1_1: bool) -> Result<Self, NetconfError> {
        // No policy is bound yet, so what the device sent goes out of an error here
        // redacted, whatever the policy will be (0.5.13).
        Self::exchange_hellos(transport, offer_1_1)
            .await
            .map_err(redact_content)
    }

    /// The hello exchange — see [`establish`](Self::establish).
    async fn exchange_hellos(mut transport: T, offer_1_1: bool) -> Result<Self, NetconfError> {
        // Our hello is ALWAYS sent with end-of-message framing: chunked is not in
        // play until both sides have announced base:1.1.
        let hello = rpc::client_hello(offer_1_1);
        let mut decoder = Decoder::new(Framing::Eom);
        transport
            .send(&encode(Framing::Eom, hello.as_bytes()))
            .await
            .map_err(|e| with_partial(e, &decoder))?;

        // Read the peer's hello, which is always end-of-message framed.
        let peer = read_message(&mut transport, &mut decoder).await?;
        // What came instead of text goes with the error, every byte of it (0.5.13).
        let peer_xml = String::from_utf8(peer).map_err(|e| {
            NetconfError::protocol_with("hello is not valid UTF-8", bytes_as_text(e.as_bytes()))
        })?;
        let capabilities = rpc::parse_hello_capabilities(&peer_xml)?;
        let session_id = rpc::hello_session_id(&peer_xml);

        // Chunked only if BOTH sides announced 1.1.
        let both_1_1 = offer_1_1 && capabilities.iter().any(|c| c == rpc::BASE_1_1);
        let mode = if both_1_1 {
            Framing::Chunked
        } else {
            Framing::Eom
        };
        // A switch is only sound on a message boundary, with nothing buffered. Data
        // the device sent after its hello and before our first request was framed
        // end-of-message; carried into chunked mode it would be misread rather than
        // reported. The protocol gives the device no reason to send it. Whitespace is
        // the exception: a device may send it, and the chunked reader skips it.
        if mode != Framing::Eom && decoder.holds_data() {
            // The data goes with the error (0.5.13).
            return Err(NetconfError::protocol_with(
                "data arrived after the hello, before any request — refusing to switch \
                 to chunked framing with it still unread",
                bytes_as_text(decoder.buffered()),
            ));
        }
        decoder.set_mode(mode);

        Ok(NetconfSession {
            transport,
            decoder,
            encode_mode: mode,
            capabilities,
            hello: peer_xml,
            session_id,
            msg_id: 0,
            warnings: Vec::new(),
            policy: None,
            synchronize_commits: false,
            confirmed: None,
        })
    }

    /// The capabilities the peer announced.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// The framing chosen for this session — EOM or chunked.
    pub fn framing(&self) -> Framing {
        self.encode_mode
    }

    /// Send a generic RPC body and return the `<rpc-reply>` XML.
    ///
    /// An `<rpc-error>` in the reply becomes [`NetconfError::Device`]. Parsing the
    /// *content* of a successful reply is the consumer's job, not this crate's.
    ///
    /// **The reply goes out with the device's secrets redacted** (0.5.11) — each
    /// replaced by [`REDACTED`](crate::redact::REDACTED), which says what was there
    /// and how to read it — unless the session's policy lets them through:
    /// [`allow_secrets`](crate::policy::ConfigPolicy::allow_secrets), or `all_free`,
    /// which redacts nothing. This is the one place every reply passes, so it holds
    /// for the typed helpers and for this raw layer alike; the raw layer goes around
    /// the read and command gates, not around this.
    pub async fn rpc(&mut self, inner: &str) -> Result<String, NetconfError> {
        self.rpc_with_budget(inner, ReplyBudget::PerRpc).await
    }

    /// [`rpc`](Self::rpc), with the request and its reply running under `budget`.
    /// The commit helpers send through here with `PerCommit`.
    ///
    /// Every request names its budget before it is sent, rather than a commit setting
    /// one and putting it back afterwards: a commit whose future is dropped part-way
    /// cannot then leave its longer budget behind for the requests after it.
    pub(crate) async fn rpc_with_budget(
        &mut self,
        inner: &str,
        budget: ReplyBudget,
    ) -> Result<String, NetconfError> {
        let xml = self.rpc_raw(inner, budget).await?;
        Ok(self.redacted(xml))
    }

    /// A reply as the policy lets it out: the device's secrets redacted unless the
    /// policy lets them through (0.5.11). Every reply passes here before it leaves
    /// the crate; a session with no policy bound has nothing that lets them out.
    pub(crate) fn redacted(&self, xml: String) -> String {
        if self.secrets_allowed() {
            xml
        } else {
            crate::redact::redact_secrets(&xml)
        }
    }

    /// An error as the policy lets it out (0.5.13): what the device sent, carried in
    /// it, redacted as [`redacted`](Self::redacted) redacts a reply. Every error that
    /// carries the device's content passes here before it leaves the session; the
    /// parsing, the de-framer and the transport build their errors without a policy
    /// to hand.
    pub(crate) fn filtered(&self, e: NetconfError) -> NetconfError {
        if self.secrets_allowed() {
            e
        } else {
            redact_content(e)
        }
    }

    /// Whether the bound policy lets the device's secrets through.
    fn secrets_allowed(&self) -> bool {
        self.policy.as_ref().is_some_and(|p| p.secrets_allowed())
    }

    /// [`rpc_with_budget`](Self::rpc_with_budget) before the redaction: the reply as
    /// the device wrote it. For the crate's own comparisons — the drift guard, the
    /// check over a confirmed commit — which must see the device's state whole, and
    /// hand it on only through [`redacted`](Self::redacted). Nothing returned from
    /// here may leave the crate unredacted.
    ///
    /// The reply is raw; an error is not. What the device sent that it carries is
    /// redacted under the policy before it is returned (0.5.13).
    pub(crate) async fn rpc_raw(
        &mut self,
        inner: &str,
        budget: ReplyBudget,
    ) -> Result<String, NetconfError> {
        match self.exchange(inner, budget).await {
            Ok(xml) => Ok(xml),
            Err(e) => Err(self.filtered(e)),
        }
    }

    /// One request and its reply — see [`rpc_raw`](Self::rpc_raw).
    async fn exchange(&mut self, inner: &str, budget: ReplyBudget) -> Result<String, NetconfError> {
        self.transport.reply_budget(budget);
        self.msg_id += 1;
        let env = rpc::wrap_rpc(self.msg_id, inner);
        if let Err(e) = self
            .transport
            .send(&encode(self.encode_mode, env.as_bytes()))
            .await
        {
            return Err(with_partial(e, &self.decoder));
        }
        let reply = read_message(&mut self.transport, &mut self.decoder).await?;
        self.take_reply(reply)
    }

    /// A reply as the session reads every one: text, the answer to the request just
    /// sent, and an `<rpc-reply>` — its errors failing the call, its warnings kept
    /// for `take_warnings`. The reply as the device wrote it, when it is a success.
    fn take_reply(&mut self, reply: Vec<u8>) -> Result<String, NetconfError> {
        // What came instead of text goes with the error, every byte of it (0.5.13).
        let xml = String::from_utf8(reply).map_err(|e| {
            NetconfError::protocol_with("rpc-reply is not valid UTF-8", bytes_as_text(e.as_bytes()))
        })?;

        // The reply must be the answer to THIS request.
        //
        // `message-id` was sent and then never looked at, so anything arriving on
        // the channel was accepted as the answer — a late reply to an earlier RPC,
        // or a notification. The caller would then read one operation's result as
        // another's, which in a compare-then-commit sequence means approving one
        // diff and committing against a different one.
        //
        // A missing `message-id` is tolerated: Junos omits it on some replies, and
        // refusing those would break ordinary use for no gain. What is refused is a
        // `message-id` that is present and is not, byte for byte, the one this
        // request was sent with. RFC 6241 §4.1 has the device echo the attribute as
        // sent, and this crate writes it, so there is nothing to parse (0.5.11): the
        // text either is the request's or it is not. It used to be read as a number
        // and compared as one, which took `007`, `+7` and `" 7 "` for 7 — and
        // before that a malformed one was read as missing, and so let through
        // without the one check that ties a reply to a request.
        //
        // The reply goes with the error, not only its id (0.5.13): what it answers
        // is in the reply.
        if let Some(raw) = rpc::reply_message_id_raw(&xml) {
            if raw != self.msg_id.to_string() {
                return Err(NetconfError::protocol_with(
                    format!(
                        "reply message-id `{}` does not match the request's ({}) — this is \
                         an answer to something else, or the device did not echo the id as \
                         it was sent",
                        // The device's id, filtered as the reply is (0.5.13).
                        printable(&self.redacted(raw.clone())),
                        self.msg_id
                    ),
                    xml,
                ));
            }
        }

        // Every `<rpc-error>` is reported. An error fails the call and carries the
        // rest of the reply's with it; warnings alone do not fail it, and are kept
        // for `take_warnings`. What the device wrote in them goes through the
        // policy's filter before it is made printable.
        let filter = |text: &str| self.redacted(text.to_string());
        let read = rpc::read_rpc_reply(&xml, &filter)?.finish(|text| self.redacted(text));
        let warnings = rpc::split_reply_errors(read)?;
        self.warnings.extend(warnings);
        Ok(xml)
    }

    /// `<close-session/>`, then close the transport. Returns the [`SessionEnd`]
    /// (0.5.13): every warning the session holds — those of the replies before it
    /// that [`take_warnings`](Self::take_warnings) has not handed over, and those of
    /// the device's reply to `<close-session/>`, since nothing could take them after
    /// — and what the device said over SSH, which the transport returns as it
    /// closes.
    ///
    /// What goes wrong is reported as it is for any request: a send that fails, a
    /// reply that does not come in time or is left incomplete, a reply that cannot
    /// be read or is not the answer to this request, and an `<rpc-error>`, which is
    /// the device refusing. A device that ends the session without replying has
    /// ended it — unless it left a message incomplete, or said something over SSH as
    /// it ended (an exit status or signal, a disconnect message); then that is the
    /// answer, and it is reported. The transport is closed either way. Every
    /// failure is [`CloseFailed`](NetconfError::CloseFailed), carrying the error
    /// and the `SessionEnd`, so the warnings reach the caller then too; when the
    /// close-session and the closing of the transport both fail, the error is
    /// `CleanupFailed` with the step `"close"`.
    pub async fn close(mut self) -> Result<SessionEnd, NetconfError> {
        let answered = match self.close_session().await {
            Ok(()) => Ok(()),
            Err(e) => Err(self.filtered(e)),
        };
        let allowed = self.secrets_allowed();
        let filter = |e: NetconfError| if allowed { e } else { redact_content(e) };
        let mut end = SessionEnd {
            warnings: std::mem::take(&mut self.warnings),
            ssh: SshMessages::default(),
        };
        let closed = match self.transport.close().await {
            Ok(ssh) => {
                end.ssh = if allowed { ssh } else { redact_ssh(ssh) };
                Ok(())
            }
            Err(e) => Err(filter(e)),
        };
        let error = match (answered, closed) {
            (Ok(()), Ok(())) => return Ok(end),
            (Ok(()), Err(e)) | (Err(e), Ok(())) => e,
            (Err(e), Err(c)) => NetconfError::CleanupFailed {
                error: Box::new(e),
                cleanup: vec![("close", c)],
            },
        };
        Err(NetconfError::CloseFailed {
            error: Box::new(error),
            end: Box::new(end),
        })
    }

    /// Send `<close-session/>` and read the device's answer — see
    /// [`close`](Self::close).
    async fn close_session(&mut self) -> Result<(), NetconfError> {
        // `close-session` is an ordinary request, whatever was sent before it.
        self.transport.reply_budget(ReplyBudget::PerRpc);
        self.msg_id += 1;
        let env = rpc::wrap_rpc(self.msg_id, "<close-session/>");
        if let Err(e) = self
            .transport
            .send(&encode(self.encode_mode, env.as_bytes()))
            .await
        {
            return Err(with_partial(e, &self.decoder));
        }
        // RFC 6241 §4.4: wait for the device's reply before tearing the transport
        // down. Closing immediately is an abrupt disconnect from the device's point
        // of view, and it loses whatever the device had to say about the session.
        // The wait is bounded by the transport's own read budget.
        //
        // A device that simply closes instead of replying has still ended the
        // session, and that is not a failure — unless it left a message
        // incomplete. Everything else is read as any reply is (0.5.13; the send,
        // the wait and the reply used to be ignored).
        //
        // It has not ended it cleanly when it said something over SSH as it ended:
        // an exit status or signal, or a disconnect message, is the answer then, and
        // goes to the caller (0.5.13). The login banner was said at the login, not
        // at the end, and does not count.
        let reply = match read_message(&mut self.transport, &mut self.decoder).await {
            Ok(reply) => reply,
            Err(NetconfError::Transport(TransportError::Closed { partial, ssh, .. }))
                if partial.is_empty()
                    && ssh.exit_status.is_none()
                    && ssh.exit_signal.is_none()
                    && ssh.disconnect.is_none() =>
            {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        self.take_reply(reply).map(|_| ())
    }
}

/// What a session hands over as it ends — see [`NetconfSession::close`] (0.5.13).
#[derive(Debug, Clone, Default)]
pub struct SessionEnd {
    /// Every warning the session held: those of earlier replies that
    /// [`take_warnings`](NetconfSession::take_warnings) had not handed over, then
    /// those of the reply to `<close-session/>`, in the device's order. When that
    /// reply holds an error — the device refusing to close — its warnings are with
    /// that error, in the `also` of the `Device` error in
    /// [`CloseFailed`](NetconfError::CloseFailed), as for any reply, and not here.
    pub warnings: Vec<DeviceError>,
    /// What the device said over SSH, as the transport returned it when it closed —
    /// the login banner, the subsystem's exit status or signal, a disconnect
    /// message — with the device's secrets redacted unless the policy lets them
    /// through. Empty for a transport that is not SSH, and when closing the
    /// transport failed: then it is in that error.
    pub ssh: SshMessages,
}

/// What a typed helper is about to do, for [`NetconfSession::permit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// A read, or a step of the change flow that changes nothing on the device:
    /// lock, unlock, discard, commit check, compare.
    Read,
    /// A step that changes the device or its candidate: load, commit, commit
    /// confirmed, rollback to a previous configuration.
    Change,
}

/// The refusal for a session with no policy bound.
pub(crate) fn no_policy_bound() -> NetconfError {
    NetconfError::Policy(
        "no policy bound to the session — nothing is permitted, as under \
         ConfigPolicy::all_deny(). Bind one with set_policy(); use \
         ConfigPolicy::all_free(Rwd) if you deliberately want everything allowed"
            .into(),
    )
}

/// Read one complete message: pump the transport until the de-framer yields one.
///
/// When the transport ends before a message is complete, or runs out of time, the
/// incomplete message goes with the error (0.5.13).
async fn read_message<T: NetconfTransport>(
    transport: &mut T,
    decoder: &mut Decoder,
) -> Result<Vec<u8>, NetconfError> {
    loop {
        if let Some(msg) = decoder.next_message()? {
            return Ok(msg);
        }
        let chunk: Bytes = match transport.recv().await {
            Ok(chunk) => chunk,
            Err(e) => return Err(with_partial(e, decoder)),
        };
        if chunk.is_empty() {
            return Err(NetconfError::Transport(TransportError::Closed {
                detail: "peer closed before a complete message".into(),
                partial: bytes_as_text(decoder.buffered()),
                ssh: Box::default(),
            }));
        }
        decoder.push(&chunk);
    }
}

/// `e`, with the incomplete message in `decoder` put in it, when `e` is a timeout or
/// an ended connection — the errors that can cut a message off. Every other error
/// is returned as it is.
fn with_partial(e: NetconfError, decoder: &Decoder) -> NetconfError {
    let held = || bytes_as_text(decoder.buffered());
    match e {
        NetconfError::Timeout { op, .. } => NetconfError::Timeout {
            op,
            partial: held(),
        },
        NetconfError::Transport(TransportError::Closed { detail, ssh, .. }) => {
            NetconfError::Transport(TransportError::Closed {
                detail,
                partial: held(),
                ssh,
            })
        }
        other => other,
    }
}

/// `e` with what the device sent, carried in it, redacted by
/// [`redact_secrets`](crate::redact::redact_secrets) — the filter a reply passes
/// (0.5.13). Every field 0.5.13 put in an error for the device's content passes it,
/// and the text of an `Io` error, nested errors included; nothing else in the error
/// is touched.
pub(crate) fn redact_content(e: NetconfError) -> NetconfError {
    use crate::redact::redact_secrets as redact;
    match e {
        NetconfError::Protocol { detail, received } => NetconfError::Protocol {
            detail,
            received: received.map(|r| redact(&r)),
        },
        NetconfError::Timeout { op, partial } => NetconfError::Timeout {
            op,
            partial: redact(&partial),
        },
        NetconfError::Drift { fresh } => NetconfError::Drift {
            fresh: redact(&fresh),
        },
        // The commit entries are filtered where they are built, before they are
        // made printable; the diff is the device's text as it wrote it.
        NetconfError::ChangedSinceConfirmed(mut c) => {
            c.diff = c.diff.map(|d| redact(&d));
            c.diff_error = c.diff_error.map(|e| Box::new(redact_content(*e)));
            NetconfError::ChangedSinceConfirmed(c)
        }
        NetconfError::Transport(TransportError::Closed {
            detail,
            partial,
            ssh,
        }) => NetconfError::Transport(TransportError::Closed {
            detail,
            partial: redact(&partial),
            ssh: Box::new(redact_ssh(*ssh)),
        }),
        // A transport other than russh's hands on its text as it got it, and that
        // can be what the device said.
        NetconfError::Transport(TransportError::Io(text)) => {
            NetconfError::Transport(TransportError::Io(redact(&text)))
        }
        NetconfError::Transport(TransportError::SubsystemUnavailable { stderr, ssh }) => {
            NetconfError::Transport(TransportError::SubsystemUnavailable {
                stderr,
                ssh: Box::new(redact_ssh(*ssh)),
            })
        }
        NetconfError::CommittedThenFailed { reply, error } => NetconfError::CommittedThenFailed {
            reply: redact(&reply),
            error: Box::new(redact_content(*error)),
        },
        NetconfError::CommitUnanswered(inner) => {
            NetconfError::CommitUnanswered(Box::new(redact_content(*inner)))
        }
        NetconfError::WithReplies { replies, error } => NetconfError::WithReplies {
            replies: replies
                .into_iter()
                .map(|(step, reply)| (step, redact(&reply)))
                .collect(),
            error: Box::new(redact_content(*error)),
        },
        NetconfError::CloseFailed { error, mut end } => {
            end.ssh = redact_ssh(end.ssh);
            NetconfError::CloseFailed {
                error: Box::new(redact_content(*error)),
                end,
            }
        }
        NetconfError::CleanupFailed { error, cleanup } => NetconfError::CleanupFailed {
            error: Box::new(redact_content(*error)),
            cleanup: cleanup
                .into_iter()
                .map(|(step, e)| (step, redact_content(e)))
                .collect(),
        },
        other => other,
    }
}

/// [`redact_content`] for what the device said over SSH.
fn redact_ssh(mut ssh: SshMessages) -> SshMessages {
    use crate::redact::redact_secrets as redact;
    ssh.banner = ssh.banner.map(|b| redact(&b));
    if let Some(s) = ssh.exit_signal.as_mut() {
        s.message = redact(&s.message);
    }
    if let Some(d) = ssh.disconnect.as_mut() {
        d.description = redact(&d.description);
    }
    ssh
}
