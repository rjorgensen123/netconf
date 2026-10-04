// SPDX-License-Identifier: MIT OR Apache-2.0
//! [`MockTransport`] — an in-memory [`NetconfTransport`] for protocol tests that
//! need no network and no device.
//!
//! The queue of incoming pieces is supplied at construction. By splitting one
//! reply into many small pieces you can verify that
//! [`Decoder`](crate::framing::Decoder) tolerates arbitrary TCP boundaries.
//! [`MockTransport::recording`] gives a shared log of the bytes sent, which can
//! be inspected *after* the transport has been moved into a
//! [`NetconfSession`](crate::session::NetconfSession).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::{NetconfError, SshMessages};
use crate::transport::{ConnectOptions, NetconfTransport};

/// Shared log of the bytes the client has sent.
pub type SentLog = Arc<Mutex<Vec<u8>>>;

/// In-memory transport. `inbound` holds the pieces handed out by
/// [`recv`](NetconfTransport::recv) in order; everything sent accumulates in `sent`.
pub struct MockTransport {
    sent: SentLog,
    inbound: VecDeque<Bytes>,
}

impl MockTransport {
    /// A new mock with a preloaded queue of incoming pieces, already framed.
    pub fn new(chunks: Vec<Vec<u8>>) -> Self {
        MockTransport {
            sent: Arc::new(Mutex::new(Vec::new())),
            inbound: chunks.into_iter().map(Bytes::from).collect(),
        }
    }

    /// A new mock plus a **shared sent log**. The cloned handle can be inspected
    /// after the transport has been moved into a session.
    pub fn recording(chunks: Vec<Vec<u8>>) -> (Self, SentLog) {
        let t = MockTransport::new(chunks);
        let log = Arc::clone(&t.sent);
        (t, log)
    }
}

#[async_trait]
impl NetconfTransport for MockTransport {
    async fn connect(_opts: &ConnectOptions) -> Result<Self, NetconfError> {
        // The mock connects to nothing; use `MockTransport::new(..)` together
        // with `NetconfSession::establish` in tests.
        Ok(MockTransport::new(Vec::new()))
    }

    async fn send(&mut self, bytes: &[u8]) -> Result<(), NetconfError> {
        self.sent
            .lock()
            .expect("sent-log mutex")
            .extend_from_slice(bytes);
        Ok(())
    }

    async fn recv(&mut self) -> Result<Bytes, NetconfError> {
        // An empty Bytes signals «the peer closed» to the session layer.
        Ok(self.inbound.pop_front().unwrap_or_default())
    }

    async fn close(self) -> Result<SshMessages, NetconfError> {
        // Nothing to close: the mock holds no resource, and is not SSH. It used to
        // set a `closed` flag that nothing ever read, kept alive by a `let _ =` that
        // existed only to silence the warning about it.
        Ok(SshMessages::default())
    }
}
