// SPDX-License-Identifier: MIT OR Apache-2.0
//! netconf — a narrow asynchronous NETCONF client (RFC 6241/6242) for Junos.
//!
//! The governing requirement is the whole span of Junos releases we target. The
//! NETCONF RPC set is stable across it; what is not stable is the SSH negotiation
//! and the shape of the replies. That is why framing and the error model are the
//! core of this crate rather than RPC construction.
//!
//! The crate is deliberately narrow. A YANG model layer and a multi-vendor
//! abstraction are non-goals. Device authentication is a **transient password**,
//! accepted **only** as a `krypto::SecretString` — secrets cross this boundary as
//! secret types and nothing else, so a password can never end up in ordinary heap
//! as a `String`, a `&str` or an owned `Vec<u8>`. SSH keys are not used.
//!
//! ```no_run
//! # async fn ex<T: netconf::NetconfTransport>(t: T) -> Result<(), netconf::NetconfError> {
//! let mut s = netconf::NetconfSession::establish(t, true).await?;
//! let reply = s.rpc("<get-configuration/>").await?;   // raw XML out; the caller parses it
//! s.close().await?;
//! # let _ = reply; Ok(()) }
//! ```
//!
//! # Features
//!
//! - `russh-transport` (off by default): the `russh_transport` module, the real SSH
//!   transport, over russh and tokio. Without it the crate builds without either,
//!   with the protocol layer and the in-memory transport in [`mock`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod change;
pub mod error;
pub mod framing;
pub mod junos;
pub mod mock;
pub mod policy;
pub mod redact;
pub mod rpc;
#[cfg(feature = "russh-transport")]
pub mod russh_transport;
pub mod session;
pub mod transport;
mod wire;

/// The crate version, for consumers that surface component versions.
///
/// It is also the anchor that says which filter and feature set is active: the
/// mapping from version to capabilities is in `CHANGELOG.md`, and the policy in
/// force can be inspected directly through [`ConfigPolicy::describe`]. Mirrors
/// `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use change::PreparedChange;
pub use error::{DeviceError, NetconfError, TransportError};
pub use framing::{Decoder, Framing};
pub use junos::{Format, LoadAction};
pub use policy::{Access, Change, ConfigPolicy, Match, Op, ParseError, Scope, Violation};
pub use redact::{contains_secrets, redact_secrets, Redactor, REDACTED};
pub use session::NetconfSession;
pub use transport::{
    is_legacy, Auth, ConnectOptions, NetconfTransport, Platform, SshPolicy, Timeouts,
    LEGACY_ALGORITHMS,
};
