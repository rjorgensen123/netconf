// SPDX-License-Identifier: MIT OR Apache-2.0
//! Locks down the legacy classification of SSH algorithms.
//!
//! Old algorithms are not forbidden — the span of Junos releases we target needs
//! some of them. They are made *visible* instead, by being marked `legacy`, so a
//! consumer can log when one is in use. These tests keep that list from drifting
//! quietly.

use netconf::{LEGACY_ALGORITHMS, is_legacy};

#[test]
fn legacy_algorithms_are_classified() {
    // Everything outside today's recommendation that an old device may still need.
    for algo in [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "ssh-rsa",
        "ssh-dss",
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "hmac-sha1",
        "hmac-sha1-etm@openssh.com",
    ] {
        assert!(is_legacy(algo), "{algo} must be classified as legacy");
    }
}

#[test]
fn modern_algorithms_are_not_legacy() {
    // Today's recommended algorithms must NEVER be marked legacy, or the log drowns
    // in false flags.
    for algo in [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group18-sha512",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "ssh-ed25519",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes256-ctr",
        "hmac-sha2-256",
        "hmac-sha2-512-etm@openssh.com",
    ] {
        assert!(!is_legacy(algo), "{algo} must NOT be legacy");
    }
}

#[test]
fn unknown_algorithm_is_not_legacy() {
    // `is_legacy` answers «is this a known-weak algorithm», not «is it unknown».
    // Fail-closed decisions belong in ConfigPolicy, not here.
    assert!(!is_legacy("something-we-have-never-seen"));
    assert!(!is_legacy(""));
}

#[test]
fn legacy_list_is_not_empty_and_has_no_duplicates() {
    assert!(!LEGACY_ALGORITHMS.is_empty());
    let mut sorted = LEGACY_ALGORITHMS.to_vec();
    sorted.sort_unstable();
    let count_before = sorted.len();
    sorted.dedup();
    assert_eq!(
        count_before,
        sorted.len(),
        "duplicates in LEGACY_ALGORITHMS"
    );
}

/// `SshPolicy::Custom` must **refuse**, not quietly do something else.
///
/// This arm used to return the legacy lists, so a consumer who chose `Custom`
/// in order to *tighten* things got `3des-cbc`, `ssh-rsa` and
/// `diffie-hellman-group1-sha1` switched on instead — fail-open, in a crate
/// whose floor is fail-closed. Refusing is the honest answer until the arm can
/// deliver what the API promises.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn custom_policy_is_denied_instead_of_yielding_legacy() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{Auth, ConnectOptions, NetconfTransport, SshPolicy, Timeouts};

    let opts = ConnectOptions {
        host: "127.0.0.1".into(),
        port: 1,
        username: "x".into(),
        auth: Auth::Password(krypto::SecretString::from_string("test-password".into()).unwrap()),
        ssh_policy: SshPolicy::Custom {
            kex: vec!["curve25519-sha256".into()],
            hostkey: vec!["ssh-ed25519".into()],
            cipher: vec!["aes256-gcm@openssh.com".into()],
            mac: vec!["hmac-sha2-256-etm@openssh.com".into()],
        },
        timeouts: Timeouts::default(),
        platform_hint: None,
        host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
    };
    let m = match RusshTransport::connect(&opts).await {
        Ok(_) => panic!("Custom should have been refused"),
        Err(e) => e.to_string(),
    };
    assert!(
        m.contains("Custom"),
        "the message does not say what is wrong: {m}"
    );
    assert!(m.contains("not implemented"), "{m}");
}

/// Blind trust-on-first-use is closed: `connect()` authenticates, which means it
/// sends the password, so it must require a pinned host key. Observation has its
/// own path.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_without_pinned_hostkey_is_denied() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{Auth, ConnectOptions, NetconfTransport, SshPolicy, Timeouts};

    let opts = ConnectOptions {
        host: "127.0.0.1".into(),
        port: 1,
        username: "x".into(),
        auth: Auth::Password(krypto::SecretString::from_string("test-password".into()).unwrap()),
        ssh_policy: SshPolicy::Modern,
        timeouts: Timeouts::default(),
        platform_hint: None,
        host_key: None,
    };
    let m = match RusshTransport::connect(&opts).await {
        Ok(_) => panic!("trust-on-first-use should have been refused"),
        Err(e) => e.to_string(),
    };
    assert!(m.contains("no pinned host key"), "{m}");
    // The message must point at the way forward, or the operator is stuck.
    assert!(
        m.contains("observe_host_key"),
        "the message offers no way forward: {m}"
    );
}

/// `observe_host_key` refuses what `connect()` refuses, for what it uses, before
/// anything goes on the wire. `Custom` used to fall back to russh's default list
/// without saying so, and a zero `connect` timeout failed as though the device had
/// not answered.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn observe_host_key_refuses_what_connect_refuses() {
    use netconf::russh_transport::observe_host_key;
    use netconf::{SshPolicy, Timeouts};

    let custom = SshPolicy::Custom {
        kex: vec!["curve25519-sha256".into()],
        hostkey: vec!["ssh-ed25519".into()],
        cipher: vec!["aes256-gcm@openssh.com".into()],
        mac: vec!["hmac-sha2-256-etm@openssh.com".into()],
    };
    let m = match observe_host_key("127.0.0.1", 1, &custom, &Timeouts::default()).await {
        Ok(fp) => panic!("Custom should have been refused, got {fp}"),
        Err(e) => e.to_string(),
    };
    assert!(m.contains("Custom"), "{m}");
    assert!(m.contains("not implemented"), "{m}");

    let zero_connect = Timeouts {
        connect: Duration::ZERO,
        ..Timeouts::default()
    };
    let m = match observe_host_key("127.0.0.1", 1, &SshPolicy::Modern, &zero_connect).await {
        Ok(fp) => panic!("a zero connect timeout should have been refused, got {fp}"),
        Err(e) => e.to_string(),
    };
    assert!(m.contains("Timeouts::connect"), "{m}");
}

/// **`connect()` refuses a host or username that cannot be right, first.** The
/// check exists as `check_target`, and it only protects anything if the entry point
/// calls it before the values reach a log line. Each case would otherwise be refused
/// for the missing pin — so the reason in the message shows which check spoke, and
/// nothing goes on the wire either way.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_refuses_a_bad_host_or_username_before_anything_else() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{Auth, ConnectOptions, NetconfTransport, SshPolicy, Timeouts};

    for (host, username, problem) in [
        ("", "ops", "host is empty"),
        (
            "pe1\nx",
            "ops",
            "host contains whitespace or a control character",
        ),
        (
            "pe 1",
            "ops",
            "host contains whitespace or a control character",
        ),
        ("127.0.0.1", "", "username is empty"),
        (
            "127.0.0.1",
            "ops\r\nx",
            "username contains a control character",
        ),
    ] {
        let opts = ConnectOptions {
            host: host.into(),
            port: 1,
            username: username.into(),
            auth: Auth::Password(
                krypto::SecretString::from_string("test-password".into()).unwrap(),
            ),
            ssh_policy: SshPolicy::Modern,
            timeouts: Timeouts::default(),
            platform_hint: None,
            host_key: None,
        };
        let m = match RusshTransport::connect(&opts).await {
            Ok(_) => panic!("{host:?} / {username:?} was let through"),
            Err(e) => e.to_string(),
        };
        assert!(
            m.contains(problem) && m.contains("refused before anything is sent"),
            "{host:?} / {username:?}: {m}"
        );
    }
}

/// **`observe_host_key()` refuses a host that cannot be right, first** — before the
/// probe's own log event, and before its other refusals: the `Custom` policy here
/// would otherwise be what refuses it.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn observe_host_key_refuses_a_bad_host_before_anything_else() {
    use netconf::russh_transport::observe_host_key;
    use netconf::{SshPolicy, Timeouts};

    let custom = SshPolicy::Custom {
        kex: vec!["curve25519-sha256".into()],
        hostkey: vec!["ssh-ed25519".into()],
        cipher: vec!["aes256-gcm@openssh.com".into()],
        mac: vec!["hmac-sha2-256-etm@openssh.com".into()],
    };
    for (host, problem) in [
        ("", "host is empty"),
        ("pe1\nx", "host contains whitespace or a control character"),
    ] {
        let m = match observe_host_key(host, 1, &custom, &Timeouts::default()).await {
            Ok(fp) => panic!("{host:?} was let through, got {fp}"),
            Err(e) => e.to_string(),
        };
        assert!(
            m.contains(problem) && m.contains("refused before anything is sent"),
            "{host:?}: {m}"
        );
    }
}

// --- Timeouts (0.5.1: the session-TTL frame) ---

use std::time::Duration;

#[test]
fn timeouts_default_is_five_minutes_and_valid() {
    let t = netconf::Timeouts::default();
    assert_eq!(t.total, Duration::from_secs(300));
    assert_eq!(t.max_total, Duration::from_secs(300));
    assert_eq!(t.per_commit, None, "commits run under per_rpc by default");
    t.validate().expect("the default must always be valid");
}

#[test]
fn ceiling_outside_the_frame_is_rejected_not_clamped() {
    let with_ceiling = |secs| netconf::Timeouts {
        total: Duration::from_secs(30),
        max_total: Duration::from_secs(secs),
        ..Default::default()
    };
    assert!(
        with_ceiling(59).validate().is_err(),
        "a ceiling below 1 min must be rejected"
    );
    assert!(
        with_ceiling(601).validate().is_err(),
        "a ceiling above 10 min must be rejected"
    );
    with_ceiling(60)
        .validate()
        .expect("1 min ceiling is inside the frame");
    with_ceiling(600)
        .validate()
        .expect("10 min ceiling is inside the frame");
}

#[test]
fn session_ttl_must_fit_within_the_ceiling_and_small_tasks_are_allowed() {
    let t = |ttl, ceiling| netconf::Timeouts {
        total: Duration::from_secs(ttl),
        max_total: Duration::from_secs(ceiling),
        ..Default::default()
    };
    // Small jobs: short TTLs are allowed, well under the cap.
    t(30, 300)
        .validate()
        .expect("a 30s TTL for a small task is fine");
    t(1, 60).validate().expect("1s is the floor");
    // A TTL above the ceiling is refused: the ceiling is absolute.
    assert!(t(301, 300).validate().is_err(), "TTL above the ceiling");
    assert!(t(0, 300).validate().is_err(), "a zero TTL is meaningless");
    // The consumer's case: the ceiling raised to 10 minutes when netconf was
    // adopted, and a 9-minute TTL for the sequence.
    t(540, 600)
        .validate()
        .expect("raised ceiling admits longer TTLs");
}

/// **All four limits are validated, not two.**
///
/// `connect` and `per_rpc` were never checked. A zero in either is not a strict
/// setting but a session that can never do anything: every read times out before
/// it starts, or the connection is impossible — and both fail in a way that looks
/// like the device is at fault.
#[test]
fn the_smaller_timeouts_are_validated_too() {
    use netconf::Timeouts;
    use std::time::Duration;

    let base = Timeouts::default();
    base.validate().expect("the default must be valid");

    let zero_connect = Timeouts {
        connect: Duration::ZERO,
        ..base
    };
    let e = zero_connect
        .validate()
        .expect_err("zero connect must be refused");
    assert!(e.contains("connect"), "{e}");

    let zero_rpc = Timeouts {
        per_rpc: Duration::ZERO,
        ..base
    };
    let e = zero_rpc
        .validate()
        .expect_err("zero per_rpc must be refused");
    assert!(e.contains("per_rpc"), "{e}");

    // A per-read limit larger than the session it lives in is fine and stays fine:
    // a short task keeps the default, and the read budget waits for the smaller of
    // the two. Refusing it would reject the ordinary case.
    let short_task = Timeouts {
        total: Duration::from_secs(5),
        ..base
    };
    short_task
        .validate()
        .expect("a small task with the default per_rpc must be valid");
}

/// **`per_commit` is held to the session's frame** (0.5.7): at least one second,
/// at most the ceiling — refused, not clamped. `None` is valid and means `per_rpc`.
#[test]
fn per_commit_outside_its_frame_is_refused() {
    use netconf::Timeouts;
    use std::time::Duration;

    let with = |per_commit| Timeouts {
        per_commit,
        ..Timeouts::default()
    };
    for bad in [
        Duration::ZERO,
        Duration::from_millis(999),
        Duration::from_secs(301),
    ] {
        let e = with(Some(bad))
            .validate()
            .expect_err("a per_commit outside 1s..=max_total must be refused");
        assert!(e.contains("Timeouts::per_commit"), "{e}");
    }
    with(None).validate().expect("None means per_rpc");
    with(Some(Duration::from_secs(1)))
        .validate()
        .expect("1s is the floor");
    with(Some(Duration::from_secs(300)))
        .validate()
        .expect("max_total is the top");
    // Like `per_rpc`, it need not fit inside this session's TTL: the wait is
    // bounded by what is left of the session anyway.
    Timeouts {
        total: Duration::from_secs(30),
        per_commit: Some(Duration::from_secs(240)),
        ..Timeouts::default()
    }
    .validate()
    .expect("per_commit above total but within max_total is valid");
}

/// ... and it is refused by `connect()`, before anything goes on the wire.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_refuses_a_per_commit_outside_its_frame() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{Auth, ConnectOptions, NetconfTransport, SshPolicy, Timeouts};

    for bad in [Duration::ZERO, Duration::from_secs(301)] {
        let opts = ConnectOptions {
            host: "127.0.0.1".into(),
            port: 1,
            username: "x".into(),
            auth: Auth::Password(
                krypto::SecretString::from_string("test-password".into()).unwrap(),
            ),
            ssh_policy: SshPolicy::Modern,
            timeouts: Timeouts {
                per_commit: Some(bad),
                ..Timeouts::default()
            },
            platform_hint: None,
            host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
        };
        let m = match RusshTransport::connect(&opts).await {
            Ok(_) => panic!("per_commit {bad:?} should have been refused"),
            Err(e) => e.to_string(),
        };
        assert!(m.contains("Timeouts::per_commit"), "{bad:?}: {m}");
    }
}

// --- A refusal before connecting: its own error kind, and one log line (0.7.0) ---

/// A pin of the right form that is no device's key.
#[cfg(feature = "russh-transport")]
const NO_DEVICES_PIN: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// What a pin of another form is refused with.
#[cfg(feature = "russh-transport")]
const NOT_A_FINGERPRINT: &str = "the pinned host key is not a fingerprint — it is SHA256: \
                                 followed by 43 base64 characters, the form \
                                 observe_host_key() returns. Refused before anything is sent.";

/// Options that pass every check before connecting; each test changes the one it
/// is about.
#[cfg(feature = "russh-transport")]
fn options() -> netconf::ConnectOptions {
    netconf::ConnectOptions {
        host: "127.0.0.1".into(),
        port: 1,
        username: "ops".into(),
        auth: netconf::Auth::Password(
            krypto::SecretString::from_string("test-password".into()).unwrap(),
        ),
        ssh_policy: netconf::SshPolicy::Modern,
        timeouts: netconf::Timeouts::default(),
        platform_hint: None,
        host_key: Some(NO_DEVICES_PIN.into()),
    }
}

/// A `SshPolicy::Custom`, which is refused.
#[cfg(feature = "russh-transport")]
fn custom() -> netconf::SshPolicy {
    netconf::SshPolicy::Custom {
        kex: vec!["curve25519-sha256".into()],
        hostkey: vec!["ssh-ed25519".into()],
        cipher: vec!["aes256-gcm@openssh.com".into()],
        mac: vec!["hmac-sha2-256-etm@openssh.com".into()],
    }
}

/// The text of the `InvalidOptions` that `result` must be.
#[cfg(feature = "russh-transport")]
fn invalid_options<T>(result: Result<T, netconf::NetconfError>) -> String {
    use netconf::{NetconfError, TransportError};
    match result {
        Err(NetconfError::Transport(TransportError::InvalidOptions(text))) => text,
        Err(e) => panic!("expected InvalidOptions, got {e}"),
        Ok(_) => panic!("expected InvalidOptions, got Ok"),
    }
}

/// A host or username that cannot be right is `InvalidOptions` from `connect()`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_refuses_a_bad_host_or_username_as_invalid_options() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    for (host, username) in [
        ("", "ops"),
        ("pe1\nx", "ops"),
        ("pe 1", "ops"),
        ("127.0.0.1", ""),
        ("127.0.0.1", "ops\r\nx"),
    ] {
        let opts = ConnectOptions {
            host: host.into(),
            username: username.into(),
            ..options()
        };
        let text = invalid_options(RusshTransport::connect(&opts).await);
        assert!(
            text.ends_with("— refused before anything is sent"),
            "{host:?} / {username:?}: {text}"
        );
    }
}

/// No pinned host key is `InvalidOptions` from `connect()`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_refuses_a_missing_pin_as_invalid_options() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    let opts = ConnectOptions {
        host_key: None,
        ..options()
    };
    let text = invalid_options(RusshTransport::connect(&opts).await);
    assert!(text.starts_with("no pinned host key"), "{text}");
}

/// `SshPolicy::Custom` is `InvalidOptions` from `connect()`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_refuses_custom_as_invalid_options() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    let opts = ConnectOptions {
        ssh_policy: custom(),
        ..options()
    };
    let text = invalid_options(RusshTransport::connect(&opts).await);
    assert!(
        text.starts_with("SshPolicy::Custom is not implemented"),
        "{text}"
    );
}

/// `Timeouts` outside their frames are `InvalidOptions` from `connect()`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_refuses_timeouts_outside_their_frames_as_invalid_options() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport, Timeouts};

    let opts = ConnectOptions {
        timeouts: Timeouts {
            connect: Duration::ZERO,
            ..Timeouts::default()
        },
        ..options()
    };
    let text = invalid_options(RusshTransport::connect(&opts).await);
    assert!(text.starts_with("Timeouts::connect"), "{text}");
}

/// What `observe_host_key()` refuses before connecting is `InvalidOptions`: a bad
/// host, `SshPolicy::Custom`, and `Timeouts` outside their frames.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn observe_host_key_refuses_as_invalid_options() {
    use netconf::russh_transport::observe_host_key;
    use netconf::{SshPolicy, Timeouts};

    let bad_host = observe_host_key("pe1\nx", 1, &SshPolicy::Modern, &Timeouts::default()).await;
    let text = invalid_options(bad_host);
    assert!(text.starts_with("host contains whitespace"), "{text}");

    let text =
        invalid_options(observe_host_key("127.0.0.1", 1, &custom(), &Timeouts::default()).await);
    assert!(
        text.starts_with("SshPolicy::Custom is not implemented"),
        "{text}"
    );

    let zero_connect = Timeouts {
        connect: Duration::ZERO,
        ..Timeouts::default()
    };
    let text =
        invalid_options(observe_host_key("127.0.0.1", 1, &SshPolicy::Modern, &zero_connect).await);
    assert!(text.starts_with("Timeouts::connect"), "{text}");
}

/// **A pin of another form is refused before connecting**, as `InvalidOptions`
/// with one fixed text that does not echo it, and nothing connects.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_pin_of_another_form_is_refused_before_connecting() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // 43 characters of the right form: the last one is among the sixteen.
    let b64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab+/cdw";
    assert_eq!(b64.len(), 43);
    for pin in [
        "abc".to_string(),
        "SHA256:".to_string(),
        "SHA256:short".to_string(),
        format!("MD5:{b64}"),
        format!("SHA256:{}", "A".repeat(42)),
        format!("SHA256:{b64}A"),
        format!("SHA256:{}={}", &b64[..21], &b64[22..]),
        format!("SHA256:{} {}", &b64[..21], &b64[22..]),
        format!("SHA256:{}B", "A".repeat(42)),
    ] {
        let opts = ConnectOptions {
            port,
            host_key: Some(pin.clone()),
            ..options()
        };
        let text = invalid_options(RusshTransport::connect(&opts).await);
        assert_eq!(text, NOT_A_FINGERPRINT, "{pin:?}");
        // `SHA256:` alone is part of the fixed text.
        if pin != "SHA256:" {
            assert!(!text.contains(&pin), "{pin:?}: {text}");
        }
    }
    let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
    assert!(accepted.is_err(), "a connection was attempted");
}

/// A well-formed pin that is no device's key is not refused for its form: against
/// a port nothing listens on, the error is not `InvalidOptions`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_well_formed_pin_is_not_refused_for_its_form() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfError, NetconfTransport, Timeouts, TransportError};

    // A port nothing listens on: bound, then let go.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let opts = ConnectOptions {
        port,
        timeouts: Timeouts {
            connect: Duration::from_secs(5),
            ..Timeouts::default()
        },
        ..options()
    };
    match RusshTransport::connect(&opts).await {
        Ok(_) => panic!("nothing listens on port {port}"),
        Err(NetconfError::Transport(TransportError::InvalidOptions(text))) => {
            panic!("a well-formed pin was refused: {text}")
        }
        Err(_) => {}
    }
}

/// `check_device` returns `Err(Transport(InvalidOptions))` for what `connect()`
/// refuses before connecting.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn check_device_returns_invalid_options_for_a_refusal_before_connecting() {
    use netconf::ConnectOptions;
    use netconf::russh_transport::check_device;

    for (host_key, starts) in [
        (None, "no pinned host key"),
        (
            Some("abc".to_string()),
            "the pinned host key is not a fingerprint",
        ),
    ] {
        let opts = ConnectOptions {
            host_key,
            ..options()
        };
        let text = invalid_options(check_device(&opts).await);
        assert!(text.starts_with(starts), "{text}");
    }
}

/// The fields of one captured event, by name, as text.
#[cfg(feature = "russh-transport")]
type Fields = std::collections::BTreeMap<String, String>;

#[cfg(feature = "russh-transport")]
thread_local! {
    /// The events this thread has emitted since `capture_events` emptied it.
    static SEEN: std::cell::RefCell<Vec<Fields>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// A subscriber that records the fields of every event in the buffer of the
/// thread that emitted it.
#[cfg(feature = "russh-transport")]
struct Capture;

#[cfg(feature = "russh-transport")]
impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Visit(Fields);
        impl tracing::field::Visit for Visit {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
        }
        let mut visit = Visit(Fields::new());
        event.record(&mut visit);
        let _ = SEEN.try_with(|seen| seen.borrow_mut().push(visit.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Install `Capture` as the global subscriber, once, and empty this thread's
/// buffer. Global, as in `tests/russh_loopback.rs`: tracing caches per callsite
/// whether anyone listens, and a subscriber for one thread races that cache.
#[cfg(feature = "russh-transport")]
fn capture_events() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::subscriber::set_global_default(Capture).expect("no other subscriber");
    });
    SEEN.with(|seen| seen.borrow_mut().clear());
}

/// The events this thread has emitted since `capture_events`.
#[cfg(feature = "russh-transport")]
fn captured() -> Vec<Fields> {
    SEEN.with(|seen| seen.take())
}

/// **A refused `connect()` is one log line**: `ssh_connect_refused` with the reason,
/// host, port and username, and no `ssh_connect`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_refused_connect_is_one_log_line() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    let opts = ConnectOptions {
        host_key: None,
        ..options()
    };
    capture_events();
    let _ = RusshTransport::connect(&opts).await;
    let events = captured();
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e["event"], "ssh_connect_refused", "{e:?}");
    for field in ["reason", "host", "port", "username"] {
        assert!(e.contains_key(field), "{field}: {e:?}");
    }
    assert!(e["reason"].starts_with("no pinned host key"), "{e:?}");
}

/// **A `connect()` refused for its host does not log the host**: the line says
/// what was wrong, not what the host held.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_connect_refused_for_its_host_does_not_log_the_host() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    let opts = ConnectOptions {
        host: "pe1\ninjected-line".into(),
        ..options()
    };
    capture_events();
    let _ = RusshTransport::connect(&opts).await;
    let events = captured();
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e["event"], "ssh_connect_refused", "{e:?}");
    assert!(e.contains_key("reason"), "{e:?}");
    assert!(!e.contains_key("host"), "{e:?}");
    assert!(!e.values().any(|v| v.contains("injected-line")), "{e:?}");
}

/// **A refused `observe_host_key()` is one log line**: `ssh_host_key_probe_refused`,
/// and no `ssh_host_key_probe`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_refused_host_key_probe_is_one_log_line() {
    use netconf::Timeouts;
    use netconf::russh_transport::observe_host_key;

    capture_events();
    let _ = observe_host_key("127.0.0.1", 1, &custom(), &Timeouts::default()).await;
    let events = captured();
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!(e["event"], "ssh_host_key_probe_refused", "{e:?}");
    for field in ["reason", "host", "port"] {
        assert!(e.contains_key(field), "{field}: {e:?}");
    }
}
