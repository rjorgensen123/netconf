// SPDX-License-Identifier: MIT OR Apache-2.0
//! Locks down the legacy classification of SSH algorithms.
//!
//! Old algorithms are not forbidden — the span of Junos releases we target needs
//! some of them. They are made *visible* instead, by being marked `legacy`, so a
//! consumer can log when one is in use. These tests keep that list from drifting
//! quietly.

use netconf::{is_legacy, LEGACY_ALGORITHMS};

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
        host_key: Some("SHA256:whatever".into()),
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
            m.contains(problem) && m.contains("refused before anything is logged or sent"),
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
            m.contains(problem) && m.contains("refused before anything is logged or sent"),
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
            host_key: Some("SHA256:whatever".into()),
        };
        let m = match RusshTransport::connect(&opts).await {
            Ok(_) => panic!("per_commit {bad:?} should have been refused"),
            Err(e) => e.to_string(),
        };
        assert!(m.contains("Timeouts::per_commit"), "{bad:?}: {m}");
    }
}
