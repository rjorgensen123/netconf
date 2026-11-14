// SPDX-License-Identifier: MIT OR Apache-2.0
//! The options a connection is checked against: the legacy classification of SSH
//! algorithms, `SshPolicy` with `validate` and `without`, and `Timeouts`. With
//! `russh-transport`, also what `RusshTransport` refuses before connecting, and the
//! events it logs on the way.

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

// --- SshPolicy::Custom: the caller's own lists (0.7.0) ---

/// Every name `LegacyJunos` offers, in its order: key exchange, host key, cipher,
/// MAC. `Modern`'s are the first of each.
const LEGACY_JUNOS_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
];
const LEGACY_JUNOS_HOSTKEY: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
];
const LEGACY_JUNOS_CIPHER: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
];
const LEGACY_JUNOS_MAC: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1",
];

/// The names as owned strings, the type `Custom` holds.
fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| name.to_string()).collect()
}

/// A `Custom` policy of one ordinary name in each list.
fn one_of_each() -> netconf::SshPolicy {
    netconf::SshPolicy::Custom {
        kex: owned(&["curve25519-sha256"]),
        hostkey: owned(&["ssh-ed25519"]),
        cipher: owned(&["aes256-gcm@openssh.com"]),
        mac: owned(&["hmac-sha2-256-etm@openssh.com"]),
    }
}

/// `one_of_each` with its list of `kinds` — as the refusal texts name it — replaced
/// by `list`.
fn one_of_each_but(kinds: &str, list: &[&str]) -> netconf::SshPolicy {
    let [mut kex, mut hostkey, mut cipher, mut mac] = lists(&one_of_each());
    match kinds {
        "key exchanges" => kex = owned(list),
        "host key algorithms" => hostkey = owned(list),
        "ciphers" => cipher = owned(list),
        "MACs" => mac = owned(list),
        other => panic!("no list of {other}"),
    }
    netconf::SshPolicy::Custom {
        kex,
        hostkey,
        cipher,
        mac,
    }
}

/// The four lists of a `Custom` policy: key exchange, host key, cipher, MAC.
fn lists(policy: &netconf::SshPolicy) -> [Vec<String>; 4] {
    match policy {
        netconf::SshPolicy::Custom {
            kex,
            hostkey,
            cipher,
            mac,
        } => [kex.clone(), hostkey.clone(), cipher.clone(), mac.clone()],
        _ => panic!("expected a Custom policy"),
    }
}

/// **`validate` accepts the built-in policies, and a `Custom` of names netconf
/// offers.** A `Custom` that holds every name of `LegacyJunos` is valid.
#[test]
fn validate_accepts_the_built_in_policies_and_every_name_netconf_offers() {
    use netconf::SshPolicy;

    SshPolicy::Modern.validate().expect("Modern");
    SshPolicy::LegacyJunos.validate().expect("LegacyJunos");
    one_of_each().validate().expect("one name of each");
    SshPolicy::Custom {
        kex: owned(LEGACY_JUNOS_KEX),
        hostkey: owned(LEGACY_JUNOS_HOSTKEY),
        cipher: owned(LEGACY_JUNOS_CIPHER),
        mac: owned(LEGACY_JUNOS_MAC),
    }
    .validate()
    .expect("every name of LegacyJunos");
}

/// **`validate` refuses a `Custom` that breaks the rules, and says what broke
/// them**: an empty list, a name twice, and a name netconf does not offer in that
/// list — `none` and `clear`, `3des-cbc`, the negotiation markers, a made-up name,
/// and a known name in the wrong list.
#[test]
fn validate_refuses_a_custom_that_breaks_the_rules() {
    let not_offered = |name: &str, kinds: &str| {
        format!(
            "SshPolicy::Custom: «{name}» is not one of the {kinds} netconf offers — the \
             names are those of Modern and LegacyJunos"
        )
    };
    let empty = |kinds: &str| {
        format!(
            "SshPolicy::Custom: the list of {kinds} is empty — each list needs at least one name"
        )
    };
    for kinds in ["key exchanges", "host key algorithms", "ciphers", "MACs"] {
        assert_eq!(
            one_of_each_but(kinds, &[]).validate(),
            Err(empty(kinds)),
            "{kinds}"
        );
    }
    assert_eq!(
        one_of_each_but("ciphers", &["aes256-ctr", "aes128-ctr", "aes256-ctr"]).validate(),
        Err("SshPolicy::Custom: «aes256-ctr» is in the list of ciphers twice".to_string())
    );
    for (kinds, name) in [
        ("key exchanges", "none"),
        ("ciphers", "none"),
        ("ciphers", "clear"),
        ("MACs", "none"),
        ("ciphers", "3des-cbc"),
        ("key exchanges", "kex-strict-c-v00@openssh.com"),
        ("key exchanges", "ext-info-c"),
        ("host key algorithms", "foo@example.com"),
        ("MACs", "aes256-ctr"),
    ] {
        assert_eq!(
            one_of_each_but(kinds, &[name]).validate(),
            Err(not_offered(name, kinds)),
            "{name} among the {kinds}"
        );
    }
}

/// **The lists are checked in order, and the first fault is the one named**: key
/// exchange before host key, cipher and MAC; within a list each name in order, and
/// for one name, not offered before twice.
#[test]
fn validate_names_the_first_fault_in_order() {
    use netconf::SshPolicy;

    let faults_everywhere = SshPolicy::Custom {
        kex: owned(&["curve25519-sha256", "none"]),
        hostkey: owned(&[]),
        cipher: owned(&["clear"]),
        mac: owned(&["none"]),
    };
    assert_eq!(
        faults_everywhere.validate(),
        Err(
            "SshPolicy::Custom: «none» is not one of the key exchanges netconf offers — the \
             names are those of Modern and LegacyJunos"
                .to_string()
        )
    );
    let twice_then_unknown = one_of_each_but(
        "key exchanges",
        &["curve25519-sha256", "curve25519-sha256", "none"],
    );
    assert_eq!(
        twice_then_unknown.validate(),
        Err(
            "SshPolicy::Custom: «curve25519-sha256» is in the list of key exchanges twice"
                .to_string()
        )
    );
    let unknown_twice = one_of_each_but("MACs", &["none", "none"]);
    assert_eq!(
        unknown_twice.validate(),
        Err(
            "SshPolicy::Custom: «none» is not one of the MACs netconf offers — the names \
             are those of Modern and LegacyJunos"
                .to_string()
        )
    );
}

/// **A name in a refusal is made printable**: a control character in it cannot
/// break the line the text is logged on.
#[test]
fn a_name_in_a_refusal_is_made_printable() {
    use netconf::SshPolicy;

    let policy = one_of_each_but("host key algorithms", &["ssh-ed25519\nevent=forged"]);
    let text = policy.validate().expect_err("a name that is not offered");
    assert_eq!(
        text,
        "SshPolicy::Custom: «ssh-ed25519\\nevent=forged» is not one of the host key \
         algorithms netconf offers — the names are those of Modern and LegacyJunos"
    );
    assert!(!text.contains('\n'), "{text}");

    let text = match SshPolicy::Modern.without(&["hmac-sha1\r"]) {
        Err(text) => text,
        Ok(_) => panic!("a name in none of Modern's lists was left out"),
    };
    assert!(
        text.contains("«hmac-sha1\\r»") && !text.contains('\r'),
        "{text}"
    );
}

/// **`without` leaves names out of a policy's lists, in the same order**, and
/// the result is a `Custom` that validates.
#[test]
fn without_leaves_names_out_in_the_same_order() {
    use netconf::SshPolicy;

    let policy = SshPolicy::LegacyJunos
        .without(&["diffie-hellman-group1-sha1", "ssh-dss"])
        .expect("both are LegacyJunos names");
    assert_eq!(
        lists(&policy),
        [
            owned(&LEGACY_JUNOS_KEX[..LEGACY_JUNOS_KEX.len() - 1]),
            owned(&LEGACY_JUNOS_HOSTKEY[..LEGACY_JUNOS_HOSTKEY.len() - 1]),
            owned(LEGACY_JUNOS_CIPHER),
            owned(LEGACY_JUNOS_MAC),
        ]
    );
    policy.validate().expect("what is left validates");
}

/// **`without` refuses a name that is in none of the policy's lists**: a
/// mistyped name must not pass as left out. `ssh-dss` is not one of `Modern`'s.
#[test]
fn without_refuses_a_name_the_policy_does_not_hold() {
    use netconf::SshPolicy;

    match SshPolicy::Modern.without(&["ssh-dss"]) {
        Err(text) => assert_eq!(
            text,
            "SshPolicy::without: «ssh-dss» is in none of this policy's lists, so there is \
             nothing to leave out"
        ),
        Ok(_) => panic!("Modern holds no ssh-dss to leave out"),
    }
}

/// **`without` works on a `Custom` policy too**, and keeps the caller's order.
#[test]
fn without_works_on_a_custom_policy() {
    use netconf::SshPolicy;

    let custom = SshPolicy::Custom {
        kex: owned(&["diffie-hellman-group14-sha256", "curve25519-sha256"]),
        hostkey: owned(&["rsa-sha2-256", "ssh-rsa", "ssh-ed25519"]),
        cipher: owned(&["aes128-ctr", "chacha20-poly1305@openssh.com"]),
        mac: owned(&["hmac-sha1", "hmac-sha2-256"]),
    };
    let policy = custom
        .without(&["ssh-rsa", "hmac-sha1"])
        .expect("both are in the lists");
    assert_eq!(
        lists(&policy),
        [
            owned(&["diffie-hellman-group14-sha256", "curve25519-sha256"]),
            owned(&["rsa-sha2-256", "ssh-ed25519"]),
            owned(&["aes128-ctr", "chacha20-poly1305@openssh.com"]),
            owned(&["hmac-sha2-256"]),
        ]
    );
}

/// **A list left empty by `without` is returned, and `validate` refuses it.**
#[test]
fn a_list_left_empty_by_without_is_refused_by_validate() {
    use netconf::SshPolicy;

    let no_ciphers = SshPolicy::Modern
        .without(&[
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
        ])
        .expect("all are Modern's ciphers");
    assert!(lists(&no_ciphers)[2].is_empty());
    assert_eq!(
        no_ciphers.validate(),
        Err(
            "SshPolicy::Custom: the list of ciphers is empty — each list needs at least one name"
                .to_string()
        )
    );
}

/// **A `Custom` policy that asks for what netconf does not offer is refused, before
/// anything connects**, not negotiated with something else: `3des-cbc` among the
/// ciphers is refused with `validate`'s text, and no connection is attempted.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_custom_policy_netconf_cannot_honour_is_refused_before_connecting() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{Auth, ConnectOptions, NetconfTransport, Timeouts};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let opts = ConnectOptions {
        host: "127.0.0.1".into(),
        port,
        username: "x".into(),
        auth: Auth::Password(krypto::SecretString::from_string("test-password".into()).unwrap()),
        ssh_policy: one_of_each_but("ciphers", &["aes256-gcm@openssh.com", "3des-cbc"]),
        timeouts: Timeouts::default(),
        platform_hint: None,
        host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
    };
    let m = match RusshTransport::connect(&opts).await {
        Ok(_) => panic!("3des-cbc should have been refused"),
        Err(e) => e.to_string(),
    };
    assert_eq!(
        m,
        "transport: invalid options: SshPolicy::Custom: «3des-cbc» is not one of the ciphers \
         netconf offers — the names are those of Modern and LegacyJunos"
    );
    let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
    assert!(accepted.is_err(), "a connection was attempted");
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
/// anything goes on the wire: a `Custom` policy that breaks its rules, and a zero
/// `connect` timeout, which would fail as though the device had not answered.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn observe_host_key_refuses_what_connect_refuses() {
    use netconf::russh_transport::observe_host_key;
    use netconf::{SshPolicy, Timeouts};

    let m = match observe_host_key("127.0.0.1", 1, &custom(), &Timeouts::default()).await {
        Ok(fp) => panic!("a Custom that breaks its rules should have been refused, got {fp}"),
        Err(e) => e.to_string(),
    };
    assert_eq!(m, format!("transport: invalid options: {CUSTOM_REFUSED}"));

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
/// breaks its rules, and would otherwise be what refuses it.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn observe_host_key_refuses_a_bad_host_before_anything_else() {
    use netconf::Timeouts;
    use netconf::russh_transport::observe_host_key;

    for (host, problem) in [
        ("", "host is empty"),
        ("pe1\nx", "host contains whitespace or a control character"),
    ] {
        let m = match observe_host_key(host, 1, &custom(), &Timeouts::default()).await {
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

/// A `SshPolicy::Custom` that breaks its rules, and so is refused: `none` as its
/// cipher.
#[cfg(feature = "russh-transport")]
fn custom() -> netconf::SshPolicy {
    one_of_each_but("ciphers", &["none"])
}

/// What `custom()` is refused with.
#[cfg(feature = "russh-transport")]
const CUSTOM_REFUSED: &str = "SshPolicy::Custom: «none» is not one of the ciphers netconf \
                              offers — the names are those of Modern and LegacyJunos";

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

/// A `SshPolicy::Custom` that breaks its rules is `InvalidOptions` from
/// `connect()`, with `validate`'s text.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn connect_refuses_a_custom_that_breaks_its_rules_as_invalid_options() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    let opts = ConnectOptions {
        ssh_policy: custom(),
        ..options()
    };
    let text = invalid_options(RusshTransport::connect(&opts).await);
    assert_eq!(text, CUSTOM_REFUSED);
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
/// host, a `SshPolicy::Custom` that breaks its rules, and `Timeouts` outside their
/// frames.
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
    assert_eq!(text, CUSTOM_REFUSED);

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

/// `check_device` returns `Err(Transport(InvalidOptions))` for a `SshPolicy::Custom`
/// that breaks its rules, as `connect()` does.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn check_device_refuses_a_custom_that_breaks_its_rules() {
    use netconf::ConnectOptions;
    use netconf::russh_transport::check_device;

    let opts = ConnectOptions {
        ssh_policy: custom(),
        ..options()
    };
    assert_eq!(invalid_options(check_device(&opts).await), CUSTOM_REFUSED);
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
    assert_eq!(e["reason"], CUSTOM_REFUSED, "{e:?}");
}

/// **A `connect()` refused for its `Custom` policy is one log line**:
/// `ssh_connect_refused` with `validate`'s text as the reason, and no
/// `ssh_connect`.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_connect_refused_for_its_custom_policy_is_one_log_line() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport};

    let opts = ConnectOptions {
        ssh_policy: custom(),
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
    assert_eq!(e["reason"], CUSTOM_REFUSED, "{e:?}");
}

/// **A `Custom` connection is logged as legacy by its names** (0.7.0): with only
/// modern names its `ssh_connect` event has no `legacy` tag, and with `ssh-rsa` it
/// has `legacy = true`. Both name the policy `custom`. Nothing listens on the port,
/// so each connect fails after the event.
#[cfg(feature = "russh-transport")]
#[tokio::test]
async fn a_custom_connection_is_logged_as_legacy_by_its_names() {
    use netconf::russh_transport::RusshTransport;
    use netconf::{ConnectOptions, NetconfTransport, Timeouts};

    // A port nothing listens on: bound, then let go.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let connect_event = |hostkey: &[&str]| {
        let opts = ConnectOptions {
            port,
            ssh_policy: one_of_each_but("host key algorithms", hostkey),
            timeouts: Timeouts {
                connect: Duration::from_secs(5),
                ..Timeouts::default()
            },
            ..options()
        };
        async move {
            capture_events();
            assert!(RusshTransport::connect(&opts).await.is_err());
            captured()
                .into_iter()
                .find(|e| e.get("event").map(String::as_str) == Some("ssh_connect"))
                .expect("an ssh_connect event")
        }
    };

    let modern = connect_event(&["ssh-ed25519", "rsa-sha2-512"]).await;
    assert_eq!(modern["ssh_policy"], "custom", "{modern:?}");
    assert!(!modern.contains_key("legacy"), "{modern:?}");

    let legacy = connect_event(&["ssh-ed25519", "ssh-rsa"]).await;
    assert_eq!(legacy["ssh_policy"], "custom", "{legacy:?}");
    assert_eq!(legacy["legacy"], "true", "{legacy:?}");
}
