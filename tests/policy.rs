// SPDX-License-Identifier: MIT OR Apache-2.0
//! The configuration filter: ConfigPolicy as WHAT × WHERE, plus the absolute
//! floor and default-deny.

use netconf::policy::{parse_set_payload, DEFAULT_PROTECTED_ROOTS};
use netconf::{Access, Change, ConfigPolicy, Match, Op, ParseError, Scope};

fn ch(op: Op, path: &[&str]) -> Change {
    Change {
        op,
        path: path.iter().map(|s| s.to_string()).collect(),
    }
}

/// A deploy-like profile: set and delete under a unit, and under l2circuit.
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

#[test]
fn absolute_floor_denies_deleting_a_top_level_tree() {
    let p = deploy_policy();
    for root in DEFAULT_PROTECTED_ROOTS {
        let v = p.check(&[ch(Op::Delete, &[root])]).unwrap_err();
        assert!(
            v.reason.contains("absolute floor"),
            "root {root}: {}",
            v.reason
        );
    }
}

#[test]
fn delete_below_protocol_ok_but_not_the_protocol_itself() {
    let p = deploy_policy();
    // Below protocols l2circuit: permitted by the Subtree rule.
    assert!(p
        .check(&[ch(
            Op::Delete,
            &["protocols", "l2circuit", "neighbor", "10.0.0.2"]
        )])
        .is_ok());
    // The protocol node itself is refused: no Node rule, and the floor does not
    // reach a two-segment path.
    assert!(p
        .check(&[ch(Op::Delete, &["protocols", "l2circuit"])])
        .is_err());
}

#[test]
fn set_under_unit_ok() {
    let p = deploy_policy();
    assert!(p
        .check(&[ch(
            Op::Set,
            &["interfaces", "ge-0/0/1", "unit", "123", "family", "ccc"]
        )])
        .is_ok());
}

#[test]
fn unmatched_path_default_deny() {
    let p = deploy_policy();
    let v = p
        .check(&[ch(Op::Set, &["system", "host-name", "evil"])])
        .unwrap_err();
    assert!(v.reason.contains("default-deny"));
}

#[test]
fn physical_interface_delete_is_not_in_the_floor() {
    // `delete interfaces ge-0/0/1` is two segments, so the floor does NOT refuse it;
    // the rules decide. With no rule permitting it, default-deny applies — which is
    // a different refusal from the absolute floor.
    let p = deploy_policy();
    let v = p
        .check(&[ch(Op::Delete, &["interfaces", "ge-0/0/1"])])
        .unwrap_err();
    assert!(v.reason.contains("default-deny"));
    assert!(!v.reason.contains("absolute floor"));

    // A mode CAN permit it, since the floor does not block it:
    let p2 = ConfigPolicy::with_default_floor().allow("interfaces *", Match::Node, &[Op::Delete]);
    assert!(p2
        .check(&[ch(Op::Delete, &["interfaces", "ge-0/0/1"])])
        .is_ok());
}

#[test]
fn modification_is_never_floor_denied() {
    // A set on system is a modification and is not blocked categorically — it is
    // default-denied without a rule, and allowed when a mode opens it.
    let p = ConfigPolicy::with_default_floor().allow("system", Match::Subtree, &[Op::Set]);
    assert!(p
        .check(&[ch(Op::Set, &["system", "ntp", "server", "10.0.0.1"])])
        .is_ok());
}

#[test]
fn parse_set_payload_is_quote_aware() {
    let payload =
        "set interfaces ge-0/0/1 unit 123 description \"10G - Customer - CIR-13080123\"\n\
                   set protocols l2circuit neighbor 10.0.0.2 interface ge-0/0/1.123 ignore-mtu";
    let changes = parse_set_payload(payload).unwrap();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].op, Op::Set);
    // The quoted description becomes ONE token, with its spaces preserved.
    assert_eq!(
        changes[0].path,
        vec![
            "interfaces",
            "ge-0/0/1",
            "unit",
            "123",
            "description",
            "10G - Customer - CIR-13080123"
        ]
    );
    assert!(changes[1].path.contains(&"ignore-mtu".to_string()));
}

// ---- The scope vocabulary (grant) ----

/// A deploy-style mode, composed from generic scope grants.
fn deploy_mode() -> ConfigPolicy {
    ConfigPolicy::with_default_floor()
        .grant(Scope::LogicalUnits, Access::Rwd)
        .grant(Scope::Protocols, Access::Rwd)
}

#[test]
fn scope_deploy_mode_lets_rendered_payload_through() {
    let payload = "\
set interfaces ge-0/0/1 unit 123 description \"10G - Customer - Acme\"
set interfaces ge-0/0/1 unit 123 encapsulation vlan-ccc
set interfaces ge-0/0/1 unit 123 vlan-id 123
set interfaces ge-0/0/1 unit 123 family ccc
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 virtual-circuit-id 13080123
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 ignore-mtu";
    assert!(deploy_mode()
        .check(&parse_set_payload(payload).unwrap())
        .is_ok());
}

/// **Not a duplicate of `delete_below_protocol_ok_but_not_the_protocol_itself`.**
/// The inputs and the assertions are deliberately identical; what differs is how
/// the policy was built. That one uses explicit path patterns, this one uses the
/// scope vocabulary — and the point is that both routes arrive at the same
/// behaviour. Delete either and the equivalence stops being checked.
#[test]
fn scope_protocols_rwd_deletes_below_but_not_the_protocol_node() {
    let p = deploy_mode();
    assert!(p
        .check(&[ch(
            Op::Delete,
            &["protocols", "l2circuit", "neighbor", "10.0.0.2"]
        )])
        .is_ok());
    // The protocol node itself can never be deleted through the Protocols scope,
    // which only reaches the subtree below it.
    assert!(p
        .check(&[ch(Op::Delete, &["protocols", "l2circuit"])])
        .is_err());
}

#[test]
fn scope_logical_units_rwd_deletes_the_whole_unit_node() {
    // Decommissioning: LogicalUnits:Rwd permits deleting the unit node itself.
    let p = deploy_mode();
    assert!(p
        .check(&[ch(Op::Delete, &["interfaces", "ge-0/0/1", "unit", "123"])])
        .is_ok());
}

#[test]
fn scope_descriptions_rw_sets_but_does_not_delete_unit() {
    let p = ConfigPolicy::with_default_floor().grant(Scope::InterfaceDescriptions, Access::Rw);
    // Setting a description, which carries a value token, is fine.
    assert!(p
        .check(&[ch(
            Op::Set,
            &[
                "interfaces",
                "ge-0/0/1",
                "unit",
                "123",
                "description",
                "new text"
            ]
        )])
        .is_ok());
    // Deleting a whole unit is not.
    assert!(p
        .check(&[ch(Op::Delete, &["interfaces", "ge-0/0/1", "unit", "123"])])
        .is_err());
}

/// **`read_only` is the ordinary policy's reading side, and nothing else** (0.5.11).
/// It reads as `with_default_floor` reads — the sensitive trees behind an
/// `allow_read` grant, which is the one grant it takes — and it permits `show` with
/// its read-only pipes. It used to be `all_free(Ro)`, which read the sensitive trees
/// ungated.
#[test]
fn read_only_reads_like_the_ordinary_policy_and_gates_the_sensitive_trees() {
    let everything: Vec<String> = Vec::new();
    let system = vec!["system".to_string()];
    let interfaces = vec!["interfaces".to_string()];

    let ro = ConfigPolicy::read_only();
    ro.check_config_read(&interfaces).expect("an ordinary tree");
    assert!(
        ro.check_config_read(&system).is_err(),
        "a sensitive tree needs a grant"
    );
    assert!(ro.check_config_read(&everything).is_err());
    assert!(ro.check_command("show configuration system").is_err());
    ro.check_command("show interfaces terse | match ge-")
        .expect("show with a read-only pipe");
    assert!(ro
        .check_command("show interfaces | save /var/tmp/x")
        .is_err());
    assert_eq!(
        ro.all_free_access(),
        None,
        "read_only is no longer all_free(Ro)"
    );
    assert!(ro.is_read_only());

    let granted = ConfigPolicy::read_only().allow_read("system");
    granted
        .check_config_read(&system)
        .expect("allow_read is the grant it takes");
    granted.check_command("show configuration system").unwrap();

    let ordinary = ConfigPolicy::with_default_floor();
    assert!(ordinary.check_config_read(&everything).is_err());
    assert!(ordinary.check_config_read(&system).is_err());
    assert!(!ordinary.is_read_only());
}

/// **`read_only` takes no command grant and no change grant** — whatever is added
/// to it has no effect, which is what its documentation always said. Until 0.5.11
/// `read_only().allow_command("request system reboot")` permitted the reboot.
#[test]
fn read_only_takes_no_command_or_change_grant() {
    let p = ConfigPolicy::read_only()
        .allow_command("request system reboot")
        .grant(Scope::LogicalUnits, Access::Rwd)
        .allow("system *", Match::Subtree, &[Op::Set, Op::Delete]);
    let e = p
        .check_command("request system reboot")
        .expect_err("a command grant on read_only has no effect");
    assert!(e.contains("read-only"), "{e}");
    let v = p
        .check(&[ch(
            Op::Set,
            &["interfaces", "ge-0/0/1", "unit", "1", "vlan-id", "1"],
        )])
        .expect_err("a change grant on read_only has no effect");
    assert!(v.reason.contains("read-only"), "{}", v.reason);
    assert!(p.describe().contains("read-only"));
}

/// **`all_deny` permits nothing, whatever is granted** (0.5.11). It is what a session
/// without a bound policy has.
#[test]
fn all_deny_permits_nothing_whatever_is_granted() {
    let p = ConfigPolicy::all_deny()
        .allow_read("system")
        .allow_command("show version")
        .grant(Scope::LogicalUnits, Access::Rwd);
    assert!(p.is_all_deny());
    assert!(p.check_command("show version").is_err());
    assert!(p.check_config_read(&["interfaces".to_string()]).is_err());
    assert!(p.check_config_read(&[]).is_err());
    assert!(p
        .check(&[ch(
            Op::Set,
            &["interfaces", "ge-0/0/1", "unit", "1", "vlan-id", "1"]
        )])
        .is_err());
    assert_eq!(p.all_free_access(), None);
    assert!(!p.is_all_free_rwd());
    assert!(p.describe().contains("all-deny"));
    // The const constructor: usable in a static.
    static DENY: ConfigPolicy = ConfigPolicy::all_deny();
    assert!(DENY.is_all_deny());
}

#[test]
fn scope_read_only_denies_all_changes() {
    let p = ConfigPolicy::read_only();
    assert!(p
        .check(&[ch(
            Op::Set,
            &["interfaces", "ge-0/0/1", "unit", "1", "family", "ccc"]
        )])
        .is_err());
}

#[test]
fn rendered_l2circuit_payload_passes_deploy_policy() {
    // The whole rendered set payload must pass this mode.
    let payload = "\
set interfaces ge-0/0/1 unit 123 description \"10G - Customer - Acme\"
set interfaces ge-0/0/1 unit 123 encapsulation vlan-ccc
set interfaces ge-0/0/1 unit 123 vlan-id 123
set interfaces ge-0/0/1 unit 123 family ccc
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 virtual-circuit-id 13080123
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 description \"10G - Customer - Acme\"
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 ignore-mtu";
    let changes = parse_set_payload(payload).unwrap();
    assert_eq!(changes.len(), 7);
    assert!(deploy_policy().check(&changes).is_ok());
}

#[test]
fn description_can_be_deleted_with_rwd() {
    // `delete interfaces X description` on the exact node must be allowed under
    // Rwd, not only `set ... description "text"`, which carries a value token and
    // therefore counts as a subtree.
    let policy =
        ConfigPolicy::with_default_floor().grant(Scope::InterfaceDescriptions, Access::Rwd);
    let set = parse_set_payload("set interfaces ge-0/0/1 description \"customer\"").unwrap();
    let del = parse_set_payload("delete interfaces ge-0/0/1 description").unwrap();
    assert!(
        policy.check(&set).is_ok(),
        "set description must be allowed"
    );
    assert!(
        policy.check(&del).is_ok(),
        "delete description must be allowed under Rwd"
    );
}

// ---- Fail-closed on unknown verbs, and the all-free modes ----

#[test]
fn unknown_verb_gives_parse_error_not_silent_skip() {
    // A GENUINELY unknown verb, absent from verb_class, must reject the WHOLE payload
    // (fail-closed) rather than silently skipped, which would send it unchecked.
    for line in ["nonsense-verb foo bar", "halt", "request system reboot"] {
        assert!(
            parse_set_payload(line).is_err(),
            "expected a parse error for: {line}"
        );
    }
}

#[test]
fn dangerous_but_known_verbs_are_denied_in_scoped_mode() {
    // deactivate/rename/wildcard delete are now RECOGNISED rather than silently skipped,
    // they are policy-checked. In a scoped deploy mode they must be refused, being
    // outside the scope or
    // so they hit the floor instead of reaching the device unchecked as they once did.
    let mode = deploy_mode(); // logical-units + protocols rwd
    for line in [
        "deactivate system services ssh",
        "wildcard delete interfaces",
        "rename interfaces ge-0/0/1 to ge-0/0/2",
    ] {
        let changes = parse_set_payload(line).unwrap(); // parses (gjenkjent)
        assert!(
            mode.check(&changes).is_err(),
            "a scoped mode should have refused: {line}"
        );
    }
}

/// **Every part of a command is checked, pipes included.** A pipe is only valid on
/// `show`, and only a read-only one is let through: `save`, `append` and `tee` write
/// files on the device, `request` messages its users. Only the text before the first
/// `|` used to be checked, and the pipe went to the device as written.
#[test]
fn every_pipe_in_a_command_is_checked() {
    let p = ConfigPolicy::with_default_floor().allow_command("request system reboot");
    for ok in [
        "show interfaces terse | match ge-0/0/1",
        "show interfaces | match \"ge|xe\" | count",
        "show configuration interfaces | display set",
    ] {
        p.check_command(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for refused in [
        "show interfaces | save /var/tmp/x",
        "show interfaces | match ge | append /var/tmp/x",
        "show log messages | request message all message hi",
        "show interfaces | m ge",
        "show interfaces |",
        "request system reboot | count",
    ] {
        assert!(
            p.check_command(refused).is_err(),
            "{refused} was let through"
        );
    }
}

/// **A pipe behind an unbalanced quote is refused.** The command gate reads strings
/// by the set parser's rule. A `"` that never closed used to hide every `|` after it
/// from the scan — the command passed as a plain `show`, and the device, which does
/// not read an open string that way, ran the pipe. A quote that does not close now
/// refuses the command, as it refuses a set payload.
#[test]
fn a_pipe_behind_an_unbalanced_quote_is_refused() {
    let p = ConfigPolicy::with_default_floor();
    for refused in [
        "show version \"| save /var/tmp/x",
        "show interfaces | match \"x | save /var/tmp/x",
        // `\"` does not close the string, so it is still open at the end.
        "show version \"a\\\"| save /var/tmp/x",
        "show interfaces | match \"a\\\"",
    ] {
        let e = p
            .check_command(refused)
            .expect_err(&format!("{refused} was let through"));
        assert!(e.contains("unbalanced quote"), "{refused}: {e}");
    }
}

/// A balanced string keeps its `|` to itself, and `\"` inside it is a quote that does
/// not close it — the rule a set payload is read by. An escaped backslash does not
/// escape the quote after it, so the `|` that follows is a pipe and is checked.
///
/// The third case rests on the device reading `\"` inside a string as a quote, as
/// the set parser assumes for a payload. For an operational command that is not
/// measured against a device; if it does not hold, this is the case that must flip.
#[test]
fn a_quoted_pipe_is_text_and_an_escaped_quote_does_not_close_the_string() {
    let p = ConfigPolicy::with_default_floor();
    for ok in [
        "show interfaces | match \"a|b\"",
        "show interfaces | match \"a\\\"|b\"",
        "show interfaces | match \"a\\\" | save /var/tmp/x\"",
    ] {
        p.check_command(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    let e = p
        .check_command("show interfaces | match \"a\\\\\" | save /var/tmp/x")
        .expect_err("an escaped backslash does not escape the quote after it");
    assert!(e.contains("| save"), "{e}");
}

/// **A control character refuses a command.** A command is one line. A carriage
/// return reaches the device as a line break — XML makes it a newline — and so does
/// a newline, while the gate read the whole text as one `show`:
/// `show interfaces\rrequest system reboot` passed. NUL, form feed, vertical tab,
/// DEL and the C1 controls are refused too; a tab is whitespace and passes.
#[test]
fn a_control_character_refuses_a_command() {
    let p = ConfigPolicy::with_default_floor();
    for (cmd, code) in [
        ("show interfaces\rrequest system reboot", "U+000D"),
        ("show interfaces\nrequest system reboot", "U+000A"),
        ("show interfaces\r\nrequest system reboot", "U+000D"),
        ("show version\n", "U+000A"),
        ("show interfaces\0", "U+0000"),
        ("show interfaces\x0bterse", "U+000B"),
        ("show interfaces\x0cterse", "U+000C"),
        ("show interfaces\x7f", "U+007F"),
        ("show interfaces\u{85}terse", "U+0085"),
        ("show interfaces | match \"a\rb\"", "U+000D"),
    ] {
        let e = p
            .check_command(cmd)
            .expect_err(&format!("{cmd:?} was let through"));
        assert!(
            e.contains("control character") && e.contains(code),
            "{cmd:?}: {e}"
        );
    }
    p.check_command("show interfaces\tterse")
        .expect("a tab is whitespace");
}

/// **A control character in a set payload refuses it.** A line ends with `\n` or
/// `\r\n`: `str::lines` ends one there, and XML makes both a newline before the
/// device reads the payload. A carriage return anywhere else is a line break to the
/// device and none to the parser — `#\rdelete protocols` was a skipped `#` line here
/// and a `delete protocols` on the device, and `description x\rdelete system` one
/// `set` here and two statements there. NUL, VT, FF, DEL and C1 are refused too. The
/// error names the line and the code point, never the line's text.
#[test]
fn a_control_character_refuses_a_set_payload() {
    for (payload, line, character) in [
        ("#\rdelete protocols", 1, '\r'),
        (
            "set interfaces ge-0/0/1 unit 1 description x\rdelete system",
            1,
            '\r',
        ),
        // A lone CR on a later line, and one just before the line's CRLF.
        (
            "set interfaces ge-0/0/1 unit 1 description x\n#\rdelete protocols",
            2,
            '\r',
        ),
        (
            "set interfaces ge-0/0/1 unit 1 description x\r\r\nset protocols l2circuit a",
            1,
            '\r',
        ),
        // A trailing one, which `trim` used to take away unseen.
        ("set interfaces ge-0/0/1 unit 1 description x\r", 1, '\r'),
        ("set interfaces ge-0/0/1 unit 1 description x\0", 1, '\0'),
        (
            "set interfaces ge-0/0/1 unit 1 description x\x0bdelete system",
            1,
            '\x0b',
        ),
        (
            "set interfaces ge-0/0/1 unit 1 description x\x0cdelete system",
            1,
            '\x0c',
        ),
        (
            "set interfaces ge-0/0/1 unit 1 description x\x7f",
            1,
            '\x7f',
        ),
        (
            "set interfaces ge-0/0/1 unit 1 description x\u{85}delete system",
            1,
            '\u{85}',
        ),
        // Inside a quoted string as well: the device breaks the line there too.
        (
            "set interfaces ge-0/0/1 unit 1 description \"a\rb\"",
            1,
            '\r',
        ),
    ] {
        match parse_set_payload(payload) {
            Err(e @ ParseError::ControlCharacter { .. }) => {
                assert_eq!(
                    e,
                    ParseError::ControlCharacter { line, character },
                    "{payload:?}"
                );
                let text = e.to_string();
                assert!(
                    text.contains(&format!("U+{:04X}", u32::from(character)))
                        && text.contains(&format!("line {line}")),
                    "{payload:?}: {text}"
                );
                assert!(
                    !text.contains("description") && !text.contains("delete"),
                    "the line is echoed: {text}"
                );
            }
            other => panic!("{payload:?}: expected ControlCharacter, got {other:?}"),
        }
    }
}

/// **A tab and CRLF are accepted in a set payload.** A tab is whitespace to the
/// parser and to the device, inside a string and out. CRLF is one line end to
/// `str::lines` and to XML alike, so a CRLF payload reads exactly as the same
/// payload with LF.
#[test]
fn a_tab_and_crlf_line_ends_are_accepted_in_a_set_payload() {
    let c = parse_set_payload("set interfaces ge-0/0/1 unit 1 description \"a\tb\"")
        .expect("a tab in a string");
    assert_eq!(c[0].path.last().unwrap(), "a\tb");
    parse_set_payload("set\tinterfaces ge-0/0/1 unit 1 description x")
        .expect("a tab between words");

    let lf = "# a comment\nset interfaces ge-0/0/1 unit 1 description \"x\"\n\
              delete interfaces ge-0/0/1 unit 2\nset protocols l2circuit neighbor 10.0.0.1\n";
    let crlf = lf.replace('\n', "\r\n");
    assert!(crlf.contains("\r\n"));
    let from_lf = parse_set_payload(lf).expect("LF");
    assert_eq!(from_lf.len(), 3);
    assert_eq!(
        parse_set_payload(&crlf).expect("CRLF is a line end"),
        from_lf
    );
}

/// **A consumer's own payload check refuses a carriage return.** A consumer may
/// check a payload itself before it loads one: `parse_set_payload`, then `check`
/// against its profile — here the default floor with `LogicalUnits` and `Protocols`
/// at `Rwd`. `#\rdelete protocols` gave no change at all, which that profile
/// passed, and the payload went on to the device as a `delete protocols`, past the
/// floor.
#[test]
fn a_consumers_parse_then_check_refuses_a_carriage_return() {
    let profile = ConfigPolicy::with_default_floor()
        .grant(Scope::LogicalUnits, Access::Rwd)
        .grant(Scope::Protocols, Access::Rwd);
    let check_payload = |payload: &str| -> Result<(), String> {
        let changes = parse_set_payload(payload).map_err(|e| e.to_string())?;
        profile.check(&changes).map_err(|v| v.reason)
    };
    for payload in [
        "#\rdelete protocols",
        "set interfaces ge-0/0/1 unit 100 description x\rdelete system",
    ] {
        let e = check_payload(payload).expect_err(&format!("{payload:?} was let through"));
        assert!(e.contains("U+000D"), "{payload:?}: {e}");
    }
    check_payload("set interfaces ge-0/0/1 unit 100 description \"x\"\r\n")
        .expect("a CRLF line end passes as before");
}

#[test]
fn known_verbs_are_classified_correctly() {
    use netconf::policy::verb_class;
    assert_eq!(verb_class("set"), Some(Op::Set));
    assert_eq!(verb_class("activate"), Some(Op::Set));
    assert_eq!(verb_class("protect"), Some(Op::Set));
    assert_eq!(verb_class("delete"), Some(Op::Delete));
    assert_eq!(verb_class("deactivate"), Some(Op::Delete));
    assert_eq!(verb_class("unprotect"), Some(Op::Delete));
    assert_eq!(verb_class("halt"), None);
}

#[test]
fn wildcard_delete_parses_as_delete() {
    let changes = parse_set_payload("wildcard delete interfaces ge-0/0/1 unit").unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].op, Op::Delete);
    assert_eq!(changes[0].path, vec!["interfaces", "ge-0/0/1", "unit"]);
}

#[test]
fn unbalanced_quote_gives_parse_error() {
    assert!(parse_set_payload("set interfaces ge-0/0/1 description \"unterminated").is_err());
}

#[test]
fn escaped_quote_in_string_is_preserved() {
    let changes =
        parse_set_payload("set interfaces ge-0/0/1 description \"says \\\"hi\\\" here\"").unwrap();
    assert_eq!(changes[0].path.last().unwrap(), "says \"hi\" here");
}

/// **Only `"` quotes a value.** A single quote is not a quote character here, and
/// the decision is Roger's (2026-09-21): `"` is what we accept.
///
/// Before this, `'` was read as ordinary text. `description 'Link to router one'`
/// came out as four tokens — `'Link`, `to`, `router`, `one'` — and the policy then
/// decided on a path the operator had not written, and let it through, because the
/// extra pieces fell inside a subtree that was already granted. The filter must not
/// pass on something it has misread, so the whole payload is refused, exactly as an
/// unbalanced `"` is.
#[test]
fn a_single_quote_outside_a_string_refuses_the_payload() {
    for line in [
        "set interfaces ge-0/0/1 unit 100 description 'Link to router one'",
        "set interfaces ge-0/0/1 unit 100 description 'one'",
        // Quoting the prefix is refused too, not only the value.
        "delete 'system'",
    ] {
        match parse_set_payload(line) {
            Err(ParseError::SingleQuote(_)) => {}
            other => panic!("{line}: expected SingleQuote, got {other:?}"),
        }
    }
    // One such line refuses the whole payload, not just itself.
    let payload = "set interfaces ge-0/0/1 unit 100 description \"fine\"\n\
                   set interfaces ge-0/0/1 unit 101 description 'not fine'";
    assert!(
        parse_set_payload(payload).is_err(),
        "the good line must not carry the bad one through"
    );
}

/// Inside a double-quoted string `'` is just a character. An apostrophe in a
/// description is ordinary text and has to keep working.
#[test]
fn a_single_quote_inside_a_string_is_text() {
    let changes = parse_set_payload("set interfaces ge-0/0/1 description \"Roger's link\"")
        .expect("an apostrophe inside a string must parse");
    assert_eq!(changes[0].path.last().unwrap(), "Roger's link");
}

/// The refused line goes into an error the consumer logs, so it is redacted like
/// every other parse error. A value in single quotes is as likely to be a secret as
/// any other.
#[test]
fn the_single_quote_error_is_redacted() {
    let line = "set system login user x authentication encrypted-password '$9$hunter2'";
    let e = parse_set_payload(line).expect_err("a single quote must be refused");
    assert!(!e.to_string().contains("hunter2"), "the secret leaked: {e}");
}

/// **The unknown verb is redacted too (0.5.10).** It goes into the same error the
/// consumer logs, and a secret pasted where the verb belongs is the first word on
/// the line. A plain unknown word is still named, so the operator sees what was
/// refused.
#[test]
fn an_unknown_verb_is_redacted_and_a_plain_one_is_still_named() {
    for payload in ["$9$hunter2secret x", "wildcard $9$hunter2secret x"] {
        let e = parse_set_payload(payload).expect_err("an unknown verb must be refused");
        assert!(matches!(e, ParseError::UnknownVerb(_)), "{e}");
        assert!(
            !e.to_string().contains("hunter2secret"),
            "the secret leaked: {e}"
        );
    }
    let e = parse_set_payload("frobnicate x").expect_err("an unknown verb must be refused");
    assert!(e.to_string().contains("«frobnicate»"), "{e}");
}

/// **`all_free(Rwd)` is the one policy that may delete everything**, a top-level
/// tree included. Every other policy has the floor: a rule that grants deleting
/// `system` itself does not get past it.
#[test]
fn all_free_rwd_may_delete_a_top_level_tree_and_a_floored_policy_may_not() {
    let free = ConfigPolicy::all_free(Access::Rwd);
    assert!(free.check(&[ch(Op::Delete, &["system"])]).is_ok());
    assert!(free.check(&[ch(Op::Delete, &["protocols", "bgp"])]).is_ok());

    let floored = ConfigPolicy::with_default_floor().allow("system", Match::Node, &[Op::Delete]);
    let v = floored
        .check(&[ch(Op::Delete, &["system"])])
        .expect_err("a floored policy deleted a top-level tree");
    assert!(v.reason.contains("absolute floor"), "{}", v.reason);
}

#[test]
fn all_free_rw_allows_set_but_not_delete() {
    let p = ConfigPolicy::all_free(Access::Rw);
    assert!(p
        .check(&[ch(Op::Set, &["system", "ntp", "server", "x"])])
        .is_ok());
    assert!(p.check(&[ch(Op::Delete, &["system", "ntp"])]).is_err());
}

#[test]
fn all_free_ro_allows_no_change() {
    let p = ConfigPolicy::all_free(Access::Ro);
    assert!(p.check(&[ch(Op::Set, &["system", "ntp"])]).is_err());
    assert!(p.check(&[ch(Op::Delete, &["system", "ntp"])]).is_err());
}

#[test]
fn known_top_level_covers_the_platforms() {
    use netconf::policy::is_known_top_level;
    for tree in [
        "system",
        "interfaces",
        "security",
        "bridge-domains",
        "vmhost",
        "unified-edge",
    ] {
        assert!(is_known_top_level(tree), "missing: {tree}");
    }
    assert!(!is_known_top_level("does-not-exist"));
}

// ---- Introspection: the crate can answer what a filter permits ----

#[test]
fn introspection_exposes_rules_and_describe() {
    let p = ConfigPolicy::with_default_floor()
        .grant(Scope::LogicalUnits, Access::Rwd)
        .grant(Scope::Protocols, Access::Rw);
    // Structured: the rules can be read back.
    assert!(!p.rules().is_empty());
    let first = &p.rules()[0];
    assert_eq!(first.pattern(), "interfaces * unit *");
    assert!(!first.ops().is_empty());
    assert!(!p.protected_roots().is_empty());
    assert_eq!(p.all_free_access(), None);
    // Readable: describe mentions both the rules and the floor.
    let d = p.describe();
    assert!(d.contains("interfaces * unit *"));
    assert!(d.contains("floor"));
}

#[test]
fn introspection_reports_default_deny_and_all_free() {
    let empty = ConfigPolicy::with_default_floor();
    assert!(empty.rules().is_empty());
    assert!(empty.describe().contains("default-deny"));

    let free = ConfigPolicy::all_free(Access::Rwd);
    assert!(free.is_all_free_rwd());
    assert_eq!(free.all_free_access(), Some(Access::Rwd));
    assert!(free.describe().contains("all-free"));
}

// ---------------------------------------------------------------------------
// Creating a unit, and the empty quoted value
// ---------------------------------------------------------------------------

/// **A grant that can delete a unit must also be able to create one.**
///
/// `set interfaces ge-0/0/1 unit 100` is exactly four tokens, and `Match::Subtree`
/// requires the change path to be strictly longer than the rule. Only Delete had a
/// Node rule, so creating a bare unit fell to default-deny: a unit could be brought
/// into existence only by setting something under it in the same line, and removed
/// freely. That asymmetry was not intended by anything.
#[test]
fn logical_units_can_create_a_unit_not_only_delete_one() {
    for access in [Access::Rw, Access::Rwd] {
        let p = ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, access);
        assert!(
            p.check(&[ch(Op::Set, &["interfaces", "ge-0/0/1", "unit", "100"])])
                .is_ok(),
            "{access:?} must be able to create a unit"
        );
    }
    // Read-only still creates nothing.
    let ro = ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Ro);
    assert!(ro
        .check(&[ch(Op::Set, &["interfaces", "ge-0/0/1", "unit", "100"])])
        .is_err());
    // And Rw still does not delete it.
    let rw = ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rw);
    assert!(rw
        .check(&[ch(Op::Delete, &["interfaces", "ge-0/0/1", "unit", "100"])])
        .is_err());
}

/// **An empty quoted value is an argument, not an absence.**
///
/// `set interfaces ge-0/0/1 description ""` clears a description. The tokenizer
/// dropped the `""`, so the path came out one token shorter — which is a different
/// path, matching different rules. The policy was then deciding about something the
/// operator had not written.
#[test]
fn an_empty_quoted_value_stays_a_token() {
    let changes =
        parse_set_payload("set interfaces ge-0/0/1 description \"\"").expect("must parse");
    assert_eq!(
        changes[0].path,
        vec!["interfaces", "ge-0/0/1", "description", ""],
        "the empty value was dropped from the path"
    );
    // A non-empty quoted value is unaffected.
    let q = parse_set_payload("set interfaces ge-0/0/1 description \"a b\"").expect("must parse");
    assert_eq!(
        q[0].path,
        vec!["interfaces", "ge-0/0/1", "description", "a b"]
    );
}

/// **The floor recognises a top-level tree whatever its case.**
///
/// Junos is forgiving about case, so `delete System` reaches the same tree as
/// `delete system`. Default-deny refuses both today — the rule patterns are
/// case-sensitive too — but the floor is the one rule meant to hold on its own,
/// and a rule that holds only because another one happens to is not a floor.
#[test]
fn the_floor_is_not_evaded_by_changing_case() {
    let p = ConfigPolicy::with_default_floor();
    for spelling in ["system", "System", "SYSTEM", "SySTeM"] {
        let v = p
            .check(&[ch(Op::Delete, &[spelling])])
            .expect_err("deleting a protected tree must be refused");
        assert!(
            v.reason.contains("floor"),
            "{spelling} was refused, but not by the floor: {}",
            v.reason
        );
    }
}

/// A verb in the wrong case is refused rather than guessed at — the payload does
/// not reach the device at all. That is fail-closed, and it stays that way.
#[test]
fn a_verb_in_the_wrong_case_is_refused_not_reinterpreted() {
    use netconf::policy::parse_set_payload;
    for line in [
        "SET interfaces ge-0/0/1 unit 1",
        "Delete interfaces ge-0/0/1",
    ] {
        assert!(
            parse_set_payload(line).is_err(),
            "«{line}» must be refused as an unknown verb"
        );
    }
}

/// **A `#` line is skipped; a `/*` comment is refused.** A comment is not sent to a
/// device — it goes in a quoted string. Skipping a `/*` line used to let it through
/// unchecked, to a device that was sent it all the same.
#[test]
fn a_hash_line_is_skipped_and_a_slash_star_comment_is_refused() {
    use netconf::policy::parse_set_payload;
    let payload = "# a hash comment\nset interfaces ge-0/0/1 unit 1 description \"x\"";
    let changes = parse_set_payload(payload).expect("a # line is skipped");
    assert_eq!(changes.len(), 1);

    for payload in [
        "/* a Junos comment */\nset interfaces ge-0/0/1 unit 1 description \"x\"",
        "set interfaces ge-0/0/1 unit 1 description x /* trailing */",
    ] {
        assert!(
            matches!(parse_set_payload(payload), Err(ParseError::Comment(_))),
            "{payload:?}"
        );
    }
}

/// **`edit` is refused.** It makes the following lines relative to a new context,
/// while the filter reads every line as a full path — so it would judge a path the
/// device never touches. Every line has to carry its full path.
#[test]
fn edit_is_refused_because_it_makes_later_lines_relative() {
    use netconf::policy::parse_set_payload;
    let payload = "edit interfaces ge-0/0/1\nset unit 5 description \"x\"";
    match parse_set_payload(payload) {
        Err(e @ ParseError::UnknownVerb(_)) => assert!(e.to_string().contains("full path"), "{e}"),
        other => panic!("expected edit to be refused, got {other:?}"),
    }
}

/// A statement with a trailing comment is left as it is. Deciding what is inside a
/// quoted value and what is not is how a parser and the device come to disagree,
/// and that gap is the bypass surface.
#[test]
fn a_trailing_comment_is_not_stripped_from_a_statement() {
    use netconf::policy::parse_set_payload;
    let c = parse_set_payload("set interfaces ge-0/0/1 description \"a /* b */ c\"")
        .expect("must parse");
    assert_eq!(c[0].path.last().unwrap(), "a /* b */ c");
}

/// **Case is refused, and the refusal says so.** Verbs and paths are compared
/// exactly — Junos names are case-sensitive, so `policy-statement EXPORT` and
/// `export` are different things, and matching them loosely would let a rule for
/// one approve the other. That stays. What changes is the text: `unknown verb «SET»`
/// left the operator staring at a correct-looking word, and default-deny on
/// `Interfaces` read as though no rule existed at all.
#[test]
fn a_verb_in_the_wrong_case_is_refused_and_named_as_such() {
    let e = parse_set_payload("SET interfaces ge-0/0/1 unit 100").unwrap_err();
    let s = e.to_string();
    assert!(matches!(e, ParseError::UnknownVerb(_)), "{s}");
    assert!(s.contains("lowercase"), "the case is not named: {s}");
    // A genuinely unknown verb gets no such hint — it is not a case problem.
    let g = parse_set_payload("frobnicate interfaces ge-0/0/1")
        .unwrap_err()
        .to_string();
    assert!(
        !g.contains("lowercase"),
        "a case hint on an unknown verb: {g}"
    );
}

#[test]
fn a_path_in_the_wrong_case_is_refused_and_named_as_such() {
    let p = ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rw);
    let v = p
        .check(&[ch(Op::Set, &["Interfaces", "ge-0/0/1", "unit", "100"])])
        .expect_err("a path in the wrong case must still be refused");
    assert!(v.reason.contains("default-deny"), "{}", v.reason);
    assert!(
        v.reason.contains("case-sensitive"),
        "the case is not named: {}",
        v.reason
    );
    // A path that no rule would allow in ANY case gets no such hint.
    let w = p
        .check(&[ch(Op::Set, &["System", "host-name", "x"])])
        .expect_err("must be refused");
    assert!(
        !w.reason.contains("case-sensitive"),
        "a case hint where case is not the reason: {}",
        w.reason
    );
}

// ---------------------------------------------------------------------------
// The command gate: printable ASCII, quotes, exact keywords, rollback and compare
// ---------------------------------------------------------------------------

/// **A command is one line of printable ASCII, and a tab.** U+2028 and U+2029 are not
/// control characters, so `is_control` let them through, while some readers take
/// them for a line break — the same gap as a carriage return. The Junos CLI is
/// ASCII; a non-ASCII value belongs in a configuration payload.
#[test]
fn a_command_is_printable_ascii_and_a_tab() {
    let p = ConfigPolicy::with_default_floor();
    for (cmd, code) in [
        ("show interfaces\u{2028}request system reboot", "U+2028"),
        ("show interfaces\u{2029}request system reboot", "U+2029"),
        ("show interfaces descriptions | match \"Ørsta\"", "U+00D8"),
        ("show interfaces\u{a0}terse", "U+00A0"),
    ] {
        let e = p
            .check_command(cmd)
            .expect_err(&format!("{cmd:?} was let through"));
        assert!(
            e.contains("outside printable ASCII") && e.contains(code),
            "{cmd:?}: {e}"
        );
    }
    p.check_command("show interfaces\tterse | match \"a b\" | count")
        .expect("printable ASCII and a tab");
}

/// **A quote belongs in a pipe's pattern and nowhere else.** `show "configuration"
/// system` was a read of the sensitive tree the gate did not see as one.
#[test]
fn a_quote_in_the_command_itself_is_refused() {
    let p = ConfigPolicy::with_default_floor();
    for refused in [
        "show \"configuration\" system",
        "show configuration \"system\"",
        "show \"version\"",
    ] {
        let e = p
            .check_command(refused)
            .expect_err(&format!("{refused} was let through"));
        assert!(e.contains("quote in the command itself"), "{refused}: {e}");
    }
    p.check_command("show interfaces | match \"ge-0/0/1\"")
        .expect("a quote in a pipe's pattern is fine");
}

/// **Keywords are compared exactly, as the device reads them.** `SHOW`, `Configuration`
/// and `| MATCH` used to be folded to lowercase and let through — `SHOW` as a `show`,
/// `show Configuration system` through the read gate — and a command grant matched
/// in lowercase. The refusal says when only the case is wrong.
#[test]
fn keywords_are_compared_exactly_as_the_device_reads_them() {
    let p = ConfigPolicy::with_default_floor().allow_command("Request System Reboot");
    let e = p
        .check_command("SHOW version")
        .expect_err("SHOW is not show");
    assert!(e.contains("lowercase") && e.contains("`SHOW`"), "{e}");
    let e = p
        .check_command("show Configuration system")
        .expect_err("Configuration is not configuration");
    assert!(
        e.contains("lowercase") && e.contains("`Configuration`"),
        "{e}"
    );
    let e = p
        .check_command("show Conf")
        .expect_err("a prefix in another case is refused, not read as an ordinary show");
    assert!(e.contains("lowercase"), "{e}");
    let e = p
        .check_command("show interfaces | MATCH ge")
        .expect_err("MATCH is not match");
    assert!(e.contains("| MATCH") && e.contains("lowercase"), "{e}");
    assert!(
        p.check_command("request system reboot").is_err(),
        "a grant matches the command's words as written, in no other case"
    );
    p.check_command("Request System Reboot")
        .expect("the grant as written matches the command as written");
    // Arguments keep their case: names on the device are case-sensitive.
    p.check_command("show route table VRF-A | match 10.0.0.0")
        .unwrap();
}

/// **A rollback is a read of the whole configuration**, sensitive trees included, so
/// `show system rollback <n>` needs the read grants `show configuration` needs. And
/// `| compare` names a rollback and nothing else: a file on the device is not read
/// through it.
#[test]
fn a_rollback_is_a_read_of_the_whole_configuration_and_compare_names_only_a_rollback() {
    let p = ConfigPolicy::with_default_floor();
    let e = p
        .check_command("show system rollback 1")
        .expect_err("a previous configuration holds the sensitive trees");
    assert!(e.contains("FULL configuration"), "{e}");
    assert!(p.check_command("show system rollback 1 compare 2").is_err());
    let mut all = ConfigPolicy::with_default_floor();
    for root in netconf::policy::SENSITIVE_READ_ROOTS {
        all = all.allow_read(root);
    }
    all.check_command("show system rollback 1")
        .expect("with every sensitive tree granted");

    p.check_command("show configuration interfaces | compare")
        .expect("compare against the last commit");
    p.check_command("show configuration interfaces | compare rollback 3")
        .expect("compare against a rollback");
    for refused in [
        "show configuration interfaces | compare /var/tmp/x",
        "show configuration interfaces | compare rollback",
        "show configuration interfaces | compare rollback x",
        "show configuration interfaces | compare rollback 1 extra",
    ] {
        let e = p
            .check_command(refused)
            .expect_err(&format!("{refused} was let through"));
        assert!(e.contains("compare"), "{refused}: {e}");
    }
}

/// **The line and paragraph separators refuse a set payload as a control character
/// does**: a line break to some readers, none to `str::lines`.
#[test]
fn a_line_separator_refuses_a_set_payload_like_a_control_character() {
    for (payload, code) in [
        (
            "set interfaces ge-0/0/1 unit 1 description x\u{2028}delete system",
            0x2028,
        ),
        (
            "set interfaces ge-0/0/1 unit 1 description x\u{2029}delete system",
            0x2029,
        ),
    ] {
        match parse_set_payload(payload) {
            Err(ParseError::ControlCharacter { line, character }) => {
                assert_eq!((line, u32::from(character)), (1, code));
            }
            other => panic!("{payload:?}: expected ControlCharacter, got {other:?}"),
        }
    }
    // Other non-ASCII text in a value is a value: the set parser reads it.
    parse_set_payload("set interfaces ge-0/0/1 unit 1 description \"Ørsta\"")
        .expect("UTF-8 in a description is a value");
}

/// **On the CLI only the first token after `configuration` names a tree.** The
/// prefix rule used to be applied to every token, so `show configuration protocols
/// bgp group x` was refused because `group` is a prefix of `groups` — the false
/// refusal 0.5.7 fixed for XML, still there for the CLI. And `show sys rollback 1`
/// is a read of the whole configuration like `show system rollback 1`: the refusal
/// side is prefix-tolerant, as it is for `show conf sys`.
#[test]
fn only_the_first_cli_token_is_a_tree_and_an_abbreviated_rollback_is_still_a_read() {
    let p = ConfigPolicy::with_default_floor();
    for ok in [
        "show configuration protocols bgp group x",
        "show configuration interfaces ge-0/0/0 unit 0 family inet",
        "show configuration interfaces system",
        "show configuration routing-instances VRF-A access",
    ] {
        p.check_command(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for refused in [
        "show configuration groups x",
        "show configuration grou",
        "show configuration system login",
        "show sys rollback 1",
        "show sy rol 1",
        "show system roll",
    ] {
        assert!(
            p.check_command(refused).is_err(),
            "{refused} was let through"
        );
    }
    p.check_command("show system uptime")
        .expect("an ordinary show under system");
}

/// **A `#` outside a quoted string makes the rest of the line a comment** (0.5.13),
/// and the line is judged without it.
#[test]
fn a_hash_comment_is_dropped_before_the_line_is_judged() {
    let refused = ConfigPolicy::with_default_floor()
        .check(&parse_set_payload("delete protocols # x").unwrap());
    assert!(
        refused.is_err(),
        "the floor let delete protocols # x through"
    );
    let p = parse_set_payload("set system host-name r1 # note").unwrap();
    assert_eq!(p, parse_set_payload("set system host-name r1").unwrap());
    let quoted = parse_set_payload("set interfaces ge-0/0/0 description \"a # b\"").unwrap();
    assert_eq!(quoted[0].path.last().map(String::as_str), Some("a # b"));
    assert!(parse_set_payload("# set system host-name r1")
        .unwrap()
        .is_empty());
}

fn change(op: Op, path: &str) -> Change {
    Change {
        op,
        path: path.split_whitespace().map(String::from).collect(),
    }
}

/// **The floor holds seven more trees** (0.5.13).
#[test]
fn the_floor_holds_logical_systems_and_the_other_six() {
    let p = ConfigPolicy::with_default_floor();
    for tree in [
        "logical-systems",
        "tenants",
        "virtual-chassis",
        "multi-chassis",
        "fabric",
        "dynamic-profiles",
        "accounting-options",
    ] {
        assert!(p.check(&[change(Op::Delete, tree)]).is_err(), "{tree}");
    }
}

/// `apply-groups-except` is a known top-level hierarchy (0.5.13).
#[test]
fn apply_groups_except_is_a_known_hierarchy() {
    assert!(netconf::policy::is_known_top_level("apply-groups-except"));
}

/// **`wildcard delete <tree> *` is held to the floor** (0.5.13), as `delete <tree>` is.
#[test]
fn a_wildcard_delete_of_a_whole_tree_meets_the_floor() {
    let p = ConfigPolicy::with_default_floor().grant(Scope::Protocols, Access::Rwd);
    let changes = parse_set_payload("wildcard delete protocols *").unwrap();
    assert!(p
        .check(&changes)
        .unwrap_err()
        .reason
        .contains("absolute floor"));
}

/// **`rename` deletes its source and writes its target; `copy` writes its target**
/// (0.5.13). The words after `to` replace as many at the end of the source.
#[test]
fn rename_and_copy_have_a_filter_of_their_own() {
    let rename = parse_set_payload("rename interfaces ge-0/0/0 unit 10 to unit 20").unwrap();
    assert_eq!(
        rename,
        vec![
            change(Op::Delete, "interfaces ge-0/0/0 unit 10"),
            change(Op::Set, "interfaces ge-0/0/0 unit 20"),
        ]
    );
    let copy = parse_set_payload("copy interfaces ge-0/0/0 unit 10 to unit 20").unwrap();
    assert_eq!(copy, vec![change(Op::Set, "interfaces ge-0/0/0 unit 20")]);
    // Writing units is not deleting them: a copy passes, a rename does not.
    let rw = ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rw);
    assert!(rw.check(&copy).is_ok());
    assert!(rw.check(&rename).is_err());
    assert!(parse_set_payload("rename interfaces ge-0/0/0 unit 10").is_err());
}

/// **`show ephemeral-configuration` is a configuration read** (0.5.13), judged as
/// `show configuration` is.
#[test]
fn show_ephemeral_configuration_is_a_configuration_read() {
    let p = ConfigPolicy::with_default_floor();
    assert!(p.check_command("show ephemeral-configuration").is_err());
    assert!(p
        .check_command("show ephemeral-configuration instance i1 system")
        .is_err());
    assert!(p
        .check_command("show ephemeral-configuration instance i1 interfaces")
        .is_ok());
}

/// **A logical system is a configuration of its own** (0.5.13): it is not deleted,
/// and what is under it is judged as at the top level — `tenants` likewise.
#[test]
fn a_logical_system_is_judged_as_the_top_level() {
    let p = ConfigPolicy::with_default_floor().grant(Scope::LogicalUnits, Access::Rwd);
    assert!(p
        .check(&[change(Op::Delete, "logical-systems ls1")])
        .is_err());
    assert!(p.check(&[change(Op::Delete, "tenants t1 system")]).is_err());
    assert!(p
        .check(&[change(
            Op::Set,
            "logical-systems ls1 interfaces ge-0/0/0 unit 0 family inet"
        )])
        .is_ok());
    assert!(p
        .check_command("show configuration logical-systems ls1 system")
        .is_err());
    assert!(p
        .check_command("show configuration logical-systems ls1")
        .is_err());
    assert!(p
        .check_command("show configuration logical-systems ls1 interfaces")
        .is_ok());
}
