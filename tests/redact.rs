// SPDX-License-Identifier: MIT OR Apache-2.0
//! The read filter (`redact_secrets`): what is redacted, what must be left
//! alone, and that the drift protection is untouched by it.

use netconf::redact::{contains_secrets, redact_secrets, Redactor, REDACTED};

fn r(s: &str) -> String {
    redact_secrets(s)
}

/// Helper: the secret is gone, but the statement itself remains.
fn assert_redacted(input: &str, secret: &str, keep: &str) {
    let out = r(input);
    assert!(
        !out.contains(secret),
        "the secret «{secret}» leaked:\n  in:  {input}\n  out: {out}"
    );
    assert!(
        out.contains(keep),
        "the structure «{keep}» disappeared:\n  in:  {input}\n  out: {out}"
    );
    assert!(out.contains(REDACTED), "no marker: {out}");
}

// ---------------------------------------------------------------------------
// (a) Known secret shapes
// ---------------------------------------------------------------------------

#[test]
fn junos_hash_literals_are_redacted_regardless_of_path() {
    // $9$ (obfuscated), $8$ (master password/AES), $1$/$5$/$6$ (crypt),
    // $0$ (cleartext marker)
    for tag in ["0", "1", "5", "6", "8", "9", "2a"] {
        let line = format!(
            "set system login user drift authentication encrypted-password \"${tag}$secret1234\""
        );
        let out = r(&line);
        assert!(!out.contains("topsecret1234"), "${tag}$ leaked: {out}");
        assert!(out.contains("encrypted-password"), "{out}");
    }
}

#[test]
fn hash_tag_is_kept_so_the_operator_sees_the_form() {
    let out = r("neighbor 10.0.0.1 authentication-key \"$9$abc123XYZ\";");
    assert_eq!(
        out,
        format!("neighbor 10.0.0.1 authentication-key {REDACTED};"),
        "{out}"
    );
    // And a $9$ that does NOT follow a known statement is caught by the heuristic:
    let out2 = r("unknown-field $9$abc123XYZ");
    assert_eq!(out2, format!("unknown-field $9${REDACTED}"), "{out2}");
}

#[test]
fn encrypted_password_with_secret_data_annotation() {
    assert_redacted(
        "    encrypted-password \"$1$WRGisGQx$twfB0m8PjBAXaUWFlfS/40\"; ## SECRET-DATA",
        "WRGisGQx",
        "encrypted-password",
    );
    // The annotation and the semicolon are structure, and must survive.
    let out = r("    encrypted-password \"$1$WRGisGQx$twfB0m8\"; ## SECRET-DATA");
    assert_eq!(
        out,
        format!("    encrypted-password {REDACTED}; ## SECRET-DATA"),
        "{out}"
    );
}

#[test]
fn radius_and_tacacs_secret() {
    assert_redacted(
        "set system radius-server 10.1.1.1 secret \"$9$aH1j8gqQ1gjyj\"",
        "aH1j8gqQ1gjyj",
        "radius-server 10.1.1.1 secret",
    );
    assert_redacted(
        "set system tacplus-server 10.1.1.2 secret cleartext-secret",
        "cleartext-secret",
        "tacplus-server 10.1.1.2 secret",
    );
}

#[test]
fn snmp_v2c_community_stays_readable_by_default() {
    // Note: the community must stay **readable** — that is the whole point here.
    // (The test name used to shout it in capitals, which `-D warnings` rejects as
    // a clippy error, so the emphasis lives in this comment instead.)
    //
    // A v2c community is not sensitive the way a password is. It travels in clear
    // on the wire whatever we do here, so hiding it in a diff would protect
    // nothing and only take readability away from the people who need it.
    let line = "set snmp community public authorization read-only";
    assert_eq!(
        redact_secrets(line),
        line,
        "the v2c community must be left untouched"
    );

    // Anyone who DOES want it hidden has Redactor::strict().
    let strict = netconf::Redactor::strict().redact(line);
    assert!(!strict.contains("public"), "strict() must redact it");
}

#[test]
fn snmp_v3_keys_are_always_redacted() {
    // v3 auth/priv keys are real secrets: they are redacted in every mode.
    assert_redacted(
        "set snmp v3 usm local-engine user u1 authentication-sha authentication-key \"$9$xyzq\"",
        "xyzq",
        "authentication-key",
    );
    assert_redacted(
        "set snmp v3 usm local-engine user u1 privacy-aes128 privacy-key \"$9$abcd\"",
        "abcd",
        "privacy-key",
    );
}

#[test]
fn ipsec_ike_pre_shared_key() {
    assert_redacted(
        "set security ike policy IKE-POL pre-shared-key ascii-text \"very-secret\"",
        "very-secret",
        "pre-shared-key",
    );
    assert_redacted(
        "set security ipsec vpn V manual authentication key ascii-text abc123",
        "abc123",
        "authentication key",
    );
}

#[test]
fn routing_protocol_authentication() {
    assert_redacted(
        "set protocols bgp group EBGP authentication-key \"$9$bgpKEY123\"",
        "bgpKEY123",
        "authentication-key",
    );
    assert_redacted(
        "set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication md5 1 key \"$9$ospfKEY\"",
        "ospfKEY",
        "md5 1 key",
    );
    assert_redacted(
        "set protocols isis interface ge-0/0/1.0 hello-authentication-key \"$9$isisKEY\"",
        "isisKEY",
        "hello-authentication-key",
    );
    assert_redacted(
        "set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 authentication simple-password cleartextpw",
        "cleartextpw",
        "simple-password",
    );
}

#[test]
fn ssh_keys_in_config() {
    assert_redacted(
        "set system login user drift authentication ssh-ed25519 \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef drift@example\"",
        "AAAAC3NzaC1lZDI1NTE5AAAAIabcdef",
        "ssh-ed25519",
    );
    // The blob heuristic catches key material even without a known statement name.
    let out = r("some-unknown-statement AAAAB3NzaC1yc2EAAAADAQABAAABgQDxyz== user@host");
    assert!(!out.contains("AAAAB3NzaC1yc2E"), "{out}");
    assert!(out.contains("user@host"), "{out}");
}

#[test]
fn pem_block_across_multiple_lines() {
    let cfg = "\
security {
    certificates local mycert {
        \"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0secretKey1
MIIEpAIBAAKCAQEA0secretKey2
-----END RSA PRIVATE KEY-----\";
    }
}";
    let out = r(cfg);
    assert!(!out.contains("secretKey1"), "{out}");
    assert!(!out.contains("secretKey2"), "{out}");
    assert!(out.contains("-----BEGIN RSA PRIVATE KEY-----"), "{out}");
    assert!(out.contains("-----END RSA PRIVATE KEY-----"), "{out}");
    assert!(out.contains("certificates local mycert"), "{out}");
}

#[test]
fn xml_leaves_from_get_configuration() {
    let xml = "<configuration><system><login><user><name>drift</name>\
<authentication><encrypted-password>$9$secretXYZ</encrypted-password></authentication>\
</user></login></system></configuration>";
    let out = r(xml);
    assert!(!out.contains("secretXYZ"), "{out}");
    assert!(out.contains("<encrypted-password>"), "{out}");
    assert!(out.contains("<name>drift</name>"), "{out}");
}

#[test]
fn secret_data_marker_is_a_safety_net_for_unknown_statements() {
    // A statement we do not know, but which Junos itself has marked as secret.
    // The name must carry NO segment from SECRET_SEGMENTS, or the ordinary
    // statement rule redacts it and the marker is never what did the work. The
    // previous fixture was named `...-secret-...`, so this test passed with the
    // `## SECRET-DATA` marker deleted — it proved nothing about the safety net.
    let out = r("    an-unknown-field cleartextvalue; ## SECRET-DATA");
    assert!(!out.contains("cleartextvalue"), "{out}");
    assert!(out.contains("an-unknown-field"), "{out}");
    assert!(out.contains("SECRET-DATA"), "{out}");
}

/// Regression: a secret VALUE can itself look like a statement name. The value
/// must still be redacted, not read as the statement and left standing.
#[test]
fn value_resembling_a_statement_name_is_still_redacted() {
    for (line, secret) in [
        (
            "set system tacplus-server 10.1.1.2 secret min-secret",
            "min-secret",
        ),
        (
            "set system radius-server 10.1.1.3 secret super-secret",
            "super-secret",
        ),
        (
            "set system login user u authentication plain-text-password-value secret-password",
            "secret-password",
        ),
    ] {
        assert!(
            !r(line).contains(secret),
            "the value «{secret}» leaked: {}",
            r(line)
        );
    }
}

#[test]
fn contains_secrets_flags_correctly() {
    assert!(contains_secrets(
        "set system radius-server 1.1.1.1 secret abc"
    ));
    assert!(!contains_secrets(
        "set interfaces ge-0/0/1 unit 123 encapsulation vlan-ccc"
    ));
}

// ---------------------------------------------------------------------------
// (b) Ordinary configuration must NOT be damaged
// ---------------------------------------------------------------------------

/// A realistic l2circuit configuration must come through unharmed.
const L2CIRCUIT: &str = "\
set interfaces ge-0/0/1 unit 123 description \"10G - Customer - Acme Ltd - CIR-13080123 12345 67890 - backup circuit\"
set interfaces ge-0/0/1 unit 123 encapsulation vlan-ccc
set interfaces ge-0/0/1 unit 123 vlan-id 123
set interfaces ge-0/0/1 unit 123 family ccc
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 virtual-circuit-id 13080123
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 description \"10G - Customer - Acme Ltd - CIR-13080123 12345 67890 - backup circuit\"
set protocols l2circuit neighbor 10.255.0.2 interface ge-0/0/1.123 ignore-mtu";

#[test]
fn l2circuit_config_passes_through_unharmed() {
    assert_eq!(r(L2CIRCUIT), L2CIRCUIT);
    assert!(!contains_secrets(L2CIRCUIT));
}

#[test]
fn compare_diff_for_l2circuit_passes_through_unharmed() {
    let diff = "\
[edit interfaces ge-0/0/1]
+   unit 123 {
+       description \"10G - Customer - Acme Ltd - CIR-13080123\";
+       encapsulation vlan-ccc;
+       vlan-id 123;
+       family ccc;
+   }
[edit protocols l2circuit]
+   neighbor 10.255.0.2 {
+       interface ge-0/0/1.123 {
+           virtual-circuit-id 13080123;
+           ignore-mtu;
+       }
+   }";
    assert_eq!(r(diff), diff);
}

/// A free-text keyword used as a NAME does not stop redaction. `description`,
/// `annotate` and `comment` used to end the scan wherever they appeared, so a secret
/// statement after a user or a policy with one of those names went out in cleartext.
#[test]
fn a_free_text_keyword_as_a_name_does_not_stop_redaction() {
    assert_redacted(
        "set system login user comment authentication plain-text-password-value \"hunter2\"",
        "hunter2",
        "plain-text-password-value",
    );
    assert_redacted(
        "set security ike policy description pre-shared-key ascii-text \"hunter2\"",
        "hunter2",
        "pre-shared-key",
    );
}

#[test]
fn description_is_free_text_and_left_alone() {
    // Words like «secret» or «password» inside a description are not statements.
    for line in [
        "set interfaces ge-0/0/1 unit 5 description \"customer secret project password key\"",
        "set interfaces ge-0/0/1 description \"NNI to Acme - community 42\"",
    ] {
        assert_eq!(r(line), line, "the description was damaged");
    }
}

#[test]
fn ordinary_non_secret_statements_are_left_alone() {
    for line in [
        "set forwarding-options hash-key family inet layer-3",
        "set protocols bgp group EBGP authentication-key-chain KC-1",
        "set security authentication-key-chains key-chain KC-1 tolerance 60",
        "set chassis aggregated-devices ethernet device-count 8",
        "set routing-options router-id 10.255.0.1",
        "set class-of-service interfaces ge-0/0/1 unit 123 classifiers ieee-802.1 default",
        "delete interfaces ge-0/0/1 unit 123",
    ] {
        assert_eq!(r(line), line, "a harmless line was edited");
    }
}

#[test]
fn delete_without_value_keeps_readability() {
    let line = "delete system login user drift authentication encrypted-password";
    assert_eq!(r(line), line);
}

#[test]
fn junos_variables_in_dynamic_profiles_are_left_alone() {
    let line = "set dynamic-profiles P interfaces \"$junos-interface-ifd-name\" unit \"$junos-underlying-interface-unit\"";
    assert_eq!(r(line), line);
}

#[test]
fn bgp_community_name_is_not_secret() {
    let line = "set policy-options community NO-EXPORT-NF members 65000:100";
    assert_eq!(r(line), line);
}

#[test]
fn snmp_community_can_be_hidden_with_strict() {
    let line = "set snmp community private authorization read-only";
    // The default keeps the v2c community readable.
    assert_eq!(r(line), line);
    // Anyone who wants it hidden anyway chooses strict().
    assert!(!Redactor::strict().redact(line).contains("private"));
    // … and the $9$ heuristic applies in BOTH modes — a real secret never walks
    // out just because the community is left visible.
    // The value must not be a word that also appears as a statement name, or the
    // assertion would match the name that legitimately survives.
    assert!(!r("set system radius-server 1.1.1.1 secret \"$9$hunter2\"").contains("hunter2"));
}

// ---------------------------------------------------------------------------
// (c) Structure and robustness properties
// ---------------------------------------------------------------------------

#[test]
fn line_structure_is_preserved_exactly() {
    for input in [
        "",
        "\n",
        "a\nb\n",
        "\n\n\n",
        "set snmp community x\r\nset snmp community y\r\n",
    ] {
        let out = r(input);
        assert_eq!(
            out.matches('\n').count(),
            input.matches('\n').count(),
            "line break count changed for {input:?} → {out:?}"
        );
        assert_eq!(
            out.matches('\r').count(),
            input.matches('\r').count(),
            "CR lost for {input:?} → {out:?}"
        );
    }
}

/// The rare shapes that used to pass redaction untouched.
///
/// A PEM line whose BEGIN marker has no closing hyphens, with the END on the same
/// line, came back as it was, key body included; so did body text on the BEGIN or
/// the END line of a multi-line block. And an XML secret whose value starts on the
/// opening tag's line had that first part let through — only the lines after it
/// were redacted.
#[test]
fn rare_pem_and_xml_shapes_are_redacted() {
    let one_line = "key \"-----BEGIN PRIVATE KEY MIIEsecretBody -----END PRIVATE KEY-----\";";
    let body_on_marker_lines =
        "-----BEGIN PRIVATE KEY-----MIIEsecretHead\nMIIE\nsecretTail==-----END PRIVATE KEY-----";
    for input in [one_line, body_on_marker_lines] {
        let out = r(input);
        for body in ["secretBody", "secretHead", "secretTail", "MIIE"] {
            assert!(!out.contains(body), "key body leaked: {out}");
        }
        assert!(out.contains("-----BEGIN"), "{out}");
        assert!(out.contains("-----END PRIVATE KEY-----"), "{out}");
        assert_eq!(r(&out), out, "not idempotent");
    }

    let xml = "<authentication-key>hunter2\n</authentication-key>";
    let out = r(xml);
    assert!(!out.contains("hunter2"), "{out}");
    assert!(out.contains("<authentication-key>"), "{out}");
    assert!(out.contains("</authentication-key>"), "{out}");
    assert_eq!(r(&out), out, "not idempotent");
}

/// Several blocks can meet on one line — a chain whose newlines were lost, say. The
/// line is walked marker by marker, so a block that begins where another ends is
/// redacted on the lines that follow too, and body text between any two markers
/// goes. Seeing the END used to end the look at the line, and the next block's body
/// went out as it was.
#[test]
fn blocks_that_meet_on_one_line_are_all_redacted() {
    let chain = "-----BEGIN CERTIFICATE-----\nMIIBcertBody\n\
                 MIIBcertTail==-----END CERTIFICATE----------BEGIN PRIVATE KEY-----\n\
                 MIIEsecretKey\n-----END PRIVATE KEY-----";
    let out = r(chain);
    for leak in ["certBody", "certTail", "secretKey"] {
        assert!(!out.contains(leak), "{leak} leaked: {out}");
    }
    assert!(
        out.contains("-----END CERTIFICATE----------BEGIN PRIVATE KEY-----"),
        "{out}"
    );
    assert!(out.contains("-----END PRIVATE KEY-----"), "{out}");
    assert_eq!(r(&out), out, "not idempotent");

    // Two whole blocks on one line, body between every pair of markers.
    let one_line = "-----BEGIN A-----MIIBfirst-----END A-----\
                    -----BEGIN B-----MIIBsecond-----END B-----";
    let out = r(one_line);
    assert!(!out.contains("first") && !out.contains("second"), "{out}");
    assert!(out.contains("-----BEGIN B-----"), "{out}");
    assert_eq!(r(&out), out, "not idempotent");
}

#[test]
fn idempotent_and_never_panics() {
    let ugly = "$$$ $9$ $9 \"unbalanced secret \n\t{}[]; ## SECRET-DATA\n-----BEGIN X\næøå secret ÆØÅ\n<secret>$9$x</secret>";
    let once = r(ugly);
    let twice = r(&once);
    assert_eq!(once, twice, "redaction is not idempotent");
}

#[test]
fn utf8_is_kept() {
    let line = "set interfaces ge-0/0/1 unit 5 description \"Bodø – Ålesund æøå\"";
    assert_eq!(r(line), line);
}

// ---------------------------------------------------------------------------
// (d) The diff and the drift protection
// ---------------------------------------------------------------------------

/// `extract_compare_diff` hands back the text exactly as it is given. The session
/// redacts the reply before this runs, unless the policy lets secrets through
/// (0.5.11) — so a fresh diff under the same policy reads the same way, and the
/// drift comparison holds in both cases. The function itself changes nothing.
#[test]
fn extract_compare_diff_hands_back_what_it_is_given() {
    let secret_diff = "[edit system login user drift authentication]\n\
-  encrypted-password \"$9$oldHASH\"; ## SECRET-DATA\n\
+  encrypted-password \"$9$newHASH\"; ## SECRET-DATA";
    let xml = format!(
        "<rpc-reply><configuration-information><configuration-output>{}</configuration-output></configuration-information></rpc-reply>",
        secret_diff.replace('<', "&lt;")
    );
    let raw = netconf::rpc::extract_compare_diff(&xml).unwrap();
    assert_eq!(raw, secret_diff, "the function changed the text");
    assert!(raw.contains("oldHASH"));

    // Redaction is its own operation, idempotent, so a reply the session has
    // already redacted comes through it unchanged.
    let shown = redact_secrets(&raw);
    assert!(!shown.contains("oldHASH"));
    assert_ne!(shown, raw);
    assert_eq!(redact_secrets(&shown), shown);
}

/// A diff that carries secrets — as it does under a policy with `allow_secrets` —
/// has a safe `redacted_diff()`, and `has_secrets()` says so; a diff without them
/// is its own redacted diff.
#[test]
fn a_diff_that_carries_secrets_has_a_safe_redacted_diff() {
    use netconf::PreparedChange;
    let c = PreparedChange::from_diff(
        "+  encrypted-password \"$9$secretHASH\"; ## SECRET-DATA".to_string(),
    );
    assert!(c.diff.contains("secretHASH"));
    assert_eq!(c.fingerprint(), c.fingerprint());
    assert!(!c.redacted_diff().contains("secretHASH"));
    assert!(c.has_secrets());

    let clean = PreparedChange::from_diff("+  encapsulation vlan-ccc;".to_string());
    assert!(!clean.has_secrets());
    assert_eq!(clean.redacted_diff(), clean.diff);
}

// ---------------------------------------------------------------------------
// (e) Idempotence and structure, on lines that end in punctuation
// ---------------------------------------------------------------------------

/// **Redaction must be idempotent on ordinary lines, not only on odd ones.**
///
/// The guard against a second pass compared the whole value against `[REDACTED]`,
/// so it missed `[REDACTED];` — and the trailing-punctuation strip then took the
/// `]` off the marker and put it back next to the `;`, giving `[REDACTED]];`. Each
/// further pass added a bracket. Nearly every real configuration line ends in a
/// semicolon, so this was the common case, not the rare one.
#[test]
fn redaction_is_idempotent_on_lines_ending_in_punctuation() {
    for line in [
        "+  encrypted-password \"$9$abc123\";",
        "+  encrypted-password \"$9$abc123\"; ## SECRET-DATA",
        "   authentication-key \"$9$xyz\";",
        "set system radius-server 1.1.1.1 secret \"$9$q\";",
    ] {
        let once = r(line);
        let twice = r(&once);
        let thrice = r(&twice);
        assert_eq!(once, twice, "second pass changed it: {line}");
        assert_eq!(twice, thrice, "third pass changed it: {line}");
        assert!(!once.contains("]]"), "a bracket was duplicated: {once}");
    }
}

/// A secret inside a Junos set keeps the list's structure. The closing bracket is
/// a terminator, not part of the value.
#[test]
fn a_secret_in_a_list_does_not_eat_the_closing_bracket() {
    let out = r("set system login user x authentication ssh-rsa [ \"$9$aaa\" \"$9$bbb\" ]");
    assert!(out.contains(']'), "the closing bracket disappeared: {out}");
    assert!(!out.contains("$9$aaa"), "the first secret survived: {out}");
    assert!(!out.contains("$9$bbb"), "the second secret survived: {out}");
}

/// Same for a comma, on the heuristic path — where there is no known statement
/// name, so only the `$9$` literal itself is replaced and what follows must stay.
#[test]
fn a_hash_literal_before_a_comma_keeps_what_follows() {
    let out = r("some-unknown-field $9$abc,next-field value");
    assert!(out.contains(','), "the comma disappeared: {out}");
    assert!(
        out.contains("next-field"),
        "what followed the comma was eaten: {out}"
    );
    assert!(!out.contains("$9$abc"), "the secret survived: {out}");
}

/// **An attribute on the element must not stop the redaction.**
///
/// The check required the whole tag to be free of whitespace, so any element
/// carrying an attribute was skipped — and Junos annotates freely, marking changed
/// leaves with `junos:changed`. A secret under such a tag went out in full.
#[test]
fn an_attribute_on_the_tag_does_not_protect_the_secret() {
    for line in [
        "<authentication-key junos:changed=\"changed\">hunter2</authentication-key>",
        "<pre-shared-key  format=\"ascii-text\" >hunter2</pre-shared-key>",
        "<nc:encrypted-password xmlns:nc=\"urn:x\">hunter2</nc:encrypted-password>",
    ] {
        let out = r(line);
        assert!(!out.contains("hunter2"), "the secret survived: {out}");
        assert!(out.contains(REDACTED), "nothing was redacted: {out}");
    }
}

/// A self-closing element carries no value, so there is nothing to redact and the
/// line survives unchanged.
#[test]
fn a_self_closing_element_without_attributes_is_untouched() {
    assert_eq!(r("<authentication-key/>"), "<authentication-key/>");
}

/// With an attribute too (0.5.13): a tag is read by the element rules, and a
/// self-closing element carries no value. The statement rule used to take
/// `<authentication-key` for a statement and redact the attribute and the `/>`.
#[test]
fn a_self_closing_element_with_an_attribute_is_untouched() {
    let line = "<authentication-key junos:changed=\"changed\"/>";
    assert_eq!(r(line), line);
}

/// **A secret split across lines must not walk out whole.**
///
/// Redaction works line by line, so a value written as its own line between an
/// opening and a closing tag had no statement name beside it — only the `$9$` and
/// key-blob heuristics could catch it, and a cleartext value matched neither.
#[test]
fn a_multiline_xml_secret_is_redacted() {
    let xml = "<configuration>\n  <authentication-key>\n    hunter2\n  </authentication-key>\n</configuration>";
    let out = r(xml);
    assert!(!out.contains("hunter2"), "the secret survived: {out}");
    assert!(out.contains(REDACTED), "nothing was redacted: {out}");
    // The structure around it is untouched.
    assert!(out.contains("<authentication-key>"), "{out}");
    assert!(out.contains("</authentication-key>"), "{out}");
    assert!(out.contains("<configuration>"), "{out}");
    assert_eq!(
        out.lines().count(),
        xml.lines().count(),
        "the line structure changed"
    );
}

/// The same with a namespace prefix on both tags.
#[test]
fn a_multiline_xml_secret_with_a_prefix_is_redacted() {
    let xml = "<nc:pre-shared-key>\n  hunter2\n</nc:pre-shared-key>";
    let out = r(xml);
    assert!(!out.contains("hunter2"), "the secret survived: {out}");
}

/// A harmless element spanning lines is left alone: the state must only follow a
/// secret statement, not any open tag.
#[test]
fn a_multiline_non_secret_element_is_left_alone() {
    let xml = "<description>\n  a long free-text description\n</description>";
    assert_eq!(r(xml), xml, "an ordinary element was redacted");
}

/// **A child must not close its parent.** The multi-line state remembered which
/// element it was inside, but ended the block on any `</…>` whose text merely
/// CONTAINED that name. A `<key>` was therefore closed by its own
/// `</key-algorithm>` child, and the secret on the next line left the crate in
/// cleartext. The shorter the secret element's name, the more children could end it.
#[test]
fn a_child_closing_tag_does_not_end_the_secret_block() {
    let xml = "<md5>\n<name>1</name>\n<key>\n  <key-algorithm>hmac</key-algorithm>\n  hunter2\n</key>\n</md5>";
    let out = r(xml);
    assert!(!out.contains("hunter2"), "the secret walked out: {out}");
}

/// The same trap one level down, and with the prefixed form the fix must keep
/// supporting: `</nc:authentication-key>` still closes `<nc:authentication-key>`,
/// because both sides are compared on the local name.
#[test]
fn only_the_matching_element_closes_the_block() {
    let nested = "<authentication-key>\n  <key-algorithm>hmac</key-algorithm>\n  hunter2\n</authentication-key>";
    assert!(!r(nested).contains("hunter2"), "{}", r(nested));
    let prefixed = "<nc:authentication-key>\n  hunter2\n</nc:authentication-key>";
    let out = r(prefixed);
    assert!(!out.contains("hunter2"), "the secret survived: {out}");
    assert!(
        out.contains("</nc:authentication-key>"),
        "the closing tag must still be recognised and kept: {out}"
    );
}

/// **The diff marker is a token.** The `## SECRET-DATA` safety net spliced at the
/// second token, which on a compare diff is the STATEMENT NAME rather than the
/// value — so the line came back as `-  [REDACTED];` and the operator could no
/// longer see which field had changed. Hiding the value is the point; hiding what
/// it belongs to is not.
#[test]
fn the_secret_data_net_keeps_the_statement_name_on_a_diff_line() {
    for marker in ["-", "+", "!"] {
        let line = format!("{marker}   custom-auth-field \"topsecret\"; ## SECRET-DATA");
        let out = r(&line);
        assert!(!out.contains("topsecret"), "the value survived: {out}");
        assert!(
            out.contains("custom-auth-field"),
            "the statement name was eaten: {out}"
        );
        assert!(out.trim_start().starts_with(marker), "{out}");
    }
    // And a line with no marker still splices at the value, as it always did.
    let plain = r("    custom-auth-field \"topsecret\"; ## SECRET-DATA");
    assert!(!plain.contains("topsecret"), "{plain}");
    assert!(plain.contains("custom-auth-field"), "{plain}");
}

/// **A list value keeps its own closing bracket.** A secret given as a list —
/// `secret [ "$9$a" "$9$b" ];` — ends in a `]` that belongs to the VALUE, and a `;`
/// that belongs to the statement. The trailing-punctuation strip could not tell
/// them apart, so the `]` was kept as if it were punctuation and the line came out
/// `secret [REDACTED]];`, with one bracket too many.
#[test]
fn a_list_value_does_not_leave_a_stray_bracket() {
    let out = r("secret [ \"$9$abc\" \"$9$def\" ];");
    assert_eq!(out, format!("secret {REDACTED};"), "{out}");
    assert_eq!(r(&out), out, "a second pass must change nothing");
    // A value that is not a list keeps its punctuation, exactly as before.
    assert_eq!(
        r("encrypted-password \"$9$abc\";"),
        format!("encrypted-password {REDACTED};")
    );
}

// ---------------------------------------------------------------------------
// L2-226: the filter, measured (0.5.13)
// ---------------------------------------------------------------------------

/// **An XML element with an attribute, its value on the lines after it, is
/// redacted** (0.5.13), and the XML stays as it was around the value. The segment
/// rule took `<authentication-key` for a statement, cut the line after it — `>`
/// included — and the element rule then found no open tag, so the value went out.
#[test]
fn an_xml_secret_with_an_attribute_and_its_value_on_the_next_line_is_redacted() {
    let xml = "<authentication-key junos:changed=\"changed\">\n  hunter2\n</authentication-key>";
    let out = r(xml);
    assert!(!out.contains("hunter2"), "the secret walked out: {out}");
    assert_eq!(
        out,
        format!(
            "<authentication-key junos:changed=\"changed\">\n  {REDACTED}\n</authentication-key>"
        )
    );
    // The start tag itself cut by the line end, its attribute on the next line.
    let split = "<authentication-key\n   junos:changed=\"changed\">hunter2</authentication-key>";
    assert!(!r(split).contains("hunter2"), "{}", r(split));
    let one_line = "<authentication-key junos:changed=\"changed\">hunter2</authentication-key>";
    assert_eq!(
        r(one_line),
        format!("<authentication-key junos:changed=\"changed\">{REDACTED}</authentication-key>"),
        "the closing tag stays"
    );
}

/// **Text that looks like the marker gets no way round the filter** (0.5.13). A
/// value beginning with the marker was taken for one already redacted, and the
/// `SECRET-DATA` net skipped any line holding the marker.
#[test]
fn text_that_looks_like_the_marker_is_redacted_like_any_other() {
    let spliced = format!("set system radius-server 1.2.3.4 secret {REDACTED}hunter2;");
    let out = r(&spliced);
    assert!(!out.contains("hunter2"), "{out}");
    assert_eq!(
        out,
        format!("set system radius-server 1.2.3.4 secret {REDACTED};")
    );

    let netted = format!("foo \"{REDACTED}\" bar hunter2; ## SECRET-DATA");
    let out = r(&netted);
    assert!(!out.contains("hunter2"), "{out}");
    assert!(out.ends_with("; ## SECRET-DATA"), "{out}");
}

/// **Redaction is idempotent on every path** (0.5.13): a second pass changes
/// nothing, so `contains_secrets` is false on what the filter let out. The `$tag$`
/// path was not — a second pass took `$9$[SENSITIVE:` for a new value and the
/// marker grew.
#[test]
fn redaction_is_idempotent_on_each_rule() {
    let inputs = [
        // `$tag$`, alone and in a statement, and `$sha1$`
        "foo $9$abcDEF bar",
        "foo bar $9$abc; ## SECRET-DATA",
        "set x authentication-key \"$9$abcDEF\";",
        "hash $sha1$12345$salt$hashvalue end",
        // statements in set, text and diff form
        "set system radius-server 1.2.3.4 secret hunter2",
        "+  encrypted-password \"$9$x\"; ## SECRET-DATA",
        "secret [ \"$9$a\" \"$9$b\" ];",
        // the SECRET-DATA net
        "-  unknown-leaf hunter2; ## SECRET-DATA",
        // XML leaf, multi-line, with an attribute
        "<secret>$9$x</secret>",
        "<authentication-key junos:changed=\"changed\">\n  hunter2\n</authentication-key>",
        // PEM and SSH key blobs
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
        "ssh-ed25519 \"AAAAC3NzaC1lZDI1NTE5AAAAIabc\";",
        "key AAAAB3NzaC1yc2EAAAADAQAB end",
        // a URL with a password, and entity-encoded text
        "archive-sites scp://admin:pw123@host/path;",
        "<data>foo &#x24;9&#x24;abcDEF bar</data>",
        "<configuration-text>authentication-&#107;ey &quot;hunter2&quot;;</configuration-text>",
        // a keyword after a control character
        "x \u{7}secret s3cr3t",
        // a marker that makes a word of what it was glued to, or ends a value
        "keyAAAAB3NzaC1,",
        " ## SECRET-DATA$9$key",
        "hunter2$9$policy-options*/key;/*)key—",
    ];
    for input in inputs {
        let once = r(input);
        let twice = r(&once);
        assert_eq!(once, twice, "not idempotent for {input:?}");
        assert!(!contains_secrets(&once), "contains_secrets on {once:?}");
    }
}

/// **A keyword is a keyword whatever is glued to it** (0.5.13): a control
/// character in front of `secret` hid it from the filter.
#[test]
fn a_keyword_glued_to_a_control_character_is_recognised() {
    for line in [
        "x \u{7}secret s3cr3t",
        "x secret\u{7}s3cr3t",
        "x(secret s3cr3t",
    ] {
        let out = r(line);
        assert!(!out.contains("s3cr3t"), "{line:?} gave {out:?}");
    }
}

/// **No entity hides a keyword or a value** (0.5.13). `compare()` redacted the
/// diff after its entities were decoded, while `rpc()`, `get_configuration` and
/// `command` redacted the XML with them still encoded, so `&#x24;9&#x24;` was no
/// `$9$` and `authentication-&#107;ey` no keyword. The filter reads entities as
/// the characters they stand for, and leaves the text it does not redact as it was.
#[test]
fn no_entity_hides_a_keyword_or_a_value() {
    let dollar = "<data>foo &#x24;9&#x24;abcDEF bar</data>";
    let out = r(dollar);
    assert!(!out.contains("abcDEF"), "{out}");
    assert!(
        out.starts_with("<data>foo &#x24;9&#x24;"),
        "the tag stays: {out}"
    );
    assert!(out.ends_with(" bar</data>"), "{out}");

    let keyword =
        "<configuration-text>authentication-&#107;ey &quot;hunter2&quot;;</configuration-text>";
    let out = r(keyword);
    assert!(!out.contains("hunter2"), "{out}");
    assert!(
        out.starts_with("<configuration-text>authentication-&#107;ey "),
        "{out}"
    );

    let untouched = "<description>a &amp; b &lt;c&gt;</description>";
    assert_eq!(
        r(untouched),
        untouched,
        "text with nothing to redact is left as it was"
    );
}

/// **A `$sha1$` hash is redacted** (0.5.13), with no secret's name on the line: the
/// rule took tags of one to three characters, and `sha1` has four.
#[test]
fn a_sha1_hash_is_redacted() {
    let out = r("foo $sha1$12345$abcdefghij bar");
    assert_eq!(out, format!("foo $sha1${REDACTED} bar"));
}

/// **The password in a URL is redacted** (0.5.13) — `scp://admin:pw@host`, an
/// archive site — and the user, the host and the path stay.
#[test]
fn the_password_in_a_url_is_redacted() {
    assert_eq!(
        r("archive-sites scp://admin:pw123@host/path;"),
        format!("archive-sites scp://admin:{REDACTED}@host/path;")
    );
    assert_eq!(
        r("url \"ftp://bob:s3cr3t@10.0.0.1/x\";"),
        format!("url \"ftp://bob:{REDACTED}@10.0.0.1/x\";")
    );
    let no_password = "url \"https://bob@example.net/x\";";
    assert_eq!(r(no_password), no_password);
}

/// **Only a tag as XML writes it is markup** (0.5.13). A statement name in a
/// comment, a CDATA section, a tag that is not well formed, or text that came from
/// `&lt;…&gt;` is a statement name like any other, and its value goes.
#[test]
fn only_a_tag_as_xml_writes_it_is_markup() {
    for line in [
        "<output><![CDATA[set system radius-server 1.1.1.1 secret hunter2]]></output>",
        "<!-- secret hunter2 -->",
        "<output>&lt;x secret hunter2&gt;</output>",
        "<x secret hunter2>",
    ] {
        let out = r(line);
        assert!(!out.contains("hunter2"), "{line:?} gave {out:?}");
    }
}

/// **The filter's output is text the filter leaves alone** (0.5.13), whatever went
/// in. A few thousand inputs are put together from the pieces the rules read —
/// names, values, markup, entities, annotations, the marker, line breaks — by a
/// generator with a fixed seed, so every run reads the same ones. A second pass
/// changes nothing, so `contains_secrets` is false on what the filter gave back,
/// under the default and under `strict()`.
#[test]
fn a_second_pass_changes_nothing_on_generated_input() {
    const PIECES: &[&str] = &[
        "secret",
        "key",
        "password",
        "authentication-key",
        "pre-shared-key",
        "encrypted-password",
        "community",
        "policy-options",
        "hash-key",
        "key-chain",
        "description",
        "set system ",
        "hunter2",
        "x",
        " ",
        "  ",
        "\t",
        "\n",
        ";",
        ",",
        "\"",
        "'",
        "[",
        "]",
        "(",
        ")",
        "{",
        "}",
        "<",
        ">",
        "</",
        "/>",
        "=",
        ":",
        "-",
        "+",
        "!",
        "*",
        "/",
        "/*",
        "*/",
        "##",
        "## SECRET-DATA",
        "SECRET-DATA",
        "$9$",
        "$1$",
        "$sha1$",
        "$junos-x",
        "AAAAB3NzaC1",
        "AAAAC3NzaC1",
        "scp://",
        "://",
        "@",
        "user:",
        "&lt;",
        "&gt;",
        "&amp;",
        "&quot;",
        "&#x24;",
        "&#107;",
        "&#7;",
        "\u{7}",
        "<![CDATA[",
        "]]>",
        "<!--",
        "-->",
        "<?pi ",
        "?>",
        "<x ",
        "<output>",
        "</output>",
        "<secret>",
        "</secret>",
        "<authentication-key junos:changed=\"c\">",
        "</authentication-key>",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        "—",
        "æ",
        REDACTED,
    ];
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let strict = Redactor::strict();
    for _ in 0..4000 {
        let pieces = 2 + (next() % 14) as usize;
        let input: String = (0..pieces)
            .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
            .collect();
        let once = r(&input);
        assert_eq!(
            r(&once),
            once,
            "a second pass changed the output of {input:?}"
        );
        assert!(
            !contains_secrets(&once),
            "contains_secrets on the output of {input:?}"
        );
        let once = strict.redact(&input);
        assert_eq!(
            strict.redact(&once),
            once,
            "strict: a second pass changed {input:?}"
        );
    }
}

/// Each of `inputs` loses `secret`.
fn hides(secret: &str, inputs: &[&str]) {
    for input in inputs {
        let out = r(input);
        assert!(
            !out.contains(secret),
            "«{secret}» survived:\n  in:  {input:?}\n  out: {out:?}"
        );
        assert!(out.contains(REDACTED), "no marker: {out:?}");
    }
}

// ---------------------------------------------------------------------------
// The statements that carry a secret (0.5.13), in set, text and XML format, with
// values in cleartext so that the list, not a net, is what redacts them.
// ---------------------------------------------------------------------------

#[test]
fn the_passwords_of_users_are_redacted() {
    hides(
        "Pw1",
        &[
            "set system root-authentication encrypted-password \"Pw1\"",
            "root-authentication {\n    encrypted-password \"Pw1\";\n}",
            "<root-authentication>\n<encrypted-password>Pw1</encrypted-password>\n</root-authentication>",
            "set system login user u authentication plain-text-password-value \"Pw1\"",
            "challenge-password \"Pw1\";",
        ],
    );
}

#[test]
fn the_authentication_keys_of_protocols_are_redacted() {
    hides(
        "K1",
        &[
            "set protocols bgp group g authentication-key \"K1\"",
            "set protocols isis interface ge-0/0/0.0 level 2 hello-authentication-key \"K1\"",
            "set protocols ospf area 0 interface ge-0/0/0.0 authentication simple-password \"K1\"",
            "set protocols ospf area 0 interface ge-0/0/0.0 authentication md5 1 key \"K1\"",
            "authentication {\n    md5 1 {\n        key \"K1\";\n    }\n}",
            "[edit protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1]\n+      key \"K1\";",
            "<md5>\n<name>1</name>\n<key>K1</key>\n</md5>",
            "<bgp><group><name>g</name><authentication-key>K1</authentication-key></group></bgp>",
        ],
    );
}

#[test]
fn shared_secrets_are_redacted() {
    hides(
        "S1",
        &[
            "set system radius-server 10.0.0.1 secret \"S1\"",
            "set security authentication-key-chains key-chain kc key 0 secret \"S1\"",
            "key 0 {\n    secret \"S1\";\n}",
            "<key>\n<name>0</name>\n<secret>S1</secret>\n</key>",
            "set access profile p client c chap-secret \"S1\"",
            "set access profile p client c pap-password \"S1\"",
            "set access profile p client c l2tp shared-secret \"S1\"",
            "set interfaces pp0 unit 0 ppp-options chap default-chap-secret \"S1\"",
            "set interfaces pp0 unit 0 ppp-options pap local-password \"S1\"",
            "set interfaces pp0 unit 0 ppp-options pap default-pap-password \"S1\"",
            "set event-options policy p then event-script f.slax remote-execution remote-hostname h passphrase \"S1\"",
        ],
    );
}

#[test]
fn pre_shared_keys_are_redacted() {
    hides(
        "P1",
        &[
            "set security ike policy p pre-shared-key ascii-text \"P1\"",
            "pre-shared-key {\n    hexadecimal \"P1\";\n}",
            "<pre-shared-key>\n<ascii-text>P1</ascii-text>\n</pre-shared-key>",
            "set security macsec connectivity-association ca pre-shared-key ckn abcd cak \"P1\"",
            "cak \"P1\";",
        ],
    );
}

#[test]
fn snmp_v3_keys_and_passwords_are_redacted() {
    hides(
        "V1",
        &[
            "set snmp v3 usm local-engine user u authentication-sha authentication-password \"V1\"",
            "set snmp v3 usm local-engine user u authentication-sha authentication-key \"V1\"",
            "set snmp v3 usm local-engine user u privacy-aes128 privacy-password \"V1\"",
            "privacy-aes128 {\n    privacy-key \"V1\";\n}",
            "<authentication-sha>\n<authentication-key>V1</authentication-key>\n</authentication-sha>",
        ],
    );
}

#[test]
fn the_value_of_an_ntp_key_is_redacted() {
    hides(
        "N1",
        &[
            "set system ntp authentication-key 1 type md5 value \"N1\"",
            "authentication-key 1 {\n    type md5;\n    value \"N1\";\n}",
            "<authentication-key>\n<name>1</name>\n<type>md5</type>\n<value>N1</value>\n</authentication-key>",
        ],
    );
}

#[test]
fn the_key_of_a_manual_security_association_is_redacted() {
    hides(
        "M1",
        &[
            "set security ipsec security-association sa manual direction bidirectional authentication key ascii-text \"M1\"",
            "set security ipsec security-association sa manual direction bidirectional encryption key hexadecimal \"M1\"",
            "authentication {\n    key ascii-text \"M1\";\n}",
            "<encryption>\n<key>\n<hexadecimal>M1</hexadecimal>\n</key>\n</encryption>",
        ],
    );
}

#[test]
fn a_password_beside_a_user_or_an_address_is_redacted() {
    hides(
        "W1",
        &[
            "set access profile p client c firewall-user password \"W1\"",
            "set access profile p ldap-options search admin-search password \"W1\"",
            "set forwarding-options dhcp-relay authentication password \"W1\"",
            "set system archival configuration archive-sites \"scp://u@h/p\" password \"W1\"",
            "<archive-sites>\n<name>scp://u@h/p</name>\n<password>W1</password>\n</archive-sites>",
            "set system license autoupdate url \"https://x\" password \"W1\"",
            "set system services dynamic-dns client h password \"W1\"",
            "set security ike gateway g aaa client password \"W1\"",
            "<client>\n<name>h</name>\n<password>W1</password>\n</client>",
            "set system proxy password \"W1\"",
        ],
    );
}

/// **What only looks like a secret goes out as it came in** (0.5.13): a word that
/// holds `key`, `secret` or `password` is no statement from the list, and nor is
/// one of them where it is not the secret leaf.
#[test]
fn what_only_looks_like_a_secret_is_left_alone() {
    for text in [
        "set snmp community public authorization read-only",
        "set forwarding-options hash-key family inet layer-3",
        "set security authentication-key-chains key-chain kc key 0 start-time \"2024-01-01.00:00\"",
        "key-chain kc {\n    key 0 {\n        start-time \"2024-01-01.00:00\";\n    }\n}",
        "<key-chain>\n<name>kc</name>\n<key>\n<name>0</name>\n</key>\n</key-chain>",
        "set protocols bgp group g authentication-key-chain kc",
        "set system license keys key \"JUNOS123\"",
        "set system login user u authentication load-key-file /var/tmp/u.pub",
        "set system services ssh hostkey-algorithm ssh-ed25519",
        "set system services ssh key-exchange curve25519-sha256",
        "set system authentication-order [ radius password ]",
        "set security ike proposal p authentication-method pre-shared-keys",
        "key-type rsa;",
        "set system login password minimum-length 8",
        "set system master-password iteration-count 1000",
        "set system master-password pseudorandom-function hmac-sha2-512",
        "set system login user secret-agent class super-user",
        "<name junos:key=\"key\">ge-0/0/0</name>",
        "    description \"uplink key customer\";",
        "no pinned host key — refusing to authenticate against an unverified device. \
         Use observe_host_key() to fetch the fingerprint for approval first.",
    ] {
        assert_eq!(r(text), text);
    }
}

/// What reads on past a value or a tag (0.5.13), one assert each.
#[test]
fn the_filter_reads_on_past_a_value_and_a_closing_tag() {
    // The net fires when the first secret statement has no value.
    assert!(!r("foo hunter2 secret ## SECRET-DATA").contains("hunter2"));
    // An annotation is a word of its own; inside a quoted value it is the value.
    assert_eq!(r("secret \"a ## b\";"), format!("secret {REDACTED};"));
    // What follows a closing tag on its line is read like any line.
    assert!(
        !r("<authentication-key>\n hunter2\n</authentication-key> secret s3cr3t")
            .contains("s3cr3t")
    );
    // Several secret elements can be open at once, each until its own closing tag.
    assert!(!r(
        "<secret><authentication-key>\n hunter2\n</authentication-key>\n s3cr3t\n</secret>"
    )
    .contains("s3cr3t"));
}

/// **A PEM rule is one rule among the others on its line** (0.5.13): a line that
/// went on past the end of a block went out as it was.
#[test]
fn what_follows_a_pem_block_on_its_line_is_read() {
    let pem = "-----BEGIN CERTIFICATE-----\nMIIabc\n-----END CERTIFICATE----- secret hunter2";
    assert!(!r(pem).contains("hunter2"), "{}", r(pem));
}

/// **A token that authenticates to a service is redacted** (0.5.13), by its exact
/// name; a name that merely holds `token` is no statement.
#[test]
fn tokens_are_redacted() {
    hides(
        "T1",
        &[
            "set services security-intelligence url https://feeds.example.net/api authentication-token \"T1\"",
            "set services example api-token \"T1\"",
            "<example>\n<bearer-token>T1</bearer-token>\n</example>",
        ],
    );
    let bucket = "set class-of-service schedulers s token-bucket 100";
    assert_eq!(r(bucket), bucket);
}
