// SPDX-License-Identifier: MIT OR Apache-2.0
//! XML entity resolution on the way IN.
//!
//! Escaping on the way out is covered elsewhere: a payload containing `&` is
//! checked to leave as `&amp;`. Nothing covered the other direction, and the
//! other direction is the one that reads bytes from a device we do not control.
//!
//! It matters most in the compare diff. That text is hashed to decide whether
//! the candidate configuration drifted between review and commit. If an entity
//! resolved one way in the first comparison and another way in the second, the
//! crate would either refuse a change that was fine or accept one that was not —
//! and it is the same function behind all three parsers, so a fault here appears
//! in the hello exchange and in error messages too.
//!
//! The resolver is private, which is correct; these go through the three public
//! entry points that use it.

use netconf::rpc::{extract_compare_diff, parse_hello_capabilities, parse_rpc_reply};

fn compare_reply(body: &str) -> String {
    format!(
        "<rpc-reply><configuration-information><configuration-output>{body}\
         </configuration-output></configuration-information></rpc-reply>"
    )
}

/// The five named entities XML defines. A diff that mentions a range, an
/// attribute or a quoted description carries them routinely.
#[test]
fn the_named_entities_resolve_in_a_compare_diff() {
    let xml = compare_reply(
        "+  description &quot;A &amp; B&quot;\n\
         +  filter &lt;inet&gt;\n\
         +  note &apos;done&apos;",
    );
    let got = extract_compare_diff(&xml).expect("the diff must parse");
    assert!(
        got.contains("\"A & B\""),
        "quot and amp did not resolve: {got}"
    );
    assert!(got.contains("<inet>"), "lt and gt did not resolve: {got}");
    assert!(got.contains("'done'"), "apos did not resolve: {got}");
    assert!(
        !got.contains("&amp;"),
        "an entity survived unresolved: {got}"
    );
}

/// Numeric character references are the other form the same function handles.
#[test]
fn numeric_character_references_resolve_too() {
    let got = extract_compare_diff(&compare_reply("+  label &#65;&#x42;")).expect("must parse");
    assert!(
        got.contains("AB"),
        "decimal and hex refs did not resolve: {got}"
    );
}

/// **Fail-closed.** An entity we do not know is a protocol deviation, not
/// something to guess at. Passing it through unresolved would put a literal
/// `&whatever;` into the text the drift hash is taken over, and dropping it
/// silently would change the diff without saying so.
#[test]
fn an_unknown_entity_is_refused_rather_than_guessed_at() {
    let err = extract_compare_diff(&compare_reply("+  description &nbsp;"))
        .expect_err("an unknown entity must not be accepted");
    let s = err.to_string();
    assert!(
        s.starts_with("protocol:"),
        "it is a protocol deviation: {s}"
    );
    assert!(s.contains("nbsp"), "the message must name the entity: {s}");
}

/// The same resolver runs while reading an error message, so a device that
/// explains itself with an escaped character is still understood.
#[test]
fn entities_resolve_inside_a_device_error_message() {
    let xml = "<rpc-reply><rpc-error>\
               <error-tag>operation-failed</error-tag>\
               <error-message>interface &lt;ge-0/0/1&gt; is down &amp; unusable</error-message>\
               </rpc-error></rpc-reply>";
    let err = parse_rpc_reply(xml).expect_err("an rpc-error must be an error");
    let s = err.to_string();
    assert!(s.contains("<ge-0/0/1>"), "lt and gt did not resolve: {s}");
    assert!(s.contains("down & unusable"), "amp did not resolve: {s}");
}

/// And while reading the hello, which is the very first thing a device sends.
#[test]
fn entities_resolve_in_a_capability_string() {
    let xml = "<hello><capabilities>\
               <capability>urn:example:cap?a=1&amp;b=2</capability>\
               </capabilities></hello>";
    let caps = parse_hello_capabilities(xml).expect("hello must parse");
    assert!(
        caps.iter().any(|c| c == "urn:example:cap?a=1&b=2"),
        "amp did not resolve in the capability: {caps:?}"
    );
}
