// SPDX-License-Identifier: MIT OR Apache-2.0
//! **The read filter** — redacting the device's secrets out of configuration and
//! diff text. The behaviour is documented in `docs/Filter.md`.
//!
//! `ConfigPolicy` is the *write* side: what may be CHANGED. This is the *read* side.
//! When we fetch something from the device — a `show | compare` diff, a
//! `get-configuration`, the output of a `command` — the reply can carry **the
//! device's** secrets: `$9$`-obfuscated passwords, SNMP communities, RADIUS and
//! TACACS+ secrets, IPsec and BGP keys, SSH keys, PEM certificates. That text is
//! shown to an operator, stored in an audit trail, and can end up in a log. Without
//! redaction we would leak the equipment's secrets.
//!
//! ## The design choice: conservative, but structure-preserving
//!
//! Redaction replaces the **value**, never the structure. The path, the statement
//! name, the `;`, `{`, `}` and `]`, the `[edit ...]` banners and the Junos annotation
//! `## SECRET-DATA` all remain, so an operator can still read WHAT is changing —
//! just not the secret itself. In doubt we redact **too much** rather than too
//! little.
//!
//! ```text
//! [edit system login user drift authentication]
//! -  encrypted-password "$9$abc123XYZ"; ## SECRET-DATA
//! +  encrypted-password "$9$zyx987ABC"; ## SECRET-DATA
//! ```
//! becomes
//! ```text
//! [edit system login user drift authentication]
//! -  encrypted-password [SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]; ## SECRET-DATA
//! +  encrypted-password [SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]; ## SECRET-DATA
//! ```
//!
//! ## The session applies it to everything it returns (0.5.11)
//!
//! Every reply a [`NetconfSession`](crate::NetconfSession) returns — `show` output,
//! configuration, the compare diff, the raw `rpc` reply — passes this filter before
//! it leaves the crate, unless the session's policy lets the device's secrets
//! through: [`allow_secrets`](crate::policy::ConfigPolicy::allow_secrets), or
//! `all_free`, which redacts nothing. The marker says what was there and how to read
//! it, so an operator sees that a value exists without seeing the value.
//!
//! The drift protection is unaffected: [`confirm_commit`](crate::NetconfSession::confirm_commit)
//! compares a fresh diff with the approved one under the same policy, so both are
//! redacted the same way or neither is. [`PreparedChange::diff`](crate::PreparedChange::diff)
//! is the diff as the policy let it through; under a policy that lets secrets
//! through, [`PreparedChange::redacted_diff`](crate::PreparedChange::redacted_diff) is
//! the one to **show, log and store**, and the crate emits a `secrets_in_diff`
//! warning, never the content. Until 0.5.11 the data was returned raw and the
//! redaction was the consumer's to apply.

/// The text a secret is replaced with. It says that something is there, that it is
/// hidden because it is sensitive, and how to read it (0.5.11; it was `[REDACTED]`).
pub const REDACTED: &str =
    "[SENSITIVE: hidden by netconf — allow_secrets() on the policy shows it]";

/// A statement that carries a secret, as Junos writes it (0.5.13). `docs/Filter.md`
/// lists them with where each is from.
struct Secret {
    /// The statement's name.
    name: &'static str,
    /// When the name alone does not say it: the words that stand right before it in
    /// set and text format, one of these — `*` is any one word, the name of a list
    /// entry. Empty: the name says it wherever it stands.
    after: &'static [&'static [&'static str]],
    /// In XML, the parent elements it carries a secret under, when `after` is not
    /// empty.
    parent: &'static [&'static str],
}

/// A statement whose name alone says that its value is a secret.
const fn named(name: &'static str) -> Secret {
    Secret {
        name,
        after: &[],
        parent: &[],
    }
}

/// **The statements that carry a secret** (0.5.13). A statement is one of these by
/// its exact name, in its context where the name alone does not say it; a word
/// that merely holds `key` or `password` is none of them. Junos marks these leaves
/// `## SECRET-DATA` in text format, and the net reads that mark as well.
const SECRETS: &[Secret] = &[
    named("encrypted-password"),
    named("plain-text-password-value"),
    named("authentication-key"),
    named("hello-authentication-key"),
    named("authentication-password"),
    named("privacy-key"),
    named("privacy-password"),
    named("simple-password"),
    named("pre-shared-key"),
    named("cak"),
    named("secret"),
    named("chap-secret"),
    named("default-chap-secret"),
    named("shared-secret"),
    named("pap-password"),
    named("local-password"),
    named("default-pap-password"),
    named("passphrase"),
    named("challenge-password"),
    // Tokens that authenticate to a service: a feed, an API.
    named("token"),
    named("api-token"),
    named("bearer-token"),
    named("access-token"),
    named("auth-token"),
    named("authentication-token"),
    named("refresh-token"),
    named("oauth-token"),
    // `authentication md5 1 key`, and the key of a manual security association.
    Secret {
        name: "key",
        after: &[&["md5", "*"], &["authentication"], &["encryption"]],
        parent: &["md5", "authentication", "encryption"],
    },
    // The key's form under `pre-shared-key` and under a manual SA's `key`.
    Secret {
        name: "ascii-text",
        after: &[&["pre-shared-key"], &["key"]],
        parent: &["pre-shared-key", "key"],
    },
    Secret {
        name: "hexadecimal",
        after: &[&["pre-shared-key"], &["key"]],
        parent: &["pre-shared-key", "key"],
    },
    // A password of a client, a proxy or an address; `system login password` is
    // the password policy, and no secret.
    Secret {
        name: "password",
        after: &[
            &["firewall-user"],
            &["admin-search"],
            &["authentication"],
            &["proxy"],
            &["client"],
            &["client", "*"],
            &["archive-sites", "*"],
            &["url", "*"],
        ],
        parent: &[
            "firewall-user",
            "admin-search",
            "authentication",
            "proxy",
            "client",
            "archive-sites",
            "url",
        ],
    },
    // `system ntp authentication-key N type T value V`.
    Secret {
        name: "value",
        after: &[
            &["authentication-key", "*", "type", "*"],
            &["authentication-key", "*"],
        ],
        parent: &["authentication-key"],
    },
];

/// Whether `before` ends with the words of `pattern`, `*` matching any one.
fn ends_with(before: &[&str], pattern: &[&str]) -> bool {
    before.len() >= pattern.len()
        && before[before.len() - pattern.len()..]
            .iter()
            .zip(pattern)
            .all(|(b, p)| *p == "*" || b == p)
}

/// The base64 prefixes SSH public keys begin with — the key-type field is part of the
/// blob — so key material is caught even when the statement name does not reveal it.
const SSH_BLOB_PREFIXES: &[&str] = &[
    "AAAAB3NzaC1",  // ssh-rsa / ssh-dss
    "AAAAC3NzaC1",  // ssh-ed25519
    "AAAAE2VjZHNh", // ecdsa-sha2-*
];

/// The redaction engine. [`Default`] redacts everything that is a real secret, but
/// leaves the **SNMP v2c community readable**.
///
/// The fields are private, so new choices can be added without breaking the API.
#[derive(Debug, Clone)]
pub struct Redactor {
    snmp_community: bool,
}

impl Default for Redactor {
    /// SNMP v2c is not sensitive, and it has to remain readable for the people who
    /// use it against the network. The community string is a shared secret, not
    /// something hidden from whoever runs the network — and it is never encrypted on
    /// the wire anyway, so redacting it here would offer false comfort. To hide it as
    /// well, use [`Redactor::strict`].
    fn default() -> Self {
        Redactor::strict().snmp_community_visible()
    }
}

impl Redactor {
    /// The strictest mode: everything that could be a secret is redacted,
    /// **including SNMP community strings**.
    ///
    /// Note that this is *not* the default behaviour — see [`Redactor::default`] and
    /// [`snmp_community_visible`](Self::snmp_community_visible). Use it only where the
    /// community string is to be hidden from the operators as well.
    pub fn strict() -> Self {
        Redactor {
            snmp_community: true,
        }
    }

    /// Leave SNMP community strings readable — **this is the default**.
    ///
    /// SNMP v2c is not sensitive, and it has to remain readable for the people who
    /// query the network with it. Redacting it would make the compare diff useless to
    /// exactly those who need it — and a v2c community is never encrypted on the wire
    /// anyway, so redacting it here offers false comfort.
    ///
    /// It also turns off the false match on BGP's `policy-options community`.
    pub fn snmp_community_visible(mut self) -> Self {
        self.snmp_community = false;
        self
    }

    /// Redact secrets out of configuration, diff or command text.
    /// The line structure — the number of lines, the indentation, the line endings —
    /// is preserved exactly.
    ///
    /// Each line is read with its XML entities as the characters they stand for
    /// (0.5.13), so `&#x24;9&#x24;` is a `$9$` and `authentication-&#107;ey` a
    /// statement name; what is not redacted goes out as it came in, entities and
    /// all. The marker itself gets no treatment of its own: text that looks like it
    /// is redacted like any other.
    ///
    /// A second pass over the filter's own output changes nothing (0.5.13): each
    /// line is read until the rules find nothing more to redact in it, and the
    /// secret elements a line leaves open for the lines after it are read on the
    /// line as it goes out.
    pub fn redact(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut in_pem = false;
        // The names of the secret XML elements we are inside, opened on an earlier
        // line. Redaction is otherwise line by line, so a value written as
        //
        //     <authentication-key>
        //       hunter2
        //     </authentication-key>
        //
        // had no statement name on the line that carried it, and only the `$9$` and
        // key-blob heuristics could catch it. A cleartext value went out whole.
        let mut in_secret_xml: Vec<Open> = Vec::new();
        let mut path = Path::default();
        let mut first = true;
        for raw in text.split('\n') {
            if !first {
                out.push('\n');
            }
            first = false;
            // Preserve CRLF: the \r belongs to the line ending, not to the content.
            let (line, cr) = match raw.strip_suffix('\r') {
                Some(l) => (l, true),
                None => (raw, false),
            };
            let view = View::of(line);
            let doc = self.redact_line(&view, &mut in_pem, &mut in_secret_xml, &path);
            path.advance(&doc);
            doc.render(&view, &mut out);
            if cr {
                out.push('\r');
            }
        }
        out
    }

    /// One line, read until the rules find nothing more to redact in it (0.5.13).
    /// A marker one rule puts in can make a word of what was glued to something
    /// else, or end a value another rule measured, so a single pass could leave a
    /// line that a second pass would still change. The rules are applied again
    /// until they leave the line as it is, and what goes out is a line the filter
    /// leaves alone. It ends: a pass that changes the line takes away at least one
    /// byte of the line's own text, or joins markers into one.
    fn redact_line(
        &self,
        view: &View<'_>,
        in_pem: &mut bool,
        in_secret_xml: &mut Vec<Open>,
        path: &Path,
    ) -> Doc {
        // The secret elements the line opens, as it came (0.5.13): a statement in
        // front of a tag can take it with its value, and the element's value on the
        // lines that follow is carried all the same. On a line inside secret
        // elements, only what follows the closing tags of all of them can open one.
        let mut doc = Doc::new(view);
        let after_closing = in_secret_xml.iter().try_fold(0, |from, o| {
            let at = closing_tag(&doc.text, &o.name)?;
            Some(
                from.max(
                    doc.text[at..]
                        .find('>')
                        .map_or(doc.text.len(), |gt| at + gt + 1),
                ),
            )
        });
        let opened = match after_closing {
            Some(from) => {
                let el = Elements::new(self, path, &doc.text, &doc.literal);
                unclosed_secret_openers(&doc.text, &doc.literal, from, &el)
            }
            None => Vec::new(),
        };
        // The elements the output does not show opening that the line closes, as it
        // came: their closing tags go with the value, so a later pass cannot see them.
        let closed_unshown: Vec<String> = in_secret_xml
            .iter()
            .filter(|o| !o.shown && closing_tag(&doc.text, &o.name).is_some())
            .map(|o| o.name.clone())
            .collect();
        let open = |name: String, shown: bool| Open { name, shown };
        loop {
            let (mut pem, mut xml) = (*in_pem, in_secret_xml.clone());
            let before = doc.text.clone();
            self.apply_rules(&mut doc, &mut pem, &mut xml, &closed_unshown, path);
            if doc.text == before {
                *in_pem = pem;
                // Did this line OPEN secret elements without closing them? Then the
                // value is on the lines that follow, and the state carries into
                // them. Read on the line as it goes out, whichever rules applied,
                // so the filter's own output carries the same state.
                //
                // One whose tag the line no longer shows is carried as well, but
                // the filter's own output cannot carry it: its closing tag goes
                // with the value, as text the output does not mark.
                let el = Elements::new(self, path, &doc.text, &doc.literal);
                let shown = unclosed_secret_openers(&doc.text, &doc.literal, 0, &el);
                xml.extend(
                    opened
                        .into_iter()
                        .filter(|n| !shown.contains(n))
                        .map(|n| open(n, false)),
                );
                xml.extend(shown.into_iter().map(|n| open(n, true)));
                xml.sort_by(|a, b| a.name.cmp(&b.name).then(b.shown.cmp(&a.shown)));
                xml.dedup_by(|a, b| a.name == b.name);
                *in_secret_xml = xml;
                return doc;
            }
        }
    }

    fn apply_rules(
        &self,
        doc: &mut Doc,
        in_pem: &mut bool,
        in_secret_xml: &mut Vec<Open>,
        closed_unshown: &[String],
        path: &Path,
    ) {
        if in_secret_xml.is_empty() {
            self.line_rules(doc, in_pem, path);
            return;
        }
        // Inside secret XML elements opened on an earlier line: everything is the
        // value until their closing tags, whatever it looks like.
        //
        // A closing tag has to NAME its element, and nothing else. Accepting any
        // `</…>` that merely contained the name as a substring let a child close
        // the block: `</key-algorithm>` ended a `<key>`, and the secret on the
        // following line then walked out in cleartext. A prefixed close
        // (`</nc:authentication-key>`) still ends it, because both sides are
        // compared on the local name.
        //
        // When the line closes every one of them the output shows, it is read like
        // any other as well (0.5.13): what followed the closing tag used to go out
        // as it was.
        let open = in_secret_xml.clone();
        if open
            .iter()
            .filter(|o| o.shown)
            .all(|o| closing_tag(&doc.text, &o.name).is_some())
        {
            self.line_rules(doc, in_pem, path);
        }
        // Then the value goes: all but the closing tags, up to the last of them —
        // or to the end of the line while an element stays open. The closing tags
        // stay, so the filter's own output closes what the line closed; that of an
        // element the output does not show opening is part of the value.
        let text = doc.text.clone();
        let mut closing: Vec<(usize, usize, bool)> = open
            .iter()
            .filter_map(|o| closing_tag(&text, &o.name).map(|at| (at, o.shown)))
            .map(|(at, shown)| {
                (
                    at,
                    text[at..].find('>').map_or(text.len(), |gt| at + gt + 1),
                    shown,
                )
            })
            .collect();
        closing.sort_unstable();
        in_secret_xml.retain(|o| {
            if o.shown {
                closing_tag(&text, &o.name).is_none()
            } else {
                !closed_unshown.contains(&o.name)
            }
        });
        let limit = if in_secret_xml.is_empty() {
            closing
                .iter()
                .filter(|c| !c.2)
                .map(|c| c.1)
                .max()
                .unwrap_or(0)
        } else {
            text.len()
        };
        let mut ranges = Vec::new();
        let mut from = text.len() - text.trim_start().len();
        for &(at, end, shown) in &closing {
            if !shown {
                continue;
            }
            if at > from && !text[from..at].trim().is_empty() {
                ranges.push(from..at);
            }
            from = from.max(end);
        }
        if limit > from && !text[from..limit].trim().is_empty() {
            ranges.push(from..limit);
        }
        doc.replace(&ranges);
    }

    /// The rules for a line outside a secret XML element.
    fn line_rules(&self, doc: &mut Doc, in_pem: &mut bool, path: &Path) {
        let line = doc.text.clone();
        let line = line.as_str();

        // Every rule reads the line as this pass found it, and what any of them
        // finds is redacted (0.5.13). One after the other, a rule read the markers
        // the rules before it had put in, and lost what they had taken: the tag of a
        // secret element in a statement's value, say, and with it the rest of the
        // line the element rule would have redacted.

        // 1. PEM blocks — certificates and private keys — which can span several
        //    lines, and several of which can meet on one line. What stands outside
        //    a block on such a line is read by the other rules too (0.5.13): a line
        //    that went on past an `-----END …-----` went out as it was.
        let mut ranges = redact_pem(line, in_pem).unwrap_or_default();

        // 2. Statement-based redaction, in set format and in curly/text format.
        ranges.extend(self.statement_ranges(doc, path));

        // 3. XML leaves (`<secret>…</secret>`) — get-configuration in XML. A tag is
        //    read with its `<` and `>` as the entities decode, and as the line has
        //    them written, and both readings redact.
        let el = Elements::new(self, path, line, &doc.literal);
        ranges.extend(self.xml_leaf_ranges(line, None, &el));
        ranges.extend(self.xml_leaf_ranges(line, Some(&doc.literal), &el));

        // 4. A heuristic whatever the path: the `$9$`, `$8$`, `$6$`, `$5$`, `$1$`,
        //    `$0$` and `$sha1$` literals.
        ranges.extend(dollar_ranges(line));

        // 5. A heuristic that applies whatever the path: SSH key blobs.
        ranges.extend(ssh_blob_ranges(line));

        // 6. The password in a URL: `scp://user:password@host` (0.5.13).
        ranges.extend(url_password_ranges(line));

        // 7. A safety net: Junos marks secret leaves itself with `## SECRET-DATA`
        //    (or `/* SECRET-DATA */`). Unless a secret statement on the line is
        //    written as a word of its own with a value after it — read the way
        //    Junos writes a statement — we may have misread the statement, so the
        //    value is redacted regardless, from the second word on. It fires on what
        //    the line holds, not on whether another rule changed it, so text that
        //    looks like the marker gets no pass (0.5.13; a line holding the marker,
        //    or one another rule had changed, used to be skipped).
        if line.contains("SECRET-DATA") && !self.statement_word_with_value(doc, path) {
            //    A compare diff prefixes the line with its own marker, and that
            //    marker is a word of its own. Splicing at word 1 then cut from the
            //    STATEMENT NAME rather than from the value, so the operator was left
            //    with `-  [REDACTED]; ## SECRET-DATA` and no way to see which field
            //    had changed — in the very diff this crate exists to produce.
            let words = words(doc);
            let value = if words
                .first()
                .is_some_and(|t| matches!(t.text, "+" | "-" | "!"))
            {
                words.get(2)
            } else {
                words.get(1)
            };
            ranges.extend(value.and_then(|t| splice_range(line, t.start)));
        }
        doc.replace(&merged(ranges));
    }

    /// What the statement rule redacts: the value of each secret statement on the
    /// line — everything after its name, to a Junos annotation or the end of the
    /// line.
    ///
    /// The first statement decides what follows it, and that is a security choice:
    /// a secret *value* can itself look like a statement name (`... secret
    /// cleartext-secret`, `... community my-secret-community`). Read as a
    /// statement, the value would pass through unredacted; inside the value of a
    /// statement before it, a name adds nothing. «First» at worst redacts slightly
    /// too much of the rest of the line — which is the right direction to err in.
    /// Past an annotation the line is read on (0.5.13).
    ///
    /// A name is read two ways (0.5.13), and both redact:
    ///
    /// - As a word, the way Junos writes a statement ([`statement_word`]), with the
    ///   words before it on the line and those of the blocks it is in ([`Path`]):
    ///   `key` is a secret after `md5 1`, and not after `key-chain kc`. The value
    ///   begins at the next word.
    /// - Out of a token, from whatever is glued to it that cannot be part of a
    ///   name — a control character, punctuation: `\u{7}secret` and `x(secret` are
    ///   `secret`, and what follows the name is the value. Only a name that says it
    ///   alone is read this way. A quoted token is one name, as written. A name
    ///   with a tag straight after it, `secret<x>`, is the text of an element, and
    ///   has no value.
    ///
    /// A tag as XML writes it ([`tag_at`]) is markup: the element's name in it is
    /// no name out of a token; the element rule reads it. Everything else is text
    /// however it looks: an attribute's name and value, a comment, a CDATA section,
    /// a processing instruction, a tag that is not well formed, and a `<` that came
    /// from `&lt;`.
    fn statement_ranges(&self, doc: &Doc, path: &Path) -> Vec<std::ops::Range<usize>> {
        let line = doc.text.as_str();
        let b = line.as_bytes();
        let toks = tokens(line);
        let notes = annotations(&toks);
        let tags = tags(line, &doc.literal);
        let mut element_name = vec![false; line.len()];
        for g in &tags {
            element_name[g.name.clone()].fill(true);
        }
        let words = words(doc);
        let names = statement_words(doc, &words);
        let in_policy_options = path.in_policy_options(&names);
        let is_name = |k: usize| !element_name[k] && (b[k].is_ascii_alphanumeric() || b[k] == b'-');
        // The tag that begins at `k`.
        let tag_at_k = |k: usize| tags.binary_search_by_key(&k, |g| g.start).is_ok();

        let mut hits = Vec::new();
        let mut before = path.words();
        for (w, name) in words.iter().zip(&names) {
            if self.secret_word(name, &before, in_policy_options) {
                hits.push(Hit {
                    at: w.start,
                    value: w.start + w.text.len(),
                    in_text: false,
                });
            }
            if !name.is_empty() && *name != "!" {
                before.push(name);
            }
        }
        for t in &toks {
            let end = t.start + t.text.len();
            // A quoted token is one name, as written.
            if t.text.starts_with('"') {
                if self.secret_name(normalize(t.text), in_policy_options) {
                    hits.push(Hit {
                        at: t.start,
                        value: end,
                        in_text: false,
                    });
                }
                continue;
            }
            // The names in the token: runs of what a name is made of.
            let mut k = t.start;
            while k < end {
                if !is_name(k) {
                    k += 1;
                    continue;
                }
                let s = k;
                while k < end && is_name(k) {
                    k += 1;
                }
                let name = line[s..k].trim_matches('-');
                if !name.is_empty() && self.secret_name(name, in_policy_options) {
                    hits.push(Hit {
                        at: s,
                        value: k,
                        in_text: true,
                    });
                }
            }
        }
        hits.sort_by_key(|h| h.at);

        // Each statement redacts its own value. One inside the value of a statement
        // before it adds nothing.
        let mut out: Vec<std::ops::Range<usize>> = Vec::new();
        let mut covered = 0..0;
        for h in &hits {
            if covered.contains(&h.at) {
                continue;
            }
            let mut start = h.value;
            while start < line.len() && is_separator(b[start]) {
                start += 1;
            }
            // A name in the text of an element with markup straight after it: the
            // tag ends the text, and the name has no value.
            if h.in_text && tag_at_k(start) {
                continue;
            }
            if let Some(r) = value_range(line, start, next_annotation(&notes, start, line.len())) {
                if r.end > covered.end {
                    covered = r.clone();
                }
                out.push(r);
            }
        }
        merged(out)
    }

    /// Whether a secret statement on the line is written as a word of its own with a
    /// value after it, the way Junos writes a statement: the first such word, and
    /// the word after it up to the first `##` or `/*`. Then the `SECRET-DATA` net
    /// stands down.
    fn statement_word_with_value(&self, doc: &Doc, path: &Path) -> bool {
        let words = words(doc);
        let names = statement_words(doc, &words);
        let in_policy_options = path.in_policy_options(&names);
        let mut before = path.words();
        let mut first = None;
        for (i, name) in names.iter().enumerate() {
            if self.secret_word(name, &before, in_policy_options) {
                first = Some(i);
                break;
            }
            if !name.is_empty() && *name != "!" {
                before.push(name);
            }
        }
        let Some(i) = first else {
            return false;
        };
        words.get(i + 1).is_some_and(|next| {
            let tail = &doc.text[next.start..];
            let cut = [tail.find("##"), tail.find("/*")]
                .into_iter()
                .flatten()
                .min();
            value_range(
                &doc.text,
                next.start,
                cut.map_or(doc.text.len(), |c| next.start + c),
            )
            .is_some()
        })
    }

    /// Whether the word `name`, with the words before it, is a secret statement.
    fn secret_word(&self, name: &str, before: &[&str], in_policy_options: bool) -> bool {
        self.community(name, in_policy_options)
            || SECRETS.iter().any(|s| {
                s.name == name
                    && (s.after.is_empty() || s.after.iter().any(|p| ends_with(before, p)))
            })
    }

    /// Whether the element `name`, under `parent`, is a secret statement.
    fn secret_element(&self, name: &str, parent: Option<&str>, in_policy_options: bool) -> bool {
        let name = name.to_ascii_lowercase();
        self.community(&name, in_policy_options)
            || SECRETS.iter().any(|s| {
                s.name == name
                    && (s.after.is_empty() || parent.is_some_and(|p| s.parent.contains(&p)))
            })
    }

    /// Whether `name` alone, wherever it stands, is a secret statement.
    fn secret_name(&self, name: &str, in_policy_options: bool) -> bool {
        self.community(name, in_policy_options)
            || SECRETS.iter().any(|s| s.name == name && s.after.is_empty())
    }

    /// An SNMP community, under [`strict`](Self::strict). `policy-options community
    /// <name>` is a BGP community name and is not secret, so it is excluded.
    fn community(&self, name: &str, in_policy_options: bool) -> bool {
        self.snmp_community && !in_policy_options && matches!(name, "community" | "community-name")
    }

    /// `<tag>value</tag>` on one line, where `tag` without its namespace prefix is a
    /// secret statement: the value goes, the tags stay.
    ///
    /// With `literal`, only a `<` and `>` the line has as written count.
    fn xml_leaf_ranges(
        &self,
        line: &str,
        literal: Option<&[bool]>,
        el: &Elements<'_>,
    ) -> Vec<std::ops::Range<usize>> {
        let mut out = Vec::new();
        if !line.contains('<') {
            return out;
        }
        let b = line.as_bytes();
        let is = |k: usize, c: u8| b[k] == c && literal.is_none_or(|l| l[k]);
        // The next `>`, and the next `</`, at or after each byte.
        let (mut next_gt, mut next_close) = (vec![None; b.len() + 1], vec![None; b.len() + 1]);
        for k in (0..b.len()).rev() {
            next_gt[k] = if is(k, b'>') { Some(k) } else { next_gt[k + 1] };
            let close = is(k, b'<') && b.get(k + 1) == Some(&b'/');
            next_close[k] = if close { Some(k) } else { next_close[k + 1] };
        }
        let find_close = |from: usize| next_close[from];
        let mut i = 0usize;
        while i < b.len() {
            if is(i, b'<') && i + 1 < b.len() && b[i + 1] != b'/' && b[i + 1] != b'?' {
                if let Some(gt) = next_gt[i] {
                    let raw = &line[i + 1..gt];
                    // The element name is what comes before the first whitespace.
                    // Requiring the whole tag to be whitespace-free skipped every
                    // element carrying an attribute — and Junos annotates freely,
                    // so `<authentication-key junos:changed="changed">` walked
                    // straight through with its value intact.
                    let name = raw.split_whitespace().next().unwrap_or("");
                    if !name.is_empty() && !raw.ends_with('/') {
                        let local = name.rsplit(':').next().unwrap_or(name);
                        if el.secret(local, i) {
                            if let Some(close) = find_close(gt + 1) {
                                if close > gt + 1 {
                                    out.push(gt + 1..close);
                                }
                                i = close;
                                continue;
                            }
                            // Not closed on this line. The following lines are carried
                            // as value (`unclosed_secret_openers`), and so is
                            // whatever already follows the tag here — that part used
                            // to go out as it was.
                            if !line[gt + 1..].trim().is_empty() {
                                out.push(gt + 1..line.len());
                            }
                            return out;
                        }
                    }
                }
            }
            i += utf8_len(b[i]);
        }
        out
    }
}

/// Redact secrets out of configuration or diff text, using the default policy.
///
/// **Use this on everything that is displayed, logged or stored** — never on what is
/// to be hashed for the drift comparison; see the module documentation.
///
/// ```
/// let diff = "+  encrypted-password \"$9$hunter2\"; ## SECRET-DATA";
/// let safe = netconf::redact_secrets(diff);
/// assert!(!safe.contains("hunter2"));
/// assert!(safe.contains("encrypted-password"));
/// ```
pub fn redact_secrets(text: &str) -> String {
    Redactor::default().redact(text)
}

/// Whether the text contains anything [`redact_secrets`] would redact. Used to
/// **warn**, without logging the content, that a diff carries the device's secrets.
pub fn contains_secrets(text: &str) -> bool {
    Redactor::default().redact(text) != text
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A line as the rules read it: its XML entities decoded to the characters they
/// stand for, with where each byte of that text came from in the line (0.5.13).
/// The rules find what to redact in `text`; what they leave goes out as the line
/// had it.
struct View<'a> {
    raw: &'a str,
    text: String,
    /// For each byte of `text`, and one past its end: the offset in `raw` of the
    /// character or entity it came from.
    map: Vec<usize>,
}

impl<'a> View<'a> {
    fn of(raw: &'a str) -> View<'a> {
        if !raw.contains('&') {
            return View {
                raw,
                text: raw.to_string(),
                map: (0..=raw.len()).collect(),
            };
        }
        let mut text = String::with_capacity(raw.len());
        let mut map = Vec::with_capacity(raw.len() + 1);
        let mut i = 0;
        while i < raw.len() {
            let (c, len) = entity_at(raw, i).unwrap_or_else(|| {
                // The line is a `&str`, so there is a character here.
                let c = raw[i..].chars().next().unwrap_or('\u{FFFD}');
                (c, c.len_utf8())
            });
            text.push(c);
            map.extend(std::iter::repeat_n(i, c.len_utf8()));
            i += len;
        }
        map.push(raw.len());
        View { raw, text, map }
    }

    /// The part of the line the bytes `a..b` of `text` came from.
    fn raw_of(&self, a: usize, b: usize) -> &'a str {
        &self.raw[self.map[a]..self.map[b]]
    }
}

/// The XML entity at `i` in `s`, if one begins there: the character it stands for,
/// and its length. The five predefined entities and character references, decimal
/// and hexadecimal.
fn entity_at(s: &str, i: usize) -> Option<(char, usize)> {
    let rest = s[i..].strip_prefix('&')?;
    let semi = rest.find(';').filter(|&n| n <= 10)?;
    let name = &rest[..semi];
    let c = match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let n = name.strip_prefix('#')?;
            let code = match n.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => n.parse::<u32>().ok()?,
            };
            char::from_u32(code)?
        }
    };
    Some((c, semi + 2))
}

/// A line being redacted: its text as the rules see it, and where each byte came
/// from — the view, or the marker a rule put in (0.5.13). The rules work on text
/// and hand back ranges to replace; rendering puts back the line's own text
/// wherever nothing was replaced.
struct Doc {
    text: String,
    from: Vec<Option<usize>>,
    /// For each byte of `text`: whether the line has it as written, rather than
    /// decoded from an entity; the marker counts as written. Markup is read only
    /// where its `<`, `>`, `=` and quotes are written, and words are split only
    /// where the line has whitespace.
    literal: Vec<bool>,
}

impl Doc {
    fn new(view: &View<'_>) -> Doc {
        let (raw, text) = (view.raw.as_bytes(), view.text.as_bytes());
        Doc {
            text: view.text.clone(),
            from: (0..text.len()).map(Some).collect(),
            literal: (0..text.len())
                .map(|i| raw[view.map[i]] == text[i])
                .collect(),
        }
    }

    /// Replace each range of the current text with [`REDACTED`]. The ranges are in
    /// order and do not overlap; an empty one replaces nothing. A range never cuts a
    /// marker in two — one a rule put in, or text that reads as one: it takes the
    /// whole of a marker it reaches into, so a marker is only ever replaced whole,
    /// by itself.
    fn replace(&mut self, ranges: &[std::ops::Range<usize>]) {
        let marks: Vec<usize> = self.text.match_indices(REDACTED).map(|(i, _)| i).collect();
        let inside = |k: usize| {
            let i = marks.partition_point(|&m| m < k);
            i.checked_sub(1)
                .map(|i| marks[i])
                .filter(|&m| k < m + REDACTED.len())
        };
        let mut spans: Vec<std::ops::Range<usize>> = Vec::new();
        for r in ranges.iter().filter(|r| !r.is_empty()) {
            let a = inside(r.start).unwrap_or(r.start);
            let b = inside(r.end).map_or(r.end, |m| m + REDACTED.len());
            match spans.last_mut() {
                Some(last) if a < last.end => last.end = last.end.max(b),
                _ => spans.push(a..b),
            }
        }
        if spans.is_empty() {
            return;
        }
        let mut text = String::with_capacity(self.text.len() + REDACTED.len());
        let mut from = Vec::with_capacity(self.from.len() + REDACTED.len());
        let mut literal = Vec::with_capacity(self.from.len() + REDACTED.len());
        let mut pos = 0;
        for r in &spans {
            text.push_str(&self.text[pos..r.start]);
            from.extend_from_slice(&self.from[pos..r.start]);
            literal.extend_from_slice(&self.literal[pos..r.start]);
            text.push_str(REDACTED);
            from.extend(std::iter::repeat_n(None, REDACTED.len()));
            // The marker reads as it is written, like text that looks like it, so
            // the rules cannot tell the two apart.
            literal.extend(std::iter::repeat_n(true, REDACTED.len()));
            pos = r.end;
        }
        text.push_str(&self.text[pos..]);
        from.extend_from_slice(&self.from[pos..]);
        literal.extend_from_slice(&self.literal[pos..]);
        self.text = text;
        self.from = from;
        self.literal = literal;
    }

    /// The line as it goes out: the line's own text where the view's is kept, the
    /// marker where it was put in.
    fn render(&self, view: &View<'_>, out: &mut String) {
        let mut i = 0;
        while i < self.text.len() {
            match self.from[i] {
                None => {
                    let mut j = i;
                    while j < self.text.len() && self.from[j].is_none() {
                        j += 1;
                    }
                    out.push_str(&self.text[i..j]);
                    i = j;
                }
                Some(v) => {
                    let mut j = i + 1;
                    while j < self.text.len() && self.from[j] == Some(v + (j - i)) {
                        j += 1;
                    }
                    out.push_str(view.raw_of(v, v + (j - i)));
                    i = j;
                }
            }
        }
    }
}

/// The length of the marker if it begins at `i` in `s`. The marker holds spaces; a
/// token, a word, a `$tag$` value, a URL's authority and the attributes of a tag
/// take it as one unit (0.5.13). It earns nothing by that: what follows it is read
/// like any text.
fn marker_at(s: &str, i: usize) -> Option<usize> {
    s.as_bytes()[i..]
        .starts_with(REDACTED.as_bytes())
        .then_some(REDACTED.len())
}

/// The ranges in order, those that overlap or touch joined into one.
fn merged(mut ranges: Vec<std::ops::Range<usize>>) -> Vec<std::ops::Range<usize>> {
    ranges.sort_by_key(|r| r.start);
    let mut out: Vec<std::ops::Range<usize>> = Vec::new();
    for r in ranges.into_iter().filter(|r| !r.is_empty()) {
        match out.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

/// A secret element the lines that follow are inside, and whether the filter's
/// output shows the tag that opened it.
#[derive(Clone)]
struct Open {
    name: String,
    shown: bool,
}

/// A secret statement the statement rule found: where it stands, and where its
/// value begins.
struct Hit {
    at: usize,
    value: usize,
    /// A name read inside a token, rather than a word: a tag straight after it is
    /// not its value.
    in_text: bool,
}

#[derive(PartialEq)]
enum TagKind {
    Start,
    End,
    Empty,
}

/// A well-formed XML tag in the line, its `<`, `>`, `=` and quotes as written.
struct Tag {
    start: usize,
    end: usize,
    name: std::ops::Range<usize>,
    kind: TagKind,
}

/// The well-formed tags in the line, in order.
fn tags(line: &str, literal: &[bool]) -> Vec<Tag> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = line[i..].find('<') {
        match tag_at(line, literal, i + p) {
            Some(t) => {
                i = t.end;
                out.push(t);
            }
            None => i += p + 1,
        }
    }
    out
}

/// The tag that begins at `i`, if a well-formed one does: `<name>`, `</name>` or
/// `<name/>`, with attributes `name="value"` or `name='value'` in a start tag. Its
/// `<`, `>`, `=`, quotes, names and the whitespace between them are as written in
/// the line; an attribute value holds no `<`. The marker may stand where
/// attributes were, so a tag reads the same once they are redacted. Comments, CDATA
/// sections and processing instructions are not tags.
fn tag_at(line: &str, literal: &[bool], i: usize) -> Option<Tag> {
    let b = line.as_bytes();
    let is = |k: usize, c: u8| b.get(k) == Some(&c) && literal[k];
    let space = |mut k: usize| {
        while k < b.len() && literal[k] && matches!(b[k], b' ' | b'\t') {
            k += 1;
        }
        k
    };
    let name = |k: usize| -> Option<usize> {
        let first = |c: u8| c.is_ascii_alphabetic() || matches!(c, b'_' | b':');
        if !(k < b.len() && literal[k] && first(b[k])) {
            return None;
        }
        let mut e = k + 1;
        while e < b.len()
            && literal[e]
            && (first(b[e]) || b[e].is_ascii_digit() || matches!(b[e], b'-' | b'.'))
        {
            e += 1;
        }
        Some(e)
    };
    if !is(i, b'<') {
        return None;
    }
    let end_tag = is(i + 1, b'/');
    let n0 = i + 1 + usize::from(end_tag);
    let n1 = name(n0)?;
    let tag = |end: usize, kind: TagKind| Tag {
        start: i,
        end,
        name: n0..n1,
        kind,
    };
    let mut k = n1;
    // After the marker, which stands where attributes were, the next attribute
    // needs no space in front of it.
    let mut after_marker = false;
    loop {
        let w = space(k);
        if is(w, b'>') {
            let kind = if end_tag {
                TagKind::End
            } else {
                TagKind::Start
            };
            return Some(tag(w + 1, kind));
        }
        if !end_tag && is(w, b'/') && is(w + 1, b'>') {
            return Some(tag(w + 2, TagKind::Empty));
        }
        if end_tag || (w == k && !after_marker) {
            return None;
        }
        if let Some(n) = marker_at(line, w).filter(|_| w > n1) {
            k = w + n;
            after_marker = true;
            continue;
        }
        after_marker = false;
        let eq = space(name(w)?);
        if !is(eq, b'=') {
            return None;
        }
        let q = space(eq + 1);
        let quote = *b.get(q)?;
        if !(literal[q] && matches!(quote, b'"' | b'\'')) {
            return None;
        }
        let mut c = q + 1;
        loop {
            if c >= b.len() || is(c, b'<') {
                return None;
            }
            if is(c, quote) {
                break;
            }
            c += 1;
        }
        k = c + 1;
    }
}

/// What separates tokens: whitespace and the ASCII control characters (0.5.13). A
/// control character glued to a name hid it from the filter.
fn is_separator(c: u8) -> bool {
    c.is_ascii_whitespace() || c.is_ascii_control()
}

struct Tok<'a> {
    text: &'a str,
    start: usize,
}

/// Separator-delimited tokens with their byte positions. A double-quoted sequence
/// is one token, since a value can contain spaces, and so is the marker. With an
/// unbalanced quote the rest of the line becomes one token — conservative, and it
/// never panics.
fn tokens(line: &str) -> Vec<Tok<'_>> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && is_separator(b[i]) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        let mut in_quote = false;
        while i < b.len() {
            if let Some(n) = marker_at(line, i) {
                i += n;
                continue;
            }
            match b[i] {
                b'"' => in_quote = !in_quote,
                c if !in_quote && is_separator(c) => break,
                _ => {}
            }
            i += utf8_len(b[i]);
        }
        out.push(Tok {
            text: &line[start..i],
            start,
        });
    }
    out
}

/// Normalise a token to a statement name: without whatever is not part of a name
/// at either end — quotes, `;{}[],`, a diff or banner marker, a control character.
/// Junos statements are always lower case, so no case conversion happens here.
fn normalize(tok: &str) -> &str {
    tok.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .trim_matches('-')
}

/// The words of the line as Junos writes them: split where the line itself has
/// whitespace, with a double-quoted sequence — its quotes as written — one word, and
/// the rest of the line one word after an unbalanced quote. What an entity stands
/// for separates nothing, and the marker is one word.
fn words(doc: &Doc) -> Vec<Tok<'_>> {
    let (line, b) = (doc.text.as_str(), doc.text.as_bytes());
    let space = |k: usize| doc.literal[k] && b[k].is_ascii_whitespace();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && space(i) {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        let mut in_quote = false;
        while i < b.len() && (in_quote || !space(i)) {
            if let Some(n) = marker_at(line, i) {
                i += n;
                continue;
            }
            if b[i] == b'"' && doc.literal[i] {
                in_quote = !in_quote;
            }
            i += 1;
        }
        // A word ends at whitespace, which is ASCII, so `i` is on a char boundary.
        out.push(Tok {
            text: &line[start..i],
            start,
        });
    }
    out
}

/// A word read as a statement name the way Junos writes one: without its quotes,
/// then `;`, braces, brackets or a comma after it, then a diff marker or an opening
/// bracket in front — each as the line has it written; what an entity stands for
/// is part of the word.
fn statement_word<'a>(doc: &Doc, w: &Tok<'a>) -> &'a str {
    let b = w.text.as_bytes();
    let trims = |k: usize, set: &[u8]| doc.literal[w.start + k] && set.contains(&b[k]);
    let (mut a, mut e) = (0, b.len());
    while a < e && trims(a, b"\"'") {
        a += 1;
    }
    while e > a && trims(e - 1, b"\"'") {
        e -= 1;
    }
    while e > a && trims(e - 1, b";{}[],") {
        e -= 1;
    }
    while a < e && trims(a, b"[+-") {
        a += 1;
    }
    &w.text[a..e]
}

/// The words of the line read as statement names ([`statement_word`]).
fn statement_words<'a>(doc: &Doc, words: &[Tok<'a>]) -> Vec<&'a str> {
    words.iter().map(|w| statement_word(doc, w)).collect()
}

/// What to replace with [`REDACTED`] when the value starts at `start` and runs to
/// the end of the line: the value, but not the trailing punctuation (`;`, `}`,
/// `]`) or the Junos annotation (`## ...` or `/* ... */`) after it, which are the
/// structure an operator reads the diff by. `None` when there is no value.
///
/// A value that is, or begins with, the marker is a value like any other (0.5.13):
/// it used to be taken for one already redacted and left whole, so `secret
/// [marker]hunter2` went out. The marker replacing itself changes nothing, so the
/// filter's own output still passes unchanged.
fn splice_range(line: &str, start: usize) -> Option<std::ops::Range<usize>> {
    // The annotation is a word of its own, as Junos writes it: `## ...` or `/* ...`
    // where a word begins (0.5.13). One glued to the value, or inside a quoted one,
    // is part of the value.
    let notes = annotations(&tokens(line));
    value_range(line, start, next_annotation(&notes, start, line.len()))
}

/// Where the Junos annotations on the line begin: the tokens that begin with `##`
/// or `/*`.
fn annotations(toks: &[Tok<'_>]) -> Vec<usize> {
    toks.iter()
        .filter(|t| t.text.starts_with("##") || t.text.starts_with("/*"))
        .map(|t| t.start)
        .collect()
}

/// The first annotation at or after `start`, or `end`.
fn next_annotation(notes: &[usize], start: usize, end: usize) -> usize {
    notes
        .get(notes.partition_point(|&n| n < start))
        .copied()
        .unwrap_or(end)
}

/// The value from `start` to `cut`, without trailing whitespace and the statement's
/// own closing punctuation. `None` when there is no value.
fn value_range(line: &str, start: usize, cut: usize) -> Option<std::ops::Range<usize>> {
    let value = line[start..cut].trim_end();
    // A `{` at the end opens a block: it is the structure, not the value (0.5.13).
    let stripped = value.trim_end_matches([';', '{', '}', ']', ')']);
    let mut punct = &value[stripped.len()..];
    // A closing bracket that balances an opening one INSIDE the value belongs to the
    // value, not to the statement. A list secret, `[ "$9$a" "$9$b" ];`, ends in a `]`
    // that closes the list and a `;` that ends the statement; keeping the `]` as
    // punctuation gave `[REDACTED]];`. Only as many closers are handed back to the
    // value as it has unmatched openers, so the statement's own punctuation stays.
    for (open, close) in [('[', ']'), ('(', ')'), ('{', '}')] {
        let unmatched = stripped
            .matches(open)
            .count()
            .saturating_sub(stripped.matches(close).count());
        for _ in 0..unmatched {
            match punct.strip_prefix(close) {
                Some(rest) => punct = rest,
                None => break,
            }
        }
    }
    let len = value[..value.len() - punct.len()].trim_end().len();
    (len > 0).then_some(start..start + len)
}

/// PEM blocks — certificates and private keys. Returns what to redact when the
/// line touches PEM at all (it continues a block, or begins one), and `None`
/// otherwise, so the other rules apply.
///
/// The line is walked marker by marker. Inside a block, everything up to an END
/// marker is body; outside one, text is kept up to the next BEGIN marker. Any number
/// of blocks can therefore end and begin on one line — a chain whose newlines were
/// lost, say — and the state carried to the next line is the state at the end of
/// this one. That is what the earlier per-case handling could not do: seeing an END
/// while inside a block, it returned, and a block beginning later on the same line
/// was never noticed, so its body on the following lines went out as it was.
///
/// Markers stay, and so does a plain label. Body text goes wherever on the line it
/// sits. A BEGIN marker without its closing hyphens fails closed: what follows it
/// is taken as body unless it is a plain label.
fn redact_pem(line: &str, in_pem: &mut bool) -> Option<Vec<std::ops::Range<usize>>> {
    const BEGIN: &str = "-----BEGIN";
    const END: &str = "-----END";
    const DASHES: &str = "-----";

    if !*in_pem && !line.contains(BEGIN) {
        return None;
    }
    let mut ranges = Vec::new();
    let mut pos = 0;
    loop {
        let rest = &line[pos..];
        if *in_pem {
            // Inside a block: everything up to the END marker is body.
            let Some(es) = rest.find(END) else {
                push_pem_body(&mut ranges, line, pos, line.len());
                return Some(ranges);
            };
            push_pem_body(&mut ranges, line, pos, pos + es);
            // The END marker runs to its closing hyphens, or to the end of the line.
            let close = rest[es + END.len()..]
                .find(DASHES)
                .map_or(rest.len(), |i| es + END.len() + i + DASHES.len());
            pos += close;
            *in_pem = false;
        } else {
            // Outside a block: text is kept up to the next BEGIN marker.
            let Some(bs) = rest.find(BEGIN) else {
                return Some(ranges);
            };
            let after = bs + BEGIN.len();
            match rest[after..].find(DASHES).map(|i| after + i) {
                // A well-formed marker: its closing hyphens are its own, not the
                // start of an END marker.
                Some(c) if !rest[c..].starts_with(END) => {
                    pos += c + DASHES.len();
                }
                // No closing hyphens before an END marker or the end of the line. A
                // plain label is kept; anything else may be body, and goes.
                c => {
                    let stop = c.unwrap_or(rest.len());
                    if !rest[after..stop].chars().all(is_pem_label_char) {
                        ranges.push(pos + after..pos + stop);
                    }
                    pos += stop;
                }
            }
            *in_pem = true;
        }
    }
}

/// A stretch of PEM body, `start..end` of the line. Indentation, a diff marker or a
/// quote in front of it is kept; the rest is key material and is redacted.
fn push_pem_body(ranges: &mut Vec<std::ops::Range<usize>>, line: &str, start: usize, end: usize) {
    let body = &line[start..end];
    let text = body.trim_start_matches(is_pem_markup);
    if !text.is_empty() {
        ranges.push(end - text.len()..end);
    }
}

/// What may stand in front of PEM body on a line and is not body: indentation, a
/// diff marker, a quote. Base64 never contains any of these.
fn is_pem_markup(c: char) -> bool {
    c.is_whitespace() || matches!(c, '+' | '-' | '!' | '"')
}

/// What a plain PEM label is made of: `RSA PRIVATE KEY`, `CERTIFICATE`.
fn is_pem_label_char(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_whitespace() || c == '"'
}

/// The Junos hash and obfuscation literals (`$9$...`, `$8$...`, `$6$...`, `$5$...`,
/// `$1$...`, `$0$...`, `$2a$...`, `$sha1$...`): the value after `$<tag>$` is
/// redacted, and the tag stays, so an operator can see WHICH form it is. A tag is
/// one to four letters or digits (0.5.13; one to three before, which missed
/// `$sha1$`).
///
/// The `$junos-...` variables used in dynamic profiles are not matched: they have no
/// short alphanumeric tag terminated by `$`.
fn dollar_ranges(s: &str) -> Vec<std::ops::Range<usize>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if let Some(n) = marker_at(s, i) {
            i += n;
            continue;
        }
        if b[i] == b'$' {
            let mut j = i + 1;
            let mut tag_len = 0usize;
            while j < b.len() && tag_len <= 4 && b[j].is_ascii_alphanumeric() {
                j += 1;
                tag_len += 1;
            }
            if (1..=4).contains(&tag_len) && j < b.len() && b[j] == b'$' {
                let mut k = j + 1;
                while k < b.len() {
                    // The marker is one unit of the value, so the filter's own
                    // `$9$` and marker read as one value on a second pass, and are
                    // replaced by the same (0.5.13).
                    if let Some(n) = marker_at(s, k) {
                        k += n;
                        continue;
                    }
                    if matches!(
                        b[k],
                        b' ' | b'\t'
                            | b'"'
                            | b'\''
                            | b';'
                            | b'<'
                            | b'>'
                            | b'\r'
                            | b'}'
                            // Junos writes sets as `[ "$9$a" "$9$b" ]`, and a value
                            // can be followed directly by `]` or `,`. Without these
                            // the closing bracket was swallowed into the secret and
                            // replaced, so the list lost its structure.
                            | b']'
                            | b','
                    ) {
                        break;
                    }
                    k += utf8_len(b[k]);
                }
                if k > j + 1 {
                    out.push(j + 1..k);
                    i = k;
                    continue;
                }
            }
        }
        i += utf8_len(b[i]);
    }
    out
}

/// SSH key blobs — base64 beginning with a known key-type prefix.
fn ssh_blob_ranges(s: &str) -> Vec<std::ops::Range<usize>> {
    let b = s.as_bytes();
    let mut starts: Vec<usize> = SSH_BLOB_PREFIXES
        .iter()
        .flat_map(|p| s.match_indices(p).map(|(i, _)| i))
        .collect();
    starts.sort_unstable();
    let mut out = Vec::new();
    let mut from = 0;
    for pos in starts {
        if pos < from {
            continue;
        }
        let mut end = pos;
        while end < b.len() && is_base64(b[end]) {
            end += 1;
        }
        out.push(pos..end);
        from = end;
    }
    out
}

/// The password in a URL's user information — `scp://user:password@host/path`, an
/// archive site, say (0.5.13). The user, the host and the rest stay.
fn url_password_ranges(s: &str) -> Vec<std::ops::Range<usize>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(p) = s[from..].find("://") {
        let auth = from + p + 3;
        // The authority runs to the path, a separator, or what cannot be in it.
        let mut end = auth;
        while end < b.len() {
            if let Some(n) = marker_at(s, end) {
                end += n;
                continue;
            }
            if is_separator(b[end])
                || matches!(
                    b[end],
                    b'/' | b'"' | b'\'' | b';' | b'<' | b'>' | b'{' | b'}' | b',' | b'?' | b'#'
                )
            {
                break;
            }
            end += utf8_len(b[end]);
        }
        if let Some(at) = s[auth..end].rfind('@') {
            if let Some(colon) = s[auth..auth + at].find(':') {
                if colon + 1 < at {
                    out.push(auth + colon + 1..auth + at);
                }
            }
        }
        from = end.max(auth);
    }
    out
}

/// Where the first closing tag of the element `tag` (a local name) begins.
fn closing_tag(line: &str, tag: &str) -> Option<usize> {
    line.match_indices("</")
        .find(|(i, _)| closing_local_name(&line[*i..]).is_some_and(|n| n == tag))
        .map(|(i, _)| i)
}

/// The local element name of a closing tag at the start of `s`, with any namespace
/// prefix removed: `</nc:authentication-key>` names `authentication-key`. Returns
/// `None` if `s` does not begin a well-formed closing tag.
fn closing_local_name(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("</")?;
    let end = rest.find('>')?;
    let name = rest[..end].trim();
    if name.is_empty() {
        return None;
    }
    Some(name.rsplit(':').next().unwrap_or(name))
}

/// The local names of the secret elements this line opens and does not close,
/// from `from` on.
///
/// `<authentication-key>` on its own line means the value is on the next ones, with
/// no statement name to recognise it by. The local names are returned so the
/// closing tags can be matched, prefix or not. A tag is read as XML writes it, and
/// the last `<` on the line also as loosely as before.
fn unclosed_secret_openers(
    line: &str,
    literal: &[bool],
    from: usize,
    el: &Elements<'_>,
) -> Vec<String> {
    let mut out = secret_openers(line, el);
    for literal in [None, Some(literal)] {
        out.extend(last_tag_opener(line, literal, el));
        out.extend(first_loose_opener(line, literal, el));
    }
    out.into_iter()
        .filter(|&(at, _)| at >= from)
        .map(|(_, name)| name)
        .collect()
}

/// The first `<` on the line read loosely, as the element rule reads it, that names
/// a secret element and has no `</` after it: the element rule takes the rest of
/// the line as its value. With `literal`, only a `<` and `>` the line has as
/// written count.
fn first_loose_opener(
    line: &str,
    literal: Option<&[bool]>,
    el: &Elements<'_>,
) -> Option<(usize, String)> {
    let b = line.as_bytes();
    let is = |k: usize, c: u8| b[k] == c && literal.is_none_or(|l| l[k]);
    let (mut next_gt, mut close_after) = (vec![None; b.len() + 1], vec![false; b.len() + 1]);
    for k in (0..b.len()).rev() {
        next_gt[k] = if is(k, b'>') { Some(k) } else { next_gt[k + 1] };
        close_after[k] = close_after[k + 1] || (is(k, b'<') && b.get(k + 1) == Some(&b'/'));
    }
    (0..b.len()).find_map(|i| {
        if !is(i, b'<') || matches!(b.get(i + 1), None | Some(b'/' | b'?')) {
            return None;
        }
        let gt = next_gt[i]?;
        let raw = &line[i + 1..gt];
        let name = raw.split_whitespace().next()?;
        let local = name.rsplit(':').next().unwrap_or(name);
        (!raw.ends_with('/') && el.secret(local, i) && !close_after[gt])
            .then(|| (i, local.to_string()))
    })
}

/// The start tags of secret elements, their names XML names, with no closing tag
/// of their own after them on the line. A start tag the line ends inside, its
/// attributes going on on the next line, is one too: its value is there.
fn secret_openers(line: &str, el: &Elements<'_>) -> Vec<(usize, String)> {
    let b = line.as_bytes();
    // The next `>` at or after each byte, and where each element is last closed.
    let mut next_gt = vec![b.len(); b.len() + 1];
    for k in (0..b.len()).rev() {
        next_gt[k] = if b[k] == b'>' { k } else { next_gt[k + 1] };
    }
    let mut last_close: Vec<(&str, usize)> = line
        .match_indices("</")
        .filter_map(|(i, _)| closing_local_name(&line[i..]).map(|n| (n, i)))
        .collect();
    last_close.sort_unstable();
    let closed_after = |name: &str, at: usize| {
        let i = last_close.partition_point(|&(n, _)| n <= name);
        i.checked_sub(1)
            .is_some_and(|i| last_close[i].0 == name && last_close[i].1 > at)
    };
    let mut out = Vec::new();
    for (open, _) in line.match_indices('<') {
        let rest = &line[open + 1..];
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '-')))
            .unwrap_or(rest.len());
        let name = &rest[..name_len];
        let after = rest[name_len..].chars().next();
        if !name.starts_with(|c: char| c.is_ascii_alphabetic() || matches!(c, '_' | ':'))
            || !after.is_none_or(|c| c.is_whitespace() || matches!(c, '>' | '/'))
        {
            continue;
        }
        let local = name.rsplit(':').next().unwrap_or(name);
        if !el.secret(local, open) {
            continue;
        }
        let gt = next_gt[open];
        // Self-closing: no value follows. Closed again on this same line: there is
        // nothing to carry.
        if gt < b.len() && (line[..gt].ends_with('/') || closed_after(local, gt)) {
            continue;
        }
        out.push((open, local.to_string()));
    }
    out
}

/// The last `<` on the line, read loosely: its name is what follows it up to
/// whitespace, when that names a secret element and nothing closes after it. With
/// `literal`, the tag ends at a `>` the line has as written.
fn last_tag_opener(
    line: &str,
    literal: Option<&[bool]>,
    el: &Elements<'_>,
) -> Option<(usize, String)> {
    let open = line.rfind('<')?;
    if line[open..].starts_with("</") {
        return None;
    }
    let gt =
        (open..line.len()).find(|&k| line.as_bytes()[k] == b'>' && literal.is_none_or(|l| l[k]))?;
    let raw = &line[open + 1..gt];
    if raw.ends_with('/') {
        return None;
    }
    let name = raw.split_whitespace().next()?;
    let local = name.rsplit(':').next().unwrap_or(name);
    if !el.secret(local, open) || line[gt..].contains("</") {
        return None;
    }
    Some((open, local.to_string()))
}

/// Where a line stands (0.5.13): the XML elements open where it begins, and the
/// text-format blocks — or the `[edit …]` banner of a diff — it is inside. Read on
/// the lines as they go out, so the filter's own output stands where the line did.
#[derive(Clone, Default)]
struct Path {
    xml: Vec<String>,
    text: Vec<Vec<String>>,
}

impl Path {
    /// The words of the blocks the line is inside, outermost first.
    fn words(&self) -> Vec<&str> {
        self.text.iter().flatten().map(String::as_str).collect()
    }

    /// Whether the line is under `policy-options`, where `community` is a BGP
    /// community name and no secret: in the blocks or elements it is inside, or by
    /// the word `policy-options` on the line, its `names`.
    fn in_policy_options(&self, names: &[&str]) -> bool {
        names.contains(&"policy-options")
            || self.xml.iter().any(|n| n == "policy-options")
            || self.text.iter().flatten().any(|w| w == "policy-options")
    }

    /// Step past `doc`, a line as it goes out.
    fn advance(&mut self, doc: &Doc) {
        for g in tags(&doc.text, &doc.literal) {
            step(&mut self.xml, &doc.text, &g);
        }
        let trimmed = doc.text.trim();
        if let Some(banner) = trimmed
            .strip_prefix("[edit")
            .and_then(|b| b.strip_suffix(']'))
        {
            self.text = vec![banner.split_whitespace().map(String::from).collect()];
            return;
        }
        let words = words(doc);
        let mut header = Vec::new();
        for (w, name) in words.iter().zip(statement_words(doc, &words)) {
            if !name.is_empty() && name != "!" {
                header.push(name.to_string());
            }
            if w.text.ends_with('{') {
                self.text.push(std::mem::take(&mut header));
            } else if w.text.ends_with('}') || w.text.ends_with("};") {
                self.text.pop();
                header.clear();
            } else if w.text.ends_with(';') {
                header.clear();
            }
        }
    }
}

/// `stack`, the elements open, past the tag `g` of `line`.
fn step(stack: &mut Vec<String>, line: &str, g: &Tag) {
    let name = &line[g.name.clone()];
    let local = name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase();
    match g.kind {
        TagKind::Start => stack.push(local),
        TagKind::End => {
            if let Some(i) = stack.iter().rposition(|n| *n == local) {
                stack.truncate(i);
            }
        }
        TagKind::Empty => {}
    }
}

/// What the element rules know of a line: the element each position of it is in,
/// from the elements open where it begins and the tags on it as XML writes them.
struct Elements<'a> {
    redactor: &'a Redactor,
    starts: Vec<usize>,
    parents: Vec<Option<String>>,
    in_policy_options: bool,
}

impl<'a> Elements<'a> {
    fn new(redactor: &'a Redactor, path: &Path, line: &str, literal: &[bool]) -> Elements<'a> {
        let mut stack = path.xml.clone();
        let (mut starts, mut parents) = (Vec::new(), Vec::new());
        for g in tags(line, literal) {
            starts.push(g.start);
            parents.push(stack.last().cloned());
            step(&mut stack, line, &g);
        }
        parents.push(stack.last().cloned());
        Elements {
            redactor,
            starts,
            parents,
            in_policy_options: path.in_policy_options(&[]),
        }
    }

    /// Whether the element `name`, whose tag begins at `at`, is a secret statement.
    fn secret(&self, name: &str, at: usize) -> bool {
        let parent = self.parents[self.starts.partition_point(|&s| s < at)].as_deref();
        self.redactor
            .secret_element(name, parent, self.in_policy_options)
    }
}

fn is_base64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}
