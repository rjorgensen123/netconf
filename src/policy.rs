// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ConfigPolicy` — the built-in configuration filter. The behaviour is documented
//! in `docs/Filter.md`.
//!
//! The model is **WHAT × WHERE**. Each rule says «in this place (WHERE) these
//! operations (WHAT) are permitted». Everything else is refused: **default-deny**.
//! On top of that sits an **absolute floor**: `delete` of a protected top-level tree
//! is refused under every policy but `all_free`, the one policy that may delete
//! everything on the device, a top-level tree included.
//!
//! The filter is *generic*. It is expressed over configuration paths and operations,
//! never over what those changes mean to the caller. This crate owns the mechanism
//! and the floor; the consumer hardcodes the concrete modes it wants.
//!
//! **Operation classes:** every Junos set-format verb maps to one of two classes —
//! `Set` for add-or-modify, `Delete` for remove. [`verb_class`] does the mapping, and
//! an **unknown verb is refused** (fail-closed) rather than let past. Enforcement
//! runs against a list of [`Change`]; a set payload is parsed with
//! [`parse_set_payload`], which fails if a line has an unknown verb, an unbalanced
//! quote or a control character. Parsing and sending must never diverge — that gap
//! is the bypass surface.
//!
//! **The four kinds of policy.** The ordinary one, [`ConfigPolicy::with_default_floor`]
//! (or [`new`](ConfigPolicy::new) with a floor of one's own), is the rules, the floor
//! and the grants. [`ConfigPolicy::read_only`] is its reading side alone: `show` and
//! configuration reads, and no command and no change whatever is granted.
//! [`ConfigPolicy::all_free`] enforces ONLY the access level (ro/rw/rwd), on any path
//! — «read, write or delete anything», with no scope check and no floor: the filter
//! is off, deliberately. [`ConfigPolicy::all_deny`] permits nothing at all, and is
//! what a session without a bound policy has (0.5.11): the consumer defines the policy
//! it uses, and until it does, netconf does nothing on its behalf.

/// An operation on a configuration path — an access class; see [`verb_class`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// The add-or-modify class: `set`, `insert`, `copy`, `replace`, `annotate`,
    /// `activate`, `protect`. Requires at least `Rw`.
    Set,
    /// The remove class: `delete`, `deactivate`, `wildcard delete`, `unprotect`,
    /// `rename`. Requires `Rwd`. `deactivate` removes the *effect* of configuration
    /// and so counts as a removal; `unprotect` is a precondition for deleting
    /// protected configuration; `rename` removes its source (0.5.13).
    Delete,
}

/// Map a Junos set-format verb to its access class. `None` means an **unknown verb**,
/// which must always be refused — fail-closed. The verb list is checked against the
/// Junos and Junos Evo documentation for modifying a device's configuration.
/// `wildcard delete`, which is two tokens, is handled in [`parse_set_payload`].
///
/// `edit` is **not** a verb here (0.5.7): it moves the context the following lines
/// are read in, and the filter reads every line as a full path, so it would judge a
/// path the device never touches. It is refused like any unknown verb.
///
/// `rename` and `copy` have a filter of their own in [`parse_set_payload`]
/// (0.5.13): `rename` is a `Delete` of its source and a `Set` of its target, `copy`
/// a `Set` of its target; the class here is the stricter of what each does.
pub fn verb_class(verb: &str) -> Option<Op> {
    match verb {
        "set" | "insert" | "copy" | "replace" | "annotate" | "activate" | "protect" => {
            Some(Op::Set)
        }
        "delete" | "deactivate" | "unprotect" | "rename" => Some(Op::Delete),
        _ => None,
    }
}

/// One configuration change: an operation plus a hierarchical path of tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The operation.
    pub op: Op,
    /// The path tokens, for example `["interfaces","ge-0/0/1","unit","123"]`.
    pub path: Vec<String>,
}

/// How a rule path matches a change path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// Exactly this node — the same length.
    Node,
    /// Strictly *below* the node: the change path is longer than the rule path, with
    /// the same prefix.
    Subtree,
}

/// The access level of a [`Scope`] grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read only: no change grants at all.
    Ro,
    /// Read, plus `set` and modify.
    Rw,
    /// Read, plus `set` and `delete`.
    Rwd,
}

impl Access {
    /// Whether this access level permits a given operation class.
    /// `Ro` permits nothing, `Rw` permits `Set`, `Rwd` permits `Set` and `Delete`.
    pub fn permits(self, op: Op) -> bool {
        match self {
            Access::Ro => false,
            Access::Rw => op == Op::Set,
            Access::Rwd => true,
        }
    }
}

/// A generic, reusable **scope vocabulary** — named after *where* in the
/// configuration tree it sits, structurally, and never after *why* a caller wants it.
/// The name has to outlive consumers with other purposes. The behaviour is documented
/// in `docs/Filter.md`. `#[non_exhaustive]`: extended as needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// Logical units: `interfaces * unit *` and below. `Rwd` permits deleting **the
    /// whole unit node**, as when decommissioning one.
    LogicalUnits,
    /// Interface descriptions: `interfaces * description` and
    /// `interfaces * unit * description`.
    InterfaceDescriptions,
    /// Below `protocols *`. `Rwd` permits deleting **below** a protocol, but **never
    /// the protocol node itself**, which is shared with other services.
    Protocols,
}

/// One path token in a rule pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pat {
    Lit(String),
    Star,
}

/// One allow rule: `WHERE (a pattern plus a match kind) → the permitted WHAT (ops)`.
///
/// **Readable:** the crate can *answer* what a filter permits, so a consumer can build
/// a dynamic rule system and choose a filter per task while this crate carries out
/// the choice. Rules are still built only through
/// [`ConfigPolicy::allow`] and [`ConfigPolicy::grant`]; this is the reading side.
#[derive(Debug, Clone)]
pub struct Rule {
    pattern: Vec<Pat>,
    m: Match,
    ops: Vec<Op>,
}

impl Rule {
    /// The path pattern as it was given to [`ConfigPolicy::allow`] (for example
    /// `"interfaces * unit *"`).
    pub fn pattern(&self) -> String {
        self.pattern
            .iter()
            .map(|p| match p {
                Pat::Lit(s) => s.as_str(),
                Pat::Star => "*",
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The match type: node, or subtree.
    pub fn match_kind(&self) -> Match {
        self.m
    }

    /// The operations the rule permits in that place.
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }
}

/// Top-level trees protected against `delete` and `deactivate` of **themselves** —
/// the whole tree. This is the absolute floor. A bare `delete <tree>` tears out
/// something that leaves the device unreachable or unmanageable. Checked against the
/// Juniper hierarchies across the platform range: the hard core, plus the
/// context-dependent ones such as class-of-service and forwarding.
pub const DEFAULT_PROTECTED_ROOTS: &[&str] = &[
    "system",
    "interfaces",
    "chassis",
    "vmhost",
    "protocols",
    "routing-options",
    "routing-instances",
    "security", // zones, policies and flow: without them the device drops all traffic
    "groups",
    "apply-groups",
    "class-of-service",
    "policy-options",
    "firewall",
    "snmp",
    "services",
    "forwarding-options",
    "vlans",
    "bridge-domains",
    "access",
    // 0.5.13
    "logical-systems",
    "tenants",
    "virtual-chassis",
    "multi-chassis",
    "fabric",
    "dynamic-profiles",
    "accounting-options",
];

/// The trees that hold a configuration of the same kind as the top level, one per
/// name (0.5.13): what stands under `logical-systems <name>` is judged as it would
/// be at the top level, by the floor, the rules and the read grants.
pub(crate) const NESTED_CONFIGURATIONS: &[&str] = &["logical-systems", "tenants"];

/// Whether `token` names a [`NESTED_CONFIGURATIONS`] tree; case-insensitive, as
/// the floor is.
fn is_nested_configuration(token: &str) -> bool {
    NESTED_CONFIGURATIONS
        .iter()
        .any(|n| n.eq_ignore_ascii_case(token))
}

/// Known top-level `[edit]` hierarchies — the union across the platform range, both
/// classic Junos and Evo.
///
/// **The policy engine does not consult this.** Enforcement is default-deny, which
/// refuses an unknown top-level token because no rule permits it, not because the
/// token is absent from a list. The table is offered to consumers that want to tell
/// «a hierarchy I did not grant» apart from «a hierarchy that does not exist», for
/// instance to log the second differently — a distinction default-deny cannot make
/// on its own, since it refuses both the same way.
///
/// The real set is DYNAMIC per device and release; `[edit] ?` on the box is the only
/// complete answer. This is therefore an extensible allowlist, not a fixed truth.
pub const KNOWN_TOP_LEVEL_HIERARCHIES: &[&str] = &[
    "system",
    "interfaces",
    "chassis",
    "routing-options",
    "routing-instances",
    "protocols",
    "policy-options",
    "firewall",
    "firewall-options",
    "class-of-service",
    "forwarding-options",
    "snmp",
    "accounting-options",
    "access",
    "groups",
    "apply-groups",
    "apply-groups-except",
    "apply-flags",
    "apply-path",
    "security",
    "event-options",
    "dynamic-profiles",
    "applications",
    "services",
    "logical-systems",
    "tenants",
    "bridge-domains",
    "vlans",
    "switch-options",
    "poe",
    "virtual-chassis",
    "fabric",
    "multi-chassis",
    "vmhost",
    "diameter",
    "jsrc",
    "unified-edge",
    "smtp",
    "provider",
    "schedulers",
    "security-intelligence",
    "health-monitor",
    "protection-group",
    "routing",
];

/// Whether a top-level token is a known Junos hierarchy — see
/// [`KNOWN_TOP_LEVEL_HIERARCHIES`].
pub fn is_known_top_level(token: &str) -> bool {
    KNOWN_TOP_LEVEL_HIERARCHIES.contains(&token)
}

/// Configuration trees that are **sensitive to READ**: they carry authentication
/// secrets and key material — `$9$` passwords, RADIUS and TACACS secrets, IKE keys,
/// templated secrets in groups, script credentials. Reading is otherwise open by
/// default, but these require an explicit read grant
/// ([`ConfigPolicy::allow_read`]). It applies both to `get_configuration` and to
/// `show configuration ...` as an operational command.
///
/// `snmp` is deliberately absent: a v2c community is not sensitive in this sense.
/// `protocols` and `interfaces` are deliberately absent too — they are the working
/// area, and any `$9$` content in their output is handled by the redaction layer.
pub const SENSITIVE_READ_ROOTS: &[&str] = &[
    "system",
    "security",
    "access",
    "groups",
    "apply-groups",
    "event-options",
];

/// A policy violation: which change, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The change that was refused.
    pub change: Change,
    /// A human-readable reason.
    pub reason: String,
}

/// How a policy decides — one of the four kinds, see the constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The rules, the floor and the grants: `new`, `with_default_floor`.
    Rules,
    /// `read_only`: the rules' reading side — reads, `show` and the read grants —
    /// and no change and no other command, whatever is granted.
    ReadOnly,
    /// `all_free(access)`: the access level alone. The filter is off.
    AllFree(Access),
    /// `all_deny`: nothing. What a session without a bound policy has.
    AllDeny,
}

/// A configuration policy: the absolute floor (`protected_roots`) plus allow rules,
/// with default-deny. In **all-free mode** ONLY the access level is enforced — no
/// scope rules and no floor; in **all-deny mode** nothing is permitted at all.
#[derive(Debug, Clone)]
pub struct ConfigPolicy {
    protected_roots: Vec<String>,
    rules: Vec<Rule>,
    mode: Mode,
    /// Sensitive trees explicitly granted for READING.
    read_allows: Vec<String>,
    /// Operational commands beyond `show` that have been explicitly granted
    /// — token prefixes, for example `"request system reboot"`.
    command_allows: Vec<String>,
    /// Whether the device's secrets come through in what the session returns.
    allow_secrets: bool,
}

impl ConfigPolicy {
    /// A new policy with the given floor of protected top-level trees, and no allow
    /// rules yet.
    pub fn new(protected_roots: &[&str]) -> Self {
        ConfigPolicy {
            protected_roots: protected_roots.iter().map(|s| s.to_string()).collect(),
            rules: Vec::new(),
            mode: Mode::Rules,
            read_allows: Vec::new(),
            command_allows: Vec::new(),
            allow_secrets: false,
        }
    }

    /// **The all-free policy:** enforces only the access level (`ro`, `rw`, `rwd`) on
    /// any path — «read, write or delete anything», with no scope check and no floor.
    /// For when the consumer deliberately wants full control. `all_free(Ro)` allows no
    /// changes; `all_free(Rw)` sets and modifies anywhere but does not delete;
    /// `all_free(Rwd)` allows everything. Fail-closed on unknown verbs still applies,
    /// through [`parse_set_payload`].
    pub fn all_free(access: Access) -> Self {
        ConfigPolicy {
            protected_roots: Vec::new(),
            rules: Vec::new(),
            mode: Mode::AllFree(access),
            read_allows: Vec::new(),
            command_allows: Vec::new(),
            allow_secrets: false,
        }
    }

    /// **The all-deny policy: nothing is permitted** — no read, no `show`, no command,
    /// no change — whatever is granted (0.5.11). It is the policy a session without a
    /// bound one has: the consumer defines the policy it uses, and until it does,
    /// netconf does nothing on its behalf. Bind it explicitly to say the same thing
    /// out loud.
    pub const fn all_deny() -> Self {
        ConfigPolicy {
            protected_roots: Vec::new(),
            rules: Vec::new(),
            mode: Mode::AllDeny,
            read_allows: Vec::new(),
            command_allows: Vec::new(),
            allow_secrets: false,
        }
    }

    /// Is this the deliberate «everything» policy — `all_free` with full access?
    ///
    /// The session's enforcement uses it: only this policy lets through payload
    /// formats that cannot be parsed and checked (Text and Xml). Full control is then
    /// an explicit, deliberate choice rather than a gap.
    pub fn is_all_free_rwd(&self) -> bool {
        self.mode == Mode::AllFree(Access::Rwd)
    }

    /// Is this the all-deny policy — the one that permits nothing (0.5.11)?
    pub fn is_all_deny(&self) -> bool {
        self.mode == Mode::AllDeny
    }

    /// Is this the read-only policy — reads and `show`, and no change and no other
    /// command whatever is granted (0.5.11)?
    pub fn is_read_only(&self) -> bool {
        self.mode == Mode::ReadOnly
    }

    /// Whether any change at all can pass this policy: a rule that permits an
    /// operation, or an all-free level above `Ro`. A policy that can change nothing
    /// commits nothing — see the session's gate.
    pub(crate) fn permits_any_change(&self) -> bool {
        match self.mode {
            Mode::Rules => self.rules.iter().any(|r| !r.ops.is_empty()),
            Mode::AllFree(access) => access != Access::Ro,
            Mode::ReadOnly | Mode::AllDeny => false,
        }
    }

    // --- Reading, and operational commands ----------------------------------
    //
    // The filter is meant for changes: writing and deleting. Reading is open by
    // default, EXCEPT for [`SENSITIVE_READ_ROOTS`], which need an explicit read
    // grant. For operational commands the default is `show ...` only — those run
    // under the device user's OWN authorisation on the box, its login class from
    // RADIUS or TACACS. `request`, `clear`, `restart` and the rest need an explicit
    // grant or `all_free(Rwd)`.

    /// Grant READ access to a sensitive tree — see [`SENSITIVE_READ_ROOTS`].
    pub fn allow_read(mut self, root: &str) -> Self {
        self.read_allows.push(root.to_string());
        self
    }

    /// Grant an operational command beyond `show` — a token prefix, for example
    /// `"request system reboot"`. Used deliberately and rarely; by default
    /// anything other than `show` is refused.
    ///
    /// An empty or blank prefix grants **nothing** and is not recorded. A grant
    /// with no tokens is a prefix of every command, so it used to allow them all —
    /// and an empty string is exactly what a missing configuration value becomes.
    pub fn allow_command(mut self, prefix: &str) -> Self {
        if !prefix.trim().is_empty() {
            self.command_allows.push(prefix.to_string());
        }
        self
    }

    /// Grant the device's secrets through (0.5.11). Everything the session returns —
    /// `show` output, configuration, the compare diff — has the device's secrets
    /// redacted, each replaced by [`REDACTED`](crate::redact::REDACTED), which says
    /// what was there and how to read it. This is how: a policy with this grant lets
    /// them through as the device wrote them. `all_free` redacts nothing in any case.
    pub fn allow_secrets(mut self) -> Self {
        self.allow_secrets = true;
        self
    }

    /// Whether the device's secrets come through in what the session returns (0.5.11):
    /// under `all_free`, and under a policy with [`allow_secrets`](Self::allow_secrets).
    pub fn secrets_allowed(&self) -> bool {
        match self.mode {
            Mode::AllFree(_) => true,
            Mode::AllDeny => false,
            Mode::Rules | Mode::ReadOnly => self.allow_secrets,
        }
    }

    fn read_allowed(&self, root: &str) -> bool {
        matches!(self.mode, Mode::AllFree(_)) || self.read_allows.iter().any(|r| r == root)
    }

    /// Check a configuration READ against the read grants. `targets` is the path after
    /// `show configuration`, as tokens; **an empty list means the whole
    /// configuration**, which requires a grant on EVERY sensitive tree. Only the first
    /// token is a tree, and only it is judged: `show configuration protocols bgp group
    /// x` used to be refused because `group` is a prefix of `groups`. Junos
    /// abbreviations — «sys» for «system» — are treated prefix-tolerantly on the
    /// refusal side, which is fail-closed.
    ///
    /// `get_configuration` does not use the prefix rule: its targets are XML element
    /// names, which are never abbreviated, and are matched exactly — every element,
    /// nested ones included.
    pub fn check_config_read(&self, targets: &[String]) -> Result<(), String> {
        self.check_read(targets, true)
    }

    /// [`check_config_read`](Self::check_config_read) for targets that are XML
    /// element names, matched EXACTLY. XML never abbreviates, so the prefix rule the
    /// CLI needs only produced false refusals here: a BGP `<group>` was read as a
    /// prefix of `groups` and refused as a sensitive tree.
    pub(crate) fn check_config_read_elements(&self, targets: &[String]) -> Result<(), String> {
        self.check_read(targets, false)
    }

    fn check_read(&self, targets: &[String], abbreviations: bool) -> Result<(), String> {
        match self.mode {
            Mode::AllDeny => {
                return Err("all-deny: nothing is permitted — no read (denied, fail-closed)".into())
            }
            Mode::AllFree(_) => return Ok(()),
            Mode::Rules | Mode::ReadOnly => {}
        }
        if targets.is_empty() {
            let missing: Vec<&str> = SENSITIVE_READ_ROOTS
                .iter()
                .filter(|r| !self.read_allowed(r))
                .copied()
                .collect();
            if !missing.is_empty() {
                return Err(format!(
                    "reading the FULL configuration includes sensitive trees without a read \
                     grant: {missing:?} — grant with allow_read(...) or read specific subtrees"
                ));
            }
            return Ok(());
        }
        // On the CLI only the first token names a tree; the rest is a path inside it.
        // Under `logical-systems <name>` (or `tenants <name>`) it is the token after
        // the name (0.5.13), and the tree itself, or one system whole, is a read of
        // a whole configuration. The refusal side is prefix-tolerant: `log` is
        // `logical-systems`.
        let targets = if abbreviations {
            let nested = NESTED_CONFIGURATIONS.iter().any(|n| {
                let t = targets[0].to_ascii_lowercase();
                !t.is_empty() && n.starts_with(t.as_str())
            });
            match targets.get(2) {
                Some(_) if nested => &targets[2..3],
                None if nested => return self.check_read(&[], abbreviations),
                _ => &targets[..1],
            }
        } else {
            targets
        };
        for t in targets {
            let tok = t.to_ascii_lowercase();
            for root in SENSITIVE_READ_ROOTS {
                let touches = if abbreviations {
                    root.starts_with(tok.as_str())
                } else {
                    *root == tok
                };
                if touches && !self.read_allowed(root) {
                    return Err(format!(
                        "reading `{root}` requires an explicit read grant (allow_read) — \
                         it carries device secrets"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Check an operational command. By default only `show ...`, unabbreviated, is
    /// permitted, and `show configuration <tree>` is additionally gated by the read
    /// grants. Everything else — `request`, `clear`, `restart` and so on — needs an
    /// explicit [`allow_command`](Self::allow_command) grant or `all_free(Rwd)`;
    /// `read_only` refuses it whatever is granted.
    ///
    /// Every part of the command is checked, pipes included (0.5.7). A pipe (`|`) is
    /// only valid on `show`, and each one must be a read-only filter — see
    /// [`READ_ONLY_PIPES`]. `| compare` may name a rollback and nothing else
    /// (0.5.11): a file on the device is not read through it. Only the text before
    /// the first `|` used to be checked, and the pipe went to the device as written.
    ///
    /// Strings are read by the set parser's quoting rule: a `|` inside a
    /// double-quoted string does not split the command, `\"` inside one is a quote
    /// that does not close it, and a quote that does not close refuses the command.
    /// A string left open used to hide every `|` after it from the scan, while the
    /// device read them as pipes. A quote belongs in a pipe's pattern and nowhere
    /// else: one in the command itself refuses it (0.5.11), since
    /// `show "configuration" system` is a read of `system` the gate did not see as one.
    ///
    /// A command is one line of printable ASCII, tab included (0.5.11). Any other
    /// character refuses it: a control character — a carriage return reaches the
    /// device as a line break, as a newline does, and the line after it is nothing
    /// the gate has read (0.5.7) — and anything beyond ASCII, the Unicode line and
    /// paragraph separators U+2028 and U+2029 among them, which some readers take
    /// for a line break. The Junos CLI is ASCII; a non-ASCII value belongs in a
    /// configuration payload, which the set parser reads line by line.
    ///
    /// Keywords are compared exactly, as the device reads them (0.5.11): `show`,
    /// `configuration` and its prefixes, and the pipe names are lowercase, and a
    /// command grant matches the command's words as written. `SHOW` and `| MATCH`
    /// used to be folded to lowercase and let through.
    ///
    /// `show system rollback …` shows a previous configuration whole, and is a read
    /// of the whole configuration (0.5.11): it needs a read grant on every sensitive
    /// tree, as `show configuration` does — abbreviated too, on the refusal side.
    ///
    /// An ordinary `show` runs under the device user's own authorisation on the box;
    /// this crate does not try to reproduce the device's login class.
    pub fn check_command(&self, cmd: &str) -> Result<(), String> {
        if self.mode == Mode::AllDeny {
            return Err("all-deny: nothing is permitted — no command (denied, fail-closed)".into());
        }
        if self.is_all_free_rwd() {
            return Ok(()); // the all/all rule: deliberate full control
        }
        if let Some(c) = outside_printable_ascii(cmd) {
            let what = if c.is_control() {
                "a control character"
            } else {
                "a character outside printable ASCII"
            };
            return Err(format!(
                "{what}, U+{:04X}, in the command — a command is one line of printable \
                 ASCII, and only a tab may appear in it besides (denied, fail-closed)",
                u32::from(c)
            ));
        }
        let segments = split_pipes(cmd).map_err(|e| format!("{e} (denied, fail-closed)"))?;
        let pipes = &segments[1..];
        if segments[0].contains('"') {
            return Err(
                "a quote in the command itself — a quote belongs in a pipe's pattern, as in \
                 `| match \"ge|xe\"`, and nowhere else in a command (denied, fail-closed)"
                    .into(),
            );
        }
        let toks: Vec<&str> = segments[0].split_whitespace().collect();
        let Some(first) = toks.first() else {
            return Err("empty operational command".into());
        };
        if *first != "show" {
            if first.eq_ignore_ascii_case("show") {
                return Err(format!(
                    "keywords are lowercase, as the device reads them: `{first}` is not `show` \
                     (denied, fail-closed)"
                ));
            }
            if !pipes.is_empty() {
                return Err(format!(
                    "a pipe (`|`) is only valid on `show` — `{first}` takes none \
                     (denied, fail-closed)"
                ));
            }
            // Read-only permits no command beyond `show`, whatever is granted.
            if self.mode == Mode::ReadOnly {
                return Err(format!(
                    "read-only: only `show ...` is permitted — `{first}` is refused whatever \
                     is granted (denied, fail-closed)"
                ));
            }
            // An explicit grant? A token prefix, written out in full, and compared as
            // written: the device reads `Request` and `request` as two different
            // things, and so does the gate.
            for grant in &self.command_allows {
                let g: Vec<&str> = grant.split_whitespace().collect();
                // A grant with no tokens would be a prefix of every command.
                // `allow_command` no longer records one; this holds regardless.
                if !g.is_empty()
                    && g.len() <= toks.len()
                    && g.iter().zip(&toks).all(|(a, b)| a == b)
                {
                    return Ok(());
                }
            }
            return Err(format!(
                "operational command outside the rule set: only `show ...` is allowed by \
                 default (got `{first}`). State-changing commands (request/clear/restart/...) \
                 require an explicit allow_command grant or the deliberate all_free(Rwd)"
            ));
        }
        for pipe in pipes {
            check_pipe(pipe)?;
        }
        // `show configuration <tree>` reads configuration, so the read grants apply.
        // The refusing side is prefix-tolerant («conf» ≙ «configuration») — fail-closed.
        // The keyword is lowercase, as the device reads it; a prefix in another case
        // is refused rather than read as an ordinary `show` the device might accept.
        if let Some(second) = toks.get(1) {
            if "configuration".starts_with(second) {
                let path: Vec<String> = toks[2..].iter().map(|t| t.to_string()).collect();
                return self.check_config_read(&path);
            }
            if "configuration".starts_with(second.to_ascii_lowercase().as_str()) {
                return Err(format!(
                    "keywords are lowercase, as the device reads them: `{second}` is not \
                     `configuration` (denied, fail-closed)"
                ));
            }
            // `show ephemeral-configuration [instance <name>] [merge] [<tree>]` reads
            // configuration as `show configuration` does (0.5.13), and is judged the
            // same way; prefix-tolerant on the refusal side.
            if "ephemeral-configuration".starts_with(second) {
                let mut rest = &toks[2..];
                loop {
                    match rest.first() {
                        Some(t) if "instance".starts_with(t) => rest = rest.get(2..).unwrap_or(&[]),
                        Some(t) if "merge".starts_with(t) => rest = &rest[1..],
                        _ => break,
                    }
                }
                let path: Vec<String> = rest.iter().map(|t| t.to_string()).collect();
                return self.check_config_read(&path);
            }
            // `show system rollback <n>` shows a previous configuration whole: a read
            // of the whole configuration, sensitive trees included. Prefix-tolerant on
            // the refusal side, as `show conf sys` is: `show sys rollback 1` too.
            if "system".starts_with(second)
                && toks
                    .get(2)
                    .is_some_and(|third| "rollback".starts_with(third))
            {
                return self.check_config_read(&[]);
            }
        }
        Ok(())
    }

    // --- Introspection -------------------------------------------------------
    //
    // The crate can ANSWER what a filter permits, so a consumer can build a dynamic
    // rule system — choosing a filter per task — and still leave this crate to both
    // carry out and explain the choice.

    /// The policy's allow rules, so they can be read back — built with
    /// [`allow`](Self::allow) and [`grant`](Self::grant).
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The top-level trees the floor protects against a `delete` of themselves.
    pub fn protected_roots(&self) -> &[String] {
        &self.protected_roots
    }

    /// The all-free access level, if the policy is in all-free mode.
    pub fn all_free_access(&self) -> Option<Access> {
        match self.mode {
            Mode::AllFree(access) => Some(access),
            _ => None,
        }
    }

    /// Sensitive trees that have been granted for reading.
    pub fn read_allows(&self) -> &[String] {
        &self.read_allows
    }

    /// Operational command grants beyond `show` (0.5.0).
    pub fn command_allows(&self) -> &[String] {
        &self.command_allows
    }

    fn describe_secrets(&self) -> &'static str {
        if self.allow_secrets {
            "secrets: let through as the device wrote them (allow_secrets)"
        } else {
            "secrets: redacted — allow_secrets() lets them through"
        }
    }

    /// A human-readable description of what the policy permits, for logs, debugging
    /// and operator-facing surfaces. One line per rule, plus the floor. It is
    /// descriptive, not a machine format — use [`rules`](Self::rules) and
    /// [`protected_roots`](Self::protected_roots) for structured access.
    pub fn describe(&self) -> String {
        match self.mode {
            Mode::AllDeny => {
                return "all-deny: nothing is permitted — no read, no command, no change, \
                        whatever is granted"
                    .into()
            }
            Mode::AllFree(access) => {
                return format!(
                    "all-free({access:?}): access level only — no scope rules, no floor, \
                     nothing redacted"
                )
            }
            Mode::ReadOnly => {
                return format!(
                    "read-only: `show` and configuration reads, the sensitive trees behind \
                     allow_read; no other command and no change, whatever is granted; {}",
                    self.describe_secrets()
                )
            }
            Mode::Rules => {}
        }
        let mut out = Vec::new();
        out.push(self.describe_secrets().to_string());
        if self.rules.is_empty() {
            out.push("no allow rules: all configuration changes are denied (default-deny)".into());
        }
        for r in &self.rules {
            out.push(format!(
                "allow {:?} at \"{}\" ({:?})",
                r.ops(),
                r.pattern(),
                r.match_kind()
            ));
        }
        out.push(format!(
            "floor: delete of {} protected top-level trees is always denied",
            self.protected_roots.len()
        ));
        out.join("\n")
    }

    /// **The ordinary policy** — the one anyone gets, and the base to grant from. It
    /// has [`DEFAULT_PROTECTED_ROOTS`] as its floor and no change grants. Reading is
    /// open, except the sensitive trees ([`SENSITIVE_READ_ROOTS`]), which each need an
    /// explicit [`allow_read`](Self::allow_read) grant.
    pub fn with_default_floor() -> Self {
        ConfigPolicy::new(DEFAULT_PROTECTED_ROOTS)
    }

    /// **Read, change nothing.** `show` with its read-only pipes, and configuration
    /// reads, as under [`with_default_floor`](Self::with_default_floor) — the sensitive
    /// trees ([`SENSITIVE_READ_ROOTS`]) behind an [`allow_read`](Self::allow_read)
    /// grant, the device's secrets redacted unless [`allow_secrets`](Self::allow_secrets)
    /// — and **no command beyond `show` and no change, whatever is granted**: an
    /// `allow_command` or a change grant added to it has no effect, which is what the
    /// name promises. `allow_read` and `allow_secrets` are the grants it takes.
    ///
    /// Until 0.5.11 it was `all_free(Ro)`, which read the sensitive trees ungated and,
    /// against its own documentation, let an `allow_command` grant through.
    pub fn read_only() -> Self {
        ConfigPolicy {
            mode: Mode::ReadOnly,
            ..ConfigPolicy::with_default_floor()
        }
    }

    /// Grant a generic [`Scope`] at a given [`Access`] level. Composable: a consumer
    /// hardcodes its modes as compositions of these. It names *where* in the
    /// configuration, never *why* the caller wants it.
    pub fn grant(self, scope: Scope, access: Access) -> Self {
        let ops: &[Op] = match access {
            Access::Ro => return self, // no change grants at all
            Access::Rw => &[Op::Set],
            Access::Rwd => &[Op::Set, Op::Delete],
        };
        match scope {
            Scope::LogicalUnits => {
                // Creating the unit itself is `set interfaces X unit N` — exactly
                // four tokens, which Subtree does not match, since Subtree requires
                // the change path to be strictly longer than the rule. Without a
                // Node rule for Set, a unit could only be created by setting
                // something under it in the same line, and a bare unit was refused
                // by default-deny.
                let s = self
                    .allow("interfaces * unit *", Match::Subtree, ops)
                    .allow("interfaces * unit *", Match::Node, &[Op::Set]);
                // Rwd also permits deleting the unit node itself, as when
                // decommissioning one.
                if access == Access::Rwd {
                    s.allow("interfaces * unit *", Match::Node, &[Op::Delete])
                } else {
                    s
                }
            }
            // Both Subtree (`set ... description "text"`, where the value is an extra
            // token) AND Node (`delete ... description`, the exact node with no
            // value) — otherwise a description could be set but never deleted.
            Scope::InterfaceDescriptions => self
                .allow("interfaces * description", Match::Subtree, ops)
                .allow("interfaces * description", Match::Node, ops)
                .allow("interfaces * unit * description", Match::Subtree, ops)
                .allow("interfaces * unit * description", Match::Node, ops),
            // Subtree only, so the protocol node itself is never deleted — only what
            // is below it.
            Scope::Protocols => self.allow("protocols *", Match::Subtree, ops),
        }
    }

    /// Add an allow rule. `pattern` is space-separated tokens, where `*` is a wildcard.
    /// For example `.allow("interfaces * unit *", Match::Subtree, &[Op::Set, Op::Delete])`.
    pub fn allow(mut self, pattern: &str, m: Match, ops: &[Op]) -> Self {
        self.rules.push(Rule {
            pattern: parse_pattern(pattern),
            m,
            ops: ops.to_vec(),
        });
        self
    }

    /// Check every change against the policy. `Ok(())` if all are permitted, otherwise
    /// the **first** violation. Fail-closed.
    pub fn check(&self, changes: &[Change]) -> Result<(), Violation> {
        for c in changes {
            self.check_one(c)?;
        }
        Ok(())
    }

    /// Check a set payload as [`parse_set_lines`] read it, line by line: `rename` and
    /// `copy` through their own filters, every other line's changes as
    /// [`check`](Self::check) does (0.5.13).
    pub(crate) fn check_lines(&self, lines: &[SetLine]) -> Result<(), Violation> {
        for line in lines {
            match &line.verb {
                SetVerb::Rename { .. } => self.check_rename(line)?,
                SetVerb::Copy { .. } => self.check_copy(line)?,
                SetVerb::Other => self.check(&line.changes)?,
            }
        }
        Ok(())
    }

    /// `rename`: its source must be one the policy lets be deleted, and its target
    /// one it lets be written (0.5.13). That the target is not there already is
    /// checked against the device before the line is sent.
    fn check_rename(&self, line: &SetLine) -> Result<(), Violation> {
        self.check(&line.changes)
    }

    /// `copy`: its target must be one the policy lets be written; the source is
    /// neither changed nor removed (0.5.13). That the target is not there already
    /// is checked against the device before the line is sent: a copy creates, it
    /// does not overwrite.
    fn check_copy(&self, line: &SetLine) -> Result<(), Violation> {
        self.check(&line.changes)
    }

    fn check_one(&self, c: &Change) -> Result<(), Violation> {
        match self.mode {
            Mode::AllDeny => {
                return Err(Violation {
                    change: c.clone(),
                    reason: "all-deny: nothing is permitted".into(),
                })
            }
            Mode::ReadOnly => {
                return Err(Violation {
                    change: c.clone(),
                    reason: "read-only: no change is permitted, whatever is granted".into(),
                })
            }
            // All-free: only the access level is enforced, with no scope and no floor.
            Mode::AllFree(access) => {
                return if access.permits(c.op) {
                    Ok(())
                } else {
                    Err(Violation {
                        change: c.clone(),
                        reason: format!("all-free: {:?} does not allow {:?}", access, c.op),
                    })
                };
            }
            Mode::Rules => {}
        }
        // The absolute floor: never remove a top-level tree itself, which is a
        // single token.
        // Compared case-insensitively. Junos itself is forgiving about case, so a
        // floor that only recognises `system` and not `System` would be relying on
        // default-deny to catch the difference. Default-deny does catch it today —
        // but the floor is the one rule that is supposed to hold on its own, and a
        // rule that holds only because another one also happens to is not a floor.
        //
        // `wildcard delete <tree> *`, a literal `*`, deletes everything in the tree, and
        // is held to the floor as `delete <tree>` is (0.5.13).
        //
        // Under `logical-systems <name>` and `tenants <name>` stands a configuration of
        // the same kind as the top level (0.5.13): the system itself is not deleted —
        // nor emptied with `*` — and what is under it is judged as it would be at the
        // top level, by the floor and by the rules.
        let whole = |path: &[String]| path.len() == 1 || (path.len() == 2 && path[1] == "*");
        let nested = c.path.len() >= 2 && is_nested_configuration(&c.path[0]);
        let inner = if nested { &c.path[2..] } else { &[][..] };
        let floor = |path: &[String]| {
            c.op == Op::Delete
                && whole(path)
                && self
                    .protected_roots
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(&path[0]))
        };
        if floor(&c.path) || (nested && c.op == Op::Delete && (inner.is_empty() || inner == ["*"]))
        {
            return Err(Violation {
                change: c.clone(),
                reason: format!(
                    "absolute floor: cannot delete the top-level tree «{}»",
                    c.path[..c.path.len().min(2)].join(" ")
                ),
            });
        }
        if nested && floor(inner) {
            return Err(Violation {
                change: c.clone(),
                reason: format!(
                    "absolute floor: cannot delete the top-level tree «{}» of «{} {}»",
                    inner[0], c.path[0], c.path[1]
                ),
            });
        }
        // The allow rules, with default-deny behind them; under a nested
        // configuration, its inner path as at the top level, or the path as written.
        for r in &self.rules {
            if r.ops.contains(&c.op)
                && (matches_pattern(&r.pattern, r.m, &c.path)
                    || (!inner.is_empty() && matches_pattern(&r.pattern, r.m, inner)))
            {
                return Ok(());
            }
        }
        // Paths are compared exactly, because Junos names are case-sensitive:
        // `policy-statement EXPORT` and `export` are different things, and a loose
        // match would let a rule for one approve the other. The refusal stands. But
        // if the same path in lowercase WOULD be allowed, the reason says so, since
        // «no rule allows this» otherwise reads as though no rule existed at all.
        let lower: Vec<String> = c.path.iter().map(|t| t.to_ascii_lowercase()).collect();
        let only_case = lower != c.path
            && self
                .rules
                .iter()
                .any(|r| r.ops.contains(&c.op) && matches_pattern(&r.pattern, r.m, &lower));
        let reason = if only_case {
            "default-deny: no rule allows this (op, path) — paths are case-sensitive, and \
             the same path in lowercase would be allowed"
        } else {
            "default-deny: no rule allows this (op, path)"
        };
        Err(Violation {
            change: c.clone(),
            reason: reason.to_string(),
        })
    }
}

/// The pipes a `show` may carry: the ones that only filter or format what is shown.
/// `save`, `append` and `tee` write files on the device, `request` messages its users,
/// `hold` and `refresh` keep the command running — those, and anything not named
/// here, are refused. Names are written in full, as `show` is.
pub const READ_ONLY_PIPES: &[&str] = &[
    "compare", "count", "display", "except", "find", "last", "match", "no-more", "resolve", "trim",
];

/// The first character in a line of a set payload that the filter refuses: a control
/// character other than a tab, or the Unicode line separator U+2028 or paragraph
/// separator U+2029 (0.5.11).
///
/// `text` is one line of a set payload as `str::lines` gives it, for
/// [`parse_set_payload`]. A command is held to the stricter rule of
/// [`outside_printable_ascii`].
///
/// A device does not read such a character the way the filter does. A carriage
/// return is a line break to it — XML turns one into a newline (XML 1.0 §2.11)
/// before Junos reads the text — while the filter sees one line; NUL, form feed,
/// vertical tab and the rest have no meaning the filter could check. U+2028 and
/// U+2029 are not control characters, but they are a line break to some readers
/// and none to `str::lines`, which is the same gap. A tab is whitespace to both.
fn control_character(text: &str) -> Option<char> {
    text.chars()
        .find(|&c| (c.is_control() && c != '\t') || c == '\u{2028}' || c == '\u{2029}')
}

/// The first character in a command that the gate refuses: anything but printable
/// ASCII (U+0020 to U+007E) and a tab (0.5.11). The Junos CLI is ASCII; a non-ASCII
/// value belongs in a configuration payload, which [`parse_set_payload`] reads.
fn outside_printable_ascii(cmd: &str) -> Option<char> {
    cmd.chars()
        .find(|&c| c != '\t' && !(' '..='~').contains(&c))
}

/// Split a command at every `|` outside a string, so a pattern such as
/// `match "ge|xe"` stays in one piece. The first piece is the command itself.
///
/// Strings are read by [`Quoting`], the rule the set parser reads a payload by. A
/// quote that does not close is [`ParseError::UnbalancedQuote`]: the scan would
/// read every `|` after it as part of the string, and the device would not.
fn split_pipes(cmd: &str) -> Result<Vec<&str>, ParseError> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoting = Quoting::default();
    for (i, c) in cmd.char_indices() {
        if let Read::Outside('|') = quoting.read(c) {
            parts.push(&cmd[start..i]);
            start = i + 1;
        }
    }
    if !quoting.balanced() {
        return Err(ParseError::UnbalancedQuote(crate::redact::redact_secrets(
            cmd,
        )));
    }
    parts.push(&cmd[start..]);
    Ok(parts)
}

/// Check one pipe after a `show`: it must name a [`READ_ONLY_PIPES`] entry, written
/// as the device reads it — lowercase (0.5.11; `| MATCH` used to be folded). `compare`
/// may name a rollback and nothing else: `| compare`, or `| compare rollback <n>`.
fn check_pipe(pipe: &str) -> Result<(), String> {
    let mut words = pipe.split_whitespace();
    let Some(name) = words.next() else {
        return Err("an empty pipe — `|` with nothing after it (denied, fail-closed)".into());
    };
    if !READ_ONLY_PIPES.contains(&name) {
        return Err(format!(
            "the pipe `| {name}` is not a read-only filter — a `show` may only be piped through \
             {}, written in lowercase (denied, fail-closed)",
            READ_ONLY_PIPES.join(", ")
        ));
    }
    if name == "compare" {
        let rest: Vec<&str> = words.collect();
        let names_a_rollback = rest.is_empty()
            || (rest.len() == 2
                && rest[0] == "rollback"
                && !rest[1].is_empty()
                && rest[1].bytes().all(|b| b.is_ascii_digit()));
        if !names_a_rollback {
            return Err(
                "`| compare` may name a rollback and nothing else — `| compare` or \
                 `| compare rollback <n>`; a file on the device is not read through it \
                 (denied, fail-closed)"
                    .into(),
            );
        }
    }
    Ok(())
}

fn parse_pattern(pattern: &str) -> Vec<Pat> {
    pattern
        .split_whitespace()
        .map(|t| {
            if t == "*" {
                Pat::Star
            } else {
                Pat::Lit(t.to_string())
            }
        })
        .collect()
}

fn prefix_matches(pattern: &[Pat], path: &[String]) -> bool {
    pattern.iter().zip(path).all(|(p, tok)| match p {
        Pat::Star => true,
        Pat::Lit(l) => l == tok,
    })
}

fn matches_pattern(pattern: &[Pat], m: Match, path: &[String]) -> bool {
    match m {
        Match::Node => path.len() == pattern.len() && prefix_matches(pattern, path),
        Match::Subtree => path.len() > pattern.len() && prefix_matches(pattern, path),
    }
}

/// Why a set payload could not be parsed safely. **Fail-closed:** any of these must
/// cause the whole payload to be refused. The parser — which the policy check runs
/// against — and what is actually sent to the device must never diverge.
///
/// **Note:** the variants that carry a configuration line (`EmptyPath`,
/// `UnbalancedQuote`, `SingleQuote`, `Comment`) are **already redacted** with
/// [`crate::redact::redact_secrets`] when they are constructed in
/// [`parse_set_payload`], because the error text ends up in `NetconfError::Policy`
/// and from there in the consumer's log. `UnknownVerb` carries the word, redacted the
/// same way (0.5.10). `ControlCharacter` carries no line at all.
///
/// `#[non_exhaustive]` (0.5.7): a variant can arrive in any release, so a `match`
/// outside this crate needs a wildcard arm.
///
/// ```
/// use netconf::ParseError;
///
/// fn kind(e: &ParseError) -> &'static str {
///     match e {
///         ParseError::UnknownVerb(_) => "verb",
///         ParseError::EmptyPath(_) => "path",
///         ParseError::UnbalancedQuote(_) => "quote",
///         ParseError::Comment(_) => "comment",
///         ParseError::SingleQuote(_) => "single quote",
///         ParseError::ControlCharacter { .. } => "control character",
///         _ => "a later variant",
///     }
/// }
/// ```
///
/// The same `match` without the wildcard arm does not compile, every variant named
/// or not:
///
/// ```compile_fail,E0004
/// use netconf::ParseError;
///
/// fn kind(e: &ParseError) -> &'static str {
///     match e {
///         ParseError::UnknownVerb(_) => "verb",
///         ParseError::EmptyPath(_) => "path",
///         ParseError::UnbalancedQuote(_) => "quote",
///         ParseError::Comment(_) => "comment",
///         ParseError::SingleQuote(_) => "single quote",
///         ParseError::ControlCharacter { .. } => "control character",
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// A verb the parser does not know, and therefore cannot classify or enforce. The
    /// word is redacted (0.5.10).
    UnknownVerb(String),
    /// A line with no path after the verb.
    EmptyPath(String),
    /// An unbalanced quote in a line.
    UnbalancedQuote(String),
    /// A `/*` comment outside a quoted string (0.5.7). A comment is not sent to a
    /// device — it goes in a quoted string, as with `annotate` or `description` — so
    /// the payload is refused. A line opening one used to be skipped: unchecked, and
    /// sent to the device all the same.
    Comment(String),
    /// A single quote outside a double-quoted string (0.5.7). Only `"` quotes a value.
    ///
    /// `'` is refused rather than read as ordinary text, because read as text it
    /// splits a value the device may treat as one — `'Link to router one'` becomes
    /// four tokens — and the policy then decides on a path nobody wrote. Inside a
    /// `"…"` string it is just a character, so `"Roger's link"` is unaffected.
    SingleQuote(String),
    /// A control character other than a tab in a line of the payload (0.5.7), or the
    /// Unicode line separator U+2028 or paragraph separator U+2029 (0.5.11): `line`
    /// is its line number, counted from 1 as `str::lines` counts, and `character` the
    /// character. The line itself is not carried — it may hold a secret.
    ///
    /// A line ends with a newline or with CRLF, and XML turns both into one newline
    /// before the device reads the payload. A carriage return anywhere else is a line
    /// break to the device and none to the parser: `#\rdelete protocols` was a
    /// skipped comment here and a `delete protocols` there. NUL, vertical tab, form
    /// feed, DEL and the C1 controls have no meaning the filter could check. U+2028
    /// and U+2029 are a line break to some readers and none to the parser — the same
    /// gap, so the same refusal.
    ControlCharacter {
        /// The line the character is on, counted from 1.
        line: usize,
        /// The character.
        character: char,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // A verb that IS known in lowercase is still refused — verbs are compared
            // exactly — but saying so spares the operator staring at a word that
            // looks right. A genuinely unknown verb gets no such hint.
            ParseError::UnknownVerb(v) if matches!(v.as_str(), "edit" | "top" | "up" | "exit") => {
                write!(
                    f,
                    "«{v}» moves the context later lines are read in, and the filter cannot \
                     follow it — write every line with its full path (denied, fail-closed)"
                )
            }
            ParseError::UnknownVerb(v) if verb_class(&v.to_ascii_lowercase()).is_some() => write!(
                f,
                "unknown verb «{v}» — verbs are lowercase, and «{v}» is not «{}» (denied, fail-closed)",
                v.to_ascii_lowercase()
            ),
            ParseError::UnknownVerb(v) => write!(f, "unknown verb «{v}» (denied, fail-closed)"),
            ParseError::EmptyPath(l) => write!(f, "line without a path: «{l}»"),
            ParseError::UnbalancedQuote(l) => write!(f, "unbalanced quote: «{l}»"),
            ParseError::Comment(l) => write!(
                f,
                "a /* comment cannot be sent to a device — a comment goes in a quoted string \
                 (denied, fail-closed): «{l}»"
            ),
            ParseError::SingleQuote(l) => write!(
                f,
                "single quote outside a string — only \" quotes a value (denied, fail-closed): «{l}»"
            ),
            ParseError::ControlCharacter { line, character } => write!(
                f,
                "a control character or line separator, U+{:04X}, on line {line} — a line ends \
                 with a newline or CRLF, and only a tab may appear in it besides printable text \
                 (denied, fail-closed)",
                u32::from(*character)
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a Junos set-format payload into a list of [`Change`]. Every non-empty line is
/// `<verb> <hierarchy path> [value]`; the verb is classified through [`verb_class`]
/// (plus the two-token verb `wildcard delete`).
///
/// **Fail-closed:** an unknown verb (`edit` included), an empty path, an unbalanced
/// quote, a single quote or a `/*` comment outside a string, or a control character
/// other than a tab, causes the WHOLE payload to be refused ([`ParseError`]). A line
/// we do not understand is never silently skipped, because it would then reach the
/// device without having passed the policy check — which is exactly the bypass
/// surface.
///
/// A line ends with `\n` or `\r\n` (0.5.7). A carriage return anywhere else, any
/// other control character but a tab, and the Unicode line and paragraph separators
/// U+2028 and U+2029 (0.5.11), is [`ParseError::ControlCharacter`], before anything
/// else in the payload is read.
///
/// A `#` outside a quoted string makes the rest of its line a comment, and the line
/// is read without it (0.5.13): `delete protocols # x` is `delete protocols`. A line
/// that begins with `#` is a comment whole. Inside `"…"`, `#` is text. What
/// `load_configuration` sends is the payload without its comments, so the device
/// reads what the policy judged.
pub fn parse_set_payload(payload: &str) -> Result<Vec<Change>, ParseError> {
    Ok(parse_set_lines(payload)?
        .into_iter()
        .flat_map(|l| l.changes)
        .collect())
}

/// What a set-payload line does to the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SetVerb {
    /// `rename <path> to <tail>`: a `Delete` of the path and a `Set` of the target.
    Rename { target: Vec<String> },
    /// `copy <path> to <tail>`: a `Set` of the target.
    Copy { target: Vec<String> },
    /// Every other verb.
    Other,
}

/// One line of a set payload, read (0.5.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetLine {
    pub(crate) verb: SetVerb,
    pub(crate) changes: Vec<Change>,
}

impl SetLine {
    /// The path a `rename` or `copy` writes, which must not be there already.
    pub(crate) fn target(&self) -> Option<&[String]> {
        match &self.verb {
            SetVerb::Rename { target } | SetVerb::Copy { target } => Some(target),
            SetVerb::Other => None,
        }
    }
}

/// The path `rename` and `copy` write (0.5.13). Junos names the new identifier on
/// the same level as the old one: `rename interfaces ge-0/0/0 unit 0 to unit 1`
/// writes `interfaces ge-0/0/0 unit 1`, `rename interfaces ge-0/0/0 to ge-0/0/1`
/// writes `interfaces ge-0/0/1`. The words after `to` replace as many words at the
/// end of the source; as many as the source has, or more, are the whole path.
fn written_by(source: &[String], to: &[String]) -> Vec<String> {
    let keep = source.len().saturating_sub(to.len());
    source[..keep].iter().chain(to).cloned().collect()
}

/// [`parse_set_payload`], line by line, with what each line's verb does.
pub(crate) fn parse_set_lines(payload: &str) -> Result<Vec<SetLine>, ParseError> {
    // The lines are the ones the device reads. `str::lines` ends a line at `\n` and
    // at `\r\n`, and XML makes both a newline (XML 1.0 §2.11) before Junos reads the
    // payload, so the two agree. A lone `\r` is where they part: a line break to the
    // device and not to `str::lines`. The command gate's rule refuses it, and every
    // other control character but a tab, on each line before any line is parsed —
    // `trim` below would otherwise take a trailing one away unseen, and a `#` line
    // would be skipped with it.
    for (i, line) in payload.lines().enumerate() {
        if let Some(character) = control_character(line) {
            return Err(ParseError::ControlCharacter {
                line: i + 1,
                character,
            });
        }
    }
    let mut out = Vec::new();
    for line in payload.lines() {
        // A `#` comment is dropped, and a line that holds nothing else is skipped. A
        // `/*` comment is refused, in `tokenize`, wherever it stands outside a quoted
        // string: skipping a line that opened one used to mean it went to the device
        // unchecked.
        let line = uncommented(line.trim());
        if line.is_empty() {
            continue;
        }
        let mut toks = tokenize(line)?;
        if toks.is_empty() {
            continue;
        }
        let verb = toks.remove(0);
        // `rename` and `copy` have a filter of their own (0.5.13): `<path> to <tail>`,
        // both sides there, or the line is refused.
        if verb == "rename" || verb == "copy" {
            let to = toks.iter().position(|t| t == "to");
            let (source, tail) = match to {
                Some(i) if i > 0 && i + 1 < toks.len() => (&toks[..i], &toks[i + 1..]),
                _ => return Err(ParseError::EmptyPath(crate::redact::redact_secrets(line))),
            };
            let target = written_by(source, tail);
            let set = Change {
                op: Op::Set,
                path: target.clone(),
            };
            out.push(if verb == "rename" {
                SetLine {
                    verb: SetVerb::Rename { target },
                    changes: vec![
                        Change {
                            op: Op::Delete,
                            path: source.to_vec(),
                        },
                        set,
                    ],
                }
            } else {
                SetLine {
                    verb: SetVerb::Copy { target },
                    changes: vec![set],
                }
            });
            continue;
        }
        // An unknown verb goes into an error text the consumer logs, like the line in
        // every other variant, so it is redacted first: a secret pasted where the
        // verb belongs is the first word on the line. A word `Display` gives a hint
        // for — `edit`, `SET` — holds nothing to redact and comes through as written.
        // The two-token verb `wildcard delete <path>`: remove class, highest risk.
        let op = if verb == "wildcard" {
            match toks.first().map(String::as_str) {
                Some("delete") => {
                    toks.remove(0);
                    Op::Delete
                }
                other => {
                    return Err(ParseError::UnknownVerb(crate::redact::redact_secrets(
                        &format!("wildcard {}", other.unwrap_or("")),
                    )))
                }
            }
        } else {
            verb_class(&verb)
                .ok_or_else(|| ParseError::UnknownVerb(crate::redact::redact_secrets(&verb)))?
        };
        if toks.is_empty() {
            return Err(ParseError::EmptyPath(crate::redact::redact_secrets(line)));
        }
        out.push(SetLine {
            verb: SetVerb::Other,
            changes: vec![Change { op, path: toks }],
        });
    }
    Ok(out)
}

/// Whether `path` is in a configuration given in set format — a line of it, read
/// as a payload line is, begins with it (0.5.13).
pub(crate) fn set_text_has(text: &str, path: &[String]) -> bool {
    text.lines().any(|line| {
        tokenize(uncommented(line.trim()))
            .is_ok_and(|toks| toks.len() > path.len() && toks[1..].starts_with(path))
    })
}

/// `line` without its comment: from a `#` outside a quoted string to the end of the
/// line, and the whitespace in front of it (0.5.13).
fn uncommented(line: &str) -> &str {
    let mut quoting = Quoting::default();
    for (i, c) in line.char_indices() {
        if let Read::Outside('#') = quoting.read(c) {
            return line[..i].trim_end();
        }
    }
    line
}

/// A set payload as [`parse_set_payload`] reads it: every line without its `#`
/// comment (0.5.13). It is what goes to the device, so the device reads what the
/// policy judged.
pub(crate) fn without_comments(payload: &str) -> String {
    let mut out: Vec<&str> = payload.lines().map(uncommented).collect();
    if payload.ends_with('\n') {
        out.push("");
    }
    out.join("\n")
}

/// The quoting rule, read one character at a time. The set parser reads a payload by
/// it and the command gate reads a command by it, so the two cannot disagree about
/// where a string begins and ends.
///
/// Only `"` quotes. Inside a string, `\` makes the next character literal, so `\"`
/// is a quote that does not close it; outside one, `\` is an ordinary character. A
/// string still open at the end is an unbalanced quote.
#[derive(Default)]
struct Quoting {
    in_string: bool,
    escaped: bool,
}

/// What one character is, under [`Quoting`].
enum Read {
    /// A `"`, opening or closing a string.
    Quote,
    /// The `\` that makes the next character in a string literal.
    Escape,
    /// A character inside a string, an escaped one included.
    InString(char),
    /// A character outside any string.
    Outside(char),
}

impl Quoting {
    fn read(&mut self, c: char) -> Read {
        if self.escaped {
            self.escaped = false;
            return Read::InString(c);
        }
        match c {
            '"' => {
                self.in_string = !self.in_string;
                Read::Quote
            }
            '\\' if self.in_string => {
                self.escaped = true;
                Read::Escape
            }
            c if self.in_string => Read::InString(c),
            c => Read::Outside(c),
        }
    }

    /// Every string closed, and no `\` left waiting for its character.
    fn balanced(&self) -> bool {
        !self.in_string && !self.escaped
    }
}

/// Split a line into tokens; a double-quoted sequence counts as one token (without
/// the quotes), and `\"` is an escaped quote inside a string — the rule is
/// [`Quoting`]. An unbalanced quote gives [`ParseError::UnbalancedQuote`], and a `'`
/// outside a string gives [`ParseError::SingleQuote`] — both fail-closed, never
/// silent. Only `"` quotes.
fn tokenize(line: &str) -> Result<Vec<String>, ParseError> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut quoting = Quoting::default();
    // Whether the token being built contained a quoted section. `description ""` is
    // a real argument with an empty value, and dropping it shortens the path by one
    // token — which changes which rule the policy matches against. An emptiness
    // check alone cannot tell `""` apart from no token at all.
    let mut quoted = false;
    for c in line.chars() {
        match quoting.read(c) {
            Read::Quote => quoted = true,
            Read::Escape => {}
            Read::InString(c) => cur.push(c),
            // Only `"` quotes a value. A `'` outside a string is refused, not read as
            // text: read as text it split `'a b c'` into three tokens, and the policy
            // decided on a path that was not the one written. Inside `"…"` it is an
            // ordinary character.
            Read::Outside('\'') => {
                return Err(ParseError::SingleQuote(crate::redact::redact_secrets(line)));
            }
            // `/*` at the start of a token, outside a string, opens a comment. A
            // comment is not sent to a device; it goes in a quoted string.
            Read::Outside('*') if cur == "/" => {
                return Err(ParseError::Comment(crate::redact::redact_secrets(line)));
            }
            Read::Outside(ws) if ws.is_whitespace() => {
                if !cur.is_empty() || quoted {
                    toks.push(std::mem::take(&mut cur));
                    quoted = false;
                }
            }
            Read::Outside(c) => cur.push(c),
        }
    }
    if !quoting.balanced() {
        // The line goes into an error text the consumer logs, so redact secrets first.
        // An unbalanced quote often means a value was cut in the wrong place, which
        // makes it rather likely that it IS a secret.
        return Err(ParseError::UnbalancedQuote(crate::redact::redact_secrets(
            line,
        )));
    }
    if !cur.is_empty() || quoted {
        toks.push(cur);
    }
    Ok(toks)
}
