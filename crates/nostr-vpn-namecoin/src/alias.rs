//! Parsing for `.bit` alias strings.

use std::fmt;

/// A parsed `.bit` alias.
///
/// Two forms are accepted:
///
/// - `Apex` — an unqualified `.bit` name like `example.bit`. Resolution
///   reads `nostr.names["_"]` (or `nostr.names["<root>"]` per ifa-0001
///   when the apex entry is absent).
/// - `Localpart` — a name with an explicit localpart, written either as
///   `alice@example.bit` (NIP-05 style) or `alice.example.bit`
///   (DNS-style subdomain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitAlias {
    Apex(String),
    Localpart { local: String, parent: String },
}

impl BitAlias {
    /// Returns the underlying `.bit` parent name (without subdomain labels).
    #[must_use]
    pub fn parent(&self) -> &str {
        match self {
            Self::Apex(name) | Self::Localpart { parent: name, .. } => name,
        }
    }

    /// Returns the localpart used when reading `nostr.names`. For an apex
    /// alias this is `"_"`.
    #[must_use]
    pub fn local(&self) -> &str {
        match self {
            Self::Apex(_) => "_",
            Self::Localpart { local, .. } => local,
        }
    }
}

impl fmt::Display for BitAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apex(name) => formatter.write_str(name),
            Self::Localpart { local, parent } => write!(formatter, "{local}@{parent}"),
        }
    }
}

/// Parse a candidate participant string into a [`BitAlias`].
///
/// Returns `Some` only if the input looks like a `.bit` name. Anything else
/// (npub, hex, junk) returns `None` so callers can cleanly fall through to
/// the existing pubkey parser.
///
/// ```
/// use nostr_vpn_namecoin::{BitAlias, parse_bit_alias};
///
/// assert_eq!(parse_bit_alias("example.bit"),
///     Some(BitAlias::Apex("example.bit".into())));
///
/// assert_eq!(parse_bit_alias("EXAMPLE.BIT"),
///     Some(BitAlias::Apex("example.bit".into())));
///
/// assert_eq!(parse_bit_alias("alice@example.bit"),
///     Some(BitAlias::Localpart { local: "alice".into(), parent: "example.bit".into() }));
///
/// assert_eq!(parse_bit_alias("alice.example.bit"),
///     Some(BitAlias::Localpart { local: "alice".into(), parent: "example.bit".into() }));
///
/// // Deeper subdomains: only the leftmost label is treated as the local part.
/// // (v1 supports a single subdomain hop; deeper trees still attempt the same walk.)
/// assert_eq!(parse_bit_alias("a.b.c.bit"),
///     Some(BitAlias::Localpart { local: "a".into(), parent: "b.c.bit".into() }));
///
/// // Non-.bit inputs return None so callers fall back to normal pubkey parsing.
/// assert_eq!(parse_bit_alias("npub1exampleexample"), None);
/// assert_eq!(parse_bit_alias("not-a-name"), None);
/// assert_eq!(parse_bit_alias(".bit"), None);
/// ```
#[must_use]
pub fn parse_bit_alias(value: &str) -> Option<BitAlias> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Reject control / whitespace inside the name.
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    let suffix_start = lower.len().checked_sub(".bit".len())?;
    if &lower[suffix_start..] != ".bit" {
        return None;
    }

    // Split optional localpart written as `local@parent`.
    if let Some((local, parent)) = lower.split_once('@') {
        if local.is_empty() || parent.is_empty() {
            return None;
        }
        if !valid_label(local) {
            return None;
        }
        // The bit suffix must live on the parent side. `lower` is already
        // lowercased above, so a plain `ends_with` is sufficient (the
        // file-extension lint is irrelevant — these are domain names).
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        let parent_ok = parent.ends_with(".bit");
        if !parent_ok {
            return None;
        }
        let parent_root = parent.strip_suffix(".bit").unwrap_or(parent);
        if parent_root.is_empty() || !valid_dns_name(parent_root) {
            return None;
        }
        return Some(BitAlias::Localpart {
            local: local.to_string(),
            parent: parent.to_string(),
        });
    }

    // No `@`. Inspect the dot-separated labels of the bare name.
    let stripped = &lower[..suffix_start];
    if stripped.is_empty() {
        return None;
    }

    let labels: Vec<&str> = stripped.split('.').collect();
    for label in &labels {
        if !valid_label(label) {
            return None;
        }
    }

    if labels.len() == 1 {
        return Some(BitAlias::Apex(lower));
    }

    // Treat the leftmost label as the localpart; everything else is the
    // parent `.bit` name. This matches the ifa-0001 walk: the resolver will
    // descend `map` entries label-by-label, but for v1 we only support a
    // single hop and a "deep" name like `a.b.c.bit` is treated as
    // `local=a, parent=b.c.bit`.
    let (local, rest) = labels.split_first().expect("non-empty after check");
    let parent = format!("{}.bit", rest.join("."));

    Some(BitAlias::Localpart {
        local: (*local).to_string(),
        parent,
    })
}

fn valid_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn valid_dns_name(name: &str) -> bool {
    name.split('.').all(valid_label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apex_parses() {
        assert_eq!(
            parse_bit_alias("example.bit"),
            Some(BitAlias::Apex("example.bit".into()))
        );
    }

    #[test]
    fn apex_case_insensitive() {
        assert_eq!(
            parse_bit_alias("Example.BIT"),
            Some(BitAlias::Apex("example.bit".into()))
        );
    }

    #[test]
    fn nip05_style_localpart() {
        assert_eq!(
            parse_bit_alias("alice@example.bit"),
            Some(BitAlias::Localpart {
                local: "alice".into(),
                parent: "example.bit".into(),
            })
        );
    }

    #[test]
    fn dns_style_localpart() {
        assert_eq!(
            parse_bit_alias("alice.example.bit"),
            Some(BitAlias::Localpart {
                local: "alice".into(),
                parent: "example.bit".into(),
            })
        );
    }

    #[test]
    fn deep_name_treats_leftmost_label_as_local() {
        assert_eq!(
            parse_bit_alias("a.b.c.bit"),
            Some(BitAlias::Localpart {
                local: "a".into(),
                parent: "b.c.bit".into(),
            })
        );
    }

    #[test]
    fn rejects_non_bit() {
        assert!(parse_bit_alias("example.com").is_none());
        assert!(parse_bit_alias("npub1examplenope").is_none());
        assert!(parse_bit_alias("not-a-name").is_none());
    }

    #[test]
    fn rejects_empty_or_pathological() {
        assert!(parse_bit_alias("").is_none());
        assert!(parse_bit_alias(".bit").is_none());
        assert!(parse_bit_alias("@example.bit").is_none());
        assert!(parse_bit_alias("alice@.bit").is_none());
        assert!(parse_bit_alias("alice@example.com").is_none());
        assert!(parse_bit_alias("alice with space@example.bit").is_none());
        assert!(parse_bit_alias("alice@example .bit").is_none());
    }

    #[test]
    fn display_round_trips_logical_form() {
        let alias = parse_bit_alias("alice.example.bit").unwrap();
        assert_eq!(alias.to_string(), "alice@example.bit");

        let apex = parse_bit_alias("example.bit").unwrap();
        assert_eq!(apex.to_string(), "example.bit");
    }

    #[test]
    fn apex_local_is_underscore() {
        let apex = parse_bit_alias("example.bit").unwrap();
        assert_eq!(apex.local(), "_");
        assert_eq!(apex.parent(), "example.bit");
    }
}
