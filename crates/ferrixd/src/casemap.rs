//! Case mapping and name validation.
//!
//! IRC compares nicknames and channel names case-insensitively, but the exact
//! folding is network-wide configuration. Applying it *consistently* everywhere
//! is a classic source of subtle bugs (`[` vs `{`), so all nick/channel lookups
//! route through [`CaseMapping::fold`] and every registry is keyed on the folded
//! form.

use serde::Deserialize;

/// The network's case-folding rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CaseMapping {
    /// Plain ASCII: `A`–`Z` fold to `a`–`z`. The modern default.
    #[default]
    Ascii,
    /// RFC 1459: ASCII folding plus the Scandinavian equivalences
    /// `[]\~` ↔ `{}|^`.
    Rfc1459,
}

impl CaseMapping {
    /// The token advertised in `RPL_ISUPPORT` (`CASEMAPPING=`).
    #[must_use]
    pub fn isupport_token(self) -> &'static str {
        match self {
            CaseMapping::Ascii => "ascii",
            CaseMapping::Rfc1459 => "rfc1459",
        }
    }

    /// Fold a single character to its canonical lowercase form.
    #[must_use]
    pub fn fold_char(self, c: char) -> char {
        match self {
            CaseMapping::Ascii => c.to_ascii_lowercase(),
            CaseMapping::Rfc1459 => match c {
                'A'..='Z' => c.to_ascii_lowercase(),
                '[' => '{',
                ']' => '}',
                '\\' => '|',
                '~' => '^',
                other => other,
            },
        }
    }

    /// Fold a whole string. Only ASCII bytes are ever transformed, so this is
    /// UTF-8 safe and leaves multi-byte characters untouched.
    #[must_use]
    pub fn fold(self, s: &str) -> String {
        s.chars().map(|c| self.fold_char(c)).collect()
    }
}

/// Maximum nickname length (a common default; advertised via `NICKLEN`).
pub const MAX_NICK_LEN: usize = 30;

/// Maximum channel-name length (advertised via `CHANNELLEN`).
pub const MAX_CHANNEL_LEN: usize = 50;

/// The "special" characters permitted in nicknames (RFC 2812 `special`).
fn is_nick_special(c: char) -> bool {
    matches!(c, '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '|' | '}')
}

/// Is `c` valid as the first character of a nickname?
fn is_nick_start(c: char) -> bool {
    c.is_ascii_alphabetic() || is_nick_special(c)
}

/// Is `c` valid in a non-leading nickname position?
fn is_nick_rest(c: char) -> bool {
    c.is_ascii_alphanumeric() || is_nick_special(c) || c == '-'
}

/// Validate a nickname against the RFC grammar and the length limit.
#[must_use]
pub fn is_valid_nick(nick: &str) -> bool {
    let mut chars = nick.chars();
    match chars.next() {
        None => return false,
        Some(first) if !is_nick_start(first) => return false,
        Some(_) => {}
    }
    if nick.chars().count() > MAX_NICK_LEN {
        return false;
    }
    chars.all(is_nick_rest)
}

/// Validate a channel name. Only `#` channels exist (`CHANTYPES=#`).
#[must_use]
pub fn is_valid_channel(name: &str) -> bool {
    let mut chars = name.chars();
    if chars.next() != Some('#') {
        return false;
    }
    if name.len() < 2 || name.chars().count() > MAX_CHANNEL_LEN {
        return false;
    }
    // No space, comma, control characters, or the BEL used as a mask separator.
    chars.all(|c| !matches!(c, ' ' | ',' | '\u{7}') && !c.is_control())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ascii_folds_only_letters() {
        assert_eq!(CaseMapping::Ascii.fold("AbC[]\\~"), "abc[]\\~");
    }

    #[test]
    fn rfc1459_folds_brackets() {
        assert_eq!(CaseMapping::Rfc1459.fold("AbC[]\\~"), "abc{}|^");
        // Nick equivalence: "Foo[]" and "foo{}" collide under rfc1459.
        assert_eq!(
            CaseMapping::Rfc1459.fold("Foo[]"),
            CaseMapping::Rfc1459.fold("foo{}")
        );
    }

    #[test]
    fn fold_is_utf8_safe() {
        assert_eq!(CaseMapping::Ascii.fold("Héllo"), "héllo");
    }

    #[test]
    fn valid_nicks() {
        for n in ["nick", "Guest123", "[bracket]", "a", "we-ird_", "`tick`"] {
            assert!(is_valid_nick(n), "{n} should be valid");
        }
    }

    #[test]
    fn invalid_nicks() {
        for n in ["", "1leading", "-leading", "has space", "with#hash", "a.b"] {
            assert!(!is_valid_nick(n), "{n} should be invalid");
        }
        assert!(!is_valid_nick(&"x".repeat(MAX_NICK_LEN + 1)));
    }

    #[test]
    fn channels() {
        assert!(is_valid_channel("#chan"));
        assert!(is_valid_channel("#a"));
        assert!(!is_valid_channel("#"));
        assert!(!is_valid_channel("nochan"));
        assert!(!is_valid_channel("#has space"));
        assert!(!is_valid_channel("#has,comma"));
        assert!(!is_valid_channel(&format!(
            "#{}",
            "x".repeat(MAX_CHANNEL_LEN)
        )));
    }
}
