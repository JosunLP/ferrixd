//! IRCv3 message-tag value escaping.
//!
//! The escape table (see the [message-tags spec]) is:
//!
//! | escaped | raw            |
//! |---------|----------------|
//! | `\:`    | `;` (semicolon)|
//! | `\s`    | ` ` (space)    |
//! | `\\`    | `\` (backslash)|
//! | `\r`    | CR             |
//! | `\n`    | LF             |
//!
//! When unescaping, a backslash followed by any *other* character yields that
//! character verbatim (the backslash is dropped), and a lone trailing
//! backslash is dropped entirely.
//!
//! [message-tags spec]: https://ircv3.net/specs/extensions/message-tags

use std::borrow::Cow;

/// Decode an escaped tag value into its raw form.
///
/// Returns a borrowed slice when the value contains no escapes (the common
/// case), allocating only when it must.
#[must_use]
pub fn unescape_value(value: &str) -> Cow<'_, str> {
    if !value.as_bytes().contains(&b'\\') {
        return Cow::Borrowed(value);
    }

    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(';'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            // Backslash + anything else: keep the character, drop the escape.
            Some(other) => out.push(other),
            // Lone trailing backslash: dropped.
            None => {}
        }
    }
    Cow::Owned(out)
}

/// Encode a raw tag value into its escaped wire form.
///
/// Returns a borrowed slice when no character needs escaping.
#[must_use]
pub fn escape_value(value: &str) -> Cow<'_, str> {
    let needs_escape = value
        .bytes()
        .any(|b| matches!(b, b';' | b' ' | b'\\' | b'\r' | b'\n'));
    if !needs_escape {
        return Cow::Borrowed(value);
    }

    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn unescape_passthrough_is_borrowed() {
        assert!(matches!(unescape_value("plain"), Cow::Borrowed("plain")));
        assert!(matches!(unescape_value(""), Cow::Borrowed("")));
    }

    #[test]
    fn unescape_all_sequences() {
        assert_eq!(unescape_value(r"a\:b\sc\\d\re\nf"), "a;b c\\d\re\nf");
    }

    #[test]
    fn unescape_unknown_escape_drops_backslash() {
        assert_eq!(unescape_value(r"\q"), "q");
    }

    #[test]
    fn unescape_trailing_backslash_dropped() {
        assert_eq!(unescape_value(r"abc\"), "abc");
    }

    #[test]
    fn escape_passthrough_is_borrowed() {
        assert!(matches!(escape_value("plain"), Cow::Borrowed("plain")));
    }

    #[test]
    fn escape_all_sequences() {
        assert_eq!(escape_value("a;b c\\d\re\nf"), r"a\:b\sc\\d\re\nf");
    }

    #[test]
    fn escape_unescape_round_trips() {
        for raw in [
            "",
            "hello",
            "a;b",
            "x y z",
            "back\\slash",
            "cr\rlf\n",
            "mix; \\\r\n",
        ] {
            let escaped = escape_value(raw);
            assert_eq!(
                unescape_value(&escaped),
                raw,
                "round-trip failed for {raw:?}"
            );
        }
    }
}
