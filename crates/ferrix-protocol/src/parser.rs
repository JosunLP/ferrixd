//! The zero-copy message parser.
//!
//! Structure is found by scanning for ASCII delimiters (`@`, space, `:`, `!`,
//! `=`, `;`) — all of which are single bytes that can never appear inside a
//! UTF-8 multi-byte sequence, so byte-level scanning is safe on UTF-8 input.
//! Field slices are validated with [`str::from_utf8`] only where they are
//! exposed as `&str`, so non-UTF-8 input is rejected, never mis-sliced, and
//! never a panic.

use smallvec::SmallVec;

use crate::limits::Limits;
use crate::message::{Command, Message, Source, Tag, Tags};
use crate::tags::unescape_value;

/// An error encountered while parsing a message.
///
/// Every malformed-input outcome is one of these variants — the parser never
/// panics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was empty (after stripping a trailing CRLF).
    #[error("empty message")]
    Empty,
    /// The message contained a raw NUL, CR, or LF octet in a non-terminator
    /// position. These octets are forbidden in IRC messages (they delimit or
    /// terminate lines) and must never appear inside fields.
    #[error("message contains an illegal NUL, CR, or LF octet")]
    IllegalControlChar,
    /// The tag section exceeded the tag byte budget.
    #[error("tag section exceeds {limit} bytes")]
    TagsTooLong {
        /// The configured tag budget that was exceeded.
        limit: usize,
    },
    /// The message body exceeded the body byte budget.
    #[error("message body exceeds {limit} bytes")]
    BodyTooLong {
        /// The configured body budget that was exceeded.
        limit: usize,
    },
    /// A required component (the command) was missing.
    #[error("missing command")]
    MissingCommand,
    /// The command token was neither a 3-digit numeric nor an all-letter verb.
    #[error("invalid command token")]
    InvalidCommand,
    /// A tag key was empty (e.g. a stray `;` or a leading `=`).
    #[error("empty tag key")]
    EmptyTagKey,
    /// A tag key contained characters outside the permitted set.
    #[error("invalid tag key")]
    InvalidTagKey,
    /// The source prefix was present but empty (a bare `:`).
    #[error("empty source prefix")]
    EmptySource,
    /// A field that must be UTF-8 was not.
    #[error("invalid UTF-8 in {field}")]
    InvalidUtf8 {
        /// Which field failed UTF-8 validation.
        field: &'static str,
    },
}

/// Parse one message from `input` (a single line, CRLF optional) with the given
/// [`Limits`].
///
/// # Errors
///
/// Returns [`ParseError`] for empty input, budget violations, a malformed
/// command, malformed tags, an empty source, or invalid UTF-8.
pub fn parse<'a>(input: &'a [u8], limits: &Limits) -> Result<Message<'a>, ParseError> {
    let mut buf = strip_line_terminators(input);
    if buf.is_empty() {
        return Err(ParseError::Empty);
    }

    // Raw NUL / CR / LF are illegal anywhere in a message body: they terminate
    // or delimit lines and can never appear inside a field. Rejecting them once,
    // up front, both enforces the RFC octet restrictions and guarantees that
    // `render` is a true inverse of `parse` (rendered output carries CR/LF only
    // in its single trailing terminator).
    if memchr::memchr3(b'\0', b'\r', b'\n', buf).is_some() {
        return Err(ParseError::IllegalControlChar);
    }

    // --- Tags (optional, leading '@') ---
    let mut tags = Tags::new();
    if buf[0] == b'@' {
        let sp = memchr::memchr(b' ', buf).ok_or(ParseError::MissingCommand)?;
        let section = &buf[1..sp]; // excludes '@'; excludes the trailing space
        if section.len() > limits.max_tag_bytes {
            return Err(ParseError::TagsTooLong {
                limit: limits.max_tag_bytes,
            });
        }
        parse_tags(section, &mut tags)?;
        buf = skip_spaces(&buf[sp..]);
        if buf.is_empty() {
            return Err(ParseError::MissingCommand);
        }
    }

    // The body is everything after the tag section. Enforce its budget here so
    // the tag budget and body budget stay independent.
    if buf.len() > limits.max_body_bytes {
        return Err(ParseError::BodyTooLong {
            limit: limits.max_body_bytes,
        });
    }

    // --- Source (optional, leading ':') ---
    let mut source = None;
    if buf[0] == b':' {
        let sp = memchr::memchr(b' ', buf).ok_or(ParseError::MissingCommand)?;
        let raw = &buf[1..sp];
        if raw.is_empty() {
            return Err(ParseError::EmptySource);
        }
        source = Some(parse_source(raw)?);
        buf = skip_spaces(&buf[sp..]);
        if buf.is_empty() {
            return Err(ParseError::MissingCommand);
        }
    }

    // --- Command (required) ---
    let cmd_end = memchr::memchr(b' ', buf).unwrap_or(buf.len());
    let command = parse_command(&buf[..cmd_end])?;
    buf = &buf[cmd_end..];

    // --- Parameters ---
    let mut params: SmallVec<[&str; 8]> = SmallVec::new();
    loop {
        buf = skip_spaces(buf);
        let Some(&first) = buf.first() else {
            break;
        };
        if first == b':' {
            // Trailing parameter: the rest of the line verbatim (may contain
            // spaces and may be empty). Its leading ':' is stripped.
            params.push(str_field(&buf[1..], "trailing")?);
            break;
        }
        let end = memchr::memchr(b' ', buf).unwrap_or(buf.len());
        params.push(str_field(&buf[..end], "param")?);
        buf = &buf[end..];
    }

    Ok(Message {
        tags,
        source,
        command,
        params,
    })
}

/// Strip a single trailing CR and/or LF (in either order) from a line.
fn strip_line_terminators(mut buf: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = buf.split_last() {
        if last == b'\r' || last == b'\n' {
            buf = rest;
        } else {
            break;
        }
    }
    buf
}

/// Skip a run of spaces at the start of `buf`.
fn skip_spaces(mut buf: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = buf.split_first() {
        if first == b' ' {
            buf = rest;
        } else {
            break;
        }
    }
    buf
}

/// Validate a byte slice as UTF-8, attributing failures to a named field.
fn str_field<'a>(bytes: &'a [u8], field: &'static str) -> Result<&'a str, ParseError> {
    std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8 { field })
}

fn parse_command(bytes: &[u8]) -> Result<Command<'_>, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::MissingCommand);
    }
    // A 3-digit numeric reply.
    if bytes.len() == 3 && bytes.iter().all(u8::is_ascii_digit) {
        let n = u16::from(bytes[0] - b'0') * 100
            + u16::from(bytes[1] - b'0') * 10
            + u16::from(bytes[2] - b'0');
        return Ok(Command::Numeric(n));
    }
    // Otherwise a verb: one or more ASCII letters.
    if bytes.iter().all(u8::is_ascii_alphabetic) {
        // All-ASCII, so UTF-8 validation cannot fail.
        return match std::str::from_utf8(bytes) {
            Ok(s) => Ok(Command::Named(s)),
            Err(_) => Err(ParseError::InvalidCommand),
        };
    }
    Err(ParseError::InvalidCommand)
}

fn parse_source(bytes: &[u8]) -> Result<Source<'_>, ParseError> {
    // name[!user][@host]. Split on '@' first (host is last), then '!' in the
    // remainder (user sits between nick and host).
    let (name_user, host) = match memchr::memchr(b'@', bytes) {
        Some(i) => (&bytes[..i], Some(&bytes[i + 1..])),
        None => (bytes, None),
    };
    let (name, user) = match memchr::memchr(b'!', name_user) {
        Some(i) => (&name_user[..i], Some(&name_user[i + 1..])),
        None => (name_user, None),
    };
    if name.is_empty() {
        return Err(ParseError::EmptySource);
    }
    Ok(Source {
        name: str_field(name, "source name")?,
        user: user.map(|u| str_field(u, "source user")).transpose()?,
        host: host.map(|h| str_field(h, "source host")).transpose()?,
    })
}

fn parse_tags<'a>(section: &'a [u8], out: &mut Tags<'a>) -> Result<(), ParseError> {
    if section.is_empty() {
        // "@ ..." with no actual tags — tolerate as an empty tag set.
        return Ok(());
    }
    for raw in section.split(|&b| b == b';') {
        if raw.is_empty() {
            // Stray/empty tag from "a;;b" or a leading/trailing ';'. Tolerate.
            continue;
        }
        let (key_bytes, value_bytes) = match memchr::memchr(b'=', raw) {
            Some(i) => (&raw[..i], Some(&raw[i + 1..])),
            None => (raw, None),
        };
        let key = parse_tag_key(key_bytes)?;
        let value = match value_bytes {
            Some(v) => Some(unescape_value(str_field(v, "tag value")?)),
            None => None,
        };
        out.push(Tag { key, value });
    }
    Ok(())
}

fn parse_tag_key(bytes: &[u8]) -> Result<&str, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::EmptyTagKey);
    }
    // Permitted: alphanumerics and `- / .`, plus an optional leading `+`
    // (client-only tag marker). Vendor prefixes use `/`.
    let valid = bytes.iter().enumerate().all(|(i, &c)| {
        c.is_ascii_alphanumeric() || matches!(c, b'-' | b'/' | b'.') || (i == 0 && c == b'+')
    });
    if !valid {
        return Err(ParseError::InvalidTagKey);
    }
    // All permitted bytes are ASCII, so validation cannot fail.
    str_field(bytes, "tag key")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn p(input: &[u8]) -> Message<'_> {
        parse(input, &Limits::default()).expect("should parse")
    }

    #[test]
    fn plain_command() {
        let m = p(b"PING");
        assert_eq!(m.command, Command::Named("PING"));
        assert!(m.params.is_empty());
        assert!(m.source.is_none());
        assert!(m.tags.is_empty());
    }

    #[test]
    fn command_is_case_preserved_but_matchable() {
        let m = p(b"privmsg #x :hi");
        assert_eq!(m.command, Command::Named("privmsg"));
        assert!(m.command.eq_name("PRIVMSG"));
    }

    #[test]
    fn numeric_command() {
        assert_eq!(p(b"001 nick :Welcome").command, Command::Numeric(1));
        assert_eq!(p(b"433 * nick :taken").command, Command::Numeric(433));
    }

    #[test]
    fn middle_and_trailing_params() {
        let m = p(b"PRIVMSG #chan :hello world");
        assert_eq!(m.command, Command::Named("PRIVMSG"));
        assert_eq!(m.params.as_slice(), ["#chan", "hello world"]);
    }

    #[test]
    fn trailing_may_be_empty_and_contain_colons() {
        let m = p(b"PRIVMSG #chan ::-)");
        assert_eq!(m.params.as_slice(), ["#chan", ":-)"]);
        let m = p(b"PRIVMSG #chan :");
        assert_eq!(m.params.as_slice(), ["#chan", ""]);
    }

    #[test]
    fn full_source_nick_user_host() {
        let m = p(b":nick!user@host.example JOIN #chan");
        let s = m.source.unwrap();
        assert_eq!(s.name, "nick");
        assert_eq!(s.user, Some("user"));
        assert_eq!(s.host, Some("host.example"));
        assert!(!s.is_server());
    }

    #[test]
    fn server_source() {
        let m = p(b":irc.example.net 001 nick :hi");
        let s = m.source.unwrap();
        assert_eq!(s.name, "irc.example.net");
        assert_eq!(s.user, None);
        assert_eq!(s.host, None);
        assert!(s.is_server());
    }

    #[test]
    fn source_with_host_no_user() {
        let m = p(b":nick@host PING x");
        let s = m.source.unwrap();
        assert_eq!(s.name, "nick");
        assert_eq!(s.user, None);
        assert_eq!(s.host, Some("host"));
    }

    #[test]
    fn tags_parsed_and_unescaped() {
        let m = p(b"@id=123;+draft/reply=a\\sb;valueless :n!u@h TAGMSG #c");
        assert_eq!(m.tags.len(), 3);
        assert_eq!(m.tags[0].key, "id");
        assert_eq!(m.tags[0].value.as_deref(), Some("123"));
        assert_eq!(m.tags[1].key, "+draft/reply");
        assert_eq!(m.tags[1].value.as_deref(), Some("a b"));
        assert_eq!(m.tags[2].key, "valueless");
        assert_eq!(m.tags[2].value, None);
        assert_eq!(m.command, Command::Named("TAGMSG"));
    }

    #[test]
    fn tag_lookup_helper() {
        let m = p(b"@time=2026;bare PING");
        assert_eq!(m.tag("time").unwrap().unwrap().as_ref(), "2026");
        assert_eq!(m.tag("bare"), Some(None));
        assert_eq!(m.tag("absent"), None);
    }

    #[test]
    fn collapses_extra_spaces_between_components() {
        let m = p(b"PRIVMSG   #chan    :hi");
        assert_eq!(m.params.as_slice(), ["#chan", "hi"]);
    }

    #[test]
    fn strips_trailing_crlf() {
        assert_eq!(p(b"PING\r\n").command, Command::Named("PING"));
        assert_eq!(p(b"PING\n").command, Command::Named("PING"));
        assert_eq!(p(b"PING\r").command, Command::Named("PING"));
    }

    #[test]
    fn empty_is_error() {
        assert_eq!(parse(b"", &Limits::default()), Err(ParseError::Empty));
        assert_eq!(parse(b"\r\n", &Limits::default()), Err(ParseError::Empty));
    }

    #[test]
    fn bad_commands_rejected() {
        assert_eq!(
            parse(b"12", &Limits::default()),
            Err(ParseError::InvalidCommand)
        );
        assert_eq!(
            parse(b"1234", &Limits::default()),
            Err(ParseError::InvalidCommand)
        );
        assert_eq!(
            parse(b"PING2", &Limits::default()),
            Err(ParseError::InvalidCommand)
        );
        assert_eq!(
            parse(b"@only=tag", &Limits::default()),
            Err(ParseError::MissingCommand)
        );
        assert_eq!(
            parse(b":src", &Limits::default()),
            Err(ParseError::MissingCommand)
        );
    }

    #[test]
    fn raw_control_chars_rejected() {
        // Embedded CR, LF, or NUL anywhere in the body is illegal...
        assert_eq!(
            parse(b"PRIVMSG #c :a\rb", &Limits::default()),
            Err(ParseError::IllegalControlChar)
        );
        assert_eq!(
            parse(b"PRIVMSG #c :a\nb", &Limits::default()),
            Err(ParseError::IllegalControlChar)
        );
        assert_eq!(
            parse(b"PING\0", &Limits::default()),
            Err(ParseError::IllegalControlChar)
        );
        // ...but a single trailing CRLF terminator is stripped, not rejected.
        assert!(parse(b"PRIVMSG #c :ab\r\n", &Limits::default()).is_ok());
    }

    #[test]
    fn empty_source_rejected() {
        assert_eq!(
            parse(b": PING", &Limits::default()),
            Err(ParseError::EmptySource)
        );
    }

    #[test]
    fn tag_budget_enforced() {
        let limits = Limits {
            max_tag_bytes: 4,
            max_body_bytes: 512,
        };
        assert_eq!(
            parse(b"@abcde PING", &limits),
            Err(ParseError::TagsTooLong { limit: 4 })
        );
        // Exactly at the budget is fine.
        assert!(parse(b"@abcd PING", &limits).is_ok());
    }

    #[test]
    fn body_budget_enforced_separately_from_tags() {
        let limits = Limits {
            max_tag_bytes: 8191,
            max_body_bytes: 8,
        };
        // Big tags, small body: allowed.
        assert!(parse(b"@a=1;b=2;c=3;d=4 PING", &limits).is_ok());
        // Body over budget: rejected.
        assert_eq!(
            parse(b"PRIVMSG #channel :x", &limits),
            Err(ParseError::BodyTooLong { limit: 8 })
        );
    }

    #[test]
    fn invalid_utf8_in_param_rejected() {
        // Valid structure, but the trailing param is not UTF-8.
        let input = b"PRIVMSG #c :\xff\xfe";
        assert_eq!(
            parse(input, &Limits::default()),
            Err(ParseError::InvalidUtf8 { field: "trailing" })
        );
    }

    #[test]
    fn invalid_tag_key_rejected() {
        assert_eq!(
            parse(b"@a\x01b=1 PING", &Limits::default()),
            Err(ParseError::InvalidTagKey)
        );
        assert_eq!(
            parse(b"@=noKey PING", &Limits::default()),
            Err(ParseError::EmptyTagKey)
        );
    }

    #[test]
    fn max_params_do_not_panic() {
        // Many middle params exercise the SmallVec spill path.
        let input = b"CMD a b c d e f g h i j k l m n o :trailing";
        let m = p(input);
        assert_eq!(m.params.len(), 16);
        assert_eq!(m.params.last(), Some(&"trailing"));
    }

    #[test]
    fn never_panics_on_short_fragments() {
        // A grab-bag of truncated / weird inputs must all return, never panic.
        for bad in [
            &b"@"[..],
            b":",
            b"@;",
            b"@=",
            b":@",
            b":!@",
            b"   ",
            b"@a ",
            b": ",
            b"\x00",
            b"@a=\\",
        ] {
            let _ = parse(bad, &Limits::default());
        }
    }
}
