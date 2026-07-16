//! The borrowed message model.
//!
//! Every field borrows from the input buffer, so a [`Message`] cannot outlive
//! the bytes it was parsed from. See the crate root for the zero-copy story.

use std::borrow::Cow;

use smallvec::SmallVec;

use crate::limits::Limits;
use crate::parser::{self, ParseError};

/// Inline capacity for tags before spilling to the heap. Most messages carry
/// zero or a handful of tags.
pub type Tags<'a> = SmallVec<[Tag<'a>; 8]>;

/// Inline capacity for parameters. IRC caps middle params at 14 + 1 trailing;
/// 8 inline covers the overwhelming majority without allocating.
pub type Params<'a> = SmallVec<[&'a str; 8]>;

/// A parsed IRC / IRCv3 message, borrowing from the source buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// IRCv3 message tags, in wire order.
    pub tags: Tags<'a>,
    /// The optional `:`-prefixed source (server name or `nick!user@host`).
    pub source: Option<Source<'a>>,
    /// The command: a named verb or a 3-digit numeric.
    pub command: Command<'a>,
    /// Parameters in order; the trailing parameter, if any, is the last element
    /// (with its leading `:` already stripped).
    pub params: Params<'a>,
}

impl<'a> Message<'a> {
    /// Parse a single message from `input` using the default IRCv3 [`Limits`].
    ///
    /// `input` is a single line **without** the trailing CRLF (a stray CRLF is
    /// tolerated and stripped). Never panics; returns [`ParseError`] on
    /// malformed input.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the message is empty, exceeds a length budget,
    /// has a malformed command, or contains invalid UTF-8.
    pub fn parse(input: &'a [u8]) -> Result<Self, ParseError> {
        parser::parse(input, &Limits::default())
    }

    /// Parse a single message with explicit length budgets.
    ///
    /// # Errors
    ///
    /// See [`Message::parse`].
    pub fn parse_with(input: &'a [u8], limits: &Limits) -> Result<Self, ParseError> {
        parser::parse(input, limits)
    }

    /// Look up the value of a tag by key, if present.
    ///
    /// Returns `Some(None)` for a valueless tag (`key` with no `=value`) and
    /// `Some(Some(_))` for a tag with a value. Returns `None` if absent.
    #[must_use]
    pub fn tag(&self, key: &str) -> Option<Option<&Cow<'a, str>>> {
        self.tags
            .iter()
            .find(|t| t.key == key)
            .map(|t| t.value.as_ref())
    }
}

/// An IRCv3 message tag: `key` or `key=value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag<'a> {
    /// The tag key, including any `+` client-tag prefix and vendor path.
    pub key: &'a str,
    /// The decoded (unescaped) value, or `None` for a valueless tag.
    pub value: Option<Cow<'a, str>>,
}

/// A message source prefix.
///
/// A server source has only [`Source::name`]; a user source additionally
/// carries [`Source::user`] and/or [`Source::host`]. The parser does not force
/// a server-vs-user interpretation — use [`Source::is_server`] for a heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source<'a> {
    /// The nickname or server name.
    pub name: &'a str,
    /// The user/ident component (after `!`), if present.
    pub user: Option<&'a str>,
    /// The host component (after `@`), if present.
    pub host: Option<&'a str>,
}

impl Source<'_> {
    /// Heuristic: a source with no user/host whose name contains a `.` is
    /// almost certainly a server (nicknames may not contain `.`).
    #[must_use]
    pub fn is_server(&self) -> bool {
        self.user.is_none() && self.host.is_none() && self.name.contains('.')
    }
}

/// A message command: a named verb or a numeric reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// A named command (e.g. `PRIVMSG`). Case is preserved as received;
    /// compare case-insensitively with [`Command::eq_name`].
    Named(&'a str),
    /// A 3-digit numeric reply (000–999). Rendered zero-padded to three digits.
    Numeric(u16),
}

impl Command<'_> {
    /// Case-insensitive comparison against a named command.
    #[must_use]
    pub fn eq_name(&self, name: &str) -> bool {
        matches!(self, Command::Named(n) if n.eq_ignore_ascii_case(name))
    }

    /// The named command as a string, or `None` for a numeric.
    #[must_use]
    pub fn as_name(&self) -> Option<&str> {
        match self {
            Command::Named(n) => Some(n),
            Command::Numeric(_) => None,
        }
    }
}
