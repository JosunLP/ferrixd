//! Building outbound protocol lines.
//!
//! Handlers construct owned lines here rather than borrowed [`ferrix_protocol`]
//! `Message`s: the server owns the data it emits, and on channel broadcast a
//! line is serialized **once** into [`Bytes`] whose reference-counted handle is
//! cloned to every recipient.
//!
//! Spacing convention: the source prefix (if any) already ends with a space,
//! [`Line::command`]/[`Line::code`] never add a leading space, and every
//! [`Line::param`]/[`Line::trailing`] prepends one.

use std::fmt::Write as _;

use bytes::Bytes;

/// A partially-built protocol line.
#[derive(Debug, Clone)]
pub struct Line {
    buf: String,
}

impl Line {
    /// Start a line with a server source prefix: `:server `.
    #[must_use]
    pub fn server(server: &str) -> Self {
        let mut buf = String::with_capacity(64);
        buf.push(':');
        buf.push_str(server);
        buf.push(' ');
        Self { buf }
    }

    /// Start a line with a user source prefix: `:nick!user@host `.
    #[must_use]
    pub fn user(nick: &str, user: &str, host: &str) -> Self {
        let mut buf = String::with_capacity(64);
        buf.push(':');
        buf.push_str(nick);
        buf.push('!');
        buf.push_str(user);
        buf.push('@');
        buf.push_str(host);
        buf.push(' ');
        Self { buf }
    }

    /// Start a line with no source prefix.
    #[must_use]
    pub fn bare() -> Self {
        Self {
            buf: String::with_capacity(32),
        }
    }

    /// Append the command verb (first token, no leading space).
    #[must_use]
    pub fn command(mut self, command: &str) -> Self {
        self.buf.push_str(command);
        self
    }

    /// Append a 3-digit numeric reply code (first token, no leading space).
    #[must_use]
    pub fn code(mut self, code: u16) -> Self {
        let _ = write!(self.buf, "{code:03}");
        self
    }

    /// Append a middle parameter (prefixed with a space).
    #[must_use]
    pub fn param(mut self, param: &str) -> Self {
        self.buf.push(' ');
        self.buf.push_str(param);
        self
    }

    /// Append the trailing parameter (` :...`), which may contain spaces.
    #[must_use]
    pub fn trailing(mut self, trailing: &str) -> Self {
        self.buf.push_str(" :");
        self.buf.push_str(trailing);
        self
    }

    /// Finish the line (appending CRLF) and freeze it into [`Bytes`].
    #[must_use]
    pub fn build(mut self) -> Bytes {
        self.buf.push_str("\r\n");
        Bytes::from(self.buf)
    }

    /// The accumulated line body **without** a trailing CRLF or leading tags —
    /// used as the fixed part of a per-recipient tagged [`crate::deliver::Event`].
    #[must_use]
    pub fn body(self) -> String {
        self.buf
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn numeric_line() {
        let b = Line::server("irc.test")
            .code(1)
            .param("nick")
            .trailing("Welcome to the network")
            .build();
        assert_eq!(&b[..], b":irc.test 001 nick :Welcome to the network\r\n");
    }

    #[test]
    fn user_sourced_privmsg() {
        let b = Line::user("alice", "~a", "host")
            .command("PRIVMSG")
            .param("#chan")
            .trailing("hello world")
            .build();
        assert_eq!(&b[..], b":alice!~a@host PRIVMSG #chan :hello world\r\n");
    }

    #[test]
    fn bare_command() {
        let b = Line::bare().command("PONG").param("irc.test").build();
        assert_eq!(&b[..], b"PONG irc.test\r\n");
    }
}
