//! Rendering messages back to the wire.
//!
//! Primarily used for tests and round-trip fuzzing today; the daemon's hot
//! outbound path will build lines through this same logic so a message is
//! serialized once and the resulting bytes reference-counted to every
//! recipient.

use std::fmt::Write as _;

use crate::message::{Command, Message};
use crate::tags::escape_value;

impl Message<'_> {
    /// Render this message to its wire form, including the trailing CRLF.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out);
        out
    }

    /// Append this message's wire form (including trailing CRLF) to `out`.
    pub fn render_into(&self, out: &mut String) {
        if !self.tags.is_empty() {
            out.push('@');
            for (i, tag) in self.tags.iter().enumerate() {
                if i > 0 {
                    out.push(';');
                }
                out.push_str(tag.key);
                if let Some(value) = &tag.value {
                    out.push('=');
                    out.push_str(&escape_value(value));
                }
            }
            out.push(' ');
        }

        if let Some(source) = &self.source {
            out.push(':');
            out.push_str(source.name);
            if let Some(user) = source.user {
                out.push('!');
                out.push_str(user);
            }
            if let Some(host) = source.host {
                out.push('@');
                out.push_str(host);
            }
            out.push(' ');
        }

        match self.command {
            Command::Named(name) => out.push_str(name),
            // `write!` to a String is infallible; ignore the Result rather than
            // unwrap (no panics in the data path).
            Command::Numeric(n) => {
                let _ = write!(out, "{n:03}");
            }
        }

        let last = self.params.len().wrapping_sub(1);
        for (i, param) in self.params.iter().enumerate() {
            out.push(' ');
            // The final parameter must be prefixed with ':' if it is empty,
            // contains a space, or begins with ':' — otherwise it would not
            // round-trip as a single trailing parameter.
            let needs_colon =
                i == last && (param.is_empty() || param.contains(' ') || param.starts_with(':'));
            if needs_colon {
                out.push(':');
            }
            out.push_str(param);
        }

        out.push_str("\r\n");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::{Limits, Message};

    fn round_trip(input: &[u8]) {
        let parsed = Message::parse(input).expect("parse input");
        let rendered = parsed.render();
        let reparsed = Message::parse_with(rendered.as_bytes(), &Limits::default())
            .expect("re-parse rendered");
        // Compare structurally via Debug so the two messages keep independent
        // lifetimes (comparing the values directly would force the borrow
        // checker to unify the input buffer's lifetime with `rendered`'s).
        assert_eq!(
            format!("{parsed:?}"),
            format!("{reparsed:?}"),
            "round-trip mismatch for {input:?} -> {rendered:?}"
        );
    }

    #[test]
    fn round_trips() {
        for input in [
            &b"PING"[..],
            b"PING :token",
            b"PRIVMSG #chan :hello world",
            b"PRIVMSG #chan :",
            b"PRIVMSG #chan ::-)",
            b":nick!user@host JOIN #chan",
            b":irc.example.net 001 nick :Welcome",
            b"@id=1;+draft/x=a\\sb :n!u@h TAGMSG #c",
            b"CMD a b c d e f :and the rest",
        ] {
            round_trip(input);
        }
    }

    #[test]
    fn numeric_is_zero_padded() {
        // A 1-digit token is not a valid command.
        assert!(Message::parse(b"1 x :y").is_err());
        // The numeric is zero-padded to three digits. The final single-word
        // param needs no leading ':' (it round-trips without one).
        let m = Message::parse(b"001 nick :hi").expect("parse");
        assert_eq!(m.render(), "001 nick hi\r\n");
    }

    #[test]
    fn tag_values_are_escaped_on_render() {
        let m = Message::parse(b"@k=a\\sb PING").expect("parse");
        // Value decoded to "a b"; must re-escape the space on the way out.
        assert_eq!(m.render(), "@k=a\\sb PING\r\n");
    }
}
