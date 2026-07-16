//! Wire-length budgets.
//!
//! IRCv3 message-tags introduce a tag budget that is *independent* of the
//! classic RFC 1459 message frame. The parser must track the two separately
//! and never let one steal from the other.

/// Length budgets used while parsing a single message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum length, in bytes, of the tag section — the data between the
    /// leading `@` and the space that separates tags from the rest of the
    /// message (the `@` and the space themselves are not counted).
    ///
    /// IRCv3 sizes the client tag data at 4094 bytes and the total (including
    /// server-added tags) at 8191 bytes; [`Limits::IRCV3_TAG_BYTES`] uses the
    /// larger total as a safe cap.
    pub max_tag_bytes: usize,

    /// Maximum length, in bytes, of the message body — everything after the
    /// tag section (source + command + params), excluding the trailing CRLF.
    ///
    /// RFC 1459's frame is 512 bytes *including* CRLF; we compare against the
    /// CRLF-stripped body, so a value of 512 is intentionally a hair more
    /// generous than the strict 510 — this is a denial-of-service cap, and
    /// leniency here is harmless.
    pub max_body_bytes: usize,
}

impl Limits {
    /// The IRCv3 total tag-data budget, in bytes.
    pub const IRCV3_TAG_BYTES: usize = 8191;

    /// The classic RFC 1459 message frame, in bytes (including CRLF).
    pub const RFC1459_BODY_BYTES: usize = 512;

    /// Budgets for a modern IRCv3 server: full tag budget plus classic body.
    #[must_use]
    pub const fn ircv3() -> Self {
        Self {
            max_tag_bytes: Self::IRCV3_TAG_BYTES,
            max_body_bytes: Self::RFC1459_BODY_BYTES,
        }
    }

    /// Budgets for a strict, tag-less RFC 1459 dialect.
    #[must_use]
    pub const fn rfc1459() -> Self {
        Self {
            max_tag_bytes: 0,
            max_body_bytes: Self::RFC1459_BODY_BYTES,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::ircv3()
    }
}
