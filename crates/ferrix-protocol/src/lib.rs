//! `ferrix-protocol` — zero-copy IRC / IRCv3 message parsing and encoding.
//!
//! This crate is deliberately dependency-light and free of async and I/O code
//! so that it can be fuzzed and audited in isolation. It is the
//! security-critical hot path of the daemon (see the technical plan, §4.2).
//!
//! # Zero-copy
//!
//! Parsing borrows directly from the input buffer: [`Message`] holds `&str`
//! slices into the bytes you hand to [`parse`]. The only allocations happen
//! when an IRCv3 tag value contains escape sequences and must be unescaped —
//! and even then a [`std::borrow::Cow`] keeps the common (escape-free) case
//! borrowed.
//!
//! # Robustness
//!
//! The parser never panics on hostile input. Every failure is a
//! [`ParseError`]. Tag and body length budgets are tracked **separately**
//! (IRCv3 message-tags add a tag budget on top of the classic 512-byte frame).
//!
//! # Example
//!
//! ```
//! use ferrix_protocol::{Command, Message};
//!
//! let msg = Message::parse(b"@time=2026-07-08T00:00:00.000Z :nick!u@host PRIVMSG #chan :hi there")
//!     .expect("valid message");
//! assert_eq!(msg.command, Command::Named("PRIVMSG"));
//! assert_eq!(msg.params.as_slice(), ["#chan", "hi there"]);
//! assert_eq!(msg.source.unwrap().name, "nick");
//! assert_eq!(msg.tags[0].key, "time");
//! ```

pub mod encode;
pub mod limits;
pub mod message;
pub mod parser;
pub mod tags;

pub use limits::Limits;
pub use message::{Command, Message, Params, Source, Tag, Tags};
pub use parser::{ParseError, parse};
