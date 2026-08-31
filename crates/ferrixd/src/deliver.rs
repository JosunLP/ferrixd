//! Per-recipient message delivery with IRCv3 message tags.
//!
//! A propagated event (PRIVMSG, JOIN, QUIT, …) has a fixed body but may carry
//! tags that only *some* recipients have negotiated — `@time` for `server-time`,
//! `@account` for `account-tag`. Rather than serialize once and send the same
//! bytes to everyone, an [`Event`] is rendered per recipient according to their
//! capabilities, with results cached by the tag-relevant cap bits so a large
//! channel still does O(distinct cap profiles) work, not O(members).

use bytes::Bytes;
use smallvec::SmallVec;

use crate::cap::{Cap, CapSet};
use crate::state::{ChannelEntry, ClientEntry};

/// A message whose leading tags — and optionally a body suffix — depend on the
/// recipient's capabilities.
#[derive(Debug, Clone)]
pub struct Event {
    /// The fixed line body: `:source COMMAND params [:trailing]` (no CRLF).
    body: String,
    /// `server-time` value, attached for recipients with that cap.
    time: Option<String>,
    /// `account-tag` value (the source's account), attached for recipients with
    /// that cap.
    account: Option<String>,
    /// `msgid` value, attached for recipients with `message-tags`.
    msgid: Option<String>,
    /// Client-only tags to forward verbatim (already `key=value;key2` form, no
    /// leading `@`), shown to recipients with `message-tags` — used by `TAGMSG`.
    client_tags: Option<String>,
    /// A body suffix appended only for recipients that have a given cap (used by
    /// `extended-join`: ` <account> :<realname>`).
    suffix: Option<(Cap, String)>,
    /// A `batch` reference attached only for recipients holding a given cap —
    /// `draft/multiline` clients see the lines grouped in a batch, everyone else
    /// gets plain messages (the spec's fallback).
    batch: Option<(Cap, String)>,
    /// IRCv3 bot-mode: when the source is a bot (`+B`), a bare `@bot` tag is
    /// added for recipients with `message-tags`.
    bot: bool,
}

impl Event {
    /// Create an event from a rendered body (see [`crate::wire::Line::body`]).
    #[must_use]
    pub fn new(body: String) -> Self {
        Self {
            body,
            time: None,
            account: None,
            msgid: None,
            client_tags: None,
            suffix: None,
            batch: None,
            bot: false,
        }
    }

    /// Mark this event as originating from a bot (`+B`), so a bare `@bot` tag is
    /// shown to recipients with `message-tags`.
    #[must_use]
    pub fn with_bot(mut self, bot: bool) -> Self {
        self.bot = bot;
        self
    }

    /// Group this event into `reference` for recipients that have `cap`.
    #[must_use]
    pub fn with_batch(mut self, cap: Cap, reference: String) -> Self {
        self.batch = Some((cap, reference));
        self
    }

    /// Attach forwarded client-only tags (shown to `message-tags` recipients).
    #[must_use]
    pub fn with_client_tags(mut self, tags: String) -> Self {
        self.client_tags = Some(tags);
        self
    }

    /// Attach a `msgid` (shown to `message-tags` recipients).
    #[must_use]
    pub fn with_msgid(mut self, msgid: String) -> Self {
        self.msgid = Some(msgid);
        self
    }

    /// Attach a `server-time` timestamp (shown to `server-time` recipients).
    #[must_use]
    pub fn with_time(mut self, time: String) -> Self {
        self.time = Some(time);
        self
    }

    /// Attach the source's account name (shown to `account-tag` recipients).
    #[must_use]
    pub fn with_account(mut self, account: Option<String>) -> Self {
        self.account = account;
        self
    }

    /// Append `suffix` to the body for recipients that have `cap`.
    #[must_use]
    pub fn with_suffix(mut self, cap: Cap, suffix: String) -> Self {
        self.suffix = Some((cap, suffix));
        self
    }

    /// The cap bits that affect this event's rendered form.
    fn variant_mask(&self) -> u32 {
        let mut mask = 0;
        if self.time.is_some() {
            mask |= Cap::ServerTime.bit();
        }
        if self.account.is_some() {
            mask |= Cap::AccountTag.bit();
        }
        if self.msgid.is_some() || self.client_tags.is_some() || self.bot {
            mask |= Cap::MessageTags.bit();
        }
        if let Some((cap, _)) = &self.suffix {
            mask |= cap.bit();
        }
        if let Some((cap, _)) = &self.batch {
            mask |= cap.bit();
        }
        mask
    }

    /// Render the line for a recipient with the given capabilities.
    #[must_use]
    pub fn render_for(&self, caps: CapSet) -> Bytes {
        let mut out = String::with_capacity(self.body.len() + 64);
        let mut wrote_tag = false;
        let sep = |out: &mut String, wrote: &mut bool| {
            out.push(if *wrote { ';' } else { '@' });
            *wrote = true;
        };
        if let Some((cap, reference)) = &self.batch
            && caps.has(*cap)
        {
            sep(&mut out, &mut wrote_tag);
            out.push_str("batch=");
            out.push_str(reference);
        }
        if let Some(tags) = &self.client_tags
            && caps.has(Cap::MessageTags)
        {
            sep(&mut out, &mut wrote_tag);
            out.push_str(tags);
        }
        if let Some(time) = &self.time
            && caps.has(Cap::ServerTime)
        {
            sep(&mut out, &mut wrote_tag);
            out.push_str("time=");
            out.push_str(time);
        }
        if let Some(msgid) = &self.msgid
            && caps.has(Cap::MessageTags)
        {
            sep(&mut out, &mut wrote_tag);
            out.push_str("msgid=");
            out.push_str(msgid);
        }
        if let Some(account) = &self.account
            && caps.has(Cap::AccountTag)
        {
            sep(&mut out, &mut wrote_tag);
            out.push_str("account=");
            out.push_str(account);
        }
        if self.bot && caps.has(Cap::MessageTags) {
            sep(&mut out, &mut wrote_tag);
            out.push_str("bot");
        }
        if wrote_tag {
            out.push(' ');
        }
        out.push_str(&self.body);
        if let Some((cap, suffix)) = &self.suffix
            && caps.has(*cap)
        {
            out.push_str(suffix);
        }
        out.push_str("\r\n");
        Bytes::from(out)
    }
}

/// Deliver an event to a single client, tailored to its capabilities.
pub fn to_client(entry: &ClientEntry, event: &Event) {
    entry.send(event.render_for(entry.caps()));
}

/// Deliver an event to every member of a channel, optionally skipping one
/// client id. Results are cached by the variant-relevant cap bits.
pub fn to_channel(channel: &ChannelEntry, event: &Event, except: Option<u64>) {
    to_channel_filtered(channel, event, except, None, None);
}

/// Like [`to_channel`], but only to members that have `required` (used by
/// `away-notify`, `account-notify`, `chghost`, `invite-notify`).
pub fn to_channel_capped(
    channel: &ChannelEntry,
    event: &Event,
    required: Cap,
    except: Option<u64>,
) {
    to_channel_filtered(channel, event, except, Some(required), None);
}

/// Like [`to_channel`], but only to members holding a channel status: ops for
/// `op_only`, ops or voiced otherwise (STATUSMSG `@#chan` / `+#chan`).
pub fn to_channel_status(
    channel: &ChannelEntry,
    event: &Event,
    op_only: bool,
    except: Option<u64>,
) {
    to_channel_filtered(channel, event, except, None, Some(op_only));
}

fn to_channel_filtered(
    channel: &ChannelEntry,
    event: &Event,
    except: Option<u64>,
    required: Option<Cap>,
    status: Option<bool>,
) {
    let mask = event.variant_mask();
    let data = channel.data.lock();
    // Cache rendered bytes per distinct cap-profile. A channel typically has
    // only a handful of distinct profiles, so a small linear-scanned vector
    // beats a HashMap here — no hashing and no heap allocation in the common
    // case (this sits directly on the message fan-out path).
    let mut cache: SmallVec<[(u32, Bytes); 4]> = SmallVec::new();
    for member in data.members.values() {
        if Some(member.entry.id) == except {
            continue;
        }
        let caps = member.entry.caps();
        if required.is_some_and(|cap| !caps.has(cap)) {
            continue;
        }
        if let Some(op_only) = status
            && !member.prefix.op
            && (op_only || !member.prefix.voice)
        {
            continue;
        }
        let key = caps.masked(mask).bits();
        let bytes = match cache.iter().find(|(k, _)| *k == key) {
            Some((_, bytes)) => bytes.clone(),
            None => {
                let bytes = event.render_for(caps);
                cache.push((key, bytes.clone()));
                bytes
            }
        };
        member.entry.send(bytes);
    }
}
