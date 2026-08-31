//! Server-side message history for `draft/chathistory`.
//!
//! Hot data lives in a bounded per-target ring in RAM; durable storage
//! (SQLite) is layered on top as write-behind. Each stored message keeps the
//! `msgid` it was delivered with, so a `CHATHISTORY` replay references the exact
//! same ids the client saw live.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

/// An operation queued for durable storage.
#[derive(Debug)]
pub enum PersistOp {
    /// Store a message under a folded target.
    Store(String, Arc<StoredMessage>),
    /// Delete one message by msgid (draft/message-redaction).
    Delete {
        /// The folded target the message was stored under.
        folded: String,
        /// The message id to delete.
        msgid: String,
    },
    /// Re-key every row of a target (draft/channel-rename).
    Rename {
        /// The old folded target.
        old: String,
        /// The new folded target.
        new: String,
    },
    /// A shutdown barrier: the writer acknowledges it once every operation
    /// queued *before* it has been committed. The queue is FIFO, so this is a
    /// complete drain of everything accepted so far.
    Flush(oneshot::Sender<()>),
}

/// A `(folded_target, message)` pair queued for durable storage.
pub type PersistItem = PersistOp;

/// What a stored history entry represents: a message (`PRIVMSG`/`NOTICE`) or a
/// membership/state event replayed only to `draft/event-playback` clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// `PRIVMSG`.
    PrivMsg,
    /// `NOTICE`.
    Notice,
    /// A user joined the channel.
    Join,
    /// A user left the channel (`text` = reason, may be empty).
    Part,
    /// A user quit while in the channel (`text` = reason).
    Quit,
    /// A user changed nick while in the channel (`text` = new nick).
    Nick,
    /// The topic changed (`text` = new topic, empty = cleared).
    Topic,
    /// A user was kicked (`text` = `<victim> <reason>`).
    Kick,
    /// A channel mode change (`text` = `<flags> [args…]`).
    Mode,
}

impl MessageKind {
    /// The IRC command verb.
    #[must_use]
    pub fn command(self) -> &'static str {
        match self {
            MessageKind::PrivMsg => "PRIVMSG",
            MessageKind::Notice => "NOTICE",
            MessageKind::Join => "JOIN",
            MessageKind::Part => "PART",
            MessageKind::Quit => "QUIT",
            MessageKind::Nick => "NICK",
            MessageKind::Topic => "TOPIC",
            MessageKind::Kick => "KICK",
            MessageKind::Mode => "MODE",
        }
    }

    /// Whether this is a plain message (always replayed) rather than an event
    /// (replayed only to `draft/event-playback` clients).
    #[must_use]
    pub fn is_message(self) -> bool {
        matches!(self, MessageKind::PrivMsg | MessageKind::Notice)
    }
}

/// A single message retained for history replay.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Unique, monotonically-increasing message id (also the `msgid` tag).
    pub msgid: String,
    /// Delivery time in epoch milliseconds (the `server-time` value).
    pub time_ms: u64,
    /// The sender's `nick!user@host` at send time.
    pub source: String,
    /// The sender's account, for `account-tag`.
    pub account: Option<String>,
    /// PRIVMSG vs NOTICE.
    pub kind: MessageKind,
    /// The display target (channel name).
    pub target: String,
    /// The message text.
    pub text: String,
}

/// The private history key for a direct-message conversation between two folded
/// nicks (symmetric; contains a NUL so it cannot collide with a channel name).
#[must_use]
pub fn pair_key(a: &str, b: &str) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    format!("@dm\0{lo}\0{hi}")
}

/// A point selector for a history query: `*`, `timestamp=…`, or `msgid=…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// `*` — the newest end.
    Latest,
    /// A `server-time` instant in epoch milliseconds.
    Timestamp(u64),
    /// A specific message id.
    MsgId(String),
}

/// The history log: a bounded ring per folded target.
///
/// Two independent bounds keep memory finite: each ring holds at most
/// `max_per_target` messages, and the *number* of rings is capped at
/// `max_targets`. The latter is essential — direct-message history is keyed by
/// a per-conversation pair key, so without a cap the ring count grows as
/// O(users²), and channel rings would otherwise outlive the channels that
/// created them. When a new target would exceed the cap, the least-recently-
/// active rings are evicted.
#[derive(Debug)]
pub struct History {
    max_per_target: usize,
    max_targets: usize,
    log: DashMap<String, Arc<Mutex<VecDeque<Arc<StoredMessage>>>>>,
    next_id: AtomicU64,
    /// Prepended to every minted msgid (the server's SID plus `-`), making ids
    /// unique network-wide — required for cross-server `msgid` references
    /// (replies, reactions, redaction). Empty until [`History::set_msgid_prefix`].
    msgid_prefix: OnceLock<String>,
    persist: OnceLock<mpsc::UnboundedSender<PersistItem>>,
}

impl History {
    /// Create a history keeping at most `max_per_target` messages per target and
    /// at most `max_targets` distinct targets (rings) in memory.
    #[must_use]
    pub fn new(max_per_target: usize, max_targets: usize) -> Self {
        Self {
            max_per_target: max_per_target.max(1),
            max_targets: max_targets.max(1),
            log: DashMap::new(),
            next_id: AtomicU64::new(1),
            msgid_prefix: OnceLock::new(),
            persist: OnceLock::new(),
        }
    }

    /// Set the msgid prefix (the server's SID; called once at startup). Minted
    /// ids become `<sid>-<counter>` so they cannot collide across servers.
    pub fn set_msgid_prefix(&self, sid: &str) {
        let _ = self.msgid_prefix.set(format!("{sid}-"));
    }

    /// Attach a write-behind persistence sink (called once at startup).
    pub fn attach_persistence(&self, sink: mpsc::UnboundedSender<PersistItem>) {
        let _ = self.persist.set(sink);
    }

    /// Queue a flush barrier; the returned receiver resolves once everything
    /// enqueued before it has been committed to disk. `None` when persistence
    /// is not attached (there is nothing to drain).
    pub fn flush_barrier(&self) -> Option<oneshot::Receiver<()>> {
        let sink = self.persist.get()?;
        let (tx, rx) = oneshot::channel();
        sink.send(PersistOp::Flush(tx)).ok()?;
        Some(rx)
    }

    /// Seed the msgid counter after loading persisted history so new ids stay
    /// unique and monotonic across restarts.
    pub fn seed_next_id(&self, next: u64) {
        self.next_id.store(next.max(1), Ordering::Relaxed);
    }

    /// Allocate a unique, monotonically-increasing message id.
    pub fn next_msgid(&self) -> String {
        let prefix = self.msgid_prefix.get().map_or("", String::as_str);
        format!(
            "{prefix}{:016x}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Load a message into memory only (no re-persist); used at startup.
    pub fn load(&self, folded_target: &str, message: Arc<StoredMessage>) {
        self.push(folded_target, message);
    }

    /// Record a message under `folded_target`: keep it in the in-memory ring and
    /// enqueue it for durable storage if persistence is attached.
    pub fn record(&self, folded_target: &str, message: Arc<StoredMessage>) {
        self.push(folded_target, message.clone());
        if let Some(sink) = self.persist.get() {
            let _ = sink.send(PersistOp::Store(folded_target.to_owned(), message));
        }
    }

    /// Look up a message by msgid (draft/message-redaction permission checks).
    #[must_use]
    pub fn find(&self, folded_target: &str, msgid: &str) -> Option<Arc<StoredMessage>> {
        let ring = self.log.get(folded_target)?;

        ring.lock().iter().find(|m| m.msgid == msgid).cloned()
    }

    /// Remove a message by msgid from the ring and durable storage
    /// (draft/message-redaction). Returns the removed message, if found.
    pub fn redact(&self, folded_target: &str, msgid: &str) -> Option<Arc<StoredMessage>> {
        let removed = {
            let ring = self.log.get(folded_target)?;
            let mut ring = ring.lock();
            let index = ring.iter().position(|m| m.msgid == msgid)?;
            ring.remove(index)
        };
        if removed.is_some()
            && let Some(sink) = self.persist.get()
        {
            let _ = sink.send(PersistOp::Delete {
                folded: folded_target.to_owned(),
                msgid: msgid.to_owned(),
            });
        }
        removed
    }

    /// Move a target's ring to a new key (draft/channel-rename) and re-key the
    /// persisted rows.
    pub fn rename_target(&self, old_folded: &str, new_folded: &str) {
        if let Some((_, ring)) = self.log.remove(old_folded) {
            self.log.insert(new_folded.to_owned(), ring);
        }
        if let Some(sink) = self.persist.get() {
            let _ = sink.send(PersistOp::Rename {
                old: old_folded.to_owned(),
                new: new_folded.to_owned(),
            });
        }
    }

    fn push(&self, folded_target: &str, message: Arc<StoredMessage>) {
        // Soft-bound the ring count before allocating a new target. The check is
        // best-effort under concurrency (a small transient overshoot is fine —
        // this is a memory guard, not an invariant).
        if self.log.len() >= self.max_targets && !self.log.contains_key(folded_target) {
            self.evict_oldest();
        }
        let ring = self
            .log
            .entry(folded_target.to_owned())
            .or_default()
            .clone();
        let mut ring = ring.lock();
        ring.push_back(message);
        while ring.len() > self.max_per_target {
            ring.pop_front();
        }
    }

    /// Evict a batch of the least-recently-active rings so that sustained
    /// new-target pressure amortises the O(n) scan across many insertions.
    fn evict_oldest(&self) {
        let batch = (self.max_targets / 32).max(1);
        let mut by_age: Vec<(String, u64)> = self
            .log
            .iter()
            .map(|e| {
                (
                    e.key().clone(),
                    e.value().lock().back().map_or(0, |m| m.time_ms),
                )
            })
            .collect();
        by_age.sort_unstable_by_key(|(_, t)| *t);
        for (key, _) in by_age.into_iter().take(batch) {
            self.log.remove(&key);
        }
    }

    /// Drop a target's ring entirely (e.g. a channel that has been reaped and
    /// whose history is no longer wanted in memory). Persisted rows are
    /// unaffected.
    pub fn forget(&self, folded_target: &str) {
        self.log.remove(folded_target);
    }

    /// The number of distinct targets currently retained in memory.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.log.len()
    }

    /// A chronological snapshot of a target's ring. Without `include_events`,
    /// membership/state events are filtered out (draft/event-playback: only
    /// capable clients see them, and limits count the entries actually sent).
    fn snapshot(&self, folded_target: &str, include_events: bool) -> Vec<Arc<StoredMessage>> {
        match self.log.get(folded_target) {
            Some(ring) => ring
                .lock()
                .iter()
                .filter(|m| include_events || m.kind.is_message())
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// The newest `limit` messages more recent than `after` (`*` = no bound).
    #[must_use]
    pub fn latest(
        &self,
        folded_target: &str,
        after: &Selector,
        limit: usize,
        include_events: bool,
    ) -> Vec<Arc<StoredMessage>> {
        let msgs = self.snapshot(folded_target, include_events);
        let filtered = filter_after(&msgs, after);
        take_last(filtered, limit)
    }

    /// The `limit` messages immediately before `point`, chronological.
    #[must_use]
    pub fn before(
        &self,
        folded_target: &str,
        point: &Selector,
        limit: usize,
        include_events: bool,
    ) -> Vec<Arc<StoredMessage>> {
        let msgs = self.snapshot(folded_target, include_events);
        let filtered = filter_before(&msgs, point);
        take_last(filtered, limit)
    }

    /// The `limit` messages immediately after `point`, chronological.
    #[must_use]
    pub fn after(
        &self,
        folded_target: &str,
        point: &Selector,
        limit: usize,
        include_events: bool,
    ) -> Vec<Arc<StoredMessage>> {
        let msgs = self.snapshot(folded_target, include_events);
        let filtered = filter_after(&msgs, point);
        take_first(filtered, limit)
    }

    /// Up to `limit` messages centred on `point` (half before, half after).
    #[must_use]
    pub fn around(
        &self,
        folded_target: &str,
        point: &Selector,
        limit: usize,
        include_events: bool,
    ) -> Vec<Arc<StoredMessage>> {
        let msgs = self.snapshot(folded_target, include_events);
        let Some(anchor) = resolve_index(&msgs, point) else {
            return Vec::new();
        };
        let half = limit / 2;
        let start = anchor.saturating_sub(half);
        let end = anchor.saturating_add(half + 1).min(msgs.len());
        take_first(msgs[start..end].to_vec(), limit)
    }

    /// Up to `limit` messages strictly between the two points, chronological.
    #[must_use]
    pub fn between(
        &self,
        folded_target: &str,
        a: &Selector,
        b: &Selector,
        limit: usize,
        include_events: bool,
    ) -> Vec<Arc<StoredMessage>> {
        let msgs = self.snapshot(folded_target, include_events);
        let (Some(ia), Some(ib)) = (resolve_index(&msgs, a), resolve_index(&msgs, b)) else {
            return Vec::new();
        };
        let (lo, hi) = (ia.min(ib), ia.max(ib));
        let start = (lo + 1).min(msgs.len());
        let end = hi.min(msgs.len());
        if start >= end {
            return Vec::new();
        }
        take_first(msgs[start..end].to_vec(), limit)
    }

    /// Targets with activity in `[after, before]`, as `(folded_key, latest_ms)`,
    /// most-recent first, capped at `limit`. The caller maps each key to what
    /// the requester should see — a channel name, or the *other* party of a DM
    /// conversation (see [`pair_key`]), which the stored `target` alone cannot
    /// give (it names whoever received the last message).
    #[must_use]
    pub fn targets(&self, after: &Selector, before: &Selector, limit: usize) -> Vec<(String, u64)> {
        let lo = selector_time(after).unwrap_or(0);
        let hi = selector_time(before).unwrap_or(u64::MAX);
        let (lo, hi) = (lo.min(hi), lo.max(hi));
        let mut out: Vec<(String, u64)> = Vec::new();
        for entry in self.log.iter() {
            let ring = entry.value().lock();
            if let Some(last) = ring
                .iter()
                .rev()
                .find(|m| m.time_ms >= lo && m.time_ms <= hi && m.kind.is_message())
            {
                out.push((entry.key().clone(), last.time_ms));
            }
        }
        out.sort_by_key(|(_, time)| std::cmp::Reverse(*time));
        out.truncate(limit);
        out
    }
}

/// The two folded nicks of a direct-message ring key, or `None` for a channel.
#[must_use]
pub fn pair_parties(folded_key: &str) -> Option<(&str, &str)> {
    let rest = folded_key.strip_prefix("@dm\0")?;
    rest.split_once('\0')
}

/// The index of the message matching `selector`, or `None` if unresolved.
fn resolve_index(msgs: &[Arc<StoredMessage>], selector: &Selector) -> Option<usize> {
    match selector {
        Selector::Latest => Some(msgs.len().saturating_sub(1)),
        Selector::Timestamp(ts) => Some(msgs.partition_point(|m| m.time_ms < *ts)),
        Selector::MsgId(id) => msgs.iter().position(|m| &m.msgid == id),
    }
}

/// The nominal time of a selector, if it has one.
fn selector_time(selector: &Selector) -> Option<u64> {
    match selector {
        Selector::Timestamp(ts) => Some(*ts),
        _ => None,
    }
}

fn filter_before(msgs: &[Arc<StoredMessage>], point: &Selector) -> Vec<Arc<StoredMessage>> {
    match point {
        Selector::Latest => msgs.to_vec(),
        Selector::Timestamp(ts) => msgs.iter().filter(|m| m.time_ms < *ts).cloned().collect(),
        Selector::MsgId(id) => match msgs.iter().position(|m| &m.msgid == id) {
            Some(i) => msgs[..i].to_vec(),
            None => Vec::new(),
        },
    }
}

fn filter_after(msgs: &[Arc<StoredMessage>], point: &Selector) -> Vec<Arc<StoredMessage>> {
    match point {
        Selector::Latest => msgs.to_vec(),
        Selector::Timestamp(ts) => msgs.iter().filter(|m| m.time_ms > *ts).cloned().collect(),
        Selector::MsgId(id) => match msgs.iter().position(|m| &m.msgid == id) {
            Some(i) => msgs[i + 1..].to_vec(),
            None => Vec::new(),
        },
    }
}

fn take_last(mut v: Vec<Arc<StoredMessage>>, limit: usize) -> Vec<Arc<StoredMessage>> {
    if v.len() > limit {
        v.drain(..v.len() - limit);
    }
    v
}

fn take_first(mut v: Vec<Arc<StoredMessage>>, limit: usize) -> Vec<Arc<StoredMessage>> {
    v.truncate(limit);
    v
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn msg(id: u64, t: u64) -> Arc<StoredMessage> {
        Arc::new(StoredMessage {
            msgid: format!("{id:016x}"),
            time_ms: t,
            source: "n!u@h".to_owned(),
            account: None,
            kind: MessageKind::PrivMsg,
            target: "#c".to_owned(),
            text: format!("m{id}"),
        })
    }

    fn seeded() -> History {
        let h = History::new(100, 1000);
        for i in 1..=5 {
            h.record("#c", msg(i, i * 10));
        }
        h
    }

    fn texts(v: &[Arc<StoredMessage>]) -> Vec<String> {
        v.iter().map(|m| m.text.clone()).collect()
    }

    #[test]
    fn latest_returns_newest() {
        let h = seeded();
        assert_eq!(
            texts(&h.latest("#c", &Selector::Latest, 2, true)),
            ["m4", "m5"]
        );
        assert_eq!(
            texts(&h.latest("#c", &Selector::Latest, 100, true)).len(),
            5
        );
    }

    #[test]
    fn before_and_after_by_timestamp() {
        let h = seeded();
        assert_eq!(
            texts(&h.before("#c", &Selector::Timestamp(30), 10, true)),
            ["m1", "m2"]
        );
        assert_eq!(
            texts(&h.after("#c", &Selector::Timestamp(30), 10, true)),
            ["m4", "m5"]
        );
    }

    #[test]
    fn before_and_after_by_msgid() {
        let h = seeded();
        let mid = format!("{:016x}", 3);
        assert_eq!(
            texts(&h.before("#c", &Selector::MsgId(mid.clone()), 10, true)),
            ["m1", "m2"]
        );
        assert_eq!(
            texts(&h.after("#c", &Selector::MsgId(mid), 10, true)),
            ["m4", "m5"]
        );
    }

    #[test]
    fn between_is_exclusive() {
        let h = seeded();
        let (a, b) = (format!("{:016x}", 1), format!("{:016x}", 5));
        assert_eq!(
            texts(&h.between("#c", &Selector::MsgId(a), &Selector::MsgId(b), 10, true)),
            ["m2", "m3", "m4"]
        );
    }

    #[test]
    fn ring_is_bounded() {
        let h = History::new(3, 1000);
        for i in 1..=5 {
            h.record("#c", msg(i, i));
        }
        assert_eq!(
            texts(&h.latest("#c", &Selector::Latest, 10, true)),
            ["m3", "m4", "m5"]
        );
    }

    #[test]
    fn ring_count_is_capped() {
        // A cap of 32 → batch eviction of 1 per overflow. Push far more distinct
        // targets than the cap; the ring count must stay bounded, and the most
        // recently active target must survive.
        let h = History::new(10, 32);
        for i in 1..=500u64 {
            h.record(&format!("#c{i}"), msg(i, i));
        }
        assert!(
            h.target_count() <= 32,
            "ring count {} exceeded cap",
            h.target_count()
        );
        // The newest target is still present.
        assert_eq!(h.latest("#c500", &Selector::Latest, 1, true).len(), 1);
        // A long-evicted early target is gone.
        assert!(h.latest("#c1", &Selector::Latest, 1, true).is_empty());
    }
}
