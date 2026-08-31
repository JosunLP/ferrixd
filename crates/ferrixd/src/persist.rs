//! SQLite write-behind persistence for message history.
//!
//! Durability is kept off the hot path: [`crate::history::History::record`]
//! enqueues each message to an unbounded channel, and a dedicated OS thread
//! owns the SQLite connection and drains the queue in batched transactions.
//! On startup the most recent messages are loaded back into the in-memory ring.

use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use tokio::sync::mpsc;
use tracing::warn;

use crate::history::{MessageKind, PersistItem, PersistOp, StoredMessage};

/// Rows kept in the database (older rows are pruned at startup).
const RETAIN_ROWS: i64 = 100_000;
/// Maximum inserts coalesced into a single transaction.
const BATCH: usize = 256;

/// History loaded from disk at startup.
#[derive(Debug)]
pub struct Loaded {
    /// `(folded_target, message)` in chronological order.
    pub messages: Vec<(String, Arc<StoredMessage>)>,
    /// The next msgid counter (one past the highest loaded).
    pub next_id: u64,
}

fn kind_to_i64(kind: MessageKind) -> i64 {
    match kind {
        MessageKind::PrivMsg => 0,
        MessageKind::Notice => 1,
        MessageKind::Join => 2,
        MessageKind::Part => 3,
        MessageKind::Quit => 4,
        MessageKind::Nick => 5,
        MessageKind::Topic => 6,
        MessageKind::Kick => 7,
        MessageKind::Mode => 8,
    }
}

fn kind_from_i64(value: i64) -> MessageKind {
    match value {
        1 => MessageKind::Notice,
        2 => MessageKind::Join,
        3 => MessageKind::Part,
        4 => MessageKind::Quit,
        5 => MessageKind::Nick,
        6 => MessageKind::Topic,
        7 => MessageKind::Kick,
        8 => MessageKind::Mode,
        _ => MessageKind::PrivMsg,
    }
}

/// Open the database, ensure the schema, prune, load the most recent
/// `load_limit` messages, and spawn the write-behind writer thread.
pub fn open(path: &str, load_limit: usize) -> Result<(Loaded, mpsc::UnboundedSender<PersistItem>)> {
    let connection = Connection::open(path).with_context(|| format!("opening database {path}"))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS history (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                folded  TEXT    NOT NULL,
                msgid   TEXT    NOT NULL,
                time_ms INTEGER NOT NULL,
                source  TEXT    NOT NULL,
                account TEXT,
                kind    INTEGER NOT NULL,
                target  TEXT    NOT NULL,
                body    TEXT    NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_history_folded ON history(folded, id);",
        )
        .context("initialising schema")?;

    // Bound the table size.
    connection
        .execute(
            "DELETE FROM history WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM history) - ?1",
            params![RETAIN_ROWS],
        )
        .context("pruning history")?;

    let loaded = load(&connection, load_limit).context("loading history")?;

    let (tx, rx) = mpsc::unbounded_channel();
    thread::Builder::new()
        .name("ferrixd-persist".to_owned())
        .spawn(move || writer_loop(connection, rx))
        .context("spawning persistence thread")?;

    Ok((loaded, tx))
}

fn load(connection: &Connection, load_limit: usize) -> Result<Loaded> {
    let mut stmt = connection.prepare(
        "SELECT folded, msgid, time_ms, source, account, kind, target, body
         FROM history ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![load_limit as i64], |row| {
        let folded: String = row.get(0)?;
        let message = StoredMessage {
            msgid: row.get(1)?,
            time_ms: row.get::<_, i64>(2)? as u64,
            source: row.get(3)?,
            account: row.get(4)?,
            kind: kind_from_i64(row.get(5)?),
            target: row.get(6)?,
            text: row.get(7)?,
        };
        Ok((folded, message))
    })?;

    let mut messages: Vec<(String, Arc<StoredMessage>)> = Vec::new();
    let mut max_counter: u64 = 0;
    for row in rows {
        let (folded, message) = row?;
        // A minted msgid is `<sid>-<hex counter>` (bare hex in old databases);
        // ids from other servers simply fail to parse and are skipped.
        let counter_part = message.msgid.rsplit('-').next().unwrap_or("");
        if let Ok(counter) = u64::from_str_radix(counter_part, 16) {
            max_counter = max_counter.max(counter);
        }
        messages.push((folded, Arc::new(message)));
    }
    messages.reverse(); // oldest-first
    Ok(Loaded {
        messages,
        next_id: max_counter + 1,
    })
}

fn writer_loop(connection: Connection, mut rx: mpsc::UnboundedReceiver<PersistItem>) {
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        while batch.len() < BATCH {
            match rx.try_recv() {
                Ok(item) => batch.push(item),
                Err(_) => break,
            }
        }
        if let Err(err) = write_batch(&connection, &batch) {
            warn!(%err, "history persistence write failed");
        }
        // Release any shutdown barrier in this batch only once the rows that
        // preceded it are committed.
        for op in batch {
            if let PersistOp::Flush(ack) = op {
                let _ = ack.send(());
            }
        }
    }
}

fn write_batch(connection: &Connection, batch: &[PersistItem]) -> rusqlite::Result<()> {
    let tx = connection.unchecked_transaction()?;
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO history (folded, msgid, time_ms, source, account, kind, target, body)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for op in batch {
            match op {
                PersistOp::Store(folded, message) => {
                    insert.execute(params![
                        folded,
                        message.msgid,
                        message.time_ms as i64,
                        message.source,
                        message.account,
                        kind_to_i64(message.kind),
                        message.target,
                        message.text,
                    ])?;
                }
                PersistOp::Delete { folded, msgid } => {
                    tx.prepare_cached("DELETE FROM history WHERE folded = ?1 AND msgid = ?2")?
                        .execute(params![folded, msgid])?;
                }
                PersistOp::Rename { old, new } => {
                    tx.prepare_cached("UPDATE history SET folded = ?2 WHERE folded = ?1")?
                        .execute(params![old, new])?;
                }
                // Acknowledged by the caller after this transaction commits.
                PersistOp::Flush(_) => {}
            }
        }
    }
    tx.commit()
}
