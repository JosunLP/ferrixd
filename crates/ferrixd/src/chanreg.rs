//! Channel and account registration persistence.
//!
//! Registered channels have a founder account and retain their topic and modes;
//! self-registered accounts (`REGISTER`) keep their credentials. Unlike message
//! history (a high-frequency write-behind queue), registrations are rare, so
//! this store owns its own SQLite connection behind a `Mutex` and writes
//! synchronously. The live [`crate::state::ChannelEntry`] stays ephemeral
//! — the registration record is the source of truth and re-seeds the channel
//! whenever it is next created.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use tracing::warn;

use crate::scram::ScramCreds;

/// `+n` no-external-messages.
pub const MODE_NO_EXTERNAL: u8 = 1;
/// `+t` topic locked to ops.
pub const MODE_TOPIC_LOCK: u8 = 2;
/// `+m` moderated.
pub const MODE_MODERATED: u8 = 4;
/// `+i` invite-only.
pub const MODE_INVITE_ONLY: u8 = 8;
/// `+s` secret.
pub const MODE_SECRET: u8 = 16;

/// A persisted channel registration.
#[derive(Debug, Clone)]
pub struct RegisteredChannel {
    /// Folded channel name (primary key).
    pub folded: String,
    /// Display channel name.
    pub name: String,
    /// Founder account.
    pub founder: String,
    /// Retained topic text, if any.
    pub topic_text: Option<String>,
    /// Who set the topic.
    pub topic_setby: String,
    /// When the topic was set (Unix seconds).
    pub topic_setat: u64,
    /// Bitfield of the boolean channel modes (see the `MODE_*` constants).
    pub mode_flags: u8,
    /// `+k` key.
    pub key: Option<String>,
    /// `+l` member limit.
    pub limit: Option<u64>,
}

/// A persisted self-registered account (credentials only; certificate
/// fingerprints stay config-managed).
#[derive(Debug, Clone)]
pub struct AccountRecord {
    /// Folded account name (primary key).
    pub folded: String,
    /// Display account name.
    pub display: String,
    /// Argon2id PHC hash for PLAIN, if password login is allowed.
    pub password_hash: Option<String>,
    /// SCRAM-SHA-256 credentials, if derived from a plaintext password.
    pub scram: Option<ScramCreds>,
}

/// A synchronous SQLite store for channel registrations.
#[derive(Debug)]
pub struct ChanRegStore {
    connection: Mutex<Connection>,
}

impl ChanRegStore {
    /// Open (creating if needed) the store and load all registrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or the schema/query
    /// fails.
    pub fn open(path: &str) -> Result<(ChanRegStore, Vec<RegisteredChannel>)> {
        let connection =
            Connection::open(path).with_context(|| format!("opening channel db {path}"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS channels (
                    folded      TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    founder     TEXT NOT NULL,
                    topic_text  TEXT,
                    topic_setby TEXT NOT NULL,
                    topic_setat INTEGER NOT NULL,
                    mode_flags  INTEGER NOT NULL,
                    key         TEXT,
                    lim         INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS accounts (
                    folded           TEXT PRIMARY KEY,
                    display          TEXT NOT NULL,
                    password_hash    TEXT,
                    scram_salt       BLOB,
                    scram_iterations INTEGER,
                    scram_stored_key BLOB,
                    scram_server_key BLOB
                 );",
            )
            .context("initialising channel schema")?;
        let loaded = Self::load(&connection).context("loading channel registrations")?;
        Ok((
            ChanRegStore {
                connection: Mutex::new(connection),
            },
            loaded,
        ))
    }

    fn load(connection: &Connection) -> Result<Vec<RegisteredChannel>> {
        let mut stmt = connection.prepare(
            "SELECT folded, name, founder, topic_text, topic_setby, topic_setat,
                    mode_flags, key, lim FROM channels",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RegisteredChannel {
                folded: row.get(0)?,
                name: row.get(1)?,
                founder: row.get(2)?,
                topic_text: row.get(3)?,
                topic_setby: row.get(4)?,
                topic_setat: row.get::<_, i64>(5)? as u64,
                mode_flags: row.get::<_, i64>(6)? as u8,
                key: row.get(7)?,
                limit: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Insert or replace a registration (best-effort; logs on failure).
    pub fn upsert(&self, record: &RegisteredChannel) {
        let result = self.connection.lock().execute(
            "INSERT OR REPLACE INTO channels
                (folded, name, founder, topic_text, topic_setby, topic_setat, mode_flags, key, lim)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.folded,
                record.name,
                record.founder,
                record.topic_text,
                record.topic_setby,
                record.topic_setat as i64,
                i64::from(record.mode_flags),
                record.key,
                record.limit.map(|v| v as i64),
            ],
        );
        if let Err(err) = result {
            warn!(%err, channel = %record.name, "channel registration write failed");
        }
    }

    /// Delete a registration (best-effort; logs on failure).
    pub fn delete(&self, folded: &str) {
        if let Err(err) = self
            .connection
            .lock()
            .execute("DELETE FROM channels WHERE folded = ?1", params![folded])
        {
            warn!(%err, %folded, "channel registration delete failed");
        }
    }

    /// Insert or replace a self-registered account (best-effort; logs on failure).
    pub fn upsert_account(&self, record: &AccountRecord) {
        let (salt, iterations, stored_key, server_key) = match &record.scram {
            Some(creds) => (
                Some(creds.salt.clone()),
                Some(i64::from(creds.iterations)),
                Some(creds.stored_key.to_vec()),
                Some(creds.server_key.to_vec()),
            ),
            None => (None, None, None, None),
        };
        let result = self.connection.lock().execute(
            "INSERT OR REPLACE INTO accounts
                (folded, display, password_hash, scram_salt, scram_iterations,
                 scram_stored_key, scram_server_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.folded,
                record.display,
                record.password_hash,
                salt,
                iterations,
                stored_key,
                server_key,
            ],
        );
        if let Err(err) = result {
            warn!(%err, account = %record.display, "account registration write failed");
        }
    }

    /// All persisted self-registered accounts (malformed rows are skipped).
    #[must_use]
    pub fn load_accounts(&self) -> Vec<AccountRecord> {
        let connection = self.connection.lock();
        let Ok(mut stmt) = connection.prepare(
            "SELECT folded, display, password_hash, scram_salt, scram_iterations,
                    scram_stored_key, scram_server_key FROM accounts",
        ) else {
            return Vec::new();
        };
        let rows = stmt.query_map([], |row| {
            let salt: Option<Vec<u8>> = row.get(3)?;
            let iterations: Option<i64> = row.get(4)?;
            let stored_key: Option<Vec<u8>> = row.get(5)?;
            let server_key: Option<Vec<u8>> = row.get(6)?;
            let scram = match (salt, iterations, stored_key, server_key) {
                (Some(salt), Some(iterations), Some(stored), Some(server)) => {
                    match (stored.try_into(), server.try_into()) {
                        (Ok(stored_key), Ok(server_key)) => Some(ScramCreds {
                            salt,
                            iterations: iterations as u32,
                            stored_key,
                            server_key,
                        }),
                        _ => None,
                    }
                }
                _ => None,
            };
            Ok(AccountRecord {
                folded: row.get(0)?,
                display: row.get(1)?,
                password_hash: row.get(2)?,
                scram,
            })
        });
        match rows {
            Ok(rows) => rows.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn upsert_survives_reopen() {
        let path = std::env::temp_dir()
            .join(format!("ferrixd-chanreg-{}.db", std::process::id()))
            .display()
            .to_string();
        let _ = std::fs::remove_file(&path);

        let record = RegisteredChannel {
            folded: "#room".to_owned(),
            name: "#Room".to_owned(),
            founder: "alice".to_owned(),
            topic_text: Some("hello".to_owned()),
            topic_setby: "alice".to_owned(),
            topic_setat: 1234,
            mode_flags: MODE_NO_EXTERNAL | MODE_MODERATED,
            key: Some("sekret".to_owned()),
            limit: Some(42),
        };

        {
            let (store, loaded) = ChanRegStore::open(&path).unwrap();
            assert!(loaded.is_empty());
            store.upsert(&record);
        }

        // Reopen a fresh connection: the record must load back verbatim.
        let (_store, loaded) = ChanRegStore::open(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        let got = &loaded[0];
        assert_eq!(got.name, "#Room");
        assert_eq!(got.founder, "alice");
        assert_eq!(got.topic_text.as_deref(), Some("hello"));
        assert_eq!(got.mode_flags, MODE_NO_EXTERNAL | MODE_MODERATED);
        assert_eq!(got.key.as_deref(), Some("sekret"));
        assert_eq!(got.limit, Some(42));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn account_upsert_survives_reopen_with_scram_creds() {
        let path = std::env::temp_dir()
            .join(format!("ferrixd-accreg-{}.db", std::process::id()))
            .display()
            .to_string();
        let _ = std::fs::remove_file(&path);

        let creds = crate::scram::derive("hunter2", b"0123456789abcdef", 4096);
        let record = AccountRecord {
            folded: "alice".to_owned(),
            display: "Alice".to_owned(),
            password_hash: Some("$argon2id$fake".to_owned()),
            scram: Some(creds.clone()),
        };

        {
            let (store, _) = ChanRegStore::open(&path).unwrap();
            assert!(store.load_accounts().is_empty());
            store.upsert_account(&record);
        }

        let (store, _) = ChanRegStore::open(&path).unwrap();
        let loaded = store.load_accounts();
        assert_eq!(loaded.len(), 1);
        let got = &loaded[0];
        assert_eq!(got.display, "Alice");
        assert_eq!(got.password_hash.as_deref(), Some("$argon2id$fake"));
        let got_scram = got.scram.as_ref().unwrap();
        assert_eq!(got_scram.salt, creds.salt);
        assert_eq!(got_scram.iterations, creds.iterations);
        assert_eq!(got_scram.stored_key, creds.stored_key);
        assert_eq!(got_scram.server_key, creds.server_key);

        let _ = std::fs::remove_file(&path);
    }
}
