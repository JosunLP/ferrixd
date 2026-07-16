//! Account store: authentication material for SASL.
//!
//! Passwords are stored only as Argon2id PHC hashes (memory-hard, salted), never
//! in plaintext, and verified in constant time. The live store is in-memory,
//! seeded from configuration and from accounts users registered themselves
//! (those are persisted — see [`crate::chanreg`]). `EXTERNAL` (client-certificate)
//! auth maps a SHA-256 certificate fingerprint to an account.
//!
//! Account names are matched case-insensitively via the configured
//! [`crate::casemap::CaseMapping`].

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use dashmap::DashMap;
use subtle::ConstantTimeEq;

use crate::casemap::CaseMapping;
use crate::scram::{self, ScramCreds};

/// PBKDF2 iterations for SCRAM credential derivation.
const SCRAM_ITERATIONS: u32 = 4096;

/// One account's stored credentials.
#[derive(Debug, Clone)]
struct Account {
    /// The canonical display name (preserving case).
    display: String,
    /// Argon2id PHC hash of the password, if password login is allowed.
    password_hash: Option<String>,
    /// SCRAM-SHA-256 credentials (only when seeded from a plaintext password).
    scram: Option<ScramCreds>,
    /// SHA-256 certificate fingerprints (lowercase hex) permitted for EXTERNAL.
    fingerprints: Vec<String>,
}

/// An in-memory account store.
#[derive(Debug)]
pub struct AccountStore {
    casemapping: CaseMapping,
    accounts: DashMap<String, Account>,
}

/// Why an authentication attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No such account, or the credential did not match.
    InvalidCredentials,
}

impl AccountStore {
    /// Create an empty store.
    #[must_use]
    pub fn new(casemapping: CaseMapping) -> Self {
        Self {
            casemapping,
            accounts: DashMap::new(),
        }
    }

    /// Hash a plaintext password into an Argon2id PHC string for storage, using a
    /// **deterministic** salt derived from `salt_seed`.
    ///
    /// This is retained only for test fixtures and other callers that genuinely
    /// need reproducible output. Production credential creation (`REGISTER`,
    /// config-seeded plaintext accounts and operators) uses
    /// [`hash_password_random`](Self::hash_password_random) so that identical
    /// passwords never yield identical hashes.
    ///
    /// # Errors
    ///
    /// Returns an error string if hashing fails (e.g. bad parameters).
    pub fn hash_password(password: &str, salt_seed: &str) -> Result<String, String> {
        // Normalise the seed to a valid Argon2 salt length.
        let mut seed = salt_seed.as_bytes().to_vec();
        while seed.len() < 16 {
            seed.push(b'.');
        }
        seed.truncate(48);
        let salt = SaltString::encode_b64(&seed).map_err(|e| e.to_string())?;
        Self::hash_with_salt(password, &salt)
    }

    /// Hash a plaintext password into an Argon2id PHC string using a fresh random
    /// per-password salt gathered from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error string if entropy cannot be gathered or hashing fails.
    pub fn hash_password_random(password: &str) -> Result<String, String> {
        let salt = random_salt_string()?;
        Self::hash_with_salt(password, &salt)
    }

    fn hash_with_salt(password: &str, salt: &SaltString) -> Result<String, String> {
        Argon2::default()
            .hash_password(password.as_bytes(), salt)
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    }

    /// Register or overwrite an account with a pre-computed password hash (no
    /// SCRAM credentials, since the plaintext is unavailable).
    pub fn upsert_password(&self, name: &str, password_hash: String) {
        let key = self.casemapping.fold(name);
        self.accounts
            .entry(key)
            .and_modify(|a| a.password_hash = Some(password_hash.clone()))
            .or_insert_with(|| Account {
                display: name.to_owned(),
                password_hash: Some(password_hash),
                scram: None,
                fingerprints: Vec::new(),
            });
    }

    /// Attach pre-computed SCRAM-SHA-256 credentials to an account (config
    /// `scram = "…"`). This is how a `password_hash`-only account — whose
    /// plaintext the server never sees — becomes SCRAM-capable.
    pub fn upsert_scram(&self, name: &str, creds: ScramCreds) {
        let key = self.casemapping.fold(name);
        self.accounts
            .entry(key)
            .and_modify(|a| a.scram = Some(creds.clone()))
            .or_insert_with(|| Account {
                display: name.to_owned(),
                password_hash: None,
                scram: Some(creds),
                fingerprints: Vec::new(),
            });
    }

    /// The SCRAM iteration count used when deriving credentials from plaintext.
    #[must_use]
    pub const fn scram_iterations() -> u32 {
        SCRAM_ITERATIONS
    }

    /// Set an account's password from plaintext, deriving both the Argon2 hash
    /// (for PLAIN) and SCRAM-SHA-256 credentials.
    ///
    /// # Errors
    ///
    /// Returns an error string if Argon2 hashing fails.
    pub fn set_password(&self, name: &str, password: &str) -> Result<(), String> {
        let hash = Self::hash_password_random(password)?;
        // Independent random salt for the SCRAM credentials (RFC 5802 §3): a
        // per-account salt so identical passwords never derive identical keys.
        let scram_salt = random_salt_bytes()?;
        let creds = scram::derive(password, &scram_salt, SCRAM_ITERATIONS);
        let key = self.casemapping.fold(name);
        self.accounts
            .entry(key)
            .and_modify(|a| {
                a.password_hash = Some(hash.clone());
                a.scram = Some(creds.clone());
            })
            .or_insert_with(|| Account {
                display: name.to_owned(),
                password_hash: Some(hash),
                scram: Some(creds),
                fingerprints: Vec::new(),
            });
        Ok(())
    }

    /// SCRAM credentials for an account (canonical name + creds).
    #[must_use]
    pub fn scram_lookup(&self, name: &str) -> Option<(String, ScramCreds)> {
        let key = self.casemapping.fold(name);
        let account = self.accounts.get(&key)?;
        account
            .scram
            .as_ref()
            .map(|c| (account.display.clone(), c.clone()))
    }

    /// Add a permitted certificate fingerprint (lowercase hex) to an account.
    pub fn add_fingerprint(&self, name: &str, fingerprint: String) {
        let key = self.casemapping.fold(name);
        self.accounts
            .entry(key)
            .and_modify(|a| a.fingerprints.push(fingerprint.clone()))
            .or_insert_with(|| Account {
                display: name.to_owned(),
                password_hash: None,
                scram: None,
                fingerprints: vec![fingerprint],
            });
    }

    /// Export an account's stored credentials for persistence:
    /// `(display, password_hash, scram)`.
    #[must_use]
    pub fn snapshot(&self, name: &str) -> Option<(String, Option<String>, Option<ScramCreds>)> {
        let account = self.accounts.get(&self.casemapping.fold(name))?;
        Some((
            account.display.clone(),
            account.password_hash.clone(),
            account.scram.clone(),
        ))
    }

    /// Restore an account from persisted credentials, unless the name already
    /// exists (config-defined accounts win over persisted self-registrations).
    pub fn restore_if_absent(
        &self,
        display: &str,
        password_hash: Option<String>,
        scram: Option<ScramCreds>,
    ) {
        let key = self.casemapping.fold(display);
        self.accounts.entry(key).or_insert_with(|| Account {
            display: display.to_owned(),
            password_hash,
            scram,
            fingerprints: Vec::new(),
        });
    }

    /// Remove all accounts (used before re-seeding on `REHASH`).
    pub fn clear(&self) {
        self.accounts.clear();
    }

    /// Number of accounts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Whether the store has no accounts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Whether an account with this (folded) name exists.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        self.accounts.contains_key(&self.casemapping.fold(name))
    }

    /// Verify a SASL PLAIN login. On success returns the canonical account name.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidCredentials`] if the account is unknown, has
    /// no password set, or the password does not verify.
    pub fn verify_password(&self, name: &str, password: &str) -> Result<String, AuthError> {
        let key = self.casemapping.fold(name);
        let account = self
            .accounts
            .get(&key)
            .ok_or(AuthError::InvalidCredentials)?;
        let hash = account
            .password_hash
            .as_deref()
            .ok_or(AuthError::InvalidCredentials)?;
        let parsed = PasswordHash::new(hash).map_err(|_| AuthError::InvalidCredentials)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map(|()| account.display.clone())
            .map_err(|_| AuthError::InvalidCredentials)
    }

    /// Verify a SASL EXTERNAL login by certificate fingerprint. If `name` is
    /// non-empty it must match the account the fingerprint belongs to.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidCredentials`] if no account authorizes the
    /// fingerprint (or the requested `name` does not match).
    pub fn verify_fingerprint(&self, name: &str, fingerprint: &str) -> Result<String, AuthError> {
        for account in self.accounts.iter() {
            let matches = account
                .fingerprints
                .iter()
                .any(|fp| fp.as_bytes().ct_eq(fingerprint.as_bytes()).into());
            if matches {
                if !name.is_empty()
                    && self.casemapping.fold(name) != self.casemapping.fold(&account.display)
                {
                    return Err(AuthError::InvalidCredentials);
                }
                return Ok(account.display.clone());
            }
        }
        Err(AuthError::InvalidCredentials)
    }
}

/// Gather 16 random bytes from the OS CSPRNG for use as a credential salt.
fn random_salt_bytes() -> Result<[u8; 16], String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| format!("gathering entropy for salt: {e}"))?;
    Ok(bytes)
}

/// A random Argon2 [`SaltString`] gathered from the OS CSPRNG.
fn random_salt_string() -> Result<SaltString, String> {
    SaltString::encode_b64(&random_salt_bytes()?).map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn store() -> AccountStore {
        let store = AccountStore::new(CaseMapping::Ascii);
        let hash = AccountStore::hash_password("s3cret", "fixedsaltvalue").unwrap();
        store.upsert_password("Alice", hash);
        store.add_fingerprint("Alice", "deadbeef".to_owned());
        store
    }

    #[test]
    fn password_roundtrip_and_case_insensitive() {
        let s = store();
        assert_eq!(s.verify_password("alice", "s3cret").unwrap(), "Alice");
        assert_eq!(s.verify_password("ALICE", "s3cret").unwrap(), "Alice");
    }

    #[test]
    fn wrong_password_and_unknown_account_rejected() {
        let s = store();
        assert_eq!(
            s.verify_password("alice", "wrong"),
            Err(AuthError::InvalidCredentials)
        );
        assert_eq!(
            s.verify_password("nobody", "s3cret"),
            Err(AuthError::InvalidCredentials)
        );
    }

    #[test]
    fn set_password_uses_distinct_random_salts() {
        let s = AccountStore::new(CaseMapping::Ascii);
        s.set_password("alice", "hunter2").unwrap();
        s.set_password("bob", "hunter2").unwrap();
        // Same password under two accounts must not produce identical hashes.
        let (_, ca) = s.scram_lookup("alice").unwrap();
        let (_, cb) = s.scram_lookup("bob").unwrap();
        assert_ne!(ca.salt, cb.salt, "SCRAM salts must be random per account");
        // ...yet both still verify.
        assert_eq!(s.verify_password("alice", "hunter2").unwrap(), "alice");
        assert_eq!(s.verify_password("bob", "hunter2").unwrap(), "bob");
        // Re-setting the same password re-salts (new hash), still verifies.
        let (_, before) = s.scram_lookup("alice").unwrap();
        s.set_password("alice", "hunter2").unwrap();
        let (_, after) = s.scram_lookup("alice").unwrap();
        assert_ne!(before.salt, after.salt);
        assert_eq!(s.verify_password("alice", "hunter2").unwrap(), "alice");
    }

    #[test]
    fn password_hash_account_can_scram_with_an_explicit_credential() {
        // The production-recommended shape: a hash-only account (the server
        // never sees the plaintext) plus the SCRAM credential minted alongside
        // it. Without the credential SCRAM is impossible; with it, it works.
        let s = AccountStore::new(CaseMapping::Ascii);
        let hash = AccountStore::hash_password("hunter2", "saltyseedvalue").unwrap();
        s.upsert_password("Alice", hash);
        assert!(
            s.scram_lookup("alice").is_none(),
            "a hash-only account has no SCRAM material"
        );

        let creds = scram::derive("hunter2", b"0123456789abcdef", SCRAM_ITERATIONS);
        let token = creds.encode();
        s.upsert_scram("Alice", ScramCreds::decode(&token).unwrap());

        let (display, found) = s.scram_lookup("alice").unwrap();
        assert_eq!(display, "Alice");
        assert_eq!(found.stored_key, creds.stored_key);
        assert_eq!(found.server_key, creds.server_key);
        // PLAIN keeps working from the Argon2 hash.
        assert_eq!(s.verify_password("alice", "hunter2").unwrap(), "Alice");
    }

    #[test]
    fn fingerprint_auth() {
        let s = store();
        assert_eq!(s.verify_fingerprint("", "deadbeef").unwrap(), "Alice");
        assert_eq!(s.verify_fingerprint("alice", "deadbeef").unwrap(), "Alice");
        assert_eq!(
            s.verify_fingerprint("bob", "deadbeef"),
            Err(AuthError::InvalidCredentials)
        );
        assert_eq!(
            s.verify_fingerprint("", "0000"),
            Err(AuthError::InvalidCredentials)
        );
    }
}
