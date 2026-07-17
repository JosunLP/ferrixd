//! ferrixd — library surface.
//!
//! The daemon's building blocks live here so that both the `ferrixd` binary
//! and the integration tests (`tests/`) can drive them. See the binary
//! (`src/main.rs`) for the process entrypoint.

pub mod account;
pub mod cap;
pub mod casemap;
pub mod chanreg;
pub mod cli;
pub mod cloak;
pub mod codec;
pub mod command;
pub mod config;
pub mod connection;
pub mod deliver;
pub mod history;
pub mod link;
pub mod listener;
pub mod mask;
pub mod metrics;
pub mod numeric;
pub mod persist;
pub mod plugin;
pub mod s2s;
pub mod sasl;
pub mod scram;
pub mod session;
pub mod state;
pub mod tls;
pub mod ts6;
pub mod websocket;
pub mod wire;
