//! ferrixd — the Ferrous IRC Daemon.
//!
//! The binary is a thin shim: all argument parsing, subcommand dispatch, and the
//! server bootstrap live in [`ferrixd::cli`] (in the library crate) so they can
//! be unit-tested. Run `ferrixd --help` for the full command surface.

use std::process::ExitCode;

fn main() -> ExitCode {
    ferrixd::cli::main()
}
