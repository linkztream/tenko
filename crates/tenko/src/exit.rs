//! Exit statuses of the `tenko` binary.
//!
//! | Status | Meaning |
//! |---|---|
//! | 0 | Success; for `tenko serve`, a graceful shutdown |
//! | 1 | An unexpected failure: I/O, a server that stopped with an error, a bug |
//! | 2 | Usage: invalid arguments, a command that does not exist on this platform, or roles that Phase 1 does not implement |
//! | 3 | The configuration is invalid (`tenko serve`, `tenko config check`) |
//! | 4 | `tenko serve` refused to start: a start step failed; the message names the step and its code |
//! | 5 | The server answered with an error (problem details; the code is printed) |
//! | 6 | Not signed in, or the stored credentials were refused: run `tenko login` |
//! | 7 | The server could not be reached (connection, TLS, timeout) |
//! | 8 | A job or an import ended without success (rolled back, failed, cancelled) |
//! | 9 | `tenko audit verify`: the audit chain does not verify |

/// Success.
pub const OK: u8 = 0;
/// An unexpected failure.
pub const FAILURE: u8 = 1;
/// Invalid usage, or a role Phase 1 does not implement.
pub const USAGE: u8 = 2;
/// The configuration is invalid.
pub const CONFIG: u8 = 3;
/// A start step failed.
pub const START: u8 = 4;
/// The server answered with problem details.
pub const API: u8 = 5;
/// Not signed in, or the credentials were refused.
pub const AUTH: u8 = 6;
/// The server could not be reached.
pub const UNREACHABLE: u8 = 7;
/// A job ended without success.
pub const JOB: u8 = 8;
/// The audit chain does not verify.
pub const INTEGRITY: u8 = 9;
