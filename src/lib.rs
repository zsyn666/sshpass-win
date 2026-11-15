//! A Windows-native, sshpass-compatible password provider.
//!
//! The public surface is intentionally the same as sshpass:
//! `sshpass [options] command [args...]`.  See `cli.rs` for the exact flags.

pub mod cli;
pub mod engine;
pub mod exit;
pub mod password;
pub mod prompt;
pub mod secret;
pub mod which;
