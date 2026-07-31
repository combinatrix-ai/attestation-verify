//! Feature-gated adapters for the repository's separate cargo-fuzz crate.
//!
//! These functions deliberately expose only `Result`-returning, parser-level
//! entry points. They are hidden from normal generated documentation and are
//! not compiled unless the `fuzzing` feature is selected; the default library
//! API and dependency graph are unchanged.

use crate::error::Error;

/// Parses one decoded Rekor canonicalized body without entering verification.
///
/// This adapter lets the external fuzz crate exercise the parser before
/// cryptographic binding checks reject a mutated body.
pub fn parse_rekor_canonicalized_body(bytes: &[u8]) -> Result<(), Error> {
    crate::parse_util::check_input_size(bytes)?;
    crate::rekor::parse_tlog_entry_body(bytes).map(|_| ())
}

/// Parses one Rekor signed-note/checkpoint envelope.
pub fn parse_checkpoint(envelope: &str) -> Result<(), Error> {
    crate::parse_util::check_input_size(envelope.as_bytes())?;
    crate::rekor::parse_checkpoint(envelope).map(|_| ())
}

/// Parses one TLS-encoded RFC 6962 `SignedCertificateTimestampList`.
pub fn parse_sct_list(bytes: &[u8]) -> Result<(), Error> {
    crate::parse_util::check_input_size(bytes)?;
    crate::sct::parse_sct_list(bytes).map(|_| ())
}

/// Parses one RFC 3339 timestamp using the same field parser as trusted-root
/// validity windows.
pub fn parse_rfc3339(timestamp: &str) -> Result<i64, Error> {
    crate::parse_util::check_input_size(timestamp.as_bytes())?;
    crate::time::parse_rfc3339("fuzzing.timestamp", timestamp).map_err(Error::from)
}
