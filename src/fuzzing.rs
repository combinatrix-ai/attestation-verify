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

/// Verifies one Rekor signed-note/checkpoint envelope against the embedded
/// public-good root's Rekor v1 log key.
///
/// The one adapter here that goes past parsing. It exists because the
/// checkpoint signature block is the only place in this crate where the
/// *amount* of cryptographic work is chosen by the input: the key-hint
/// filter, the `MAX_CHECKPOINT_SIGNATURES` bound, and the ECDSA loop all
/// live after `parse_checkpoint` returns, so a parser-only target cannot
/// reach them. Running them under libFuzzer puts that loop under the
/// `-timeout` and `-rss_limit_mb` budgets.
///
/// The envelope is anchored to its own tree size and root hash — see
/// [`crate::rekor::verify_checkpoint_self_anchored`] for why.
pub fn verify_checkpoint(envelope: &str) -> Result<(), Error> {
    crate::parse_util::check_input_size(envelope.as_bytes())?;
    let (log, log_key) = embedded_rekor_v1_log()?;
    crate::rekor::verify_checkpoint_self_anchored(envelope, log, log_key)
}

/// A transparency log and the verifying key parsed from it.
type SelectedLog = (
    crate::trust::TransparencyLog,
    crate::dsse::EcdsaVerifyingKey,
);

/// The embedded public-good root's first ECDSA transparency log, parsed
/// once.
///
/// Cached because the alternative — re-parsing the trust root on every
/// fuzz iteration — would dominate the run and starve the code actually
/// under test. Selection is by key algorithm rather than by URL or index
/// so that a trust-root refresh reordering the list cannot silently point
/// this target at a different log.
fn embedded_rekor_v1_log() -> Result<&'static SelectedLog, Error> {
    use std::sync::OnceLock;

    static LOG: OnceLock<Option<SelectedLog>> = OnceLock::new();

    LOG.get_or_init(|| {
        let trust_store = crate::trust::TrustStore::embedded_public_good().ok()?;
        trust_store.tlogs.iter().find_map(|log| {
            let key =
                crate::dsse::EcdsaVerifyingKey::from_spki_der(&log.public_key.raw_bytes).ok()?;
            Some((log.clone(), key))
        })
    })
    .as_ref()
    .ok_or(Error::Transparency(
        crate::error::TransparencyError::UnknownLogKey,
    ))
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
