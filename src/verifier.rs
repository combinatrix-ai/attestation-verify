//! The verification entry point.
//!
//! **The verification chain is not implemented yet.** Every
//! [`Verifier::verify_digest`] / [`Verifier::verify_bytes`] call fails
//! closed with [`crate::UnsupportedError::ChainNotImplemented`] after
//! doing only as much parsing as is needed to exercise the parser this
//! crate does implement. There is no code path in this crate that reports
//! a successful verification.

use crate::bundle::Bundle;
use crate::error::{Error, PolicyError, UnsupportedError};
use crate::policy::GithubPolicy;
use crate::subject::Subject;
use crate::trust::TrustStore;

/// Verifies artifact attestations against a trust store and identity
/// policy.
///
/// Trust material and policy are validated once, at
/// [`VerifierBuilder::build`] time, and reused for every `verify_*` call
/// (DESIGN.md "Core decisions" item 5).
///
/// # Current status
///
/// This crate's verification chain is not implemented yet: every
/// `verify_*` method fails closed with
/// [`crate::UnsupportedError::ChainNotImplemented`]. A `Verifier` is
/// still useful today only insofar as constructing one exercises the
/// trust-store and policy parsing/validation this crate does implement.
#[derive(Debug, Clone)]
pub struct Verifier {
    #[allow(dead_code)] // read by the verification chain once implemented.
    trust_store: TrustStore,
    #[allow(dead_code)] // read by the verification chain once implemented.
    github_policy: GithubPolicy,
}

impl Verifier {
    /// Starts building a [`Verifier`].
    #[must_use]
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::default()
    }

    /// Verifies that `bundle` attests to `subject`, under this verifier's
    /// trust store and policy.
    ///
    /// Performs the parsing steps needed to exercise this crate's parser
    /// (decoding and validating the bundle's in-toto statement), then
    /// unconditionally fails closed: **this crate cannot yet report a
    /// successful verification.**
    ///
    /// # Errors
    ///
    /// Returns whatever [`Bundle::statement`] would return if the
    /// bundle's statement fails to parse; otherwise always returns
    /// `Err(`[`Error::Unsupported`]`(`[`UnsupportedError::ChainNotImplemented`]`))`.
    pub fn verify_digest(
        &self,
        _subject: &Subject,
        bundle: &Bundle,
    ) -> Result<VerificationReport, Error> {
        // "Basic input parsing" per this task's scope: exercise the
        // statement parser so a malformed bundle is reported as the
        // specific parse failure it is, rather than being masked by the
        // blanket not-implemented error below.
        let _statement = bundle.statement()?;
        Err(Error::Unsupported(UnsupportedError::ChainNotImplemented))
    }

    /// Convenience wrapper around [`Verifier::verify_digest`] that hashes
    /// `bytes` first.
    ///
    /// # Errors
    ///
    /// Same as [`Verifier::verify_digest`].
    pub fn verify_bytes(&self, bytes: &[u8], bundle: &Bundle) -> Result<VerificationReport, Error> {
        let subject = Subject::sha256_of(bytes);
        self.verify_digest(&subject, bundle)
    }
}

/// Builder for [`Verifier`].
#[derive(Debug, Clone, Default)]
pub struct VerifierBuilder {
    trust_store: Option<TrustStore>,
    github_policy: Option<GithubPolicy>,
}

impl VerifierBuilder {
    /// Sets the trust store (certificate authorities, transparency logs,
    /// timestamp authorities) to verify against.
    #[must_use]
    pub fn trust_store(mut self, trust_store: TrustStore) -> Self {
        self.trust_store = Some(trust_store);
        self
    }

    /// Sets the identity policy to require.
    #[must_use]
    pub fn github_policy(mut self, github_policy: GithubPolicy) -> Self {
        self.github_policy = Some(github_policy);
        self
    }

    /// Builds the verifier.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if either
    /// [`VerifierBuilder::trust_store`] or [`VerifierBuilder::github_policy`]
    /// was never called.
    pub fn build(self) -> Result<Verifier, Error> {
        let trust_store = self.trust_store.ok_or_else(|| {
            Error::Policy(PolicyError::InvalidConfiguration(
                "trust_store is required".to_owned(),
            ))
        })?;
        let github_policy = self.github_policy.ok_or_else(|| {
            Error::Policy(PolicyError::InvalidConfiguration(
                "github_policy is required".to_owned(),
            ))
        })?;
        Ok(Verifier {
            trust_store,
            github_policy,
        })
    }
}

/// The result of a successful verification, split by provenance
/// (DESIGN.md "Core decisions" item 7): certificate-derived facts,
/// transparency-log facts, and workflow-controlled statement content have
/// different trust provenance and are never flattened into one struct.
///
/// **Not yet constructed by any code path in this crate** — the
/// verification chain that would produce one is future work. `#[non_exhaustive]`
/// and privately-unconstructable outside this crate, so no caller can
/// fabricate a report that looks verified.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerificationReport {
    /// The verified subject digest.
    pub subject: VerifiedSubject,
    /// Certificate-derived signer identity.
    pub signer: VerifiedCertificateIdentity,
    /// Transparency-log facts.
    pub transparency: VerifiedTransparency,
    /// The signed statement's own (unverified-against-reality) claims.
    pub statement: VerifiedSignedStatement,
    /// Which trust-root snapshot produced this result.
    pub trust: TrustSnapshotInfo,
}

/// The subject digest that was verified, as bound by the signed
/// statement. Not yet constructed — see [`VerificationReport`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedSubject {
    /// The verified digest.
    pub digest: Subject,
    /// The matched statement subject's name, if it had one.
    pub name: Option<String>,
}

/// Facts extracted from, and authenticated by, the leaf certificate's
/// Fulcio OIDC extensions: SAN issuer, source repository, workflow
/// identity. Certificate-derived: authenticated by the X.509 chain, not
/// by the (attacker-controlled) statement content. Not yet constructed —
/// see [`VerificationReport`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedCertificateIdentity {
    /// The OIDC issuer URL (pinned to GitHub Actions' issuer once
    /// verification is implemented).
    pub issuer: String,
    /// The authenticated source repository, `"owner/name"`.
    pub source_repository: String,
    /// The authenticated source ref.
    pub source_ref: String,
    /// The authenticated signer workflow's repository, `"owner/name"`.
    pub signer_repository: String,
    /// The authenticated signer workflow file path.
    pub signer_workflow_path: String,
}

/// Facts about the transparency-log inclusion: log index and
/// authenticated integration time. Transparency-log-derived:
/// authenticated by the Rekor SET/checkpoint, not by the statement
/// content. Not yet constructed — see [`VerificationReport`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedTransparency {
    /// The entry's index in the log.
    pub log_index: u64,
    /// Unix seconds at which the entry was authenticated as integrated.
    pub integrated_time: u64,
}

/// The signed in-toto statement's own claims. Signed ≠ independently
/// true: this is workflow-controlled content, authenticated only as "the
/// signer said this," not verified against reality. Not yet constructed —
/// see [`VerificationReport`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedSignedStatement {
    /// The predicate type URI.
    pub predicate_type: String,
    /// The opaque predicate body.
    pub predicate: serde_json::Value,
}

/// Identifies which trust-root snapshot produced a verification result,
/// so operators can tell which root made the decision. Not yet
/// constructed — see [`VerificationReport`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TrustSnapshotInfo {
    /// A content fingerprint of the trust-root snapshot used.
    pub fingerprint: String,
    /// The trust-root document's own version label, if any.
    pub version: String,
}
