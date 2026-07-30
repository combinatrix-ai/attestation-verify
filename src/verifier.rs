//! The verification entry point.
//!
//! [`Verifier::verify_digest`] runs the full offline verification chain
//! (DESIGN.md "Verification chain") in a fixed order, each step surfacing
//! its own typed error the moment it fails — there is no step this crate
//! treats as optional, and nothing here is configurable except *what
//! identity to require* ([`GithubPolicy`], via this crate's internal
//! `policy_match` module):
//!
//! 1. Parse the signed in-toto statement from the bundle's DSSE payload
//!    ([`Bundle::statement`]).
//! 2. Check the statement's `predicateType` against this crate's
//!    one-entry allow-list (`https://slsa.dev/provenance/v1`) — anything
//!    else (including GitHub's own release predicate) is a typed
//!    [`UnsupportedError::PredicateType`], never best-effort-interpreted.
//! 3. Bind the requested subject digest to one of the statement's
//!    subjects (`Statement::find_subject`).
//! 4. Verify the bundle's transparency-log entry end to end —
//!    canonicalized-body binding, SET, Merkle inclusion proof, checkpoint,
//!    and time window (this crate's internal `rekor` module, DESIGN.md
//!    "Time-evidence model"). Exactly one entry is required; this is also
//!    the step that turns `integratedTime` into an *authenticated*
//!    timestamp, which every later time-window check is measured against.
//! 5. Validate the leaf certificate's X.509 chain against the trust
//!    store at that authenticated time (this crate's internal `x509`
//!    module). Bundle-supplied roots are never trusted.
//! 6. Verify the DSSE envelope's signature under the validated leaf's
//!    public key (this crate's internal `dsse` module).
//! 7. Verify at least one embedded SCT against a trusted CT log (this
//!    crate's internal `sct` module).
//! 8. Extract the leaf certificate's Fulcio identity claims (this
//!    crate's internal `fulcio` module) — certificate-derived facts, not
//!    statement content.
//! 9. Match those claims against the caller's [`GithubPolicy`] (this
//!    crate's internal `policy_match` module).
//! 10. Assemble the provenance-separated [`VerificationReport`].
//!
//! Steps 4 and 5 mean a trust store carrying no matching transparency-log
//! key fails at step 4 ([`crate::error::TransparencyError::UnknownLogKey`])
//! before the X.509 chain (step 5) is ever examined, even if the chain
//! itself would also have been untrusted — the two are independent trust
//! decisions, and this crate reports whichever it checks first, precisely
//! rather than guessing at which one "really" mattered.
//!
//! See the crate root docs for this crate's current verified scope (Rekor
//! v1 only, one predicate type, the public-good or a caller-supplied
//! trust root).

use crate::bundle::Bundle;
use crate::dsse;
use crate::error::{ContentBindingError, Error, PolicyError, UnsupportedError};
use crate::fulcio;
use crate::policy::GithubPolicy;
use crate::policy_match;
use crate::rekor;
use crate::sct;
use crate::subject::Subject;
use crate::trust::TrustStore;
use crate::x509;

/// The only signed-statement predicate type this crate verifies (v0.1).
/// DESIGN.md "Roadmap": GitHub's own release predicate
/// (`https://in-toto.io/attestation/release/v0.2`) is v0.2 scope, gated
/// behind the same no-tlog-entries / RFC 3161 TSA path this crate does
/// not yet implement.
const SUPPORTED_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";

/// Verifies artifact attestations against a trust store and identity
/// policy.
///
/// Trust material and policy are validated once, at
/// [`VerifierBuilder::build`] time, and reused for every `verify_*` call
/// (DESIGN.md "Core decisions" item 5).
#[derive(Debug, Clone)]
pub struct Verifier {
    trust_store: TrustStore,
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
    /// Runs the full chain described in this module's docs and returns a
    /// provenance-separated [`VerificationReport`] only once every step
    /// has verified.
    ///
    /// # Errors
    ///
    /// Returns the first failing step's typed error (see this module's
    /// docs for the fixed step order): a [`crate::error::ParseError`] or
    /// [`crate::error::UnsupportedError::StatementType`] from
    /// [`Bundle::statement`]; [`UnsupportedError::PredicateType`] if the
    /// predicate type is not on this crate's allow-list;
    /// [`ContentBindingError::SubjectNotFound`] if `subject` is not among
    /// the statement's subjects; a [`crate::error::TransparencyError`],
    /// [`crate::error::CertificateError`], or
    /// [`crate::error::ContentBindingError`] from the transparency-log,
    /// X.509 chain, DSSE, or SCT steps; and otherwise a
    /// [`crate::error::PolicyError`] naming exactly which identity check
    /// failed.
    pub fn verify_digest(
        &self,
        subject: &Subject,
        bundle: &Bundle,
    ) -> Result<VerificationReport, Error> {
        // 1. Parse the signed statement.
        let statement = bundle.statement()?;

        // 2. Predicate-type allow-list (v0.1: SLSA provenance v1 only).
        if statement.predicate_type != SUPPORTED_PREDICATE_TYPE {
            return Err(Error::Unsupported(UnsupportedError::PredicateType {
                found: statement.predicate_type.clone(),
            }));
        }

        // 3. Subject binding: `subject` must be among the statement's
        // (signed but not yet authenticated) claimed subjects.
        let matched_name = statement
            .find_subject(subject)
            .ok_or(Error::ContentBinding(ContentBindingError::SubjectNotFound))?
            .name
            .clone();

        // 4. Transparency log: exactly one entry, fully authenticated.
        // This is what makes `integrated_time` usable as authenticated
        // time below (DESIGN.md "Time-evidence model").
        let verified_timestamp = rekor::verify_tlog_entry(bundle, &self.trust_store)?;
        // `integrated_time` is unix seconds; the saturating conversion
        // mirrors `crate::dsse::unix_seconds`'s handling of the same
        // practically-unreachable overflow (X.509 / Rekor times never
        // approach `i64::MAX` seconds from the epoch).
        let authenticated_time =
            i64::try_from(verified_timestamp.integrated_time).unwrap_or(i64::MAX);

        // 5. X.509 chain, at the authenticated log time. Only
        // `self.trust_store`'s certificate authorities are ever trusted;
        // a bundle can carry no roots of its own to be trusted instead.
        let leaf_der = &bundle.verification_material.certificate.raw_bytes;
        let validated_leaf = x509::validate_chain(leaf_der, &self.trust_store, authenticated_time)?;

        // 6. DSSE envelope signature, under the validated leaf's key.
        let leaf_key = dsse::EcdsaVerifyingKey::from_spki_der(&validated_leaf.leaf_spki_der)?;
        dsse::verify_envelope(&bundle.dsse_envelope, &leaf_key)?;

        // 7. Certificate Transparency: at least one embedded SCT must
        // verify against a trusted CT log.
        sct::verify_embedded_scts(&validated_leaf, &self.trust_store)?;

        // 8. Certificate-derived identity claims (authenticated by the
        // X.509 chain just validated, not by statement content).
        let claims = fulcio::extract_claims(&validated_leaf)?;

        // 9. Identity policy: the only configurable part of this chain.
        let matched_identity = policy_match::match_policy(&claims, &self.github_policy)?;

        // 10. Assemble the provenance-separated report.
        Ok(VerificationReport {
            subject: VerifiedSubject {
                digest: *subject,
                name: matched_name,
            },
            signer: VerifiedCertificateIdentity {
                issuer: matched_identity.issuer,
                source_repository: matched_identity.source_repository,
                source_ref: matched_identity.source_ref,
                signer_repository: matched_identity.signer_repository,
                signer_workflow_path: matched_identity.signer_workflow_path,
            },
            transparency: VerifiedTransparency {
                log_index: verified_timestamp.log_index,
                integrated_time: verified_timestamp.integrated_time,
            },
            statement: VerifiedSignedStatement {
                predicate_type: statement.predicate_type,
                predicate: statement.predicate,
            },
            trust: TrustSnapshotInfo {
                fingerprint: self.trust_store.fingerprint.clone(),
                source: self.trust_store.source.clone(),
            },
        })
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
/// `#[non_exhaustive]` and privately-unconstructable outside this crate:
/// no caller can fabricate a report that looks verified.
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
/// statement.
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
/// by the (attacker-controlled) statement content.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedCertificateIdentity {
    /// The OIDC issuer URL (always GitHub Actions' issuer — pinned,
    /// non-configurable).
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
/// content.
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
/// signer said this," not verified against reality.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedSignedStatement {
    /// The predicate type URI.
    pub predicate_type: String,
    /// The opaque predicate body.
    pub predicate: serde_json::Value,
}

/// Identifies which trust-root snapshot produced a verification result,
/// so operators can tell which root made the decision (DESIGN.md
/// "Trust-root operations").
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TrustSnapshotInfo {
    /// Lowercase-hex SHA-256 of the exact trust-root JSON bytes used
    /// ([`crate::trust::TrustStore::fingerprint`]).
    pub fingerprint: String,
    /// Where the trust-root snapshot was loaded from:
    /// `"embedded-public-good"` or `"external"`
    /// ([`crate::trust::TrustStore::source`]).
    pub source: String,
}
