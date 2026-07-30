//! Verify GitHub Artifact Attestations (Sigstore bundles) offline, at
//! runtime, in Rust, with a minimal and auditable dependency footprint.
//!
//! See `DESIGN.md` in the repository root for the full design.
//!
//! # Status: not yet usable for verification
//!
//! This crate currently implements crate scaffolding, the public API
//! shape, the error taxonomy, and **hardened parsers** for the Sigstore
//! bundle, in-toto statement, and trusted-root formats — with fixture
//! tests against real-world data. **The cryptographic verification chain
//! is not implemented.** Every [`Verifier::verify_digest`] /
//! [`Verifier::verify_bytes`] call fails closed with
//! [`UnsupportedError::ChainNotImplemented`]; there is no code path in
//! this crate that reports a successful verification. Do not depend on
//! this crate for actual attestation verification yet.
//!
//! # Layout
//!
//! - [`Subject`]: the artifact digest being verified.
//! - [`Bundle`] / [`BundleSet`]: parsed Sigstore bundles, and the two
//!   container shapes GitHub serves them in.
//! - [`Statement`]: the in-toto statement inside a bundle's DSSE payload.
//! - [`TrustStore`]: a parsed trusted-root document.
//! - [`GithubPolicy`]: the identity policy a [`Verifier`] enforces (no
//!   matching logic yet).
//! - [`Verifier`]: the (fail-closed, not-yet-implemented) verification
//!   entry point.

pub mod bundle;
pub mod error;
pub mod policy;
pub mod statement;
pub mod trust;
pub mod verifier;

mod dsse;
mod limits;
mod parse_util;
mod rekor;
mod strict_json;
mod subject;
mod time;

pub use bundle::{
    AttestationEntry, BUNDLE_MEDIA_TYPE, Bundle, BundleSet, Certificate, Checkpoint, DsseEnvelope,
    DsseSignature, InclusionPromise, InclusionProof, Rfc3161Timestamp, TimestampVerificationData,
    TlogEntry, VerificationMaterial,
};
pub use error::{
    CertificateError, ContentBindingError, Error, ParseError, PolicyError, ResourceLimitError,
    TimestampError, TransparencyError, TrustError, UnsupportedError,
};
pub use policy::{
    CommitSha, GithubPolicy, GithubPolicyBuilder, RefPolicy, RepositoryIdentity, SignerPolicy,
    SourcePolicy, WorkflowPath, WorkflowRevisionPolicy,
};
pub use statement::{STATEMENT_TYPE, Statement, StatementSubject};
pub use subject::Subject;
pub use trust::{
    CaSubject, CertificateAuthority, PublicKey, TRUSTED_ROOT_MEDIA_TYPE, TransparencyLog,
    TrustStore, ValidityPeriod,
};
pub use verifier::{
    TrustSnapshotInfo, VerificationReport, VerifiedCertificateIdentity, VerifiedSignedStatement,
    VerifiedSubject, VerifiedTransparency, Verifier, VerifierBuilder,
};
