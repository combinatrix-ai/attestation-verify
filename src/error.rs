//! Mechanical error taxonomy.
//!
//! Every error states what check failed, never what an attacker may have
//! intended. Each top-level variant wraps its own `#[non_exhaustive]` enum so
//! new failure modes can be added without a semver break. See DESIGN.md,
//! "Core decisions" item 8.

use thiserror::Error;

/// Top-level error type for this crate.
///
/// Each variant corresponds to one stage of parsing or (eventually)
/// verification. The taxonomy is intentionally mechanical: it says what
/// check failed, not what an attacker may have intended (no `Tampered`
/// variant, no inferred staleness).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A parser rejected malformed or non-conforming input.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// The input uses a format, media type, or version this crate does not
    /// (yet) support.
    #[error("unsupported: {0}")]
    Unsupported(#[from] UnsupportedError),

    /// A trust-root or trust-material check failed.
    #[error("trust error: {0}")]
    Trust(#[from] TrustError),

    /// An X.509 certificate failed validation.
    #[error("certificate error: {0}")]
    Certificate(#[from] CertificateError),

    /// A transparency-log (Rekor) check failed.
    #[error("transparency error: {0}")]
    Transparency(#[from] TransparencyError),

    /// An RFC 3161 timestamp check failed.
    #[error("timestamp error: {0}")]
    Timestamp(#[from] TimestampError),

    /// The subject digest did not bind to the signed statement.
    #[error("content binding error: {0}")]
    ContentBinding(#[from] ContentBindingError),

    /// The caller's identity policy was not satisfied.
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),

    /// An input exceeded a hard-coded resource limit.
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(#[from] ResourceLimitError),
}

/// Failures while parsing a bundle, statement, or trusted-root document.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was not well-formed JSON, or did not match the expected
    /// shape once parsed.
    #[error("invalid JSON: {0}")]
    Json(String),

    /// A field that must be strict base64 (standard alphabet, padded) was
    /// not valid base64.
    #[error("invalid base64 in field `{field}`: {reason}")]
    Base64 {
        /// Name of the field that failed to decode.
        field: &'static str,
        /// Human-readable reason the decode failed.
        reason: String,
    },

    /// A field that must be strict hex was not valid hex, or had the wrong
    /// length.
    #[error("invalid hex in field `{field}`: {reason}")]
    Hex {
        /// Name of the field that failed to decode.
        field: &'static str,
        /// Human-readable reason the decode failed.
        reason: String,
    },

    /// A digest string was the wrong length, wrong case set, or contained
    /// non-hex characters.
    #[error("malformed digest: {0}")]
    MalformedDigest(String),

    /// An integer field that protojson encodes as a JSON string (`int64`,
    /// `uint64`) was not a valid decimal integer.
    #[error("field `{field}` is not a valid integer: {value}")]
    NotAnInteger {
        /// Name of the field that failed to parse.
        field: &'static str,
        /// The raw string value that failed to parse as an integer.
        value: String,
    },

    /// The DSSE envelope did not carry exactly one signature.
    #[error("dsse envelope has {count} signatures, expected exactly 1")]
    DsseSignatureCount {
        /// Number of signatures actually present.
        count: usize,
    },

    /// A required field was absent.
    #[error("missing required field `{0}`")]
    MissingField(&'static str),

    /// A container format (JSONL, API response) had no usable entries.
    #[error("empty container: {0}")]
    EmptyContainer(&'static str),

    /// An in-toto statement subject had an empty or otherwise unusable
    /// digest map.
    #[error("statement subject has no usable digest: {0}")]
    MalformedSubject(String),

    /// A field that must be an RFC 3339 timestamp did not parse as one.
    #[error("invalid RFC 3339 timestamp in field `{field}`: {reason}")]
    Rfc3339 {
        /// Name of the field that failed to parse.
        field: &'static str,
        /// Human-readable reason the timestamp was rejected.
        reason: String,
    },

    /// A Rekor checkpoint (signed note) envelope did not match the
    /// expected line structure: `<origin>\n<treeSize>\n<rootHash>\n`,
    /// optional extension lines, a blank line, then one or more `— <name>
    /// <base64>` signature lines.
    #[error("malformed checkpoint envelope: {0}")]
    Checkpoint(String),
}

/// The input is well-formed but uses a format, version, or shape this crate
/// does not implement.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UnsupportedError {
    /// `mediaType` did not match any media type this crate understands.
    #[error("unsupported media type: {found}")]
    MediaType {
        /// The media-type string found in the input.
        found: String,
    },

    /// The verification chain is not implemented yet (this crate is a
    /// parsing-only prototype). Every `Verifier::verify_*` call returns this
    /// error after basic input parsing succeeds.
    #[error("verification chain not implemented")]
    ChainNotImplemented,

    /// A container (e.g. the GitHub attestations API response) had entries
    /// but none carried an inline bundle.
    #[error("no inline bundles in response (bundles must be fetched out of band)")]
    BundlesNotInline,

    /// A Rekor transparency-log entry used an unsupported `kind`/`version`
    /// pair.
    #[error("unsupported tlog entry kind/version: {kind}/{version}")]
    TlogEntryKindVersion {
        /// The `kind` field found in the entry.
        kind: String,
        /// The `version` field found in the entry.
        version: String,
    },

    /// An in-toto statement's `_type` field did not match a statement
    /// version this crate understands.
    #[error("unsupported in-toto statement type: {found}")]
    StatementType {
        /// The `_type` string found in the input.
        found: String,
    },
}

/// Trust-root or trust-material failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrustError {
    /// No key in the trust store matched the identifier the bundle
    /// referenced.
    #[error("unknown trust-store key id")]
    UnknownKeyId,

    /// A key existed but was not valid at the required authenticated time.
    #[error("no trusted key valid at the required time")]
    NoTrustedKeyValidAt,
}

/// X.509 certificate validation failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertificateError {
    /// The certificate could not be parsed as DER.
    #[error("certificate is not valid DER: {0}")]
    InvalidDer(String),

    /// A `SubjectPublicKeyInfo` (from a leaf certificate or a trust-store
    /// key) used a key algorithm/curve this crate does not implement.
    /// Only P-256 and P-384 ECDSA are supported.
    #[error("unsupported public key algorithm")]
    UnsupportedKeyAlgorithm,
}

/// Transparency-log (Rekor) verification failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransparencyError {
    /// The Merkle inclusion proof did not verify against the checkpoint,
    /// or the proof's `logIndex`/`treeSize`/hash count were inconsistent
    /// (including over- or under-length hash lists).
    #[error("inclusion proof did not verify")]
    InclusionProofInvalid,

    /// The bundle carried no transparency-log entries to verify.
    #[error("bundle has no transparency-log entries")]
    NoTlogEntries,

    /// No key in the trust store's transparency logs had a SHA-256 digest
    /// of its `SubjectPublicKeyInfo` matching the entry's `logId.keyId`.
    #[error("no trusted log key matches this entry's logId")]
    UnknownLogKey,

    /// The tlog entry carried no inclusion promise (SET). A SET is
    /// required: an inclusion proof alone does not authenticate
    /// `integratedTime` (DESIGN.md "Time-evidence model").
    #[error("tlog entry has no inclusion promise (SET)")]
    SetMissing,

    /// The inclusion promise (SET) did not verify against the selected
    /// trusted log key.
    #[error("inclusion promise (SET) did not verify")]
    SetInvalid,

    /// The tlog entry carried no Merkle inclusion proof.
    #[error("tlog entry has no inclusion proof")]
    InclusionProofMissing,

    /// The checkpoint's tree size did not match the inclusion proof's
    /// tree size.
    #[error("checkpoint treeSize does not match the inclusion proof's treeSize")]
    CheckpointTreeSizeMismatch,

    /// The checkpoint's root hash did not match the inclusion proof's
    /// root hash.
    #[error("checkpoint rootHash does not match the inclusion proof's rootHash")]
    CheckpointRootHashMismatch,

    /// No signature line in the checkpoint verified against the selected
    /// trusted log key.
    #[error("no checkpoint signature verified with the trusted log key")]
    CheckpointSignatureInvalid,
}

/// RFC 3161 timestamp verification failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TimestampError {
    /// The RFC 3161 timestamp token did not parse or verify.
    #[error("rfc3161 timestamp invalid")]
    Invalid,

    /// The authenticated `integratedTime` fell outside the selected
    /// trusted log key's `validFor` window.
    #[error("integratedTime is outside the trusted log key's validity window")]
    IntegratedTimeOutsideLogKeyValidity,

    /// The authenticated `integratedTime` fell outside the leaf
    /// certificate's `[notBefore, notAfter]` validity window.
    #[error("integratedTime is outside the leaf certificate's validity window")]
    IntegratedTimeOutsideCertificateValidity,
}

/// The signed content did not bind to the requested subject.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContentBindingError {
    /// The requested subject digest was not present among the statement's
    /// subjects.
    #[error("subject digest not found in statement")]
    SubjectNotFound,

    /// A DSSE envelope's signature did not verify against the leaf
    /// certificate's public key over the PAE-encoded payload.
    #[error("dsse envelope signature did not verify")]
    DsseSignatureInvalid,

    /// The Rekor entry's own `kind`/`apiVersion` (inside the
    /// canonicalized body) did not match the bundle's `kindVersion`
    /// metadata for the same tlog entry.
    #[error("tlog entry kindVersion does not match the canonicalized body's kind/apiVersion")]
    TlogEntryKindVersionMismatch,

    /// The Rekor entry's recorded signature did not match the bundle's
    /// DSSE signature.
    #[error("tlog entry signature does not match the bundle's DSSE signature")]
    TlogEntrySignatureMismatch,

    /// The Rekor entry's recorded verifier certificate did not match the
    /// bundle's leaf certificate.
    #[error("tlog entry verifier certificate does not match the bundle's leaf certificate")]
    TlogEntryCertificateMismatch,

    /// The Rekor entry's recorded payload hash did not match the SHA-256
    /// of the bundle's decoded DSSE payload.
    #[error("tlog entry payloadHash does not match the bundle's DSSE payload")]
    TlogEntryPayloadHashMismatch,

    /// The Rekor entry's recorded envelope hash did not match this
    /// crate's recomputation of it from the bundle's DSSE envelope.
    #[error("tlog entry envelopeHash does not match the bundle's DSSE envelope")]
    TlogEntryEnvelopeHashMismatch,
}

/// The caller-supplied identity policy was not satisfied.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// A policy builder was given an empty or malformed value.
    #[error("invalid policy configuration: {0}")]
    InvalidConfiguration(String),
}

/// A hard resource limit (size, count, or depth) was exceeded. These limits
/// exist to keep parsing cost bounded and independent of attacker-controlled
/// input shape.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ResourceLimitError {
    /// The raw input exceeded the maximum accepted byte length.
    #[error("input of {actual} bytes exceeds the {limit}-byte limit")]
    InputTooLarge {
        /// The actual input length in bytes.
        actual: usize,
        /// The maximum accepted length in bytes.
        limit: usize,
    },

    /// A bundle carried more transparency-log entries than the limit.
    #[error("{actual} tlog entries exceeds the limit of {limit}")]
    TooManyTlogEntries {
        /// The actual number of entries found.
        actual: usize,
        /// The maximum accepted number of entries.
        limit: usize,
    },

    /// An in-toto statement carried more subjects than the limit.
    #[error("{actual} statement subjects exceeds the limit of {limit}")]
    TooManySubjects {
        /// The actual number of subjects found.
        actual: usize,
        /// The maximum accepted number of subjects.
        limit: usize,
    },

    /// A `BundleSet` container carried more bundles than the limit.
    #[error("{actual} bundles exceeds the limit of {limit} per BundleSet")]
    TooManyBundles {
        /// The actual number of bundles found.
        actual: usize,
        /// The maximum accepted number of bundles.
        limit: usize,
    },

    /// A certificate chain carried more certificates than the limit.
    #[error("{actual} certificates exceeds the limit of {limit} per chain")]
    TooManyCertificates {
        /// The actual number of certificates found.
        actual: usize,
        /// The maximum accepted number of certificates.
        limit: usize,
    },
}
