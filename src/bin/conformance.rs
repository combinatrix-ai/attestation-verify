//! Verification-only client for the official `sigstore-conformance` suite.
//!
//! The conformance protocol is intentionally broader than this crate: it
//! includes signing and verification with caller-managed keys. This binary
//! implements the bundle verification flow for GitHub Actions identities and
//! reports the deliberately unsupported protocol paths explicitly. The
//! upstream suite must be invoked with `--skip-signing` for this client.

use std::error::Error as StdError;
use std::process::ExitCode;

use attestation_verify::{
    BUNDLE_MEDIA_TYPE, Bundle, GithubPolicy, RefPolicy, RepositoryIdentity, SignerPolicy,
    SourcePolicy, Subject, TrustStore, Verifier, WorkflowPath, WorkflowRevisionPolicy,
};

const EXPECTED_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_IDENTITY_PREFIX: &str = "https://github.com/";
const WORKFLOW_PATH_PREFIX: &str = ".github/workflows/";

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            print_error_chain(error.as_ref());
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn StdError>> {
    let subcommand = args.next().ok_or("missing conformance subcommand")?;
    match subcommand.as_str() {
        "sign-bundle" => Err(
            "unsupported: this client is verification-only; run sigstore-conformance with --skip-signing"
                .into(),
        ),
        "verify-bundle" => run_verify(args),
        other => Err(format!(
            "unsupported conformance subcommand {other:?}; expected sign-bundle or verify-bundle"
        )
        .into()),
    }
}

fn run_verify(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn StdError>> {
    let mut staging = false;
    let mut bundle_path = None;
    let mut certificate_identity = None;
    let mut certificate_issuer = None;
    let mut key_path = None;
    let mut trusted_root_path = None;
    let mut artifact_or_digest = None;

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--staging" => staging = true,
            "--bundle" => bundle_path = Some(next_value(&mut args, &argument)?),
            "--certificate-identity" => {
                certificate_identity = Some(next_value(&mut args, &argument)?);
            }
            "--certificate-oidc-issuer" => {
                certificate_issuer = Some(next_value(&mut args, &argument)?);
            }
            "--key" => key_path = Some(next_value(&mut args, &argument)?),
            "--trusted-root" => {
                trusted_root_path = Some(next_value(&mut args, &argument)?);
            }
            value if value.starts_with('-') => {
                return Err(format!("unsupported or unknown conformance option {value:?}").into());
            }
            value if artifact_or_digest.is_none() => artifact_or_digest = Some(value.to_owned()),
            value => return Err(format!("unexpected extra positional argument {value:?}").into()),
        }
    }

    if staging {
        return Err(
            "unsupported: --staging selects online Sigstore staging infrastructure, but this verifier is offline"
                .into(),
        );
    }
    if key_path.is_some() {
        return Err(
            "unsupported: --key requests managed-key/cosign verification, which this crate does not implement"
                .into(),
        );
    }
    if certificate_identity.is_none() || certificate_issuer.is_none() {
        return Err(
            "verify-bundle requires --certificate-identity and --certificate-oidc-issuer (or an unsupported --key path)"
                .into(),
        );
    }

    let bundle_path = bundle_path.ok_or("verify-bundle requires --bundle FILE")?;
    let artifact_or_digest = artifact_or_digest.ok_or(
        "verify-bundle requires an artifact path or a sha256:<64-hex-character-digest> operand",
    )?;
    let certificate_identity = certificate_identity.ok_or("missing certificate identity")?;
    let certificate_issuer = certificate_issuer.ok_or("missing certificate OIDC issuer")?;

    if certificate_issuer != EXPECTED_ISSUER {
        return Err(format!(
            "unsupported certificate OIDC issuer {certificate_issuer:?}; this crate only verifies GitHub Actions issuer {EXPECTED_ISSUER:?}"
        )
        .into());
    }

    let identity = parse_github_identity(&certificate_identity)?;
    let repository = RepositoryIdentity::parse(&identity.repository)?;
    let policy = GithubPolicy::builder()
        .source(SourcePolicy {
            repository: repository.clone(),
            // The protocol supplies the certificate SAN identity, not the
            // source ref claim. Keep that part of the crate policy broad
            // rather than inventing a source-ref assertion from the SAN.
            git_ref: RefPolicy::Glob("*".to_owned()),
            commit: None,
        })
        .signer(SignerPolicy {
            repository,
            path: WorkflowPath::new(identity.workflow_path)?,
            revision: WorkflowRevisionPolicy::Ref(identity.workflow_ref),
        })
        .build()?;

    let trust_store = match trusted_root_path {
        Some(path) => TrustStore::from_json(&std::fs::read(path)?)?,
        None => TrustStore::embedded_public_good()?,
    };
    let bundle_bytes = std::fs::read(bundle_path)?;
    reject_unsupported_bundle_shape(&bundle_bytes)?;
    let bundle = Bundle::from_json(&bundle_bytes)?;
    let verifier = Verifier::builder()
        .trust_store(trust_store)
        .github_policy(policy)
        .build()?;

    if let Some(digest) = artifact_or_digest.strip_prefix("sha256:") {
        if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let subject = Subject::from_digest_hex(digest)?;
            verifier.verify_digest(&subject, &bundle)?;
        } else {
            let bytes = std::fs::read(artifact_or_digest)?;
            verifier.verify_bytes(&bytes, &bundle)?;
        }
    } else {
        let bytes = std::fs::read(artifact_or_digest)?;
        verifier.verify_bytes(&bytes, &bundle)?;
    }

    println!("verified");
    Ok(())
}

fn reject_unsupported_bundle_shape(bytes: &[u8]) -> Result<(), Box<dyn StdError>> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Ok(());
    };

    if value
        .pointer("/verificationMaterial/publicKey")
        .is_some_and(|key| !key.is_null())
    {
        return Err(
            "unsupported: this bundle uses managed-key verification, which this crate does not implement"
                .into(),
        );
    }

    let tlog_entry = value.pointer("/verificationMaterial/tlogEntries/0");
    let kind = tlog_entry
        .and_then(|entry| entry.pointer("/kindVersion/kind"))
        .and_then(serde_json::Value::as_str);
    let version = tlog_entry
        .and_then(|entry| entry.pointer("/kindVersion/version"))
        .and_then(serde_json::Value::as_str);
    let has_integrated_time = tlog_entry
        .and_then(|entry| entry.get("integratedTime"))
        .is_some();

    if version == Some("0.0.2") && !has_integrated_time {
        return Err(
            "unsupported: this bundle uses Rekor v2/TSA verification, but this crate implements Rekor v1 only"
                .into(),
        );
    }
    if kind == Some("hashedrekord") {
        return Err(
            "unsupported: this bundle uses a hashedrekord entry, but this crate models DSSE entries only"
                .into(),
        );
    }

    if let Some(media_type) = value.get("mediaType").and_then(serde_json::Value::as_str)
        && media_type != BUNDLE_MEDIA_TYPE
    {
        return Err(format!(
            "unsupported: bundle media type {media_type:?}; this crate accepts {BUNDLE_MEDIA_TYPE:?} only"
        )
        .into());
    }

    Ok(())
}

struct GithubIdentity {
    repository: String,
    workflow_path: String,
    workflow_ref: String,
}

fn parse_github_identity(identity: &str) -> Result<GithubIdentity, Box<dyn StdError>> {
    let rest = identity
        .strip_prefix(GITHUB_IDENTITY_PREFIX)
        .ok_or_else(|| {
            format!("unsupported certificate identity {identity:?}: expected a GitHub workflow URI")
        })?;
    let (repository_and_path, workflow_ref) = rest
        .split_once('@')
        .ok_or("certificate identity is missing the workflow @revision separator")?;
    if workflow_ref.is_empty() {
        return Err("certificate identity has an empty workflow revision".into());
    }

    let mut components = repository_and_path.splitn(3, '/');
    let owner = components
        .next()
        .filter(|value| !value.is_empty())
        .ok_or("certificate identity is missing the GitHub repository owner")?;
    let name = components
        .next()
        .filter(|value| !value.is_empty())
        .ok_or("certificate identity is missing the GitHub repository name")?;
    let workflow_path = components
        .next()
        .filter(|value| value.starts_with(WORKFLOW_PATH_PREFIX))
        .filter(|value| value.len() > WORKFLOW_PATH_PREFIX.len())
        .ok_or("certificate identity is missing a .github/workflows/ path")?;

    Ok(GithubIdentity {
        repository: format!("{owner}/{name}"),
        workflow_path: workflow_path.to_owned(),
        workflow_ref: workflow_ref.to_owned(),
    })
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn StdError>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn print_error_chain(error: &dyn StdError) {
    eprintln!("error: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("caused by: {cause}");
        source = cause.source();
    }
}
