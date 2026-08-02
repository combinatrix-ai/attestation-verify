//! Small example CLI built entirely on `attestation-verify`'s public API
//! (no other dependency, hand-rolled argument parsing): verify one
//! artifact or digest against a bundle and a GitHub identity policy
//! assembled from flags.
//!
//! ```text
//! cargo run --example verify -- \
//!     --artifact gh_2.96.0_linux_amd64.tar.gz \
//!     --bundle tarball-user-slsa-provenance.json \
//!     --repo cli/cli --owner-id 59704711 --repo-id 212613049 \
//!     --source-ref refs/heads/trunk \
//!     --signer-workflow .github/workflows/deployment.yml \
//!     --checkpoint-origin 'rekor.sigstore.dev - 1193050959916656506'
//! ```
//!
//! `--repo` names both the source repository and the signer-workflow's
//! repository (the common case: the workflow lives in the repo it
//! releases). `--source-ref` defaults to `Glob("*")` (any ref) when
//! omitted; prefer an exact ref for real release verification. See
//! `scripts/differential.sh` for this binary exercised against
//! `gh attestation verify`.

use std::process::ExitCode;

use attestation_verify::{
    Bundle, BundleSet, CheckpointOriginPolicy, GithubPolicy, RefPolicy, RepositoryIdentity,
    SignerPolicy, SourcePolicy, Subject, TrustStore, VerificationReport, Verifier, WorkflowPath,
    WorkflowRevisionPolicy,
};

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            print_error_chain(err.as_ref());
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    let (mut artifact, mut digest, mut bundle_path, mut repo) = (None, None, None, None);
    let (mut owner_id, mut repo_id, mut source_ref, mut signer_workflow, mut checkpoint_origin) =
        (None, None, None, None, None);

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--artifact" => artifact = Some(next_value(&mut args, &flag)?),
            "--digest" => digest = Some(next_value(&mut args, &flag)?),
            "--bundle" => bundle_path = Some(next_value(&mut args, &flag)?),
            "--repo" => repo = Some(next_value(&mut args, &flag)?),
            "--owner-id" => owner_id = Some(next_value(&mut args, &flag)?.parse::<u64>()?),
            "--repo-id" => repo_id = Some(next_value(&mut args, &flag)?.parse::<u64>()?),
            "--source-ref" => source_ref = Some(next_value(&mut args, &flag)?),
            "--signer-workflow" => signer_workflow = Some(next_value(&mut args, &flag)?),
            "--checkpoint-origin" => checkpoint_origin = Some(next_value(&mut args, &flag)?),
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let subject = match (artifact.as_deref(), digest.as_deref()) {
        (Some(path), None) => Subject::sha256_of(&std::fs::read(path)?),
        (None, Some(hex)) => Subject::from_digest_hex(hex)?,
        (Some(_), Some(_)) => {
            return Err("pass exactly one of --artifact or --digest, not both".into());
        }
        (None, None) => return Err("pass one of --artifact <path> or --digest <hex>".into()),
    };
    let bundle_path = bundle_path.ok_or("missing required --bundle <path>")?;
    let repo = repo.ok_or("missing required --repo <owner/name>")?;
    let signer_workflow = signer_workflow.ok_or("missing required --signer-workflow <path>")?;
    let checkpoint_origin =
        checkpoint_origin.ok_or("missing required --checkpoint-origin <origin>")?;

    let bundle = load_bundle(&std::fs::read(bundle_path)?)?;

    // Numeric ids are enforceable for the source repository only, so the
    // signer half keeps the unpinned identity.
    let signer_repository = RepositoryIdentity::parse(&repo)?;
    let mut repository = RepositoryIdentity::parse(&repo)?;
    if let Some(id) = owner_id {
        repository = repository.with_owner_id(id);
    }
    if let Some(id) = repo_id {
        repository = repository.with_repository_id(id);
    }
    let git_ref = source_ref.map_or_else(|| RefPolicy::Glob("*".to_owned()), RefPolicy::Exact);
    let policy = GithubPolicy::builder()
        .source(SourcePolicy {
            repository,
            git_ref,
            commit: None,
        })
        .signer(SignerPolicy {
            repository: signer_repository,
            path: WorkflowPath::new(signer_workflow)?,
            revision: WorkflowRevisionPolicy::Any,
        })
        .build()?;
    let trust_store = TrustStore::embedded_public_good()?;
    let log = trust_store
        .tlogs
        .first()
        .ok_or("embedded trust root has no Rekor log")?;
    let checkpoint_origin_policy = CheckpointOriginPolicy::builder()
        .allow_origin(log, checkpoint_origin)?
        .build()?;
    let verifier = Verifier::builder()
        .trust_store(trust_store)
        .github_policy(policy)
        .checkpoint_origin_policy(checkpoint_origin_policy)
        .build()?;

    let report = verifier.verify_digest(&subject, &bundle)?;
    print_report(&report);
    Ok(())
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

/// Tries a bare bundle JSON document first, then falls back to
/// `gh attestation download`'s JSONL container, requiring it to carry
/// exactly one bundle (this example does not support disambiguating
/// several).
fn load_bundle(bytes: &[u8]) -> Result<Bundle, Box<dyn std::error::Error>> {
    if let Ok(bundle) = Bundle::from_json(bytes) {
        return Ok(bundle);
    }
    let set = BundleSet::from_json_lines(bytes)?;
    let [bundle] = <[Bundle; 1]>::try_from(set.bundles).map_err(|bundles| {
        format!(
            "expected exactly 1 bundle in JSONL --bundle input, got {}",
            bundles.len()
        )
    })?;
    Ok(bundle)
}

fn print_report(report: &VerificationReport) {
    let name_suffix = report
        .subject
        .name
        .as_deref()
        .map_or_else(String::new, |name| format!(" ({name})"));
    println!("verified: subject {}{name_suffix}", report.subject.digest);
    println!(
        "  source:  {} @ {}",
        report.signer.source_repository, report.signer.source_ref
    );
    println!(
        "  signer:  {} {}",
        report.signer.signer_repository, report.signer.signer_workflow_path
    );
    println!(
        "  transparency: integratedTime={} logIndex={}",
        report.transparency.integrated_time, report.transparency.log_index
    );
    println!(
        "  trust root:   {} {}",
        report.trust.source, report.trust.fingerprint
    );
}

fn print_error_chain(err: &dyn std::error::Error) {
    eprintln!("error: {err}");
    let mut source = err.source();
    while let Some(cause) = source {
        eprintln!("caused by: {cause}");
        source = cause.source();
    }
}
