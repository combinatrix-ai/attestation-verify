# attestation-verify

Verify GitHub Artifact Attestations (Sigstore bundles) offline in Rust —
minimal dependencies, sans-io, fail-closed.

## Status: functional, narrow scope

This crate verifies, fully offline, against the embedded Sigstore
public-good trust root (or a caller-supplied one):

- `actions/attest-build-provenance`-generated bundles
  (`application/vnd.dev.sigstore.bundle.v0.3+json`) carrying a
  `https://slsa.dev/provenance/v1` predicate.
- The full chain: DSSE envelope signature, Rekor v1 transparency-log
  inclusion (SET + Merkle inclusion proof + checkpoint), X.509/Fulcio
  certificate-chain validation, embedded SCT verification, and GitHub
  identity-policy matching (source repository + ref, signer workflow
  repository + path + revision).

There are no verification knobs — every step above always runs. The only
configuration is *which identity to require* (`GithubPolicy`).

```rust
use attestation_verify::{Bundle, GithubPolicy, RefPolicy, RepositoryIdentity};
use attestation_verify::{SignerPolicy, SourcePolicy, TrustStore, Verifier, WorkflowPath};
use attestation_verify::WorkflowRevisionPolicy;

let policy = GithubPolicy::builder()
    .source(SourcePolicy {
        repository: RepositoryIdentity::parse("cli/cli")?
            .with_owner_id(59_704_711)
            .with_repository_id(212_613_049),
        git_ref: RefPolicy::Exact("refs/heads/trunk".to_owned()),
        commit: None,
    })
    .signer(SignerPolicy {
        repository: RepositoryIdentity::parse("cli/cli")?,
        path: WorkflowPath::new(".github/workflows/deployment.yml")?,
        revision: WorkflowRevisionPolicy::Any,
    })
    .build()?;

let verifier = Verifier::builder()
    .trust_store(TrustStore::embedded_public_good()?)
    .github_policy(policy)
    .build()?;

let bundle = Bundle::from_json(&bundle_bytes)?;
let report = verifier.verify_bytes(&artifact_bytes, &bundle)?;
println!("{} @ {}", report.signer.source_repository, report.signer.source_ref);
```

See `examples/verify.rs` for a small, dependency-free CLI wrapping the
same API — run it with:

```sh
cargo run --example verify -- \
    --artifact gh_2.96.0_linux_amd64.tar.gz \
    --bundle tests/fixtures/github-cli/tarball-user-slsa-provenance.json \
    --repo cli/cli --owner-id 59704711 --repo-id 212613049 \
    --source-ref refs/heads/trunk \
    --signer-workflow .github/workflows/deployment.yml
```

## v0.2 boundaries (out of scope today, typed `Unsupported` errors, never
silently accepted)

- GitHub's own TSA-timestamped release-attestation flavor (`initiator:
  github`: no tlog entries, RFC 3161 timestamp, GitHub's own Fulcio/TSA
  trust root, predicate `https://in-toto.io/attestation/release/v0.2`).
- Rekor v2 (Ed25519, tiles/sharded logs) — this crate detects and rejects
  v2 entries rather than misinterpreting them; only Rekor v1 is verified.
- Private-repository attestations (different trust root; kept possible
  via root injection, not implemented).
- Any predicate type other than `https://slsa.dev/provenance/v1`.

See [DESIGN.md](DESIGN.md) for the full design, the normative
time-evidence model, and the roadmap.

## Disclaimer

This crate has not been independently audited. Review it yourself before
relying on it for anything security-sensitive.

License: MIT OR Apache-2.0
