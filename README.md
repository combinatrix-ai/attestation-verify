# attestation-verify

[![CI](https://github.com/combinatrix-ai/attestation-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/combinatrix-ai/attestation-verify/actions/workflows/ci.yml)

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

## Development

The minimum supported Rust version is 1.88. Run the same checks as CI from
the repository root:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo test --locked
```

The dependency budget counts unique `(name, version)` pairs in the default
feature set's normal+build dependencies, excluding dev-dependencies. The
target is below 60 and the hard ceiling is 80. Measure the current count with:

```sh
scripts/dep-budget.sh
```

The script measures the canonical `x86_64-unknown-linux-gnu` target used by
CI; set `DEP_BUDGET_TARGET` to inspect another supported target.

### Parser fuzzing

The fixture-seeded cargo-fuzz crate is a separate workspace under `fuzz/`, so
its nightly-only `libfuzzer-sys` dependency is not part of the library's
dependency budget or MSRV build. Install the tools and regenerate the checked-
in seeds with:

```sh
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
python3 fuzz/scripts/generate_corpora.py
```

Seeds live in `fuzz/corpus/<target>/` and are derived from committed files in
`tests/fixtures/`. Run one target locally, for example:

```sh
cargo +nightly fuzz run bundle -- -max_total_time=180
```

The targets are `bundle`, `jsonl`, `github_api`, `statement`, `trusted_root`,
`rekor_body`, `checkpoint`, `sct`, and `rfc3339`. Crash and sanitizer outputs
are written under `fuzz/artifacts/`; preserve and minimize any input there
before reporting a failure. The pull-request CI smoke job runs every target
for the single workflow constant `FUZZ_SMOKE_SECONDS` (currently 60 seconds).
That catches reproducible crashes and panics within those bounded runs; it is
not a coverage claim, an exhaustive parser proof, or a replacement for the
unit, fixture, and differential tests.

The weekly/manual differential gate runs `scripts/differential.sh` against a
real `cli/cli` release and its tampered copy. It requires an authenticated
`gh` CLI and network access, so it is not part of the local unit-test suite.

## Disclaimer

This crate has not been independently audited. Review it yourself before
relying on it for anything security-sensitive.

License: MIT OR Apache-2.0
