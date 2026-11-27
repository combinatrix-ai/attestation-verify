# attestation-verify

[![CI](https://github.com/combinatrix-ai/attestation-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/combinatrix-ai/attestation-verify/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/attestation-verify.svg)](https://crates.io/crates/attestation-verify)
[![docs.rs](https://docs.rs/attestation-verify/badge.svg)](https://docs.rs/attestation-verify)

**Check that a downloaded file was built by the GitHub Actions workflow you
trust, offline, from inside your Rust program.**

GitHub can attach a signed build provenance ([Artifact
Attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations))
to every release asset. `attestation-verify` checks one of those bundles
against the file you downloaded and a policy you write down in code: *this
repository, this branch, this workflow file*. If anything does not match, you
get an error, not a warning.

- **Offline and sans-io.** No network calls, no `gh` binary, no Go toolchain.
  The Sigstore public-good trust root is embedded.
- **Fail-closed, no knobs.** Every check always runs. Unsupported inputs return
  a typed `Unsupported` error instead of being skipped.
- **Small.** 54 unique dependencies in the default build.

Typical uses: self-updaters that should only replace themselves with an
official build, installers and package managers that fetch release binaries,
and air-gapped machines that receive artifacts by hand.

## Try it: verify the real GitHub CLI release

The repository ships the real provenance bundle that GitHub published for
`gh` 2.96.0. Download the release tarball from GitHub and verify it:

```sh
git clone https://github.com/combinatrix-ai/attestation-verify
cd attestation-verify
curl -fsSLO https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_linux_amd64.tar.gz

cargo run -q --example verify -- \
    --artifact gh_2.96.0_linux_amd64.tar.gz \
    --bundle tests/fixtures/github-cli/tarball-user-slsa-provenance.json \
    --repo cli/cli --owner-id 59704711 --repo-id 212613049 \
    --source-ref refs/heads/trunk \
    --signer-workflow .github/workflows/deployment.yml \
    --checkpoint-origin 'rekor.sigstore.dev - 1193050959916656506'
```

```text
verified: subject 83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60 (gh_2.96.0_linux_amd64.tar.gz)
  source:  cli/cli @ refs/heads/trunk
  signer:  cli/cli .github/workflows/deployment.yml
  transparency: integratedTime=1783027755 logIndex=2049189324
  trust root:   embedded-public-good efe219604a80ad73be4c010b799cfcc3bd85c4fc37ff54f701ae4db7ebdeef95
```

Now change a single byte of the tarball and run the same command:

```text
error: content binding error: subject digest not found in statement
```

A checksum would catch that too. The more interesting case is a genuine file
with a valid signature that came from a different build path. Put the original
tarball back and expect `.github/workflows/release.yml` instead:

```text
error: policy error: signer workflow path mismatch: expected .github/workflows/release.yml, found .github/workflows/deployment.yml
```

The signature is valid, but this is not the build path you decided to trust,
so verification fails. That is the decision an updater needs to make before it
replaces a binary.

## Install

```sh
cargo add attestation-verify
```

The minimum supported Rust version is 1.88.

## Use it in your code

Write the policy once, then verify each artifact against it:

```rust
use attestation_verify::{Bundle, CheckpointOriginPolicy, GithubPolicy, RefPolicy, RepositoryIdentity};
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

let trust_store = TrustStore::embedded_public_good()?;
let rekor_log = trust_store
    .tlogs
    .first()
    .ok_or("embedded trust root has no Rekor log")?;
let origin_policy = CheckpointOriginPolicy::builder()
    .allow_origin(rekor_log, "rekor.sigstore.dev - 1193050959916656506")?
    .build()?;
let verifier = Verifier::builder()
    .trust_store(trust_store)
    .github_policy(policy)
    .checkpoint_origin_policy(origin_policy)
    .build()?;

let bundle = Bundle::from_json(&bundle_bytes)?;
let report = verifier.verify_bytes(&artifact_bytes, &bundle)?;
println!("{} @ {}", report.signer.source_repository, report.signer.source_ref);
```

The caller must provide both the identity policy (`GithubPolicy`) and a
non-empty exact checkpoint-origin policy (`CheckpointOriginPolicy`); the
latter is validated against the selected trust store's log-key SPKI digests
at builder time. [`examples/verify.rs`](examples/verify.rs) is the
dependency-free CLI used above, built only on this public API. It also accepts
a JSON Lines file holding a single bundle, such as one written by
`gh attestation download`. The full API is on
[docs.rs](https://docs.rs/attestation-verify).

## What is verified

Every call runs the whole chain against the embedded Sigstore public-good
trust root (or a caller-supplied one):

- Bundles generated by `actions/attest-build-provenance`
  (`application/vnd.dev.sigstore.bundle.v0.3+json`) carrying a
  `https://slsa.dev/provenance/v1` predicate.
- The artifact's SHA-256 digest against the attested subject.
- The DSSE envelope signature.
- Rekor v1 transparency-log inclusion: SET, Merkle inclusion proof, and
  checkpoint.
- The X.509/Fulcio certificate chain and the embedded SCT.
- GitHub identity policy: source repository and ref, plus signer workflow
  repository, path, and revision.

## Not supported yet

These inputs return typed `Unsupported` errors and are never silently
accepted:

- GitHub's own TSA-timestamped release-attestation flavor (`initiator:
  github`: no tlog entries, RFC 3161 timestamp, GitHub's own Fulcio/TSA
  trust root, predicate `https://in-toto.io/attestation/release/v0.2`).
- Rekor v2 (Ed25519, tiles/sharded logs). This crate detects and rejects v2
  entries rather than misinterpreting them; only Rekor v1 is verified.
- Private-repository attestations (different trust root; kept possible via
  root injection, not implemented).
- Any predicate type other than `https://slsa.dev/provenance/v1`.

See [DESIGN.md](DESIGN.md) for the full design, the normative time-evidence
model, and the roadmap.

## Sigstore conformance gate

CI builds a dependency-free `conformance` binary and runs the official
[sigstore-conformance Action](https://github.com/sigstore/sigstore-conformance)
on pull requests. It covers the suite's bundle verification flow for
certificate identities, custom trusted roots, artifact paths, and
`sha256:<digest>` inputs. The binary maps a GitHub workflow identity URI onto
`GithubPolicy` and pins the OIDC issuer to
`https://token.actions.githubusercontent.com`.

This is an honest verification subset. Signing is disabled with the Action's
`skip-signing` input because signing is a v0.1 non-goal. Managed-key
(`--key`) verification, staging, hashedrekord entries, legacy bundle versions,
Rekor v2/TSA fixtures, and non-GitHub identities return non-zero with an
explicit unsupported message. The current expected-failure list, with one
scope annotation per test node, is
[`tests/conformance-expected-failures.txt`](tests/conformance-expected-failures.txt).
The Action's strict xfail behavior makes both an unexpected failure and an
unexpected pass fail CI. The upstream CPython-release aggregate is skipped
because its Google/OIDC identities are outside this crate's GitHub-only scope.

To run the same static subset locally:

```sh
crate_dir="$(pwd)"
suite_dir="$(mktemp -d /tmp/attestation-verify-conformance.XXXXXX)"
git clone --depth=1 https://github.com/sigstore/sigstore-conformance.git "$suite_dir"
uv venv "$suite_dir/.venv"
uv pip install --python "$suite_dir/.venv/bin/python" \
    --requirement "$suite_dir/requirements.txt"
cargo build --locked --release --package attestation-verify-conformance
xfail="$(awk -F '\t' '!/^[[:space:]]*#/ && NF >= 2 { print $1 }' \
    tests/conformance-expected-failures.txt | paste -sd ' ' -)"
GHA_SIGSTORE_CONFORMANCE_SKIP_CPYTHON_RELEASE_TESTS=true \
GHA_SIGSTORE_CONFORMANCE_XFAIL="$xfail" \
    "$suite_dir/.venv/bin/python" -m pytest -q "$suite_dir/test" \
    --entrypoint "$crate_dir/target/release/attestation-verify-conformance" \
    --skip-signing
```

## Development

The minimum supported Rust version is 1.88. Run the same checks as CI from
the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
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

## Embedded trust root

`TrustStore::embedded_public_good()` is a pinned snapshot: this sans-io crate
does not fetch or refresh trust material at runtime. We update the snapshot
and publish a patch release when the upstream Sigstore public-good root
changes. Applications that need a different or newer root can parse a
caller-supplied trusted-root document instead. Monitor release notes before
long-lived deployments so an upstream key rotation does not leave the
embedded snapshot stale.

## Disclaimer

This crate has not been independently audited. Review it yourself before
relying on it for anything security-sensitive.

License: MIT OR Apache-2.0
