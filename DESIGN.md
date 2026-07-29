# attestation-verify — Design

Status: draft for counterpart review
Date: 2026-07-29
Owner: combinatrix-ai

## One-line

Verify GitHub Artifact Attestations (Sigstore bundles) offline, at runtime, in
Rust, with a minimal and auditable dependency footprint.

## The gap this fills

GitHub made attestation *generation* a free one-step workflow feature
(`actions/attest-build-provenance`, GA since 2024). Consumption from Rust is a
hole:

- `sigstore` (sigstore-rs): official Sigstore org crate, self-described
  experimental, API unstable. Measured 2026-07: 290 transitive crates with the
  minimal `bundle` feature, 387 with defaults; transport (HTTP/OCI/OAuth) is
  entangled with verification.
- `sigstore-verification` (jdx, built for mise): archived 2026-05.
- `sigstore-rust` (prefix-dev): v0.1, aws-lc-rs crypto backend, which is
  hostile to zig-based cross builds.
- `gh attestation verify` requires the gh CLI plus GitHub authentication —
  unsuitable as a library dependency for a CLI's self-update path.

Demand is broader than self-update: CI pipelines verifying downloaded tool
binaries without gh/auth, tool managers verifying third-party tools (mise's
actual use case), plugin loaders, artifact intake audit, and updaters
(self_update has 10.3M downloads and zipsign-only verification).

First consumer: `dlgt update` (fail-closed verification of its own release
archives). Dogfooding is the acceptance test.

## Goals (v0.1)

1. Verify a GitHub artifact attestation bundle against an artifact digest,
   fully offline.
2. Full verification chain, no shortcuts (see "Verification chain").
3. Identity policy with safe defaults; numeric repo-owner ID matching is
   first-class (rename/resurrection resistance, same judgment as gh CLI).
4. Dependency budget: **< 60 transitive crates**, pure-Rust crypto
   (RustCrypto stack only), no HTTP client, no protobuf toolchain.
5. sans-io: no network, no filesystem access, no wall clock (see below).
6. Fail-closed: no "skip this check" knobs in the public API. The only
   configuration is *what identity to require*, never *how much to verify*.
7. Embeddable everywhere dlgt builds: the 6-target zig cross-build matrix
   (mac x86_64/aarch64, linux gnu/musl x86_64/aarch64) must pass.

## Non-goals (v0.1)

Signing. OCI/container verification. Key-based cosign signatures.
npm-provenance / Homebrew profiles (same bundle format; deliberately deferred,
architecture must not preclude them). GitHub private-repo attestations
(different trust root; kept possible via root injection, not implemented).
HTTP fetching of any kind. A TUF client. WASM target (not designed against,
not tested in v0.1).

## Core decisions

1. **sans-io core.** Inputs are values: artifact digest, bundle JSON, trusted
   root, policy. Output is a verified-facts struct or a typed error. All
   acquisition (downloading archives, bundle assets, refreshing roots) is the
   caller's business. This is where the dependency budget comes from.
2. **Hand-modeled serde types** for the Sigstore bundle (v0.3 JSON, protojson
   encoding), the trusted root, and the in-toto statement — only the subset we
   verify. No `prost`/`sigstore_protobuf_specs`.
3. **Embedded trusted root, swappable.** Vendor the Sigstore public-good
   `trusted_root.json` in the crate (`TrustedRoot::embedded()`); refresh it
   via crate releases. Accept caller-supplied roots
   (`TrustedRoot::from_json`), format-compatible with
   `gh attestation trusted-root` output. No TUF: this is the deliberate
   lightweight answer, and the staleness semantics are documented rather than
   hidden. Historical key material in the root (validity windows) keeps old
   artifacts verifiable.
4. **No wall clock.** Certificate validity and trust-root key windows are
   checked against the transparency-log integrated time (the Sigstore model
   for short-lived certs), not `SystemTime::now()`. Verification is therefore
   deterministic and reproducible; root *freshness* is a separate,
   caller-visible concern.
5. **GithubPolicy with safe defaults.** Matches Fulcio certificate extensions
   (OID arc 1.3.6.1.4.1.57264.1.*): OIDC issuer must be
   `https://token.actions.githubusercontent.com`; repository; numeric owner
   ID (first-class, recommended); workflow path; source ref glob
   (`refs/tags/*`); optionally trigger event. Repo-name-only matching is
   possible but the docs and examples push owner-ID pinning.
6. **Rich verified output.** On success return the proven facts: repository,
   owner ID, workflow ref, commit SHA, run identity, trigger, log index,
   integrated time — so callers can log, display, or enforce further.
7. **Error taxonomy distinguishes attack-shaped from config-shaped.**
   `Tampered`, `UntrustedCertificate`, `LogInconsistent` vs
   `PolicyMismatch { expected, found }`, `StaleRoot { .. }`, `Malformed`.
   Callers (e.g. an updater) can decide to hard-fail vs explain.

## Verification chain (spec level)

Given (subject digest, bundle, trusted root, policy):

1. Parse bundle (v0.3): DSSE envelope + verification material (leaf
   certificate, tlog entries, no TSA data expected for public GitHub).
2. Build and verify the certificate chain from the leaf to a Fulcio CA in the
   trusted root; check key-usage/extensions appropriate for Fulcio leaves.
3. Verify the SCT embedded in the leaf against the CT log keys in the root.
4. Verify the DSSE PAE signature with the leaf key (ECDSA P-256; P-384
   supported).
5. Verify the Rekor tlog entry: inclusion proof against the checkpoint,
   checkpoint signature against the Rekor key in the root; entry body must
   be consistent with the DSSE envelope (kind `dsse`/`intoto`).
6. Time consistency: integrated time must fall within leaf-certificate
   validity and within the validity window of the log keys used.
7. Parse the in-toto statement: `_type` in-toto v1, subject digest (sha256)
   must equal the caller's subject; predicate type must be SLSA provenance v1
   (configurable allow-list later, not a free-for-all).
8. Apply GithubPolicy to the certificate claims.

Every step has a corresponding typed error and at least one negative test.

## API sketch

```rust
use attestation_verify::{Bundle, GithubPolicy, Subject, TrustedRoot, verify};

let root = TrustedRoot::embedded();                  // vendored public-good root
let bundle = Bundle::from_json(&bundle_bytes)?;      // .sigstore.json / API / gh download forms
let subject = Subject::sha256_of(&artifact_bytes);   // or Subject::from_digest_hex(...)

let policy = GithubPolicy::builder("combinatrix-ai/dlgt")
    .owner_id(OWNER_ID)                              // numeric; recommended
    .workflow(".github/workflows/release.yml")
    .source_ref("refs/tags/*")
    .build()?;

let facts = verify(&root, &subject, &bundle, &policy)?;
println!("built by {} @ {}", facts.workflow_ref, facts.commit_sha);
```

Open sub-questions: free function vs a `Verifier` struct holding
(root, policy) for reuse across many artifacts; whether `Subject` should
offer a streaming hasher (`impl Write`) for large archives.

## Bundle acquisition conventions (documented, not implemented)

- Recommended release-asset convention: attach the bundle as
  `<artifact-filename>.sigstore.json` next to each artifact. Discoverable via
  any release-listing API, including self_update's `ReleaseList`.
- Accepted input shapes: a bare bundle JSON, the GitHub attestation API
  response (`{"attestations":[{"bundle":...}]}`), and `gh attestation
  download` JSONL. One `Bundle::from_json` entry point sniffs these.

## Dependency budget (target)

`serde`, `serde_json`, `sha2`, `p256`, `p384`, `ecdsa`, `signature`,
`x509-cert`, `der`, `spki`, `const-oid`, `base64`, `hex`, `thiserror`.
(`ed25519-dalek` only if checkpoint key types require it, behind a feature.)

CI enforces the budget: a test fails if the transitive crate count exceeds 60.
CI also runs the 6-target zigbuild matrix to guarantee downstream
embeddability in dlgt-like release pipelines.

## Testing strategy

- Golden fixtures: real bundles + artifacts from dlgt releases (and one
  gh-CLI-produced fixture from another public repo for diversity).
- Mutation negatives, one per chain step: flipped artifact byte, certificate
  from another repo, stripped tlog entry, broken inclusion proof, integrated
  time outside cert validity, wrong subject digest, wrong predicate type,
  policy mismatches (owner ID, workflow, ref).
- Determinism test: verification result is identical regardless of system
  clock.
- Later: sigstore-conformance subset, parser fuzzing (cargo-fuzz).
- Acceptance: dlgt update verifies its own release fail-closed using this
  crate.

## self_update composition and upstream strategy

self_update (10.3M downloads; 1.0.0-rc series iterating actively as of
2026-07) exposes building blocks (`ReleaseList`, `Download`, `Extract`,
re-exported `self_replace`) but its one-shot `update()` has no custom
verification hook (zipsign only). Composition works today: list → download
archive + `<name>.sigstore.json` → `attestation_verify::verify` → extract →
self-replace. Once this crate is public, propose an `attestations` feature
upstream (engine = this crate, default-off); the 1.0-rc window is the moment
to raise the API-shape issue so the hook is not precluded.

## dlgt integration plan (first consumer)

Prerequisite in dlgt's release.yml: attest the six archives and the checksum
manifest; attach bundles as release assets per the naming convention above.
Then `dlgt update`: download archive + bundle (curl, as today) → verify with
policy (owner combinatrix-ai pinned by ID, repo dlgt, workflow
`.github/workflows/release.yml`, `refs/tags/*`) → only then hand off to the
installer (which re-checks sha256 from the verified manifest). Rollout:
warn-only in one release, fail-closed in the next.

## Roadmap

- v0.1: verification core as designed here.
- v0.2: GitHub private-repo attestations via injected trust root;
  npm-provenance and Homebrew profiles (same bundle format, different
  identity policies).
- v0.3: optional `fetch` feature (attestation API + root refresh); a tiny CLI
  (potentially doubling as a gh extension); possibly an `attested-update`
  sugar crate for updater flows; upstream self_update PR.

## Naming

Crate and repo: `attestation-verify` (crates.io availability confirmed
2026-07-29). Rejected: `gh-attestation` (name of GitHub's own early-access
extension; reads official), `attested` (collides with the TEE/remote-
attestation term space), `attested-updates` (names the first use case, not
the thing; reserved-in-spirit for the future updater sugar crate). In
supply-chain tooling, unqualified "attestation" is the in-toto/SLSA/GitHub
term; TEE usage is qualified ("remote attestation"), and crates.io keywords
disambiguate.

License: MIT OR Apache-2.0. MSRV: latest stable minus a small window,
finalized at implementation.

## Open questions for review

1. Is deferring SCT verification acceptable for v0.1, or is it load-bearing
   from day one? (Current position: in scope, day one.)
2. Rekor entry verification: inclusion proof + checkpoint only, or also
   accept SET (signed entry timestamp) for older entries?
3. Any holes in the "no wall clock" determinism claim?
4. TrustedRoot staleness UX: typed `StaleRoot` error with guidance vs plain
   verification failure when key windows don't cover the integrated time.
5. `verify()` free function vs reusable `Verifier` — which surface ages
   better, especially for the future multi-profile (npm/Homebrew) world?
6. Is the < 60 crate budget realistic given x509-cert + ecdsa + p384, or
   should the budget be restated (e.g. < 80) before it becomes a public
   promise?
7. Streaming `Subject` hashing in v0.1 or defer?
8. Anything in this design that would preclude the v0.2/v0.3 roadmap items?
