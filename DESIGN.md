# attestation-verify — Design

Status: revision 4 — verification chain and conformance gate implemented
Date: 2026-07-31
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
2. Full verification chain with a **normative time-evidence model** (below):
   no step is optional, and the only configuration is *what identity to
   require*, never *how much to verify*.
3. Identity policy that separates **source identity** from **signer-workflow
   identity**, with numeric owner and repository IDs first-class and exact
   release-ref binding for updater callers.
4. Dependency discipline: pure-Rust crypto (RustCrypto stack), no HTTP
   client, no protobuf toolchain. Budget: **target < 60, ceiling < 80**
   transitive crates (metric defined below); the number becomes a public
   promise only after the prototype passes all correctness gates.
5. sans-io: no network, no filesystem access, no wall clock inside
   verification. Determinism is *relative to a caller-selected trust-root
   snapshot and authenticated timestamp evidence* — see "Time-evidence
   model" for exactly what this does and does not establish.
6. Embeddable everywhere dlgt builds: the 6-target zig cross-build matrix
   (mac x86_64/aarch64, linux gnu/musl x86_64/aarch64) must pass with
   `--locked`, and cryptographic fixture tests must run natively on macOS and
   Linux.

## Non-goals (v0.1)

Signing. OCI/container verification. Key-based cosign signatures.
npm-provenance / Homebrew profiles (same bundle format; deferred, and the
invariant-verification/profile split below keeps them possible).
GitHub private-repo attestations (different trust root; kept possible via
root injection). HTTP fetching of any kind — acquisition belongs in a future
companion crate (`attestation-verify-fetch` / `-tuf`), not behind a feature
flag on the minimal core. A TUF client. Streaming subject hashing (deferred;
v0.1 takes a precomputed digest or a byte slice). WASM (not designed
against, not tested).

## Core decisions

1. **sans-io core.** Inputs are values: subject digest, bundle, trust
   snapshot, policy. Output is a provenance-separated report or a mechanical
   typed error. All acquisition is the caller's business.
2. **Hand-modeled serde types** for the bundle (v0.3 protojson), trusted
   root, and in-toto statement subset. No `prost`. Parsers are hardened:
   size/count/depth limits, duplicate-key rejection, strict base64/hex,
   exactly one DSSE signature, media-type enforcement, unknown
   kind/version → typed `Unsupported`, never best-effort.
3. **Embedded trusted root, swappable, identified.** Vendor the Sigstore
   public-good `trusted_root.json` (`TrustStore::embedded_public_good()`);
   accept caller-supplied roots (`TrustStore::from_json`, format-compatible
   with `gh attestation trusted-root` output). No TUF in-core. Every report
   and every trust error carries the snapshot's fingerprint/version/date so
   operators can see which root made the decision.
4. **Time-evidence model is normative** (next section). Certificate and log-
   key validity are checked against *authenticated* log time only.
5. **`Verifier` is the primary API**; `verify()` is a thin convenience.
   Policy and trust material are validated once at build time and reused.
6. **Identity policy split**: `SourcePolicy` (repository identity + ref +
   optional commit) and `SignerPolicy` (workflow repository + path +
   revision), because reusable workflows make "repository + workflow path"
   ambiguous and unsafe on its own.
7. **Provenance-separated output.** Certificate-derived facts, transparency-
   log facts, and workflow-controlled statement content have different trust
   provenance and are never flattened into one struct.
8. **Mechanical error taxonomy.** Errors state what check failed, not the
   attacker's intent: `Parse`, `Unsupported`, `Trust`, `Certificate`,
   `Transparency`, `Timestamp`, `ContentBinding`, `Policy`, `ResourceLimit`
   (all `#[non_exhaustive]`). No `Tampered`, no inferred `StaleRoot`; root
   freshness is a separate caller-supplied-`as_of` assessment, never derived
   from attacker-controlled bundle data.

## Time-evidence model (normative)

For GitHub's expected no-TSA Rekor v1 bundles, an inclusion proof alone does
NOT authenticate `integratedTime` — it proves body inclusion under a
checkpoint, while `integratedTime`/`logID`/`logIndex` are separate metadata
authenticated only by the SET (inclusion promise). Both are therefore
required; they answer different questions:

1. Bind the Rekor entry body field-by-field to the bundle (list below).
2. Verify the Merkle inclusion proof against the checkpoint root/tree size.
3. Verify the signed checkpoint (origin, root, tree size) against the
   trusted log key.
4. Verify the SET over the canonical entry body + integration metadata.
5. Only then use `integratedTime` to check leaf-certificate validity and
   trust-root key validity windows.

If a bundle carries a verified RFC 3161 timestamp (future), it may establish
signing time, but the inclusion proof remains required and a present SET is
still verified.

What this model deliberately does NOT establish (callers own these):
trust-snapshot currency, post-snapshot revocation, rejection of future-dated
(but correctly signed) log times, artifact freshness/latest-version, and
rollback protection. An updater binds the requested release tag via policy
(exact ref), which is the rollback answer at that layer.

## Rekor v1 / v2 scope

The current public-good trusted root already contains a Rekor v2 (Ed25519,
tiles/sharded) log key, so "Ed25519 behind a feature" is untenable. Decision:

- Ed25519 and checkpoint/signed-note parsing are mandatory dependencies.
- v0.1.0 implements Rekor v1 fully (SET + inclusion + checkpoint) and
  *detects* v2 entries with a typed `Unsupported` error.
- v2 verification is a fast-follow (v0.1.x). **Settled by live fixtures
  (2026-07-29):** GitHub's `attest-build-provenance` path still emits Rekor
  v1 entries (`kind: dsse, version: 0.0.1`) with SET + inclusion proof +
  checkpoint — see `tests/fixtures/README.md`. v1-normative v0.1.0 stands.

## Fixture findings (2026-07-29, cli/cli v2.96.0)

Captured real-world facts that bind this design (details in
`tests/fixtures/README.md`):

- **Multi-subject statements are the normal case.** The workflow provenance
  statement carries all 21 release artifacts as subjects; subject matching
  means finding the caller's digest in a set, and "multiple subjects" is not
  an edge case or an error.
- **GitHub now auto-attests public release assets itself** (`initiator:
  github`): bundle with RFC 3161 TSA timestamp, no tlog entries, predicate
  `in-toto release/v0.2`, verifiable only against GitHub's own trust root
  (six `fulcio.githubapp.com` CAs, six TSAs, no logs). This flavor is v0.2
  scope alongside private repos — same mechanism.
- **Acquisition shape:** the attestations API no longer inlines bundles; it
  returns `initiator`, `repository_id`, and a short-lived `bundle_url`
  serving raw-snappy-compressed bundle JSON. Fetching/decompression stays in
  the future companion crate; `BundleSet` parses the fetched forms.
- The public-good root currently lists both the Rekor v1 P-256 log and the
  Rekor v2 Ed25519 log (`log2025-1.rekor.sigstore.dev`) — confirming the
  mandatory-Ed25519 decision.

## Rekor-entry ↔ bundle binding (normative)

Reject unless ALL hold (Rekor v1): entry signature == the single DSSE
signature; entry certificate/key == bundle leaf; entry payload hash ==
decoded DSSE payload hash; entry kind/version in the supported exact set
(`dsse`/`intoto`, pinned versions); SET canonical body == inclusion-leaf
body; proof root/tree size == checkpoint root/tree size; `logId` ==
selected trusted key. (Modeled on Cosign GHSA-whqx-f9j3-ch6m, where an
unrelated valid Rekor entry satisfied verification; regression fixtures
reproduce that shape.)

Two requirements that earlier drafts of this section listed are recorded
below instead, so that neither is mistaken for an unimplemented check.

**`logIndex` is NOT compared against the inclusion proof's index.** An
earlier draft required `entry logIndex == proof index`; real bundles
refute it. The `cli/cli` golden fixture carries `logIndex` 2049189324 and
`inclusionProof.logIndex` 1927285062 (`treeSize` 1927285185). These are
different quantities in `sigstore_rekor.proto`: the entry's own
`logIndex` is its position in the log as a whole, while the proof's is
the leaf's position within the specific tree the proof was issued
against. Implementing the equality would reject every genuine bundle.

**Checkpoint origin binding is specified but not yet implemented.** The
origin line, the signature line's name, and the 4-byte key hint are all
parsed and discarded (`src/rekor.rs`). The origin is not unprotected —
it sits inside the signed note body, so altering it fails the checkpoint
signature check — and the key is selected from the entry's `logId`
against the trust store, not from the checkpoint's own labels. Binding
them is defence in depth, not a live gap; it is worth doing because the
unused key hint is also what makes signature-line fan-out cheap
(`MAX_CHECKPOINT_SIGNATURES`).

## X.509 / Fulcio validation profile (normative)

Local path validation implemented against a *declared* profile — `x509-cert`
supplies parsing only. The profile specifies: leaf/intermediate/root
selection with bundle-supplied roots never trusted; allowed signature
algorithms and curve/hash mapping (P-256 leaves; P-384 required for current
Fulcio CA signatures); basic-constraints and path-length enforcement; leaf
and CA KU/EKU requirements (code-signing EKU on leaves); rejection on
unknown critical extensions; certificate validity at every accepted
authenticated signing time; trusted-root CA `validFor` windows; Fulcio
certificate-profile checks; duplicate/malformed identity-extension
rejection; deterministic behavior on chain ambiguity and superfluous
embedded roots.

**SCT verification is day one** (Sigstore's model: never trust unlogged
certificates): embedded SCT extraction with exact CT serialization,
signature verification in correct precertificate/issuer context, CT log
key selection from the root, SCT time within the CT key validity window,
threshold ≥ 1 distinct trusted CT log. An SCT is evidence about certificate
issuance; it is not artifact-signing time and cannot replace SET/TSA.

## Identity policy

```rust
GithubPolicy {
    source: SourcePolicy {          // where the code came from
        repository: RepositoryIdentity,   // owner/name + numeric owner ID
                                          // + numeric repository ID when present
        git_ref: RefPolicy,               // Exact("refs/tags/v0.4.0") | Glob(...)
        commit: Option<CommitSha>,
    },
    signer: SignerPolicy {          // which workflow signed (reusable-workflow safe)
        repository: RepositoryIdentity,
        path: WorkflowPath,               // ".github/workflows/release.yml"
        revision: WorkflowRevisionPolicy,
    },
    // issuer pinned internally to https://token.actions.githubusercontent.com
}
```

Numeric owner ID protects against owner rename/recreation; numeric
repository ID protects against repository rename/transfer/recreation.
Updaters exact-match the requested release ref (`Exact`); globs exist but
are documented as the weaker form, not showcased as the default.

## API sketch

```rust
use attestation_verify::{Bundle, BundleSet, GithubPolicy, TrustStore, Verifier};

let verifier = Verifier::builder()
    .trust_store(TrustStore::embedded_public_good())
    .github_policy(policy)                       // validated here, once
    .build()?;

let bundle = Bundle::from_json(&bundle_bytes)?;  // exactly one bundle
// containers are explicit — no sniffing:
// BundleSet::from_github_response(..) / BundleSet::from_json_lines(..)

let report = verifier.verify_digest(&sha256_digest, &bundle)?;
// or: verifier.verify_bytes(&artifact_bytes, &bundle)?;

// provenance-separated result:
report.subject;       // VerifiedSubject
report.signer;        // VerifiedCertificateIdentity (cert-derived claims)
report.transparency;  // VerifiedTransparency (log index, integrated time)
report.statement;     // VerifiedSignedStatement (signed ≠ independently true)
report.trust;         // TrustSnapshotInfo (root fingerprint/version/date)
```

`verify()` remains as a one-shot convenience wrapper. `verify_digest` /
`verify_bytes` are distinct names so digests and artifact bytes cannot be
confused. `BundleSet` verification defines its success semantics explicitly
(policy-satisfying bundle found; per-bundle failures retained for
diagnostics). Profile extension points (npm/Homebrew later) run only *after*
the invariant cryptographic chain — no trait allows a profile to accept a
result before mandatory checks.

## Trust-root operations (documented commitments)

- Release overlap: publish releases verifiable by both old and new roots
  before retiring keys; historical key windows keep old artifacts
  verifiable.
- Snapshot identity (fingerprint/version/date) reported on success and in
  trust errors.
- Documented manual recovery for a stale updater (fetch root via
  `gh attestation trusted-root` or upgrade out-of-band); a root shipped
  beside the artifact is never accepted unless independently authenticated.
- Offline roots have no built-in expiration and cannot surface
  post-snapshot revocations — stated in docs, surfaced via the separate
  `as_of` freshness assessment API.

## Dependencies (target)

`serde`, `serde_json`, `sha2`, `p256`, `p384`, `ecdsa`, `signature`,
`ed25519-dalek` (mandatory: current Rekor v2 key), `x509-cert`, `der`,
`spki`, `const-oid`, `base64`, `hex`, `thiserror`, plus small pieces for
checkpoint/signed-note parsing and ref matching (hand-rolled where
reasonable).

Budget metric: unique normal+build dependencies for the default feature set,
per supported target, excluding dev-deps, measured by `cargo tree`. Target
< 60, ceiling < 80 — correctness is never traded for the number (no
hand-written PKI shortcuts to hit a marketing figure). CI enforces the
ceiling, the 6-target `--locked` zigbuild matrix, and native crypto fixture
tests on macOS + Linux.

## Testing strategy

- Golden fixtures: real bundles + artifacts from dlgt releases, plus
  gh-CLI-produced fixtures from an unrelated public repo.
- **Release gates for v0.1**: sigstore-conformance subset, and differential
  verification against `sigstore-go`/`gh attestation verify` for every
  golden fixture (accept/reject parity).
- Mutation negatives — per chain step AND the cross-binding class:
  unrelated-but-valid Rekor entry/SET (advisory shape); altered unsigned
  `integratedTime`; SET without proof and proof without SET; index/tree-
  size/root/origin mismatches; wrong log ID; v1/v2 confusion; unsupported
  kind/version; zero/multiple DSSE signatures; wrong payload type; malformed
  PAE; untrusted embedded root; reordered chain; CA-constraint and KU/EKU
  violations; unknown critical extension; SCT wrong issuer/key/
  altered/out-of-window; cert valid at SCT time but not SET time; duplicate
  or malformed Fulcio extensions; source vs reusable signer-workflow
  confusion; owner/repo rename-recreation-transfer; case normalization;
  exact-tag mismatch hidden by glob; empty/multiple subjects; malformed or
  unknown digest; duplicate JSON keys; oversized inputs, deep nesting,
  integer overflow, negative index/time; root rotation and stale-updater
  recovery.
- **Low-S is NOT enforced, and must not be.** An earlier draft listed
  "high-S ECDSA" as a mutation negative. Every signature in the `cli/cli`
  golden fixture is high-S — the Rekor checkpoint signature, the SET, and
  the DSSE signature alike — so rejecting high-S anywhere in this chain
  would reject genuine bundles. ECDSA malleability is also not exploitable
  here: the DSSE signature bytes are compared against the Rekor entry body
  byte-for-byte, and that body is Merkle-committed, while the SET and
  checkpoint signatures are not re-bound anywhere, so re-encoding one
  gains an attacker nothing.
- Determinism test: identical results regardless of system clock.
- Fuzz targets + hard resource limits ship with the first parser; corpus
  maturity grows later.
- Acceptance: dlgt update verifies its own release fail-closed.

## self_update composition and upstream strategy

self_update (10.3M downloads; 1.0.0-rc iterating actively 2026-07) exposes
building blocks (`ReleaseList`, `Download`, `Extract`, re-exported
`self_replace`) but one-shot `update()` has no custom verification hook
(zipsign only). Composition works today: list → download archive +
`<name>.sigstore.json` → `Verifier::verify_bytes` → extract → self-replace.
Once public, propose an `attestations` feature upstream (engine = this
crate, default-off); raise the API-shape issue during the 1.0-rc window so
the hook is not precluded.

Bundle conventions: recommend attaching `<artifact-filename>.sigstore.json`
per artifact; accepted container inputs are the GitHub attestation API
response and `gh attestation download` JSONL via explicit `BundleSet`
constructors.

## dlgt integration plan (first consumer)

Prerequisite in dlgt's release.yml: attest the six archives and the checksum
manifest; attach bundles as release assets. Then `dlgt update`: download
archive + bundle (curl, as today) → verify with source repo
`combinatrix-ai/dlgt` pinned by numeric IDs, signer workflow
`.github/workflows/release.yml`, **exact ref = the requested release tag**
→ only then hand off to the installer. Rollout: warn-only one release, then
fail-closed.

## Roadmap

- v0.1.0: verification core as specified; Rekor v1 normative; v2 typed
  `Unsupported` (promoted if fixtures show GitHub emits v2).
- v0.1.x: Rekor v2 verification.
- v0.2: GitHub-trust-root verification (RFC 3161 TSA path) — covers both
  `initiator: github` release attestations on public repos and private-repo
  attestations; npm-provenance and Homebrew profiles atop the invariant
  chain.
- v0.3: companion acquisition crate (`-fetch`/`-tuf`), tiny CLI (potential
  gh extension), possible `attested-update` sugar crate, upstream
  self_update PR.

## Naming

Crate and repo: `attestation-verify` (crates.io availability confirmed
2026-07-29). Rejected: `gh-attestation` (GitHub's own early-access extension
name; reads official), `attested` (TEE/remote-attestation term space),
`attested-updates` (names the first use case; reserved-in-spirit for the
future updater sugar crate). In supply-chain tooling, unqualified
"attestation" is the in-toto/SLSA/GitHub term; TEE usage is qualified.

License: MIT OR Apache-2.0. MSRV: latest stable minus a small window,
finalized at implementation.

## Resolved questions (counterpart review, 2026-07-29)

1. SCT: in scope day one — load-bearing CT evidence (not signing time).
2. SET vs checkpoint: BOTH required for GitHub no-TSA v1 bundles; SET-only
   legacy excluded unless real fixtures force it.
3. No-wall-clock: restated as determinism relative to snapshot +
   authenticated time; freshness/future-dating/revocation/latest are caller
   policy.
4. Staleness UX: mechanical `UnknownLogKey`/`NoTrustedKeyValidAt` errors +
   separate `as_of` freshness assessment; never inferred from bundle data.
5. API: `Verifier` primary; `verify()` convenience wrapper;
   `verify_digest`/`verify_bytes` distinct.
6. Budget: <60 target, <80 ceiling, metric pinned, promise deferred until
   the prototype passes correctness gates.
7. Streaming subject: deferred from v0.1.
8. Roadmap compatibility: invariant chain vs profile split; multi-root,
   multi-log-version model; acquisition/TUF in companion crates.

## Remaining open items

- Choose or hand-roll ref-glob matching (dependency-budget sensitive).
- MSRV number.
- Second-implementer review of the X.509 profile before it is frozen.

## Revision log

- r1 (2026-07-29): initial draft.
- r2 (2026-07-29): counterpart review applied — normative time-evidence
  model (SET + checkpoint both required); field-by-field Rekor↔bundle
  binding (GHSA-whqx-f9j3-ch6m shape); Rekor v2/Ed25519 scope decision;
  X.509/Fulcio profile made explicit; SCT detailed; source/signer policy
  split + numeric repo ID + exact release-ref binding; provenance-separated
  report; Verifier-primary API; Bundle/BundleSet explicit constructors;
  mechanical error taxonomy; trust-root operational commitments; budget
  restated (<60 target/<80 ceiling) with pinned metric; conformance +
  differential testing promoted to release gates; streaming and fetch cut.
- r3 (2026-07-30): verification chain implemented end to end (identity-
  policy matching + full orchestration in `Verifier::verify_digest`,
  `ChainNotImplemented` removed) and passing against the real `cli/cli`
  golden fixture; sigstore-conformance subset and differential-verification
  gates (`scripts/differential.sh`, shipped but not run in CI) are next.
- r4 (2026-07-31): added the dependency-free verification-only
  sigstore-conformance client and PR release gate; recorded the strict
  expected-failure manifest for signing, managed-key, legacy/hashedrekord,
  Rekor v2/TSA, and non-GitHub scope boundaries.
- r5 (2026-07-31): fixture-seeded cargo-fuzz targets and a bounded pull-request
  smoke job added for every security-sensitive parser; fuzz build output is
  isolated from the library workspace and dependency budget.
