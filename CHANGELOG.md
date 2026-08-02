# Changelog

All notable changes to this project are documented in this file.

## 0.1.0

Initial crates.io release.

- Verify GitHub Actions SLSA provenance bundles fully offline.
- Enforce DSSE, Rekor v1 SET/inclusion/checkpoint, Fulcio/X.509, SCT, subject,
  and GitHub identity-policy checks as one fail-closed chain.
- Support embedded public-good or caller-supplied Sigstore trust roots.
- Bound attacker-controlled parsing, allocation, and checkpoint-signature
  work.
- Test against real GitHub fixtures, the supported sigstore-conformance
  subset, differential `gh attestation verify` behavior, and fuzz targets.
