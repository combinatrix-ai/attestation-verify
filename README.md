# attestation-verify

Verify GitHub Artifact Attestations (Sigstore bundles) offline in Rust —
minimal dependencies, sans-io, fail-closed.

**Status: early implementation.** The verification chain is not complete yet;
`verify` fails closed with a typed error on unimplemented steps. Do not
depend on this crate yet. See [DESIGN.md](DESIGN.md) for the full design.

License: MIT OR Apache-2.0
