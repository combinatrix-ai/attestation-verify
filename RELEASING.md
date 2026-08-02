# Releasing

Releases are published from an exact `v<version>` tag through
`.github/workflows/publish.yml`. The workflow checks that the selected tag,
workflow input, and `Cargo.toml` version all agree before it can upload.

## First release bootstrap

crates.io Trusted Publishing can only be configured after the crate exists,
so version `0.1.0` needs a one-time API token.

1. Confirm the required CI checks and the manual differential workflow pass
   on the release commit.
2. Create a crates.io API token that is allowed to publish a new crate.
3. Create or protect the GitHub environment `crates-io`, add required
   reviewers, and store the token as its `CRATES_IO_TOKEN` secret.
4. Create and push the exact tag `v0.1.0` on the reviewed release commit.
5. Manually run the `Publish crate` workflow against the `v0.1.0` ref with
   input `0.1.0`.
6. Confirm the version appears on crates.io and docs.rs, then revoke the
   bootstrap token.

Publishing is permanent. Do not rerun a completed version; bump the package
version and create a new tag for any correction.

## Switch to Trusted Publishing

Immediately after the first publish:

1. In the crate's crates.io settings, add a GitHub Trusted Publisher for
   owner `combinatrix-ai`, repository `attestation-verify`, workflow
   `publish.yml`, and environment `crates-io`.
2. Update the workflow to grant only `id-token: write`, exchange the GitHub
   OIDC identity through `rust-lang/crates-io-auth-action`, and pass its
   short-lived output as `CARGO_REGISTRY_TOKEN` to `cargo publish`.
3. Remove `CRATES_IO_TOKEN` from the GitHub environment and confirm the next
   release uses no long-lived crates.io credential.

Keep the workflow filename and environment stable: crates.io binds both as
part of the trusted publisher identity.
