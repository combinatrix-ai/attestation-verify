# Releasing

Only `hmirin` is authorized to release `attestation-verify`. Pushing an exact
`v<version>` tag is a release request; publishing also requires `hmirin` to
approve the `crates-io` environment job.

## Release authorization

The following GitHub settings enforce this policy independently of the tagged
workflow contents:

- The active **Release tags: hmirin only** tag ruleset covers `refs/tags/v*`.
  Creation, update, and deletion are restricted, with user `hmirin`
  (GitHub user ID `1284876`) as the sole bypass actor. Repository roles,
  organization administrators, other users, and apps have no bypass entry.
- The `crates-io` environment requires approval from `hmirin` only. Administrator
  bypass is disabled. Self-review remains allowed so `hmirin` can approve their
  own release request.
- The environment accepts tags matching `v*` only; branches are not allowed.
- The crates.io Trusted Publisher must be bound to owner `combinatrix-ai`,
  repository `attestation-verify`, workflow `publish.yml`, and environment
  `crates-io`. Confirm this binding in crates.io before publishing.

GitHub settings are not stored in this checkout. Verify them after permission
or protection changes. Repository and organization administrators remain
trusted to administer these settings; this policy does not prevent an
administrator from changing or removing the protections themselves.

## Publish a release

1. Confirm the required CI checks and the manual differential workflow pass
   on the reviewed release commit. Check the package version in `Cargo.toml`.
2. As `hmirin`, create and push the exact `v<version>` tag on that commit.
   `.github/workflows/publish.yml` starts automatically on `v*` tag pushes.
3. Inspect the tag and exact commit SHA, then approve the pending `crates-io`
   environment job as `hmirin`.
4. The workflow checks the tag syntax and package-version equality, runs the
   locked tests and publish dry-run, then authenticates through GitHub OIDC
   Trusted Publishing and uploads the crate.
5. Confirm the version appears on crates.io and docs.rs.

Publishing is permanent. Do not rerun a completed version; bump the package
version and create a new tag for any correction. Approval authorizes the
selected release source, not merely a tag name.

## First release bootstrap

crates.io Trusted Publishing can only be configured after the crate exists.
If the crate has not yet been created, the current OIDC-only workflow cannot
bootstrap it. Arrange a separate, explicitly authorized one-time publish by
`hmirin` with a temporary crates.io API token, revoke that token, and configure
the Trusted Publisher before using this workflow. Do not store the token in
this repository or restore a long-lived credential to the workflow.

Keep the workflow filename and environment stable: crates.io binds both as
part of the trusted publisher identity.
