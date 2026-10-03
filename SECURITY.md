# Security policy

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
GitHub Security Advisories page. Do not open a public issue before a fix or
coordinated disclosure is ready.

Include the affected input shape, observed behavior, expected security
property, and a minimal reproducer when possible. Never include credentials,
private attestations, or other sensitive data in a report.

## Release authorization

`hmirin` is the sole authorized releaser. Release tag operations and publishing
job approval are restricted by GitHub settings described in `RELEASING.md`.
A tag push requests a release; it does not skip the required approval.
Repository and organization administrators are trusted to maintain these
protections. This policy does not defend against administrators changing the
release authorization settings themselves.

Release tests and package build verification must run without publishing or
OIDC authority. Only the separate, approved publishing job may mint an OIDC
token; it must not execute package tests, build scripts, proc macros, or
repository-selected credential helpers. It must publish the same package
content verified by the unprivileged job.
