#!/usr/bin/env bash
#
# Differential verification gate (DESIGN.md "Testing strategy": release
# gates include differential verification against `gh attestation
# verify` for every golden fixture). This crate's `examples/verify.rs`
# must agree with `gh attestation verify` on both acceptance of the real
# artifact and rejection of a tampered copy.
#
# NOT run by `cargo test` or CI: requires the `gh` CLI (authenticated
# enough to download a public release asset) and network access. Run it
# by hand as a release gate:
#
#   scripts/differential.sh
#
# Exits 0 and prints "PASS: ..." if this crate's verifier agrees with
# `gh attestation verify` on every check below; exits 1 and prints
# "FAIL: ..." (with per-check detail) otherwise.

set -euo pipefail

REPO="cli/cli"
TAG="v2.96.0"
ARTIFACT="gh_2.96.0_linux_amd64.tar.gz"
BUNDLE_FIXTURE="tests/fixtures/github-cli/tarball-user-slsa-provenance.json"
SIGNER_WORKFLOW=".github/workflows/deployment.yml"
OWNER_ID="59704711"
REPOSITORY_ID="212613049"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

if ! command -v gh >/dev/null 2>&1; then
    echo "FAIL: the gh CLI is required and was not found on PATH" >&2
    exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "==> Downloading ${ARTIFACT} (${REPO} @ ${TAG}) to ${workdir}"
gh release download "$TAG" --repo "$REPO" --pattern "$ARTIFACT" --dir "$workdir"

genuine="$workdir/$ARTIFACT"
tampered="$workdir/tampered-$ARTIFACT"
cp "$genuine" "$tampered"

# Flip the low bit of the tampered copy's first byte: guaranteed to
# differ from the original (XOR with 1 always changes the byte), no
# python/perl dependency needed -- just dd, od, and printf.
first_byte_hex="$(dd if="$tampered" bs=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
flipped_hex="$(printf '%02x' "$(( 0x$first_byte_hex ^ 1 ))")"
printf "\\x${flipped_hex}" | dd of="$tampered" bs=1 count=1 conv=notrunc 2>/dev/null
echo "==> Tampered copy: ${tampered} (first byte 0x${first_byte_hex} -> 0x${flipped_hex})"

run_gh_verify() {
    gh attestation verify "$1" -R "$REPO"
}

run_example_verify() {
    (
        cd "$repo_root" && cargo run --quiet --example verify -- \
            --artifact "$1" \
            --bundle "$BUNDLE_FIXTURE" \
            --repo "$REPO" \
            --owner-id "$OWNER_ID" \
            --repo-id "$REPOSITORY_ID" \
            --signer-workflow "$SIGNER_WORKFLOW"
    )
}

overall_pass=0

# check DESCRIPTION expect_success[yes|no] COMMAND...
check() {
    local description="$1"
    local expect_success="$2"
    shift 2
    local output status
    if output="$("$@" 2>&1)"; then
        status=0
    else
        status=$?
    fi
    if { [ "$status" -eq 0 ] && [ "$expect_success" = yes ]; } \
        || { [ "$status" -ne 0 ] && [ "$expect_success" = no ]; }; then
        echo "  PASS: $description"
    else
        echo "  FAIL: $description (exit=$status, expected success=$expect_success)"
        echo "$output" | sed 's/^/    | /'
        overall_pass=1
    fi
}

echo "==> Positive: both verifiers must ACCEPT the genuine artifact"
check "gh attestation verify" yes run_gh_verify "$genuine"
check "cargo run --example verify" yes run_example_verify "$genuine"

echo "==> Negative: both verifiers must REJECT the one-byte-flipped copy"
check "gh attestation verify" no run_gh_verify "$tampered"
check "cargo run --example verify" no run_example_verify "$tampered"

echo
if [ "$overall_pass" -eq 0 ]; then
    echo "PASS: this crate's verifier agrees with gh attestation verify on all checks"
    exit 0
else
    echo "FAIL: disagreement between this crate's verifier and gh attestation verify -- see above"
    exit 1
fi
