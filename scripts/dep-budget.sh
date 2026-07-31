#!/usr/bin/env bash
#
# Measure the attestation-verify dependency budget for the library's default
# feature set. The metric is the number of unique (name, version) pairs in
# the normal and build dependency tree for the canonical Linux target,
# excluding dev-dependencies; shared leaves are counted once even when cargo
# tree prints them again with a (*) marker. The target keeps the reported
# budget stable when the script is run on a macOS workstation; CI runs on the
# same x86_64-unknown-linux-gnu target.
#
# The design target is below 60 and the hard ceiling is 80. This script is
# intentionally locked to Cargo.lock so CI measures the committed graph.
#
# Usage: scripts/dep-budget.sh

set -euo pipefail

target=60
ceiling=80
budget_target="${DEP_BUDGET_TARGET:-x86_64-unknown-linux-gnu}"

tree="$(cargo tree --locked --target "$budget_target" --edges normal,build --prefix none --format '{p}')"
root_pair="$(printf '%s\n' "$tree" | awk 'NF >= 2 { print $1 "\t" $2; exit }')"
count="$(printf '%s\n' "$tree" \
    | awk -v root="$root_pair" 'NF >= 2 { pair = $1 "\t" $2; if (pair != root) print pair }' \
    | sort -u \
    | wc -l \
    | tr -d '[:space:]')"

printf 'Dependency count: %s unique (name, version) pairs\n' "$count"
if [ "$count" -lt "$target" ]; then
    printf 'Within target (<%s): yes\n' "$target"
else
    printf 'Within target (<%s): no\n' "$target"
fi

if [ "$count" -gt "$ceiling" ]; then
    printf 'Within ceiling (<=%s): no\n' "$ceiling"
    exit 1
fi

printf 'Within ceiling (<=%s): yes\n' "$ceiling"
