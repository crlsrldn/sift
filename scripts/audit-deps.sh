#!/usr/bin/env bash
#
# Dependency audit gate — enforcement for PRD G4 ("no network access, no
# telemetry") and technical spec §2 ("a dependency audit gate in CI fails the
# build if a transitive network dependency appears").
#
# The PRD's promise that `sift` makes zero outbound connections is only credible
# if it is mechanically enforced. A comment in Cargo.toml is not enforcement; a
# CI job that fails the build is. This script is that job.
#
# Scope: normal (non-dev) dependency edges only. Dev-dependencies do not ship in
# the released binary, so a test helper pulling in a socket library is not a
# violation of the shipped artifact's guarantee.
#
# Usage: scripts/audit-deps.sh
# Exit:  0 clean, 1 violation found.

set -euo pipefail

# Crates that provide, or exist to provide, outbound network capability or a TLS
# stack. Matched on exact crate name.
#
# `socket2` and `mio` are included deliberately: neither speaks a protocol on its
# own, but neither has any business in a tool that opens no sockets, so their
# appearance means something upstream started doing networking.
BANNED=(
  # HTTP clients and servers
  reqwest hyper hyper-util h2 http-body isahc surf ureq attohttpc curl curl-sys
  # Async runtimes with network capability
  tokio async-std smol
  # TLS stacks
  rustls native-tls openssl openssl-sys boring boring-sys schannel
  rustls-webpki webpki tokio-rustls tokio-native-tls
  # Sockets and DNS
  socket2 mio hickory-resolver hickory-proto trust-dns-resolver trust-dns-proto
  # Telemetry
  opentelemetry sentry
)

echo "Auditing normal dependency edges for network and TLS crates..."

# macOS ships bash 3.2, so no `mapfile` and no associative arrays. Temp files
# and `grep -Fx -f` keep this portable to the system bash on both a developer's
# Mac and the CI runner.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# One crate name per line. --edges normal excludes dev- and build-dependencies;
# --no-dedupe ensures a crate reachable only via a deduped path is still listed.
cargo tree --edges normal --prefix none --no-dedupe 2>/dev/null \
  | awk 'NF {print $1}' \
  | sed 's/[[:space:]]*$//' \
  | sort -u > "$tmp/present"

printf '%s\n' "${BANNED[@]}" | sort -u > "$tmp/banned"

count="$(wc -l < "$tmp/present" | tr -d ' ')"
if [ "$count" -eq 0 ]; then
  echo "ERROR: dependency tree came back empty; refusing to report a clean audit." >&2
  exit 1
fi

# -x anchors to the whole line so `http-body` never matches `http-body-util`.
grep -Fx -f "$tmp/banned" "$tmp/present" > "$tmp/violations" || true

echo "Scanned $count crates in the normal dependency graph."

if [ -s "$tmp/violations" ]; then
  echo >&2
  echo "DEPENDENCY AUDIT FAILED — G4 violation" >&2
  echo >&2
  echo "These crates provide network or TLS capability and must not appear in" >&2
  echo "sift's shipped dependency graph:" >&2
  echo >&2
  while IFS= read -r v; do
    echo "  - $v" >&2
    cargo tree --edges normal --invert "$v" 2>/dev/null | head -12 | sed 's/^/      /' >&2
    echo >&2
  done < "$tmp/violations"
  echo "Either drop the dependency that pulls this in, or disable the feature" >&2
  echo "responsible. If a crate here is genuinely inert, removing it from the" >&2
  echo "BANNED list requires justifying that in the PR — the whole point of this" >&2
  echo "gate is that the exception is visible." >&2
  exit 1
fi

echo "PASS — no network or TLS crates in the shipped dependency graph."
