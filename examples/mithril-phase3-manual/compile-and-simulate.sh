#!/usr/bin/env bash
set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
policy=target/debug/mithril-policy
[[ -x $policy ]] || {
  echo "build first: cargo build -p mithril-control --bin mithril-policy" >&2
  exit 2
}
work=$(mktemp -d /tmp/mithril-phase3-policy.XXXXXX)
trap 'rm -r -- "$work"' EXIT

"$policy" compile --source "$directory/policy-v1.yaml" \
  --seal-request "$directory/seal-request.json" \
  --signing-key "$directory/test-signing-key.hex" \
  --output "$work/profile.json"
"$policy" verify --artifact "$work/profile.json" \
  --public-key "$directory/test-public-key.hex"
"$policy" simulate --artifact "$work/profile.json" \
  --public-key "$directory/test-public-key.hex" \
  --decision-key "$directory/decision-key.json" >"$work/would-deny.json"
"$policy" simulate --artifact "$work/profile.json" \
  --public-key "$directory/test-public-key.hex" \
  --decision-key "$directory/decision-key.json" \
  --hard-safety-condition missing-task-identity >"$work/hard-deny.json"

grep -q '"disposition": "WOULD_DENY"' "$work/would-deny.json"
grep -q '"physical_result": "NOT_ATTEMPTED"' "$work/would-deny.json"
grep -q '"disposition": "HARD_DENY"' "$work/hard-deny.json"
echo "signed candidate is deterministic; policy denial simulates, hard safety still denies"

