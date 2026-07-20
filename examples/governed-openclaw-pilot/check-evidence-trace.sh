#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output="${TMPDIR:-/tmp}/erebor-openclaw-evidence-trace-$$.md"
workspace="${TMPDIR:-/tmp}/erebor-openclaw-evidence-trace-work-$$"
registry="$workspace/.erebor/sessions"
trap 'rm -f "$output"; rm -rf "$workspace"' EXIT

cd "$repo_root"
session_id="session-fixture"
session_dir="$registry/$session_id"
audit_path="$session_dir/audit.jsonl"
policy_path="$session_dir/policies/policy.json"
config_path="$session_dir/config.json"
prompt_path="$session_dir/prompt.txt"
mkdir -p "$session_dir/policies"
cp "$repo_root/examples/governed-openclaw-pilot/fixtures/evidence-trace-audit.jsonl" "$audit_path"
cp "$repo_root/examples/governed-openclaw-pilot/policy.json" "$policy_path"
cp "$repo_root/examples/governed-openclaw-pilot/session-config.json" "$config_path"
cp "$repo_root/examples/governed-openclaw-pilot/prompt.txt" "$prompt_path"
cat > "$session_dir/session.json" <<JSON
{
  "schema_version": 1,
  "session_id": "$session_id",
  "status": "succeeded",
  "actor_id": "openclaw",
  "actor_kind": "agent",
  "runner": "linux-host",
  "surfaces": ["terminal", "browser_cdp"],
  "workspace": null,
  "command": ["fixture"],
  "diagnostic": null,
  "registry_path": "$registry",
  "session_dir": "$session_dir",
  "audit_path": "$audit_path",
  "config_artifact_path": "$config_path",
  "source_config_path": null,
  "policy_artifact_paths": ["$policy_path"],
  "source_policy_paths": [],
  "started_at_unix_ms": 1,
  "ended_at_unix_ms": 2,
  "exit_code": 0,
  "failure": null
}
JSON

(
  cd "$workspace"
  cargo run --manifest-path "$repo_root/Cargo.toml" -p erebor-runtime-cli --quiet -- \
    audit evidence-trace \
    "$session_id" \
    --prompt "$prompt_path" \
    --out "$output"
)

require() {
  local needle="$1"
  if ! grep -Fq "$needle" "$output"; then
    echo "missing evidence trace text: $needle" >&2
    echo "report=$output" >&2
    exit 1
  fi
}

require "# Governed OpenClaw Evidence Trace"
require "Session id | session-fixture"
require "No semantic PII classifier enabled"
require "OAuth callback handoff | enforced"
require "deny-oauth-callback-network-request"
require "code=redacted"
require "state=redacted"
require "Artifact Integrity"
require "Audit JSONL"
require "Policy package"
require "Report body"

echo "evidence_trace_check=complete"
