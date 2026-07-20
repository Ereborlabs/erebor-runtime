#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
policy="examples/governed-openclaw-pilot/policy.json"

run_case() {
  local name="$1"
  local event="$2"
  local expected_type="$3"
  local expected_rule="$4"

  echo "policy_fixture=${name}"
  output="$(
    cd "$repo_root" && \
      cargo run -p erebor-runtime-cli --quiet -- \
        policy test \
        --policy "$policy" \
        --event "$event"
  )"
  echo "$output"

  if [[ "$output" != *"\"type\":\"${expected_type}\""* ]]; then
    echo "expected decision type ${expected_type} for ${name}" >&2
    exit 1
  fi

  if [[ "$output" != *"\"rule_id\":\"${expected_rule}\""* ]]; then
    echo "expected rule ${expected_rule} for ${name}" >&2
    exit 1
  fi
}

run_case \
  "oauth_lab_navigation_allowed" \
  "examples/governed-openclaw-pilot/fixtures/oauth-lab-navigation-event.json" \
  "allow" \
  "allow-oauth-lab-navigation"

run_case \
  "oauth_lab_click_allowed" \
  "examples/governed-openclaw-pilot/fixtures/oauth-lab-click-event.json" \
  "allow" \
  "allow-oauth-lab-click"

run_case \
  "oauth_authorize_navigation_visible" \
  "examples/governed-openclaw-pilot/fixtures/oauth-authorize-navigation-event.json" \
  "allow" \
  "allow-github-oauth-navigation-visibility"

run_case \
  "oauth_authorize_script_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-authorize-script-event.json" \
  "deny" \
  "deny-github-oauth-authorize-script-action"

run_case \
  "oauth_authorize_click_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-authorize-click-event.json" \
  "deny" \
  "deny-github-oauth-authorize-click"

run_case \
  "oauth_login_return_script_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-login-return-script-event.json" \
  "deny" \
  "deny-github-oauth-login-return-script-action"

run_case \
  "oauth_login_return_click_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-login-return-click-event.json" \
  "deny" \
  "deny-github-oauth-login-return-click"

run_case \
  "oauth_callback_navigation_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-callback-navigation-event.json" \
  "deny" \
  "deny-oauth-callback-navigation"

run_case \
  "oauth_callback_script_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-callback-script-event.json" \
  "deny" \
  "deny-oauth-callback-script-action"

run_case \
  "oauth_callback_click_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-callback-click-event.json" \
  "deny" \
  "deny-oauth-callback-click"

run_case \
  "oauth_callback_network_request_denied" \
  "examples/governed-openclaw-pilot/fixtures/oauth-callback-network-event.json" \
  "deny" \
  "deny-oauth-callback-network-request"

run_case \
  "openclaw_owned_denied_script" \
  "examples/governed-openclaw-pilot/fixtures/openclaw-owned-denied-script-event.json" \
  "deny" \
  "deny-openclaw-owned-denied-script"

echo "policy_fixtures=complete"
