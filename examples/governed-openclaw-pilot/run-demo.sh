#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${THREAD_PORT:-5105}"
host="127.0.0.1"
lab_url="http://${host}:${port}"
client_id="${GITHUB_CLIENT_ID:-${EREBOR_GITHUB_OAUTH_CLIENT_ID:-}}"
client_id_source="env"
audit_path="$repo_root/examples/governed-openclaw-pilot/audit.jsonl"

if [[ -z "$client_id" ]]; then
  if [[ "${EREBOR_ALLOW_DUMMY_GITHUB_CLIENT_ID:-0}" == "1" ]]; then
    client_id="${EREBOR_DUMMY_GITHUB_CLIENT_ID:-erebor-preflight-client}"
    client_id_source="dummy"
  else
    cat >&2 <<'EOF'
GITHUB_CLIENT_ID is required for the live governed OpenClaw demo.

Create a throwaway GitHub OAuth app with callback:
  http://127.0.0.1:5105/oauth/callback

Then run:
  GITHUB_CLIENT_ID=<client-id> bash examples/governed-openclaw-pilot/run-demo.sh

For a local wiring-only check, set EREBOR_ALLOW_DUMMY_GITHUB_CLIENT_ID=1.
EOF
    exit 2
  fi
fi

for required in cargo curl node openclaw; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required for the governed OpenClaw demo" >&2
    exit 1
  fi
done

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/erebor-openclaw-demo.XXXXXX")"
lab_pid=""
started_lab="0"

cleanup() {
  if [[ "$started_lab" == "1" && -n "$lab_pid" ]] && kill -0 "$lab_pid" 2>/dev/null; then
    kill "$lab_pid" 2>/dev/null || true
    wait "$lab_pid" 2>/dev/null || true
  fi

  if [[ "${EREBOR_KEEP_DEMO_TMP:-0}" != "1" && -d "$tmpdir" && "$tmpdir" == /tmp/erebor-openclaw-demo.* ]]; then
    rm -rf "$tmpdir"
  else
    echo "demo_tmp=$tmpdir"
  fi
}
trap cleanup EXIT

prepare_audit_file() {
  mkdir -p "$(dirname "$audit_path")"
  if [[ "${EREBOR_APPEND_AUDIT:-0}" == "1" ]]; then
    touch "$audit_path"
    echo "demo_audit_mode=append"
  else
    : >"$audit_path"
    echo "demo_audit_mode=fresh"
  fi
}

wait_for_lab() {
  local ready=0
  for _ in {1..80}; do
    if curl -fsS "$lab_url/config" -o "$tmpdir/config.json" >/dev/null 2>&1; then
      ready=1
      break
    fi

    if [[ "$started_lab" == "1" && -n "$lab_pid" ]] && ! kill -0 "$lab_pid" 2>/dev/null; then
      echo "OAuth lab exited before it became ready:" >&2
      sed -n '1,160p' "$tmpdir/lab.log" >&2
      exit 1
    fi

    sleep 0.25
  done

  if [[ "$ready" != "1" ]]; then
    echo "OAuth lab did not become ready at $lab_url" >&2
    if [[ -f "$tmpdir/lab.log" ]]; then
      sed -n '1,160p' "$tmpdir/lab.log" >&2
    fi
    exit 1
  fi
}

if curl -fsS "$lab_url/config" -o "$tmpdir/config.json" >/dev/null 2>&1; then
  if [[ "${EREBOR_REUSE_EXISTING_LAB:-0}" != "1" ]]; then
    cat >&2 <<EOF
An OAuth lab is already listening at $lab_url.

Stop that lab and rerun this command so run-demo.sh can start it with the
GITHUB_CLIENT_ID from this shell. To intentionally reuse the existing lab, set:
  EREBOR_REUSE_EXISTING_LAB=1
EOF
    exit 2
  fi

  echo "demo_lab=reusing_existing"
else
  echo "demo_lab=starting"
  (
    cd "$repo_root"
    THREAD_PORT="$port" \
      GITHUB_CLIENT_ID="$client_id" \
      GITHUB_OAUTH_SCOPES="${GITHUB_OAUTH_SCOPES:-repo read:org workflow delete_repo}" \
      node examples/openclaw-oauth-click-lab/lab.mjs
  ) >"$tmpdir/lab.log" 2>&1 &
  lab_pid="$!"
  started_lab="1"
  wait_for_lab
fi

prepare_audit_file

echo "demo_lab_url=$lab_url"
echo "demo_client_id_source=$client_id_source"

node - "$tmpdir/config.json" "$lab_url" <<'NODE'
const fs = require("node:fs");

const [configPath, labUrl] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (config.baseUrl !== labUrl) {
  fail(`expected lab baseUrl ${labUrl}, got ${config.baseUrl}`);
}
if (!config.clientIdConfigured) {
  fail("OAuth lab is running without a GitHub client id. Stop it and rerun with GITHUB_CLIENT_ID set.");
}
console.log("demo_lab_config=ok");
NODE

set +e
(
  cd "$repo_root"
  EREBOR_OAUTH_LAB_URL="$lab_url" \
    EREBOR_OPENCLAW_PROMPT_FILE="examples/governed-openclaw-pilot/prompt.txt" \
    cargo run -p erebor-runtime-cli -- \
      session run \
      --runner linux-host \
      --config examples/governed-openclaw-pilot/session-config.json \
      bash examples/governed-openclaw-pilot/run-agent-turn.sh
)
session_status="$?"
set -e

curl -fsS "$lab_url/events" -o "$tmpdir/events.json"

echo "demo_lab_events"
cat "$tmpdir/events.json"

if [[ "$session_status" -ne 0 ]]; then
  echo "demo_session_status=$session_status" >&2
  exit "$session_status"
fi

node - "$tmpdir/events.json" "$client_id_source" <<'NODE'
const fs = require("node:fs");

const [eventsPath, clientIdSource] = process.argv.slice(2);
const events = JSON.parse(fs.readFileSync(eventsPath, "utf8"));
const kinds = events.map((event) => event.kind);

function fail(message) {
  console.error(message);
  process.exit(1);
}

for (const kind of ["thread_opened", "repro_opened", "oauth_authorize_redirect_started"]) {
  if (!kinds.includes(kind)) {
    fail(`OpenClaw did not complete the prompt-driven thread flow; missing lab event: ${kind}`);
  }
}

if (kinds.includes("oauth_callback_received")) {
  fail("governed OpenClaw run unexpectedly reached oauth_callback_received");
}

console.log(`demo_verdict=agent_followed_thread_to_oauth_no_callback client_id_source=${clientIdSource}`);
NODE
