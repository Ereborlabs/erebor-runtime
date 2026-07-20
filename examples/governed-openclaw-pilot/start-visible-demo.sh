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
GITHUB_CLIENT_ID is required for the visible governed OpenClaw demo.

Create a throwaway GitHub OAuth app with callback:
  http://127.0.0.1:5105/oauth/callback

Then run:
  GITHUB_CLIENT_ID=<client-id> bash examples/governed-openclaw-pilot/start-visible-demo.sh

For a local wiring-only rehearsal, set EREBOR_ALLOW_DUMMY_GITHUB_CLIENT_ID=1.
EOF
    exit 2
  fi
fi

for required in cargo curl node openclaw tail; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required for the visible governed OpenClaw demo" >&2
    exit 1
  fi
done

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/erebor-openclaw-visible-demo.XXXXXX")"
lab_pid=""
audit_watch_pid=""
lab_watch_pid=""
started_lab="0"

cleanup() {
  if [[ -n "$audit_watch_pid" ]]; then
    kill "$audit_watch_pid" >/dev/null 2>&1 || true
    wait "$audit_watch_pid" >/dev/null 2>&1 || true
  fi

  if [[ -n "$lab_watch_pid" ]]; then
    kill "$lab_watch_pid" >/dev/null 2>&1 || true
    wait "$lab_watch_pid" >/dev/null 2>&1 || true
  fi

  if [[ "$started_lab" == "1" && -n "$lab_pid" ]] && kill -0 "$lab_pid" 2>/dev/null; then
    kill "$lab_pid" 2>/dev/null || true
    wait "$lab_pid" 2>/dev/null || true
  fi

  if [[ "${EREBOR_KEEP_DEMO_TMP:-0}" != "1" && -d "$tmpdir" && "$tmpdir" == /tmp/erebor-openclaw-visible-demo.* ]]; then
    rm -rf "$tmpdir"
  else
    echo "visible_demo_tmp=$tmpdir"
  fi
}
trap cleanup EXIT

prepare_audit_file() {
  mkdir -p "$(dirname "$audit_path")"
  if [[ "${EREBOR_APPEND_AUDIT:-0}" == "1" ]]; then
    touch "$audit_path"
    echo "visible_demo_audit_mode=append"
  else
    : >"$audit_path"
    echo "visible_demo_audit_mode=fresh"
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

watch_audit() {
  node - "$audit_path" <<'NODE'
const { spawn } = require("node:child_process");
const auditPath = process.argv[2];
const tail = spawn("tail", ["-n", "0", "-F", auditPath], {
  stdio: ["ignore", "pipe", "ignore"],
});

let buffer = "";
tail.stdout.setEncoding("utf8");
tail.stdout.on("data", (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    if (!line.trim()) {
      continue;
    }

    try {
      const record = JSON.parse(line);
      const event = record.event ?? {};
      const payload = event.payload ?? {};
      if (payload.kind !== "process_interception") {
        continue;
      }

      const finalType = record.final_decision?.type ?? "unknown";
      const policyType = record.policy_decision?.type ?? "unknown";
      const command = Array.isArray(payload.command) ? payload.command.join(" ") : payload.argv_summary;
      if (policyType === "mediate" || payload.governed_endpoint) {
        console.log(`[erebor] Chrome launch mediated -> ${payload.governed_endpoint} | ${command}`);
      } else if (finalType === "deny") {
        console.log(`[erebor] process denied -> ${record.final_decision?.reason ?? "no reason"} | ${command}`);
      }
    } catch {
      console.log(`[erebor] audit parse skipped: ${line.slice(0, 160)}`);
    }
  }
});

process.on("SIGTERM", () => {
  tail.kill("SIGTERM");
  process.exit(0);
});
process.on("SIGINT", () => {
  tail.kill("SIGINT");
  process.exit(0);
});
NODE
}

watch_lab() {
  node - "$lab_url" <<'NODE'
const http = require("node:http");

const labUrl = process.argv[2];
let seen = 0;

function fetchEvents() {
  http
    .get(`${labUrl}/events`, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        try {
          const events = JSON.parse(body);
          for (const event of events.slice(seen)) {
            const prefix = event.kind === "oauth_callback_received" ? "[lab:ALERT]" : "[lab]";
            console.log(`${prefix} ${event.kind}`);
          }
          seen = events.length;
        } catch {
          // Keep watching; the lab may be restarting during setup.
        }
      });
    })
    .on("error", () => {});
}

fetchEvents();
setInterval(fetchEvents, 1000);
NODE
}

if curl -fsS "$lab_url/config" -o "$tmpdir/config.json" >/dev/null 2>&1; then
  if [[ "${EREBOR_REUSE_EXISTING_LAB:-0}" != "1" ]]; then
    cat >&2 <<EOF
An OAuth lab is already listening at $lab_url.

Stop that lab and rerun this command so start-visible-demo.sh can start it with
the GITHUB_CLIENT_ID from this shell. To intentionally reuse the existing lab,
set:
  EREBOR_REUSE_EXISTING_LAB=1
EOF
    exit 2
  fi

  echo "visible_demo_lab=reusing_existing"
else
  echo "visible_demo_lab=starting"
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

echo "visible_demo_lab_url=$lab_url"
echo "visible_demo_events_url=$lab_url/events"
echo "visible_demo_client_id_source=$client_id_source"
echo "visible_demo_audit=$audit_path"

watch_audit &
audit_watch_pid="$!"

watch_lab &
lab_watch_pid="$!"

(
  cd "$repo_root"
  EREBOR_OAUTH_LAB_URL="$lab_url" \
    EREBOR_OPENCLAW_PROMPT_FILE="examples/governed-openclaw-pilot/prompt.txt" \
    EREBOR_OPENCLAW_HEADLESS="${EREBOR_OPENCLAW_HEADLESS:-false}" \
    cargo run -p erebor-runtime-cli -- \
      session run \
      --runner linux-host \
      --config examples/governed-openclaw-pilot/session-config.json \
      bash examples/governed-openclaw-pilot/run-openclaw-gateway.sh
)
