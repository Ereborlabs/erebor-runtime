#!/usr/bin/env bash
set -euo pipefail

gateway_port="${EREBOR_OPENCLAW_GATEWAY_PORT:-19123}"
gateway_token="${EREBOR_OPENCLAW_TOKEN:-erebor-pilot-token}"
browser_profile="${EREBOR_OPENCLAW_PROFILE:-openclaw}"
browser_executable="${EREBOR_OPENCLAW_BROWSER_EXECUTABLE:-google-chrome}"
headless="${EREBOR_OPENCLAW_HEADLESS:-false}"
lab_url="${EREBOR_OAUTH_LAB_URL:-http://127.0.0.1:5105}"
prompt_file="${EREBOR_OPENCLAW_PROMPT_FILE:-examples/governed-openclaw-pilot/prompt.txt}"
model_primary="${EREBOR_OPENCLAW_MODEL:-github-copilot/claude-sonnet-4.6}"
workspace_dir="${EREBOR_OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}"
state_dir="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"

if [[ -z "${EREBOR_PROCESS_INTERCEPTION:-}" ]]; then
  echo "EREBOR_PROCESS_INTERCEPTION is not set. Run this through session-config.json." >&2
  exit 2
fi

if [[ -z "${EREBOR_PROCESS_INTERCEPTION_SHIM_DIR:-}" ]]; then
  echo "EREBOR_PROCESS_INTERCEPTION_SHIM_DIR is not set. Browser launch shims were not injected." >&2
  exit 2
fi

if [[ ! -f "$prompt_file" ]]; then
  echo "OpenClaw prompt file not found: $prompt_file" >&2
  exit 1
fi
prompt_text="$(<"$prompt_file")"

for required in curl node openclaw; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required inside the governed OpenClaw session" >&2
    exit 1
  fi
done

browser_executable_input="$browser_executable"
if [[ "$browser_executable" != */* ]]; then
  browser_executable="$(command -v "$browser_executable" || true)"
fi

if [[ -z "$browser_executable" ]]; then
  browser_executable="${EREBOR_PROCESS_INTERCEPTION_SHIM_DIR}/google-chrome"
fi

if [[ ! -x "$browser_executable" ]]; then
  echo "OpenClaw browser executable is not executable: $browser_executable" >&2
  echo "Set EREBOR_OPENCLAW_BROWSER_EXECUTABLE to an executable Chrome/Chromium path." >&2
  exit 1
fi

curl -fsS "${lab_url}/config" >/dev/null

tmp="$(mktemp -d /tmp/erebor-openclaw-gateway.XXXXXX)"
gateway_pid=""

cleanup() {
  if [[ -n "$gateway_pid" ]]; then
    kill "$gateway_pid" >/dev/null 2>&1 || true
    wait "$gateway_pid" >/dev/null 2>&1 || true
  fi

  if [[ "${EREBOR_KEEP_OPENCLAW_TMP:-0}" != "1" && -d "$tmp" && "$tmp" == /tmp/erebor-openclaw-gateway.* ]]; then
    rm -rf "$tmp"
  else
    echo "openclaw_tmp=$tmp"
  fi
}
trap cleanup EXIT

export OPENCLAW_CONFIG_PATH="$tmp/openclaw.json"
export OPENCLAW_STATE_DIR="$state_dir"
mkdir -p "$workspace_dir" "$state_dir"

node - \
  "$OPENCLAW_CONFIG_PATH" \
  "$gateway_port" \
  "$gateway_token" \
  "$browser_profile" \
  "$browser_executable" \
  "$headless" \
  "$workspace_dir" \
  "$model_primary" <<'NODE'
const fs = require("node:fs");

const [
  configPath,
  gatewayPortRaw,
  gatewayToken,
  browserProfile,
  browserExecutable,
  headlessRaw,
  workspaceDir,
  modelPrimary,
] = process.argv.slice(2);

const model = modelPrimary || "github-copilot/claude-sonnet-4.6";
const config = {
  agents: {
    defaults: {
      model: {
        primary: model,
      },
      models: {
        [model]: {},
      },
      workspace: workspaceDir,
    },
  },
  gateway: {
    mode: "local",
    bind: "loopback",
    port: Number.parseInt(gatewayPortRaw, 10),
    auth: {
      mode: "token",
      token: gatewayToken,
    },
  },
  browser: {
    enabled: true,
    defaultProfile: browserProfile,
    executablePath: browserExecutable,
    headless: headlessRaw === "true",
    ssrfPolicy: {
      dangerouslyAllowPrivateNetwork: true,
    },
  },
  plugins: {
    entries: {
      "github-copilot": {
        enabled: true,
        config: {},
      },
      browser: {
        enabled: true,
        config: {},
      },
      "memory-core": {
        enabled: true,
        config: {},
      },
    },
  },
  auth: {
    profiles: {
      "github-copilot:github": {
        provider: "github-copilot",
        mode: "token",
      },
    },
  },
};

fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
NODE

echo "openclaw_config=$OPENCLAW_CONFIG_PATH"
echo "openclaw_state_dir=$state_dir"
echo "openclaw_workspace=$workspace_dir"
echo "openclaw_browser_profile=$browser_profile"
echo "openclaw_browser_executable_command=$browser_executable_input"
echo "openclaw_browser_executable_path=$browser_executable"
echo "openclaw_browser_headless=$headless"
echo "openclaw_browser_launch=normal_openclaw_chrome_launch_mediated_by_erebor"
echo "openclaw_lab_url=$lab_url"
echo "openclaw_interception=$EREBOR_PROCESS_INTERCEPTION"
echo "openclaw_shim_dir=$EREBOR_PROCESS_INTERCEPTION_SHIM_DIR"
echo "openclaw_chrome_path_env=${CHROME_PATH:-}"

openclaw config validate

openclaw gateway run \
  --auth token \
  --token "$gateway_token" \
  --bind loopback \
  --port "$gateway_port" \
  --compact >"$tmp/gateway.log" 2>&1 &
gateway_pid="$!"

gateway_ready() {
  [[ -f "$tmp/gateway.log" ]] && [[ "$(<"$tmp/gateway.log")" == *"[gateway] ready"* ]]
}

for _ in {1..100}; do
  if ! kill -0 "$gateway_pid" >/dev/null 2>&1; then
    echo "OpenClaw gateway exited before becoming ready." >&2
    cat "$tmp/gateway.log" >&2 || true
    exit 1
  fi

  if gateway_ready; then
    break
  fi

  sleep 0.25
done

if ! gateway_ready; then
  echo "OpenClaw gateway did not become healthy." >&2
  cat "$tmp/gateway.log" >&2 || true
  exit 1
fi

dashboard_url="http://127.0.0.1:${gateway_port}/#token=${gateway_token}"

cat <<EOF

openclaw_gateway=ready
openclaw_dashboard_url=$dashboard_url
openclaw_gateway_token=$gateway_token

Paste this prompt into the OpenClaw Control UI chat:

--- prompt begin ---
$prompt_text
--- prompt end ---

Keep this terminal running while you demo. Press Ctrl-C here to stop the
governed OpenClaw gateway and the Erebor session.
EOF

wait "$gateway_pid"
