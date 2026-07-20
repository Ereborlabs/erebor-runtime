#!/usr/bin/env bash
set -euo pipefail

gateway_port="${EREBOR_OPENCLAW_GATEWAY_PORT:-19123}"
gateway_token="${EREBOR_OPENCLAW_TOKEN:-erebor-pilot-token}"
browser_profile="${EREBOR_OPENCLAW_PROFILE:-openclaw}"
browser_executable="${EREBOR_OPENCLAW_BROWSER_EXECUTABLE:-google-chrome}"
headless="${EREBOR_OPENCLAW_HEADLESS:-true}"
lab_url="${EREBOR_OAUTH_LAB_URL:-http://127.0.0.1:5105}"
prompt_file="${EREBOR_OPENCLAW_PROMPT_FILE:-examples/governed-openclaw-pilot/prompt.txt}"
agent_session_id="${EREBOR_OPENCLAW_AGENT_SESSION_ID:-erebor-oauth-demo-$(date +%Y%m%d%H%M%S)}"
agent_timeout="${EREBOR_OPENCLAW_AGENT_TIMEOUT:-600}"
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

tmp="$(mktemp -d /tmp/erebor-openclaw-agent.XXXXXX)"
gateway_pid=""

cleanup() {
  if [[ -n "$gateway_pid" ]]; then
    kill "$gateway_pid" >/dev/null 2>&1 || true
    wait "$gateway_pid" >/dev/null 2>&1 || true
  fi

  if [[ "${EREBOR_KEEP_OPENCLAW_TMP:-0}" != "1" && -d "$tmp" && "$tmp" == /tmp/erebor-openclaw-agent.* ]]; then
    rm -rf "$tmp"
  else
    echo "agent_tmp=$tmp"
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
    headless: headlessRaw !== "false",
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

echo "agent_config=$OPENCLAW_CONFIG_PATH"
echo "agent_state_dir=$state_dir"
echo "agent_workspace=$workspace_dir"
echo "agent_browser_profile=$browser_profile"
echo "agent_browser_executable_command=$browser_executable_input"
echo "agent_browser_executable_path=$browser_executable"
echo "agent_browser_headless=$headless"
echo "agent_browser_launch=normal_openclaw_chrome_launch_mediated_by_erebor"
echo "agent_lab_url=$lab_url"
echo "agent_interception=$EREBOR_PROCESS_INTERCEPTION"
echo "agent_shim_dir=$EREBOR_PROCESS_INTERCEPTION_SHIM_DIR"
echo "agent_chrome_path_env=${CHROME_PATH:-}"

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

echo "agent_gateway=ready"
echo "agent_session_id=$agent_session_id"
echo "agent_prompt_file=$prompt_file"
echo "agent_step=prompt_openclaw"

openclaw agent \
  --session-id "$agent_session_id" \
  --timeout "$agent_timeout" \
  --message "$prompt_text" \
  --json
