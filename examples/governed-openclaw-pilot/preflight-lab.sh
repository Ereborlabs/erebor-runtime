#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
port="${THREAD_PORT:-5105}"
host="127.0.0.1"
base_url="http://${host}:${port}"
client_id="${GITHUB_CLIENT_ID:-erebor-preflight-client}"
scopes="${GITHUB_OAUTH_SCOPES:-repo read:org workflow delete_repo}"

for required in node curl; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "$required is required for the OAuth lab preflight" >&2
    exit 1
  fi
done

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/erebor-oauth-lab-preflight.XXXXXX")"
lab_pid=""

cleanup() {
  if [[ -n "$lab_pid" ]] && kill -0 "$lab_pid" 2>/dev/null; then
    kill "$lab_pid" 2>/dev/null || true
    wait "$lab_pid" 2>/dev/null || true
  fi

  if [[ -d "$tmpdir" && "$tmpdir" == /tmp/erebor-oauth-lab-preflight.* ]]; then
    rm -rf "$tmpdir"
  fi
}
trap cleanup EXIT

(
  cd "$repo_root"
  THREAD_PORT="$port" \
    GITHUB_CLIENT_ID="$client_id" \
    GITHUB_OAUTH_SCOPES="$scopes" \
    node examples/openclaw-oauth-click-lab/lab.mjs
) >"$tmpdir/lab.log" 2>&1 &
lab_pid=$!

ready=0
for _ in {1..50}; do
  if curl -fsS "$base_url/config" -o "$tmpdir/config.json" >/dev/null 2>&1; then
    ready=1
    break
  fi

  if ! kill -0 "$lab_pid" 2>/dev/null; then
    echo "OAuth lab exited before it became ready:" >&2
    sed -n '1,120p' "$tmpdir/lab.log" >&2
    exit 1
  fi

  sleep 0.1
done

if [[ "$ready" != "1" ]]; then
  echo "OAuth lab did not become ready at $base_url" >&2
  sed -n '1,120p' "$tmpdir/lab.log" >&2
  exit 1
fi

echo "oauth_lab_preflight=config"
node - "$tmpdir/config.json" "$base_url" "$scopes" <<'NODE'
const fs = require("node:fs");

const [configPath, baseUrl, scopes] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (config.baseUrl !== baseUrl) {
  fail(`expected baseUrl ${baseUrl}, got ${config.baseUrl}`);
}
if (config.callbackUrl !== `${baseUrl}/oauth/callback`) {
  fail(`expected callbackUrl ${baseUrl}/oauth/callback, got ${config.callbackUrl}`);
}
if (config.clientIdConfigured !== true) {
  fail("expected clientIdConfigured=true");
}
if (config.requestedScopes !== scopes) {
  fail(`expected scopes ${scopes}, got ${config.requestedScopes}`);
}
console.log("config=ok");
NODE

curl -fsS "$base_url/" -o "$tmpdir/thread.html"
curl -fsS "$base_url/repro" -o "$tmpdir/repro.html"

http_code="$(
  curl -sS \
    -D "$tmpdir/connect.headers" \
    -o "$tmpdir/connect.body" \
    -w "%{http_code}" \
    "$base_url/connect/github"
)"

if [[ "$http_code" != "303" ]]; then
  echo "expected /connect/github to return 303, got $http_code" >&2
  sed -n '1,120p' "$tmpdir/connect.body" >&2
  exit 1
fi

location="$(awk 'tolower($1) == "location:" { sub(/\r$/, ""); print $2; exit }' "$tmpdir/connect.headers")"
if [[ -z "$location" ]]; then
  echo "expected /connect/github to return a Location header" >&2
  sed -n '1,120p' "$tmpdir/connect.headers" >&2
  exit 1
fi

echo "oauth_lab_preflight=authorize_redirect"
state="$(
  node - "$location" "$base_url" "$client_id" "$scopes" <<'NODE'
const [location, baseUrl, clientId, scopes] = process.argv.slice(2);
const authorizeUrl = new URL(location);

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (authorizeUrl.protocol !== "https:") {
  fail(`expected https redirect, got ${authorizeUrl.protocol}`);
}
if (authorizeUrl.host !== "github.com") {
  fail(`expected github.com redirect, got ${authorizeUrl.host}`);
}
if (authorizeUrl.pathname !== "/login/oauth/authorize") {
  fail(`expected /login/oauth/authorize, got ${authorizeUrl.pathname}`);
}
if (authorizeUrl.searchParams.get("client_id") !== clientId) {
  fail("redirect client_id did not match configured lab client id");
}
if (authorizeUrl.searchParams.get("redirect_uri") !== `${baseUrl}/oauth/callback`) {
  fail("redirect callback URL did not match the local lab callback");
}
if (authorizeUrl.searchParams.get("scope") !== scopes) {
  fail(`redirect scopes did not match ${scopes}`);
}

const state = authorizeUrl.searchParams.get("state");
if (!state) {
  fail("redirect did not include OAuth state");
}

console.error("authorize_redirect=ok");
process.stdout.write(state);
NODE
)"

curl -fsS "${base_url}/oauth/callback?code=demo-code&state=${state}" -o "$tmpdir/callback.html"
curl -fsS "$base_url/events" -o "$tmpdir/events.json"

echo "oauth_lab_preflight=events"
node - "$tmpdir/events.json" <<'NODE'
const fs = require("node:fs");

const [eventsPath] = process.argv.slice(2);
const events = JSON.parse(fs.readFileSync(eventsPath, "utf8"));
const expected = [
  "thread_opened",
  "repro_opened",
  "oauth_authorize_redirect_started",
  "oauth_callback_received",
];

function fail(message) {
  console.error(message);
  process.exit(1);
}

let cursor = 0;
for (const event of events) {
  if (event.kind === expected[cursor]) {
    cursor += 1;
  }
}

if (cursor !== expected.length) {
  fail(`missing expected event sequence: ${expected.join(" -> ")}`);
}

const callback = events.find((event) => event.kind === "oauth_callback_received");
if (!callback?.detail?.stateMatches) {
  fail("expected callback event to include stateMatches=true");
}
if (events.some((event) => event.kind === "oauth_callback_probe")) {
  fail("preflight should not record oauth_callback_probe");
}

for (const kind of expected) {
  console.log(`${kind}=ok`);
}
NODE

echo "oauth_lab_preflight=complete"
