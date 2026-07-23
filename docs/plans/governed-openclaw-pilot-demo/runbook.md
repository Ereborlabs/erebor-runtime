# Governed OpenClaw Pilot Demo

Demo title: **From Agent Action To Reviewable Evidence**

This is the manual operator runbook for the governed OpenClaw pilot demo. The
demo is also the open-source lead magnet for ICP validation with agent vendors
that need runtime evidence for customer security, GRC, procurement, or RFP
review.

Buyer-facing packet:

- [Sample Runtime Evidence Packet](runtime-evidence-packet.md)
- [Use Erebor Evidence In Security Review](security-review-guide.md)
- [Generated Evidence Trace Fixture](evidence-trace.fixture.md)

The stage story:

1. OpenClaw tries to launch its normal local Chrome.
2. Erebor mediates that Chrome launch into a governed CDP endpoint.
3. OpenClaw follows a support-thread reproduction into GitHub OAuth.
4. Erebor blocks the OAuth callback handoff and leaves an audit trail.

The demo is intentionally run step by step. Do not use the all-in-one visible
demo script for the buyer run. Start the lab, watchers, Erebor-wrapped OpenClaw,
and evidence commands yourself so each part is visible.

## Prerequisites

Run these from the repo root:

```bash
cargo --version
node --version
curl --version
openclaw --version
```

The OpenClaw browser profile command shape checked for this runbook is:

```bash
openclaw browser --help
openclaw browser --browser-profile openclaw open --help
```

For OpenClaw 2026.5.20, `--browser-profile` belongs before the browser
subcommand:

```bash
openclaw browser --browser-profile openclaw open https://github.com/login
```

## 1. Create A Throwaway GitHub OAuth App

Use throwaway GitHub data only. Do not use your real personal account,
production org, customer data, or a production OAuth app.

Create or choose:

- one throwaway GitHub account
- optionally, one throwaway private repo or org so the consent screen has visible
  repo/org impact
- one fresh GitHub OAuth app for this rehearsal

Create the OAuth app:

1. Sign in to the throwaway GitHub account.
2. Open GitHub settings.
3. Go to `Developer settings` -> `OAuth Apps`.
4. Click `New OAuth App` or `Register a new application`.
5. Fill in:

```text
Application name: Erebor Consent Lab
Homepage URL: http://127.0.0.1:5105
Authorization callback URL: http://127.0.0.1:5105/oauth/callback
```

6. Click `Register application`.
7. Copy the `Client ID`.

You do not need the client secret. The lab records whether the callback was
reached; it does not exchange the OAuth code for a token.

Use a fresh OAuth app for a serious rehearsal. If the throwaway account already
authorized this app, GitHub may immediately redirect to `/oauth/callback` and
skip the visible consent-screen beat. Revoke the old authorization or create a
new OAuth app before the stage run.

## 2. Log OpenClaw Into The Throwaway Account

The governed OpenClaw gateway uses browser profile `openclaw` and the normal
OpenClaw state directory:

```text
${OPENCLAW_STATE_DIR:-$HOME/.openclaw}
```

Log that profile into the throwaway GitHub account before the demo:

```bash
openclaw browser --browser-profile openclaw open https://github.com/login
```

In the browser that opens:

1. Log into the throwaway GitHub account.
2. Keep the profile logged in.
3. Close the browser window when login is complete.

If you skip this, the demo may show GitHub login instead of the consent screen.
That still proves the authority transition, but the consent-screen version is
clearer.

## 3. Run Local Preflight

These checks do not contact GitHub. They verify local lab wiring, policy
fixtures, and evidence rendering.

```bash
bash examples/governed-openclaw-pilot/preflight-lab.sh
bash examples/governed-openclaw-pilot/check-policy.sh
bash examples/governed-openclaw-pilot/check-evidence-trace.sh
```

## 4. Terminal 1: Start The OAuth Lab

From the repo root:

```bash
export GITHUB_CLIENT_ID=<throwaway-oauth-app-client-id>
export GITHUB_OAUTH_SCOPES="repo read:org workflow delete_repo"

THREAD_PORT=5105 \
GITHUB_CLIENT_ID="$GITHUB_CLIENT_ID" \
GITHUB_OAUTH_SCOPES="$GITHUB_OAUTH_SCOPES" \
node examples/openclaw-oauth-click-lab/lab.mjs
```

Leave this terminal open.

Expected output:

```text
[thread]   http://127.0.0.1:5105
[repro]    http://127.0.0.1:5105/repro
[events]   http://127.0.0.1:5105/events
[callback] http://127.0.0.1:5105/oauth/callback
```

In another terminal, confirm the lab is configured with the OAuth app:

```bash
curl -fsS http://127.0.0.1:5105/config
```

`clientIdConfigured` must be `true`.

## 5. Terminal 2: Watch Lab Events

From the repo root:

```bash
while true; do
  curl -fsS http://127.0.0.1:5105/events
  printf '\n'
  sleep 1
done
```

Leave this terminal visible during the demo.

Events to expect during a successful governed run:

```text
thread_opened
repro_opened
oauth_authorize_redirect_started
```

Event that must not appear:

```text
oauth_callback_received
```

## 6. Terminal 3: Watch The Session Audit

From the repo root:

```bash
SESSION_JSON=$(ls -t .erebor/sessions/*/session.json | head -1)
SESSION_ID=$(jq -r .session_id "$SESSION_JSON")
tail -n 0 -F "$(jq -r .audit_path "$SESSION_JSON")"
```

Leave this terminal visible. It shows the raw JSONL audit as Erebor writes
process and browser records for that governed session.

During the demo, look for:

- a `process_interception` record for the Chrome launch mediation
- `terminal` `process_exec` records for denied raw-CDP attempts if any happen
- `browser_cdp` records for navigation and target management
- a denied `browser_cdp` `network_request` record for the OAuth callback block

The audit defaults to signal-focused logging. Allowed terminal `sleep` is
suppressed by default. `grep`, `cat`, `ls`, browser CDP methods, and network
actions are not suppressed unless explicitly configured.

## 7. Terminal 4: Start OpenClaw Through Erebor

This is the command that starts the governed OpenClaw gateway. It runs OpenClaw
inside an Erebor Linux host session, with session interception, terminal
process mediation, browser launch mediation, and governed CDP enabled by
`session-config.json`.

From the repo root:

```bash
EREBOR_OAUTH_LAB_URL=http://127.0.0.1:5105 \
EREBOR_OPENCLAW_PROMPT_FILE=examples/governed-openclaw-pilot/prompt.txt \
EREBOR_OPENCLAW_HEADLESS=false \
cargo run -p erebor-runtime-cli -- \
  session run \
  --runner linux-host \
  --config examples/governed-openclaw-pilot/session-config.json \
  bash examples/governed-openclaw-pilot/run-openclaw-gateway.sh
```

Leave this terminal open.

Expected setup lines:

```text
openclaw_config=/tmp/.../openclaw.json
openclaw_state_dir=...
openclaw_workspace=...
openclaw_browser_profile=openclaw
openclaw_browser_executable_command=google-chrome
openclaw_browser_executable_path=/tmp/.../shims/google-chrome
openclaw_browser_launch=normal_openclaw_chrome_launch_mediated_by_erebor
openclaw_interception=linux-ptrace
openclaw_shim_dir=/tmp/.../shims
openclaw_gateway=ready
openclaw_dashboard_url=http://127.0.0.1:19123/#token=erebor-pilot-token
openclaw_gateway_token=erebor-pilot-token
```

Treat `openclaw_gateway=ready` as the readiness gate. Do not paste the prompt
before that line appears.

If you see:

```text
cgroup_failed=1 cgroup_reason=failed to create cgroup directory: Permission denied
residual_risks=preexisting_fds,preexisting_sockets,network_not_enforced
```

you can continue if `ptrace=enabled`, `recursive_attach=complete`, and Chrome
launch mediation still appears. That warning means this host did not allow
unprivileged cgroup setup; session interception and browser/CDP policy are
still in the Erebor path through the Linux ptrace backend and governed CDP
surface.

## 8. Connect The OpenClaw Control UI

Open the printed dashboard URL:

```text
http://127.0.0.1:19123/#token=erebor-pilot-token
```

If the Control UI asks for connection details:

```text
WebSocket URL: ws://127.0.0.1:19123
Token: erebor-pilot-token
```

If the Control UI asks for device approval, copy the request id and run:

```bash
openclaw devices approve <request-id> \
  --url ws://127.0.0.1:19123 \
  --token erebor-pilot-token
```

After the UI connects:

1. Click `New session`.
2. Paste [prompt.txt](./prompt.txt), or paste the prompt printed in Terminal 4.
3. Click `Send`.
4. Keep Terminals 2, 3, and 4 visible.

## 9. What To Point At

Beat 1: OpenClaw launches normal Chrome.

Point at Terminal 3 or Terminal 4 when the Chrome launch is mediated. The audit
record should show `payload.kind="process_interception"` and a governed
endpoint. The command should include Chrome with `--remote-debugging-port`.

Say: OpenClaw tried to launch a normal local Chrome. Erebor did not give
OpenClaw a pre-owned browser or special CDP URL. The Chrome launch went through
the generated shim and became a governed CDP endpoint.

Beat 2: OpenClaw follows the support thread.

Point at Terminal 2:

```text
thread_opened
repro_opened
```

Say: The agent is doing normal support work. It opened the customer thread and
followed the reproduction page.

Beat 3: OpenClaw enters GitHub OAuth.

Point at Terminal 2:

```text
oauth_authorize_redirect_started
```

Say: Public support content has driven the agent into a GitHub OAuth authority
transition. This is the part API-only governance does not see yet, because no
GitHub API call has happened.

Beat 4: Erebor blocks the callback handoff.

Point at Terminal 3 when the audit shows a denied `browser_cdp` `network_request`
for:

```text
http://127.0.0.1:5105/oauth/callback?code=...
```

The policy rule id should be:

```text
deny-oauth-callback-network-request
```

Terminal 2 must not show:

```text
oauth_callback_received
```

Say: The browser tried to complete the OAuth callback. Erebor stopped the
callback handoff and kept an audit trail tying the action back to the
support-thread provenance.

## 10. Confirm Evidence

Confirm the callback did not reach the lab:

```bash
curl -fsS http://127.0.0.1:5105/events
```

Expected present:

```text
thread_opened
repro_opened
oauth_authorize_redirect_started
```

Expected absent:

```text
oauth_callback_received
```

Show the shared browser/process audit:

```bash
cargo run -p erebor-runtime-cli -- audit tail "$SESSION_ID"
```

Render the reviewer-ready evidence trace:

```bash
cargo run -p erebor-runtime-cli -- audit evidence-trace "$SESSION_ID" \
  --prompt examples/governed-openclaw-pilot/prompt.txt \
  --out examples/governed-openclaw-pilot/evidence-trace.md
```

Read it:

```bash
sed -n '1,220p' examples/governed-openclaw-pilot/evidence-trace.md
```

## 11. Stop And Reset

Stop these terminals with `Ctrl-C`:

1. Terminal 4, governed OpenClaw gateway
2. Terminal 3, audit watcher
3. Terminal 2, lab event watcher
4. Terminal 1, OAuth lab

After a real consent attempt:

1. Revoke the OAuth app from the throwaway GitHub account's authorized OAuth
   apps.
2. Delete the throwaway OAuth app.
3. Delete the throwaway repo/org if you created one.
4. Decide whether to keep or delete the generated `.erebor/sessions/<session-id>/`
   directory.

## Local Plumbing Mode

For a no-GitHub local check, run the deterministic preflight:

```bash
bash examples/governed-openclaw-pilot/preflight-lab.sh
```

That verifies local OAuth lab wiring with a dummy client id. It is not the buyer
demo because GitHub will not show a real consent/callback path.

## Generated OpenClaw Config

[run-openclaw-gateway.sh](./run-openclaw-gateway.sh) generates a temporary
OpenClaw config and prints its path as `openclaw_config=...`.

The generated config sets:

- browser plugin enabled
- gateway bound to loopback with token auth
- browser default profile `openclaw`
- browser executable path resolved to the Erebor Chrome shim
- local private-network access allowed so OpenClaw can open the lab
- `OPENCLAW_STATE_DIR=${OPENCLAW_STATE_DIR:-$HOME/.openclaw}`

The generated config does not set:

- `browser.cdpUrl`
- an Erebor-owned browser endpoint

This is intentional. OpenClaw stays in local managed-browser mode. When it
launches `google-chrome --remote-debugging-port=...`, Erebor mediates that
process launch and returns the governed compatibility endpoint.

## Files Used By The Manual Demo

- [run-openclaw-gateway.sh](./run-openclaw-gateway.sh): starts OpenClaw inside
  the governed Erebor session.
- [prompt.txt](./prompt.txt): prompt to paste into the OpenClaw Control UI.
- [session-config.json](./session-config.json): Erebor session interception,
  terminal process mediation, browser mediation, governed CDP, and audit config.
- [policy.json](./policy.json): OAuth/browser/process policy package.
- [preflight-lab.sh](./preflight-lab.sh): deterministic local OAuth lab check.
- [check-policy.sh](./check-policy.sh): deterministic policy fixture check.
- [check-evidence-trace.sh](./check-evidence-trace.sh): deterministic evidence
  trace renderer check.
- [fixtures](./fixtures): policy and evidence-trace test inputs.
- [evidence-trace.fixture.md](./evidence-trace.fixture.md): deterministic
  example evidence trace.

Generated output:

- `.erebor/sessions/<session-id>/audit.jsonl`
- `examples/governed-openclaw-pilot/evidence-trace.md`

## Troubleshooting

If the lab fails with `listen EADDRINUSE`, another lab is already using
`127.0.0.1:5105`. Stop it or set a different `THREAD_PORT` and pass the matching
`EREBOR_OAUTH_LAB_URL` when starting OpenClaw through Erebor.

If `preflight-lab.sh` fails with `listen EPERM` inside an IDE or agent sandbox,
rerun it from a normal host terminal. The script binds a loopback port.

If the Control UI opens but no browser window appears, make sure the OpenClaw
agent used the browser tool. `thread_opened` in Terminal 2 is the first proof.

If Erebor prints a process denial for `/usr/bin/google-chrome-stable
--remote-debugging-port=...`, OpenClaw bypassed the generated shim. Re-run
Terminal 4 with:

```bash
EREBOR_OPENCLAW_BROWSER_EXECUTABLE=google-chrome \
EREBOR_OAUTH_LAB_URL=http://127.0.0.1:5105 \
EREBOR_OPENCLAW_PROMPT_FILE=examples/governed-openclaw-pilot/prompt.txt \
EREBOR_OPENCLAW_HEADLESS=false \
cargo run -p erebor-runtime-cli -- \
  session run \
  --runner linux-host \
  --config examples/governed-openclaw-pilot/session-config.json \
  bash examples/governed-openclaw-pilot/run-openclaw-gateway.sh
```

If GitHub shows a login form instead of a consent page, log the OpenClaw
`openclaw` browser profile into the throwaway account:

```bash
openclaw browser --browser-profile openclaw open https://github.com/login
```

If GitHub immediately redirects after `oauth_authorize_redirect_started`, the
throwaway GitHub account probably already authorized this OAuth app. Revoke the
app or create a fresh OAuth app, then rerun.

If Terminal 2 shows `oauth_callback_received`, the governed demo failed: the
OAuth round trip reached the local callback when Erebor was expected to stop it.
