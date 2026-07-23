# Live Lifecycle Probe

Status: Required for runtime/session-touching phases in this plan.

## Purpose

Prove an ownership/module cleanup did not merely pass Rust tests. Any phase
touching runtime startup, session execution, terminal/process mediation, CDP
ownership, audit recording, or CLI session wiring must prove the runtime still
starts and governs a real Linux-host session.

This probe exercises:

- CLI parsing
- runtime config loading
- policy loading
- Linux-host session runner startup
- session interception backend startup
- Linux ptrace process guard connection
- runtime interception broker routing
- allowed process execution
- denied process execution
- session registry and audit artifact writes

## Host Requirement

This probe requires a Linux host that can run the Linux ptrace process guard. If
the host blocks ptrace/session execution, the phase is blocked until the probe
can run on a compatible host.

Do not replace this probe with unit tests.

## Probe Script

Run from the repository root after the phase's compile/test checkpoint:

```sh
set -eu

probe_dir="$(mktemp -d /tmp/erebor-ownership-lifecycle.XXXXXX)"

cat >"$probe_dir/policy.json" <<'JSON'
{
  "rules": [
    {
      "id": "deny-raw-cdp",
      "match": {
        "surface": "terminal",
        "action": "process_exec",
        "command_contains": "remote-debugging-port"
      },
      "decision": "deny",
      "reason": "raw CDP process launch is denied"
    }
  ]
}
JSON

cat >"$probe_dir/config.json" <<JSON
{
  "policies": ["$probe_dir/policy.json"],
  "session": {
    "enabled": true,
    "actor": { "id": "ownership-cleanup-probe", "kind": "agent" },
    "workspace": "$probe_dir",
    "runner": { "kind": "linux_host" },
    "interception": { "enabled": true }
  },
  "surfaces": {
    "terminal": { "enabled": true }
  }
}
JSON

allowed_output="$(
  cargo run -p erebor-runtime-cli -- \
    session run \
    --runner linux-host \
    --config "$probe_dir/config.json" \
    -- sh -lc 'echo erebor-lifecycle-allowed'
)"

printf '%s\n' "$allowed_output" | rg 'erebor-lifecycle-allowed'
test -d "$probe_dir/.erebor/sessions"

set +e
denied_output="$(
  cargo run -p erebor-runtime-cli -- \
    session run \
    --runner linux-host \
    --config "$probe_dir/config.json" \
    -- sh --remote-debugging-port=9222 2>&1
)"
denied_status=$?
set -e

test "$denied_status" -ne 0
printf '%s\n' "$denied_output" | rg 'deny|denied|DiagnosticFailed|command failed'
rg -n '"type":"deny"' "$probe_dir/.erebor/sessions"
rg -n 'deny-raw-cdp' "$probe_dir/.erebor/sessions"

printf 'probe workspace: %s\n' "$probe_dir"
```

## Required Result

- The allowed session prints `erebor-lifecycle-allowed`.
- The session registry directory exists under the probe workspace.
- The denied session exits non-zero.
- Session audit artifacts contain a deny record.
- Session audit artifacts contain `deny-raw-cdp`.

## Reporting

For every runtime/session-touching phase, report:

- whether the allowed command succeeded
- whether the denied command failed closed
- where the probe workspace was created
- whether audit evidence contained both `"type":"deny"` and `deny-raw-cdp`
- any host-level ptrace/session error, verbatim, if the probe is blocked
