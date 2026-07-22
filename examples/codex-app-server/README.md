# Daemon-Owned Codex

This is the Phase 4 public workflow for a real locally installed Codex
executable. `erebor` is only a client: `erebord` verifies the executable,
creates the governed session, owns the child process and I/O, and preserves
the session's output and evidence.

There is deliberately no `runtime.json`, raw executable argv, `sudo env`, or
client-selected `CODEX_HOME` in this example. Those were the retired direct
foreground path.

## Prerequisites

- Linux with the installed `erebord` service running and the caller authorized
  to use `/run/erebor/daemon.sock`.
- A root administrator has configured one `codex-v1` release in the daemon's
  `root_curated_codex_packages`. That configuration pins the vendor executable
  digest, the managed hook and support-artifact digests, supported entrypoints,
  adapter digest, and root-owned artifact directory.
- The administrator gives the caller the exact configured package reference,
  for example `codex-v1@sha256:<64-lowercase-hex-digest>`.
- The caller has the matching vendor Codex executable at an absolute path.
  Erebor does not download it, search `PATH`, or accept a same-named binary.

The root-curated release is an administrator responsibility, not an import or
distribution command. OCI/Notation distribution remains Phase 10 work.

## Enroll the local executable

Replace the two values with the administrator-provided package reference and
the caller-owned vendor executable. The daemon resolves this path under the
caller UID, holds its descriptor, verifies identity and digest, and then makes
the `codex` and (when certified) `codex-app-server` aliases available.

```sh
package_ref='codex-v1@sha256:<64-lowercase-hex-digest>'
codex_bin="$HOME/.local/bin/codex"

erebor agent load "$package_ref" --from "$codex_bin"
```

Expected output names the immutable package and installation digests, followed
by `alias=codex` and `alias=codex-app-server` when the release certifies both
entrypoints.

## Interactive Codex TUI

`codex` is always an interactive daemon-owned TTY session. There is no `-t`
requirement: the client attaches the terminal, while the daemon owns the PTY,
workload, process guard, hook endpoint, output, and lifecycle.

```sh
erebor run --policy engineering codex
```

Use the normal Codex TUI. A nested Codex launched from that session remains a
governed descendant; it cannot contact the daemon control socket, enroll an
agent, mint an alias, or make itself a separately trusted App Server.

## Structured Codex App Server

`codex-app-server` is different from the TUI. Its standard input and standard
output are a bounded JSON-RPC JSONL bridge. The daemon validates each client
frame, correlates requests and replies, sends EOF to the child when client
input closes, validates child output before returning it, and never mixes
daemon telemetry into protocol stdout.

The smallest useful probe is an initialization request. Keep credentials and
real prompts out of shell history and committed files.

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"erebor-example","version":"1"},"capabilities":{"experimentalApi":true}}}' \
  '{"jsonrpc":"2.0","method":"initialized"}' \
  | erebor run --policy engineering codex-app-server
```

The command's stdout is only Codex App Server JSONL responses. Its stderr may
contain Codex diagnostics. A policy-denied sensitive transport method returns a
JSON-RPC error on stdout and is not forwarded to Codex.

For an interactive App Server client, connect that client directly to the
command's stdin/stdout; do not wrap it with `erebor session attach` or send its
frames through generic session input.

## Inspect governed evidence

After a run, use the daemon session commands to locate the session and inspect
the durable records:

```sh
erebor session ps
erebor session inspect <session-id>
erebor session events <session-id>
erebor session logs <session-id> --stream stderr
erebor audit tail <session-id>
```

Phase 4 acceptance uses a deterministic Codex-compatible privileged Linux
fixture to prove package/installation revalidation, hook ticket and peer
binding, private daemon-socket absence, App Server JSONL validation, Context
DAG prompt binding, and two-UID isolation. Phase 5 adds the state-projected,
authenticated real-vendor Codex fixture. This walkthrough does not replace
either evidence set.
