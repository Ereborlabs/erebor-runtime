# Installing the Linux V1 daemon

`erebord` is the one privileged control-plane daemon on a Linux host. It is
not a workload runner and Phase 1 has no session or guard listener in this
service yet.

## Prerequisites

- Linux with systemd and Unix-domain peer credentials.
- The `erebord` executable installed at `/usr/lib/erebor/erebord`.
- The `erebor` CLI installed somewhere in users' `PATH`.

Create the dedicated connection group, add the intended local users, and
capture its numeric GID:

```sh
sudo groupadd --system erebor
sudo usermod -aG erebor <user>
getent group erebor
```

The numeric GID in the root-owned configuration is deliberate: it is the exact
group assigned to the socket at daemon startup. Use the GID returned by
`getent`, not the example value below.

## Configuration and service

Create `/etc/erebor/erebord.json` as `root:root` and mode `0640` or stricter:

```json
{
  "socket_group_gid": 987,
  "max_log_bytes": 4194304,
  "max_log_records": 256,
  "max_idempotency_records": 256
}
```

Install the repository-owned service definition as
`/etc/systemd/system/erebord.service`, then start it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now erebord
```

On success, the daemon creates a root-owned `/run/erebor/daemon.sock` with
mode `0660` and the configured `erebor` group. `/run/erebor/erebord.lock` is
root-owned mode `0600` and intentionally remains after clean shutdown or a
crash. The configuration is rejected if it is a symlink, not root-owned, or
writable by group or other users.

Use the new short-lived client only for control-plane commands in Phase 1:

```sh
erebor daemon status
sudo erebor daemon logs --maximum-records 100
sudo erebor daemon reload --idempotency-key maintenance-2026-07-19
sudo erebor daemon stop --idempotency-key maintenance-stop-2026-07-19
```

Every retry of `reload` or `stop` after an uncertain result must reuse the same
idempotency key for the same operation. Do not reuse it for another mutation.
Non-root group members can obtain only the sanitized status response. They
cannot read global daemon logs, reload configuration, or stop the daemon.

Daemon operational records are written as rotated JSON Lines under
`/var/log/erebor/daemon.jsonl`. `erebor daemon logs` is the only deliberate
CLI retrieval path; ordinary command output and governed workload streams do
not receive daemon diagnostics. Do not place registry credentials, package
tokens, hook tickets, or workload data in daemon configuration or command
arguments.
