# Privileged Daemon And Session Lifecycle Probe

Status: Required as specified by each implementation phase. Phase 1's
automated temporary-path case and the Phase 2 installed-product matrix pass in
the local ignored privileged Docker acceptance. This acceptance is deliberately
not CI; any additional manual observation supplements, but never replaces,
the committed Rust tests.

## Purpose

Prove the product works across the boundaries that unit tests cannot fully
simulate:

- one installed root daemon;
- separately owned daemon-control and runtime-guard services inside that
  daemon process;
- real Unix peer credentials from multiple OS users;
- UID/GID privilege drop;
- Linux mount/process enforcement;
- Docker container lifecycle when Phase 6 is under test;
- daemon control-socket absence inside workloads;
- detached output and the Phase 2 read-only attach/lease foundation;
- the Linux-host controller and independent session-owned systemd/cgroup
  subtree; Docker-controller parity only when Phase 6 is under test;
- abrupt client and daemon death;
- runner-specific recovery;
- real package/policy/install resolution;
- real Codex behavior; and
- Claude behavior only when Phase 7/8 is approved and registry trust/revocation
  only when Phase 10 is approved.

Manual evidence supplements committed Rust tests. It never replaces them.

## Probe Host

Use the repository's ignored privileged Docker acceptance, based on Ubuntu
24.04, for repeatable temporary-path and installed-product evidence. It starts
a disposable privileged container with a real PID 1/systemd and nested Docker;
it is run explicitly by a developer and is not part of ordinary CI. A
disposable Linux VM is only for additional manual observation. A missing
required condition fails the explicit local acceptance rather than silently
skipping it.

The host has:

- no production Erebor data;
- root access inside the disposable acceptance environment and the user/group
  administration tools;
- systemd and cgroup v2 when a later installed-product/session scenario
  requires them;
- at least two disposable non-root users in the `erebor` group and a third user
  outside it;
- mount/user namespaces, cgroups, Unix peer credentials, ptrace/process guard,
  PTY, and signal support;
- Docker only for Phase 6 sections;
- a loopback OCI registry and signed OCI catalog-artifact fixture only for
  Phase 10;
- a separately provided real Codex fixture for Phase 4; and
- a separately approved real Claude Code fixture for Phases 7/8.

Record the kernel, distribution, filesystem, cgroup mode, Docker version when
used, Erebor build id, test UIDs/GIDs, and whether the host is a VM. If a
required kernel/container feature is unavailable, report the exact failure; do
not replace the runner with a mock.

Do not run destructive lifecycle probes against an existing
`/var/lib/erebor`, `/var/log/erebor`, or `/run/erebor/daemon.sock`. Snapshot the
disposable VM before the first probe or install onto a newly provisioned host.

## Evidence Record

For every probe action, record:

- phase, UTC time, command, caller UID/GID, and expected result;
- daemon PID/build/protocol version;
- service family, listener path, owning `erebord` PID, and accepted peer
  evidence for control or guard traffic;
- returned object id and immutable digests;
- runner stable identity, implementation id/version, and exact versioned
  capability-document digest, not only PID;
- private runner-controller identity, inherited-handle inventory,
  runner-specific continuity journal, session slice, child scopes, and cgroup
  subtree where applicable;
- exit code and bounded relevant stdout/stderr;
- lifecycle transitions in order;
- daemon telemetry path and matching structured record ids;
- workload log/event/evidence paths and hashes;
- daemon socket lookup/connect result from inside the workload;
- cleanup result; and
- an explicit `Passed`, `Failed`, or `Blocked`.

Redact prompts, credentials, registry tokens, hook tickets, and user data.

## Phase 1: Automated Temporary-Path Control Plane

1. The ignored Rust probe creates its own temporary root, connection group,
   root configuration, and disposable users. It starts `erebord` directly with
   `--config`, `--runtime-dir`, `--log-dir`, and `--state-dir`; it does not use
   `/etc/erebor`, `/run/erebor`, `/var/log/erebor`, `/var/lib/erebor`, or
   systemd.
2. Verify exactly one daemon owns the temporary `daemon.sock`; record socket
   owner `root`, the temporary connection group, and mode `0660`.
3. As each in-group user, run `erebor daemon status`. Verify the response
   identifies the kernel-observed caller but exposes no other user's state.
4. As the user outside the group, prove the connection is rejected by the
   socket boundary.
5. As a non-root in-group user, prove `logs`, `reload`, and `stop` are rejected.
   As root, read a bounded log stream and reload one valid config and one
   invalid config; prove invalid reload retains the prior effective config.
6. Attempt to start a second `erebord`. Prove it fails without replacing or
   unlinking the healthy socket.
7. Record the root-owned mode-`0600` temporary `erebord.lock` inode. Stop
   cleanly as root and prove the daemon socket is removed while the lock file
   remains. Create only a stale `daemon.sock`, restart directly, and prove the
   daemon removes it only while holding the persistent flock after failed
   connect/protocol/peer checks. Repeat after abrupt daemon death; the lock path
   must never be unlinked or replaced as part of recovery.
8. Verify operational records are in the temporary `log/daemon.jsonl` and are
   not copied into command output after logging initialization.
9. Run the existing real Linux process-guard allow/deny lifecycle and Codex
   hook IPC fixtures. Prove the protocol split and generated/standalone codec
   conformance did not break the temporary foreground runtime.
10. Prove the Phase 1 `erebord` control listener rejects a guard message before
    control dispatch. Also prove Phase 1 has not silently moved the existing
    foreground runtime interception listener onto `/run/erebor/daemon.sock`;
    the actual runtime guard service migration is a Phase 2 concern.

## Phase 2: Internal Generic Session Probe

Until the public CLI cutover, use a dedicated
`erebor-runtime-e2e` daemon-session driver built on
`erebor-runtime-client`; do not use the old CLI direct execution path.

For both Linux-host and Docker:

1. Submit a generic `create` request. Verify state is `created` and no workload
   process/container, live namespace, helper, or session endpoint exists.
2. Start once; prove a second start is rejected. Record the daemon control
   socket and the shared runtime guard socket. Prove the same installed
   `erebord` PID hosts both, while each socket maps to a different named service
   owner, connection state machine, and message allowlist. Prove 1, 10, and 100
   guard registrations do not create additional listeners or worker runtimes.
   Record the Phase 2 `RunnerCapabilityDocument`, runner implementation
   id/version, immutable `SessionSpec` snapshot, private
   runner-owned Linux or Docker controller, independent session slice, child
   scopes, and cgroup subtree. Verify the two runners use distinct controller
   protocols/binaries and no controller contains a runner-kind dispatcher.
3. Exercise a real Linux guard hello, allowed effect, denied effect, and
   lifecycle message. Prove they reach only the runtime guard service. Send a
   guard message to the daemon control socket and a daemon message to the guard
   socket; both must fail before domain dispatch and must not create a session,
   control operation, or policy decision. Prove Phase 2 has no production Codex
   hook listener in `erebord`; the real Codex hook fixture remains on the
   temporary foreground path until Phase 4.
4. Start simultaneous Linux sessions for both in-group users. Prove each guard
   connection is bound to its exact immutable session and cannot reuse the
   other user's credential. Stop one session and prove its logical registration
   is immediately revoked while the shared listener and the other session stay
   available.
5. Inside the workload print UID/GID, inspect `/run/erebor`, attempt both
   `stat` and `connect` on `/run/erebor/daemon.sock`, and use one admitted
   per-session endpoint. Required result:
   - UID/GID equal the requesting user;
   - daemon socket is absent/unconnectable; and
   - the exact session guard endpoint reaches only the runtime guard service.
6. Produce distinct stdout/stderr, detach the client, reconnect, inspect ordered
   logs/events, and wait for terminal result. Prove output is written through
   the helper and remains appendable during the admitted daemon-loss gap.
7. Verify both Phase 2 runner capability documents report
   `tty_supported=false`. Attach read-only, request an input lease, and prove
   lease issuance rejects because no admitted PTY exists. Exercise lease
   exclusivity/renewal/expiry on the durable owner in crate-local tests. The
   real PTY/stdin transport probe begins only when Phase 6 implements it.
8. Stop one process tree/container gracefully, kill another, and prove the
   exact driver-owned recovery identity—not an arbitrary PID/name—was
   targeted.
9. Restart the daemon during `starting`, `running`, and `stopping` and verify
   honest reconciliation of both control-service and runtime-guard-service
   listener state.
10. Force a client timeout after each mutating request, retry with the same
    daemon-only `erebor-idempotency-key` header, and prove no duplicate
    session/start/stop/remove. Reuse the key with different exact protobuf
    payload bytes and prove request-fingerprint mismatch rejection. Prove the
    header is rejected on read-only daemon, guard, and hook messages and is
    independent of numeric message/correlation ids. Resume logs/events by the
    recorded durable cursor.
11. Attempt a workspace/executable symlink swap after create, inject a marker
    into the root daemon environment, and use a configured secret fixture.
    Prove start rejects changed identities, the root marker is absent, and the
    daemon does not render the secret into any spec, telemetry, error, metadata,
    or evidence. Treat workload output as sensitive opaque content rather than
    claiming automatic redaction. Record the descriptor broker's cleared
    supplementary groups, permanent GID/UID drop, closed unrelated
    descriptors, no-network constraint, `openat2`/no-follow resolution,
    `SCM_RIGHTS` held-fd/`statx` handoff, and proof that `erebord` never reopens
    the path string.
12. For Docker, use a pinned local image, remove registry connectivity, and
    prove start uses the exact image id without an implicit pull.
13. As non-root, prove normal requests cannot name a target UID. As root, use
    the distinct administrative API to inspect/stop a test user's session and
    verify the audit record and absence of an interactive attach.
14. While a session is active, prove graceful daemon stop refuses until root
    explicitly resolves it.
15. Repeat the supported failure-mode cases with direct daemon SIGKILL,
    systemd automatic restart, `systemctl stop erebord`, and
    `systemctl restart erebord`. Prove each is daemon loss, not the graceful
    refusal RPC. The independent session slice and child scopes have no
    `PartOf=`/`BindsTo=` relationship to `erebord.service`, so service
    management does not kill a `continue` session as a daemon descendant or
    spare a `terminate` session contrary to its lease. Prove the helper and
    workload/container occupy distinct child scopes beneath the session-owned
    cgroup subtree. Killing the one `erebord` PID removes both hosted services.
    Host shutdown is outside the initial `continue` guarantee.

## Daemon-Loss Matrix

Run each row separately for each runner that declares it supported. Phase 2
Linux-host and Docker must declare and prove `terminate` and `continue`, and
must reject `continue_if_enforced` at admission with a stable capability
reason. The behavioral `continue_if_enforced` row is reserved for a future
runner guard that independently enforces the complete pinned policy and
evidence continuity.

| Mode | Failure injection | Required result |
| --- | --- | --- |
| `terminate` | Abruptly kill only the recorded daemon PID while a child process tree/container is active. | Independent control lease terminates the complete workload and resources; restart records the loss and terminal classification. |
| `continue_if_enforced` | Initial Linux-host/Docker admission attempt; for a future supporting guard, kill the daemon before delayed allowed and denied effects. | Phase 2 Linux-host/Docker reject admission. A future supporting guard must keep complete pinned enforcement/evidence independent, allow only the allowed effect, deny before execution, and prove continuity before returning to `running`. |
| `continue` | Kill the daemon while a workload emits sequenced output and later exits. | Workload and admitted durable output owner continue; restart reattaches from stable identity and records the control gap. If continuity cannot be proved, result is `interrupted`, never fabricated success. |

For every row:

- record the daemon PID before killing it and never use a name-wide kill;
- prove the CLI cannot control the host while the daemon is absent;
- restart through the installed service;
- verify lifecycle ordering includes `control_lost`;
- compare pre/post output sequence and evidence chain;
- prove no unrelated user workload was signaled; and
- retain the exact capability report that admitted or rejected the mode.

## Phase 3: Public Generic CLI

As each test user:

1. Apply one policy containing an allowed command and the established denied
   `remote-debugging-port` process rule as a policy package, create a
   policy-set revision, and record both digests and aliases.
2. Inspect the daemon-installed built-in generic package and installation
   identity. Prove that no user `agent import` or package-verification command
   can add content to the daemon store in this phase.
3. Run:

   ```sh
   erebor create --name created-only --policy probe -- sh -lc 'echo must-not-run'
   erebor run --policy probe -- sh -lc 'printf "allowed-out\n"; printf "allowed-err\n" >&2'
   erebor run -d --name detached --policy probe -- sh -lc 'sleep 1; echo detached-done'
   erebor ps -a
   erebor inspect detached --format json
   erebor logs --tail 20 detached
   erebor events detached
   erebor wait detached
   ```

4. Run the denied command and prove its child-side marker is absent while
   policy/audit evidence contains the deny rule id.
5. Exercise attach, stop, kill, rm, and dry-run/real prune against explicitly
   recorded ids.
6. Exercise the daemonized policy-test, audit/evidence trace, filesystem
   transaction/retention, diagnosis, and transitional surface commands that
   replaced current CLI capabilities. Prove there is no adoption command.
7. Trigger one `require_approval` effect. Inspect it from another client,
   approve it once, and prove exact-effect release and replay rejection. Repeat
   denial, expiry, session cancellation, wrong-user access, and daemon restart
   with a pending approval.
8. Stop `erebord`, invoke generic `erebor run`, and prove it fails before
   creating any process/container. Confirm migrated commands have no direct
   fallback. The sole `erebor` command may retain only the current direct Codex
   implementation until Phase 4.
9. Place an old workspace `.erebor/sessions` fixture and prove the new daemon
   neither imports nor deletes it.
10. Cross-check from user B that user A's ids, aliases, policy packages/sets,
    approvals, logs, events, installs, and evidence are unresolvable.
11. Exceed the configured session, output, policy-upload, and pending-approval
    quotas and prove typed rejection before a partial side effect.

Repeat the generic lifecycle on Linux-host. Confirm Docker reports unavailable
until Phase 6 is approved and proven.

## Phase 4: Real Codex

Use the existing real Codex Linux fixture requirements and record the exact
binary/version/hash. Never put credentials or prompts in the evidence report.

1. Use the root-curated Codex package fixture and explicitly enroll the real
   vendor binary. Do not add local package import or signature verification in
   this phase.
2. Prove modification, symlink replacement, wrong owner, wrong hash, wrong
   schema, wrong entrypoint, and raw-argv Codex selection all fail admission.
3. Run the approved interactive entrypoint if the package certifies it.
4. Run the exact `codex-app-server` entrypoint through `erebor`.
5. Prove hook ticket/peer binding, invocation lease, prompt/turn Context DAG,
   physical allowed/denied effects, output separation, and final evidence.
   Record the one shared Codex hook listener inside the installed `erebord`
   process, prove multiple registered Codex sessions cannot cross-route tickets
   or events, and prove the final foreground hook/runtime-guard adapter no
   longer exists.
6. Repeat daemon-socket absence and supported/rejected daemon-loss modes.
7. Remove/disable `erebord`, invoke both generic and Codex public runs, and
   prove no process starts. Confirm no direct Codex fallback or compatibility
   alias remains. Formal installation, checksums, signatures, and uninstall
evidence belong to Phase 10.

## Phase 10: Registry, Trust, And Packaging

1. Import signed generic-agent, Codex-agent, and policy-package OCI-layout
   fixtures through `erebor agent import`, then push the admitted subjects plus
   signatures, provenance, SBOMs, compatibility reports where applicable, and
   review statements to the loopback OCI registry. Prove descriptor-broker path
   safety and that each compatibility report names the exact Phase 2 capability
   schema and runner implementation id/version.
2. Refresh the signed OCI catalog-artifact fixture, search its verified local
   snapshot, pull by tag, and record the independently resolved
   subject/referrer digests.
3. Install and run offline within the admitted trust age.
4. Independently test wrong digest, invalid/expired/wrong-scope signature,
   missing attestation, stale revocation snapshot, revoked package, corrupt
   blob, malicious layer, unauthorized redirect, interrupted pull, concurrent
   pull, and GC with a live session lease.
5. Make catalog metadata disagree with registry content and prove registry
   verification—not catalog display—controls the result.
6. Prove user A's registry credentials/private aliases are unavailable to user
   B and no secret appears in helper argv, child environment, telemetry,
   inspect, or errors.
7. Make catalog revocation metadata disagree with the configured signed feed
   and prove the feed/static root policy wins. Exercise `leave_running` and
   `terminate` for already-running sessions.

## Phase 5: Ambient Surfaces

1. Prove `erebor start` is rejected before it can create a foreground listener,
   process, surface record, or daemon request. Create/start a named browser-CDP
   ambient surface through `erebor surface`, then exercise one allowed and one
   denied CDP action against a real Erebor-owned or fixture browser.
2. Verify surface health, logs, events, evidence, restart classification,
   owner-only access, session binding, stop, and removal.
3. Prove the CLI, daemon protocol, and runner capability documents expose no
   session adoption operation.
4. Query Docker and a nonexistent platform runner and verify a stable
   unavailable reason rather than a fake capability.

## Phase 6: Docker, PTY, And Runner Parity

Run the Linux-host/Docker conformance, Docker image/no-pull, Docker guard,
PTY/input-lease, and runner-capability-extension matrix only after Phase 6
is explicitly approved. Retain Docker as unavailable if any required physical
enforcement, lifecycle, or recovery proof fails.

## Phases 7–8: Claude Code

Phase 7 runs only the approved discovery probes from its source/security
record. Phase 8 repeats the Phase 4 structure using the exact pinned Claude
package, installation, entrypoints, settings, transport, trust classifications,
and negative cases approved after discovery.

No Phase 8 live result is accepted if a hook or structured record is called
trusted without the Phase 7 wrong-peer, replay, omission, and replacement
proofs.

## Phase 9: Full Installed-System Matrix

Run every core section plus the Phase 9 quota, ENOSPC/EIO, corruption,
backup/import, upgrade/rollback, fuzz, load, log rotation, service restart,
uninstall-with-retention, and explicit purge scenarios on clean snapshots.
Include a later-phase section only when that capability is to be certified;
otherwise record it as unsupported rather than blocking core certification.

The final report groups results by exact:

- Erebor build and schema versions;
- agent package/installation/adapter versions;
- runner/OS/kernel/Docker version;
- registry/catalog-artifact fixture version; and
- supported versus rejected capability.

## Cleanup

- Address sessions, approvals, surfaces, packages, test users, and processes by
  recorded exact id or stable identity.
- Stop/remove resources through `erebor` before stopping the daemon.
- Never use recursive deletion on `/`, a home directory, `/var/lib`, or an
  unvalidated variable/glob.
- Preserve failed evidence before cleanup.
- Revert the disposable VM snapshot or destroy the dedicated VM after the
  report; do not reuse its root-owned state as production data.

## Required Result

A core phase passes only when:

- every required action has a code-backed test and the live result above;
- every expected failure fails before the forbidden side effect;
- state, logs, events, and evidence agree;
- UID and socket isolation are observed inside real workloads;
- runner/agent limitations are reported rather than hidden; and
- cleanup targets only the recorded probe resources.

A later phase passes only when its approved additional actions and the same
core evidence rules pass. An unapproved later capability is reported as
unavailable; it does not block the Phase 5 core roadmap.
