# Phase 9: Recovery Hardening And Product Certification

Status: Not started.

## Purpose

Harden the complete daemon/client product against corruption, overload,
upgrades, hostile local users, and long-running operational failures, then
certify the public CLI and lifecycle as the first supported Erebor
daemon/client release. Phase 4 supplied an installable developer preview; it
did not make this support or certification claim.

This phase builds on the mandatory correctness and daemon-loss behavior already
implemented earlier; it is not where those guarantees are first added.
It depends on Phases 1 through 6, not on the optional Claude track. Include
Claude only if Phase 8 has completed; otherwise certify generic and Codex and
list Claude as unsupported.

## Scope

### Least Privilege And Local Attack Resistance

- Inventory every root operation and capability. Keep privileged path,
  namespace, UID/GID, cgroup, and signal setup behind narrow owners; drop
  capabilities in daemon workers and children as soon as each operation
  permits.
- Harden the Linux service with compatible systemd protections, resource
  limits, restart policy, file descriptor limits, and a controlled environment.
  Do not enable a protection that breaks required mount/user namespace or
  runner behavior without recording the exception.
- Extend, tune, and load-validate the basic Phase 2/3 limits into complete
  per-UID and host quotas for concurrent sessions/surfaces, stored output,
  package/cache bytes, IPC connections, streams, pull bandwidth, and request
  rates. Quota failures are typed and cannot leave partial admitted work.
- Audit TOCTOU, symlink/hardlink, ownership, PID/container reuse, socket
  replacement, credential lifetime, signal authorization, path traversal, and
  cross-UID side channels across every privileged owner.

### Corruption, Disk, And Crash Recovery

- Detect and classify corrupt/truncated state, unknown schema, digest mismatch,
  missing output/evidence, partial package graphs, lost runner identity, and
  broken surface resources.
- Never rewrite corrupt evidence as valid. Quarantine recoverable objects,
  retain original bytes, expose typed inspect/repair guidance, and require an
  explicit root repair/remove action.
- Test ENOSPC, EIO, read-only filesystem, inode exhaustion, permission changes,
  clock jumps, abrupt power-style process death, repeated crash loops, and
  partial rotation/GC.
- Add daemon-owned backup/export of immutable session evidence and package/
  policy manifests. Import verifies schemas, digests, ownership, and signatures
  and never resurrects a terminal session as running.

### Upgrades And Schema Lifecycle

- Define daemon, client protocol, package schema, `SessionSpec`, lifecycle
  store, policy, capability, adapter, and attestation compatibility/version
  rules.
- Support a controlled `erebord` upgrade:
  - preflight new binary/config/schema compatibility;
  - stop admitting work;
  - resolve active sessions according to runner/failure capabilities;
  - preserve or explicitly interrupt streams/input leases;
  - atomically hand over or restart;
  - reconcile every live object; and
  - roll back only when the prior binary can safely read the resulting state.
- Store schema migrations as idempotent, crash-recoverable steps with backups
  and generation markers. No in-place best-effort JSON rewriting.
- Define agent-package/adapter retirement, publisher key rotation, trust-policy
  replacement, revocation update, and compatibility-attestation expiry.

### Protocol And Supply-Chain Hardening

- Fuzz IPC frames/envelopes/message-family dispatch, daemon state requests,
  package manifests, OCI references/manifests/referrers, signature envelopes,
  attestation payloads, policy input, stream parsing, and archive extraction.
- Fuzz daemon-control and runtime-guard listener state machines independently.
  Prove a shared `erebord` process or shared IPC codec cannot create a
  cross-service dispatch path, authorization-cache leak, queue-starvation
  channel, or connection-state confusion.
- Add dependency/license/advisory review for crates in the privileged daemon,
  cryptography, registry, archive, IPC, and runner paths.
- Bound every parser, collection, queue, retry, recursion depth, stream,
  decompression, and retained error. Sensitive values use redacted wrappers and
  are zeroized where practical.
- Add tamper-evident lifecycle/audit segment chaining and optional root-configured
  evidence signing. Verification must distinguish missing, corrupt, unsigned,
  and valid evidence.

### Reliability And Performance

- Establish measured budgets for:
  - daemon idle memory and file descriptors;
  - control request latency;
  - create-to-start latency per runner;
  - log/attach throughput and slow-reader isolation;
  - recovery time with many retained/live sessions;
  - concurrent pull/cache behavior; and
  - audit/evidence overhead.
- Load-test multiple UIDs, sessions, surfaces, attaches, policy decisions,
  registry operations, daemon restarts, and churn. Results must show no
  cross-user starvation or unbounded growth.
- Add health/readiness reporting that distinguishes process alive, control
  ready, storage writable, trust refresh healthy, and degraded runner/surface
  capabilities.

### Product Certification

- Certify every documented public command, text/JSON schema, exit code,
  interrupt behavior, help example, and destructive confirmation.
- Certify the root-only administrative API separately from user APIs,
  including target-UID authorization, audit records, and the default absence of
  interactive attach/payload access.
- Verify daemon installation, start/stop/reload/log rotation, group setup,
  upgrade, uninstall-with-data-retention, and explicit data purge on supported
  Linux distributions.
- Update repository documentation so users can understand:
  - daemon privilege and the `erebor` group;
  - packages versus policies versus installations versus sessions;
  - runner capability differences;
  - logs versus audit/evidence;
  - offline, revocation, and trust labels;
  - daemon-failure modes;
  - recovery/repair;
  - Codex and any agent adapter already completed before this phase; and
  - the absence of remote contexts/engines and generic session exec.
- Produce a release checklist with exact compatibility matrices and known
  limitations. Do not certify untested platform, agent, runner, or registry
  combinations.

## Non-Goals

- Do not add remote daemon access, multiple daemon selection, cluster
  orchestration, arbitrary plugins, or generic session exec.
- Do not use hardening to conceal unsupported runner/agent capabilities.
- Do not delete user data during uninstall or repair without a separate
  explicit purge operation.

## Checkpoint

Extend `examples/codex-app-server` with the Phase 9 recovery, upgrade, and
certification-evidence walkthrough. Keep its failure injection on a disposable
host and identify the automated certification tests it supplements.

Add fault-injection, fuzz, load, upgrade, packaging, and CLI certification
tests. Run the complete `lifecycle-probe.md` matrix from a clean installed
system. Pure model/parser/fuzz cases may run in the normal workspace lane; the
serial Ubuntu 24.04 `privileged-linux` installed-product target is the
authoritative systemd/cgroup/root/two-UID/Linux-host/Docker/upgrade and
daemon-loss certification lane. Missing required host conditions fail that
lane and never convert a supported-release requirement into a skip.

Run:

```sh
rtk cargo fmt --all -- --check
rtk cargo test --workspace --all-targets --all-features
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk git diff --check
```

Run the repository's dependency, advisory, packaging, fuzz, and performance
commands selected during implementation and record their exact versions and
results in this phase.

## Required Evidence

- Root capability/service-hardening inventory and exceptions.
- Quota, fault-injection, corruption/quarantine, backup/import, and crash-loop
  results.
- Upgrade and rollback matrix across supported schema/protocol versions.
- Fuzz corpus/crash results and dependency/advisory report.
- Performance baselines and resource-growth graphs.
- Installed-system CLI/lifecycle certification matrix.
- Final compatibility and known-limitations document.

## Acceptance

- A hostile local user, malformed client/package, crash, disk failure, or slow
  consumer cannot cross UID boundaries or silently corrupt a valid session.
- Upgrades and schema changes either reconcile honestly or fail before unsafe
  mutation.
- Operational resource use is bounded and measured.
- Every advertised command, agent, runner, registry, trust label, and
  daemon-failure behavior has code-backed and installed-system evidence.
- Documentation describes the shipped product rather than the historical
  foreground runtime.
- This phase's approved evidence is the first basis for calling the
  daemon/client product supported and certified; the Phase 4 artifact remains
  a developer preview.

## Stop Point

Stop after Phase 9 evidence, final plan/status updates, and explicit user
release approval. Do not commit, publish, or deploy on the user's behalf.

## Phase 9 Result

State: Not started.
