# Phase 1: One-Binary Node Chassis

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Create the one-process Mithril node deployment and shared observation substrate
without yet claiming exact inherited identity or effect prevention.

The result is one DaemonSet Pod containing one container that runs one Rust
`mithril-node` process. Internal owners are modules, not extra node daemons.

## Depends On

Phase 0 must be `Done`, including approved paths, toolchain, ABI, license
dispositions, fixture, support tiers, and budgets.

## Phase Scope

### Shared ABI And Host Owner

Create the Phase 0-approved equivalent of:

```text
crates/erebor-linux-sensor-abi/src/
  lib.rs
  header.rs
  event.rs
  capability.rs
  identity.rs
  effect.rs
  policy.rs

crates/erebor-linux-sensor-host/src/
  lib.rs
  error.rs
  program_manager.rs
  capability_probe.rs
  ownership_lease.rs
  pinned_state.rs
  ring_buffer.rs
  subscription.rs
```

`program_manager` owns every BPF object, link, map, pin, generation, load
failure, verifier result, and startup reconciliation. No caller receives raw
writable libbpf objects.

Implement three physical loader authorities:

- `mithril-observe`;
- `mithril-protect`, initially with no approved deny profile; and
- `runtime-observe`, restricted to Runtime-owned cgroups and observation-only
  object/program sets.

The Rust type/API boundary must make it impossible for a
`runtime-observe` handle to call policy-map or response-map mutation methods.

### Minimal BPF Program Set

Create the owned lifecycle/health subset under
`bpf/erebor-linux-sensor/`:

- process fork;
- successful exec;
- process/task exit;
- cgroup and namespace coordinates needed for enrichment;
- ABI/program/sequence/loss health; and
- a controlled capability probe program.

Do not claim Phase 2 task-cookie completeness from process exec/exit events.
Missing parents and tasks first seen at attachment are visible bootstrap/gap
states.

### Mithril Node Process

Create the Phase 0-approved equivalent of:

```text
crates/mithril-node/src/
  main.rs
  lib.rs
  error.rs
  config.rs
  node.rs
  kernel.rs
  enrichment.rs
  evidence.rs
  transport.rs
  diagnostics.rs
  runtime_subscription.rs
```

The binary:

- probes and publishes node capabilities;
- acquires the one-owner lease;
- loads/reconciles the selected observation programs;
- enriches events with authenticated node boot, cgroup, full container ID,
  Pod UID, container name, image digest, and cluster identity;
- merges kernel events into one ordered userspace path;
- emits sequence/loss/health evidence;
- exposes an authenticated Unix-domain read-only observation subscription;
- sends one outbound mTLS stream; and
- remains healthy when Mithril Control is unavailable.

The subscription authenticates both caller and requested cgroup scope.
Runtime cannot request node-wide data.

### Packaging

Create:

```text
packaging/mithril/image/
packaging/mithril/helm/mithril/
```

The minimal Helm release installs:

- one `mithril-node` DaemonSet;
- one container per DaemonSet Pod;
- one ServiceAccount with the Phase 1 minimum RBAC;
- required host mounts/capabilities from the measured kernel matrix;
- trust/configuration material; and
- no operator, relay, sidecar, Falco, Tetragon, KubeArmor, or Cilium dependency.

Mithril Control may be a test endpoint in this phase.

## Hugging Face Test Increment

Extend `HF-BASE-001`:

- run overlapping jobs and the legitimate controller;
- observe process exec/exit and workload identity from exactly one gatherer;
- prove the original deployment digest is unchanged;
- restart the outbound connection and replay without accepting duplicate
  sequence identities; and
- run a Runtime-only and co-resident fixture to prove scoped observation and
  one active owner.

The Phase 1 Runtime consumer is a test client in `mithril-e2e` unless a
separate Runtime integration phase has already been approved. This phase does
not silently replace the current ptrace Runtime backend.

No Phase 1 result may call the observed tree complete or an effect prevented.

## Code-Backed Tests

- crate-local configuration, capability, lease, pin-state, ABI decoder,
  enrichment, sequence, mTLS reconnect, and subscription authorization tests;
- malformed/oversized event and unknown ABI version tests;
- full container ID and Pod UID reuse interval tests;
- second-loader refusal and stale-lease reconciliation tests;
- forged Runtime subscriber, node-wide scope request, and writable-map access
  compile/runtime rejection tests;
- packaging tests proving one container/one process intent and absence of
  upstream daemon dependencies;
- `mithril-e2e` one-node lifecycle, disconnect/reconnect, and
  `HF-BASE-001` controls; and
- performance comparison with the Phase 0 budgets.

## Live Probe

Run Probe A from
[Live Two-Node Lifecycle Probe](./live-two-node-lifecycle-probe.md) on at least
one Phase 0 full-tier node. Also run one-owner and Runtime co-residency
preflight.

## Checkpoint

Run the common repository gates, Phase 1 crate/package tests, one-owner and
subscription-security tests, the live Probe A run, and the Phase 0 performance
comparison. Preserve exact binary, BPF object, image, chart, capability, and
fixture digests.

## Acceptance

- one DaemonSet Pod per node contains one running `mithril-node` process;
- no second privileged collector is installed;
- all production loader/userspace code is Rust;
- owned BPF objects build reproducibly from recorded sources;
- the node reports truthful measured capabilities;
- process exec/exit observations carry authenticated node/container/Pod/image
  identity and sequence/coverage data;
- central disconnect does not stop or crash the node;
- reconnect does not duplicate accepted source identities;
- `runtime-observe` sees only its authorized agent cgroups and cannot mutate
  enforcement or response state;
- co-resident Runtime uses `mithril-node` as the sole active owner;
- the unchanged incident control fixture completes; and
- performance remains within Phase 0 budgets.

## Explicit Stop Point

Stop after the one-binary watch-only chassis passes. Do not add inherited task
identity, profile decisions, or prevention until the user approves Phase 2.

## Phase Result

State: Not started.

Record files, binary/image/chart digests, process/Pod inventory, test commands,
live probe artifacts, performance, gaps, and final state.
