# Mithril Manual Acceptance Index

Status: Proposed operator runbooks. No procedure in this directory has been
executed by this documentation change.

These documents turn each phase's automated fixtures into a human-reviewable
live acceptance procedure. They supplement, but never replace, the committed
Rust tests, deterministic fixtures, and qualification artifacts required by
the phase plan.

Start with [environment setup](./environment-setup.md). Then use the guide for
the approved phase:

| Phase | Manual acceptance guide |
| ---: | --- |
| 0 | [Feasibility, source, ABI, and fixture closure](./phase-0-manual-acceptance.md) |
| 1 | [Shared Interceptor, node, Control, and boot lifecycle](./phase-1-manual-acceptance.md) |
| 2 | [Exact task, process, exec, and runtime-root identity](./phase-2-manual-acceptance.md) |
| 3 | [Policy simulation, effect observation, and canonical paths](./phase-3-manual-acceptance.md) |
| 4 | [Signed local pre-effect enforcement](./phase-4-manual-acceptance.md) |
| 5 | [Process-aware network enforcement](./phase-5-manual-acceptance.md) |
| 6 | [Evidence, coverage, WAL, and recovery](./phase-6-manual-acceptance.md) |
| 7 | [Mithril Control and detection packages](./phase-7-manual-acceptance.md) |
| 8 | [Kubernetes distributed causality and node floor](./phase-8-manual-acceptance.md) |
| 9 | [Local and distributed response](./phase-9-manual-acceptance.md) |
| 10 | [Provider connectors and recovery](./phase-10-manual-acceptance.md) |
| 11 | [Production installation and final conformance](./phase-11-manual-acceptance.md) |
| 12 | [Optional-surface evaluations](./phase-12-manual-acceptance.md) |

## Current-Source Privileged Lane

Use the [repository-owned VM harness](../../../../crates/mithril-e2e/harness/vm/README.md)
for the current kernel, identity, effect-observation, and local-enforcement
physical probes:

```sh
crates/mithril-e2e/harness/vm/run.sh --with-k3s \
  --output-directory /tmp/mithril-vm-evidence
```

The harness creates one disposable Ubuntu 24.04 libvirt guest, verifies the
qualified kernel features, runs the current binaries, copies the evidence, and
destroys the guest. The optional Kubernetes lane uses the K3s distribution.
It proves Pod and CRI facts, creates an exact Mithril CRI binding, and records
restricted direct CRI exec, non-TTY and TTY `kubectl exec`, and `kubectl cp`
roots. It also records an identical native child with its parent lineage and
role. The lifecycle-sleep extension records that the native Kubernetes sleep
action creates no extra task in the container cgroup. The network-probe
extension records the same task-absence result for HTTP, TCP, and gRPC
readiness probes. The container-identity extension records separate roots and
execution sets for a regular init, native sidecar, and application in one Pod.
The ephemeral extension records a separate root, process, execution set, and
profile for a targeted ephemeral container in the application's PID namespace.
It does not prove approved administrative exec, shared-resource or network-flow
policy, multi-node propagation, or complete Kubernetes protection.

For a retained guest that runs manual shells, use the [manual retained-VM
procedure](../../../../crates/mithril-e2e/harness/vm/README.md#manual-testing-in-a-retained-vm).
The controller mounts the current source read-only at `/mnt/mithril-source`.
Use its `start`, `ssh`, and `destroy` commands. Keep all fixture, binding,
pin, lease, and output paths in the guest.

## How To Read A Manual Case

Each guide contains a fixture matrix. Every row names:

- the exact fixture or phase-owned test;
- the action an operator initiates;
- the physical oracle that must be inspected; and
- the legitimate control that must still work.

Some races, saturation conditions, packet rewrites, and kernel transitions
cannot be produced reliably by typing shell commands. Those rows are marked
`operator + harness`: the committed fixture harness injects the condition, and
the operator independently reviews the physical result and retained artifacts.
Calling such a row “manual” never permits replacing the deterministic harness
with timing guesses.

## Standard Run Workflow

1. Create an isolated run using the environment guide and record its manifest.
2. Confirm the exact phase is approved and every dependency phase is `Done`.
3. Run the phase's automated test suite from the final source state.
4. Execute every applicable manual matrix row, including its legitimate
   control and one missing-prerequisite variant.
5. Inspect the physical effect, not only Mithril telemetry.
6. Save the required artifacts under one run ID and calculate their digest.
7. Copy the exact fixture results, commands, platform manifest, failures, and
   artifact digest into the phase's `Phase Result` block.

## Command Contract

A guide for a surface that has no implementation may use this marker:

```text
IMPLEMENTATION COMMAND REQUIRED: <owner and intended operation>
```

That marker is a blocking documentation contract. The implementing phase must
replace it with a copy-pastable command and expected machine-readable result
before the phase can be `Done`. An operator must not substitute an ad-hoc
command and treat the row as qualified.

## Shared Result Rule

A row passes only when all of these agree:

```text
automated fixture result
manual operator observation
physical syscall/packet/object/provider postcondition
coverage and capability state
legitimate control result
retained artifact digest
```

Any disagreement is `Not done` or `Blocked`, never a majority vote.

## Required Case Record

Record one immutable result per fixture or named phase test:

```text
run_id
phase and deliverable IDs
fixture/test ID and activation condition
candidate and platform-manifest digests
automated command and result
manual stimulus and operator
expected and observed physical result
coverage/capability state
legitimate control result
faults and timing
artifact locations and digest
status: pass | fail | blocked | not-applicable
reason and remaining branches
```

`not-applicable` requires the exact registry activation condition to be false;
it cannot mean that the environment or implementation was inconvenient.

## Related Contracts

- [Master plan](../README.md)
- [Validated readable architecture](../policy-and-protection-algorithm-architecture-readable.md)
- [Hugging Face adversarial acceptance](../hugging-face-adversarial-acceptance.md)
- [Live two-node lifecycle probe](../live-two-node-lifecycle-probe.md)
