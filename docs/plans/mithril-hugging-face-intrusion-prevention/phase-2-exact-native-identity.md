# Phase 2: Exact Native Identity

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Replace process-cache and PID identity with race-aware kernel-assigned task,
process, and execution identity suitable for later enforcement and response.

No effect is eligible for Phase 4 enforcement until these identity invariants
pass hostile tests.

## Depends On

Phase 1 must be `Done`, with one active loader, authenticated workload
enrichment, versioned ABI, and healthy lifecycle evidence.

## Phase Scope

### Kernel Identity Programs

Extend the owned BPF tree with:

- `task_alloc` child label inheritance;
- scheduler fork/clone/vfork events;
- exec authorization context and post-exec commit observation;
- exit;
- task iterator/readback;
- task-local storage, or the exact Phase 0-approved fallback;
- label epoch and never-reused task/process counters;
- bounded ancestor process-lineage vector; and
- missing-label/depth-overflow evidence.

The label must exist before a new child can perform a later protected effect:

```text
TaskLabel {
  workload_instance_id
  label_epoch
  task_cookie
  process_profile_id
  process_profile_version
  role_id
  process_lineage_id
  ancestor_process_lineage_ids[]
  response_state
}
```

Threads share a `process_lineage_id` but retain distinct task cookies. Forked
processes get a new process lineage even when they never exec. Exec retains
task/process identity and creates a new execution generation.

### Native Identity Owner

Create cohesive modules in the Phase 0-approved `mithril-node` crate:

```text
src/identity/
  mod.rs
  task.rs
  process.rs
  execution.rs
  graph.rs
  bootstrap.rs
  runtime_binding.rs
  revalidation.rs
```

Own:

- `(node_boot_id, label_epoch, task_cookie)` task identity;
- `(node_boot_id, label_epoch, process_lineage_id)` process identity;
- task coordinate history across namespace and non-leader exec transitions;
- root, parent-task, parent-process, inherited-execution, and exec edges;
- full container/Pod/cgroup/image binding intervals;
- `complete`, `bootstrapped`, `missing_parent`, and `source_gap` states; and
- live lookup through pidfd/start-time/task-label revalidation.

Source-native IDs from optional products remain adapter keys, never canonical
identity.

### Root Admission Handoff

Implement the strict-from-first-exec transaction at the container-runtime
boundary without taking ownership of container construction:

1. CRI/OCI creates namespaces, mounts, cgroup, and init task and holds the
   container in OCI `created`.
2. The runtime/shim integration sends authenticated cluster, Pod UID, sandbox,
   full container ID, image digest, cgroup FD/ID, init pidfd, and lifecycle
   generation to `mithril-node`.
3. Mithril binds the approved observation/profile generation, initializes and
   reads back the root task/process label, and verifies identity/link/map
   generations.
4. Mithril returns a single-use acknowledgement bound to the exact transaction.
5. Only approved protect mode makes that acknowledgement a start prerequisite.
   Observe mode records a gap and does not block start.

The integration is served by the same `mithril-node` process over an
authenticated local socket/hook. It is not another gatherer. No code in this
phase creates the container namespaces or cgroup.

### Recovery

- Reuse a healthy pinned label epoch/counter across userspace restart.
- If pinned identity state is lost while tasks survive, start a new explicit
  bootstrap transaction and coverage interval; never reset invisibly.
- Iterate/reconstruct already-running tasks as `bootstrapped`.
- Reconcile full runtime/container identity from authoritative CRI inventory.
- Reject stale task/PID/cgroup/container coordinates.

## Hugging Face Test Increment

Implement `HF-ID-001` and attach identity to every `HF-BASE-001` branch:

- concurrent logical jobs inside one interpreter remain one native process
  without invented job identity;
- natural child subtrees are distinct even when they use identical executable
  paths;
- the safe in-process driver creates no fabricated exec;
- unexpected real children receive inherited identity before first effect;
- equal PIDs/cookies/cgroups on different boots never merge; and
- the second node's root remains an independent tree with a later typed
  `container_started_for_pod` edge, not a native child.

## Code-Backed Tests

- thread, fork, vfork, clone, clone3, fork-without-exec, fork-then-exec,
  exec-without-fork, and double-fork tests;
- non-leader-thread exec/de-thread coordinate-history test;
- orphan, bootstrap, missing parent, sequence loss, depth overflow, and fork
  bomb tests;
- PID/TID, cgroup, Pod-name, container-name, node reboot, label epoch, and
  loader restart reuse tests;
- root-admission success plus missing/stale/wrong-container/wrong-cgroup/
  wrong-profile acknowledgement failures;
- observe-mode late/missing acknowledgement coverage test;
- pidfd/start-time/task-cookie revalidation and stale target rejection;
- task-iterator readback equivalence; and
- adversarial attempts to act between child creation and label inheritance.

## Live Probe

Run Probe A and the identity/root-admission portions of Probes B, D, and G.
Test at least the advertised containerd path; add CRI-O before advertising it.

## Checkpoint

Run the common repository gates, the full hostile native-identity matrix,
root-admission integration tests for every advertised runtime, task-iterator
recovery, and the applicable live probes. Preserve the identity graph and
admission transaction artifacts.

## Acceptance

- every task/process/execution has stable non-PID identity;
- child policy identity exists before its first protected effect;
- threads, fork-without-exec, and exec-without-fork are represented correctly;
- non-leader exec does not change stable task/process identity;
- PID/TID/cgroup/container/Pod/name reuse cannot retarget an old subject;
- root admission binds the runtime-owned init task while the container remains
  in `created`;
- observe mode never blocks the deployment on Mithril availability;
- protect mode fails closed on an invalid root-admission transaction;
- bootstrap/loss/missing-parent states remain explicit;
- exact live revalidation rejects stale coordinates; and
- `HF-ID-001` and legitimate concurrency controls pass within budget.

## Explicit Stop Point

Stop after identity and root admission are proven. Do not compile learned
effects into denial maps until Phase 3 observes the unchanged deployment and
the user reviews the simulated profile.

## Phase Result

State: Not started.

Record exact hooks/storage/fallback, identity schemas, runtime integration
files, kernels/runtimes, hostile test results, live artifacts, and final state.
