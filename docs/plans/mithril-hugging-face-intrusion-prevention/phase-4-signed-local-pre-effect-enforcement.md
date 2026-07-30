# Phase 4: Signed Local Pre-Effect Enforcement

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Turn the reviewed Phase 3 profile into local synchronous exec, file/code,
device, privilege, process-control, namespace, and kernel-surface decisions.

This phase proves that the effect itself is denied before completion. It does
not yet claim complete network prevention or multi-node response.

## Depends On

Phase 3 must be `Done`, and the user must approve the exact signed profile,
effect classes, kernel tiers, fail behavior, and canary scope.

## Phase Scope

### Enforcement Programs

Add the Phase 0-approved BPF LSM, cgroup-device, and related pre-effect paths:

- `bprm_check_security` and required script/interpreter/code-loading checks;
- file open/permission, mmap, inode/path, descriptor-receive/use, and ioctl
  hooks required by the declared matrix;
- device read/write/`mknod` and ioctl decisions;
- capability, credential, ptrace/process-control, namespace, mount, BPF, perf,
  keyring, and module decisions; and
- missing-label and emergency response-root checks at every protected hook.

Preserve a prior LSM denial. Return the selected denial from the authoritative
hook. Evidence reservation failure increments loss/coverage state but does not
turn a denial into allow.

Each program decision is a bounded lookup over validated numeric keys:

```text
protected workload/cgroup
  + current TaskLabel/profile generation/role
  + immutable object/effect key
  + response-root state
  → allow or hook-specific denial
```

No normal allowed decision calls userspace.

### Signed Generation Lifecycle

The `mithril-node` policy owner must:

1. authenticate and validate the profile artifact;
2. reject stale, expired, wrong-image, wrong-capability, or unrepresentable
   content;
3. compile a complete inactive map generation;
4. load/read back maps and links;
5. run generation-specific allow/deny probes;
6. atomically activate the generation;
7. retain the prior verified generation while referenced; and
8. roll back or preserve prior enforcement on failure/restart.

An incomplete new generation never partially overlays the old one.

### Decision And Postcondition Evidence

Every denied effect includes:

- native and workload identity;
- exact role and profile/program/policy generations;
- object/effect key;
- requested access/transition;
- matched or missing rule;
- hook and returned errno;
- source sequence and coverage; and
- a testable effect-specific postcondition.

Signal delivery is recorded separately and never upgrades a denial claim.

### Emergency Local Restriction Primitive

Implement the in-kernel `response_roots` check and generation update needed for
later Phase 9 response, but expose it only to an internal Phase 4 controlled
probe. Full authorization, pidfd stopping, socket fencing, cgroup widening, and
distributed response remain out of scope.

## Hugging Face Test Increment

Promote these scenarios from simulation to physical denial:

- `HF-LOCAL-001`: the same interpreter cannot read the protected
  environment/token object when its role does not need it;
- `HF-LOCAL-002`: unapproved `python → sh/curl/tailscale`, changed binary, and
  alternate exec forms never install an execution image;
- `HF-LOCAL-003`: device, process-memory, namespace, mount, privilege, BPF,
  perf, keyring, and module effects fail for the fixture role; and
- the `HF-010` driver remains the same `ExecutionInstance`, proving Mithril
  denied its first prohibited external effect rather than claiming to detect
  Python computation.

Every scenario asserts that its forbidden later stage did not execute. The
legitimate worker/controller controls must continue to pass.

## Code-Backed Tests

- allow, deny, missing-label, prior-LSM-denial, and event-reservation-loss paths
  for every advertised hook;
- child-before-first-effect and fork-bomb race tests;
- already-open descriptor, passed descriptor, mmap/shared-memory, and alias
  cases against the exact claimed coverage;
- exec/interpreter/`memfd`/content-mutation bypass matrix;
- device/ioctl and privilege/escape matrix;
- unsigned, stale, expired, wrong-image, partial, and incompatible profile
  rejection;
- atomic generation activation, concurrent tasks on old/new generations,
  failed swap, rollback, and loader restart;
- response-root controlled restriction probe;
- physical postcondition checks for bytes, file metadata/content, execution
  image, device state, capability/namespace state, and kernel object state; and
- legitimate unchanged fixture plus performance budgets.

## Live Probe

Run Probes A and B for every enabled local effect family, plus relevant Probe G
restart, loss, profile-swap, and rollback cases.

## Checkpoint

Run the common repository gates, per-hook allow/deny and bypass matrices,
generation/recovery tests, every physical postcondition probe, and the live
canary. Record the exact approved profile/program generations and prove the
protected deployment digest did not change.

## Acceptance

- a prohibited executable image never runs;
- a prohibited file read returns no bytes and a prohibited mutation leaves
  content/metadata unchanged;
- prohibited code loading, device, privilege, process-control, namespace,
  mount, and kernel-surface effects fail before completion;
- a missing task label fails closed only inside the explicitly protected scope;
- expected legitimate effects remain functional;
- profile generations are signed, complete, atomic, recoverable, and
  rollback-capable;
- enforcement continuity and evidence continuity remain separate;
- the local incident scenarios stop before their next forbidden stage;
- signal-only results are not called prevention; and
- latency/CPU/memory remain within the approved budgets.

## Explicit Stop Point

Stop after approved local effect classes pass canary and incident tests. Do not
claim complete `HF-012` or established-flow prevention until the user approves
the Phase 5 network plane.

## Phase Result

State: Not started.

Record exact programs/hooks/maps, profile generation, denial/postcondition
results, bypass matrix, kernels, live artifacts, performance, gaps, and final
state.
