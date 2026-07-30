# Phase 3: Effect Observation And Profile Simulation

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Observe and classify the physical effects Mithril will later deny, bind them to
exact native identity, and compile a human-reviewed signed workload profile in
observe/simulate mode without changing protected workload behavior.

## Depends On

Phase 2 must be `Done`. Incomplete task/process identity may still generate
evidence, but it cannot silently become an authorized profile edge.

## Phase Scope

### Effect Program Families

Add observation paths for:

- executable and script/interpreter resolution;
- file open/read/write/create/delete/rename/link/metadata and descriptor use;
- process environment and projected credential object classes;
- mmap, executable memory, `memfd`, `dlopen`, and code-source effects;
- socket create/connect/bind/listen/accept/send/receive/pass;
- DNS and actual destination address;
- device open, `mknod`, and ioctl class;
- capability and credential transitions;
- ptrace, `process_vm_*`, proc-memory, and process control;
- namespace, mount, chroot/pivot, and filesystem topology;
- BPF, perf, keyring, and module/kernel attack surfaces; and
- current seccomp, mount namespace, Landlock, LSM, CNI, and device context as
  observed deployment evidence.

Use semantic kernel decision/trace points and in-kernel filtering. Do not gather
every syscall or reconstruct every path for ordinary allowed activity.

### Stable Object And Socket Identity

Define and test effect keys using the real kernel object:

- mount/filesystem/device/inode/generation or version;
- content/IMA/fs-verity/image-layer digest when available;
- alias/link/deleted-open state;
- access mask and object class;
- network namespace, socket cookie, tuple, protocol, destination live interval;
- device type/major/minor and ioctl class; and
- profile, program, policy, label, and coverage generations.

Path, DNS name, image tag, PID, and destination label are context, not durable
authority.

### Effect Owner And Schema

Create:

```text
crates/mithril-node/src/effects/
  mod.rs
  executable.rs
  file.rs
  credential.rs
  memory.rs
  socket.rs
  device.rs
  security.rs
  object_identity.rs
  decision.rs
```

Every normalized effect references the exact task, process, execution,
workload, object/socket, policy/program generation, raw source sequence, and
coverage interval. `OrphanEffect` and `LineageCoverageGap` remain separate
from an attached `Unexpected*Effect`.

### Profile Compiler In Simulation Mode

Create:

```text
crates/mithril-node/src/profile/
  mod.rs
  model.rs
  resolver.rs
  learner.rs
  compiler.rs
  signature.rs
  simulation.rs
```

Implement the signed `WorkloadProcessProfile` model:

- immutable image/profile selector;
- root, fork, and exec edge rules;
- roles before and after exec;
- per-role file, socket, device, privilege, namespace, kernel-surface, and
  control-plane effects;
- maximum depth/count;
- approval, version, expiry, and artifact digest;
- required capabilities and coverage;
- unsupported/unrepresentable result; and
- observe, alert, and later enforce modes.

OCI configuration, SBOM/image contents, immutable binary/object identity,
reviewed deployment configuration, and monitor evidence can propose a
candidate. Observations never self-authorize.

Simulation records:

```text
effect
matched or missing rule
would_allow or would_deny
resulting role
required kernel capability
profile generation
coverage state
```

No Phase 3 BPF program returns a new denial for the protected workload.

## Hugging Face Test Increment

Implement observation/simulation variants of:

- `HF-LOCAL-001`;
- `HF-LOCAL-002`;
- `HF-LOCAL-003`;
- `HF-NET-001`;
- `HF-NET-002`; and
- `HF-SEM-001`.

The safe in-process driver must show:

- no false exec edge at `HF-010`;
- exact file/credential effects for `HF-009`/`HF-011`;
- direct Python socket effects for `HF-012` without requiring `curl`;
- expected controller token/API behavior as ordinary evidence;
- unexpected child/helper behavior as a different role; and
- packet/TLS evidence without provider-operation semantics.

Review the candidate `hf-dataset-worker` and legitimate-controller profiles
against false positives before Phase 4.

## Code-Backed Tests

- overlayfs, bind mount, rename, hard link, symlink, deleted-open file,
  projected-volume alias, procfs, mount namespace, and descriptor-passing
  object tests;
- `execveat`, scripts/interpreters, changed-content same-path, `memfd`/
  `fexecve`, mmap, and library/JIT code-source tests;
- TCP, UDP, IPv4/IPv6, DNS change, hard-coded address, inherited/passed socket,
  and alternate-interface observation tests;
- device/ioctl, ptrace, process memory, namespace, mount, capability, BPF,
  perf, keyring, and module observation tests;
- exact identity/coverage join for every effect;
- orphan and gap classification tests;
- profile schema/signature/version/expiry/image-digest validation;
- unrepresentable rule rejection;
- monitor learning cannot approve itself;
- simulation determinism and atomic compiled-image digest; and
- unchanged `HF-BASE-001` completion and Phase 0 performance budgets.

## Live Probe

Run Probes A, B, and C in observe/simulate mode. Record every effect class the
platform could and could not observe. The protected deployment must remain
unchanged.

## Checkpoint

Run the common repository gates, every effect/object/socket fixture, profile
compiler and signature tests, the incident observe/simulation corpus, and live
Probes A–C. Present the signed candidate profile, false positives, unsupported
classes, deployment digest comparison, and performance report.

## Acceptance

- every advertised effect class has an exact observation mechanism and test;
- every effect is bound to native/workload/object/profile/coverage identity;
- identical executable paths in distinct native branches remain distinguishable;
- same-interpreter jobs remain explicitly ambiguous;
- simulation identifies the exact rule and decision without denial;
- expected controller credential/API use does not create a false deviation;
- the incident effect driver produces the expected `HF-009`–`HF-012`
  simulation path;
- unsupported classes are explicit;
- allowed-event volume and overhead stay within budget; and
- a human-approved signed profile candidate exists for the fixture.

## Explicit Stop Point

Stop and present the learned/simulated profiles, false-positive results,
unsupported classes, and performance. Phase 4 requires explicit approval of
the exact effect classes and profile generation that will begin returning
denials.

## Phase Result

State: Not started.

Record files, hook/object matrices, profile digests, fixture paths, false
positives, unsupported effects, commands, live results, performance, and final
state.
